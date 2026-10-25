//! Shared TLS listener identity handling for the honeypot protocol modules
//! (mysql, mssql, ...). Every module serves either a configured PEM pair or
//! an in-memory generated self-signed certificate, since attackers must not
//! be able to validate our identity anyway.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Builds the TLS acceptor used to upgrade connections mid-stream. Returns
/// None when TLS support is disabled or no usable server identity could be
/// obtained. `module` is used for log prefixes so multiple protocol modules
/// can share this code without ambiguity.
pub fn build_tls_acceptor(
    module: &str,
    enable_tls: bool,
    tls_cert: Option<&Path>,
    tls_key: Option<&Path>,
) -> Option<TlsAcceptor> {
    if !enable_tls {
        log::info!("{} TLS support is disabled", module);
        return None;
    }

    let (certs, key) = match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => match load_pem_identity(cert_path, key_path) {
            Ok(identity) => {
                log::info!(
                    "{} TLS identity loaded from {} and {}",
                    module,
                    cert_path.display(),
                    key_path.display()
                );
                identity
            }
            Err(err) => {
                log::error!(
                    "Failed to load {} TLS identity from {} and {}: {}",
                    module,
                    cert_path.display(),
                    key_path.display(),
                    err
                );
                return None;
            }
        },
        (Some(_), None) | (None, Some(_)) => {
            log::error!(
                "{} tls_cert and tls_key must be configured together; \
                 falling back to a generated self-signed certificate",
                module
            );
            match generate_self_signed_identity() {
                Ok(identity) => identity,
                Err(err) => {
                    log::error!(
                        "Failed to generate a self-signed {} certificate: {}",
                        module,
                        err
                    );
                    return None;
                }
            }
        }
        (None, None) => match generate_self_signed_identity() {
            Ok(identity) => identity,
            Err(err) => {
                log::error!(
                    "Failed to generate a self-signed {} certificate: {}",
                    module,
                    err
                );
                return None;
            }
        },
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = match rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|builder| builder.with_no_client_auth().with_single_cert(certs, key))
    {
        Ok(config) => config,
        Err(err) => {
            log::error!("Invalid {} TLS configuration: {}", module, err);
            return None;
        }
    };

    log::info!(
        "{} TLS support enabled (self-signed or configured certificate)",
        module
    );
    Some(TlsAcceptor::from(Arc::new(config)))
}

/// Generates an in-memory self-signed certificate for the TLS listener.
fn generate_self_signed_identity()
-> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("rcgen: {err}")))?;
    let cert = CertificateDer::from(identity.cert);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.signing_key.serialize_der(),
    ));
    Ok((vec![cert], key))
}

/// Loads a PEM encoded certificate chain and private key from disk.
fn load_pem_identity(
    cert_path: &Path,
    key_path: &Path,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_file = std::fs::File::open(cert_path)?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut io::BufReader::new(cert_file))
        .collect::<Result<_, _>>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("bad PEM: {err}")))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificates found",
        ));
    }

    let key_file = std::fs::File::open(key_path)?;
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(key_file))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("bad PEM: {err}")))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found"))?;

    Ok((certs, key))
}
