use std::fs::OpenOptions;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;
use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKey};
use russh::keys::signature::rand_core::OsRng;
use crate::app::App;

pub struct Keys {
    pub ed25519: PrivateKey,
    pub rsa: PrivateKey,
    pub ecdsa: PrivateKey,
    pub sk_ed25519: PrivateKey,
}

pub fn load_or_generate_keys(app: &App) -> Keys {
    let key_dir = app.effective_key_dir();
    let ed_path = key_dir.join("ed25519");
    let rsa_path = key_dir.join("rsa");
    let ecdsa_path = key_dir.join("ecdsa");
    let sk_ed_path = key_dir.join("sk_ed25519");
    
    log::debug!("Loading keys from: {}, {}, {}, {}", 
        ed_path.display(), 
        rsa_path.display(), 
        ecdsa_path.display(),
        sk_ed_path.display()
    );

    let ed_key = load_or_create_key(ed_path, Algorithm::Ed25519);
    let rsa_key = load_or_create_key(rsa_path, Algorithm::Rsa { hash: Some(HashAlg::Sha512) });
    let ecdsa_key = load_or_create_key(ecdsa_path, Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 });
    let sk_ed_key = load_or_create_key(sk_ed_path, Algorithm::SkEd25519);
    
    Keys {
        ed25519: ed_key,
        rsa: rsa_key,
        ecdsa: ecdsa_key,
        sk_ed25519: sk_ed_key,
    }
}

fn load_or_create_key(key_file_path: PathBuf, algorithm: Algorithm) -> PrivateKey {
    log::debug!("Loading key from: {} with algorithm {}", key_file_path.display(), algorithm);
    match OpenOptions::new().read(true).open(key_file_path.clone()) {
        Ok(mut keyfile) => {
            match keyfile.metadata() {
                Ok(metadata) => {
                    let size = metadata.len();
                    if size == 0 {
                        log::warn!("Key file '{}' is empty", key_file_path.display());
                        let key = PrivateKey::random(&mut OsRng, algorithm).unwrap();
                        match std::fs::write(key_file_path, key.to_bytes().unwrap()) {
                            Ok(_) => log::debug!("Wrote key to file"),
                            Err(err) => log::warn!("Error when writing key to file: {err}")
                        };
                        key
                    } else {
                        let mut buffer = Vec::with_capacity(size as usize);
                        match keyfile.read_to_end(&mut buffer) {
                            Ok(_) => {
                                let key = match PrivateKey::from_bytes(buffer.as_slice()) {
                                    Ok(key) => key,
                                    Err(err) => {
                                        log::warn!("Error when reading key file: {err}. Creating ephemeral key");
                                        PrivateKey::random(&mut OsRng, algorithm).unwrap()
                                    }
                                };
                                log::debug!("Loaded key");
                                key
                            }
                            Err(err) => {
                                log::warn!("Error when reading key file: {err}. Creating ephemeral key");
                                PrivateKey::random(&mut OsRng, algorithm).unwrap()
                            }
                        }
                    }
                }
                Err(err) => {
                    log::warn!("Error when reading key file: {err}. Creating ephemeral key");
                    PrivateKey::random(&mut OsRng, algorithm).unwrap()
                }
            }
        }
        Err(err) => {
            match err.kind() {
                ErrorKind::PermissionDenied => {
                    log::warn!("Key file is not readable; Creating ephemeral key");
                }
                ErrorKind::IsADirectory => {
                    log::warn!("Key file is a directory; Creating ephemeral key");
                }
                ErrorKind::NotFound => {
                    let key = PrivateKey::random(&mut OsRng, algorithm).unwrap();
                    match std::fs::write(key_file_path, key.to_bytes().unwrap()) {
                        Ok(_) => log::debug!("Wrote key to new file"),
                        Err(err) => log::warn!("Error when writing key to file: {err}")
                    };
                    return key
                }
                _ => {
                    log::warn!("Error when opening key file: {err}. Creating ephemeral key");
                }
            };
            PrivateKey::random(&mut OsRng, algorithm).unwrap()
        }
    }
}
