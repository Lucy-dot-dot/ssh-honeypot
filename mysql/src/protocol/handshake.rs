use super::constants::{NATIVE_PASSWORD_PLUGIN, UTF8MB4_CHARSET, capabilities, status};
use super::packet::{Cursor, ProtocolError};
use rand::{RngExt, rng};

/// Length of the auth scramble sent in the initial handshake
/// (8 bytes part 1 + 12 bytes part 2, part 2 includes a trailing NUL on the wire)
pub const SCRAMBLE_LEN: usize = 20;

/// Everything the server needs from the client handshake response
#[derive(Debug, Clone)]
pub struct ClientHandshake {
    pub capabilities: u32,
    pub protocol_41: bool,
    pub username: String,
    pub database: Option<String>,
    pub auth_plugin: Option<String>,
    pub auth_response: Vec<u8>,
}

/// Random per-connection handshake data
#[derive(Debug, Clone)]
pub struct HandshakeSeed {
    pub connection_id: u32,
    pub scramble: [u8; SCRAMBLE_LEN],
}

/// Builds the protocol version 10 initial handshake payload
pub fn build_initial_handshake(
    server_version: &str,
    server_capabilities: u32,
) -> (Vec<u8>, HandshakeSeed) {
    let mut rng = rng();
    let seed = HandshakeSeed {
        connection_id: rng.random(),
        scramble: std::array::from_fn(|_| rng.random_range(0x21u8..=0x7Eu8)),
    };

    let mut p = Vec::with_capacity(128);
    p.push(10); // protocol version
    p.extend_from_slice(server_version.as_bytes());
    p.push(0);
    p.extend_from_slice(&seed.connection_id.to_le_bytes());
    p.extend_from_slice(&seed.scramble[..8]);
    p.push(0); // filler
    p.extend_from_slice(&(server_capabilities as u16).to_le_bytes());
    p.push(UTF8MB4_CHARSET);
    p.extend_from_slice(&status::SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    p.extend_from_slice(&((server_capabilities >> 16) as u16).to_le_bytes());
    p.push((SCRAMBLE_LEN + 1) as u8); // auth plugin data length incl. NUL
    p.extend_from_slice(&seed.scramble[8..]);
    p.push(0);
    p.extend_from_slice(NATIVE_PASSWORD_PLUGIN.as_bytes());
    p.push(0);

    (p, seed)
}

/// True if the payload looks like an SSL request (client wants TLS, which we
/// do not support). Same layout as a handshake response but truncated after
/// the 32 byte fixed prefix with CLIENT_SSL set.
pub fn is_ssl_request(payload: &[u8]) -> bool {
    payload.len() == 32
        && payload
            .first_chunk::<4>()
            .is_some_and(|b| u32::from_le_bytes(*b) & capabilities::CLIENT_SSL != 0)
}

/// Parses a handshake response (protocol 41 and the legacy pre-41 variant)
pub fn parse_handshake_response(payload: &[u8]) -> Result<ClientHandshake, ProtocolError> {
    let mut c = Cursor::new(payload);

    // A pre-41 handshake response has a 2 byte capability prefix, so it is
    // impossible to distinguish up front. Peek at the capability flags: for
    // protocol 41 the low 2 bytes contain CLIENT_PROTOCOL_41 in a fixed spot.
    let caps_low = c.u16()?;
    if caps_low & capabilities::CLIENT_PROTOCOL_41 as u16 != 0 {
        parse_v41(c, caps_low)
    } else {
        parse_pre41(c, caps_low)
    }
}

fn parse_v41(mut c: Cursor<'_>, caps_low: u16) -> Result<ClientHandshake, ProtocolError> {
    let caps_high = c.u16()?;
    let capabilities = caps_low as u32 | (caps_high as u32) << 16;
    let _max_packet_size = c.u32()?;
    let _charset = c.u8()?;
    c.bytes(23)?; // reserved

    let username = c.nul_str()?.to_string();

    let auth_response = if capabilities & capabilities::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        c.lenenc_bytes()?.to_vec()
    } else if capabilities & capabilities::CLIENT_SECURE_CONNECTION != 0 {
        let len = c.u8()? as usize;
        c.bytes(len)?.to_vec()
    } else {
        c.nul_str()?.as_bytes().to_vec()
    };

    let database = if capabilities & capabilities::CLIENT_CONNECT_WITH_DB != 0 && !c.is_empty() {
        Some(c.nul_str()?.to_string())
    } else {
        None
    };

    let auth_plugin = if capabilities & capabilities::CLIENT_PLUGIN_AUTH != 0 && !c.is_empty() {
        Some(c.nul_str()?.to_string())
    } else {
        None
    };

    Ok(ClientHandshake {
        capabilities,
        protocol_41: true,
        username,
        database,
        auth_plugin,
        auth_response,
    })
}

fn parse_pre41(mut c: Cursor<'_>, caps_low: u16) -> Result<ClientHandshake, ProtocolError> {
    let _max_packet = c.u24()?;
    let username = c.nul_str()?.to_string();

    // Legacy clients terminate the auth data with NUL; the connect-with-db
    // bit (in the low 16 bits for pre-41) signals a following database name.
    let auth_response = if caps_low & capabilities::CLIENT_SECURE_CONNECTION as u16 != 0 {
        let len = c.u8()? as usize;
        c.bytes(len)?.to_vec()
    } else {
        c.nul_str()?.as_bytes().to_vec()
    };

    let database = if caps_low & capabilities::CLIENT_CONNECT_WITH_DB as u16 != 0 && !c.is_empty() {
        Some(c.nul_str()?.to_string())
    } else {
        None
    };

    Ok(ClientHandshake {
        capabilities: caps_low as u32,
        protocol_41: false,
        username,
        database,
        auth_plugin: None,
        auth_response,
    })
}

/// Auth switch request asking the client to resend credentials using the
/// given auth plugin
pub fn build_auth_switch_request(plugin: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(plugin.len() + 2);
    p.push(0xFE);
    p.extend_from_slice(plugin.as_bytes());
    p.push(0);
    p
}

/// Extracts the cleartext password from a `mysql_clear_password` auth switch
/// response (NUL terminated). Returns None when the payload is not valid
/// UTF-8 (e.g. the client answered with a native password scramble).
pub fn parse_clear_password(payload: &[u8]) -> Option<String> {
    let end = payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(payload.len());
    std::str::from_utf8(&payload[..end])
        .ok()
        .map(|s| s.to_string())
}

/// OK packet. Empty response for the simulated SQL shell.
pub fn build_ok(protocol_41: bool) -> Vec<u8> {
    let mut p = Vec::with_capacity(16);
    p.push(0x00); // OK header
    p.push(0x00); // affected rows (lenenc)
    p.push(0x00); // last insert id (lenenc)
    if protocol_41 {
        p.extend_from_slice(&status::SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes()); // warnings
    }
    p
}

/// ERR packet with sql state (protocol 41 format)
pub fn build_err(code: u16, sql_state: &str, message: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(9 + message.len());
    p.push(0xFF);
    p.extend_from_slice(&code.to_le_bytes());
    p.push(b'#');
    let mut state = sql_state.as_bytes().to_vec();
    state.resize(5, b'0');
    p.extend_from_slice(&state[..5]);
    p.extend_from_slice(message.as_bytes());
    p
}

/// Response payload for COM_STATISTICS, mimicking real server output
pub fn build_statistics(uptime_secs: u64) -> Vec<u8> {
    format!(
        "Uptime: {}  Threads: 1  Questions: {}  Slow queries: 0  Opens: 0  Flush tables: 1  Open tables: 0  Queries per second avg: 0.000",
        uptime_secs,
        uptime_secs * 3
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_payload_layout() {
        let (payload, seed) = build_initial_handshake("8.0.36", capabilities::SERVER_CAPABILITIES);
        let mut c = Cursor::new(&payload);
        assert_eq!(c.u8().unwrap(), 10);
        assert_eq!(c.nul_str().unwrap(), "8.0.36");
        let conn_id = c.u32().unwrap();
        assert_eq!(conn_id, seed.connection_id);
        assert_eq!(c.bytes(8).unwrap(), &seed.scramble[..8]);
        assert_eq!(c.u8().unwrap(), 0); // filler
        let caps_low = c.u16().unwrap();
        assert_eq!(c.u8().unwrap(), UTF8MB4_CHARSET);
        assert_eq!(c.u16().unwrap(), status::SERVER_STATUS_AUTOCOMMIT);
        let caps_high = c.u16().unwrap();
        assert_eq!(
            caps_low as u32 | (caps_high as u32) << 16,
            capabilities::SERVER_CAPABILITIES
        );
        assert_eq!(c.u8().unwrap(), (SCRAMBLE_LEN + 1) as u8);
        assert_eq!(c.bytes(12).unwrap(), &seed.scramble[8..]);
        assert_eq!(c.u8().unwrap(), 0);
        assert_eq!(c.nul_str().unwrap(), NATIVE_PASSWORD_PLUGIN);
    }

    #[test]
    fn parse_v41_response() {
        let mut p = Vec::new();
        let caps = capabilities::CLIENT_PROTOCOL_41
            | capabilities::CLIENT_SECURE_CONNECTION
            | capabilities::CLIENT_PLUGIN_AUTH
            | capabilities::CLIENT_CONNECT_WITH_DB
            | capabilities::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&16777216u32.to_le_bytes());
        p.push(45);
        p.extend_from_slice(&[0u8; 23]);
        p.extend_from_slice(b"root\x00");
        p.push(4); // lenenc auth response length
        p.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        p.extend_from_slice(b"mydb\x00");
        p.extend_from_slice(b"mysql_native_password\x00");

        let hs = parse_handshake_response(&p).unwrap();
        assert!(hs.protocol_41);
        assert_eq!(hs.username, "root");
        assert_eq!(hs.database.as_deref(), Some("mydb"));
        assert_eq!(hs.auth_plugin.as_deref(), Some("mysql_native_password"));
        assert_eq!(hs.auth_response, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_secure_connection_response() {
        let mut p = Vec::new();
        let caps = capabilities::CLIENT_PROTOCOL_41 | capabilities::CLIENT_SECURE_CONNECTION;
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.push(8);
        p.extend_from_slice(&[0u8; 23]);
        p.extend_from_slice(b"admin\x00");
        p.push(20); // 1-byte length prefixed auth response
        p.extend_from_slice(&[7u8; 20]);

        let hs = parse_handshake_response(&p).unwrap();
        assert_eq!(hs.username, "admin");
        assert_eq!(hs.database, None);
        assert_eq!(hs.auth_response.len(), 20);
    }

    #[test]
    fn clear_password_parsing() {
        assert_eq!(
            parse_clear_password(b"secret\x00"),
            Some("secret".to_string())
        );
        assert_eq!(parse_clear_password(b"secret"), Some("secret".to_string()));
        assert_eq!(parse_clear_password(&[0xff, 0xfe]), None);
    }

    #[test]
    fn ssl_request_detection() {
        let mut p = Vec::new();
        p.extend_from_slice(
            &(capabilities::CLIENT_SSL | capabilities::CLIENT_PROTOCOL_41).to_le_bytes(),
        );
        p.extend_from_slice(&0u32.to_le_bytes());
        p.push(45);
        p.extend_from_slice(&[0u8; 23]);
        assert!(is_ssl_request(&p));

        let mut p2 = p.clone();
        p2[1] = 0; // clear CLIENT_SSL (0x800 lives in the second byte)
        assert!(!is_ssl_request(&p2));
    }

    #[test]
    fn ok_packet_layout() {
        let ok = build_ok(true);
        assert_eq!(ok, vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
        let ok_pre41 = build_ok(false);
        assert_eq!(ok_pre41, vec![0x00, 0x00, 0x00]);
    }
}
