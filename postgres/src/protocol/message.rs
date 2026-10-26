//! PostgreSQL frontend/backend protocol (version 3.0) message framing.
//!
//! Regular messages are a single type byte followed by an int32 length
//! (which includes itself, but not the type byte) and the payload. Startup
//! phase messages have no type byte: int32 length, int32 protocol and the
//! payload.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SSL request code, sent by clients before any TLS handshake
pub const SSL_REQUEST_CODE: u32 = 80_877_103;
/// GSSAPI encryption request code (answered with 'N', unsupported)
pub const GSSENC_REQUEST_CODE: u32 = 80_877_104;
/// Cancel request code, followed by the target pid and cancel secret
pub const CANCEL_REQUEST_CODE: u32 = 80_877_102;
/// Protocol major/minor packed as (major << 16) | minor for version 3.0
pub const PROTOCOL_VERSION_3_0: u32 = 196_608;

/// Authentication codes sent in Authentication ('R') messages
pub const AUTHENTICATION_OK: i32 = 0;
/// Cleartext password request. The only auth method this honeypot
/// advertises - no MD5 and no SCRAM, so passwords arrive in the clear.
pub const AUTHENTICATION_CLEARTEXT_PASSWORD: i32 = 3;

/// Frontend message types
pub mod message_types {
    pub const PASSWORD: u8 = b'p';
    pub const QUERY: u8 = b'Q';
    pub const PARSE: u8 = b'P';
    pub const BIND: u8 = b'B';
    pub const DESCRIBE: u8 = b'D';
    pub const EXECUTE: u8 = b'E';
    pub const CLOSE: u8 = b'C';
    pub const FLUSH: u8 = b'H';
    pub const SYNC: u8 = b'S';
    pub const TERMINATE: u8 = b'X';
}

/// Backend message types
pub mod backend_types {
    pub const AUTHENTICATION: u8 = b'R';
    pub const BACKEND_KEY_DATA: u8 = b'K';
    pub const PARAMETER_STATUS: u8 = b'S';
    pub const READY_FOR_QUERY: u8 = b'Z';
    pub const ERROR_RESPONSE: u8 = b'E';
    pub const NOTICE_RESPONSE: u8 = b'N';
    pub const EMPTY_QUERY_RESPONSE: u8 = b'I';
    pub const COMMAND_COMPLETE: u8 = b'C';
    pub const ROW_DESCRIPTION: u8 = b'T';
    pub const PARSE_COMPLETE: u8 = b'1';
    pub const BIND_COMPLETE: u8 = b'2';
    pub const CLOSE_COMPLETE: u8 = b'3';
    pub const NO_DATA: u8 = b'n';
}

/// Largest message length the parser accepts (1 GiB protocol limit),
/// guarding against bogus length fields allocating huge buffers.
const MAX_MESSAGE_LENGTH: u32 = 1 << 30;

/// First startup message received from a client. SSL and GSS encryption
/// requests are answered before the real startup message is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientStartup {
    SslRequest,
    GssEncRequest,
    /// CancelRequest with the target backend pid and cancel secret
    CancelRequest {
        pid: i32,
        secret: i32,
    },
    Startup(StartupMessage),
    /// Any other protocol version
    UnsupportedProtocol {
        major: u32,
        minor: u32,
    },
}

/// Parsed StartupMessage (protocol 3.0)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StartupMessage {
    pub protocol_version: u32,
    /// key/value parameters in the order sent by the client
    pub parameters: Vec<(String, String)>,
}

impl StartupMessage {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Reads and classifies the first client message of the startup phase.
pub async fn read_startup<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<ClientStartup> {
    let length = stream.read_u32().await?;
    if !(8..=MAX_MESSAGE_LENGTH).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid startup message length",
        ));
    }
    let mut payload = vec![0u8; length as usize - 4];
    stream.read_exact(&mut payload).await?;

    let mut cursor = Cursor::new(&payload);
    let Some(code) = cursor.u32() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated startup message",
        ));
    };

    match code {
        SSL_REQUEST_CODE => Ok(ClientStartup::SslRequest),
        GSSENC_REQUEST_CODE => Ok(ClientStartup::GssEncRequest),
        CANCEL_REQUEST_CODE => {
            let pid = cursor.i32().unwrap_or(0);
            let secret = cursor.i32().unwrap_or(0);
            Ok(ClientStartup::CancelRequest { pid, secret })
        }
        _ => {
            let major = code >> 16;
            let minor = code & 0xffff;
            if major != 3 {
                return Ok(ClientStartup::UnsupportedProtocol { major, minor });
            }
            let mut parameters = Vec::new();
            // The parameter list is terminated by a single \0, which reads
            // as an empty key
            while let Some(key) = cursor.cstring() {
                if key.is_empty() {
                    break;
                }
                let Some(value) = cursor.cstring() else {
                    break;
                };
                parameters.push((key, value));
            }
            Ok(ClientStartup::Startup(StartupMessage {
                protocol_version: code,
                parameters,
            }))
        }
    }
}

/// Reads a regular message: type byte, int32 length, payload.
pub async fn read_message<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(u8, Vec<u8>)> {
    let msg_type = stream.read_u8().await?;
    let length = stream.read_u32().await?;
    if !(4..=MAX_MESSAGE_LENGTH).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid message length",
        ));
    }
    let mut payload = vec![0u8; length as usize - 4];
    stream.read_exact(&mut payload).await?;
    Ok((msg_type, payload))
}

/// Writes a regular message. Payload must not include the length header.
pub async fn write_message<S: AsyncWrite + Unpin>(
    stream: &mut S,
    msg_type: u8,
    payload: &[u8],
) -> io::Result<()> {
    stream.write_u8(msg_type).await?;
    stream
        .write_u32(u32::try_from(payload.len() + 4).expect("payload within protocol limits"))
        .await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Writes the single byte answer of the SSL/GSS request phase ('S' or 'N').
pub async fn write_single_byte_answer<S: AsyncWrite + Unpin>(
    stream: &mut S,
    answer: u8,
) -> io::Result<()> {
    stream.write_u8(answer).await?;
    stream.flush().await
}

/// Extracts the password from a PasswordMessage payload ("password\0").
pub fn parse_password_message(payload: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(payload);
    let password = cursor.cstring()?;
    if password.is_empty() {
        None
    } else {
        Some(password)
    }
}

/// Extracts (statement name, query text) from a Parse message payload.
pub fn parse_parse_message(payload: &[u8]) -> Option<(String, String)> {
    let mut cursor = Cursor::new(payload);
    let name = cursor.cstring()?;
    let query = cursor.cstring()?;
    Some((name, query))
}

fn i32_payload(value: i32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// 'R' AuthenticationOk
pub fn build_authentication_ok() -> Vec<u8> {
    i32_payload(AUTHENTICATION_OK)
}

/// 'R' AuthenticationCleartextPassword request
pub fn build_authentication_cleartext_password() -> Vec<u8> {
    i32_payload(AUTHENTICATION_CLEARTEXT_PASSWORD)
}

/// 'S' ParameterStatus payload (key\0value\0)
pub fn build_parameter_status_payload(key: &str, value: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(key.len() + value.len() + 2);
    payload.extend_from_slice(key.as_bytes());
    payload.push(0);
    payload.extend_from_slice(value.as_bytes());
    payload.push(0);
    payload
}

/// 'K' BackendKeyData payload (pid + cancel secret)
pub fn build_backend_key_data_payload(pid: i32, secret: i32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&pid.to_be_bytes());
    payload.extend_from_slice(&secret.to_be_bytes());
    payload
}

/// 'T' RowDescription announcing zero columns
pub fn build_empty_row_description() -> Vec<u8> {
    vec![0, 0] // int16 field count = 0
}

/// 'C' CommandComplete payload (tag\0)
pub fn build_command_complete_payload(tag: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(tag.len() + 1);
    payload.extend_from_slice(tag.as_bytes());
    payload.push(0);
    payload
}

/// 'E' ErrorResponse payload: FATAL severity + SQLSTATE + message.
pub fn build_fatal_error_payload(code: &str, message: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(message.len() + 32);
    for (field, value) in [
        (b'S', "FATAL".as_bytes()),
        (b'V', b"FATAL"),
        (b'C', code.as_bytes()),
        (b'M', message.as_bytes()),
    ] {
        payload.push(field);
        payload.extend_from_slice(value);
        payload.push(0);
    }
    payload.push(0); // message terminator
    payload
}

/// Convenience: send a FATAL ErrorResponse and return, closing the session
/// is up to the caller.
pub async fn write_fatal_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: &str,
    message: &str,
) -> io::Result<()> {
    write_message(
        stream,
        backend_types::ERROR_RESPONSE,
        &build_fatal_error_payload(code, message),
    )
    .await
}

/// True for queries that consist of nothing (whitespace/comments and at most
/// a single ';'), which a real server answers with EmptyQueryResponse.
pub fn is_empty_query(query: &str) -> bool {
    let trimmed = query.trim();
    trimmed.is_empty() || trimmed == ";"
}

/// CommandComplete tag for a statement this honeypot does not execute.
/// Derived from the first keyword so drivers see a plausible response.
pub fn command_tag_for(query: &str) -> String {
    let first = query
        .split(|c: char| c.is_whitespace() || c == '(' || c == ';')
        .find(|word| !word.is_empty())
        .unwrap_or("");
    match first.to_ascii_uppercase().as_str() {
        "SELECT" | "WITH" | "SHOW" | "TABLE" | "VALUES" => "SELECT 0",
        "INSERT" => "INSERT 0 0",
        "UPDATE" => "UPDATE 0",
        "DELETE" => "DELETE 0",
        "BEGIN" | "START" => "BEGIN",
        "COMMIT" | "END" => "COMMIT",
        "ROLLBACK" | "ABORT" => "ROLLBACK",
        "SET" | "RESET" => "SET",
        "COPY" => "COPY 0",
        "CREATE" => "CREATE",
        "DROP" => "DROP",
        "ALTER" => "ALTER",
        _ => "SELECT 0",
    }
    .to_string()
}

/// Minimal big-endian payload cursor. Parsing helpers return None on
/// truncation or invalid UTF-8 so callers can treat garbage as an
/// unrecognized message.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }

    fn i32(&mut self) -> Option<i32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(i32::from_be_bytes(bytes))
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    /// NUL-terminated UTF-8 string
    fn cstring(&mut self) -> Option<String> {
        let end = self.data[self.pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|offset| self.pos + offset)?;
        let slice = &self.data[self.pos..end];
        self.pos = end + 1;
        String::from_utf8(slice.to_vec()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn startup_message_parses_parameters() {
        // StartupMessage: length 8+22, protocol 3.0, user\0postgres\0database\0test\0\0
        let payload = {
            let mut p = Vec::new();
            p.extend_from_slice(&196_608u32.to_be_bytes());
            p.extend_from_slice(b"user\0postgres\0database\0test\0");
            p.push(0);
            let mut msg = (p.len() as u32 + 4).to_be_bytes().to_vec();
            msg.extend_from_slice(&p);
            msg
        };

        let mut cursor = Cursor::new(&payload[4..]);
        let code = cursor.u32().unwrap();
        assert_eq!(code, PROTOCOL_VERSION_3_0);

        let mut parameters = Vec::new();
        // The parameter list is terminated by a single \0, which reads as
        // an empty key
        while let Some(key) = cursor.cstring() {
            if key.is_empty() {
                break;
            }
            let value = cursor.cstring().unwrap();
            parameters.push((key, value));
        }

        let startup = StartupMessage {
            protocol_version: code,
            parameters,
        };
        assert_eq!(startup.get("user"), Some("postgres"));
        assert_eq!(startup.get("database"), Some("test"));
        assert_eq!(startup.get("missing"), None);
    }

    #[tokio::test]
    async fn startup_roundtrip_over_stream() {
        let (mut client, mut server) = duplex(64);

        // SSLRequest: length 8, code 80877103
        let mut ssl = 8u32.to_be_bytes().to_vec();
        ssl.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
        client.write_all(&ssl).await.unwrap();
        client.flush().await.unwrap();

        assert_eq!(
            read_startup(&mut server).await.unwrap(),
            ClientStartup::SslRequest
        );
    }

    #[tokio::test]
    async fn message_roundtrip_over_stream() {
        let (mut client, mut server) = duplex(64);

        write_message(&mut client, b'Q', b"SELECT 1\0")
            .await
            .unwrap();
        let (msg_type, payload) = read_message(&mut server).await.unwrap();
        assert_eq!(msg_type, b'Q');
        assert_eq!(payload, b"SELECT 1\0");
    }

    #[tokio::test]
    async fn invalid_message_length_is_rejected() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&0u32.to_be_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let err = read_startup(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn password_message_parsing() {
        assert_eq!(
            parse_password_message(b"secret\0"),
            Some("secret".to_string())
        );
        assert_eq!(parse_password_message(b"\0"), None);
        assert_eq!(parse_password_message(b""), None);
        assert_eq!(parse_password_message(b"no-terminator"), None);
    }

    #[test]
    fn parse_message_extract_name_and_query() {
        let (name, query) = parse_parse_message(b"\0SELECT $1\0\0\0").unwrap();
        assert_eq!(name, "");
        assert_eq!(query, "SELECT $1");
        assert!(parse_parse_message(b"\0SELECT $1").is_none());
    }

    #[test]
    fn error_response_layout() {
        let payload = build_fatal_error_payload("28P01", "password authentication failed");
        let rendered = String::from_utf8(payload).unwrap();
        // Each field is a field code byte followed by a cstring, then the
        // message terminator
        assert!(rendered.starts_with("SFATAL\0VFATAL\0C28P01\0Mpassword authentication failed\0"));
        assert!(rendered.ends_with('\0'));
    }

    #[test]
    fn empty_query_detection() {
        assert!(is_empty_query(""));
        assert!(is_empty_query("   "));
        assert!(is_empty_query(";"));
        assert!(is_empty_query(" ; "));
        assert!(!is_empty_query("SELECT 1"));
        assert!(!is_empty_query("SELECT 1;"));
    }

    #[test]
    fn command_tags_follow_first_keyword() {
        assert_eq!(command_tag_for("SELECT 1"), "SELECT 0");
        assert_eq!(command_tag_for("  insert into t values (1)"), "INSERT 0 0");
        assert_eq!(command_tag_for("update t set a = 1"), "UPDATE 0");
        assert_eq!(command_tag_for("DELETE FROM t"), "DELETE 0");
        assert_eq!(command_tag_for("BEGIN"), "BEGIN");
        assert_eq!(command_tag_for("START TRANSACTION"), "BEGIN");
        assert_eq!(command_tag_for("COMMIT"), "COMMIT");
        assert_eq!(command_tag_for("ROLLBACK"), "ROLLBACK");
        assert_eq!(command_tag_for("SET search_path = public"), "SET");
        assert_eq!(command_tag_for("CREATE TABLE x (a int)"), "CREATE");
        assert_eq!(command_tag_for("VACUUM"), "SELECT 0");
    }

    #[test]
    fn backend_payloads_have_wire_shapes() {
        assert_eq!(build_authentication_ok(), vec![0, 0, 0, 0]);
        assert_eq!(build_authentication_cleartext_password(), vec![0, 0, 0, 3]);
        assert_eq!(build_empty_row_description(), vec![0, 0]);
        assert_eq!(
            build_command_complete_payload("SELECT 0"),
            b"SELECT 0\0".to_vec()
        );
        assert_eq!(
            build_parameter_status_payload("client_encoding", "UTF8"),
            b"client_encoding\0UTF8\0".to_vec()
        );
        let key_data = build_backend_key_data_payload(0x01020304, 0x05060708);
        assert_eq!(key_data.len(), 8);
        assert_eq!(&key_data[..4], &[1, 2, 3, 4]);
        assert_eq!(&key_data[4..], &[5, 6, 7, 8]);
    }
}
