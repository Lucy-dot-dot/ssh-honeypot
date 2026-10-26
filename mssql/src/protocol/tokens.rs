//! Server response token builders (MS-TDS 2.2.7).
//!
//! Everything the honeypot ever sends after authentication: ERROR,
//! LOGINACK, ENVCHANGE and DONE tokens.

pub mod token_type {
    pub const ERROR: u8 = 0xAA;
    pub const INFO: u8 = 0xAB;
    pub const LOGINACK: u8 = 0xAD;
    pub const ENVCHANGE: u8 = 0xE3;
    pub const DONE: u8 = 0xFD;
}

pub mod done_status {
    pub const DONE_FINAL: u16 = 0x0000;
    pub const DONE_ERROR: u16 = 0x0002;
    pub const DONE_ATTN: u16 = 0x0020;
}

pub mod envchange_type {
    pub const DATABASE: u8 = 1;
    pub const LANGUAGE: u8 = 2;
    pub const PACKET_SIZE: u8 = 4;
}

pub mod error_number {
    /// Login failed for user (SQL Server authentication)
    pub const LOGIN_FAILED: u32 = 18456;
    /// Login from untrusted domain (integrated auth failure)
    pub const UNTRUSTED_DOMAIN: u32 = 18452;
    /// Could not find stored procedure
    pub const PROC_NOT_FOUND: u32 = 2812;
}

/// UTF-16LE length-prefixed string
fn us_varchar(out: &mut Vec<u8>, s: &str) {
    let units: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    out.extend_from_slice(&(units.len() as u16).to_le_bytes());
    out.extend_from_slice(&units);
}

/// ASCII length-prefixed (single byte) string
fn b_varchar(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.push(bytes.len().min(255) as u8);
    out.extend_from_slice(&bytes[..bytes.len().min(255)]);
}

/// Builds a token stream from individual tokens
pub fn token_stream(tokens: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::with_capacity(tokens.iter().map(|t| t.len()).sum());
    for token in tokens {
        out.extend_from_slice(&token);
    }
    out
}

/// ERROR token: mimics a real "Login failed for user" response so brute
/// force tooling keeps hammering and we keep harvesting attempts.
pub fn build_error(
    number: u32,
    state: u8,
    class: u8,
    message: &str,
    server_name: &str,
    proc_name: &str,
    line: u16,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&number.to_le_bytes());
    body.push(state);
    body.push(class);
    us_varchar(&mut body, message);
    b_varchar(&mut body, server_name);
    b_varchar(&mut body, proc_name);
    body.extend_from_slice(&line.to_le_bytes());

    let mut out = Vec::with_capacity(body.len() + 3);
    out.push(token_type::ERROR);
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Standard login failure for SQL auth (18456, class 14, state 1)
pub fn build_login_failed(username: &str, server_name: &str) -> Vec<u8> {
    build_error(
        error_number::LOGIN_FAILED,
        1,
        14,
        &format!("Login failed for user '{username}'."),
        server_name,
        "",
        1,
    )
}

/// Standard failure for Kerberos / unsupported SSPI mechanisms
pub fn build_untrusted_domain(server_name: &str) -> Vec<u8> {
    build_error(
        error_number::UNTRUSTED_DOMAIN,
        1,
        14,
        "Login failed. The login is from an untrusted domain and cannot be used with integrated authentication.",
        server_name,
        "",
        0,
    )
}

/// LOGINACK token confirming successful authentication
pub fn build_login_ack(tds_version: u32, version: (u8, u8, u16, u16)) -> Vec<u8> {
    let (major, minor, build, subbuild) = version;
    // Interface(1) TDSVersion(4) BrandName(4) Version(6) ProcName(US_VARCHAR)
    let body_len = 1 + 4 + 4 + 6 + 2;

    let mut out = Vec::with_capacity(body_len + 3);
    out.push(token_type::LOGINACK);
    out.extend_from_slice(&(body_len as u16).to_le_bytes());
    out.push(1); // Interface: SQL Server TDS
    out.extend_from_slice(&tds_version.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // BrandName: SQL Server
    // Version struct: build(2 LE) minor(1) major(1) subbuild(2 LE)
    out.extend_from_slice(&build.to_le_bytes());
    out.push(minor);
    out.push(major);
    out.extend_from_slice(&subbuild.to_le_bytes());
    us_varchar(&mut out, ""); // ProcName
    out
}

/// ENVCHANGE token. Used for the post-login database/packet size changes.
pub fn build_envchange(kind: u8, new_value: &str, old_value: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(kind);
    us_varchar(&mut body, new_value);
    us_varchar(&mut body, old_value);

    let mut out = Vec::with_capacity(body.len() + 3);
    out.push(token_type::ENVCHANGE);
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// DONE token terminating a token stream
pub fn build_done(status: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(13);
    out.push(token_type::DONE);
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // CurCmd
    out.extend_from_slice(&0u64.to_le_bytes()); // DoneCount
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_token_layout() {
        let err = build_login_failed("sa", "WIN-SERVER01");
        assert_eq!(err[0], token_type::ERROR);
        let len = u16::from_le_bytes([err[1], err[2]]) as usize;
        assert_eq!(err.len(), len + 3);
        // Number field
        let number = u32::from_le_bytes([err[3], err[4], err[5], err[6]]);
        assert_eq!(number, error_number::LOGIN_FAILED);
        // Message must be parseable UTF-16LE: scan us_varchar at offset 9
        let msg_len = u16::from_le_bytes([err[9], err[10]]) as usize;
        let msg_bytes = &err[11..11 + msg_len];
        let units: Vec<u16> = msg_bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let msg = String::from_utf16(&units).unwrap();
        assert_eq!(msg, "Login failed for user 'sa'.");
    }

    #[test]
    fn login_ack_layout() {
        let ack = build_login_ack(0x0400_0000, (16, 0, 1000, 6));
        assert_eq!(ack[0], token_type::LOGINACK);
        let len = u16::from_le_bytes([ack[1], ack[2]]) as usize;
        assert_eq!(len + 3, ack.len());
        assert_eq!(len, 1 + 4 + 4 + 6 + 2);
        // Version struct check at offset 3+1+4+4 = 12
        let build = u16::from_le_bytes([ack[12], ack[13]]);
        assert_eq!(build, 1000);
        assert_eq!(ack[15], 16); // major
    }

    #[test]
    fn envchange_and_done_layout() {
        let env = build_envchange(envchange_type::DATABASE, "master", "");
        assert_eq!(env[0], token_type::ENVCHANGE);
        let len = u16::from_le_bytes([env[1], env[2]]) as usize;
        assert_eq!(env.len(), len + 3);
        assert_eq!(env[3], envchange_type::DATABASE);

        let done = build_done(done_status::DONE_FINAL);
        assert_eq!(done.len(), 13);
        assert_eq!(done[0], token_type::DONE);
    }

    #[test]
    fn token_stream_concatenates() {
        let stream = token_stream(vec![
            build_login_ack(0x0400_0000, (16, 0, 1000, 6)),
            build_envchange(envchange_type::DATABASE, "master", ""),
            build_done(done_status::DONE_FINAL),
        ]);
        // Walk the stream by token lengths; DONE is fixed-size (no length
        // prefix) while the others carry a 2 byte body length
        let mut i = 0usize;
        let mut kinds = Vec::new();
        while i < stream.len() {
            let kind = stream[i];
            let len = if kind == token_type::DONE {
                13
            } else {
                u16::from_le_bytes([stream[i + 1], stream[i + 2]]) as usize + 3
            };
            kinds.push(kind);
            i += len;
        }
        assert_eq!(i, stream.len(), "stream must be exactly consumed");
        assert_eq!(
            kinds,
            vec![
                token_type::LOGINACK,
                token_type::ENVCHANGE,
                token_type::DONE
            ]
        );
    }
}
