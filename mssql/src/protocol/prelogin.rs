//! PRELOGIN negotiation (MS-TDS 2.2.6.4).
//!
//! The first exchange on a plain TCP connection. Both directions send a
//! list of option descriptors (`type, offset(2 BE), length(2 BE)` followed
//! by a 0xFF terminator) with the option data after the table. The only
//! option that matters to the honeypot is ENCRYPTION.

/// ENCRYPTION values
pub mod encryption {
    /// Encryption is available but off: the client may still encrypt the
    /// login sequence (and TDS 8.0-capable stacks may upgrade voluntarily).
    pub const ENCRYPT_OFF: u8 = 0x00;
    /// Full encryption from the first packet after prelogin
    pub const ENCRYPT_ON: u8 = 0x01;
    /// Encryption not supported: the client must not attempt a TLS upgrade
    pub const ENCRYPT_NOT_SUP: u8 = 0x02;
    /// Encryption required
    pub const ENCRYPT_REQ: u8 = 0x03;
}

pub mod option_type {
    pub const VERSION: u8 = 0x00;
    pub const ENCRYPTION: u8 = 0x01;
    pub const INSTOPT: u8 = 0x02;
    pub const THREADID: u8 = 0x03;
    pub const MARS: u8 = 0x04;
    pub const TRACEID: u8 = 0x05;
    pub const TERMINATOR: u8 = 0xFF;
}

/// Parsed client prelogin request (only what the honeypot needs)
#[derive(Debug, Default)]
pub struct PreloginRequest {
    /// Client's desired encryption level
    pub encryption: Option<u8>,
    /// Whether the client requested MARS
    pub mars: Option<u8>,
    /// Instance name requested by the client (empty for default)
    pub instance: Option<String>,
}

/// Parses a client PRELOGIN payload. Never fails: unknown/malformed
/// options are skipped, a truncated request yields what was readable.
pub fn parse_request(payload: &[u8]) -> PreloginRequest {
    let mut req = PreloginRequest::default();
    let mut i = 0usize;
    while i + 5 <= payload.len() {
        let opt = payload[i];
        if opt == option_type::TERMINATOR {
            break;
        }
        let offset = ((payload[i + 1] as usize) << 8) | payload[i + 2] as usize;
        let length = ((payload[i + 3] as usize) << 8) | payload[i + 4] as usize;
        i += 5;

        let data = if offset <= payload.len() && offset + length <= payload.len() && length > 0 {
            &payload[offset..offset + length]
        } else {
            continue;
        };

        match opt {
            option_type::ENCRYPTION => req.encryption = Some(data[0]),
            option_type::MARS => req.mars = Some(data[0]),
            option_type::INSTOPT => {
                // INSTOPT: bit 0-5 = instance name length (0 => default
                // instance), remaining bits reserved
                let name_len = (data[0] & 0x3F) as usize;
                if name_len > 1 && data.len() >= name_len {
                    req.instance = Some(
                        String::from_utf8_lossy(&data[1..name_len])
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
            }
            _ => {}
        }
    }
    req
}

/// Builds the server PRELOGIN response advertising the given ENCRYPTION
/// flag and our version struct. MARS is echoed only when the client asked
/// for it, mirroring real server behaviour.
pub fn build_response(encrypt_flag: u8, version: (u8, u8, u16, u16), client_mars: bool) -> Vec<u8> {
    let (major, minor, build, subbuild) = version;
    let mut version_bytes = Vec::with_capacity(6);
    version_bytes.extend_from_slice(&build.to_le_bytes());
    version_bytes.push(minor);
    version_bytes.push(major);
    version_bytes.extend_from_slice(&subbuild.to_le_bytes());

    // Option table: 5 bytes per option + terminator, then the data section.
    // A MARS option in the table shifts where the data section begins.
    let option_count = if client_mars { 5 } else { 4 };
    let data_start = 5usize * option_count + 1;

    let mars_len = if client_mars { 1 } else { 0 };
    let version_off = data_start;
    let encryption_off = version_off + 6;
    let instopt_off = encryption_off + 1;
    let threadid_off = instopt_off + 1;
    let mars_off = threadid_off + 4;

    let mut out = Vec::with_capacity(mars_off + mars_len);
    let push_option = |out: &mut Vec<u8>, opt: u8, offset: usize, length: usize| {
        out.push(opt);
        out.extend_from_slice(&(offset as u16).to_be_bytes());
        out.extend_from_slice(&(length as u16).to_be_bytes());
    };

    push_option(&mut out, option_type::VERSION, version_off, 6);
    push_option(&mut out, option_type::ENCRYPTION, encryption_off, 1);
    push_option(&mut out, option_type::INSTOPT, instopt_off, 1);
    push_option(&mut out, option_type::THREADID, threadid_off, 4);
    if client_mars {
        push_option(&mut out, option_type::MARS, mars_off, 1);
    }
    out.push(option_type::TERMINATOR);

    // Data section
    out.extend_from_slice(&version_bytes);
    out.push(encrypt_flag);
    out.push(0x00); // INSTOPT: default instance
    out.extend_from_slice(&0u32.to_le_bytes()); // THREADID
    if client_mars {
        out.push(0x00); // MARS: not allowed
    }
    out
}

/// Parses a "16.0.1000.6" style version string into the TDS version struct
/// components `(major, minor, build, subbuild)`.
pub fn parse_version_string(s: &str) -> (u8, u8, u16, u16) {
    let parts: Vec<&str> = s.split('.').collect();
    let num = |i: usize| {
        parts
            .get(i)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0)
    };
    (
        num(0).clamp(0, 255) as u8,
        num(1).clamp(0, 255) as u8,
        num(2).clamp(0, 65535) as u16,
        num(3).clamp(0, 65535) as u16,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_parsing() {
        assert_eq!(parse_version_string("16.0.1000.6"), (16, 0, 1000, 6));
        assert_eq!(parse_version_string("15.0.2000"), (15, 0, 2000, 0));
        assert_eq!(parse_version_string("garbage"), (0, 0, 0, 0));
    }

    #[test]
    fn response_layout_is_parseable() {
        let resp = build_response(encryption::ENCRYPT_OFF, (16, 0, 1000, 6), false);
        // Walk the option table
        let mut i = 0usize;
        let mut seen = Vec::new();
        loop {
            assert!(i + 5 <= resp.len());
            let opt = resp[i];
            if opt == option_type::TERMINATOR {
                break;
            }
            let offset = ((resp[i + 1] as usize) << 8) | resp[i + 2] as usize;
            let length = ((resp[i + 3] as usize) << 8) | resp[i + 4] as usize;
            assert!(
                offset + length <= resp.len(),
                "option {opt:#x} out of bounds"
            );
            seen.push((opt, &resp[offset..offset + length]));
            i += 5;
        }

        let version = seen
            .iter()
            .find(|(o, _)| *o == option_type::VERSION)
            .unwrap();
        assert_eq!(version.1.len(), 6);
        // build(2 LE) minor(1) major(1) subbuild(2 LE)
        assert_eq!(version.1[3], 16);

        let enc = seen
            .iter()
            .find(|(o, _)| *o == option_type::ENCRYPTION)
            .unwrap();
        assert_eq!(enc.1[0], encryption::ENCRYPT_OFF);

        // No MARS option when the client did not request it
        assert!(!seen.iter().any(|(o, _)| *o == option_type::MARS));
    }

    #[test]
    fn parse_client_request() {
        // Minimal request: VERSION + ENCRYPTION + terminator, data section
        let mut req = vec![
            0x00, 0x00, 0x0B, 0x00, 0x06, // VERSION at 11, len 6
            0x01, 0x00, 0x11, 0x00, 0x01, // ENCRYPTION at 17, len 1
            0xFF, // terminator
        ];
        while req.len() < 11 {
            req.push(0);
        }
        req.extend_from_slice(&[0xE8, 0x03, 0x00, 0x10, 0x00, 0x00]); // version data
        req.push(0x03); // ENCRYPT_REQ

        let parsed = parse_request(&req);
        assert_eq!(parsed.encryption, Some(3));
    }
}
