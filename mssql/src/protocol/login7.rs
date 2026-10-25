//! LOGIN7 authentication packet (MS-TDS 2.2.6.4).
//!
//! The client's credentials arrive in a fixed 36 byte header followed by
//! offset/length pairs pointing into the packet payload. Character data is
//! UTF-16LE; the password is obfuscated with a reversible XOR 0xA5 byte
//! transform — every credential the client sends is fully recoverable.
//!
//! Authentication methods distinguishable here:
//! - SQL Server authentication (username + obfuscated password)
//! - Windows Integrated Auth (OptionFlags2 bit 0, SSPI blob in the SSPI
//!   slot; NTLM or Kerberos/SPNEGO)
//! - Azure AD / Entra ID (OptionFlags2 bits 4-7): mechanism 0x01 puts a
//!   principal+secret in the user/password fields, mechanism 0x02 puts a
//!   bearer token in the SSPI slot.

/// Fixed size of the LOGIN7 header (through ClientLCID)
const FIXED_HEADER_LEN: usize = 36;
/// Number of variable-length offset/length pairs before the ClientID
const VARIABLE_FIELD_COUNT: usize = 8;
/// Size of the 6 byte ClientID (MAC address)
const CLIENT_ID_LEN: usize = 6;
/// Size of one offset/length pair
const OFFSET_LEN_PAIR: usize = 4;

/// Total size of everything after the fixed header: 8 variable field
/// pairs, ClientID, SSPI pair, AttachDBFile pair.
const FIXED_TAIL_LEN: usize =
    VARIABLE_FIELD_COUNT * OFFSET_LEN_PAIR + CLIENT_ID_LEN + 2 * OFFSET_LEN_PAIR;

pub mod fedauth_mechanism {
    /// No federated authentication
    pub const NONE: u8 = 0x0;
    /// Federated auth via password secret in the user/password fields
    pub const PASSWORD: u8 = 0x01;
    /// Federated auth via security token carried in the SSPI slot
    pub const TOKEN: u8 = 0x02;
}

/// Parsed LOGIN7 packet. String fields that fall outside the packet (or
/// fail to decode) become None rather than failing the whole parse —
/// attackers send all kinds of garbage and we want to record it anyway.
#[derive(Debug, Default, Clone)]
pub struct Login7 {
    /// TDS version announced by the client, e.g. 7.4
    pub tds_version_major: u8,
    pub tds_version_minor: u8,
    /// Requested packet buffer size in bytes
    pub packet_size: u32,
    /// Client computer name
    pub client_name: Option<String>,
    /// Username / principal
    pub username: Option<String>,
    /// De-obfuscated password / secret (None with integrated security)
    pub password: Option<String>,
    /// Application name — often fingerprints the attacking toolset
    pub app_name: Option<String>,
    /// Server name the client believes it is connecting to
    pub server_name: Option<String>,
    pub language: Option<String>,
    /// Initial database requested by the client
    pub database: Option<String>,
    /// Raw SSPI / federated auth token bytes (None when absent)
    pub sspi: Option<Vec<u8>>,
    /// AttachDB filename (rarely used)
    pub attach_db: Option<String>,
    /// OptionFlags1 as sent (byte order, charset, float, dump/load, ...)
    pub option_flags1: u8,
    /// OptionFlags2 as sent: bit 0 = fIntSecurity, bits 4-7 = fFedAuth
    pub option_flags2: u8,
    /// True when OptionFlags2 bit 0 requests integrated security
    pub integrated_security: bool,
    /// Federated auth mechanism (upper nibble of OptionFlags2)
    pub fedauth_mechanism: u8,
}

/// De-obfuscates the LOGIN7 password: XOR 0xA5 over the UTF-16LE encoding.
pub fn deobfuscate_password(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let lo = chunk[0] ^ 0xA5;
        let hi = chunk.get(1).map(|b| b ^ 0xA5).unwrap_or(0);
        units.push(u16::from_le_bytes([lo, hi]));
    }
    String::from_utf16_lossy(&units)
}

/// Obfuscates a password the same way (used for tests and tooling).
#[cfg(test)]
pub fn obfuscate_password(password: &str) -> Vec<u8> {
    password
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .map(|b| b ^ 0xA5)
        .collect()
}

impl Login7 {
    /// Parses a LOGIN7 payload (the packet payload without the TDS header).
    /// Returns None only when the packet is too short to be LOGIN7 at all.
    pub fn parse(payload: &[u8]) -> Option<Login7> {
        if payload.len() < FIXED_HEADER_LEN + FIXED_TAIL_LEN {
            return None;
        }

        let u16le = |buf: &[u8], off: usize| u16::from_le_bytes([buf[off], buf[off + 1]]);
        let u32le = |buf: &[u8], off: usize| {
            u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
        };

        let tds_version = u32le(payload, 4);
        let packet_size = u32le(payload, 8);
        let option_flags1 = payload[24];
        let option_flags2 = payload[25];

        // Variable field pairs start after the fixed header
        let base = FIXED_HEADER_LEN;
        let field = |i: usize| -> (usize, usize) {
            let off = base + i * OFFSET_LEN_PAIR;
            (
                u16le(payload, off) as usize,
                u16le(payload, off + 2) as usize,
            )
        };
        let (client_name, username, password, app_name, server_name, _unused, language, database) = (
            field(0),
            field(1),
            field(2),
            field(3),
            field(4),
            field(5),
            field(6),
            field(7),
        );

        // After the 8 variable pairs sits the 6 byte ClientID (client MAC),
        // then the SSPI and AttachDBFile pairs.
        let tail_pair = |i: usize| -> (usize, usize) {
            let off =
                base + VARIABLE_FIELD_COUNT * OFFSET_LEN_PAIR + CLIENT_ID_LEN + i * OFFSET_LEN_PAIR;
            (
                u16le(payload, off) as usize,
                u16le(payload, off + 2) as usize,
            )
        };
        let sspi = tail_pair(0);
        let attach_db = tail_pair(1);

        let str_field = |(offset, length): (usize, usize)| -> Option<String> {
            if length == 0 || offset >= payload.len() || offset + length > payload.len() {
                return None;
            }
            let bytes = &payload[offset..offset + length];
            let units: Vec<u16> = bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect();
            // Trailing NUL terminators are common
            let s = String::from_utf16_lossy(&units)
                .trim_end_matches('\0')
                .to_string();
            if s.is_empty() { None } else { Some(s) }
        };

        let raw_field = |(offset, length): (usize, usize)| -> Option<Vec<u8>> {
            if length == 0 || offset >= payload.len() || offset + length > payload.len() {
                return None;
            }
            Some(payload[offset..offset + length].to_vec())
        };

        let integrated_security = option_flags2 & 0x01 != 0;
        let fedauth_mechanism = (option_flags2 >> 4) & 0x0F;

        Some(Login7 {
            tds_version_major: (tds_version >> 24) as u8,
            tds_version_minor: ((tds_version >> 16) & 0xFF) as u8,
            packet_size,
            client_name: str_field(client_name),
            username: str_field(username),
            password: if integrated_security {
                None
            } else {
                raw_field(password)
                    .filter(|b| !b.is_empty())
                    .map(|b| deobfuscate_password(&b))
            },
            app_name: str_field(app_name),
            server_name: str_field(server_name),
            language: str_field(language),
            database: str_field(database),
            sspi: raw_field(sspi),
            attach_db: str_field(attach_db),
            option_flags1,
            option_flags2,
            integrated_security,
            fedauth_mechanism,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal but well-formed LOGIN7 payload for testing:
    /// 36 byte header, 8 field pairs + ClientID + SSPI pair + AttachDB
    /// pair (46 bytes of tail), then the data section.
    fn build_login(username: &str, password: &str, sspi: Option<&[u8]>, flags2: u8) -> Vec<u8> {
        const TAIL_LEN: usize = 8 * 4 + 6 + 4 + 4;
        const DATA_START: usize = FIXED_HEADER_LEN + TAIL_LEN;

        let mut data = Vec::new();
        let mut fields: Vec<(u16, u16)> = Vec::new();

        let push_str = |fields: &mut Vec<(u16, u16)>, data: &mut Vec<u8>, s: &str| {
            let mut bytes: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            bytes.push(0);
            bytes.push(0);
            fields.push(((DATA_START + data.len()) as u16, bytes.len() as u16));
            data.extend_from_slice(&bytes);
        };

        push_str(&mut fields, &mut data, "ATTACKER-PC"); // client name
        push_str(&mut fields, &mut data, username); // username
        if sspi.is_none() {
            let obf = obfuscate_password(password);
            fields.push(((DATA_START + data.len()) as u16, obf.len() as u16));
            data.extend_from_slice(&obf);
        } else {
            fields.push(((DATA_START + data.len()) as u16, 0u16));
        }
        push_str(&mut fields, &mut data, "sqlmap"); // app name
        push_str(&mut fields, &mut data, "MSSQLSERVER"); // server name
        fields.push((0, 0)); // unused
        fields.push((0, 0)); // language
        push_str(&mut fields, &mut data, "master"); // database

        let sspi_off = DATA_START + data.len();
        let sspi_entry = match sspi {
            Some(blob) => {
                let entry = (sspi_off as u16, blob.len() as u16);
                data.extend_from_slice(blob);
                entry
            }
            None => (sspi_off as u16, 0u16),
        };

        let mut packet = vec![0u8; FIXED_HEADER_LEN];
        packet[0..4].copy_from_slice(&((DATA_START + data.len()) as u32).to_le_bytes());
        packet[4..8].copy_from_slice(&0x0400_0000u32.to_le_bytes()); // TDS 7.4
        packet[8..12].copy_from_slice(&8000u32.to_le_bytes()); // packet size
        packet[25] = flags2;
        for (off, len) in &fields {
            packet.extend_from_slice(&off.to_le_bytes());
            packet.extend_from_slice(&len.to_le_bytes());
        }
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34]); // ClientID
        packet.extend_from_slice(&sspi_entry.0.to_le_bytes());
        packet.extend_from_slice(&sspi_entry.1.to_le_bytes());
        packet.extend_from_slice(&0u16.to_le_bytes()); // attach db offset
        packet.extend_from_slice(&0u16.to_le_bytes()); // attach db length
        packet.extend_from_slice(&data);
        packet
    }

    #[test]
    fn password_deobfuscation_roundtrip() {
        let obf = obfuscate_password("P@ssw0rd!");
        assert_eq!(deobfuscate_password(&obf), "P@ssw0rd!");
        // Empty password still decodes
        assert_eq!(deobfuscate_password(&obfuscate_password("")), "");
    }

    #[test]
    fn parse_sql_auth_login() {
        let packet = build_login("sa", "hunter2", None, 0x00);
        let login = Login7::parse(&packet).expect("parse");
        // TDS 7.4 is encoded 0x04000000: the byte at >>24 carries the
        // post-7.0 subversion, not a literal major of 7
        assert_eq!(login.tds_version_major, 4);
        assert_eq!(login.tds_version_minor, 0);
        assert_eq!(login.packet_size, 8000);
        assert_eq!(login.client_name.as_deref(), Some("ATTACKER-PC"));
        assert_eq!(login.username.as_deref(), Some("sa"));
        assert_eq!(login.password.as_deref(), Some("hunter2"));
        assert_eq!(login.app_name.as_deref(), Some("sqlmap"));
        assert_eq!(login.database.as_deref(), Some("master"));
        assert!(!login.integrated_security);
        assert_eq!(login.fedauth_mechanism, 0);
        assert!(login.sspi.is_none());
    }

    #[test]
    fn parse_integrated_security_login() {
        let ntlm = b"NTLMSSP\0\x01\x00\x00\x00";
        let packet = build_login("", "", Some(ntlm), 0x01); // fIntSecurity
        let login = Login7::parse(&packet).expect("parse");
        assert!(login.integrated_security);
        assert!(login.password.is_none());
        assert_eq!(login.sspi.as_deref(), Some(&ntlm[..]));
    }

    #[test]
    fn parse_fedauth_token_login() {
        let token = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake";
        let packet = build_login("", "", Some(token), 0x20); // mechanism 0x02
        let login = Login7::parse(&packet).expect("parse");
        assert_eq!(login.fedauth_mechanism, fedauth_mechanism::TOKEN);
        assert_eq!(login.sspi.as_deref(), Some(&token[..]));
    }

    #[test]
    fn truncated_packet_is_rejected() {
        assert!(Login7::parse(&[0u8; 10]).is_none());
        assert!(Login7::parse(&[]).is_none());
    }
}
