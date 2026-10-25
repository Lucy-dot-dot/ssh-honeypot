//! TDS packet framing (MS-TDS section 2.2.3).
//!
//! Every packet starts with an 8 byte header:
//! `type(1) status(1) length(2, big endian, inclusive) channel(2, LE)
//! packet_no(1) window(1)`. Payloads themselves are little endian.
//! Logical streams larger than one packet are split; the final packet has
//! the EOM status bit set.

use std::io;

/// Maximum TDS packet payload size per physical packet. The total length
/// field is 2 bytes and inclusive of the 8 byte header, so the largest
/// payload is 0xFFFF - 8.
pub const MAX_PAYLOAD_LEN: usize = 0xFF_F7;

/// Sanity cap for a reassembled logical packet (16 MiB).
pub const MAX_LOGICAL_LEN: usize = 16 * 1024 * 1024;

pub mod packet_type {
    /// Raw SQL batch (TDS 7.4 and earlier, no deprecation)
    pub const SQL_BATCH: u8 = 0x01;
    /// Legacy pre-TDS 7.0 login
    pub const PRE_TDS7_LOGIN: u8 = 0x02;
    /// Remote procedure call
    pub const RPC: u8 = 0x03;
    /// Tabular result stream (server -> client)
    pub const TABULAR_RESULT: u8 = 0x04;
    /// Attention (cancel)
    pub const ATTENTION: u8 = 0x06;
    /// Bulk load
    pub const BULK_LOAD: u8 = 0x07;
    /// Federated authentication (Azure AD continuation)
    pub const FEDAUTH: u8 = 0x08;
    /// LOGIN7 authentication
    pub const LOGIN7: u8 = 0x10;
    /// SSPI authentication continuation (client -> server)
    pub const SSPI_AUTH: u8 = 0x11;
    /// Prelogin negotiation
    pub const PRELOGIN: u8 = 0x12;
}

pub mod status {
    /// End of message: last (or only) physical packet of a logical stream
    pub const EOM: u8 = 0x01;
    /// Ignore this event (client -> server)
    pub const IGNORE: u8 = 0x10;
}

/// One reassembled logical TDS packet
#[derive(Debug)]
pub struct Packet {
    pub ptype: u8,
    pub channel: u16,
    pub payload: Vec<u8>,
}

/// Reads one logical TDS packet, transparently reassembling chunked
/// streams until the EOM status bit is seen.
pub async fn read_packet<S>(stream: &mut S) -> io::Result<Packet>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut payload = Vec::new();
    let (mut ptype, mut channel);
    loop {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header).await?;
        ptype = header[0];
        let status = header[1];
        // Big endian and inclusive of the 8 byte header
        let length = (header[2] as usize) << 8 | header[3] as usize;
        channel = u16::from_le_bytes([header[4], header[5]]);

        if length < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TDS packet with invalid length {length}"),
            ));
        }
        let chunk_len = length - 8;
        if payload.len() + chunk_len > MAX_LOGICAL_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TDS logical packet exceeds size cap",
            ));
        }

        let mut chunk = vec![0u8; chunk_len];
        stream.read_exact(&mut chunk).await?;
        payload.extend_from_slice(&chunk);

        if status & status::EOM != 0 {
            break;
        }
    }

    Ok(Packet {
        ptype,
        channel,
        payload,
    })
}

/// Writes one logical TDS payload, splitting it into physical packets when
/// necessary and setting EOM on the final chunk.
pub async fn write_packet<S>(
    stream: &mut S,
    channel: u16,
    ptype: u8,
    payload: &[u8],
) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let mut packet_no = 0u8;
    let mut rest = payload;
    loop {
        let chunk_len = rest.len().min(MAX_PAYLOAD_LEN);
        let chunk = &rest[..chunk_len];
        let has_more = chunk_len < rest.len();
        let status = if has_more { 0 } else { status::EOM };
        let total = (chunk_len + 8) as u16;

        let header = [
            ptype,
            status,
            (total >> 8) as u8,
            (total & 0xFF) as u8,
            channel as u8,
            (channel >> 8) as u8,
            packet_no,
            0x00, // window
        ];
        stream.write_all(&header).await?;
        stream.write_all(chunk).await?;
        packet_no = packet_no.wrapping_add(1);
        rest = &rest[chunk_len..];

        if !has_more {
            break;
        }
    }
    stream.flush().await
}

/// True when the byte at the start of the stream is a TLS ClientHello
/// (record type 0x16). 0x16 is not a valid TDS packet type, so this safely
/// identifies TDS 8.0 "strict encryption" clients which perform the TLS
/// handshake before the prelogin exchange.
pub fn is_tls_client_hello(first_byte: u8) -> bool {
    first_byte == 0x16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packet_roundtrip() {
        let (mut server, mut client) = tokio::io::duplex(64);

        let payload = vec![0xABu8; 20];
        write_packet(&mut server, 0x1234, packet_type::PRELOGIN, &payload)
            .await
            .unwrap();

        let pkt = read_packet(&mut client).await.unwrap();
        assert_eq!(pkt.ptype, packet_type::PRELOGIN);
        assert_eq!(pkt.channel, 0x1234);
        assert_eq!(pkt.payload, payload);
    }

    #[tokio::test]
    async fn chunked_payload_roundtrip() {
        // Larger than one physical packet forces at least two chunks with
        // EOM only on the final one.
        let payload: Vec<u8> = (0..MAX_PAYLOAD_LEN + 100)
            .map(|i| (i % 251) as u8)
            .collect();
        let expected = payload.clone();

        let (mut server, mut client) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            write_packet(&mut server, 0x0001, packet_type::SQL_BATCH, &payload)
                .await
                .unwrap();
        });

        let pkt = read_packet(&mut client).await.unwrap();
        writer.await.unwrap();
        assert_eq!(pkt.ptype, packet_type::SQL_BATCH);
        assert_eq!(pkt.payload, expected);
    }

    #[test]
    fn tls_hello_detection() {
        assert!(is_tls_client_hello(0x16));
        // Valid TDS packet types must not be mistaken for a TLS handshake
        assert!(!is_tls_client_hello(packet_type::LOGIN7));
        assert!(!is_tls_client_hello(packet_type::PRELOGIN));
    }
}
