use std::io;

/// Maximum MySQL packet payload size (2^24 - 1). Larger payloads are split
/// across multiple packets.
pub const MAX_PACKET_LEN: usize = 0xFF_FF_FF;

/// Reads one logical MySQL payload. Handles 16MB-1 chunked payloads
/// transparently and advances the sequence id for each packet consumed.
pub async fn read_packet<S>(stream: &mut S, seq: &mut u8) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut payload = Vec::new();
    loop {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        let len = header[0] as usize | (header[1] as usize) << 8 | (header[2] as usize) << 16;
        *seq = header[3].wrapping_add(1);

        let mut chunk = vec![0u8; len];
        stream.read_exact(&mut chunk).await?;
        payload.extend_from_slice(&chunk);

        if len < MAX_PACKET_LEN {
            break;
        }
    }
    Ok(payload)
}

/// Writes one logical MySQL payload, splitting it into 16MB-1 packets when
/// necessary. Uses and advances the shared sequence id.
pub async fn write_packet<S>(stream: &mut S, seq: &mut u8, payload: &[u8]) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let mut rest = payload;
    loop {
        let chunk_len = rest.len().min(MAX_PACKET_LEN);
        let chunk = &rest[..chunk_len];
        let header = [
            (chunk_len & 0xFF) as u8,
            (chunk_len >> 8 & 0xFF) as u8,
            (chunk_len >> 16 & 0xFF) as u8,
            *seq,
        ];
        stream.write_all(&header).await?;
        stream.write_all(chunk).await?;
        *seq = seq.wrapping_add(1);
        rest = &rest[chunk_len..];

        if chunk_len < MAX_PACKET_LEN {
            break;
        }
    }
    stream.flush().await
}

/// Decoding cursor over a received payload
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

#[derive(Debug)]
pub enum ProtocolError {
    UnexpectedEof,
    InvalidUtf8,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::UnexpectedEof => write!(f, "unexpected end of packet"),
            ProtocolError::InvalidUtf8 => write!(f, "invalid utf-8 in packet"),
        }
    }
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn u8(&mut self) -> Result<u8, ProtocolError> {
        let bytes = self.bytes(1)?;
        Ok(bytes[0])
    }

    pub fn u16(&mut self) -> Result<u16, ProtocolError> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn u24(&mut self) -> Result<u32, ProtocolError> {
        let bytes = self.bytes(3)?;
        Ok(bytes[0] as u32 | (bytes[1] as u32) << 8 | (bytes[2] as u32) << 16)
    }

    pub fn u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        if self.remaining() < n {
            return Err(ProtocolError::UnexpectedEof);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// NUL terminated string
    pub fn nul_str(&mut self) -> Result<&'a str, ProtocolError> {
        let rest = &self.buf[self.pos..];
        let end = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(ProtocolError::UnexpectedEof)?;
        let s = std::str::from_utf8(&rest[..end]).map_err(|_| ProtocolError::InvalidUtf8)?;
        self.pos += end + 1;
        Ok(s)
    }

    /// Length encoded binary data (prefix: lenenc integer)
    pub fn lenenc_bytes(&mut self) -> Result<&'a [u8], ProtocolError> {
        let len = self.lenenc_int()?;
        self.bytes(len as usize)
    }

    /// Length encoded integer, returns 0 for NULL (0xFB)
    pub fn lenenc_int(&mut self) -> Result<u64, ProtocolError> {
        match self.u8()? {
            0xFB => Ok(0),
            0xFC => Ok(self.u16()? as u64),
            0xFD => Ok(self.u24()? as u64),
            0xFE => {
                let bytes = self.bytes(8)?;
                Ok(u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
            v => Ok(v as u64),
        }
    }

    /// Consumes and returns everything that is left
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packet_roundtrip() {
        let (mut server, mut client) = tokio::io::duplex(64);

        let payload = b"SELECT 1";
        let mut w_seq = 0u8;
        write_packet(&mut server, &mut w_seq, payload)
            .await
            .unwrap();

        let mut r_seq = 0u8;
        let read = read_packet(&mut client, &mut r_seq).await.unwrap();
        assert_eq!(read, payload);
        assert_eq!(w_seq, 1);
        assert_eq!(r_seq, 1);
    }

    #[test]
    fn cursor_nul_str() {
        let mut c = Cursor::new(b"user\x00db\x00rest");
        assert_eq!(c.nul_str().unwrap(), "user");
        assert_eq!(c.nul_str().unwrap(), "db");
        assert_eq!(c.rest(), b"rest");
    }

    #[test]
    fn cursor_lenenc() {
        let mut c = Cursor::new(&[0x03, b'a', b'b', b'c']);
        assert_eq!(c.lenenc_bytes().unwrap(), b"abc");
    }

    #[test]
    fn cursor_eof() {
        let mut c = Cursor::new(&[0x01, 0x02]);
        c.bytes(2).unwrap();
        assert!(c.u8().is_err());
    }
}
