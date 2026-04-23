// Wire protocol for git-sign-proxy.
//
// Messages are length-prefixed binary over TCP. One request-response per connection.
//
// Request (client → daemon):
//   [4 bytes: payload length as big-endian u32]
//   [N bytes: the data git wants signed]
//
// Response (daemon → client):
//   [1 byte: status — 0x00 success, 0x01 validation error, 0x02 signing error]
//   [4 bytes: payload length as big-endian u32]
//   [N bytes: signature (success) or error message (failure)]

use std::io::{self, Read, Write};

/// Maximum allowed payload size (1 MB). Anything larger is rejected immediately.
pub const MAX_PAYLOAD_SIZE: u32 = 1_048_576;

/// Status codes in the response.
/// repr(u8) means each variant is stored as a single byte.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Status {
    Success = 0x00,
    ValidationError = 0x01,
    SigningError = 0x02,
}

impl Status {
    /// Convert a raw byte back into a Status enum.
    /// Returns None if the byte doesn't match any known status.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Success),
            0x01 => Some(Self::ValidationError),
            0x02 => Some(Self::SigningError),
            _ => None,
        }
    }
}

/// A signing request: just the raw bytes git wants signed.
#[derive(Debug)]
pub struct Request {
    pub payload: Vec<u8>,
}

/// A signing response: status code + body (signature or error message).
#[derive(Debug)]
pub struct Response {
    pub status: Status,
    pub body: Vec<u8>,
}

/// Write a request to any stream that implements Write (e.g., a TCP socket).
/// Format: [4-byte length][payload bytes]
pub fn write_request(writer: &mut impl Write, req: &Request) -> io::Result<()> {
    let len = req.payload.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&req.payload)?;
    writer.flush()
}

/// Read a request from any stream that implements Read.
/// Returns an error if the payload exceeds MAX_PAYLOAD_SIZE.
pub fn read_request(reader: &mut impl Read) -> io::Result<Request> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);

    if len > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload too large: {} bytes (max {})", len, MAX_PAYLOAD_SIZE),
        ));
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    Ok(Request { payload })
}

/// Write a response to any stream that implements Write.
/// Format: [1-byte status][4-byte length][body bytes]
pub fn write_response(writer: &mut impl Write, resp: &Response) -> io::Result<()> {
    writer.write_all(&[resp.status as u8])?;
    let len = resp.body.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&resp.body)?;
    writer.flush()
}

/// Read a response from any stream that implements Read.
pub fn read_response(reader: &mut impl Read) -> io::Result<Response> {
    let mut status_buf = [0u8; 1];
    reader.read_exact(&mut status_buf)?;
    let status = Status::from_byte(status_buf[0]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown status byte: 0x{:02x}", status_buf[0]),
        )
    })?;

    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);

    if len > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("response too large: {} bytes", len),
        ));
    }

    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    Ok(Response { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip_request() {
        let req = Request {
            payload: b"tree 0000000000000000000000000000000000000000\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\ntest".to_vec(),
        };
        let mut buf = Vec::new();
        write_request(&mut buf, &req).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_request(&mut cursor).unwrap();
        assert_eq!(decoded.payload, req.payload);
    }

    #[test]
    fn round_trip_response_success() {
        let resp = Response {
            status: Status::Success,
            body: b"-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----".to_vec(),
        };
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_response(&mut cursor).unwrap();
        assert_eq!(decoded.status, Status::Success);
        assert_eq!(decoded.body, resp.body);
    }

    #[test]
    fn round_trip_response_error() {
        let resp = Response {
            status: Status::ValidationError,
            body: b"not a valid git object".to_vec(),
        };
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_response(&mut cursor).unwrap();
        assert_eq!(decoded.status, Status::ValidationError);
        assert_eq!(decoded.body, resp.body);
    }

    #[test]
    fn rejects_oversized_request() {
        let len: u32 = 2_000_000;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_be_bytes());
        let mut cursor = Cursor::new(buf);
        let result = read_request(&mut cursor);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn rejects_unknown_status_byte() {
        let mut buf = Vec::new();
        buf.push(0xFF);
        buf.extend_from_slice(&0u32.to_be_bytes());
        let mut cursor = Cursor::new(buf);
        let result = read_response(&mut cursor);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown status"));
    }
}
