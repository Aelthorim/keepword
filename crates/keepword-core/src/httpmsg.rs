//! Minimal HTTP/1.x response parsing for transcripts proven with TLSNotary.
//!
//! A TLSNotary transcript holds the raw response bytes. To link it to an
//! attestation, prover and verifier derive the header block and body the
//! same way: status line and end-to-end header lines exactly as received,
//! hop-by-hop headers dropped, body de-chunked.

use crate::Error;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: Option<String>,
    /// Status line and end-to-end headers, CRLF-terminated, ending in a
    /// blank line.
    pub header_block: Vec<u8>,
    pub body: Vec<u8>,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn parse_response(raw: &[u8]) -> Result<Response, Error> {
    let end = find(raw, b"\r\n\r\n").ok_or(Error::Malformed("HTTP response has no header end"))?;
    let head = std::str::from_utf8(&raw[..end])
        .map_err(|_| Error::Malformed("HTTP headers are not UTF-8"))?;
    let rest = &raw[end + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(Error::Malformed("not an HTTP/1.x response"));
    }
    let status: u16 = parts
        .next()
        .and_then(|c| c.parse().ok())
        .ok_or(Error::Malformed("bad HTTP status code"))?;

    let mut block = Vec::with_capacity(end + 4);
    block.extend_from_slice(status_line.as_bytes());
    block.extend_from_slice(b"\r\n");
    let (mut chunked, mut length, mut content_type) = (false, None, None);
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(Error::Malformed("bad HTTP header line"))?;
        let lname = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match lname.as_str() {
            "transfer-encoding" => chunked |= value.to_ascii_lowercase().contains("chunked"),
            "content-length" => length = value.parse::<usize>().ok(),
            "content-type" => content_type = Some(value.to_string()),
            _ => {}
        }
        if HOP_BY_HOP.contains(&lname.as_str()) {
            continue;
        }
        block.extend_from_slice(line.as_bytes());
        block.extend_from_slice(b"\r\n");
    }
    block.extend_from_slice(b"\r\n");

    let body = if chunked {
        dechunk(rest)?
    } else if let Some(n) = length {
        rest.get(..n)
            .ok_or(Error::Malformed("HTTP body shorter than Content-Length"))?
            .to_vec()
    } else {
        rest.to_vec()
    };
    Ok(Response {
        status,
        content_type,
        header_block: block,
        body,
    })
}

fn dechunk(mut b: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    loop {
        let eol = find(b, b"\r\n").ok_or(Error::Malformed("truncated chunk header"))?;
        let size_str =
            std::str::from_utf8(&b[..eol]).map_err(|_| Error::Malformed("bad chunk size"))?;
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(size_str, 16).map_err(|_| Error::Malformed("bad chunk size"))?;
        b = &b[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        let chunk = b.get(..size).ok_or(Error::Malformed("truncated chunk"))?;
        out.extend_from_slice(chunk);
        b = b
            .get(size + 2..)
            .ok_or(Error::Malformed("truncated chunk"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_and_hop_by_hop() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
        assert_eq!(r.content_type.as_deref(), Some("text/html"));
        assert_eq!(
            r.header_block,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\n"
        );
    }

    #[test]
    fn chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n6;x=y\r\npedia \r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.body, b"Wikipedia ");
        assert!(!String::from_utf8_lossy(&r.header_block).contains("chunked"));
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").is_err()
        );
        assert!(parse_response(b"garbage").is_err());
    }
}
