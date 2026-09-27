//! Canonical URLs and the key they map to.

use url::Url;

use crate::{Digest, Error};

/// Canonicalize a URL for witnessing: http(s) only, no fragment, no empty
/// query, no credentials. Host case and default ports are already normalized
/// by the `url` crate's WHATWG parser.
pub fn canonical_url(input: &str) -> Result<Url, Error> {
    let mut u = Url::parse(input.trim()).map_err(|_| Error::Malformed("unparseable URL"))?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err(Error::Malformed(
            "only http and https URLs can be witnessed",
        ));
    }
    if u.host_str().is_none() {
        return Err(Error::Malformed("URL has no host"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(Error::Malformed(
            "URLs with credentials cannot be witnessed",
        ));
    }
    u.set_fragment(None);
    if u.query() == Some("") {
        u.set_query(None);
    }
    Ok(u)
}

/// The key a URL is filed under in the DHT and in assignment.
pub fn url_key(canonical: &Url) -> Digest {
    Digest::tagged("witness url-key v1", &[canonical.as_str().as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes() {
        let u = canonical_url("HTTPS://Example.COM:443/a/../b?#frag").unwrap();
        assert_eq!(u.as_str(), "https://example.com/b");
        assert!(canonical_url("ftp://example.com").is_err());
        assert!(canonical_url("https://user:pw@example.com").is_err());
        assert_eq!(
            url_key(&canonical_url("https://example.com/b#x").unwrap()),
            url_key(&u)
        );
    }
}
