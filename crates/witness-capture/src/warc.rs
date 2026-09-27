//! WARC 1.1 export (ISO 28500), for interop with archiving tools.
//!
//! WARC files aren't stored: each carries per-capture record headers, which
//! would defeat content-addressed deduplication. Instead a WARC is rebuilt on
//! demand from the attestation and the header/body blobs. Record IDs derive
//! from the attestation ID, so the export is deterministic.

use witness_core::{format_ms, SignedAttestation};

fn uuid_urn(seed: &[u8; 32], n: u8) -> String {
    let mut b = [0u8; 16];
    b.copy_from_slice(&seed[..16]);
    b[15] ^= n;
    b[6] = (b[6] & 0x0f) | 0x80; // version 8: custom
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    let h = hex_lower(&b);
    format!(
        "<urn:uuid:{}-{}-{}-{}-{}>",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn record(out: &mut Vec<u8>, fields: &[(&str, String)], block: &[u8]) {
    out.extend_from_slice(b"WARC/1.1\r\n");
    for (k, v) in fields {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", block.len()).as_bytes());
    out.extend_from_slice(block);
    out.extend_from_slice(b"\r\n\r\n");
}

/// Build a WARC file with a `warcinfo`, a `response` (or `resource` for
/// rendered captures) and a `metadata` record holding the signed attestation.
pub fn export(att: &SignedAttestation, headers: &[u8], body: &[u8]) -> Vec<u8> {
    let a = &att.attestation;
    let id = att.id();
    let date = format_ms(a.fetched_at_ms);
    let mut out = Vec::new();

    let info = format!(
        "software: witness/{}\r\nformat: WARC File Format 1.1\r\nwitness-key: {}\r\n",
        env!("CARGO_PKG_VERSION"),
        a.witness
    );
    record(
        &mut out,
        &[
            ("WARC-Type", "warcinfo".into()),
            ("WARC-Record-ID", uuid_urn(id.as_bytes(), 0)),
            ("WARC-Date", date.clone()),
            ("Content-Type", "application/warc-fields".into()),
        ],
        info.as_bytes(),
    );

    let response_id = uuid_urn(id.as_bytes(), 1);
    let mut fields = vec![
        ("WARC-Record-ID", response_id.clone()),
        ("WARC-Date", date.clone()),
        ("WARC-Target-URI", a.final_url.clone()),
        ("WARC-Payload-Digest", format!("blake3:{}", a.body_hash)),
    ];
    if let Some(ip) = a.server_ip {
        fields.push(("WARC-IP-Address", ip.to_string()));
    }
    let block = match a.method {
        witness_core::CaptureMethod::Http => {
            fields.insert(0, ("WARC-Type", "response".into()));
            fields.push(("Content-Type", "application/http;msgtype=response".into()));
            let mut b = headers.to_vec();
            b.extend_from_slice(body);
            b
        }
        witness_core::CaptureMethod::Rendered => {
            fields.insert(0, ("WARC-Type", "resource".into()));
            fields.push(("Content-Type", "text/html".into()));
            body.to_vec()
        }
    };
    record(&mut out, &fields, &block);

    let meta = serde_json::to_vec_pretty(att).expect("attestation serializes");
    record(
        &mut out,
        &[
            ("WARC-Type", "metadata".into()),
            ("WARC-Record-ID", uuid_urn(id.as_bytes(), 2)),
            ("WARC-Date", date),
            ("WARC-Target-URI", a.final_url.clone()),
            ("WARC-Refers-To", response_id),
            (
                "Content-Type",
                "application/vnd.witness.attestation+json".into(),
            ),
        ],
        &meta,
    );
    out
}
