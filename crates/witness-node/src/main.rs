use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use witness_core::bundle::{Bundle, Report, Status};
use witness_core::{format_ms, merkle, now_ms, target};
use witness_node::config::{Config, ContentConfig, Retain, VantageConfig};
use witness_node::{method_name, parse_time, Node, Outcome};
use witness_normalize::diff;

#[derive(Parser)]
#[command(
    name = "witness",
    version,
    about = "Independent, verifiable records of what web pages said"
)]
struct Cli {
    /// Node data directory.
    #[arg(
        long,
        global = true,
        env = "WITNESS_DIR",
        default_value = "./witness-data"
    )]
    dir: PathBuf,
    /// Print machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a node: key, config and empty log.
    Init {
        /// ASN this node fetches from (e.g. 3320).
        #[arg(long)]
        asn: Option<u32>,
        /// ISO country code of this node (e.g. DE).
        #[arg(long)]
        country: Option<String>,
        /// What content to keep: full, normalized or none.
        #[arg(long, default_value = "full", value_parser = parse_retain)]
        retain: Retain,
    },
    /// Show this node's identity and log head.
    Id,
    /// Fetch a URL now, attest to it and log the attestation.
    Capture {
        url: String,
        /// Render with a headless browser instead of raw HTTP.
        #[arg(long)]
        render: bool,
    },
    /// Verify an attestation from this node's store, or a bundle file.
    Verify {
        /// URL or attestation ID (prefix). Omit with --bundle.
        reference: Option<String>,
        /// Point in time for URL lookups (RFC 3339 or YYYY-MM-DD).
        #[arg(long)]
        at: Option<String>,
        /// Verify a bundle file instead of the local store.
        #[arg(long, conflicts_with = "reference")]
        bundle: Option<PathBuf>,
    },
    /// Write a self-contained evidence bundle anyone can verify.
    Export {
        reference: String,
        #[arg(long)]
        at: Option<String>,
        /// Leave out headers, body and normalized text.
        #[arg(long)]
        no_content: bool,
        /// Output file (default: stdout).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Rebuild a WARC file for a capture.
    Warc {
        reference: String,
        #[arg(long)]
        at: Option<String>,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// List captures of a URL and where its content changed.
    History { url: String },
    /// Diff two captures (IDs), or the last two versions of a URL.
    Diff { a: String, b: Option<String> },
    /// Manage the watchlist.
    Watch {
        #[command(subcommand)]
        cmd: WatchCmd,
    },
    /// Inspect and audit this node's log.
    Log {
        #[command(subcommand)]
        cmd: LogCmd,
    },
    /// Delete stored content for a URL (for example after an erasure request).
    Purge {
        url: String,
        /// Also delete the attestations. The log keeps only opaque IDs.
        #[arg(long)]
        forget: bool,
    },
    /// Serve the web UI (read-only) and optionally run the watch scheduler.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8480")]
        addr: String,
        /// Also capture watched URLs when due.
        #[arg(long)]
        watch: bool,
    },
}

#[derive(Subcommand)]
enum WatchCmd {
    /// Watch a URL.
    Add {
        url: String,
        /// Capture interval, e.g. 30m, 6h, 1day.
        #[arg(long, default_value = "1h", value_parser = humantime::parse_duration)]
        every: Duration,
        #[arg(long)]
        render: bool,
    },
    /// Stop watching a URL.
    Rm { url: String },
    /// List watched URLs.
    List,
    /// Capture due URLs, forever or once.
    Run {
        #[arg(long)]
        once: bool,
    },
}

#[derive(Subcommand)]
enum LogCmd {
    /// Print the latest signed tree head.
    Head,
    /// Print a consistency proof between two tree sizes.
    Consistency {
        old: u64,
        /// Defaults to the current size.
        new: Option<u64>,
    },
    /// Re-verify the entire log and store.
    Audit,
}

fn parse_retain(s: &str) -> Result<Retain, String> {
    match s {
        "full" => Ok(Retain::Full),
        "normalized" => Ok(Retain::Normalized),
        "none" => Ok(Retain::None),
        _ => Err("expected full, normalized or none".into()),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(2);
        }
    }
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn at_ms(at: &Option<String>) -> Result<Option<i64>> {
    at.as_deref().map(parse_time).transpose()
}

/// Returns Ok(false) when a verification failed.
async fn run(cli: Cli) -> Result<bool> {
    let dir = cli.dir.clone();
    match cli.cmd {
        Cmd::Init {
            asn,
            country,
            retain,
        } => {
            let cfg = Config {
                vantage: VantageConfig {
                    asn,
                    country: country.map(|c| c.to_ascii_uppercase()),
                },
                content: ContentConfig { retain },
                ..Config::default()
            };
            let key = Node::init(&dir, &cfg)?;
            println!("initialized witness node in {}", dir.display());
            println!("witness key: {}", key.public());
            if asn.is_none() {
                println!(
                    "hint: set vantage.asn and vantage.country in {} before joining a network",
                    dir.join("witness.toml").display()
                );
            }
        }
        Cmd::Id => {
            let node = Node::open(&dir)?;
            let head = node.store.latest_tree_head()?;
            if cli.json {
                print_json(
                    &serde_json::json!({ "witness": node.key.public(), "tree_head": head }),
                )?;
            } else {
                println!("witness key: {}", node.key.public());
                match head {
                    Some(h) => println!(
                        "log: {} entries, root {}, signed {}",
                        h.head.size,
                        h.head.root,
                        format_ms(h.head.timestamp_ms)
                    ),
                    None => println!("log: empty"),
                }
            }
        }
        Cmd::Capture { url, render } => {
            let node = Node::open(&dir)?;
            let out = node.capture(&url, render).await?;
            if cli.json {
                print_json(&out)?;
            } else {
                print_outcome(&out);
            }
        }
        Cmd::Verify {
            reference,
            at,
            bundle,
        } => {
            let b: Bundle = match (bundle, reference) {
                (Some(path), _) => {
                    let text = std::fs::read_to_string(&path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    serde_json::from_str(&text).context("parsing bundle")?
                }
                (None, Some(r)) => {
                    let node = Node::open(&dir)?;
                    let rec = node.resolve(&r, at_ms(&at)?)?;
                    node.bundle(&rec, true)?
                }
                (None, None) => bail!("give a URL, an attestation ID, or --bundle FILE"),
            };
            let report = Node::verify_bundle(&b);
            if cli.json {
                print_json(
                    &serde_json::json!({ "ok": report.ok(), "attestation": b.attestation, "checks": report.checks }),
                )?;
            } else {
                print_attestation_header(&b);
                print_report(&report);
            }
            return Ok(report.ok());
        }
        Cmd::Export {
            reference,
            at,
            no_content,
            out,
        } => {
            let node = Node::open(&dir)?;
            let rec = node.resolve(&reference, at_ms(&at)?)?;
            let b = node.bundle(&rec, !no_content)?;
            let json = serde_json::to_string_pretty(&b)?;
            match out {
                Some(p) => {
                    std::fs::write(&p, json)?;
                    eprintln!("wrote bundle for {} to {}", rec.id.short(), p.display());
                }
                None => println!("{json}"),
            }
        }
        Cmd::Warc { reference, at, out } => {
            let node = Node::open(&dir)?;
            let rec = node.resolve(&reference, at_ms(&at)?)?;
            let a = &rec.signed.attestation;
            let headers = node.store.blobs.get(&a.headers_hash)?;
            let body = node.store.blobs.get(&a.body_hash)?;
            let (Some(headers), Some(body)) = (headers, body) else {
                bail!("the raw content of this capture was not retained");
            };
            std::fs::write(
                &out,
                witness_capture::warc::export(&rec.signed, &headers, &body),
            )?;
            eprintln!("wrote {}", out.display());
        }
        Cmd::History { url } => {
            let node = Node::open(&dir)?;
            let url = target::canonical_url(&url)?;
            let hist = node.store.history(url.as_str())?;
            if cli.json {
                return print_json(&hist).map(|_| true);
            }
            if hist.is_empty() {
                println!("no captures of {url}");
            }
            // Versions are counted per capture method; `*` marks a change.
            let mut last = std::collections::HashMap::new();
            let mut versions = std::collections::HashMap::new();
            for r in &hist {
                let a = &r.signed.attestation;
                let hash = a.comparison_hash();
                let changed = last.insert(a.method, hash).is_some_and(|prev| prev != hash);
                let version = versions.entry(a.method).or_insert(0);
                if changed || *version == 0 {
                    *version += 1;
                }
                println!(
                    "{} {}  {}  {:<8} {}  v{version}  norm {}",
                    if changed { "*" } else { " " },
                    r.id.short(),
                    format_ms(a.fetched_at_ms),
                    method_name(a.method),
                    a.status,
                    a.comparison_hash().short()
                );
            }
            let changes = node.store.changes(Some(url.as_str()), 50)?;
            if !changes.is_empty() {
                println!("\nchanges:");
                for c in changes {
                    println!(
                        "  {}  {} → {}  {}{}",
                        format_ms(c.detected_at),
                        c.from_id.short(),
                        c.to_id.short(),
                        if c.silent { "SILENT " } else { "" },
                        c.summary
                    );
                }
            }
        }
        Cmd::Diff { a, b } => {
            let node = Node::open(&dir)?;
            let (ra, rb) = match b {
                Some(b) => (node.resolve(&a, None)?, node.resolve(&b, None)?),
                None => {
                    let url = target::canonical_url(&a).context("with one argument, give a URL")?;
                    let hist = node.store.history(url.as_str())?;
                    let latest = hist.last().context("no captures")?.clone();
                    let prev = hist
                        .iter()
                        .rev()
                        .find(|r| {
                            r.signed.attestation.method == latest.signed.attestation.method
                                && r.signed.attestation.comparison_hash()
                                    != latest.signed.attestation.comparison_hash()
                        })
                        .context("only one version captured")?
                        .clone();
                    (prev, latest)
                }
            };
            let (Some(ta), Some(tb)) = (
                node.normalized_text(&ra.signed.attestation)?,
                node.normalized_text(&rb.signed.attestation)?,
            ) else {
                bail!("normalized text for one of the captures was not retained");
            };
            match diff::diff(&ta, &tb) {
                None => println!("no difference"),
                Some(c) if cli.json => print_json(&c)?,
                Some(c) => {
                    println!("{}  ({} → {})\n", c.summary(), ra.id.short(), rb.id.short());
                    print!("{}", c.unified);
                }
            }
        }
        Cmd::Watch { cmd } => {
            let node = Node::open(&dir)?;
            match cmd {
                WatchCmd::Add { url, every, render } => {
                    let url = target::canonical_url(&url)?;
                    if every < Duration::from_secs(60) {
                        bail!("minimum interval is one minute");
                    }
                    node.store
                        .watch_add(url.as_str(), every.as_secs(), render, now_ms())?;
                    println!("watching {url} every {}", humantime::format_duration(every));
                }
                WatchCmd::Rm { url } => {
                    let url = target::canonical_url(&url)?;
                    if !node.store.watch_remove(url.as_str())? {
                        bail!("{url} is not watched");
                    }
                    println!("stopped watching {url}");
                }
                WatchCmd::List => {
                    let w = node.store.watches()?;
                    if cli.json {
                        return print_json(&w).map(|_| true);
                    }
                    for w in w {
                        println!(
                            "{}  every {}{}  last {}{}",
                            w.url,
                            humantime::format_duration(Duration::from_secs(w.every_secs)),
                            if w.render { " (rendered)" } else { "" },
                            w.last_run.map(format_ms).unwrap_or_else(|| "never".into()),
                            w.last_error
                                .map(|e| format!("  error: {e}"))
                                .unwrap_or_default()
                        );
                    }
                }
                WatchCmd::Run { once } => {
                    let node = Arc::new(node);
                    if once {
                        witness_node::web::run_due(&node, |line| println!("{line}")).await?;
                    } else {
                        tokio::select! {
                            r = witness_node::web::scheduler(node.clone(), |line| println!("{line}")) => r?,
                            _ = tokio::signal::ctrl_c() => eprintln!("stopping"),
                        }
                    }
                }
            }
        }
        Cmd::Log { cmd } => {
            let node = Node::open(&dir)?;
            match cmd {
                LogCmd::Head => match node.store.latest_tree_head()? {
                    Some(h) => print_json(&h)?,
                    None => bail!("log is empty"),
                },
                LogCmd::Consistency { old, new } => {
                    let leaves = node.store.leaves()?;
                    let new = new.unwrap_or(leaves.len() as u64);
                    if new as usize > leaves.len() || old > new {
                        bail!("sizes must satisfy old <= new <= {}", leaves.len());
                    }
                    let proof = merkle::consistency_proof(&leaves[..new as usize], old as usize)
                        .expect("sizes checked");
                    print_json(&serde_json::json!({
                        "old_size": old,
                        "new_size": new,
                        "old_root": merkle::root(&leaves[..old as usize]),
                        "new_root": merkle::root(&leaves[..new as usize]),
                        "proof": proof,
                    }))?;
                }
                LogCmd::Audit => {
                    let r = node.audit()?;
                    if cli.json {
                        print_json(&r)?;
                    } else {
                        print_report(&r);
                    }
                    return Ok(r.ok());
                }
            }
        }
        Cmd::Purge { url, forget } => {
            let node = Node::open(&dir)?;
            let url = target::canonical_url(&url)?;
            let (blobs, rows) = node.store.purge(url.as_str(), forget)?;
            println!("deleted {blobs} blobs and {rows} attestation records for {url}; the log is unchanged");
        }
        Cmd::Serve { addr, watch } => {
            let node = Arc::new(Node::open(&dir)?);
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            eprintln!("web UI on http://{addr}/");
            let server = axum::serve(listener, witness_node::web::router(node.clone()));
            if watch {
                tokio::select! {
                    r = server => r?,
                    r = witness_node::web::scheduler(node, |line| eprintln!("{line}")) => r?,
                    _ = tokio::signal::ctrl_c() => eprintln!("stopping"),
                }
            } else {
                tokio::select! {
                    r = server => r?,
                    _ = tokio::signal::ctrl_c() => eprintln!("stopping"),
                }
            }
        }
    }
    Ok(true)
}

fn print_outcome(o: &Outcome) {
    let a = &o.record.signed.attestation;
    println!("attestation {}", o.record.id);
    println!("  url        {}", a.url);
    if a.final_url != a.url {
        println!(
            "  final url  {} (after {} redirects)",
            a.final_url,
            a.redirects.len()
        );
    }
    println!(
        "  fetched    {} ({})",
        format_ms(a.fetched_at_ms),
        method_name(a.method)
    );
    println!(
        "  status     {}  {} bytes  {}",
        a.status,
        a.body_len,
        a.content_type.as_deref().unwrap_or("-")
    );
    println!("  body       {}", a.body_hash);
    if let Some(n) = a.norm {
        println!("  normalized {}", n.hash);
    }
    if let Some(c) = a.cert_sha256 {
        let hex: String = c.iter().map(|b| format!("{b:02x}")).collect();
        println!("  tls cert   sha256:{hex}");
    }
    if let Some(ip) = a.server_ip {
        println!("  server ip  {ip}");
    }
    println!(
        "  log        leaf {} of {}, root {}",
        o.record.leaf_index,
        o.tree_head.head.size,
        o.tree_head.head.root.short()
    );
    match (&o.previous, &o.change) {
        (None, _) => println!("first capture of this URL"),
        (Some(p), None) => println!("unchanged since {}", p.short()),
        (Some(p), Some(c)) => {
            println!("CHANGED since {}: {}", p.short(), c.summary);
            if let Some(d) = &c.diff {
                println!();
                print!("{}", d.unified);
            }
        }
    }
}

fn print_attestation_header(b: &Bundle) {
    let a = &b.attestation.attestation;
    println!(
        "{} ({}) at {}",
        a.url,
        method_name(a.method),
        format_ms(a.fetched_at_ms)
    );
    println!("attestation {}", b.attestation.id());
    if let Some(c) = a.cert_sha256 {
        let hex: String = c.iter().map(|b| format!("{b:02x}")).collect();
        println!("tls cert https://crt.sh/?sha256={hex}");
    }
    println!();
}

fn print_report(r: &Report) {
    for c in &r.checks {
        let tag = match c.status {
            Status::Pass => "ok  ",
            Status::Fail => "FAIL",
            Status::Skip => "skip",
        };
        println!("  [{tag}] {:<14} {}", c.name, c.detail);
    }
    println!(
        "\n{}",
        if r.ok() {
            "VERIFIED"
        } else {
            "VERIFICATION FAILED"
        }
    );
}
