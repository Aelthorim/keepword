use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use witness_core::bundle::{Bundle, Report, Status};
use witness_core::{format_ms, merkle, now_ms, target};
use witness_node::config::{Config, ContentConfig, Retain, VantageConfig};
use witness_node::{Node, Outcome, method_name, parse_time};
use witness_normalize::diff;

#[derive(Parser)]
#[command(
    name = "witness",
    version,
    about = "Independent, verifiable records of what web pages said"
)]
struct Cli {
    /// Node data directory. Default: ./witness-data if it exists, else the
    /// node set up by the installer (/var/lib/witness). Run as root, the
    /// command switches to the directory's owner, the service user.
    #[arg(long, global = true, env = "WITNESS_DIR")]
    dir: Option<PathBuf>,
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
        /// Check Bitcoin anchors against this Esplora API.
        #[arg(long)]
        esplora: Option<String>,
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
    /// Serve the web UI and, with --api-addr, the peer API; run the watch
    /// scheduler, federation and anchoring loops.
    Serve {
        /// Web UI address. The UI shows page content: keep it private.
        #[arg(long, default_value = "127.0.0.1:8480")]
        addr: String,
        /// Public API address for peers and verifiers (e.g. 0.0.0.0:8481).
        #[arg(long)]
        api_addr: Option<String>,
        /// Also capture watched URLs when due.
        #[arg(long)]
        watch: bool,
        /// Periodically anchor the log in Bitcoin via OpenTimestamps.
        #[arg(long)]
        anchor: bool,
    },
    /// Talk to other witnesses.
    Net {
        #[command(subcommand)]
        cmd: NetCmd,
    },
    /// Ask the network to watch a URL; assigned witnesses capture it.
    /// Asking again for the same URL replaces your earlier request.
    Request {
        url: String,
        /// Withdraw your requests for this URL instead.
        #[arg(long, conflicts_with_all = ["every", "duration", "render"])]
        cancel: bool,
        #[arg(long, default_value = "1h", value_parser = humantime::parse_duration)]
        every: Duration,
        /// How long the request stays active (at most 30 days).
        #[arg(long = "for", default_value = "7days", value_parser = humantime::parse_duration)]
        duration: Duration,
        #[arg(long)]
        render: bool,
    },
    /// Active network watch requests.
    Requests {
        /// Only this node's own.
        #[arg(long)]
        mine: bool,
    },
    /// What independent witnesses agree a URL served.
    Verdict { url: String },
    /// Alerts raised by this node and received from the network.
    Alerts {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Anchor the log in Bitcoin through OpenTimestamps.
    Anchor {
        #[command(subcommand)]
        cmd: AnchorCmd,
    },
    /// Read or change witness.toml.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Fetch and verify a drand beacon.
    Beacon {
        /// Round number (default: latest).
        round: Option<u64>,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print the whole configuration.
    Show,
    /// Print one setting, e.g. `network.endpoint`.
    Get { key: String },
    /// Change a setting. VALUE is a TOML value (`true`, `3`, `["a"]`) or a
    /// plain string.
    Set { key: String, value: String },
    /// Reset an optional setting to unset.
    Unset { key: String },
}

#[derive(Subcommand)]
enum NetCmd {
    /// Add a peer by its API base URL.
    AddPeer { url: String },
    /// List known peers.
    Peers,
    /// Forget a peer, e.g. a test node that no longer exists. A live peer
    /// comes back through gossip.
    RemovePeer {
        /// Key (or a prefix of it) or endpoint URL.
        peer: String,
    },
    /// Run one federation round now.
    Sync,
    /// Summary of this node's view of the network.
    Status,
    /// Look an IP address up in the configured IP-to-ASN table.
    Lookup { ip: std::net::IpAddr },
}

#[derive(Subcommand)]
enum AnchorCmd {
    /// Submit the latest tree head to the calendars.
    Submit,
    /// Fetch completed proofs and check them against Bitcoin.
    Upgrade,
    /// List anchors.
    List,
    /// Write the .ots proof and the tree-head bytes it timestamps, for the
    /// standard `ots verify` tool.
    Export {
        size: u64,
        #[arg(short, long)]
        out: PathBuf,
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

fn main() {
    // Exit quietly when piped into `head` and the like.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    // `init` creates a node, so it never picks the installed one by itself.
    let dir = match (&cli.cmd, &cli.dir) {
        (Cmd::Init { .. }, None) => PathBuf::from(witness_node::sysdir::LOCAL_DIR),
        _ => witness_node::sysdir::resolve(cli.dir.clone()),
    };
    // Before the runtime starts any threads.
    let result = witness_node::sysdir::become_owner(&dir).and_then(|()| {
        tokio::runtime::Runtime::new()
            .map_err(anyhow::Error::from)
            .and_then(|rt| rt.block_on(run(cli, dir)))
    });
    match result {
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
async fn run(cli: Cli, dir: PathBuf) -> Result<bool> {
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
            esplora,
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
            let mut report = Node::verify_bundle(&b);
            if let Some(esplora) = esplora {
                let http = witness_node::httpc::Http::new(false, false)?;
                witness_node::anchor::verify_anchor_online(&http, &esplora, &b, &mut report).await;
            }
            if cli.json {
                print_json(
                    &serde_json::json!({ "ok": report.ok(), "summary": report.summary(), "attestation": b.attestation, "checks": report.checks }),
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
            println!(
                "deleted {blobs} blobs and {rows} attestation records for {url}; the log is unchanged"
            );
        }
        Cmd::Serve {
            addr,
            api_addr,
            watch,
            anchor,
        } => {
            let node = Arc::new(Node::open(&dir)?);
            let ui = tokio::net::TcpListener::bind(&addr).await?;
            eprintln!("web UI on http://{addr}/");
            let mut tasks = tokio::task::JoinSet::new();
            let ui_app = witness_node::web::router(node.clone());
            tasks.spawn(async move { axum::serve(ui, ui_app).await.map_err(anyhow::Error::from) });
            if let Some(api_addr) = api_addr {
                let api = tokio::net::TcpListener::bind(&api_addr).await?;
                eprintln!("peer API on http://{api_addr}/v1/");
                let app = witness_node::api::router(node.clone());
                tasks.spawn(async move {
                    axum::serve(
                        api,
                        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                    )
                    .await
                    .map_err(anyhow::Error::from)
                });
            }
            if watch {
                let n = node.clone();
                tasks.spawn(async move {
                    witness_node::web::scheduler(n, |line| eprintln!("{line}")).await
                });
            }
            if node.config.network.endpoint.is_some() || !node.config.network.peers.is_empty() {
                let n = node.clone();
                tasks.spawn(async move {
                    witness_node::daemon::federation_loop(n, |l| eprintln!("{l}")).await
                });
            }
            if anchor {
                let n = node.clone();
                tasks.spawn(async move {
                    witness_node::daemon::anchor_loop(n, |l| eprintln!("{l}")).await
                });
            }
            tokio::select! {
                Some(r) = tasks.join_next() => r??,
                _ = tokio::signal::ctrl_c() => eprintln!("stopping"),
            }
        }
        Cmd::Net { cmd } => {
            let node = Node::open(&dir)?;
            match cmd {
                NetCmd::AddPeer { url } => {
                    let d = node.add_peer(&url).await?;
                    println!(
                        "added peer {} at {}",
                        d.body.key,
                        d.body.endpoint.unwrap_or_default()
                    );
                }
                NetCmd::RemovePeer { peer } => {
                    let want = peer.trim_end_matches('/').to_ascii_lowercase();
                    let matches: Vec<_> = node
                        .store
                        .peers()?
                        .into_iter()
                        .filter(|p| {
                            p.key.to_hex().starts_with(&want)
                                || p.endpoint.as_deref().is_some_and(|e| {
                                    e.trim_end_matches('/').eq_ignore_ascii_case(&want)
                                })
                        })
                        .collect();
                    match matches.as_slice() {
                        [] => bail!("no peer matches {peer:?}"),
                        [p] => {
                            node.store.peer_remove(&p.key)?;
                            println!(
                                "removed {} {}",
                                p.key.short(),
                                p.endpoint.as_deref().unwrap_or("")
                            );
                            if node.config.network.peers.iter().any(|b| {
                                p.endpoint.as_deref().is_some_and(|e| {
                                    e.trim_end_matches('/') == b.trim_end_matches('/')
                                })
                            }) {
                                println!(
                                    "note: it is in network.peers and will be re-added while it answers"
                                );
                            }
                        }
                        _ => bail!(
                            "{peer:?} matches {} peers; give more of the key",
                            matches.len()
                        ),
                    }
                }
                NetCmd::Peers => {
                    let peers = node.store.peers()?;
                    if cli.json {
                        return print_json(&peers).map(|_| true);
                    }
                    let scores = node.store.reputation_scores(now_ms())?;
                    for p in peers {
                        let loc = node.location_of(&p.key, now_ms())?;
                        println!(
                            "{}  {}  log {}  location {}  reputation {:.1}  last sync {}{}",
                            p.key.short(),
                            p.endpoint.as_deref().unwrap_or("(no endpoint)"),
                            // Only known for logs this node audits.
                            p.head
                                .as_ref()
                                .map_or("-".to_string(), |h| h.head.size.to_string()),
                            loc.map(|l| l.to_string())
                                .unwrap_or_else(|| "unknown".into()),
                            scores.get(&p.key).copied().unwrap_or(0.0),
                            p.last_sync.map(format_ms).unwrap_or_else(|| "never".into()),
                            p.last_error
                                .map(|e| format!("  error: {e}"))
                                .unwrap_or_default()
                        );
                    }
                }
                NetCmd::Sync => {
                    let r = node.sync().await?;
                    if cli.json {
                        print_json(&r)?;
                    } else {
                        println!(
                            "synced {}/{} peers: {} logs audited, {} new attestations, {} messages in, {} out",
                            r.synced,
                            r.peers,
                            r.audited,
                            r.new_attestations,
                            r.gossip_in,
                            r.gossip_out
                        );
                        for (who, e) in &r.errors {
                            println!("  {who}: {e}");
                        }
                    }
                }
                NetCmd::Lookup { ip } => {
                    let db = node
                        .asn_db
                        .as_ref()
                        .context("no IP-to-ASN table configured (quorum.asn_db)")?;
                    match db.lookup(ip) {
                        Some((asn, country)) => println!("{asn} {country}"),
                        None => bail!("{ip} is not in the IP-to-ASN table"),
                    }
                }
                NetCmd::Status => {
                    let now = now_ms();
                    let epoch = witness_core::beacon::epoch_of(now);
                    let seed = node.epoch_seed(epoch).await;
                    let me = node.location_of(&node.key.public(), now)?;
                    println!("witness     {}", node.key.public());
                    println!(
                        "endpoint    {}",
                        node.config
                            .network
                            .endpoint
                            .as_deref()
                            .unwrap_or("(none: push-only)")
                    );
                    println!(
                        "location    {}",
                        me.as_ref()
                            .map(|l| l.to_string())
                            .unwrap_or_else(|| "not corroborated".into())
                    );
                    println!("peers       {}", node.store.peers()?.len());
                    println!(
                        "candidates  {} witnesses eligible for assignment",
                        node.candidates(now)?.len()
                    );
                    match seed {
                        Ok((s, true)) => {
                            println!("epoch       {epoch}, seed {} (drand)", s.short())
                        }
                        Ok((s, false)) => println!(
                            "epoch       {epoch}, seed {} (INSECURE: no beacon)",
                            s.short()
                        ),
                        Err(e) => println!("epoch       {epoch}, no seed: {e:#}"),
                    }
                    println!(
                        "requests    {} active",
                        node.store.requests_active(now)?.len()
                    );
                    println!("auditing    {} logs", node.audited_logs_now()?.len());
                    println!(
                        "fetched     {} attestations from peers",
                        node.store.foreign_count()?
                    );
                    println!(
                        "capturing   {} URLs for the network",
                        node.store
                            .watches()?
                            .iter()
                            .filter(|w| w.request_id.is_some())
                            .count()
                    );
                    let bad = node.store.equivocating_logs()?;
                    if !bad.is_empty() {
                        println!(
                            "EQUIVOCATED {}",
                            bad.iter().map(|k| k.short()).collect::<Vec<_>>().join(", ")
                        );
                    }
                    let warnings = status_warnings(&node, me.is_some())?;
                    if !warnings.is_empty() {
                        println!();
                        for w in warnings {
                            println!("warning: {w}");
                        }
                    }
                }
            }
        }
        Cmd::Request {
            url, cancel: true, ..
        } => {
            let node = Node::open(&dir)?;
            match node.cancel_requests(&url)? {
                0 => bail!("you have no active request for {url}"),
                n => println!(
                    "withdrew {n} request{}; assigned witnesses stop after the next sync",
                    if n == 1 { "" } else { "s" }
                ),
            }
        }
        Cmd::Requests { mine } => {
            let node = Node::open(&dir)?;
            let now = now_ms();
            let me = node.key.public();
            let watching: std::collections::HashSet<String> = node
                .store
                .watches()?
                .into_iter()
                .filter(|w| w.request_id.is_some())
                .map(|w| w.url)
                .collect();
            let reqs: Vec<_> = if mine {
                node.store.requests_by(&me, now)?
            } else {
                node.store.requests_active(now)?
            };
            if cli.json {
                return print_json(&reqs).map(|_| true);
            }
            for r in reqs {
                let b = &r.body;
                println!(
                    "{}  every {:<8} until {}  {}{}{}",
                    b.url,
                    humantime::format_duration(std::time::Duration::from_secs(b.every_secs))
                        .to_string(),
                    format_ms(b.expires_at_ms),
                    if b.requester == me { "mine" } else { "from " },
                    if b.requester == me {
                        String::new()
                    } else {
                        b.requester.short()
                    },
                    if watching.contains(&b.url) {
                        "  [this node captures it]"
                    } else {
                        ""
                    }
                );
            }
        }
        Cmd::Request {
            url,
            every,
            duration,
            render,
            ..
        } => {
            let node = Node::open(&dir)?;
            let replaced = node.cancel_requests(&url)?;
            let r =
                node.request_watch(&url, every.as_secs(), duration.as_millis() as i64, render)?;
            println!(
                "request {} for {} every {} until {}; it spreads on the next sync",
                r.id().short(),
                r.body.url,
                humantime::format_duration(every),
                format_ms(r.body.expires_at_ms)
            );
            if replaced > 0 {
                println!("  (replaces your earlier request)");
            }
        }
        Cmd::Verdict { url } => {
            let node = Node::open(&dir)?;
            let url = target::canonical_url(&url)?;
            // Ask the witnesses assigned to it for their latest captures.
            if let Err(e) = node.refresh_url(url.as_str()).await {
                eprintln!("warning: could not fetch from peers: {e:#}");
            }
            let v = node.verdict(url.as_str())?;
            if cli.json {
                return print_json(&v).map(|_| true);
            }
            print_verdict(&v);
        }
        Cmd::Alerts { limit } => {
            let node = Node::open(&dir)?;
            let alerts = node.store.alerts(limit)?;
            if cli.json {
                return print_json(&alerts).map(|_| true);
            }
            for a in alerts {
                println!(
                    "{}  {:<12} {}  {}  (from {})",
                    format_ms(a.body.issued_at_ms),
                    format!("{:?}", a.body.kind),
                    a.body.url.as_deref().unwrap_or("-"),
                    a.body.summary,
                    a.body.issuer.short()
                );
            }
        }
        Cmd::Anchor { cmd } => {
            let node = Node::open(&dir)?;
            match cmd {
                AnchorCmd::Submit => match node.anchor_submit().await? {
                    Some(a) => println!(
                        "submitted tree head of size {} ({} calendar attestations)",
                        a.size,
                        witness_core::ots::DetachedTimestamp::from_bytes(&a.ots)?
                            .timestamp
                            .claims()
                            .len()
                    ),
                    None => println!("latest tree head is already anchored"),
                },
                AnchorCmd::Upgrade => {
                    let r = node.anchor_upgrade().await?;
                    println!(
                        "checked {} pending anchors: {} upgraded, {} confirmed in Bitcoin",
                        r.checked, r.upgraded, r.confirmed
                    );
                }
                AnchorCmd::List => {
                    for a in node.store.anchors()? {
                        println!(
                            "size {:>8}  {}  {}  updated {}",
                            a.size,
                            a.status,
                            a.height.map(|h| format!("block {h}")).unwrap_or_default(),
                            format_ms(a.updated_at)
                        );
                    }
                }
                AnchorCmd::Export { size, out } => {
                    let a = node
                        .store
                        .anchors()?
                        .into_iter()
                        .find(|a| a.size == size)
                        .with_context(|| format!("no anchor for size {size}"))?;
                    std::fs::write(&out, a.head.head.signing_bytes())?;
                    let mut ots = out.clone().into_os_string();
                    ots.push(".ots");
                    std::fs::write(&ots, &a.ots)?;
                    println!(
                        "wrote {} and {}",
                        out.display(),
                        PathBuf::from(ots).display()
                    );
                }
            }
        }
        Cmd::Config { cmd } => {
            let mut cfg = Config::load(&dir)?;
            match cmd {
                ConfigCmd::Show => print!("{}", toml::to_string_pretty(&cfg)?),
                ConfigCmd::Get { key } => match cfg.get_path(&key)? {
                    serde_json::Value::String(s) => println!("{s}"),
                    serde_json::Value::Null => {}
                    v => println!("{v}"),
                },
                ConfigCmd::Set { key, value } => {
                    cfg.set_path(&key, Some(&value))?;
                    cfg.save(&dir)?;
                }
                ConfigCmd::Unset { key } => {
                    cfg.set_path(&key, None)?;
                    cfg.save(&dir)?;
                }
            }
        }
        Cmd::Beacon { round } => {
            let node = Node::open(&dir)?;
            let b = node.fetch_beacon(round).await?;
            println!(
                "drand quicknet round {} at {}: randomness {} (signature verified)",
                b.round,
                format_ms(b.time_ms()),
                b.randomness()
            );
        }
    }
    Ok(true)
}

/// Misconfigurations that silently keep a node out of the network.
fn status_warnings(node: &Node, located: bool) -> Result<Vec<String>> {
    let cfg = &node.config;
    let mut w = Vec::new();
    let peers = node.store.peers()?;
    if cfg.network.endpoint.is_none() && cfg.network.peers.is_empty() && peers.is_empty() {
        w.push(
            "federation is off: set network.endpoint (the node then joins through the default \
             seeds) and restart the service"
                .to_string(),
        );
    } else if peers.is_empty() && cfg.network.bootstrap().is_empty() {
        w.push("no peers to join through: set network.peers to any witness's address".to_string());
    }
    if let Some(ep) = &cfg.network.endpoint {
        if ep.starts_with("http://") && !cfg.network.allow_private_peers {
            w.push(format!(
                "endpoint {ep} is plain HTTP; public nodes should use https"
            ));
        }
    }
    if cfg.quorum.asn_db.is_none() {
        w.push(
            "no IP-to-ASN table (quorum.asn_db), so no witness's location can be corroborated"
                .to_string(),
        );
    } else if !located && !cfg.quorum.trust_self_reported {
        w.push(format!(
            "this node's location isn't corroborated yet; it needs {} peers to observe it \
             (a few sync rounds), and until then it isn't assigned requests",
            cfg.quorum.min_observers
        ));
    }
    let failing = peers
        .iter()
        .filter(|p| p.endpoint.is_some() && p.last_error.is_some())
        .count();
    if failing > 0 {
        w.push(format!(
            "{failing} peer(s) failing to sync; see `witness net peers`"
        ));
    }
    let q = &cfg.quorum;
    for (on, what) in [
        (q.trust_self_reported, "quorum.trust_self_reported"),
        (cfg.beacon.allow_insecure_seed, "beacon.allow_insecure_seed"),
        (
            cfg.network.allow_private_peers,
            "network.allow_private_peers",
        ),
        (q.min_asns < 3, "quorum.min_asns below 3"),
        (q.min_dissent_asns < 2, "quorum.min_dissent_asns below 2"),
    ] {
        if on {
            w.push(format!("test-only setting in use: {what}"));
        }
    }
    Ok(w)
}

fn print_verdict(v: &witness_node::consensus::VerdictView) {
    use witness_core::quorum::Verdict;
    println!("{}  ({} recent attestations)", v.url, v.considered);
    match &v.evaluation.verdict {
        Verdict::Agreed { group, dissenters } => {
            println!(
                "AGREED by {} witnesses in {} independent networks: normalized content {}",
                group.witnesses.len(),
                group.asns.len(),
                group.hash.short()
            );
            if !dissenters.is_empty() {
                println!(
                    "  dissenting: {}",
                    dissenters
                        .iter()
                        .map(|k| k.short())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        Verdict::Split { groups } => {
            println!("SPLIT: independent witnesses saw different content at the same time");
            for g in groups {
                println!(
                    "  {} ← {} witnesses in ASNs {:?}",
                    g.hash.short(),
                    g.witnesses.len(),
                    g.asns
                );
            }
        }
        Verdict::Insufficient { groups } => {
            println!("INSUFFICIENT: not enough independent networks yet");
            for g in groups {
                println!(
                    "  {} ← {} witnesses, {} known ASNs",
                    g.hash.short(),
                    g.witnesses.len(),
                    g.asns.len()
                );
            }
        }
    }
    if v.evaluation.rejected > 0 {
        println!(
            "  {} attestations rejected (bad signature)",
            v.evaluation.rejected
        );
    }
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
    let s = r.summary();
    match s.strength {
        None => println!("\nVERIFICATION FAILED"),
        Some(level) => {
            println!("\nVERIFIED: {}", level.label());
            println!("\nThis bundle shows");
            for line in &s.shows {
                println!("  - {line}");
            }
            println!("It does not show");
            for line in &s.does_not_show {
                println!("  - {line}");
            }
        }
    }
}
