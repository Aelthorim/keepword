use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use keepword_core::{WitnessKey, target};
use keepword::Node;
use keepword_tlsn::{Limits, Notary, VerifierService, capture_with, connect_server, mozilla_roots};

#[derive(Parser)]
#[command(
    name = "keepword-tlsn",
    version,
    about = "TLSNotary proof tier for Keepword"
)]
struct Cli {
    /// Node data directory (shared with `keepword`, and found the same way).
    #[arg(long, global = true, env = "KEEPWORD_DIR")]
    dir: Option<PathBuf>,
    /// Largest response to prove, in KiB. MPC cost grows with size.
    #[arg(long, global = true, default_value_t = 256)]
    max_recv_kib: usize,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Notarize other witnesses' captures.
    Serve {
        #[arg(long, default_value = "0.0.0.0:8482")]
        addr: String,
        /// Serve any prover, not just known peers.
        #[arg(long)]
        open: bool,
    },
    /// Capture a URL with another witness notarizing the TLS session.
    Capture {
        url: String,
        /// The verifier's notarization address, host:port.
        #[arg(long)]
        verifier: String,
        /// The verifier's witness key.
        #[arg(long)]
        verifier_key: WitnessKey,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = keepword::sysdir::resolve(cli.dir.clone());
    // Before the runtime starts any threads.
    keepword::sysdir::become_owner(&dir)?;
    tokio::runtime::Runtime::new()?.block_on(run(cli, dir))
}

async fn run(cli: Cli, dir: PathBuf) -> Result<()> {
    let limits = Limits {
        max_recv: cli.max_recv_kib * 1024,
        ..Limits::default()
    };
    let node = Arc::new(Node::open(&dir)?);
    match cli.cmd {
        Cmd::Serve { addr, open } => {
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            eprintln!(
                "notarizing for {} on {addr}",
                if open { "anyone" } else { "known peers" }
            );
            VerifierService::new(node, mozilla_roots(), limits, open)
                .serve(listener)
                .await
        }
        Cmd::Capture {
            url,
            verifier,
            verifier_key,
        } => {
            let url = target::canonical_url(&url)?;
            let verifier = tokio::net::lookup_host(&verifier)
                .await?
                .next()
                .context("verifier address does not resolve")?;
            let (server, ip) = connect_server(&node, &url).await?;
            let notary = Notary {
                addr: verifier,
                key: verifier_key,
                roots: mozilla_roots(),
                limits,
            };
            let (out, receipt) = capture_with(&node, &notary, server, Some(ip), &url).await?;
            println!("attestation {}", out.record.id);
            println!(
                "  notarized by {} for {} ({} bytes received)",
                receipt.body.verifier.short(),
                receipt.body.server_name,
                receipt.body.received_len
            );
            println!("  verify with: keepword verify {}", out.record.id.short());
            Ok(())
        }
    }
}
