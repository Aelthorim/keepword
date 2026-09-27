//! Print the normalized form of an HTML file: `cargo run --example normalize -- FILE URL`
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(path), Some(url)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: normalize FILE URL [FETCHED_AT_MS]");
        std::process::exit(2);
    };
    let body = std::fs::read(path).expect("read file");
    let url = url::Url::parse(url).expect("valid URL");
    let at = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let n = witness_normalize::Normalizer::default().normalize(&url, Some("text/html"), &body, at);
    print!("{}", n.text);
}
