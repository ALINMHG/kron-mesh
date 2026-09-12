//! Resolve the internet bootstrap (paid VPS or another hub).
//!
//! Priority: CLI `--bootstrap` / `--follow`, then env `KRON_BOOTSTRAP`,
//! then `bootstrap.txt` in the data-dir (or cwd), then
//! [`DEFAULT_BOOTSTRAP`] (`144.91.105.244:8000`) for phones.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;

/// Paid KRON Mesh VPS — public gossip relay + explorer. Never mines.
pub const DEFAULT_BOOTSTRAP: &str = "144.91.105.244:8000";
/// Public explorer on the same VPS (TCP 8080).
pub const DEFAULT_EXPLORER_URL: &str = "http://144.91.105.244:8080";
/// Environment variable: `KRON_BOOTSTRAP=144.91.105.244:8000` (overrides default).
pub const KRON_BOOTSTRAP_ENV: &str = "KRON_BOOTSTRAP";
/// Filename looked up in `--data-dir` then the current directory.
pub const BOOTSTRAP_FILE_NAME: &str = "bootstrap.txt";

/// Parse `host:port` or `IPv4:port` / `[IPv6]:port`. Does not default an IP.
pub fn parse_peer_addr(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("bootstrap address is empty".into());
    }
    if is_placeholder_spec(s) {
        return Err(format!(
            "replace the placeholder with your VPS IPv4 (got '{s}'). Copy bootstrap.txt.example → bootstrap.txt"
        ));
    }
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    match s.to_socket_addrs() {
        Ok(mut iter) => iter
            .next()
            .ok_or_else(|| format!("bootstrap '{s}' resolved to no addresses")),
        Err(_) => Err(format!("invalid --bootstrap '{s}' (expected host:port)")),
    }
}

/// CLI wins, then env, then file. If all unset and `use_default`, the paid VPS.
pub fn resolve_bootstrap_sources(
    cli: Option<SocketAddr>,
    env_text: Option<&str>,
    file_text: Option<&str>,
    use_default: bool,
) -> Result<Option<SocketAddr>, String> {
    if let Some(addr) = cli {
        return Ok(Some(addr));
    }
    if let Some(raw) = env_text {
        if let Some(addr) = parse_bootstrap_text(raw)? {
            return Ok(Some(addr));
        }
    }
    if let Some(raw) = file_text {
        if let Some(addr) = parse_bootstrap_text(raw)? {
            return Ok(Some(addr));
        }
    }
    if use_default {
        return Ok(Some(default_bootstrap_addr()));
    }
    Ok(None)
}

/// Phones: CLI / `KRON_BOOTSTRAP` / `bootstrap.txt` / paid VPS default.
pub fn resolve_bootstrap(
    cli: Option<SocketAddr>,
    data_dir: &Path,
) -> Result<Option<SocketAddr>, String> {
    resolve_bootstrap_from(cli, data_dir, true)
}

/// VPS `--hub`: no implicit self-dial. CLI / env / file only.
pub fn resolve_bootstrap_optional(
    cli: Option<SocketAddr>,
    data_dir: &Path,
) -> Result<Option<SocketAddr>, String> {
    resolve_bootstrap_from(cli, data_dir, false)
}

fn resolve_bootstrap_from(
    cli: Option<SocketAddr>,
    data_dir: &Path,
    use_default: bool,
) -> Result<Option<SocketAddr>, String> {
    let env = std::env::var(KRON_BOOTSTRAP_ENV).ok();
    let file = read_bootstrap_file(data_dir);
    resolve_bootstrap_sources(cli, env.as_deref(), file.as_deref(), use_default)
}

pub fn default_bootstrap_addr() -> SocketAddr {
    DEFAULT_BOOTSTRAP
        .parse()
        .expect("DEFAULT_BOOTSTRAP is a literal IPv4:port")
}

/// Host of [`DEFAULT_BOOTSTRAP`] — used when the VPS cannot detect a public IPv4.
pub fn default_public_ipv4() -> Ipv4Addr {
    match default_bootstrap_addr().ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => Ipv4Addr::new(144, 91, 105, 244),
    }
}

/// True when `peer` is this process (same port + loopback / advertised / LAN IP).
/// The VPS hub must not dial `144.91.105.244:8000` when it *is* that hub.
pub fn is_self_hub_target(
    peer: SocketAddr,
    listen_port: u16,
    advertised: Option<Ipv4Addr>,
    lan: Option<Ipv4Addr>,
) -> bool {
    if peer.port() != listen_port {
        return false;
    }
    match peer.ip() {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || advertised == Some(ip)
                || lan == Some(ip)
        }
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unspecified(),
    }
}

/// Phone miner: CLI `--bootstrap` wins; `--no-bootstrap` stays LAN-only;
/// otherwise env / file / paid VPS default.
pub fn resolve_phone_bootstrap(
    cli: Option<SocketAddr>,
    no_bootstrap: bool,
    data_dir: &Path,
) -> Result<Option<SocketAddr>, String> {
    if cli.is_some() {
        return resolve_bootstrap(cli, data_dir);
    }
    if no_bootstrap {
        return Ok(None);
    }
    resolve_bootstrap(None, data_dir)
}

/// First non-comment line of a bootstrap file or env value.
pub fn parse_bootstrap_text(text: &str) -> Result<Option<SocketAddr>, String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if is_placeholder_spec(line) {
            return Ok(None);
        }
        return parse_peer_addr(line).map(Some);
    }
    Ok(None)
}

fn read_bootstrap_file(data_dir: &Path) -> Option<String> {
    let candidates = [
        data_dir.join(BOOTSTRAP_FILE_NAME),
        Path::new(BOOTSTRAP_FILE_NAME).to_path_buf(),
    ];
    for path in candidates {
        if let Ok(text) = std::fs::read_to_string(&path) {
            return Some(text);
        }
    }
    None
}

fn is_placeholder_spec(s: &str) -> bool {
    let u = s.to_ascii_uppercase();
    u.contains("YOUR_VPS")
        || u.contains("YOUR_IP")
        || u.contains("<VPS")
        || u.contains("PLACEHOLDER")
        || u.contains("PHONE1_IP")
        || u.contains("PHONE_IP")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parses_literal_ipv4() {
        let addr = parse_peer_addr("203.0.113.10:8000").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(addr.port(), 8000);
    }

    #[test]
    fn placeholder_file_is_unset_not_an_error() {
        let got = parse_bootstrap_text("# put your VPS IPv4 here\nYOUR_VPS_IP:8000\n").unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn cli_wins_over_env_and_file() {
        let cli: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let got = resolve_bootstrap_sources(
            Some(cli),
            Some("203.0.113.10:8000"),
            Some("198.51.100.1:8000"),
            true,
        )
        .unwrap();
        assert_eq!(got, Some(cli));
    }

    #[test]
    fn env_wins_over_file_and_default() {
        let got =
            resolve_bootstrap_sources(None, Some("127.0.0.1:8000"), Some("127.0.0.1:9000"), true)
                .unwrap();
        assert_eq!(got.unwrap().ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(got.unwrap().port(), 8000);
    }

    #[test]
    fn default_bootstrap_is_paid_vps() {
        let got = resolve_bootstrap_sources(None, None, None, true).unwrap();
        assert_eq!(got, Some(default_bootstrap_addr()));
        assert_eq!(got.unwrap().to_string(), "144.91.105.244:8000");
        assert_eq!(default_public_ipv4(), Ipv4Addr::new(144, 91, 105, 244));
        assert!(
            resolve_bootstrap_sources(None, None, None, false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn hub_does_not_self_dial_advertised_vps() {
        let peer = default_bootstrap_addr();
        let vps = Ipv4Addr::new(144, 91, 105, 244);
        assert!(is_self_hub_target(peer, 8000, Some(vps), None));
        assert!(!is_self_hub_target(peer, 8001, Some(vps), None));
        let other: SocketAddr = "203.0.113.10:8000".parse().unwrap();
        assert!(!is_self_hub_target(other, 8000, Some(vps), None));
    }

    #[test]
    fn comments_and_blank_lines_skipped() {
        let got = parse_bootstrap_text("\n# comment\n127.0.0.1:8001\n").unwrap();
        assert_eq!(got.unwrap().port(), 8001);
    }

    #[test]
    fn empty_text_is_unset() {
        assert!(parse_bootstrap_text("").unwrap().is_none());
        assert!(parse_bootstrap_text("# only comments\n").unwrap().is_none());
    }
}
