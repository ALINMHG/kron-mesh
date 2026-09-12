//! Shared argv helpers for `kron-phone`, `kron-node`, and the Termux menu.
//!
//! The binaries use `std::env::args` (not clap). Accept the forms people
//! actually type: `--flag value`, `--flag=value`, quoted values, and a
//! positional `kron1…` reward address.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use super::bech32::{normalize_bech32_input, KRON1_LEN};
use super::bootstrap::parse_peer_addr;
use super::wallet::KronAddress;

pub const PHONE_FLAGS: &[&str] = &[
    "--mine",
    "--reward-address",
    "--miner-address",
    "--hub",
    "--node-only",
    "--generate-wallet",
    "--show-mnemonic",
    "--phone",
    "--port",
    "--port-auto",
    "--explorer-port",
    "--data-dir",
    "--bootstrap",
    "--node",
    "--no-discovery",
    "--no-bootstrap",
    "--no-mine",
    "--help",
    "-h",
];

pub const NODE_FLAGS: &[&str] = &[
    "--port",
    "--follow",
    "--bootstrap",
    "--node",
    "--data-dir",
    "--name",
    "--explorer-port",
    "--hub",
    "--public-ip",
    "--read-only",
    "--no-mine",
    "--no-discovery",
    "--print-identity",
    "--help",
    "-h",
];

pub const PHONE_MINER_FLAGS: &[&str] = &[
    "--phone",
    "--node",
    "--bootstrap",
    "--reward-address",
    "--miner-address",
    "--mine",
    "--data-dir",
    "--help",
    "-h",
];

pub const CREDIT_FLAGS: &[&str] = &["--to", "--amount", "--data-dir", "--port"];

pub const NODE_MINE_REFUSAL: &str = "mining is phone-only. On Termux run kron-phone --mine --reward-address kron1... (also --miner-address or positional kron1...). This PC is a read-only explorer.";

#[derive(Debug, Clone)]
pub struct PhoneCli {
    pub generate: bool,
    pub mine: bool,
    /// `kron-phone 2` with no address yet — prompt, do not treat stdin as argv.
    pub prompt_mine: bool,
    pub hub_only: bool,
    pub show_mnemonic: bool,
    pub reward: Option<KronAddress>,
    pub port: u16,
    /// Try `--port`, then +1 … +4 (max 5) if the requested port is busy.
    pub port_auto: bool,
    pub explorer_port: Option<u16>,
    pub data_dir: PathBuf,
    pub bootstrap: Option<SocketAddr>,
    pub phone: bool,
    /// Disable LAN UDP beacons (phones still accept `--bootstrap` / VPS).
    pub no_discovery: bool,
    /// Stay LAN-only: do not dial the paid VPS default (CLI `--bootstrap` still wins).
    pub no_bootstrap: bool,
}

/// How `kron-node` should run after flags + host arch are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRunMode {
    /// Gossip relay + explorer. Accepts inbound `kron-mesh/1`. Never mines.
    PublicHub,
    /// Home-PC pull client. Needs `--follow` (or the default VPS) to fill.
    Viewer,
    /// ARM / Termux full hub (WAL + P2P). May still dial the VPS.
    PhoneHub,
}

/// Parsed `kron-node` flags. `--hub` is a public gossip relay (VPS); it never mines.
/// Listen on `0.0.0.0` without `--follow` is the same mode (even on x86).
#[derive(Debug, Clone)]
pub struct NodeCli {
    pub port: u16,
    pub explorer_port: u16,
    pub data_dir: Option<PathBuf>,
    pub follow: Option<SocketAddr>,
    pub name: Option<String>,
    pub print_identity: bool,
    pub read_only: bool,
    pub public_hub: bool,
    pub no_discovery: bool,
    pub public_ip: Option<Ipv4Addr>,
}

/// x86 VPS: bind-all and no `--follow` / `--read-only` → hub (phones dial in).
/// `--hub` is an explicit alias. `--follow` or `--read-only` on x86 → viewer.
pub fn decide_node_run_mode(
    hub_flag: bool,
    read_only: bool,
    explicit_follow: bool,
    x86_host: bool,
) -> NodeRunMode {
    if hub_flag || (x86_host && !read_only && !explicit_follow) {
        NodeRunMode::PublicHub
    } else if x86_host || read_only {
        NodeRunMode::Viewer
    } else {
        NodeRunMode::PhoneHub
    }
}

/// `--public-ip 144.91.105.244` or `144.91.105.244:8000` (host only).
pub fn parse_public_ipv4(s: &str) -> Result<Ipv4Addr, String> {
    let s = sanitize_cli_value(s);
    if s.is_empty() {
        return Err("--public-ip requires an IPv4 address".into());
    }
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        if ip.is_unspecified() {
            return Err("--public-ip cannot be 0.0.0.0".into());
        }
        return Ok(ip);
    }
    if let Ok(addr) = parse_peer_addr(&s) {
        match addr.ip() {
            IpAddr::V4(ip) if !ip.is_unspecified() => return Ok(ip),
            _ => {}
        }
    }
    Err(format!("invalid --public-ip '{s}' (expected IPv4)"))
}

/// Build the phone binary from the repo root (package `new-blockchain`).
/// There is no `kron-phone/` crate; do not pass `--bin` on Termux.
pub const TERMUX_BUILD_CMD: &str = "cargo build --release -p new-blockchain";

/// `[KRON ERROR]` is prefixed by each binary's `main`.
pub fn unknown_argument(arg: &str, valid_flags: &[&str]) -> String {
    format!(
        "unknown argument: {arg}\nvalid flags: {}",
        valid_flags.join(" ")
    )
}

/// Cargo flags people paste onto `./kron-phone` after a failed `cargo` line.
pub fn is_cargo_build_flag(token: &str) -> bool {
    matches!(
        token,
        "--bin"
            | "--release"
            | "-p"
            | "--package"
            | "--target"
            | "--offline"
            | "--locked"
            | "--workspace"
            | "bin"
            | "cargo"
    )
}

pub fn cargo_flag_misuse(_arg: &str) -> String {
    format!("that is a cargo flag; run: {TERMUX_BUILD_CMD}")
}

/// Trim BOM / whitespace / matching quotes (`"…"`, `'…'`, smart quotes, backticks).
pub fn sanitize_cli_value(s: &str) -> String {
    let mut s = s.trim().trim_start_matches('\u{feff}').trim().to_string();
    loop {
        let stripped = strip_matching_quotes(&s);
        if stripped.len() == s.len() {
            break;
        }
        s = stripped.trim().to_string();
    }
    s
}

fn strip_matching_quotes(s: &str) -> String {
    let pairs = [
        ('"', '"'),
        ('\'', '\''),
        ('\u{201c}', '\u{201d}'),
        ('\u{2018}', '\u{2019}'),
        ('`', '`'),
    ];
    for (open, close) in pairs {
        if s.len() >= open.len_utf8() + close.len_utf8()
            && s.starts_with(open)
            && s.ends_with(close)
        {
            return s[open.len_utf8()..s.len() - close.len_utf8()].to_string();
        }
    }
    s.to_string()
}

/// `--flag=value` → `("--flag", Some("value"))`; otherwise `(token, None)`.
pub fn split_eq_flag(token: &str) -> (&str, Option<&str>) {
    if token.starts_with('-') {
        if let Some((flag, value)) = token.split_once('=') {
            return (flag, Some(value));
        }
    }
    (token, None)
}

pub fn looks_like_kron1(s: &str) -> bool {
    let s = sanitize_address_input(s);
    s.len() >= 5 && s.as_bytes()[..5].eq_ignore_ascii_case(b"kron1")
}

/// First line of a Termux-wrapped `kron1…` paste (too short to be complete).
pub fn is_incomplete_kron1(s: &str) -> bool {
    let s = sanitize_address_input(s);
    s.len() >= 5
        && s.as_bytes()[..5].eq_ignore_ascii_case(b"kron1")
        && s.len() < KRON1_LEN
}

/// Strip quotes / `--reward-address` prefixes people paste into the menu.
pub fn sanitize_address_input(s: &str) -> String {
    let mut s = sanitize_cli_value(s);
    s = strip_leading_menu_two(&s);
    const PREFIXES: &[&str] = &[
        "--reward-address=",
        "--miner-address=",
        "--reward-address",
        "--miner-address",
    ];
    let lower = s.to_ascii_lowercase();
    for prefix in PREFIXES {
        if lower.starts_with(prefix) {
            s = sanitize_cli_value(&s[prefix.len()..]);
            break;
        }
    }
    normalize_bech32_input(&s)
}

fn strip_leading_menu_two(s: &str) -> String {
    let t = s.trim();
    if t == "2" {
        return String::new();
    }
    if let Some(rest) = t.strip_prefix('2') {
        if rest.starts_with(|c: char| c.is_whitespace()) {
            return sanitize_cli_value(rest);
        }
    }
    t.to_string()
}

pub fn parse_kron1_arg(s: &str) -> Result<KronAddress, String> {
    let cleaned = sanitize_address_input(s);
    if cleaned.is_empty() {
        return Err("expected kron1... address".into());
    }
    KronAddress::parse(&cleaned).map_err(|e| e.cli_message(&cleaned))
}

pub fn parse_menu_reward_input(line: &str) -> Result<KronAddress, String> {
    let cleaned = sanitize_address_input(line);
    if cleaned.is_empty() {
        return Err("empty address".into());
    }
    parse_kron1_arg(&cleaned)
}

pub fn is_phone_mine_cli_token(token: &str) -> bool {
    let t = sanitize_cli_value(token);
    let (flag, val) = split_eq_flag(&t);
    matches!(
        flag,
        "--mine" | "--miner-only" | "--miner-ui" | "--reward-address" | "--miner-address"
    ) || looks_like_kron1(&t)
        || val.map(looks_like_kron1).unwrap_or(false)
}

pub fn take_cli_value(
    inline: Option<&str>,
    raw: &[String],
    i: &mut usize,
    flag: &str,
) -> Result<String, String> {
    if let Some(v) = inline {
        let v = sanitize_cli_value(v);
        if v.is_empty() {
            return Err(format!("{flag} requires a value"));
        }
        return Ok(v);
    }
    *i += 1;
    let v = raw
        .get(*i)
        .ok_or_else(|| format!("{flag} requires a value"))?;
    let v = sanitize_cli_value(v);
    if v.is_empty() {
        return Err(format!("{flag} requires a value"));
    }
    Ok(v)
}

fn take_reward(inline: Option<&str>, raw: &[String], i: &mut usize, flag: &str) -> Result<KronAddress, String> {
    let v = take_cli_value(inline, raw, i, flag).map_err(|_| format!("{flag} requires kron1..."))?;
    if v.starts_with('-') && !looks_like_kron1(&v) {
        return Err(format!("{flag} requires kron1..."));
    }
    parse_kron1_arg(&v)
}

/// Parse `kron-phone` argv (already without argv[0]).
pub fn parse_phone_cli(raw: &[String]) -> Result<PhoneCli, String> {
    let mut generate = false;
    let mut mine = false;
    let mut prompt_mine = false;
    let mut hub_only = false;
    let mut show_mnemonic = false;
    let mut reward = None;
    let mut port = 8000u16;
    let mut port_auto = false;
    let mut explorer_port = Some(8080u16);
    let mut data_dir = None;
    let mut bootstrap = None;
    let mut phone = false;
    let mut no_discovery = false;
    let mut no_bootstrap = false;
    let mut i = 0;
    while i < raw.len() {
        let token = sanitize_cli_value(&raw[i]);
        if token.is_empty() {
            i += 1;
            continue;
        }
        let (flag, inline) = split_eq_flag(&token);

        if is_cargo_build_flag(flag) {
            return Err(cargo_flag_misuse(&token));
        }

        if !flag.starts_with('-') {
            if flag == "1" {
                generate = true;
                i += 1;
                continue;
            }
            if flag == "2" {
                mine = true;
                prompt_mine = true;
                i += 1;
                continue;
            }
            if looks_like_kron1(flag) {
                reward = Some(parse_kron1_arg(flag)?);
                mine = true;
                i += 1;
                continue;
            }
            return Err(unknown_argument(&token, PHONE_FLAGS));
        }

        match flag {
            "--generate-wallet" => generate = true,
            "--mine" => {
                mine = true;
                if let Some(v) = inline {
                    if !sanitize_cli_value(v).is_empty() {
                        reward = Some(parse_kron1_arg(v)?);
                    }
                }
            }
            "--hub" | "--node-only" => hub_only = true,
            "--show-mnemonic" => show_mnemonic = true,
            "--phone" => phone = true,
            "--reward-address" | "--miner-address" => {
                reward = Some(take_reward(inline, raw, &mut i, flag)?);
            }
            "--port" => {
                let v = take_cli_value(inline, raw, &mut i, "--port")?;
                port = v.parse().map_err(|_| "invalid --port")?;
            }
            "--port-auto" => port_auto = true,
            "--explorer-port" => {
                let v = take_cli_value(inline, raw, &mut i, "--explorer-port")?;
                explorer_port = Some(v.parse().map_err(|_| "invalid --explorer-port")?);
            }
            "--data-dir" => {
                data_dir = Some(PathBuf::from(take_cli_value(inline, raw, &mut i, "--data-dir")?));
            }
            "--bootstrap" | "--node" => {
                let v = take_cli_value(inline, raw, &mut i, "--bootstrap")?;
                bootstrap = Some(parse_peer_addr(&v)?);
            }
            "--no-discovery" => no_discovery = true,
            "--no-bootstrap" => no_bootstrap = true,
            "--no-mine" => {}
            "--help" | "-h" => {}
            other if looks_like_kron1(other) => {
                reward = Some(parse_kron1_arg(other)?);
                mine = true;
            }
            other => return Err(unknown_argument(other, PHONE_FLAGS)),
        }
        i += 1;
    }
    if reward.is_some() && !hub_only && !generate && !show_mnemonic {
        mine = true;
    }
    Ok(PhoneCli {
        generate,
        mine,
        prompt_mine,
        hub_only,
        show_mnemonic,
        reward,
        port,
        port_auto,
        explorer_port,
        data_dir: data_dir.unwrap_or_else(|| PathBuf::from("kron-phone")),
        bootstrap,
        phone,
        no_discovery,
        no_bootstrap,
    })
}

/// Parse `kron-node` argv (already without argv[0]).
pub fn parse_node_cli(raw: &[String]) -> Result<NodeCli, String> {
    let mut port = 8000u16;
    let mut explorer_port = 8080u16;
    let mut data_dir = None;
    let mut follow = None;
    let mut name = None;
    let mut print_identity = false;
    let mut read_only = false;
    let mut public_hub = false;
    let mut no_discovery = false;
    let mut public_ip = None;
    let mut i = 0;
    while i < raw.len() {
        let token = sanitize_cli_value(&raw[i]);
        let (flag, inline) = split_eq_flag(&token);
        if !flag.starts_with('-') && looks_like_kron1(flag) {
            return Err(NODE_MINE_REFUSAL.into());
        }
        match flag {
            "--port" => {
                port = take_cli_value(inline, raw, &mut i, "--port")?
                    .parse()
                    .map_err(|_| "invalid --port")?;
            }
            "--explorer-port" => {
                explorer_port = take_cli_value(inline, raw, &mut i, "--explorer-port")?
                    .parse()
                    .map_err(|_| "invalid --explorer-port")?;
            }
            "--data-dir" => {
                data_dir = Some(PathBuf::from(take_cli_value(
                    inline,
                    raw,
                    &mut i,
                    "--data-dir",
                )?));
            }
            "--follow" | "--bootstrap" | "--node" => {
                let v = take_cli_value(inline, raw, &mut i, "--follow")?;
                follow = Some(parse_peer_addr(&v)?);
            }
            "--name" => {
                name = Some(take_cli_value(inline, raw, &mut i, "--name")?);
            }
            "--hub" => public_hub = true,
            "--public-ip" => {
                public_ip = Some(parse_public_ipv4(&take_cli_value(
                    inline,
                    raw,
                    &mut i,
                    "--public-ip",
                )?)?);
            }
            "--read-only" => read_only = true,
            "--no-mine" => {}
            "--no-discovery" => no_discovery = true,
            "--print-identity" => print_identity = true,
            "--reward-address" | "--miner-address" | "--mine" | "--miner-only" | "--miner-ui" => {
                return Err(NODE_MINE_REFUSAL.into());
            }
            other => return Err(unknown_argument(other, NODE_FLAGS)),
        }
        i += 1;
    }
    Ok(NodeCli {
        port,
        explorer_port,
        data_dir,
        follow,
        name,
        print_identity,
        read_only,
        public_hub,
        no_discovery,
        public_ip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_addr() -> String {
        KronAddress::from_hash([0xAB; 32]).into_string()
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn mine_reward_address_flag() {
        let a = sample_addr();
        let cli = parse_phone_cli(&argv(&["--mine", "--reward-address", &a])).unwrap();
        assert!(cli.mine);
        assert!(!cli.prompt_mine);
        assert_eq!(cli.reward.as_ref().unwrap().as_str(), a);
    }

    #[test]
    fn mine_miner_address_flag() {
        let a = sample_addr();
        let cli = parse_phone_cli(&argv(&["--mine", "--miner-address", &a])).unwrap();
        assert!(cli.mine);
        assert_eq!(cli.reward.as_ref().unwrap().as_str(), a);
    }

    #[test]
    fn mine_positional_address() {
        let a = sample_addr();
        let cli = parse_phone_cli(&argv(&["--mine", &a])).unwrap();
        assert!(cli.mine);
        assert_eq!(cli.reward.as_ref().unwrap().as_str(), a);
    }

    #[test]
    fn bare_positional_address_implies_mine() {
        let a = sample_addr();
        let cli = parse_phone_cli(&argv(&[&a])).unwrap();
        assert!(cli.mine);
        assert_eq!(cli.reward.as_ref().unwrap().as_str(), a);
    }

    #[test]
    fn mine_equals_and_quoted_forms() {
        let a = sample_addr();
        let eq = format!("--reward-address={a}");
        let cli = parse_phone_cli(&argv(&["--mine", &eq])).unwrap();
        assert_eq!(cli.reward.as_ref().unwrap().as_str(), a);

        let quoted = format!("\"{a}\"");
        let cli = parse_phone_cli(&argv(&["--mine", &quoted])).unwrap();
        assert_eq!(cli.reward.as_ref().unwrap().as_str(), a);
    }

    #[test]
    fn menu_option_1_generates_without_mine_or_listen() {
        let cli = parse_phone_cli(&argv(&["1"])).unwrap();
        assert!(cli.generate);
        assert!(!cli.mine);
        assert!(!cli.hub_only);
        assert!(!cli.port_auto);
        assert_eq!(cli.port, 8000);
    }

    #[test]
    fn port_auto_flag() {
        let cli = parse_phone_cli(&argv(&["--port-auto"])).unwrap();
        assert!(cli.port_auto);
        assert!(!cli.mine);
        assert!(!cli.generate);
    }

    #[test]
    fn menu_option_2_without_address_prompts() {
        let cli = parse_phone_cli(&argv(&["2"])).unwrap();
        assert!(cli.mine);
        assert!(cli.prompt_mine);
        assert!(cli.reward.is_none());
    }

    #[test]
    fn menu_option_2_with_positional_address() {
        let a = sample_addr();
        let cli = parse_phone_cli(&argv(&["2", &a])).unwrap();
        assert!(cli.mine);
        assert_eq!(cli.reward.as_ref().unwrap().as_str(), a);
    }

    #[test]
    fn unknown_argument_lists_valid_flags() {
        let err = parse_phone_cli(&argv(&["--not-a-real-flag"])).unwrap_err();
        assert!(err.starts_with("unknown argument: --not-a-real-flag"));
        assert!(err.contains("valid flags:"));
        assert!(err.contains("--mine"));
        assert!(err.contains("--reward-address"));
        assert!(err.contains("--miner-address"));
    }

    #[test]
    fn menu_input_trims_newlines_and_quotes() {
        let a = sample_addr();
        let parsed = parse_menu_reward_input(&format!("  \"{a}\"\r\n")).unwrap();
        assert_eq!(parsed.as_str(), a);
    }

    #[test]
    fn menu_input_joins_termux_wrapped_address() {
        let a = sample_addr();
        let wrapped = format!("{}\n{}", &a[..32], &a[32..]);
        let parsed = parse_menu_reward_input(&wrapped).unwrap();
        assert_eq!(parsed.as_str(), a);
        let spaced = format!("{} {}", &a[..40], &a[40..]);
        let parsed = parse_menu_reward_input(&spaced).unwrap();
        assert_eq!(parsed.as_str(), a);
    }

    #[test]
    fn truncated_reward_address_explains_checksum() {
        let a = sample_addr();
        let truncated = &a[..40];
        let err = parse_kron1_arg(truncated).unwrap_err();
        assert!(err.contains("40"), "{err}");
        assert!(err.contains("63"), "{err}");
        assert!(err.contains("one line"), "{err}");
        assert!(is_incomplete_kron1(truncated));
        assert!(!is_incomplete_kron1(&a));
    }

    #[test]
    fn menu_input_accepts_flag_prefix_and_option_2() {
        let a = sample_addr();
        let parsed = parse_menu_reward_input(&format!("--reward-address {a}")).unwrap();
        assert_eq!(parsed.as_str(), a);
        let parsed = parse_menu_reward_input(&format!("2 {a}")).unwrap();
        assert_eq!(parsed.as_str(), a);
    }

    #[test]
    fn quoted_flag_and_address_as_one_token() {
        let a = sample_addr();
        let combined = format!("--reward-address {a}");
        let cli = parse_phone_cli(&argv(&["--mine", &combined])).unwrap();
        assert_eq!(cli.reward.as_ref().unwrap().as_str(), a);
    }

    #[test]
    fn phone_mine_tokens_detected() {
        let a = sample_addr();
        assert!(is_phone_mine_cli_token("--mine"));
        assert!(is_phone_mine_cli_token("--reward-address"));
        assert!(is_phone_mine_cli_token(&a));
        assert!(!is_phone_mine_cli_token("--follow"));
    }

    #[test]
    fn cargo_flags_are_not_phone_args() {
        for arg in ["--bin", "bin", "--release", "-p", "cargo"] {
            let err = parse_phone_cli(&argv(&[arg])).unwrap_err();
            assert!(
                err.contains("that is a cargo flag"),
                "expected cargo-flag hint for {arg}, got {err}"
            );
            assert!(err.contains(TERMUX_BUILD_CMD), "{err}");
        }
        let err = parse_phone_cli(&argv(&["--bin", "kron-phone"])).unwrap_err();
        assert!(err.contains(TERMUX_BUILD_CMD), "{err}");
    }

    #[test]
    fn no_discovery_flag() {
        let cli = parse_phone_cli(&argv(&["--no-discovery"])).unwrap();
        assert!(cli.no_discovery);
        assert!(!cli.mine);
    }

    #[test]
    fn no_bootstrap_flag_is_lan_only() {
        let cli = parse_phone_cli(&argv(&["--no-bootstrap"])).unwrap();
        assert!(cli.no_bootstrap);
        assert!(cli.bootstrap.is_none());
        let a = sample_addr();
        let cli = parse_phone_cli(&argv(&[
            "--mine",
            "--reward-address",
            &a,
            "--bootstrap",
            "203.0.113.10:8000",
            "--no-bootstrap",
        ]))
        .unwrap();
        assert!(cli.no_bootstrap);
        assert_eq!(
            cli.bootstrap.unwrap().to_string(),
            "203.0.113.10:8000"
        );
    }

    #[test]
    fn node_hub_flag_is_public_relay_not_mine() {
        let cli = parse_node_cli(&argv(&[
            "--hub",
            "--port",
            "8000",
            "--explorer-port",
            "8080",
        ]))
        .unwrap();
        assert!(cli.public_hub);
        assert!(!cli.read_only);
        assert_eq!(cli.port, 8000);
        assert_eq!(cli.explorer_port, 8080);
        let err = parse_node_cli(&argv(&["--mine"])).unwrap_err();
        assert!(err.contains("phone-only"), "{err}");
    }

    #[test]
    fn node_public_ip_flag() {
        let cli = parse_node_cli(&argv(&["--hub", "--public-ip", "144.91.105.244"])).unwrap();
        assert_eq!(cli.public_ip, Some(Ipv4Addr::new(144, 91, 105, 244)));
        let cli = parse_node_cli(&argv(&["--public-ip=203.0.113.10:8000"])).unwrap();
        assert_eq!(cli.public_ip, Some(Ipv4Addr::new(203, 0, 113, 10)));
        let err = parse_node_cli(&argv(&["--public-ip", "0.0.0.0"])).unwrap_err();
        assert!(err.contains("0.0.0.0"), "{err}");
    }

    #[test]
    fn x86_listen_without_follow_is_hub() {
        assert_eq!(
            decide_node_run_mode(false, false, false, true),
            NodeRunMode::PublicHub
        );
        assert_eq!(
            decide_node_run_mode(true, false, false, true),
            NodeRunMode::PublicHub
        );
        assert_eq!(
            decide_node_run_mode(true, false, true, true),
            NodeRunMode::PublicHub
        );
    }

    #[test]
    fn x86_follow_or_read_only_is_viewer() {
        assert_eq!(
            decide_node_run_mode(false, false, true, true),
            NodeRunMode::Viewer
        );
        assert_eq!(
            decide_node_run_mode(false, true, false, true),
            NodeRunMode::Viewer
        );
    }

    #[test]
    fn arm_without_hub_flag_is_phone_hub() {
        assert_eq!(
            decide_node_run_mode(false, false, false, false),
            NodeRunMode::PhoneHub
        );
        assert_eq!(
            decide_node_run_mode(true, false, false, false),
            NodeRunMode::PublicHub
        );
        assert_eq!(
            decide_node_run_mode(false, true, false, false),
            NodeRunMode::Viewer
        );
    }

    #[test]
    fn no_mine_does_not_force_viewer() {
        let cli = parse_node_cli(&argv(&["--no-mine"])).unwrap();
        assert!(!cli.read_only);
        assert!(!cli.public_hub);
        assert_eq!(
            decide_node_run_mode(cli.public_hub, cli.read_only, cli.follow.is_some(), true),
            NodeRunMode::PublicHub
        );
    }
}
