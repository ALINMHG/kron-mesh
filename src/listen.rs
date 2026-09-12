//! Shared TCP listen helpers: SO_REUSEADDR and a Termux-friendly EADDRINUSE hint.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, ToSocketAddrs, UdpSocket};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Unix EADDRINUSE. Windows WSAEADDRINUSE is 10048.
const UNIX_EADDRINUSE: i32 = 98;

/// Bind `addr` with `SO_REUSEADDR` on Unix (helps after a crash / TIME_WAIT).
/// Does **not** steal a port from a live listener — that still returns error 98.
pub fn bind_tcp_reuse(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // Windows SO_REUSEADDR can let two processes bind the same port; skip it there.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(128)?;
    Ok(socket.into())
}

pub fn is_addr_in_use(err: &io::Error) -> bool {
    err.kind() == ErrorKind::AddrInUse
        || err.raw_os_error() == Some(UNIX_EADDRINUSE)
        || err.raw_os_error() == Some(10048)
}

fn addr_in_use_code(err: Option<&io::Error>) -> i32 {
    err.and_then(|e| e.raw_os_error()).unwrap_or(UNIX_EADDRINUSE)
}

/// Body of the EADDRINUSE hint (no `[KRON …]` prefix).
pub fn port_already_in_use_message(
    service: &str,
    port: u16,
    flag: &str,
    err: Option<&io::Error>,
) -> String {
    let code = addr_in_use_code(err);
    let next = port.saturating_add(1);
    format!(
        "{service} port {port} already in use (error {code}).\n\
         Stop the old process: pkill -f kron-phone\n\
         Or use another port: {flag} {next}"
    )
}

/// Log the Termux hint (`[prefix]` on the first line only).
pub fn log_port_in_use(prefix: &str, service: &str, port: u16, flag: &str, err: Option<&io::Error>) {
    let code = addr_in_use_code(err);
    let next = port.saturating_add(1);
    crate::kron_elog(
        prefix,
        format!("{service} port {port} already in use (error {code})."),
    );
    eprintln!("Stop the old process: pkill -f kron-phone");
    eprintln!("Or use another port: {flag} {next}");
}

/// `--port-auto`: try `port`, then `port+1` … up to `max_tries` ports (capped at 5).
pub fn port_auto_candidates(port: u16, auto: bool) -> impl Iterator<Item = u16> {
    let n = if auto { 5u16 } else { 1 };
    (0..n).filter_map(move |i| port.checked_add(i).filter(|&p| p != 0))
}

/// Usable LAN IPv4: skip loopback, unspecified, multicast, broadcast.
pub fn is_usable_lan_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && ip != Ipv4Addr::BROADCAST
}

/// Best-effort IPv4 of this host on the LAN (std only).
///
/// Prefers the UDP "connect" trick to `8.8.8.8:80` (no packets need to be
/// exchanged — the kernel just picks a source address). Falls back to common
/// private gateways, hostname resolution, and Linux `/proc/net/fib_trie`.
pub fn detect_lan_ipv4() -> Option<Ipv4Addr> {
    for dest in ["8.8.8.8:80", "1.1.1.1:80"] {
        if let Some(ip) = udp_route_ipv4(dest) {
            return Some(ip);
        }
    }
    for dest in [
        "192.168.1.1:80",
        "192.168.0.1:80",
        "10.0.0.1:80",
        "172.16.0.1:80",
    ] {
        if let Some(ip) = udp_route_ipv4(dest) {
            return Some(ip);
        }
    }
    prefer_private(&enumerate_non_loopback_ipv4())
}

fn udp_route_ipv4(dest: &str) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    let _ = sock.set_nonblocking(true);
    sock.connect(dest).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if is_usable_lan_ipv4(ip) => Some(ip),
        _ => None,
    }
}

fn prefer_private(ips: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    ips.iter()
        .copied()
        .find(Ipv4Addr::is_private)
        .or_else(|| ips.first().copied())
}

fn enumerate_non_loopback_ipv4() -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    push_unique_usable(&mut ips, ipv4s_from_hostname_env());
    if let Ok(text) = std::fs::read_to_string("/etc/hostname") {
        let host = text.trim();
        if !host.is_empty() {
            push_unique_usable(&mut ips, ipv4s_from_host(host));
        }
    }
    if let Ok(text) = std::fs::read_to_string("/proc/net/fib_trie") {
        push_unique_usable(&mut ips, ipv4s_from_fib_trie(&text));
    }
    ips
}

fn ipv4s_from_hostname_env() -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    for key in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(name) = std::env::var(key) {
            let name = name.trim();
            if !name.is_empty() {
                push_unique_usable(&mut ips, ipv4s_from_host(name));
            }
        }
    }
    ips
}

fn ipv4s_from_host(host: &str) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    if let Ok(addrs) = (host, 0u16).to_socket_addrs() {
        for addr in addrs {
            if let IpAddr::V4(ip) = addr.ip() {
                if is_usable_lan_ipv4(ip) && !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    ips
}

fn push_unique_usable(out: &mut Vec<Ipv4Addr>, extra: Vec<Ipv4Addr>) {
    for ip in extra {
        if is_usable_lan_ipv4(ip) && !out.contains(&ip) {
            out.push(ip);
        }
    }
}

/// Parse Linux `fib_trie` for `/32 … LOCAL` host addresses.
fn ipv4s_from_fib_trie(text: &str) -> Vec<Ipv4Addr> {
    let mut prev_ip = None;
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let token = trimmed.trim_start_matches(['|', '+', '-', ' ']);
        if let Some(ip) = parse_ipv4_token(token) {
            prev_ip = Some(ip);
        }
        if trimmed.contains("/32") && trimmed.contains("LOCAL") {
            if let Some(ip) = prev_ip {
                if is_usable_lan_ipv4(ip) && !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

fn parse_ipv4_token(token: &str) -> Option<Ipv4Addr> {
    let ip = token.split(|c: char| !c.is_ascii_digit() && c != '.').next()?;
    if ip.is_empty() {
        return None;
    }
    ip.parse().ok()
}

pub fn format_p2p_listen_line(port: u16) -> String {
    format!("P2P listening 0.0.0.0:{port}")
}

pub fn format_lan_address_line(ip: Option<Ipv4Addr>, port: u16) -> String {
    match ip {
        Some(ip) => format!("LAN: {ip}:{port}"),
        None => format!("LAN: unknown (listening on all interfaces)"),
    }
}

/// Explorer URL for a PC on the same Wi‑Fi. Never `http://0.0.0.0:…`.
pub fn format_explorer_open_line(ip: Option<Ipv4Addr>, port: u16) -> String {
    match ip {
        Some(ip) if !ip.is_unspecified() => format!("http://{ip}:{port}"),
        Some(_) | None => format!("open explorer from PC: http://<this-phone-WiFi-IP>:{port}"),
    }
}

/// Routable public IPv4 (not RFC1918 / link-local / loopback / unspecified).
pub fn is_public_routable_ipv4(ip: Ipv4Addr) -> bool {
    is_usable_lan_ipv4(ip) && !ip.is_private() && !ip.is_link_local()
}

/// Best-effort public IPv4 of this host. VPS NICs often have the public
/// address on-interface; NATed hosts typically only see a private LAN IP.
pub fn detect_public_ipv4() -> Option<Ipv4Addr> {
    detect_lan_ipv4().filter(|ip| is_public_routable_ipv4(*ip))
}

/// Printed hub / explorer host: `--public-ip`, then a detected public IPv4,
/// then `fallback` (usually the paid VPS address from `DEFAULT_BOOTSTRAP`).
pub fn advertised_public_ipv4(cli: Option<Ipv4Addr>, fallback: Ipv4Addr) -> Ipv4Addr {
    cli.or_else(detect_public_ipv4).unwrap_or(fallback)
}

/// Browser URL for a public hub. Never `http://0.0.0.0:…`.
pub fn format_public_explorer_url(ip: Ipv4Addr, port: u16) -> String {
    let ip = if ip.is_unspecified() {
        Ipv4Addr::new(144, 91, 105, 244)
    } else {
        ip
    };
    format!("http://{ip}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn in_use_hint_matches_termux_copy() {
        let msg = port_already_in_use_message("P2P", 8000, "--port", None);
        assert_eq!(
            msg,
            "P2P port 8000 already in use (error 98).\n\
             Stop the old process: pkill -f kron-phone\n\
             Or use another port: --port 8001"
        );
        let explorer = port_already_in_use_message("Explorer", 8080, "--explorer-port", None);
        assert!(explorer.contains("Explorer port 8080 already in use (error 98)."));
        assert!(explorer.contains("pkill -f kron-phone"));
        assert!(explorer.contains("--explorer-port 8081"));
    }

    #[test]
    fn bind_reuse_then_second_live_listener_fails() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let first = bind_tcp_reuse(addr).expect("first bind");
        let bound = first.local_addr().unwrap();
        let second = bind_tcp_reuse(bound);
        assert!(second.is_err(), "live listener must still own the port");
        let err = second.unwrap_err();
        assert!(is_addr_in_use(&err), "{err}");
        drop(first);
        bind_tcp_reuse(bound).expect("rebind after drop");
    }

    #[test]
    fn port_auto_default_is_single_port() {
        let v: Vec<u16> = port_auto_candidates(8000, false).collect();
        assert_eq!(v, vec![8000]);
        let v: Vec<u16> = port_auto_candidates(8000, true).collect();
        assert_eq!(v, vec![8000, 8001, 8002, 8003, 8004]);
    }

    #[test]
    fn usable_lan_ipv4_skips_loopback_and_unspecified() {
        assert!(!is_usable_lan_ipv4(Ipv4Addr::UNSPECIFIED));
        assert!(!is_usable_lan_ipv4(Ipv4Addr::LOCALHOST));
        assert!(!is_usable_lan_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_usable_lan_ipv4(Ipv4Addr::BROADCAST));
        assert!(is_usable_lan_ipv4(Ipv4Addr::new(192, 168, 1, 42)));
        assert!(is_usable_lan_ipv4(Ipv4Addr::new(10, 0, 0, 8)));
    }

    #[test]
    fn bind_all_and_lan_log_lines() {
        assert_eq!(format_p2p_listen_line(8000), "P2P listening 0.0.0.0:8000");
        assert_eq!(
            format_lan_address_line(Some(Ipv4Addr::new(192, 168, 1, 42)), 8000),
            "LAN: 192.168.1.42:8000"
        );
        assert_eq!(
            format_lan_address_line(None, 8000),
            "LAN: unknown (listening on all interfaces)"
        );
        assert_eq!(
            format_explorer_open_line(Some(Ipv4Addr::new(192, 168, 1, 42)), 8080),
            "http://192.168.1.42:8080"
        );
        assert_eq!(
            format_explorer_open_line(None, 8080),
            "open explorer from PC: http://<this-phone-WiFi-IP>:8080"
        );
        assert_eq!(
            format_explorer_open_line(Some(Ipv4Addr::UNSPECIFIED), 8080),
            "open explorer from PC: http://<this-phone-WiFi-IP>:8080"
        );
        assert_eq!(
            format_public_explorer_url(Ipv4Addr::new(144, 91, 105, 244), 8080),
            "http://144.91.105.244:8080"
        );
        assert_eq!(
            format_public_explorer_url(Ipv4Addr::UNSPECIFIED, 8080),
            "http://144.91.105.244:8080"
        );
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_public_routable_ipv4(Ipv4Addr::new(144, 91, 105, 244)));
        assert_eq!(
            advertised_public_ipv4(Some(Ipv4Addr::new(203, 0, 113, 10)), Ipv4Addr::new(144, 91, 105, 244)),
            Ipv4Addr::new(203, 0, 113, 10)
        );
        assert_eq!(
            advertised_public_ipv4(None, Ipv4Addr::new(144, 91, 105, 244)),
            detect_public_ipv4().unwrap_or(Ipv4Addr::new(144, 91, 105, 244))
        );
    }

    #[test]
    fn detect_lan_ipv4_never_returns_loopback() {
        if let Some(ip) = detect_lan_ipv4() {
            assert!(is_usable_lan_ipv4(ip), "{ip}");
            assert_ne!(ip, Ipv4Addr::LOCALHOST);
            assert_ne!(ip, Ipv4Addr::UNSPECIFIED);
        }
    }

    #[test]
    fn fib_trie_picks_local_host_not_loopback() {
        let sample = "\
Main:
  +-- 127.0.0.0
     /8 host LOCAL
        |-- 127.0.0.1
           /32 host LOCAL
  +-- 192.168.1.0
     /24 link UNICAST
        |-- 192.168.1.42
           /32 host LOCAL
";
        let ips = ipv4s_from_fib_trie(sample);
        assert_eq!(ips, vec![Ipv4Addr::new(192, 168, 1, 42)]);
        assert_eq!(
            prefer_private(&ips),
            Some(Ipv4Addr::new(192, 168, 1, 42))
        );
    }
}
