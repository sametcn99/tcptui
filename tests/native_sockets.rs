use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use tcptui::model::{ConnectionRow, Protocol};

fn loopback_pair(ip: IpAddr) -> (TcpListener, TcpStream, TcpStream) {
    let listener = TcpListener::bind((ip, 0)).expect("bind TCP loopback");
    let client = TcpStream::connect(listener.local_addr().unwrap()).expect("connect TCP loopback");
    let (server, _) = listener.accept().unwrap();
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    (listener, client, server)
}

fn owned_row(
    rows: Vec<ConnectionRow>,
    local: SocketAddr,
    remote: Option<SocketAddr>,
    protocol: Protocol,
) -> ConnectionRow {
    let pid = std::process::id();
    rows.into_iter()
        .find(|row| {
            row.pid == pid
                && row.id.local == local
                && row.id.remote == remote
                && row.protocol == protocol
        })
        .unwrap_or_else(|| panic!("missing {protocol} socket {local} for PID {pid}"))
}

#[test]
fn loopback_rows_are_visible_through_tcpvcon() {
    tcptui::net::initialize().unwrap();
    let pid = std::process::id().to_string();
    for ip in [
        IpAddr::from(Ipv4Addr::LOCALHOST),
        IpAddr::from(Ipv6Addr::LOCALHOST),
    ] {
        let (listener, client, server) = loopback_pair(ip);
        let udp = UdpSocket::bind((ip, 0)).unwrap();
        let listen = listener.local_addr().unwrap();
        let local = client.local_addr().unwrap();
        let remote = server.local_addr().unwrap();
        let udp_addr = udp.local_addr().unwrap();

        let rows = tcptui::net::collect_sockets().unwrap();
        let tcp = owned_row(rows.clone(), local, Some(remote), Protocol::Tcp);
        assert!(tcp.is_established());
        assert_eq!(tcp.id.remote, Some(remote));
        let bound = owned_row(rows.clone(), listen, None, Protocol::Tcp);
        assert_eq!(bound.state, Some(netstat2::TcpState::Listen));
        assert!(
            owned_row(rows, udp_addr, None, Protocol::Udp)
                .state
                .is_none()
        );

        let expression = format!(
            "pid={pid} and (lport={} or lport={} or lport={})",
            local.port(),
            listen.port(),
            udp_addr.port()
        );
        let output = Command::new(env!("CARGO_BIN_EXE_tcpvcon"))
            .args(["-a", "-j", "-n", "--filter", &expression])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        for (addr, protocol, state) in [
            (local, "TCP", Some("ESTABLISHED")),
            (listen, "TCP", Some("LISTEN")),
            (udp_addr, "UDP", None),
        ] {
            let ip = addr.ip().to_string();
            let port = addr.port().to_string();
            assert!(
                json.iter().any(|row| {
                    row["PID"] == pid
                        && row["Local Address"] == ip
                        && row["Local Port"] == port
                        && row["Protocol"] == protocol
                        && state.is_none_or(|state| row["State"] == state)
                }),
                "missing {protocol} {addr} in {json:?}"
            );
        }
    }
}

fn validate_traffic_increases(ip: IpAddr) {
    let (_listener, mut client, mut server) = loopback_pair(ip);
    let client_addr = client.local_addr().unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut traffic = tcptui::net::TrafficReader::new(true);
    let mut sample = || {
        let rows = traffic.collect().unwrap();
        let client = owned_row(rows.clone(), client_addr, Some(server_addr), Protocol::Tcp);
        let server = owned_row(rows, server_addr, Some(client_addr), Protocol::Tcp);
        client.tx_bytes.zip(server.rx_bytes)
    };

    let deadline = Instant::now() + Duration::from_secs(10);
    let (initial_tx, initial_rx) = loop {
        if let Some(counters) = sample() {
            break counters;
        }
        assert!(
            Instant::now() < deadline,
            "counter provider never reported the owned TCP pair"
        );
        thread::sleep(Duration::from_millis(100));
    };

    let data = [17u8; 8192];
    client.write_all(&data).unwrap();
    let mut received = [0; 8192];
    server.read_exact(&mut received).unwrap();
    assert_eq!(received, data);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some((tx, rx)) = sample()
            && tx >= initial_tx + data.len() as u64
            && rx >= initial_rx + data.len() as u64
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "byte counters did not reflect the loopback transfer"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
#[test]
fn native_traffic_counters_track_ipv4_and_ipv6_tcp() {
    for ip in [
        IpAddr::from(Ipv4Addr::LOCALHOST),
        IpAddr::from(Ipv6Addr::LOCALHOST),
    ] {
        validate_traffic_increases(ip);
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "run in an isolated network namespace with CAP_NET_ADMIN"]
fn destroy_requires_the_original_socket_cookie() {
    let this = std::fs::read_link("/proc/self/ns/net").unwrap();
    if let Ok(parent) = std::fs::read_link("/proc/1/ns/net") {
        assert_ne!(this, parent, "run this test in a new network namespace");
    }
    for ip in [
        IpAddr::from(Ipv4Addr::LOCALHOST),
        IpAddr::from(Ipv6Addr::LOCALHOST),
    ] {
        let (_listener, mut client, mut server) = loopback_pair(ip);
        let local = client.local_addr().unwrap();
        let actual = owned_row(
            tcptui::net::collect_sockets().unwrap(),
            local,
            Some(client.peer_addr().unwrap()),
            Protocol::Tcp,
        );
        let mut stale = actual.clone();
        stale.id.socket_cookie = Some(actual.id.socket_cookie.unwrap() ^ (1 << 32));
        assert!(tcptui::actions::close_connection(&stale).is_err());

        client.write_all(b"ok").unwrap();
        let mut text = [0; 2];
        server.read_exact(&mut text).unwrap();
        assert_eq!(&text, b"ok");

        tcptui::actions::close_connection(&actual).unwrap();
        let after = client.read(&mut text);
        assert!(
            matches!(after, Ok(0))
                || after.as_ref().is_err_and(|error| matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                )),
            "socket should have closed: {after:?}"
        );
    }
}

#[cfg(all(target_os = "linux", feature = "linux-trace"))]
#[test]
#[ignore = "requires a BTF-enabled Linux kernel and permission to load eBPF"]
fn ebpf_reports_short_lived_tcp_connections() {
    use tcptui::app::App;
    use tcptui::{config::Config, trace};

    let (session, rx) = trace::start().expect("start Linux TCP trace");
    let mut config = Config::default();
    config.view.refresh_interval_ms = 60_000;
    let mut app = App::new(config, Some(rx));
    app.trace_session = Some(session);

    let deadline = Instant::now() + Duration::from_secs(5);
    while app.snapshot_count == 0 {
        app.poll_channels();
        assert!(
            Instant::now() < deadline,
            "initial polling snapshot never arrived"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let baseline = app.snapshot_count;
    for ip in [
        IpAddr::from(Ipv4Addr::LOCALHOST),
        IpAddr::from(Ipv6Addr::LOCALHOST),
    ] {
        let (listener, client, server) = loopback_pair(ip);
        let local = client.local_addr().unwrap().to_string();
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop((client, server, listener));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            app.poll_channels();
            if app.event_log.iter().any(|entry| {
                entry.message.contains("OPEN+CLOSE (transient") && entry.message.contains(&local)
            }) {
                break;
            }
            assert!(Instant::now() < deadline, "no transient event for {local}");
            thread::sleep(Duration::from_millis(20));
        }
    }
    assert_eq!(
        app.snapshot_count, baseline,
        "event was observed between polls"
    );
}

#[cfg(windows)]
#[test]
#[ignore = "requires an elevated Windows shell for EStats, SetTcpEntry and ETW"]
fn windows_transport_capabilities() {
    tcptui::net::initialize().unwrap();
    let ip = IpAddr::from(Ipv4Addr::LOCALHOST);
    validate_traffic_increases(ip);

    let (_session, rx) = tcptui::trace::start().expect("start Windows ETW");
    let (_listener, mut client, _server) = loopback_pair(ip);
    let local = client.local_addr().unwrap();
    let remote = client.peer_addr().unwrap();
    let row = owned_row(
        tcptui::net::collect_sockets().unwrap(),
        local,
        Some(remote),
        Protocol::Tcp,
    );
    tcptui::actions::close_connection(&row).expect("close with SetTcpEntry");
    let mut byte = [0];
    let after = client.read(&mut byte);
    assert!(
        matches!(after, Ok(0))
            || after.as_ref().is_err_and(|error| matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            )),
        "socket should have closed: {after:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let message = rx
            .recv_timeout(timeout)
            .expect("ETW did not report loopback connect");
        if let tcptui::trace::Message::Event(event) = message
            && event.connected
            && event.local == local
            && event.remote == remote
        {
            break;
        }
    }
}
