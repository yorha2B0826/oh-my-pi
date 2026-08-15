//! SOCKS5 listener and the TCP-over-UDP flow state machine.
//!
//! Port of `ustcode/packages/ustcode/src/iwan/socks.ts`. A single UDP tunnel
//! multiplexes many inner TCP connections, each represented by a [`Flow`] that
//! hand-builds IPv4/TCP datagrams (via [`crate::tcp`]) and carries them through
//! the tunnel. Local applications reach the tunnel through a SOCKS5 proxy
//! bound to `127.0.0.1`.
//!
//! The flow machine reproduces the reference state model exactly:
//!
//! - `greeting` → `request` → `resolving` (domains) → `connecting` →
//!   `established` → `closing`.
//! - A sliding window (`TCP_WINDOW`, scaled by the peer's window-scale option),
//!   retransmit with `RETRANSMIT_AFTER` / `MAX_RETRIES`, a keepalive
//!   `EchoRequest` every `KEEPALIVE_AFTER`, and idle/connect timeouts.

use std::{
	collections::HashMap,
	net::{Ipv4Addr, SocketAddr},
	sync::Arc,
	time::Duration,
};

use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{TcpListener, TcpStream, UdpSocket},
	sync::{Mutex, mpsc, watch},
	time::{Instant, interval},
};

use crate::{
	crypto::xor,
	protocol::{AuthResult, PacketType, control_packet, data_packet, packet_header},
	tcp::{
		BuildTcpPacket, build_tcp_packet, flags, parse_tcp_options, parse_tcp_packet, sequence_end,
		syn_options,
	},
	tunnel::{AuthenticatedTunnel, ENCRYPTION},
};

/// Maximum payload bytes per inner TCP segment.
const MAX_PACKET_PAYLOAD: usize = 1200;
/// Maximum in-flight bytes per flow (the advertised receive window).
const TCP_WINDOW: u32 = 1024 * 1024;
/// Window value placed in outgoing TCP headers (saturates a `u16`).
const TCP_ADVERTISED_WINDOW: u16 = 0xffff;
/// How long a pending segment waits before retransmission.
const RETRANSMIT_AFTER: Duration = Duration::from_millis(1000);
/// Retries before the connection is declared dead.
const MAX_RETRIES: u32 = 5;
/// Idle keepalive cadence for the tunnel.
const KEEPALIVE_AFTER: Duration = Duration::from_millis(10_000);
/// Timeout for the SYN/SYN-ACK handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle timeout for an established flow (4 × connect timeout).
const IDLE_TIMEOUT: Duration = Duration::from_millis(120_000);
/// First local (in-tunnel) port handed out to flows.
const LOCAL_PORT_START: u16 = 49152;
/// Local task tick cadence (retransmit / keepalive / timeouts).
const TICK_INTERVAL: Duration = Duration::from_millis(50);

/// A queued, unacknowledged outbound segment awaiting ACK or retransmit.
struct PendingSegment {
	packet:   Vec<u8>,
	sequence: u32,
	end:      u32,
	flags:    u8,
	sent_at:  Instant,
	retries:  u32,
}

/// The SOCKS handshake / TCP connection phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowState {
	Greeting,
	Request,
	Resolving,
	Connecting,
	Established,
	Closing,
}

/// One inner TCP connection multiplexed over the tunnel.
struct Flow {
	/// Outbound channel to the local socket writer task (a `None` sentinel
	/// half-closes the socket).
	write:               mpsc::UnboundedSender<Option<Vec<u8>>>,
	state:               FlowState,
	input:               Vec<u8>,
	local_port:          u16,
	remote_ip:           Option<Ipv4Addr>,
	remote_port:         Option<u16>,
	send_sequence:       u32,
	receive_sequence:    u32,
	remote_window:       u32,
	remote_window_scale: u8,
	pending:             Vec<PendingSegment>,
	last_activity:       Instant,
	local_fin:           bool,
	remote_fin:          bool,
	resolving:           bool,
}

/// Shared mutable state (a single lock keeps the state machine faithful to the
/// single-threaded reference while allowing concurrent socket tasks).
struct Shared {
	flows:     HashMap<u64, Arc<Mutex<Flow>>>,
	by_port:   HashMap<u16, u64>,
	next_id:   u64,
	next_port: u16,
}

/// Public status snapshot, mirrored to the napi layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksStatus {
	pub address: SocketAddr,
	pub flows:   usize,
}

/// Error type for the SOCKS5 layer.
#[derive(Debug, thiserror::Error)]
pub enum SocksError {
	#[error("io error: {0}")]
	Io(#[from] std::io::Error),
	#[error("DNS resolution failed for {0}")]
	Dns(String),
}

/// A running SOCKS5 listener draining an authenticated tunnel.
pub struct Socks {
	local:    SocketAddr,
	shared:   Arc<Mutex<Shared>>,
	shutdown: Arc<watch::Sender<bool>>,
	/// Set when the tunnel dies on its own (UDP socket error or a server `Close`
	/// packet). `None` means still healthy; the string is a human-readable cause.
	failure:  Arc<watch::Sender<Option<String>>>,
	tasks:    Vec<tokio::task::JoinHandle<()>>,
}

impl Socks {
	/// Bind the SOCKS5 proxy on `127.0.0.1:0` and start draining `tunnel`.
	pub async fn open(tunnel: AuthenticatedTunnel) -> Result<Self, SocksError> {
		let (udp, auth, xor_key) = tunnel.into_parts();
		let udp = Arc::new(udp);
		let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
		let local = listener.local_addr()?;
		let shared = Arc::new(Mutex::new(Shared {
			flows:     HashMap::new(),
			by_port:   HashMap::new(),
			next_id:   0,
			next_port: LOCAL_PORT_START,
		}));
		let (shutdown, shutdown_rx) = watch::channel(false);
		let (failure, _failure_rx) = watch::channel::<Option<String>>(None);
		// `failure` is also driven by the tasks themselves (UDP socket errors and
		// server `Close`), so wrap both senders in `Arc` for shared ownership.
		let shutdown = Arc::new(shutdown);
		let failure = Arc::new(failure);
		let mut tasks = Vec::new();

		// Accept loop.
		{
			let shared = Arc::clone(&shared);
			let udp = Arc::clone(&udp);
			let auth = auth.clone();
			let mut rx = shutdown_rx.clone();
			tasks.push(tokio::spawn(async move {
				loop {
					tokio::select! {
						_ = rx.changed() => break,
						accepted = listener.accept() => {
							let Ok((stream, _)) = accepted else { break };
							spawn_flow(stream, Arc::clone(&shared), Arc::clone(&udp), auth.clone(), xor_key).await;
						}
					}
				}
			}));
		}

		// UDP receive loop: this is the tunnel's heartbeat. A socket error here
		// means the data plane is dead (NAT expiry, server restart, …) — surface
		// it instead of silently `break`-ing and leaving a zombie SOCKS listener.
		{
			let shared = Arc::clone(&shared);
			let udp = Arc::clone(&udp);
			let auth = auth.clone();
			let shutdown = Arc::clone(&shutdown);
			let failure = Arc::clone(&failure);
			let mut rx = shutdown_rx.clone();
			tasks.push(tokio::spawn(async move {
				let mut buf = vec![0u8; 65536];
				loop {
					tokio::select! {
						_ = rx.changed() => break,
						received = udp.recv(&mut buf) => {
							match received {
								Ok(n) => receive_vpn(&buf[..n], &shared, &udp, &auth, &xor_key, shutdown.as_ref(), failure.as_ref()).await,
								Err(err) => {
									report_failure(shutdown.as_ref(), failure.as_ref(), &format!("iWAN tunnel data plane lost: {err}")).await;
									break;
								},
							}
						}
					}
				}
			}));
		}

		// Tick loop.
		{
			let shared = Arc::clone(&shared);
			let udp = Arc::clone(&udp);
			let auth = auth.clone();
			let mut rx = shutdown_rx.clone();
			tasks.push(tokio::spawn(async move {
				let mut ticker = interval(TICK_INTERVAL);
				let mut last_keepalive = Instant::now();
				loop {
					tokio::select! {
						_ = rx.changed() => break,
						_ = ticker.tick() => {
							let now = Instant::now();
							if now.duration_since(last_keepalive) >= KEEPALIVE_AFTER {
								last_keepalive = now;
								send_control(&udp, &auth, PacketType::EchoRequest).await;
							}
							tick(&shared, &udp, &auth, &xor_key).await;
						}
					}
				}
			}));
		}

		drop(shutdown_rx);

		Ok(Self { local, shared, shutdown, failure, tasks })
	}

	/// The bound `127.0.0.1:port` of the SOCKS5 listener.
	pub const fn local(&self) -> SocketAddr {
		self.local
	}

	/// A status snapshot for the napi layer.
	pub async fn status(&self) -> SocksStatus {
		SocksStatus { address: self.local, flows: self.shared.lock().await.flows.len() }
	}

	/// Stop all tasks and drop the tunnel socket.
	pub async fn stop(&mut self) {
		let _ = self.shutdown.send(true);
		for task in self.tasks.drain(..) {
			task.abort();
		}
		for (_, flow) in self.shared.lock().await.flows.drain() {
			let f = flow.lock().await;
			let _ = f.write.send(None);
		}
	}

	/// A clone of the tunnel's failure signal. It yields `None` while healthy and
	/// a `Some(cause)` once the tunnel dies on its own (UDP error or server
	/// `Close`). A clean `stop()` keeps it at `None`.
	pub fn failure(&self) -> watch::Receiver<Option<String>> {
		self.failure.subscribe()
	}
}

// ---------------------------------------------------------------------------
// Tunnel send helpers
// ---------------------------------------------------------------------------

async fn send_control(udp: &UdpSocket, auth: &AuthResult, packet_type: PacketType) {
	let header = packet_header(packet_type, ENCRYPTION, auth.sid, auth.token);
	let _ = udp.send(&control_packet(&header, &[])).await;
}

async fn send_inner(udp: &UdpSocket, auth: &AuthResult, xor_key: &[u8; 8], inner: &[u8]) {
	let payload = xor(inner, xor_key);
	let header = packet_header(PacketType::DataEncrypted, ENCRYPTION, auth.sid, auth.token);
	let _ = udp.send(&data_packet(&header, &payload)).await;
}

/// Record that the tunnel died on its own and broadcast shutdown so the accept
/// and tick loops unwind. Idempotent: the first cause wins.
async fn report_failure(shutdown: &watch::Sender<bool>, failure: &watch::Sender<Option<String>>, cause: &str) {
	let _ = failure.send_replace(Some(cause.to_string()));
	let _ = shutdown.send(true);
}

// ---------------------------------------------------------------------------
// Flow lifecycle
// ---------------------------------------------------------------------------

async fn spawn_flow(
	stream: TcpStream,
	shared: Arc<Mutex<Shared>>,
	udp: Arc<UdpSocket>,
	auth: AuthResult,
	xor_key: [u8; 8],
) {
	let _ = stream.set_nodelay(true);
	let (mut reader, mut writer) = stream.into_split();
	let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Option<Vec<u8>>>();

	let flow = Arc::new(Mutex::new(Flow {
		write:               write_tx.clone(),
		state:               FlowState::Greeting,
		input:               Vec::new(),
		local_port:          0,
		remote_ip:           None,
		remote_port:         None,
		send_sequence:       0,
		receive_sequence:    0,
		remote_window:       65535,
		remote_window_scale: 0,
		pending:             Vec::new(),
		last_activity:       Instant::now(),
		local_fin:           false,
		remote_fin:          false,
		resolving:           false,
	}));

	// Register under a fresh id (local_port is allocated on open_remote).
	{
		let mut sh = shared.lock().await;
		let id = sh.next_id;
		sh.next_id += 1;
		sh.flows.insert(id, Arc::clone(&flow));
	}

	// Writer task.
	{
		let flow = Arc::clone(&flow);
		tokio::spawn(async move {
			while let Some(item) = write_rx.recv().await {
				match item {
					Some(bytes) if !bytes.is_empty() => {
						if writer.write_all(&bytes).await.is_err() {
							break;
						}
					},
					Some(_) => {},
					None => {
						let _ = writer.shutdown().await;
						break;
					},
				}
			}
			flow.lock().await.local_fin = true;
		});
	}

	// Reader task.
	{
		let flow = Arc::clone(&flow);
		tokio::spawn(async move {
			let mut buf = vec![0u8; 65536];
			loop {
				match reader.read(&mut buf).await {
					Ok(0) => {
						let mut f = flow.lock().await;
						f.local_fin = true;
						drop(f);
						flush_remote(&flow, &udp, &auth, &xor_key).await;
						break;
					},
					Ok(n) => {
						let mut f = flow.lock().await;
						f.input.extend_from_slice(&buf[..n]);
						f.last_activity = Instant::now();
						drop(f);
						process_local(&flow, &shared, &udp, &auth, &xor_key).await;
						// `process_local` only drives the SOCKS5 handshake. Once the
						// flow is established, every subsequent local read must also
						// drain the buffered application bytes into inner TCP segments.
						flush_remote(&flow, &udp, &auth, &xor_key).await;
					},
					Err(_) => break,
				}
			}
		});
	}
}

// ---------------------------------------------------------------------------
// Local (SOCKS socket → tunnel) direction
// ---------------------------------------------------------------------------

/// Drive the local SOCKS5 handshake + payload loop for `flow`.
async fn process_local(
	flow: &Arc<Mutex<Flow>>,
	shared: &Arc<Mutex<Shared>>,
	udp: &Arc<UdpSocket>,
	auth: &AuthResult,
	xor_key: &[u8; 8],
) {
	// Greeting.
	{
		let mut f = flow.lock().await;
		loop {
			if f.state != FlowState::Greeting {
				break;
			}
			if f.input.len() < 2 {
				return;
			}
			let methods_len = f.input[1] as usize;
			if f.input.len() < methods_len + 2 {
				return;
			}
			let version = f.input[0];
			let methods: Vec<u8> = f.input[2..methods_len + 2].to_vec();
			f.input.drain(..methods_len + 2);
			if version == 5 && methods.contains(&0) {
				let _ = f.write.send(Some(vec![5, 0]));
				f.state = FlowState::Request;
			} else {
				let _ = f.write.send(Some(vec![5, 0xff]));
				f.state = FlowState::Closing;
				let _ = f.write.send(None);
				return;
			}
		}
	}

	// Request: parse CMD / ATYP / DST.ADDR / DST.PORT.
	let request = {
		let mut f = flow.lock().await;
		if f.state != FlowState::Request {
			return;
		}
		if f.input.len() < 4 {
			return;
		}
		if f.input[0] != 5 || f.input[1] != 1 || f.input[2] != 0 {
			let _ = f.write.send(Some(vec![5, 7, 0, 1, 0, 0, 0, 0, 0, 0]));
			f.state = FlowState::Closing;
			let _ = f.write.send(None);
			return;
		}
		match f.input[3] {
			1 => {
				if f.input.len() < 10 {
					return;
				}
				let ip = Ipv4Addr::new(f.input[4], f.input[5], f.input[6], f.input[7]);
				let port = u16::from_be_bytes([f.input[8], f.input[9]]);
				f.input.drain(..10);
				Some((ip, port))
			},
			3 => {
				if f.input.len() < 5 {
					return;
				}
				let domain_len = f.input[4] as usize;
				let request_len = 5 + domain_len + 2;
				if domain_len == 0 || f.input.len() < request_len {
					return;
				}
				let domain = String::from_utf8_lossy(&f.input[5..5 + domain_len]).into_owned();
				let port = u16::from_be_bytes([f.input[5 + domain_len], f.input[6 + domain_len]]);
				f.input.drain(..request_len);
				f.state = FlowState::Resolving;
				f.resolving = true;
				resolve_remote(flow, shared, udp, auth, *xor_key, domain, port);
				None
			},
			_ => {
				let _ = f.write.send(Some(vec![5, 8, 0, 1, 0, 0, 0, 0, 0, 0]));
				f.state = FlowState::Closing;
				let _ = f.write.send(None);
				return;
			},
		}
	};

	if let Some((ip, port)) = request {
		open_remote(flow, shared, udp, auth, xor_key, ip, port).await;
	}
}

/// Background DNS resolution, then transition into the connecting state.
fn resolve_remote(
	flow: &Arc<Mutex<Flow>>,
	shared: &Arc<Mutex<Shared>>,
	udp: &Arc<UdpSocket>,
	auth: &AuthResult,
	xor_key: [u8; 8],
	domain: String,
	port: u16,
) {
	let flow = Arc::clone(flow);
	let shared = Arc::clone(shared);
	let udp = Arc::clone(udp);
	let auth = auth.clone();
	tokio::spawn(async move {
		let resolved = crate::dns::resolve_ipv4(&domain).await.ok();

		let mut f = flow.lock().await;
		f.resolving = false;
		match resolved {
			Some(ip) if f.state == FlowState::Resolving => {
				drop(f);
				open_remote(&flow, &shared, &udp, &auth, &xor_key, ip, port).await;
			},
			_ => {
				if f.state != FlowState::Closing {
					f.state = FlowState::Closing;
					let _ = f.write.send(Some(vec![5, 4, 0, 1, 0, 0, 0, 0, 0, 0]));
					let _ = f.write.send(None);
				}
			},
		}
	});
}

/// Allocate an in-tunnel port, arm the SYN, and move to `connecting`.
async fn open_remote(
	flow: &Arc<Mutex<Flow>>,
	shared: &Arc<Mutex<Shared>>,
	udp: &Arc<UdpSocket>,
	auth: &AuthResult,
	xor_key: &[u8; 8],
	ip: Ipv4Addr,
	port: u16,
) {
	let local_port = {
		let mut sh = shared.lock().await;
		let Some(p) = allocate_port(&mut sh) else {
			let mut f = flow.lock().await;
			if f.state != FlowState::Closing {
				f.state = FlowState::Closing;
				let _ = f.write.send(Some(vec![5, 1, 0, 1, 0, 0, 0, 0, 0, 0]));
				let _ = f.write.send(None);
			}
			return;
		};
		let id = flow_id(&sh, flow);
		sh.by_port.insert(p, id);
		p
	};

	let mut f = flow.lock().await;
	f.local_port = local_port;
	f.remote_ip = Some(ip);
	f.remote_port = Some(port);
	f.state = FlowState::Connecting;
	f.send_sequence = random_u32();
	f.receive_sequence = 0;
	f.remote_window = 65535;
	f.remote_window_scale = 0;
	drop(f);

	send_segment(flow, udp, auth, xor_key, flags::SYN, &[], true).await;
}

/// Look up the flow's map id. The id is stored in `by_port` so we can recover
/// it here by scanning — but simpler: we stash the id inside `Flow` via
/// `local_port` only after allocation. To avoid a second bookkeeping field we
/// rebuild the mapping by matching the `Arc` pointer identity.
fn flow_id(shared: &Shared, flow: &Arc<Mutex<Flow>>) -> u64 {
	shared
		.flows
		.iter()
		.find(|(_, v)| Arc::ptr_eq(v, flow))
		.map(|(k, _)| *k)
		.expect("flow is registered before port allocation")
}

// ---------------------------------------------------------------------------
// Remote (tunnel → SOCKS socket) direction
// ---------------------------------------------------------------------------

async fn receive_vpn(
	packet: &[u8],
	shared: &Arc<Mutex<Shared>>,
	udp: &Arc<UdpSocket>,
	auth: &AuthResult,
	xor_key: &[u8; 8],
	shutdown: &watch::Sender<bool>,
	failure: &watch::Sender<Option<String>>,
) {
	if packet.len() < 8 {
		return;
	}
	let packet_type = packet[0];
	let sid = u16::from_be_bytes([packet[2], packet[3]]);
	let token = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
	if sid != auth.sid || token != auth.token {
		return;
	}
	if packet_type == PacketType::EchoRequest as u8 {
		send_control(udp, auth, PacketType::EchoResponse).await;
		return;
	}
	if packet_type == PacketType::Close as u8 {
		// Tunnel closed by the server: surface it as a failure so the host can
		// reconnect rather than quietly keeping a dead SOCKS listener around.
		report_failure(shutdown, failure, "iWAN server closed the tunnel").await;
		return;
	}
	if packet_type != PacketType::Data as u8 && packet_type != PacketType::DataEncrypted as u8 {
		return;
	}
	let inner = if packet_type == PacketType::DataEncrypted as u8 {
		xor(&packet[8..], xor_key)
	} else {
		packet[8..].to_vec()
	};
	let Some(tcp) = parse_tcp_packet(&inner) else {
		return;
	};
	if tcp.destination != tunnel_ip_bytes(auth) {
		return;
	}

	let flow = {
		let sh = shared.lock().await;
		sh.by_port
			.get(&tcp.destination_port)
			.and_then(|id| sh.flows.get(id).cloned())
	};
	let Some(flow) = flow else {
		return;
	};

	{
		let mut f = flow.lock().await;
		let src_matches =
			f.remote_ip == Some(Ipv4Addr::from(tcp.source)) && f.remote_port == Some(tcp.source_port);
		if !src_matches {
			return;
		}
		f.last_activity = Instant::now();
	}
	receive_tcp(&flow, &tcp, shared, udp, auth, xor_key).await;
}

async fn receive_tcp(
	flow: &Arc<Mutex<Flow>>,
	packet: &crate::tcp::TcpPacket,
	shared: &Arc<Mutex<Shared>>,
	udp: &Arc<UdpSocket>,
	auth: &AuthResult,
	xor_key: &[u8; 8],
) {
	{
		let mut f = flow.lock().await;
		if packet.flags & flags::RST != 0 {
			drop(f);
			close_flow(flow, shared).await;
			return;
		}
		if packet.flags & flags::ACK != 0 {
			acknowledge(&mut f, packet.acknowledgement);
		}
	}

	// SYN-ACK completes the handshake.
	{
		let mut f = flow.lock().await;
		if f.state == FlowState::Connecting
			&& packet.flags & flags::SYN != 0
			&& packet.flags & flags::ACK != 0
		{
			if packet.acknowledgement != f.send_sequence {
				drop(f);
				return;
			}
			let opts = parse_tcp_options(&packet.options);
			f.remote_window_scale = opts.window_scale.unwrap_or(0);
			f.receive_sequence = packet.sequence.wrapping_add(1);
			f.remote_window = scaled_window(u32::from(packet.window), f.remote_window_scale);
			f.state = FlowState::Established;
			let reply = {
				let ip = tunnel_ip_bytes(auth);
				vec![
					5,
					0,
					0,
					1,
					ip[0],
					ip[1],
					ip[2],
					ip[3],
					(f.local_port >> 8) as u8,
					(f.local_port & 0xff) as u8,
				]
			};
			let write = f.write.clone();
			drop(f);
			// Complete the inner TCP handshake before exposing success to the
			// SOCKS client, then forward any bytes that raced with the reply.
			send_segment(flow, udp, auth, xor_key, flags::ACK, &[], false).await;
			let _ = write.send(Some(reply));
			flush_remote(flow, udp, auth, xor_key).await;
			return;
		}
	}

	// Established/closing data path.
	let mut accepted_payload = false;
	{
		let mut f = flow.lock().await;
		if f.state != FlowState::Established && f.state != FlowState::Closing {
			drop(f);
			return;
		}
		f.remote_window = scaled_window(u32::from(packet.window), f.remote_window_scale);
		if !packet.payload.is_empty() {
			if packet.sequence == f.receive_sequence {
				f.receive_sequence = f.receive_sequence.wrapping_add(packet.payload.len() as u32);
				let payload = packet.payload.clone();
				let _ = f.write.send(Some(payload));
				accepted_payload = true;
			}
			drop(f);
			send_segment(flow, udp, auth, xor_key, flags::ACK, &[], false).await;
			f = flow.lock().await;
		}

		// FIN.
		if packet.flags & flags::FIN != 0 {
			let in_order = if packet.payload.is_empty() {
				packet.sequence == f.receive_sequence
			} else {
				accepted_payload
			};
			if in_order {
				f.receive_sequence = f.receive_sequence.wrapping_add(1);
				f.remote_fin = true;
				let _ = f.write.send(None);
				f.state = FlowState::Closing;
			}
		}
		drop(f);
	}
	flush_remote(flow, udp, auth, xor_key).await;
}

fn acknowledge(flow: &mut Flow, acknowledgement: u32) {
	flow
		.pending
		.retain(|seg| !is_sequence_at_or_before(seg.end, acknowledgement));
}

async fn flush_remote(
	flow: &Arc<Mutex<Flow>>,
	udp: &Arc<UdpSocket>,
	auth: &AuthResult,
	xor_key: &[u8; 8],
) {
	loop {
		let (payload, has_fin) = {
			let mut f = flow.lock().await;
			if f.state != FlowState::Established && f.state != FlowState::Closing {
				return;
			}
			let window = available_window(&f);
			if f.input.is_empty() || window == 0 {
				// Send FIN when the local side is done and nothing is in flight.
				let fin_pending = f.pending.iter().any(|seg| seg.flags & flags::FIN != 0);
				if f.local_fin && !fin_pending {
					drop(f);
					send_segment(flow, udp, auth, xor_key, flags::FIN | flags::ACK, &[], true).await;
					return;
				}
				return;
			}
			let len = f.input.len().min(MAX_PACKET_PAYLOAD).min(window as usize);
			let payload = f.input[..len].to_vec();
			f.input.drain(..len);
			(payload, false)
		};
		let _ = has_fin;
		send_segment(flow, udp, auth, xor_key, flags::ACK, &payload, true).await;
	}
}

fn available_window(flow: &Flow) -> u32 {
	let in_flight = flow
		.pending
		.iter()
		.fold(0u32, |total, seg| total.wrapping_add(sequence_distance(seg.sequence, seg.end)));
	flow.remote_window.min(TCP_WINDOW).saturating_sub(in_flight)
}

async fn send_segment(
	flow: &Arc<Mutex<Flow>>,
	udp: &Arc<UdpSocket>,
	auth: &AuthResult,
	xor_key: &[u8; 8],
	seg_flags: u8,
	payload: &[u8],
	track: bool,
) {
	let (source, remote_ip, remote_port, local_port, sequence, acknowledgement, mtu) = {
		let f = flow.lock().await;
		(
			tunnel_ip_bytes(auth),
			f.remote_ip,
			f.remote_port,
			f.local_port,
			f.send_sequence,
			f.receive_sequence,
			auth.mtu,
		)
	};
	let (Some(remote_ip), Some(remote_port)) = (remote_ip, remote_port) else {
		return;
	};
	let source = ip_bytes_to_string(source);
	let dest = remote_ip.to_string();

	let options = if seg_flags & flags::SYN != 0 {
		syn_options(mtu)
	} else {
		Vec::new()
	};
	let packet = build_tcp_packet(&BuildTcpPacket {
		source: &source,
		destination: &dest,
		source_port: local_port,
		destination_port: remote_port,
		sequence,
		acknowledgement,
		flags: seg_flags,
		window: TCP_ADVERTISED_WINDOW,
		payload,
		options: &options,
		identification: 0,
	})
	.expect("valid TCP packet");
	let start = sequence;
	let mut f = flow.lock().await;
	f.send_sequence = sequence_end(start, payload.len(), seg_flags);
	drop(f);
	send_inner(udp, auth, xor_key, &packet).await;

	if track && (!payload.is_empty() || seg_flags & (flags::SYN | flags::FIN) != 0) {
		let mut f = flow.lock().await;
		let end = f.send_sequence;
		f.pending.push(PendingSegment {
			packet,
			sequence: start,
			end,
			flags: seg_flags,
			sent_at: Instant::now(),
			retries: 0,
		});
	}
}

// ---------------------------------------------------------------------------
// Tick: keepalive + retransmit + timeouts
// ---------------------------------------------------------------------------

async fn tick(
	shared: &Arc<Mutex<Shared>>,
	udp: &Arc<UdpSocket>,
	auth: &AuthResult,
	xor_key: &[u8; 8],
) {
	let snapshot = {
		let sh = shared.lock().await;
		sh.flows.values().cloned().collect::<Vec<_>>()
	};
	for flow in snapshot {
		let mut f = flow.lock().await;
		let now = Instant::now();

		// Retransmit the head of the pending queue.
		if f
			.pending
			.first()
			.is_some_and(|first| now.duration_since(first.sent_at) >= RETRANSMIT_AFTER)
		{
			let first = &mut f.pending[0];
			if first.retries >= MAX_RETRIES {
				socks_error(&mut f, 4);
				continue;
			}
			first.retries += 1;
			first.sent_at = now;
			let packet = first.packet.clone();
			drop(f);
			send_inner(udp, auth, xor_key, &packet).await;
			continue;
		}

		if f.state == FlowState::Connecting && now.duration_since(f.last_activity) > CONNECT_TIMEOUT {
			socks_error(&mut f, 4);
			continue;
		}
		if f.state == FlowState::Established && now.duration_since(f.last_activity) > IDLE_TIMEOUT {
			drop(f);
			close_flow(&flow, shared).await;
			continue;
		}
		drop(f);
		flush_remote(&flow, udp, auth, xor_key).await;
	}
}

fn socks_error(flow: &mut Flow, code: u8) {
	if flow.state == FlowState::Closing {
		return;
	}
	flow.state = FlowState::Closing;
	let _ = flow.write.send(Some(vec![5, code, 0, 1, 0, 0, 0, 0, 0, 0]));
	let _ = flow.write.send(None);
}

/// Remove `flow` from the shared registry and half-close its local socket.
async fn close_flow(flow: &Arc<Mutex<Flow>>, shared: &Arc<Mutex<Shared>>) {
	{
		let mut sh = shared.lock().await;
		let mut found: Option<u64> = None;
		for (id, f) in &sh.flows {
			if Arc::ptr_eq(f, flow) {
				found = Some(*id);
				break;
			}
		}
		let Some(id) = found else {
			return;
		};
		sh.flows.remove(&id);
		sh.by_port.retain(|_, v| *v != id);
	}
	let f = flow.lock().await;
	let _ = f.write.send(None);
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Allocate a distinct in-tunnel port for a new flow.
fn allocate_port(shared: &mut Shared) -> Option<u16> {
	for _ in 0..16384 {
		let port = shared.next_port;
		shared.next_port = if shared.next_port == u16::MAX {
			LOCAL_PORT_START
		} else {
			shared.next_port + 1
		};
		if !shared.by_port.contains_key(&port) {
			return Some(port);
		}
	}
	None
}

const fn tunnel_ip_bytes(auth: &AuthResult) -> [u8; 4] {
	// Re-parse the stored dotted-quad string each call; acceptable at this rate.
	let parts = split_ipv4(auth.tunnel_ip.as_bytes());
	[parts[0], parts[1], parts[2], parts[3]]
}

const fn split_ipv4(s: &[u8]) -> [u8; 4] {
	let mut out = [0u8; 4];
	let mut i = 0;
	let mut val = 0u8;
	let mut k = 0;
	while i < s.len() && k < 4 {
		match s[i] {
			b'.' => {
				out[k] = val;
				val = 0;
				k += 1;
			},
			c @ b'0'..=b'9' => {
				val = val * 10 + (c - b'0');
			},
			_ => {},
		}
		i += 1;
	}
	if k < 4 {
		out[k] = val;
	}
	out
}

fn ip_bytes_to_string(b: [u8; 4]) -> String {
	format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn random_u32() -> u32 {
	let mut buf = [0u8; 4];
	getrandom::fill(&mut buf).expect("OS RNG is available");
	u32::from_be_bytes(buf)
}

fn scaled_window(window: u32, scale: u8) -> u32 {
	window.saturating_mul(1u32 << scale).min(0x7fff_ffff)
}

const fn sequence_distance(start: u32, end: u32) -> u32 {
	end.wrapping_sub(start)
}

const fn is_sequence_at_or_before(value: u32, target: u32) -> bool {
	sequence_distance(value, target) < 0x8000_0000
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn scaled_window_applies_shift_and_caps() {
		// window 65535 << 4 = 1_048_560, within cap.
		assert_eq!(scaled_window(65535, 4), 1_048_560);
		// A huge window saturates at 0x7fff_ffff (sign-bit clear, per reference).
		assert_eq!(scaled_window(u32::MAX, 14), 0x7fff_ffff);
		// Shift 0 is identity.
		assert_eq!(scaled_window(1234, 0), 1234);
	}

	#[test]
	fn sequence_distance_wraps_correctly() {
		assert_eq!(sequence_distance(10, 20), 10);
		// Wraparound: 0xffff_fffe → 3 = 5.
		assert_eq!(sequence_distance(0xffff_fffe, 3), 5);
		assert_eq!(sequence_distance(5, 5), 0);
	}

	#[test]
	fn is_sequence_at_or_before_uses_half_space() {
		// `value` exactly at `target` is "at or before".
		assert!(is_sequence_at_or_before(100, 100));
		// 5 behind 100 wraps to a small forward distance → at-or-before.
		assert!(is_sequence_at_or_before(95, 100));
		// 100 is not "at or before" 95 (short backward distance).
		assert!(!is_sequence_at_or_before(100, 95));
		// Half the sequence space is the boundary (exclusive).
		assert!(is_sequence_at_or_before(0, 0x7fff_ffff));
		assert!(!is_sequence_at_or_before(0, 0x8000_0000));
	}

	#[test]
	fn tunnel_ip_bytes_parses_dotted_quad() {
		let auth = AuthResult {
			sid:       1,
			token:     2,
			tunnel_ip: "10.0.0.2".into(),
			gateway:   "10.0.0.1".into(),
			dns:       "10.0.0.53".into(),
			mtu:       1400,
		};
		assert_eq!(tunnel_ip_bytes(&auth), [10, 0, 0, 2]);
	}

	#[test]
	fn split_ipv4_handles_three_octet_max() {
		assert_eq!(split_ipv4(b"192.168.1.254"), [192, 168, 1, 254]);
		assert_eq!(split_ipv4(b"1.2.3.4"), [1, 2, 3, 4]);
	}

	#[test]
	fn allocate_port_skips_taken_and_wraps() {
		let mut sh = Shared {
			flows:     HashMap::new(),
			by_port:   HashMap::new(),
			next_id:   0,
			next_port: LOCAL_PORT_START,
		};
		let first = allocate_port(&mut sh).expect("free port");
		assert_eq!(first, LOCAL_PORT_START);
		// Take the returned port, then allocate again → next one.
		sh.by_port.insert(first, 0);
		let second = allocate_port(&mut sh).expect("free port");
		assert_eq!(second, LOCAL_PORT_START + 1);
	}
}
