//! N-API bindings for the iWAN VPN tunnel.
//!
//! The engine — UDP tunnel handshake plus the TCP-over-UDP SOCKS5 stack — lives
//! in `pi_iwan`; this class exposes a single long-lived tunnel and its local
//! SOCKS5 proxy address to TypeScript. OAuth PKCE login, the controller HTTP
//! calls and server-password decryption stay in TypeScript (reusing
//! `packages/ai`'s `pkce.ts` + `fetch`); Rust only receives an already-decoded
//! server password and runs the tunnel.
//!
//! See [`pi_iwan::tunnel::authenticate`] and [`pi_iwan::socks::Socks`].

use std::{
	net::{SocketAddr, ToSocketAddrs},
	sync::Arc,
};

use napi::{
	Status,
	bindgen_prelude::Result,
	threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode, UnknownReturnValue},
};
use napi_derive::napi;
use pi_iwan::{socks::Socks, tunnel::authenticate};

/// A JS-facing `(message: string) => void` callback for tunnel-death events.
type ClosedCallback = ThreadsafeFunction<String, UnknownReturnValue, String, Status, true, true>;

/// Status of a running tunnel, mirrored from [`pi_iwan::socks::SocksStatus`].
#[napi(object)]
pub struct IwanStatus {
	/// Bound local SOCKS5 address (`127.0.0.1:port`).
	pub address: String,
	/// SOCKS5 listener port.
	pub port:    u16,
	/// Number of inner TCP connections currently multiplexed.
	pub flows:   u32,
}

/// A single active iWAN tunnel draining through a local SOCKS5 proxy.
#[napi]
pub struct IwanTunnel {
	socks:     tokio::sync::Mutex<Option<Socks>>,
	/// `Arc`-shared so `connect()` (called once per reconnect) can hand a clone
	/// to each watch task without consuming the callback.
	on_closed: Option<Arc<ClosedCallback>>,
}

#[napi]
impl IwanTunnel {
	/// Create an idle tunnel handle. Call [`IwanTunnel::connect`] to establish
	/// a tunnel once the TS login flow has recovered a server password.
	///
	/// `on_closed` fires once per connection, non-blocking, when the tunnel dies
	/// on its own — a UDP socket error or the server sending a `Close` packet. A
	/// clean `stop()` does not fire it.
	#[napi(constructor)]
	pub fn new(
		#[napi(ts_arg_type = "(message: string) => void")] on_closed: Option<ClosedCallback>,
	) -> Result<Self> {
		Ok(Self { socks: tokio::sync::Mutex::new(None), on_closed: on_closed.map(Arc::new) })
	}

	/// Authenticate to a server and start draining its tunnel through a local
	/// SOCKS5 proxy. `password` is the already-decrypted server password
	/// (the TS layer has recovered it from the controller's server list via
	/// [`pi_iwan::protocol::decrypt_server_password`]).
	#[napi]
	pub async fn connect(
		&self,
		host: String,
		port: u16,
		username: String,
		password: String,
	) -> Result<IwanStatus> {
		// Resolve the controller-provided host (may be a name or IP literal).
		let server = resolve_server(&host, port).await.ok_or_else(|| {
			napi::Error::from_reason(format!("iWAN: cannot resolve server {host}:{port}"))
		})?;

		let tunnel = authenticate(server, &username, &password)
			.await
			.map_err(|err| napi::Error::from_reason(format!("iWAN authenticate: {err}")))?;
		let socks = Socks::open(tunnel)
			.await
			.map_err(|err| napi::Error::from_reason(format!("iWAN socks: {err}")))?;
		let status = socks.status().await;

		// Watch for the tunnel dying on its own and relay the cause to JS so the
		// host can stop using the dead port and (optionally) reconnect. The task
		// leaks no resources: it exits when the `Socks` sender is dropped (on
		// `stop()` or replacement) or after the first non-`None` failure.
		if let Some(callback) = self.on_closed.as_ref().map(Arc::clone) {
			let mut failure = socks.failure();
			tokio::spawn(async move {
				loop {
					let Ok(()) = failure.changed().await else {
						break;
					};
					let cause = failure.borrow().clone();
					let Some(cause) = cause else { continue };
					callback.call(Ok(cause), ThreadsafeFunctionCallMode::NonBlocking);
					break;
				}
			});
		}

		*self.socks.lock().await = Some(socks);

		Ok(IwanStatus {
			address: status.address.to_string(),
			port:    status.address.port(),
			flows:   status.flows as u32,
		})
	}

	/// Snapshot the current tunnel: the bound SOCKS5 address and flow count.
	#[napi]
	pub async fn status(&self) -> Result<IwanStatus> {
		let guard = self.socks.lock().await;
		let Some(socks) = guard.as_ref() else {
			return Err(napi::Error::from_reason("iWAN tunnel is not connected"));
		};
		let status = socks.status().await;
		Ok(IwanStatus {
			address: status.address.to_string(),
			port:    status.address.port(),
			flows:   status.flows as u32,
		})
	}

	/// Stop the tunnel, closing the SOCKS5 listener and the UDP socket.
	#[napi]
	pub async fn stop(&self) -> Result<()> {
		let existing = self.socks.lock().await.take();
		if let Some(mut socks) = existing {
			socks.stop().await;
		}
		Ok(())
	}
}

impl Default for IwanTunnel {
	fn default() -> Self {
		Self { socks: tokio::sync::Mutex::new(None), on_closed: None }
	}
}

/// Resolve `host:port` to a single UDP-reachable socket address, preferring
/// IPv4 (the iWAN tunnel only carries IPv4).
async fn resolve_server(host: &str, port: u16) -> Option<SocketAddr> {
	// First try the fast synchronous path (IP literal or `/etc/hosts`).
	if let Ok(mut addrs) = (host, port).to_socket_addrs()
		&& let Some(addr) = addrs.find(SocketAddr::is_ipv4)
	{
		return Some(addr);
	}
	// Fall back to an async lookup (handles real DNS names).
	tokio::net::lookup_host((host, port))
		.await
		.ok()?
		.find(SocketAddr::is_ipv4)
}
