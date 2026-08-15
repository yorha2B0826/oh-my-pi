//! UDP tunnel handshake and authenticated channel.
//!
//! Port of the `authenticate` path in
//! `ustcode/packages/ustcode/src/iwan/service.ts` (with the UDP socket wrapper
//! from `udp.ts`). A tunnel is established in three steps:
//!
//! 1. Generate a random 4-byte auth nonce.
//! 2. Send an [`protocol::build_open`](crate::protocol::build_open) packet to
//!    the chosen server over UDP.
//! 3. Wait up to 3 seconds for an `OpenAck` (validating signature + nonce),
//!    retrying up to 4 times.
//!
//! On success the returned [`AuthenticatedTunnel`] owns the connected UDP
//! socket plus the [`AuthResult`] (sid/token/tunnel address), which the
//! SOCKS5/TCP layers in later stages drive.

use std::{net::SocketAddr, time::Duration};

use tokio::net::UdpSocket;

use crate::{
	crypto::xor,
	protocol::{AuthResult, PacketType, build_open, data_packet, packet_header, parse_open_ack},
};

/// Encryption is hard-wired on (the controller only serves encrypted tunnels;
/// the reference client sets `ENCRYPTION = 1`).
pub const ENCRYPTION: u8 = 1;
/// MTU offered in the Open packet.
pub const MTU: u16 = 1400;
/// Per-attempt authentication timeout.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);
/// Number of Open attempts before giving up.
const MAX_ATTEMPTS: u32 = 4;
/// Delay between failed attempts.
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Error type for tunnel establishment.
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
	#[error("iWAN authentication timed out")]
	TimedOut,
	#[error("protocol error: {0}")]
	Protocol(#[from] crate::protocol::ProtocolError),
	#[error("io error: {0}")]
	Io(#[from] std::io::Error),
	#[error("authentication failed after {0} attempts: {1}")]
	Exhausted(u32, String),
}

fn random_nonce() -> u32 {
	let mut buf = [0u8; 4];
	getrandom::fill(&mut buf).expect("OS RNG is available");
	u32::from_be_bytes(buf)
}

/// A connected, authenticated iWAN tunnel.
///
/// Owns the UDP socket and the session parameters. The data-plane layers build
/// on this to multiplex inner TCP connections.
pub struct AuthenticatedTunnel {
	socket:  UdpSocket,
	auth:    AuthResult,
	/// XOR key for the encrypted data plane: `md5(username + password)[..8]`.
	xor_key: [u8; 8],
}

impl AuthenticatedTunnel {
	/// The authenticated session parameters (sid/token/tunnel addressing).
	pub const fn auth(&self) -> &AuthResult {
		&self.auth
	}

	/// The XOR key used to (de)obfuscate `DataEncrypted` payloads.
	pub const fn xor_key(&self) -> &[u8; 8] {
		&self.xor_key
	}

	/// The underlying connected UDP socket, for the SOCKS/TCP layer.
	pub const fn socket(&self) -> &UdpSocket {
		&self.socket
	}

	/// Split into the parts the data-plane layer needs.
	pub fn into_parts(self) -> (UdpSocket, AuthResult, [u8; 8]) {
		(self.socket, self.auth, self.xor_key)
	}

	/// Send a control packet (no payload) of the given type.
	///
	/// Control packets carry the 16-byte signature; kept here because the
	/// keepalive `EchoRequest` is part of the tunnel lifecycle.
	pub async fn send_control(&self, packet_type: PacketType) -> std::io::Result<()> {
		let header = packet_header(packet_type, ENCRYPTION, self.auth.sid, self.auth.token);
		let packet = crate::protocol::control_packet(&header, &[]);
		self.socket.send(&packet).await.map(|_| ())
	}

	/// Send an (optionally encrypted) data packet.
	///
	/// When `encrypted` is true, the inner payload is `XORed` with the session
	/// key and sent as `DataEncrypted`; otherwise it is sent verbatim as
	/// `Data`. This mirrors [`Socks::#sendInner`] in the reference client.
	pub async fn send_data(&self, inner: &[u8], encrypted: bool) -> std::io::Result<()> {
		let (packet_type, payload) = if encrypted {
			(PacketType::DataEncrypted, xor(inner, &self.xor_key))
		} else {
			(PacketType::Data, inner.to_vec())
		};
		let header = packet_header(packet_type, ENCRYPTION, self.auth.sid, self.auth.token);
		let packet = data_packet(&header, &payload);
		self.socket.send(&packet).await.map(|_| ())
	}
}

/// Establish a tunnel to `server`, authenticating as `username`.
///
/// `password` is the *decrypted* server password (see
/// [`crate::protocol::decrypt_server_password`], which the login layer has
/// already recovered from the controller's server list).
pub async fn authenticate(
	server: SocketAddr,
	username: &str,
	password: &str,
) -> Result<AuthenticatedTunnel, TunnelError> {
	let nonce = random_nonce();
	let socket = UdpSocket::bind("0.0.0.0:0").await?;
	socket.connect(server).await?;

	let encrypted_password = crate::protocol::encrypt_server_password(password, username);
	let open = build_open(username, &encrypted_password, MTU, ENCRYPTION, nonce)?;

	let mut last_error = String::from("iWAN authentication timed out");
	for attempt in 0..MAX_ATTEMPTS {
		// Send before awaiting the response, matching the reference order
		// (`receive` arms a handler, then `send`, then awaits).
		socket.send(&open).await?;

		let mut buf = vec![0u8; 65536];
		let received = tokio::time::timeout(AUTH_TIMEOUT, socket.recv(&mut buf))
			.await
			.map_err(|_| TunnelError::TimedOut)?
			.map_err(TunnelError::Io)?;

		let result = parse_open_ack(&buf[..received], nonce);
		match result {
			Ok(auth) => {
				let xor_key = session_xor_key(username, password);
				return Ok(AuthenticatedTunnel { socket, auth, xor_key });
			},
			Err(e) => {
				last_error = e.to_string();
				if attempt < MAX_ATTEMPTS - 1 {
					tokio::time::sleep(RETRY_DELAY).await;
				}
			},
		}
	}

	Err(TunnelError::Exhausted(MAX_ATTEMPTS, last_error))
}

/// The 8-byte XOR key derived from `md5(username + password)`.
///
/// Split out so the SOCKS layer and tests can derive the same key without a
/// live socket.
pub fn session_xor_key(username: &str, password: &str) -> [u8; 8] {
	let digest = crate::crypto::session_key(username, password);
	let mut key = [0u8; 8];
	key.copy_from_slice(&digest[..8]);
	key
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::protocol::signature;

	#[test]
	fn session_xor_key_is_md5_prefix() {
		let key = session_xor_key("user", "pass");
		let digest = crate::crypto::md5(b"userpass");
		assert_eq!(&key[..], &digest[..8]);
	}

	#[test]
	fn random_nonce_is_u32() {
		// Nonce is arbitrary; we can only assert it doesn't panic and the
		// function is callable (determinism isn't expected here).
		let _ = random_nonce();
	}

	#[test]
	fn control_packet_uses_signature() {
		// Sanity-check that send_control's packet layout is signature-bearing:
		// header(8) + signature(16) + empty payload = 24 bytes.
		let header = packet_header(PacketType::EchoRequest, ENCRYPTION, 1, 2);
		let packet = crate::protocol::control_packet(&header, &[]);
		assert_eq!(packet.len(), 24);
		let mut sig_input = header.to_vec();
		sig_input.extend_from_slice(b"mw");
		assert_eq!(&packet[8..24], &crate::crypto::md5(&sig_input)[..]);
		// `signature(header)` matches bytes 8..24 exactly.
		assert_eq!(&packet[8..24], signature(&header));
	}
}
