//! iWAN wire protocol constants and packet codec.
//!
//! This is a port of `ustcode/packages/ustcode/src/iwan/protocol.ts`. The wire
//! format is a bespoke UDP tunneling protocol layered over TLS-grade crypto:
//!
//! - Every **control** packet is `8-byte header ‖ 16-byte signature ‖ payload`,
//!   where the signature is `md5(header[0..8] + "mw")`.
//! - Every **data** packet is `8-byte header ‖ payload` (no signature; the
//!   payload is `XORed` with the session key when the tunnel is "encrypted").
//! - The header is `type(1) ‖ encryption(1) ‖ sid(u16 BE) ‖ token(u32 BE)`.
//! - Control payloads are a sequence of TLVs: `type(1) ‖ length(1, incl. the
//!   2-byte type+length prefix) ‖ value`.
//!
//! The `Open`/`OpenAck` exchange authenticates the tunnel and returns the
//! client's in-tunnel IPv4 address, gateway, DNS server and MTU.

use crate::crypto::{aes_ecb_encrypt, aes_gcm_decrypt, base64url_decode, md5, sha256};

/// The iWAN domain served by the USTC controller.
pub const DOMAIN: &str = "iwan.ustc";
/// Application secret used to derive password-decrypt keys and sign controller
/// requests. Value mirrors the upstream client.
pub const APP_SECRET: &str = "ca6a3532abd2986a03b86b3a";
/// Controller base URL (server list + keepalive).
pub const CONTROLLER: &str = "https://crtl.ivpn.ustc.edu.cn";
/// OAuth authorization endpoint.
pub const AUTH_URL: &str = "https://auth.ivpn.ustc.edu.cn/login/oauth/authorize";
/// OAuth token endpoint.
pub const TOKEN_URL: &str = "https://auth.ivpn.ustc.edu.cn/api/login/oauth/access_token";
/// OAuth client id.
pub const CLIENT_ID: &str = "afc6479ffb531d71daef";
/// OAuth redirect URI (deep-link scheme).
pub const REDIRECT_URI: &str = "com.panabit.mobile://oauth2redirect";
/// OAuth scope.
pub const SCOPE: &str = "openid profile email offline_access";
/// Controller app id sent in `X-Auth-AppId`.
pub const CONTROLLER_APP_ID: &str = "controller-ustc";

/// Packet type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
	/// 0x11 — server rejected the tunnel.
	OpenReject    = 0x11,
	/// 0x12 — server accepted the tunnel.
	OpenAck       = 0x12,
	/// 0x13 — client opens a tunnel.
	Open          = 0x13,
	/// 0x14 — unencrypted data payload.
	Data          = 0x14,
	/// 0x15 — keepalive request.
	EchoRequest   = 0x15,
	/// 0x16 — keepalive response.
	EchoResponse  = 0x16,
	/// 0x17 — tunnel closed.
	Close         = 0x17,
	/// 0x18 — encrypted (`XORed`) data payload.
	DataEncrypted = 0x18,
}

impl PacketType {
	pub const fn from_byte(b: u8) -> Option<Self> {
		Some(match b {
			0x11 => Self::OpenReject,
			0x12 => Self::OpenAck,
			0x13 => Self::Open,
			0x14 => Self::Data,
			0x15 => Self::EchoRequest,
			0x16 => Self::EchoResponse,
			0x17 => Self::Close,
			0x18 => Self::DataEncrypted,
			_ => return None,
		})
	}
}

/// TLV type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlvType {
	/// 0x01 — username.
	Username     = 0x01,
	/// 0x02 — (encrypted) password.
	Password     = 0x02,
	/// 0x03 — MTU (2 bytes BE).
	Mtu          = 0x03,
	/// 0x04 — tunnel IPv4 address (4 bytes).
	Ip           = 0x04,
	/// 0x05 — DNS server (4 bytes).
	Dns          = 0x05,
	/// 0x06 — gateway (4 bytes).
	Gateway      = 0x06,
	/// 0x08 — encryption flag (1 byte).
	Encrypt      = 0x08,
	/// 0x0f — auth nonce (4 bytes BE).
	AuthVerify   = 0x0f,
	/// 0x10 — error message (UTF-8).
	ErrorMessage = 0x10,
}

impl TlvType {
	pub const fn from_byte(b: u8) -> Option<Self> {
		Some(match b {
			0x01 => Self::Username,
			0x02 => Self::Password,
			0x03 => Self::Mtu,
			0x04 => Self::Ip,
			0x05 => Self::Dns,
			0x06 => Self::Gateway,
			0x08 => Self::Encrypt,
			0x0f => Self::AuthVerify,
			0x10 => Self::ErrorMessage,
			_ => return None,
		})
	}
}

/// A successful tunnel authentication result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
	pub sid:       u16,
	pub token:     u32,
	pub tunnel_ip: String,
	pub gateway:   String,
	pub dns:       String,
	pub mtu:       u16,
}

/// Error type for protocol parse/validation failures.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
	#[error("iWAN authentication response is too short")]
	ResponseTooShort,
	#[error("iWAN authentication rejected: {0}")]
	OpenRejected(String),
	#[error("unexpected iWAN packet type 0x{0:02x}")]
	UnexpectedType(u8),
	#[error("invalid iWAN response signature")]
	InvalidSignature,
	#[error("iWAN authentication nonce mismatch")]
	NonceMismatch,
	#[error("iWAN authentication response did not include tunnel addressing")]
	MissingAddressing,
	#[error("invalid IPv4 address: {0}")]
	InvalidIpv4(String),
	#[error("iWAN TLV is too large")]
	TlvTooLarge,
	#[error("decrypt error: {0}")]
	Decrypt(String),
}

/// Build an 8-byte packet header: `type ‖ encryption ‖ sid(u16 BE) ‖ token(u32
/// BE)`.
pub fn packet_header(packet_type: PacketType, encryption: u8, sid: u16, token: u32) -> [u8; 8] {
	let mut header = [0u8; 8];
	header[0] = packet_type as u8;
	header[1] = encryption;
	header[2..4].copy_from_slice(&sid.to_be_bytes());
	header[4..8].copy_from_slice(&token.to_be_bytes());
	header
}

/// Signature over a header: `md5(header[0..8] + "mw")`.
pub fn signature(header: &[u8; 8]) -> Vec<u8> {
	let mut data = Vec::with_capacity(10);
	data.extend_from_slice(header);
	data.extend_from_slice(b"mw");
	md5(&data)
}

/// Assemble a control packet: `header[0..8] ‖ signature ‖ payload`.
pub fn control_packet(header: &[u8; 8], payload: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(8 + 16 + payload.len());
	out.extend_from_slice(header);
	out.extend_from_slice(&signature(header));
	out.extend_from_slice(payload);
	out
}

/// Assemble a data packet: `header[0..8] ‖ payload` (no signature).
pub fn data_packet(header: &[u8; 8], payload: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(8 + payload.len());
	out.extend_from_slice(header);
	out.extend_from_slice(payload);
	out
}

/// Encode a single TLV: `type(1) ‖ length(1, incl. 2-byte prefix) ‖ value`.
pub fn tlv(tlv_type: TlvType, value: &[u8]) -> Result<Vec<u8>, ProtocolError> {
	if value.len() + 2 > 255 {
		return Err(ProtocolError::TlvTooLarge);
	}
	let mut out = Vec::with_capacity(2 + value.len());
	out.push(tlv_type as u8);
	out.push((value.len() + 2) as u8);
	out.extend_from_slice(value);
	Ok(out)
}

/// Parse a TLV stream into `(type, value)` pairs. Stops cleanly on truncation.
pub fn parse_tlvs(data: &[u8]) -> Vec<(u8, &[u8])> {
	let mut result = Vec::new();
	let mut offset = 0usize;
	while offset + 2 <= data.len() {
		let t = data[offset];
		let len = data[offset + 1] as usize;
		if len < 2 || offset + len > data.len() {
			break;
		}
		result.push((t, &data[offset + 2..offset + len]));
		offset += len;
	}
	result
}

/// Build the `Open` control packet that starts a tunnel.
pub fn build_open(
	username: &str,
	encrypted_password: &[u8],
	mtu: u16,
	encryption: u8,
	nonce: u32,
) -> Result<Vec<u8>, ProtocolError> {
	let mut payload = Vec::new();
	payload.extend_from_slice(&tlv(TlvType::Mtu, &mtu.to_be_bytes())?);
	payload.extend_from_slice(&tlv(TlvType::Username, username.as_bytes())?);
	payload.extend_from_slice(&tlv(TlvType::Password, encrypted_password)?);
	payload.extend_from_slice(&tlv(TlvType::Encrypt, &[encryption])?);
	payload.extend_from_slice(&tlv(TlvType::AuthVerify, &nonce.to_be_bytes())?);
	Ok(control_packet(&packet_header(PacketType::Open, encryption, 0, 0), &payload))
}

/// Parse an `OpenAck` (or `OpenReject`) response, validating the signature and,
/// when present, the auth nonce.
pub fn parse_open_ack(data: &[u8], expected_nonce: u32) -> Result<AuthResult, ProtocolError> {
	if data.len() < 24 {
		return Err(ProtocolError::ResponseTooShort);
	}
	let ptype = PacketType::from_byte(data[0]).ok_or(ProtocolError::UnexpectedType(data[0]))?;
	if ptype == PacketType::OpenReject {
		let msg = String::from_utf8_lossy(&data[24..]).into_owned();
		return Err(ProtocolError::OpenRejected(msg));
	}
	if ptype != PacketType::OpenAck {
		return Err(ProtocolError::UnexpectedType(data[0]));
	}

	// Recompute the signature over the header (bytes 0..8).
	let mut header = [0u8; 8];
	header.copy_from_slice(&data[0..8]);
	if data[8..24] != *signature(&header) {
		return Err(ProtocolError::InvalidSignature);
	}

	let mut tunnel_ip = String::new();
	let mut gateway = String::new();
	let mut dns = String::new();
	let mut mtu: u16 = 1400;
	let mut nonce: Option<u32> = None;

	for (t, value) in parse_tlvs(&data[24..]) {
		match TlvType::from_byte(t) {
			Some(TlvType::Ip) => tunnel_ip = ipv4_string(value)?,
			Some(TlvType::Gateway) => gateway = ipv4_string(value)?,
			Some(TlvType::Dns) => dns = ipv4_string(value)?,
			Some(TlvType::Mtu) if value.len() >= 2 => {
				mtu = u16::from_be_bytes([value[0], value[1]]);
			},
			Some(TlvType::AuthVerify) if value.len() == 4 => {
				nonce = Some(u32::from_be_bytes(value.try_into().expect("4-byte nonce")));
			},
			_ => {},
		}
	}

	if let Some(n) = nonce
		&& n != expected_nonce
	{
		return Err(ProtocolError::NonceMismatch);
	}
	if tunnel_ip.is_empty() || gateway.is_empty() {
		return Err(ProtocolError::MissingAddressing);
	}

	Ok(AuthResult {
		sid: u16::from_be_bytes([data[2], data[3]]),
		token: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
		tunnel_ip,
		gateway,
		dns,
		mtu,
	})
}

/// Convert an IPv4 dotted-quad string to 4 bytes.
pub fn ipv4_bytes(value: &str) -> Result<[u8; 4], ProtocolError> {
	let mut out = [0u8; 4];
	let mut it = value.split('.');
	for (i, part) in it.by_ref().take(4).enumerate() {
		let n: u8 = part
			.parse()
			.map_err(|_| ProtocolError::InvalidIpv4(value.to_string()))?;
		out[i] = n;
	}
	if it.next().is_some() {
		return Err(ProtocolError::InvalidIpv4(value.to_string()));
	}
	Ok(out)
}

/// Convert 4 IPv4 bytes to a dotted-quad string.
pub fn ipv4_string(value: &[u8]) -> Result<String, ProtocolError> {
	if value.len() < 4 {
		return Err(ProtocolError::InvalidIpv4(format!("{value:?}")));
	}
	Ok(format!("{}.{}.{}.{}", value[0], value[1], value[2], value[3]))
}

/// Decrypt a controller-issued server password (see
/// [`crate::crypto::decrypt_password`]).
pub fn decrypt_server_password(encrypted: &str, username: &str) -> Result<String, ProtocolError> {
	decrypt_password_inner(encrypted, DOMAIN, username)
}

fn decrypt_password_inner(
	encrypted: &str,
	domain: &str,
	username: &str,
) -> Result<String, ProtocolError> {
	let key = sha256(format!("{APP_SECRET}|{domain}|{username}").as_bytes());
	let encoded = base64url_decode(encrypted).map_err(|e| ProtocolError::Decrypt(e.to_string()))?;
	if encoded.len() < 28 {
		return Err(ProtocolError::Decrypt("password is too short".into()));
	}
	let nonce = &encoded[..12];
	let blob = &encoded[12..];
	let aad = format!("{domain}|{username}");
	let plaintext = aes_gcm_decrypt(&key, nonce, blob, aad.as_bytes());
	String::from_utf8(plaintext).map_err(|e| ProtocolError::Decrypt(e.to_string()))
}

/// Encrypt a server password for the Open packet (see
/// [`crate::crypto::encrypt_password`]).
pub fn encrypt_server_password(password: &str, username: &str) -> Vec<u8> {
	let mut key_material = String::with_capacity(2 + username.len());
	key_material.push_str("mw");
	key_material.push_str(username);
	let key = md5(key_material.as_bytes());
	let mut plaintext = [0u8; 16];
	let pw = password.as_bytes();
	let n = pw.len().min(16);
	plaintext[..n].copy_from_slice(&pw[..n]);
	aes_ecb_encrypt(&key, &plaintext)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::hex;

	#[test]
	fn header_layout_matches_wire() {
		let h = packet_header(PacketType::Open, 1, 0x1234, 0x0102_0304);
		assert_eq!(h, [0x13, 0x01, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04]);
	}

	#[test]
	fn signature_is_md5_header_plus_mw() {
		let h = packet_header(PacketType::Open, 1, 0, 0);
		let mut expected_input = h.to_vec();
		expected_input.extend_from_slice(b"mw");
		assert_eq!(signature(&h), crate::crypto::md5(&expected_input));
	}

	#[test]
	fn control_packet_layout() {
		let h = packet_header(PacketType::EchoResponse, 1, 0, 0);
		let pkt = control_packet(&h, &[]);
		assert_eq!(pkt.len(), 8 + 16);
		assert_eq!(&pkt[..8], &h);
		assert_eq!(&pkt[8..], &signature(&h)[..]);
	}

	#[test]
	fn tlv_roundtrip() {
		let enc = tlv(TlvType::Username, b"alice").unwrap();
		assert_eq!(enc, [0x01, 0x07, b'a', b'l', b'i', b'c', b'e']);
		let parsed = parse_tlvs(&enc);
		assert_eq!(parsed.len(), 1);
		assert_eq!(parsed[0].0, TlvType::Username as u8);
		assert_eq!(parsed[0].1, b"alice");
	}

	#[test]
	fn tlv_too_large_is_error() {
		let big = vec![0u8; 254];
		assert!(tlv(TlvType::Username, &big).is_err());
	}

	#[test]
	fn build_open_parse_ack_roundtrip() {
		let nonce = 0xdead_beefu32;
		let pw = encrypt_server_password("password123", "testuser");
		let open = build_open("testuser", &pw, 1400, 1, nonce).unwrap();

		// Spot-check the header type/encryption.
		assert_eq!(open[0], PacketType::Open as u8);
		assert_eq!(open[1], 1);

		// Build a synthetic OpenAck echoing the nonce.
		let sid = 0x0001u16;
		let token = 0x1234_5678u32;
		let ack_header = packet_header(PacketType::OpenAck, 1, sid, token);
		let sig = signature(&ack_header);
		let mut payload = Vec::new();
		payload.extend_from_slice(&tlv(TlvType::Ip, &[10, 0, 0, 2]).unwrap());
		payload.extend_from_slice(&tlv(TlvType::Gateway, &[10, 0, 0, 1]).unwrap());
		payload.extend_from_slice(&tlv(TlvType::Dns, &[10, 0, 0, 53]).unwrap());
		payload.extend_from_slice(&tlv(TlvType::Mtu, &1400u16.to_be_bytes()).unwrap());
		payload.extend_from_slice(&tlv(TlvType::AuthVerify, &nonce.to_be_bytes()).unwrap());

		let mut ack = Vec::new();
		ack.extend_from_slice(&ack_header);
		ack.extend_from_slice(&sig);
		ack.extend_from_slice(&payload);

		let parsed = parse_open_ack(&ack, nonce).unwrap();
		assert_eq!(parsed.sid, sid);
		assert_eq!(parsed.token, token);
		assert_eq!(parsed.tunnel_ip, "10.0.0.2");
		assert_eq!(parsed.gateway, "10.0.0.1");
		assert_eq!(parsed.dns, "10.0.0.53");
		assert_eq!(parsed.mtu, 1400);
	}

	#[test]
	fn parse_open_ack_rejects_bad_nonce() {
		let nonce = 1u32;
		let pw = encrypt_server_password("password123", "testuser");
		let open = build_open("testuser", &pw, 1400, 1, nonce).unwrap();
		assert_eq!(open[0], PacketType::Open as u8);

		// Same as above but with a mismatched nonce.
		let sid = 1u16;
		let token = 2u32;
		let ack_header = packet_header(PacketType::OpenAck, 1, sid, token);
		let sig = signature(&ack_header);
		let mut payload = Vec::new();
		payload.extend_from_slice(&tlv(TlvType::Ip, &[10, 0, 0, 2]).unwrap());
		payload.extend_from_slice(&tlv(TlvType::Gateway, &[10, 0, 0, 1]).unwrap());
		payload.extend_from_slice(&tlv(TlvType::AuthVerify, &999u32.to_be_bytes()).unwrap());
		let mut ack = Vec::new();
		ack.extend_from_slice(&ack_header);
		ack.extend_from_slice(&sig);
		ack.extend_from_slice(&payload);

		assert!(matches!(parse_open_ack(&ack, nonce), Err(ProtocolError::NonceMismatch)));
	}

	#[test]
	fn ipv4_roundtrip() {
		assert_eq!(ipv4_bytes("10.0.0.2").unwrap(), [10, 0, 0, 2]);
		assert_eq!(ipv4_string(&[10, 0, 0, 2]).unwrap(), "10.0.0.2");
		assert!(ipv4_bytes("10.0.0.2.3").is_err());
		assert!(ipv4_bytes("256.0.0.1").is_err());
	}

	#[test]
	fn decrypt_server_password_pins_aad_layout() {
		// Verify the key material / AAD layout by constructing a decryptable blob
		// with the exact same derivation the encrypt path would use, then decrypting
		// through the public API. This catches a swapped AAD vs key ordering.
		use aes_gcm::{
			Aes256Gcm, KeyInit as _, Nonce,
			aead::{Aead as _, Payload},
		};
		let username = "testuser";
		let key = sha256(format!("{APP_SECRET}|{DOMAIN}|{username}").as_bytes());
		let nonce = [0u8; 12];
		let aad = format!("{DOMAIN}|{username}");
		let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
		let ct = cipher
			.encrypt(Nonce::from_slice(&nonce), Payload {
				msg: b"secretpw".as_ref(),
				aad: aad.as_bytes(),
			})
			.unwrap();
		let mut blob = nonce.to_vec();
		blob.extend_from_slice(&ct);
		let encoded = crate::crypto::base64url(&blob);
		let recovered = decrypt_server_password(&encoded, username).unwrap();
		assert_eq!(recovered, "secretpw");
	}

	#[test]
	fn encrypt_server_password_matches_crypto_encrypt_password() {
		let a = encrypt_server_password("secretpw", "testuser");
		let b = crate::crypto::encrypt_password("secretpw", "testuser");
		assert_eq!(a, b);
		assert_eq!(hex(&a).len(), 32); // 16 bytes -> 32 hex chars
	}
}
