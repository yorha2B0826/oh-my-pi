//! Inner TCP/IP packet codec for the iWAN data plane.
//!
//! Port of `ustcode/packages/ustcode/src/iwan/tcp.ts`. The tunnel carries raw
//! IPv4 datagrams whose upper payload is a TCP segment; the SOCKS layer
//! hand-builds these (rather than using a host TCP stack) because the far end
//! is a user-space router expecting a specific, minimal IPv4/TCP shape.
//!
//! The module is split into pure functions so every byte-layout decision —
//! header field order, the IPv4 header checksum, and the TCP pseudo-header
//! checksum — is unit-tested independently of the stateful flow machinery.

/// TCP flag bits (RFC 793).
pub mod flags {
	pub const FIN: u8 = 0x01;
	pub const SYN: u8 = 0x02;
	pub const RST: u8 = 0x04;
	pub const ACK: u8 = 0x10;
}

/// A parsed TCP segment plus the IPv4 header length that preceded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpPacket {
	pub source:           [u8; 4],
	pub destination:      [u8; 4],
	pub source_port:      u16,
	pub destination_port: u16,
	pub sequence:         u32,
	pub acknowledgement:  u32,
	pub flags:            u8,
	pub window:           u16,
	pub options:          Vec<u8>,
	pub payload:          Vec<u8>,
}

impl TcpPacket {
	/// Dotted-quad source address.
	pub fn source_string(&self) -> String {
		format!("{}.{}.{}.{}", self.source[0], self.source[1], self.source[2], self.source[3])
	}

	/// Dotted-quad destination address.
	pub fn destination_string(&self) -> String {
		format!(
			"{}.{}.{}.{}",
			self.destination[0], self.destination[1], self.destination[2], self.destination[3]
		)
	}
}

/// Parse an IPv4 datagram wrapping a TCP segment.
///
/// Returns `None` for any packet that is not a well-formed IPv4/TCP packet
/// (bad version, wrong protocol, truncated header, oversized declared length).
pub fn parse_tcp_packet(packet: &[u8]) -> Option<TcpPacket> {
	if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
		return None;
	}
	let ip_header_len = (packet[0] & 0x0f) as usize * 4;
	if ip_header_len < 20 || packet.len() < ip_header_len + 20 {
		return None;
	}
	let declared = u16::from_be_bytes([packet[2], packet[3]]) as usize;
	let total_len = packet.len().min(declared);
	let tcp_offset = ip_header_len;
	let tcp_header_len = (packet[tcp_offset + 12] >> 4) as usize * 4;
	if tcp_header_len < 20 || total_len < tcp_offset + tcp_header_len {
		return None;
	}

	Some(TcpPacket {
		source:           [packet[12], packet[13], packet[14], packet[15]],
		destination:      [packet[16], packet[17], packet[18], packet[19]],
		source_port:      read_u16(packet, tcp_offset),
		destination_port: read_u16(packet, tcp_offset + 2),
		sequence:         read_u32(packet, tcp_offset + 4),
		acknowledgement:  read_u32(packet, tcp_offset + 8),
		flags:            packet[tcp_offset + 13],
		window:           read_u16(packet, tcp_offset + 14),
		options:          packet[tcp_offset + 20..tcp_offset + tcp_header_len].to_vec(),
		payload:          packet[tcp_offset + tcp_header_len..total_len].to_vec(),
	})
}

/// Build an IPv4 datagram wrapping a TCP segment.
#[derive(Debug, Clone)]
pub struct BuildTcpPacket<'a> {
	pub source:           &'a str,
	pub destination:      &'a str,
	pub source_port:      u16,
	pub destination_port: u16,
	pub sequence:         u32,
	pub acknowledgement:  u32,
	pub flags:            u8,
	pub window:           u16,
	pub payload:          &'a [u8],
	pub options:          &'a [u8],
	pub identification:   u16,
}

/// Build the full IPv4+TCP datagram, computing both checksums.
pub fn build_tcp_packet(input: &BuildTcpPacket<'_>) -> Result<Vec<u8>, String> {
	if input.options.len() > 40 || !input.options.len().is_multiple_of(4) {
		return Err("TCP options must be padded to a 4-byte boundary".to_string());
	}
	let tcp_header_len = 20 + input.options.len();
	let total = 20 + tcp_header_len + input.payload.len();
	let source = crate::protocol::ipv4_bytes(input.source).map_err(|e| e.to_string())?;
	let destination = crate::protocol::ipv4_bytes(input.destination).map_err(|e| e.to_string())?;

	let mut packet = vec![0u8; total];
	// IPv4 header.
	packet[0] = 0x45;
	packet[1] = 0;
	packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
	packet[4..6].copy_from_slice(&input.identification.to_be_bytes());
	packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
	packet[8] = 64;
	packet[9] = 6;
	packet[12..16].copy_from_slice(&source);
	packet[16..20].copy_from_slice(&destination);
	// TCP header.
	packet[20..22].copy_from_slice(&input.source_port.to_be_bytes());
	packet[22..24].copy_from_slice(&input.destination_port.to_be_bytes());
	packet[24..28].copy_from_slice(&input.sequence.to_be_bytes());
	packet[28..32].copy_from_slice(&input.acknowledgement.to_be_bytes());
	packet[32] = ((tcp_header_len / 4) as u8) << 4;
	packet[33] = input.flags;
	packet[34..36].copy_from_slice(&input.window.to_be_bytes());
	// checksum (offset 36..38) and urgent (38..40) are zeroed already.
	packet[40..40 + input.options.len()].copy_from_slice(input.options);
	packet[20 + tcp_header_len..].copy_from_slice(input.payload);

	// IPv4 header checksum (over the 20-byte header).
	let ip_checksum = checksum(&packet[..20]);
	packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
	// TCP checksum (over pseudo-header + segment).
	let tcp_checksum = tcp_checksum(&packet);
	packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());

	Ok(packet)
}

/// Parsed TCP options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpOptions {
	pub mss:            Option<u16>,
	pub window_scale:   Option<u8>,
	pub sack_permitted: bool,
}

/// Parse TCP options (RFC 793/1323: MSS, window scale, SACK-permitted).
pub fn parse_tcp_options(options: &[u8]) -> TcpOptions {
	let mut out = TcpOptions::default();
	let mut offset = 0usize;
	while offset < options.len() {
		let kind = options[offset];
		if kind == 0 {
			break;
		}
		if kind == 1 {
			offset += 1;
			continue;
		}
		if offset + 2 > options.len() {
			break;
		}
		let len = options[offset + 1] as usize;
		if len < 2 || offset + len > options.len() {
			break;
		}
		match kind {
			2 if len == 4 => out.mss = Some(read_u16(options, offset + 2)),
			3 if len == 3 => out.window_scale = Some(options[offset + 2].min(14)),
			4 if len == 2 => out.sack_permitted = true,
			_ => {},
		}
		offset += len;
	}
	out
}

/// The sequence number one past a segment's payload + SYN/FIN control bits.
pub fn sequence_end(sequence: u32, payload_len: usize, flags: u8) -> u32 {
	sequence
		.wrapping_add(payload_len as u32)
		.wrapping_add(u32::from(flags & flags::SYN != 0))
		.wrapping_add(u32::from(flags & flags::FIN != 0))
}

/// Build the SYN options (MSS, window scale, SACK-permitted), mirroring the
/// reference `synOptions`.
pub fn syn_options(mtu: u16) -> Vec<u8> {
	let mss = 536u16.max(mtu.saturating_sub(40).min(1460));
	// MSS(2,4) window-scale(3,3) SACK-permitted(4,2) -> 10 bytes, padded to 12.
	vec![
		2,
		4,
		(mss >> 8) as u8,
		(mss & 0xff) as u8,
		3,
		3,
		4, // window scale shift
		4,
		2,
		0,
		0,
		0,
	]
}

const fn read_u16(data: &[u8], offset: usize) -> u16 {
	u16::from_be_bytes([data[offset], data[offset + 1]])
}

const fn read_u32(data: &[u8], offset: usize) -> u32 {
	u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
	let mut sum = 0u32;
	let mut i = 0;
	while i + 1 < data.len() {
		sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
		i += 2;
	}
	if i < data.len() {
		sum += u32::from(data[i]) << 8;
	}
	while sum >> 16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	!(sum as u16)
}

/// TCP checksum over the IPv4 pseudo-header + TCP segment.
fn tcp_checksum(packet: &[u8]) -> u16 {
	let tcp_len = packet.len() - 20;
	let mut pseudo = vec![0u8; 12];
	pseudo[..8].copy_from_slice(&packet[12..20]); // src + dst IP
	pseudo[9] = 6; // protocol = TCP
	pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());
	let mut data = pseudo;
	data.extend_from_slice(&packet[20..]);
	// Zero the checksum field inside the segment before summing.
	data[28] = 0;
	data[29] = 0;
	checksum(&data)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn checksum_matches_known_vector() {
		// A trivial 20-byte zeroed IP header has a well-known checksum.
		let header = vec![0u8; 20];
		// checksum of all-zero (with no carry wrap) = 0xffff.
		assert_eq!(checksum(&header), 0xffff);
	}

	#[test]
	fn emitted_tcp_checksum_validates_against_the_wire_bytes() {
		let pkt = build_tcp_packet(&BuildTcpPacket {
			source:           "10.0.0.2",
			destination:      "10.0.0.1",
			source_port:      12345,
			destination_port: 443,
			sequence:         1,
			acknowledgement:  0,
			flags:            flags::SYN,
			window:           65535,
			payload:          &[],
			options:          &syn_options(1400),
			identification:   42,
		})
		.unwrap();
		let mut pseudo_and_tcp = vec![0u8; 12];
		pseudo_and_tcp[..8].copy_from_slice(&pkt[12..20]);
		pseudo_and_tcp[9] = 6;
		pseudo_and_tcp[10..12].copy_from_slice(&((pkt.len() - 20) as u16).to_be_bytes());
		pseudo_and_tcp.extend_from_slice(&pkt[20..]);
		assert_eq!(checksum(&pseudo_and_tcp), 0);
	}

	#[test]
	fn parse_build_roundtrip() {
		let built = build_tcp_packet(&BuildTcpPacket {
			source:           "10.0.0.2",
			destination:      "192.168.1.1",
			source_port:      10000,
			destination_port: 80,
			sequence:         0xdead_beef,
			acknowledgement:  0x1234_5678,
			flags:            flags::ACK,
			window:           4096,
			payload:          b"hello",
			options:          &[],
			identification:   7,
		})
		.unwrap();
		let parsed = parse_tcp_packet(&built).unwrap();
		assert_eq!(parsed.source_string(), "10.0.0.2");
		assert_eq!(parsed.destination_string(), "192.168.1.1");
		assert_eq!(parsed.source_port, 10000);
		assert_eq!(parsed.destination_port, 80);
		assert_eq!(parsed.sequence, 0xdead_beef);
		assert_eq!(parsed.acknowledgement, 0x1234_5678);
		assert_eq!(parsed.flags, flags::ACK);
		assert_eq!(parsed.payload, b"hello");
	}

	#[test]
	fn reject_non_tcp_or_non_ipv4() {
		// Version 6 -> reject.
		let mut v6 = vec![0u8; 40];
		v6[0] = 0x60;
		assert!(parse_tcp_packet(&v6).is_none());
		// Wrong protocol (UDP=17 instead of TCP=6).
		let mut udp = vec![0u8; 40];
		udp[0] = 0x45;
		udp[9] = 17;
		assert!(parse_tcp_packet(&udp).is_none());
	}

	#[test]
	fn parse_tcp_options_window_scale_capped() {
		let opts = [3, 3, 200]; // window scale 200 -> capped to 14
		let parsed = parse_tcp_options(&opts);
		assert_eq!(parsed.window_scale, Some(14));
	}

	#[test]
	fn sequence_end_counts_syn_fin() {
		assert_eq!(sequence_end(10, 3, 0), 13);
		assert_eq!(sequence_end(10, 0, flags::SYN), 11);
		assert_eq!(sequence_end(10, 5, flags::SYN | flags::FIN), 17);
	}
}
