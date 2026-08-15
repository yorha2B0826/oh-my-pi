//! IPv4 DNS resolver used by SOCKS domain requests.
//!
//! iWAN must not use the host resolver here: local TUN proxies such as
//! Shadowrocket can return Fake-IP addresses that only exist inside their own
//! tunnel. Resolving against a public DNS server mirrors the reference client
//! and gives the iWAN data plane a routable destination.

use std::{net::Ipv4Addr, time::Duration};

use tokio::net::UdpSocket;

const DNS_SERVER: &str = "114.114.114.114:53";
const DNS_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
	#[error("invalid DNS name")]
	InvalidName,
	#[error("DNS lookup timed out for {0}")]
	TimedOut(String),
	#[error("DNS lookup failed")]
	Failed,
	#[error("DNS name has no IPv4 address")]
	NoIpv4,
	#[error("truncated DNS response")]
	Truncated,
	#[error("io error: {0}")]
	Io(#[from] std::io::Error),
}

pub async fn resolve_ipv4(domain: &str) -> Result<Ipv4Addr, DnsError> {
	let normalized = domain.trim().trim_end_matches('.');
	if normalized.is_empty() || normalized.len() > 253 {
		return Err(DnsError::InvalidName);
	}
	let mut id_bytes = [0u8; 2];
	getrandom::fill(&mut id_bytes).expect("OS RNG is available");
	let id = u16::from_be_bytes(id_bytes);
	let query = build_query(id, normalized)?;

	let socket = UdpSocket::bind("0.0.0.0:0").await?;
	socket.connect(DNS_SERVER).await?;
	socket.send(&query).await?;
	let mut response = [0u8; 4096];
	let received = tokio::time::timeout(DNS_TIMEOUT, socket.recv(&mut response))
		.await
		.map_err(|_| DnsError::TimedOut(normalized.to_string()))??;
	parse_response(id, &response[..received])
}

fn build_query(id: u16, domain: &str) -> Result<Vec<u8>, DnsError> {
	let labels = domain.split('.').collect::<Vec<_>>();
	if labels
		.iter()
		.any(|label| label.is_empty() || label.len() > 63)
	{
		return Err(DnsError::InvalidName);
	}
	let encoded_len = labels.iter().map(|label| label.len() + 1).sum::<usize>() + 1;
	let mut query = vec![0u8; 12 + encoded_len + 4];
	query[0..2].copy_from_slice(&id.to_be_bytes());
	query[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
	query[4..6].copy_from_slice(&1u16.to_be_bytes());
	let mut offset = 12;
	for label in labels {
		query[offset] = label.len() as u8;
		offset += 1;
		query[offset..offset + label.len()].copy_from_slice(label.as_bytes());
		offset += label.len();
	}
	offset += 1;
	query[offset..offset + 2].copy_from_slice(&1u16.to_be_bytes());
	query[offset + 2..offset + 4].copy_from_slice(&1u16.to_be_bytes());
	Ok(query)
}

fn parse_response(id: u16, packet: &[u8]) -> Result<Ipv4Addr, DnsError> {
	if packet.len() < 12 || u16::from_be_bytes([packet[0], packet[1]]) != id {
		return Err(DnsError::Truncated);
	}
	let flags = u16::from_be_bytes([packet[2], packet[3]]);
	if flags & 0x8000 == 0 || flags & 0x000f != 0 {
		return Err(DnsError::Failed);
	}
	let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
	let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
	let mut offset = 12;
	for _ in 0..questions {
		offset = skip_name(packet, offset)?;
		offset = offset
			.checked_add(4)
			.filter(|end| *end <= packet.len())
			.ok_or(DnsError::Truncated)?;
	}
	for _ in 0..answers {
		offset = skip_name(packet, offset)?;
		if offset + 10 > packet.len() {
			return Err(DnsError::Truncated);
		}
		let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
		let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
		let length = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
		offset += 10;
		if offset + length > packet.len() {
			return Err(DnsError::Truncated);
		}
		if record_type == 1 && class == 1 && length == 4 {
			return Ok(Ipv4Addr::new(
				packet[offset],
				packet[offset + 1],
				packet[offset + 2],
				packet[offset + 3],
			));
		}
		offset += length;
	}
	Err(DnsError::NoIpv4)
}

fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize, DnsError> {
	loop {
		let length = *packet.get(offset).ok_or(DnsError::Truncated)?;
		if length & 0xc0 == 0xc0 {
			return offset
				.checked_add(2)
				.filter(|end| *end <= packet.len())
				.ok_or(DnsError::Truncated);
		}
		if length & 0xc0 != 0 {
			return Err(DnsError::Failed);
		}
		offset += 1;
		if length == 0 {
			return Ok(offset);
		}
		offset = offset
			.checked_add(length as usize)
			.filter(|end| *end <= packet.len())
			.ok_or(DnsError::Truncated)?;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_compressed_ipv4_answer() {
		let id = 0x1234;
		let mut packet = build_query(id, "api.llm.ustc.edu.cn").unwrap();
		packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
		packet[6..8].copy_from_slice(&1u16.to_be_bytes());
		packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 114, 214, 240, 204]);
		assert_eq!(parse_response(id, &packet).unwrap(), Ipv4Addr::new(114, 214, 240, 204));
	}

	#[test]
	fn rejects_invalid_labels() {
		assert!(matches!(build_query(1, "a..b"), Err(DnsError::InvalidName)));
	}
}
