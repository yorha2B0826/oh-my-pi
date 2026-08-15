//! iWAN VPN tunnel client for the USTC LLM gateway.
//!
//! `pi-iwan` re-implements the bespoke UDP tunneling protocol used by the USTC
//! iWAN campus VPN in pure Rust. It is a faithful port of the reference
//! TypeScript client (`ustcode/packages/ustcode/src/iwan/`), split into
//! layered modules:
//!
//! - [`crypto`] — the hash / HMAC / AES primitives the protocol builds on.
//! - [`protocol`] — wire constants and the packet / TLV / Open handshake codec.
//! - (later stages) tunnel handshake, the TCP-over-UDP state machine, the local
//!   SOCKS5 listener, and the OAuth/controller login flow.
//!
//! Stage 1 ships only the first two modules — pure functions with pinned unit
//! tests — so each byte-level decision is verified before the stateful layers
//! are added on top.

pub mod crypto;
pub mod dns;
pub mod protocol;
pub mod socks;
pub mod tcp;
pub mod tunnel;
