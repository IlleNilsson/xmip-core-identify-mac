#![forbid(unsafe_code)]

//! Identify by mac: the peer's link-layer address is the claim.
//!
//! An Ethernet, fieldbus or industrial transport that sees the frame — a
//! raw socket, `EtherNet/IP`, `PROFINET`, `EtherCAT` — knows the 48-bit address
//! the peer sent from, and a device on a plant network is very often named
//! by nothing else. The transport puts it on the arrival as [`PEER_MAC`] in
//! whatever spelling its stack uses — `00:1B:44:11:3A:B7`,
//! `00-1b-44-11-3a-b7`, `001b.4411.3ab7` — and this presents the one
//! spelling, lowercase and colon-separated, passed. Like every name read off
//! a connection the mechanism identifies and never authenticates
//! ([`xcore::mechanism::mac`]): an address is set in software on most
//! adapters.
//!
//! Only a pushed Stream has a peer; a detected or scheduled arrival presents
//! nothing here.
//!
//! Property name this technology defines for the transports: `peer.mac`.
//! Evidence it writes: `peer.mac`, the address exactly as the transport
//! spelled it.

use context::property::PEER_MAC;
use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier};
use xcore::{Arriving, Mechanism};

/// Reads the peer's link-layer address.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacIdentifier;

impl TransportIdentifier for MacIdentifier {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::mac()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        let Some(reported) = arrival.property(PEER_MAC) else {
            return Ok(None);
        };

        Ok(Some(
            Presented::passed(self.mechanism(), normalize(reported)?)
                .with_evidence(PEER_MAC, reported),
        ))
    }
}

/// The one spelling: six octets, lowercase hex, colon-separated.
///
/// Accepts the spellings `net::mac` reads — colons, hyphens, the Cisco
/// dotted-quad form or the digits alone — and writes the one it writes.
///
/// # Errors
///
/// Where the text is not six octets of hex.
pub fn normalize(text: &str) -> Result<String, IdentifyError> {
    net::mac::parse(text)
        .ok()
        .filter(|octets| octets.len() == 6)
        .map(|octets| net::mac::notation(&octets))
        .ok_or_else(|| {
            IdentifyError::new(format!(
                "the link-layer address {text:?} is not six octets of hex"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stream::Stream;
    use xcore::StreamId;

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"frame".to_vec(), None)
    }

    fn facts(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn the_reported_address_is_presented_in_one_spelling() {
        let stream = stream();
        let facts = facts(&[("peer.mac", "00-1B-44-11-3A-B7")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "enip://plc-7", &facts);

        let claim = MacIdentifier
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "00:1b:44:11:3a:b7");
        assert_eq!(claim.mechanism.name(), "mac");
        assert_eq!(
            claim.evidence,
            vec![("peer.mac".to_string(), "00-1B-44-11-3A-B7".to_string())]
        );
    }

    #[test]
    fn every_common_spelling_reads_as_the_same_address() {
        for spelling in ["00:1b:44:11:3a:b7", "001b.4411.3ab7", "001B44113AB7"] {
            assert_eq!(normalize(spelling).expect("read"), "00:1b:44:11:3a:b7");
        }
    }

    #[test]
    fn an_arrival_without_a_link_layer_address_presents_nothing() {
        let stream = stream();
        let facts = facts(&[("peer.address", "192.0.2.10")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        assert!(MacIdentifier.identify(&arrival).expect("read").is_none());
    }

    #[test]
    fn an_address_that_is_not_six_octets_is_an_error() {
        let stream = stream();
        let facts = facts(&[("peer.mac", "00:1b:44:11:3a")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "enip://plc-7", &facts);

        let failure = MacIdentifier.identify(&arrival).expect_err("five octets");

        assert_eq!(
            failure.to_string(),
            "the link-layer address \"00:1b:44:11:3a\" is not six octets of hex"
        );
    }

    #[test]
    fn a_scheduled_pickup_has_no_peer_to_present() {
        let stream = stream();
        let facts = facts(&[("peer.mac", "00:1b:44:11:3a:b7")]);
        let arrival = StreamArrival::new(&stream, Arriving::Scheduled, "modbus://plc-7", &facts);

        assert!(MacIdentifier.identify(&arrival).expect("read").is_none());
    }
}
