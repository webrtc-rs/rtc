//! Advertising a different address than the one a candidate was gathered on — the 1:1 NAT case.
//!
//! A host behind a static 1:1 NAT (a cloud instance with an elastic IP, a container with a
//! published port) is reachable on an address its interfaces do not carry. pion/ice expresses this
//! as `AddressRewriteRule`s applied while gathering (`NAT1To1IPs` is the older, flatter form of
//! the same thing). This agent never gathers — the caller binds sockets and hands over
//! candidates — so the rules are applied by [`rewrite_candidate`], which the caller runs on each
//! host candidate it gathers before [`Agent::add_local_candidate`](crate::agent::Agent):
//!
//! ```
//! use rtc_ice::address_rewrite::{AddressRewriteRule, rewrite_candidate};
//! use rtc_ice::candidate::{CandidateConfig, candidate_host::CandidateHostConfig};
//!
//! let host = CandidateHostConfig {
//!     base_config: CandidateConfig {
//!         network: "udp".to_owned(),
//!         address: "10.0.0.5".to_owned(),
//!         port: 9000,
//!         component: 1,
//!         ..Default::default()
//!     },
//!     ..Default::default()
//! }
//! .new_candidate_host()
//! .unwrap();
//!
//! // Advertise the instance's public address instead of its private one.
//! let rules = [AddressRewriteRule::replace_host(["203.0.113.7".parse().unwrap()])];
//! let advertised = rewrite_candidate(&rules, &host, None).unwrap();
//! assert_eq!(advertised.len(), 1);
//! assert_eq!(advertised[0].address(), "203.0.113.7");
//! ```

use std::net::IpAddr;

use shared::error::{Error, Result};

use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::candidate::{Candidate, CandidateConfig, CandidateType};
use crate::network_type::NetworkType;

/// Whether a rule replaces the candidate it applies to or adds candidates beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressRewriteMode {
    /// The rewritten candidate takes the original's place; the original is no longer advertised.
    Replace,
    /// The original stays; the rewritten candidates are added.
    Append,
}

/// An IP network in CIDR notation, such as `10.0.0.0/8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Parses `a.b.c.d/len` or `x:x::/len`.
    pub fn parse(text: &str) -> Result<Self> {
        let (address, len) = text
            .split_once('/')
            .ok_or(Error::ErrInvalidNat1to1IpMapping)?;
        let network: IpAddr = address
            .trim()
            .parse()
            .map_err(|_| Error::ErrInvalidNat1to1IpMapping)?;
        let prefix_len: u8 = len
            .trim()
            .parse()
            .map_err(|_| Error::ErrInvalidNat1to1IpMapping)?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(Error::ErrInvalidNat1to1IpMapping);
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Whether `ip` is inside this network (and of the same family).
    pub fn contains(&self, ip: IpAddr) -> bool {
        let (a, b): (u128, u128) = match (self.network, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => (u32::from(n).into(), u32::from(i).into()),
            (IpAddr::V6(n), IpAddr::V6(i)) => (n.into(), i.into()),
            _ => return false,
        };
        let bits = if self.network.is_ipv4() { 32 } else { 128 };
        let shift = bits - u32::from(self.prefix_len);
        shift >= 128 || (a >> shift) == (b >> shift)
    }
}

/// One rule: which candidates it applies to, and what to advertise for them.
#[derive(Clone, Debug)]
pub struct AddressRewriteRule {
    /// The external addresses to advertise. At least one is required.
    pub external: Vec<IpAddr>,
    /// Restricts the rule to the candidate gathered on exactly this local address. When unset,
    /// the rule is a catch-all for the family of `cidr` (or, without one, of the external
    /// address).
    pub local: Option<IpAddr>,
    /// Restricts the rule to candidates gathered on this interface (as named by the caller).
    pub iface: Option<String>,
    /// Restricts the rule to candidates whose local address is in this network.
    pub cidr: Option<Cidr>,
    /// The type to advertise the external addresses as: host, server reflexive or relay.
    pub as_candidate_type: CandidateType,
    /// Replace or append. `None` picks the default for the type: replace for host, append for
    /// server reflexive and relay.
    pub mode: Option<AddressRewriteMode>,
    /// Restricts the rule to these network types; empty means any.
    pub networks: Vec<NetworkType>,
    /// Rewrite the advertised port: candidates on `original_port` (any port when 0) advertise
    /// `new_port`. Both 0 leaves ports alone.
    pub original_port: u16,
    /// The port to advertise; see `original_port`.
    pub new_port: u16,
}

impl AddressRewriteRule {
    /// Advertise `external` in place of every host candidate (the `NAT1To1IPs` case).
    pub fn replace_host(external: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            external: external.into_iter().collect(),
            local: None,
            iface: None,
            cidr: None,
            as_candidate_type: CandidateType::Host,
            mode: None,
            networks: vec![],
            original_port: 0,
            new_port: 0,
        }
    }

    /// Advertise `external` as server-reflexive candidates beside the host candidates
    /// (`NAT1To1IPCandidateType: srflx`).
    pub fn append_srflx(external: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            as_candidate_type: CandidateType::ServerReflexive,
            ..Self::replace_host(external)
        }
    }

    /// Restricts the rule to the host candidate on `local`.
    pub fn for_local(mut self, local: IpAddr) -> Self {
        self.local = Some(local);
        self
    }

    fn effective_type(&self) -> CandidateType {
        match self.as_candidate_type {
            CandidateType::Unspecified => CandidateType::Host,
            t => t,
        }
    }

    fn effective_mode(&self) -> AddressRewriteMode {
        self.mode.unwrap_or(match self.effective_type() {
            CandidateType::Host => AddressRewriteMode::Replace,
            _ => AddressRewriteMode::Append,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.external.is_empty() {
            return Err(Error::ErrInvalidNat1to1IpMapping);
        }
        if !matches!(
            self.effective_type(),
            CandidateType::Host | CandidateType::ServerReflexive | CandidateType::Relay
        ) {
            return Err(Error::ErrInvalidNat1to1IpMapping);
        }
        // A port rewrite needs a target port, unless it is the "leave ports alone" 0/0.
        if self.new_port == 0 && self.original_port != 0 {
            return Err(Error::ErrInvalidNat1to1IpMapping);
        }
        Ok(())
    }

    /// How specific this rule's scope is; the most specific matching rule wins.
    fn specificity(&self) -> u8 {
        if self.local.is_some() {
            4
        } else if self.cidr.is_some() {
            3
        } else if self.iface.is_some() {
            2
        } else {
            1
        }
    }

    fn matches(&self, ip: IpAddr, network: NetworkType, port: u16, iface: Option<&str>) -> bool {
        if let Some(local) = self.local
            && local != ip
        {
            return false;
        }
        if let Some(cidr) = &self.cidr
            && !cidr.contains(ip)
        {
            return false;
        }
        if let Some(want) = &self.iface
            && iface != Some(want.as_str())
        {
            return false;
        }
        if !self.networks.is_empty() && !self.networks.contains(&network) {
            return false;
        }
        if self.original_port != 0 && self.original_port != port {
            return false;
        }
        true
    }
}

/// What to advertise for the host candidate `host`, gathered on interface `iface` if known.
///
/// The result is the candidate list that stands for `host`: the host itself when no rule applies
/// (or when matching rules only append), the replacement candidates when a rule replaces it,
/// followed by any appended ones. An appended server-reflexive or relay candidate reports the
/// host address as its related address, as a gathered one would.
///
/// Within each candidate type the most specific matching rule is used (`local`, then `cidr`, then
/// `iface`, then a catch-all). An external address of a different IP family than the candidate is
/// skipped.
///
/// # Errors
///
/// [`Error::ErrInvalidNat1to1IpMapping`] if any rule is malformed (no external address, an
/// unsupported type, or a port rewrite without a target port).
pub fn rewrite_candidate(
    rules: &[AddressRewriteRule],
    host: &Candidate,
    iface: Option<&str>,
) -> Result<Vec<Candidate>> {
    // pion validates every rule when the agent is created; a malformed one is an error even if it
    // would not apply to this candidate.
    for rule in rules {
        rule.validate()?;
    }

    let Ok(ip) = host.address().parse::<IpAddr>() else {
        // A host name (an mDNS candidate) has no address to rewrite.
        return Ok(vec![host.clone()]);
    };
    if host.candidate_type() != CandidateType::Host {
        return Ok(vec![host.clone()]);
    }

    let mut replaced: Vec<Candidate> = vec![];
    let mut appended: Vec<Candidate> = vec![];
    let mut keep_original = true;

    for typ in [
        CandidateType::Host,
        CandidateType::ServerReflexive,
        CandidateType::Relay,
    ] {
        let best = rules
            .iter()
            .filter(|r| r.effective_type() == typ)
            .filter(|r| r.matches(ip, host.network_type(), host.port(), iface))
            .max_by_key(|r| r.specificity());
        let Some(rule) = best else { continue };

        let port = if rule.new_port != 0 {
            rule.new_port
        } else {
            host.port()
        };
        let mode = rule.effective_mode();
        for external in rule.external.iter().filter(|e| e.is_ipv4() == ip.is_ipv4()) {
            let candidate = build(host, typ, *external, port)?;
            match mode {
                AddressRewriteMode::Replace => replaced.push(candidate),
                AddressRewriteMode::Append => appended.push(candidate),
            }
        }
        if mode == AddressRewriteMode::Replace && !replaced.is_empty() {
            keep_original = false;
        }
    }

    let mut out = if keep_original {
        vec![host.clone()]
    } else {
        vec![]
    };
    out.extend(replaced);
    out.extend(appended);
    Ok(out)
}

fn build(host: &Candidate, typ: CandidateType, external: IpAddr, port: u16) -> Result<Candidate> {
    let base_config = CandidateConfig {
        network: host.network_type().network_short(),
        address: external.to_string(),
        port,
        component: host.component(),
        ..Default::default()
    };
    match typ {
        CandidateType::Host => CandidateHostConfig {
            base_config,
            tcp_type: host.tcp_type(),
        }
        .new_candidate_host(),
        CandidateType::ServerReflexive => CandidateServerReflexiveConfig {
            base_config,
            rel_addr: host.address().to_owned(),
            rel_port: host.port(),
            url: None,
        }
        .new_candidate_server_reflexive(),
        CandidateType::Relay => CandidateRelayConfig {
            base_config,
            rel_addr: host.address().to_owned(),
            rel_port: host.port(),
            url: None,
            relay_protocol: String::new(),
        }
        .new_candidate_relay(),
        _ => Err(Error::ErrInvalidNat1to1IpMapping),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ip: &str, port: u16) -> Candidate {
        host_on("udp", ip, port)
    }

    fn host_on(network: &str, ip: &str, port: u16) -> Candidate {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: network.to_owned(),
                address: ip.to_owned(),
                port,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn no_rules_leaves_the_host_alone() {
        let h = host("10.0.0.5", 9000);
        let out = rewrite_candidate(&[], &h, None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address(), "10.0.0.5");
    }

    #[test]
    fn replace_host_swaps_the_address_and_keeps_port_and_type() {
        let rules = [AddressRewriteRule::replace_host([ip("203.0.113.7")])];
        let out = rewrite_candidate(&rules, &host("10.0.0.5", 9000), None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address(), "203.0.113.7");
        assert_eq!(out[0].port(), 9000);
        assert_eq!(out[0].candidate_type(), CandidateType::Host);
    }

    #[test]
    fn several_external_addresses_all_replace() {
        let rules = [AddressRewriteRule::replace_host([
            ip("203.0.113.7"),
            ip("203.0.113.8"),
        ])];
        let out = rewrite_candidate(&rules, &host("10.0.0.5", 9000), None).unwrap();
        let addrs: Vec<_> = out.iter().map(|c| c.address().to_owned()).collect();
        assert_eq!(addrs, ["203.0.113.7", "203.0.113.8"]);
    }

    #[test]
    fn srflx_rule_appends_beside_the_host_with_a_related_address() {
        let rules = [AddressRewriteRule::append_srflx([ip("203.0.113.7")])];
        let out = rewrite_candidate(&rules, &host("10.0.0.5", 9000), None).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].candidate_type(), CandidateType::Host);
        assert_eq!(out[0].address(), "10.0.0.5");
        assert_eq!(out[1].candidate_type(), CandidateType::ServerReflexive);
        assert_eq!(out[1].address(), "203.0.113.7");
        let related = out[1].related_address().unwrap();
        assert_eq!((related.address.as_str(), related.port), ("10.0.0.5", 9000));
    }

    #[test]
    fn a_local_address_pins_the_rule() {
        let rules =
            [AddressRewriteRule::replace_host([ip("203.0.113.7")]).for_local(ip("10.0.0.5"))];
        let hit = rewrite_candidate(&rules, &host("10.0.0.5", 9000), None).unwrap();
        assert_eq!(hit[0].address(), "203.0.113.7");
        let miss = rewrite_candidate(&rules, &host("10.0.0.6", 9000), None).unwrap();
        assert_eq!(miss[0].address(), "10.0.0.6");
    }

    #[test]
    fn the_most_specific_rule_wins() {
        let rules = [
            AddressRewriteRule::replace_host([ip("198.51.100.1")]),
            AddressRewriteRule::replace_host([ip("203.0.113.7")]).for_local(ip("10.0.0.5")),
        ];
        let pinned = rewrite_candidate(&rules, &host("10.0.0.5", 9000), None).unwrap();
        assert_eq!(pinned.len(), 1);
        assert_eq!(pinned[0].address(), "203.0.113.7");
        let other = rewrite_candidate(&rules, &host("10.0.0.9", 9000), None).unwrap();
        assert_eq!(other[0].address(), "198.51.100.1");
    }

    #[test]
    fn cidr_and_interface_scopes() {
        let mut by_cidr = AddressRewriteRule::replace_host([ip("203.0.113.7")]);
        by_cidr.cidr = Some(Cidr::parse("10.0.0.0/24").unwrap());
        assert_eq!(
            rewrite_candidate(&[by_cidr.clone()], &host("10.0.0.5", 1), None).unwrap()[0].address(),
            "203.0.113.7"
        );
        assert_eq!(
            rewrite_candidate(&[by_cidr], &host("10.0.1.5", 1), None).unwrap()[0].address(),
            "10.0.1.5"
        );

        let mut by_iface = AddressRewriteRule::replace_host([ip("203.0.113.7")]);
        by_iface.iface = Some("eth0".to_owned());
        assert_eq!(
            rewrite_candidate(&[by_iface.clone()], &host("10.0.0.5", 1), Some("eth0")).unwrap()[0]
                .address(),
            "203.0.113.7"
        );
        assert_eq!(
            rewrite_candidate(&[by_iface.clone()], &host("10.0.0.5", 1), Some("lo")).unwrap()[0]
                .address(),
            "10.0.0.5"
        );
        // Without a caller-supplied interface name an interface-scoped rule cannot apply.
        assert_eq!(
            rewrite_candidate(&[by_iface], &host("10.0.0.5", 1), None).unwrap()[0].address(),
            "10.0.0.5"
        );
    }

    #[test]
    fn a_family_mismatch_is_skipped() {
        let rules = [AddressRewriteRule::replace_host([ip("2001:db8::7")])];
        let out = rewrite_candidate(&rules, &host("10.0.0.5", 9000), None).unwrap();
        assert_eq!(
            out[0].address(),
            "10.0.0.5",
            "an IPv6 external cannot stand for an IPv4 host"
        );
    }

    #[test]
    fn network_filter_and_port_rewrite() {
        let mut rule = AddressRewriteRule::replace_host([ip("203.0.113.7")]);
        rule.networks = vec![NetworkType::Udp4];
        rule.original_port = 9000;
        rule.new_port = 19000;
        let out = rewrite_candidate(&[rule.clone()], &host("10.0.0.5", 9000), None).unwrap();
        assert_eq!((out[0].address(), out[0].port()), ("203.0.113.7", 19000));
        // Another port is untouched; another network type is untouched.
        let other_port = rewrite_candidate(&[rule.clone()], &host("10.0.0.5", 9001), None).unwrap();
        assert_eq!(other_port[0].port(), 9001);
        let tcp = rewrite_candidate(&[rule], &host_on("tcp", "10.0.0.5", 9000), None).unwrap();
        assert_eq!(tcp[0].address(), "10.0.0.5");
    }

    #[test]
    fn malformed_rules_are_refused() {
        let empty = AddressRewriteRule::replace_host([]);
        assert_eq!(
            rewrite_candidate(&[empty], &host("10.0.0.5", 1), None).unwrap_err(),
            Error::ErrInvalidNat1to1IpMapping
        );
        let mut no_target = AddressRewriteRule::replace_host([ip("203.0.113.7")]);
        no_target.original_port = 9000;
        assert_eq!(
            rewrite_candidate(&[no_target], &host("10.0.0.5", 9000), None).unwrap_err(),
            Error::ErrInvalidNat1to1IpMapping
        );
        let mut wrong_type = AddressRewriteRule::replace_host([ip("203.0.113.7")]);
        wrong_type.as_candidate_type = CandidateType::PeerReflexive;
        assert_eq!(
            rewrite_candidate(&[wrong_type], &host("10.0.0.5", 1), None).unwrap_err(),
            Error::ErrInvalidNat1to1IpMapping
        );
    }

    #[test]
    fn cidr_parsing_and_membership() {
        assert!(
            Cidr::parse("10.0.0.0/8")
                .unwrap()
                .contains(ip("10.200.1.1"))
        );
        assert!(!Cidr::parse("10.0.0.0/8").unwrap().contains(ip("11.0.0.1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("1.2.3.4")));
        assert!(
            Cidr::parse("192.168.1.7/32")
                .unwrap()
                .contains(ip("192.168.1.7"))
        );
        assert!(
            !Cidr::parse("192.168.1.7/32")
                .unwrap()
                .contains(ip("192.168.1.8"))
        );
        assert!(
            Cidr::parse("2001:db8::/32")
                .unwrap()
                .contains(ip("2001:db8:1::1"))
        );
        // A v6 network never contains a v4 address and vice versa.
        assert!(
            !Cidr::parse("2001:db8::/32")
                .unwrap()
                .contains(ip("10.0.0.1"))
        );
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("10.0.0.0").is_err());
        assert!(Cidr::parse("nonsense/8").is_err());
    }
}
