use crc::{Crc, CRC_32_ISCSI};
use std::fmt;
use std::time::Instant;

use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::network_type::determine_network_type;
use shared::error::*;

#[derive(Default)]
pub struct CandidateBaseConfig {
    pub candidate_id: String,
    pub network: String,
    pub address: String,
    pub port: u16,
    pub component: u16,
    pub priority: u32,
    pub foundation: String,
    //todo: pub initialized_ch: Option<broadcast::Receiver<()>>,
}

pub struct CandidateBase {
    pub(crate) id: String,
    pub(crate) network_type: NetworkType,
    pub(crate) candidate_type: CandidateType,

    pub(crate) component: u16,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) related_address: Option<CandidateRelatedAddress>,
    pub(crate) tcp_type: TcpType,

    pub(crate) resolved_addr: SocketAddr,

    pub(crate) last_sent: Instant,
    pub(crate) last_received: Instant,

    //todo: pub(crate) closed_ch: Arc<Mutex<Option<broadcast::Sender<()>>>>,
    pub(crate) foundation_override: String,
    pub(crate) priority_override: u32,

    //CandidateHost
    pub(crate) network: String,
    //CandidateRelay
    //TODO: pub(crate) relay_client: Option<Arc<turn::client::Client>>,
}

impl Default for CandidateBase {
    fn default() -> Self {
        Self {
            id: String::new(),
            network_type: NetworkType::Unspecified,
            candidate_type: CandidateType::default(),

            component: 0,
            address: String::new(),
            port: 0,
            related_address: None,
            tcp_type: TcpType::default(),

            resolved_addr: SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),

            last_sent: Instant::now(),
            last_received: Instant::now(),

            //todo: closed_ch: Arc::new(Mutex::new(None)),
            foundation_override: String::new(),
            priority_override: 0,
            network: String::new(),
            //TODO: relay_client: None,
        }
    }
}

// String makes the candidateBase printable
impl fmt::Display for CandidateBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(related_address) = self.related_address() {
            write!(
                f,
                "{} {} {}:{}{}",
                self.network_type(),
                self.candidate_type(),
                self.address(),
                self.port(),
                related_address,
            )
        } else {
            write!(
                f,
                "{} {} {}:{}",
                self.network_type(),
                self.candidate_type(),
                self.address(),
                self.port(),
            )
        }
    }
}

impl Candidate for CandidateBase {
    fn foundation(&self) -> String {
        if !self.foundation_override.is_empty() {
            return self.foundation_override.clone();
        }

        let mut buf = vec![];
        buf.extend_from_slice(self.candidate_type().to_string().as_bytes());
        buf.extend_from_slice(self.address.as_bytes());
        buf.extend_from_slice(self.network_type().to_string().as_bytes());

        let checksum = Crc::<u32>::new(&CRC_32_ISCSI).checksum(&buf);

        format!("{checksum}")
    }

    /// Returns Candidate ID.
    fn id(&self) -> String {
        self.id.clone()
    }

    /// Returns candidate component.
    fn component(&self) -> u16 {
        self.component
    }

    fn set_component(&mut self, component: u16) {
        self.component = component;
    }

    /// Returns a time indicating the last time this candidate was received.
    fn last_received(&self) -> Instant {
        self.last_received
    }

    /// Returns a time indicating the last time this candidate was sent.
    fn last_sent(&self) -> Instant {
        self.last_sent
    }

    /// Returns candidate NetworkType.
    fn network_type(&self) -> NetworkType {
        self.network_type
    }

    /// Returns Candidate Address.
    fn address(&self) -> String {
        self.address.clone()
    }

    /// Returns Candidate Port.
    fn port(&self) -> u16 {
        self.port
    }

    /// Computes the priority for this ICE Candidate.
    fn priority(&self) -> u32 {
        if self.priority_override != 0 {
            return self.priority_override;
        }

        // The local preference MUST be an integer from 0 (lowest preference) to
        // 65535 (highest preference) inclusive.  When there is only a single IP
        // address, this value SHOULD be set to 65535.  If there are multiple
        // candidates for a particular component for a particular data stream
        // that have the same type, the local preference MUST be unique for each
        // one.
        (1 << 24) * u32::from(self.candidate_type().preference())
            + (1 << 8) * u32::from(self.local_preference())
            + (256 - u32::from(self.component()))
    }

    /// Returns `Option<CandidateRelatedAddress>`.
    fn related_address(&self) -> Option<CandidateRelatedAddress> {
        self.related_address.as_ref().cloned()
    }

    /// Returns candidate type.
    fn candidate_type(&self) -> CandidateType {
        self.candidate_type
    }

    fn tcp_type(&self) -> TcpType {
        self.tcp_type
    }

    /// Returns the string representation of the ICECandidate.
    fn marshal(&self) -> String {
        let mut val = format!(
            "{} {} {} {} {} {} typ {}",
            self.foundation(),
            self.component(),
            self.network_type().network_short(),
            self.priority(),
            self.address(),
            self.port(),
            self.candidate_type()
        );

        if self.tcp_type != TcpType::Unspecified {
            val += format!(" tcptype {}", self.tcp_type()).as_str();
        }

        if let Some(related_address) = self.related_address() {
            val += format!(
                " raddr {} rport {}",
                related_address.address, related_address.port,
            )
            .as_str();
        }

        val
    }

    fn addr(&self) -> SocketAddr {
        self.resolved_addr
    }

    /// Stops the recvLoop.
    fn close(&self) -> Result<()> {
        /*TODO:{
            let mut closed_ch = self.closed_ch.lock().await;
            if closed_ch.is_none() {
                return Err(Error::ErrClosed);
            }
            closed_ch.take();
        }*/

        Ok(())
    }

    fn seen(&mut self, outbound: bool) {
        let now = Instant::now();

        if outbound {
            self.set_last_sent(now);
        } else {
            self.set_last_received(now);
        }
    }

    fn write_to(&mut self, _raw: &[u8], _dst: &dyn Candidate) -> Result<usize> {
        let n = /*TODO: if let Some(conn) = &self.conn {
            let addr = dst.addr();
            conn.send_to(raw, addr).await?
        } else */{
            0
        };
        self.seen(true);
        Ok(n)
    }

    /// Used to compare two candidateBases.
    fn equal(&self, other: &dyn Candidate) -> bool {
        self.network_type() == other.network_type()
            && self.candidate_type() == other.candidate_type()
            && self.address() == other.address()
            && self.port() == other.port()
            && self.tcp_type() == other.tcp_type()
            && self.related_address() == other.related_address()
    }

    fn set_ip(&mut self, ip: &IpAddr) -> Result<()> {
        let network_type = determine_network_type(&self.network, ip)?;
        self.network_type = network_type;
        self.resolved_addr = SocketAddr::new(*ip, self.port);

        Ok(())
    }

    /*TODO:fn get_closed_ch(&self) -> Arc<Mutex<Option<broadcast::Sender<()>>>> {
        self.closed_ch.clone()
    }*/
}

impl CandidateBase {
    pub fn set_last_received(&mut self, now: Instant) {
        self.last_received = now;
    }

    pub fn set_last_sent(&mut self, now: Instant) {
        self.last_sent = now;
    }

    /// Returns the local preference for this candidate.
    pub fn local_preference(&self) -> u16 {
        if self.network_type().is_tcp() {
            // RFC 6544, section 4.2
            //
            // In Section 4.1.2.1 of [RFC5245], a recommended formula for UDP ICE
            // candidate prioritization is defined.  For TCP candidates, the same
            // formula and candidate type preferences SHOULD be used, and the
            // RECOMMENDED type preferences for the new candidate types defined in
            // this document (see Section 5) are 105 for NAT-assisted candidates and
            // 75 for UDP-tunneled candidates.
            //
            // (...)
            //
            // With TCP candidates, the local preference part of the recommended
            // priority formula is updated to also include the directionality
            // (active, passive, or simultaneous-open) of the TCP connection.  The
            // RECOMMENDED local preference is then defined as:
            //
            //     local preference = (2^13) * direction-pref + other-pref
            //
            // The direction-pref MUST be between 0 and 7 (both inclusive), with 7
            // being the most preferred.  The other-pref MUST be between 0 and 8191
            // (both inclusive), with 8191 being the most preferred.  It is
            // RECOMMENDED that the host, UDP-tunneled, and relayed TCP candidates
            // have the direction-pref assigned as follows: 6 for active, 4 for
            // passive, and 2 for S-O.  For the NAT-assisted and server reflexive
            // candidates, the RECOMMENDED values are: 6 for S-O, 4 for active, and
            // 2 for passive.
            //
            // (...)
            //
            // If any two candidates have the same type-preference and direction-
            // pref, they MUST have a unique other-pref.  With this specification,
            // this usually only happens with multi-homed hosts, in which case
            // other-pref is the preference for the particular IP address from which
            // the candidate was obtained.  When there is only a single IP address,
            // this value SHOULD be set to the maximum allowed value (8191).
            let other_pref: u16 = 8191;

            let direction_pref: u16 = match self.candidate_type() {
                CandidateType::Host | CandidateType::Relay => match self.tcp_type() {
                    TcpType::Active => 6,
                    TcpType::Passive => 4,
                    TcpType::SimultaneousOpen => 2,
                    TcpType::Unspecified => 0,
                },
                CandidateType::PeerReflexive | CandidateType::ServerReflexive => {
                    match self.tcp_type() {
                        TcpType::SimultaneousOpen => 6,
                        TcpType::Active => 4,
                        TcpType::Passive => 2,
                        TcpType::Unspecified => 0,
                    }
                }
                CandidateType::Unspecified => 0,
            };

            (1 << 13) * direction_pref + other_pref
        } else {
            DEFAULT_LOCAL_PREFERENCE
        }
    }
}

/// Creates a Candidate from its string representation.
pub fn unmarshal_candidate(raw: &str) -> Result<impl Candidate> {
    let split: Vec<&str> = raw.split_whitespace().collect();
    if split.len() < 8 {
        return Err(Error::Other(format!(
            "{:?} ({})",
            Error::ErrAttributeTooShortIceCandidate,
            split.len()
        )));
    }

    // Foundation
    let foundation = split[0].to_owned();

    // Component
    let component: u16 = split[1].parse()?;

    // Network
    let network = split[2].to_owned();

    // Priority
    let priority: u32 = split[3].parse()?;

    // Address
    let address = split[4].to_owned();

    // Port
    let port: u16 = split[5].parse()?;

    let typ = split[7];

    let mut rel_addr = String::new();
    let mut rel_port = 0;
    let mut tcp_type = TcpType::Unspecified;

    if split.len() > 8 {
        let split2 = &split[8..];

        if split2[0] == "raddr" {
            if split2.len() < 4 {
                return Err(Error::Other(format!(
                    "{:?}: incorrect length",
                    Error::ErrParseRelatedAddr
                )));
            }

            // RelatedAddress
            rel_addr = split2[1].to_owned();

            // RelatedPort
            rel_port = split2[3].parse()?;
        } else if split2[0] == "tcptype" {
            if split2.len() < 2 {
                return Err(Error::Other(format!(
                    "{:?}: incorrect length",
                    Error::ErrParseType
                )));
            }

            tcp_type = TcpType::from(split2[1]);
        }
    }

    match typ {
        "host" => {
            let config = CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateBaseConfig::default()
                },
                tcp_type,
            };
            config.new_candidate_host()
        }
        "srflx" => {
            let config = CandidateServerReflexiveConfig {
                base_config: CandidateBaseConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateBaseConfig::default()
                },
                rel_addr,
                rel_port,
            };
            config.new_candidate_server_reflexive()
        }
        "prflx" => {
            let config = CandidatePeerReflexiveConfig {
                base_config: CandidateBaseConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateBaseConfig::default()
                },
                rel_addr,
                rel_port,
            };

            config.new_candidate_peer_reflexive()
        }
        "relay" => {
            let config = CandidateRelayConfig {
                base_config: CandidateBaseConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateBaseConfig::default()
                },
                rel_addr,
                rel_port,
            };
            config.new_candidate_relay()
        }
        _ => Err(Error::Other(format!(
            "{:?} ({})",
            Error::ErrUnknownCandidateType,
            typ
        ))),
    }
}
