use crc::{Crc, CRC_32_ISCSI};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;
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
    pub(crate) network_type: u8,
    pub(crate) candidate_type: CandidateType,

    pub(crate) component: u16,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) related_address: Option<CandidateRelatedAddress>,

    pub(crate) resolved_addr: SocketAddr,

    pub(crate) baseline_time: Instant,
    pub(crate) last_sent: AtomicU64,
    pub(crate) last_received: AtomicU64,

    //todo: pub(crate) closed_ch: Arc<Mutex<Option<broadcast::Sender<()>>>>,
    pub(crate) foundation_override: String,
    pub(crate) priority_override: u32,

    //CandidateHost
    pub(crate) network: String,
}

impl Default for CandidateBase {
    fn default() -> Self {
        Self {
            id: String::new(),
            network_type: 0,
            candidate_type: CandidateType::default(),

            component: 0,
            address: String::new(),
            port: 0,
            related_address: None,

            resolved_addr: SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),

            baseline_time: Instant::now(),
            last_sent: AtomicU64::new(0),
            last_received: AtomicU64::new(0),

            //todo: closed_ch: Arc::new(Mutex::new(None)),
            foundation_override: String::new(),
            priority_override: 0,
            network: String::new(),
        }
    }
}

// String makes the candidateBase printable
impl fmt::Display for CandidateBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(related_address) = self.related_address() {
            write!(
                f,
                "{} {}:{}{}",
                self.candidate_type(),
                self.address(),
                self.port(),
                related_address,
            )
        } else {
            write!(
                f,
                "{} {}:{}",
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
        self.baseline_time + Duration::from_nanos(self.last_received.load(Ordering::SeqCst))
    }

    /// Returns a time indicating the last time this candidate was sent.
    fn last_sent(&self) -> Instant {
        self.baseline_time + Duration::from_nanos(self.last_sent.load(Ordering::SeqCst))
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

    /// Returns the string representation of the ICECandidate.
    fn marshal(&self) -> String {
        let mut val = format!(
            "{} {} {} {} {} typ {}",
            self.foundation(),
            self.component(),
            self.priority(),
            self.address(),
            self.port(),
            self.candidate_type()
        );

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

    fn seen(&self, outbound: bool) {
        let d = Instant::now().duration_since(self.baseline_time);

        if outbound {
            self.set_last_sent(d);
        } else {
            self.set_last_received(d);
        }
    }

    fn write_to(&self, _raw: &[u8], _dst: &dyn Candidate) -> Result<usize> {
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
        self.candidate_type() == other.candidate_type()
            && self.address() == other.address()
            && self.port() == other.port()
            && self.related_address() == other.related_address()
    }

    fn set_ip(&mut self, ip: &IpAddr) -> Result<()> {
        self.resolved_addr = SocketAddr::new(*ip, self.port);

        Ok(())
    }

    /*TODO:fn get_closed_ch(&self) -> Arc<Mutex<Option<broadcast::Sender<()>>>> {
        self.closed_ch.clone()
    }*/
}

impl CandidateBase {
    pub fn set_last_received(&self, d: Duration) {
        self.last_received
            .store(d.as_nanos() as u64, Ordering::SeqCst);
    }

    pub fn set_last_sent(&self, d: Duration) {
        self.last_sent.store(d.as_nanos() as u64, Ordering::SeqCst);
    }

    /// Returns the local preference for this candidate.
    pub fn local_preference(&self) -> u16 {
        DEFAULT_LOCAL_PREFERENCE
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

    //let mut rel_addr = String::new();
    //let mut rel_port = 0;

    if split.len() > 8 {
        let split2 = &split[8..];

        if split2[0] == "raddr" && split2.len() < 4 {
            return Err(Error::Other(format!(
                "{:?}: incorrect length",
                Error::ErrParseRelatedAddr
            )));

            // RelatedAddress
            //rel_addr = split2[1].to_owned();

            // RelatedPort
            //rel_port = split2[3].parse()?;
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
            };
            config.new_candidate_host()
        }
        _ => Err(Error::Other(format!(
            "{:?} ({})",
            Error::ErrUnknownCandidateType,
            typ
        ))),
    }
}
