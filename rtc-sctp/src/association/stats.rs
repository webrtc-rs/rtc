/// Association statistics
#[derive(Default, Debug, Copy, Clone)]
pub struct AssociationStats {
    n_datas: u64,
    n_sacks: u64,
    n_t3timeouts: u64,
    n_ack_timeouts: u64,
    n_fast_retrans: u64,
    n_rack_losses: u64,
    n_pto_probes: u64,
    bytes_sent: u64,
    bytes_received: u64,
}

impl AssociationStats {
    /// Counts one DATA chunk sent.
    pub fn inc_datas(&mut self) {
        self.n_datas += 1;
    }

    /// The number of DATA chunks sent.
    pub fn get_num_datas(&mut self) -> u64 {
        self.n_datas
    }

    /// Counts one SACK chunk received.
    pub fn inc_sacks(&mut self) {
        self.n_sacks += 1;
    }

    /// The number of SACK chunks received.
    pub fn get_num_sacks(&mut self) -> u64 {
        self.n_sacks
    }

    /// Counts one T3-rtx retransmission timeout.
    pub fn inc_t3timeouts(&mut self) {
        self.n_t3timeouts += 1;
    }

    /// The number of T3-rtx retransmission timeouts, a signal of loss or a stalled path.
    pub fn get_num_t3timeouts(&mut self) -> u64 {
        self.n_t3timeouts
    }

    /// Counts one delayed-acknowledgement timeout.
    pub fn inc_ack_timeouts(&mut self) {
        self.n_ack_timeouts += 1;
    }

    /// The number of delayed-acknowledgement timeouts.
    pub fn get_num_ack_timeouts(&mut self) -> u64 {
        self.n_ack_timeouts
    }

    /// Counts chunks that RACK declared lost.
    pub(crate) fn add_rack_losses(&mut self, count: usize) {
        self.n_rack_losses += count as u64;
    }

    /// The number of DATA chunks declared lost by time-based (RACK) detection, i.e. without three
    /// SACK gap reports and without waiting for a retransmission timeout.
    pub fn get_num_rack_losses(&self) -> u64 {
        self.n_rack_losses
    }

    /// Counts one tail-loss probe.
    pub(crate) fn inc_pto_probes(&mut self) {
        self.n_pto_probes += 1;
    }

    /// The number of tail-loss probes sent after two round trips of silence.
    pub fn get_num_pto_probes(&self) -> u64 {
        self.n_pto_probes
    }

    /// Counts one fast retransmission.
    pub fn inc_fast_retrans(&mut self) {
        self.n_fast_retrans += 1;
    }

    /// The number of fast retransmissions, triggered by SACK gap reports rather than a timeout.
    pub fn get_num_fast_retrans(&mut self) -> u64 {
        self.n_fast_retrans
    }

    /// Counts application payload bytes accepted for transmission.
    ///
    /// One call per DATA chunk at `send_payload_data` time, so the count is of user data
    /// handed to the association — not of retransmissions of it, which re-send bytes
    /// already counted here.
    pub fn add_bytes_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
    }

    /// The total application payload bytes accepted for transmission.
    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Counts application payload bytes accepted from the peer.
    ///
    /// Counted once per DATA chunk accepted into the payload queue; duplicates dropped
    /// before reassembly are not counted.
    pub fn add_bytes_received(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
    }

    /// The total application payload bytes accepted from the peer.
    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Zeroes every counter.
    pub fn reset(&mut self) {
        self.n_datas = 0;
        self.n_sacks = 0;
        self.n_t3timeouts = 0;
        self.n_ack_timeouts = 0;
        self.n_fast_retrans = 0;
        self.bytes_sent = 0;
        self.bytes_received = 0;
    }
}
