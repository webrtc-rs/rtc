/// Association statistics
#[derive(Default, Debug, Copy, Clone)]
pub struct AssociationStats {
    n_datas: u64,
    n_sacks: u64,
    n_t3timeouts: u64,
    n_ack_timeouts: u64,
    n_fast_retrans: u64,
    n_cwnd_cuts: u64,
    n_cwnd_cuts_undone: u64,
    n_loss_probes: u64,
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

    /// Counts one fast retransmission.
    pub fn inc_fast_retrans(&mut self) {
        self.n_fast_retrans += 1;
    }

    /// The number of fast retransmissions, triggered by SACK gap reports rather than a timeout.
    pub fn get_num_fast_retrans(&mut self) -> u64 {
        self.n_fast_retrans
    }

    /// Counts one congestion window cut made on a SACK or a loss probe.
    pub fn inc_cwnd_cuts(&mut self) {
        self.n_cwnd_cuts += 1;
    }

    /// The number of congestion window cuts made on a SACK or a loss probe; T3-rtx counts apart.
    pub fn get_num_cwnd_cuts(&mut self) -> u64 {
        self.n_cwnd_cuts
    }

    /// Counts one cut restored because duplicate reports proved its retransmissions needless.
    pub fn inc_cwnd_cuts_undone(&mut self) {
        self.n_cwnd_cuts_undone += 1;
    }

    /// The number of congestion window cuts restored after needless retransmissions.
    pub fn get_num_cwnd_cuts_undone(&mut self) -> u64 {
        self.n_cwnd_cuts_undone
    }

    /// Counts one tail loss probe sent.
    pub fn inc_loss_probes(&mut self) {
        self.n_loss_probes += 1;
    }

    /// The number of tail loss probes sent.
    pub fn get_num_loss_probes(&mut self) -> u64 {
        self.n_loss_probes
    }

    /// Zeroes every counter.
    pub fn reset(&mut self) {
        self.n_datas = 0;
        self.n_sacks = 0;
        self.n_t3timeouts = 0;
        self.n_ack_timeouts = 0;
        self.n_fast_retrans = 0;
        self.n_cwnd_cuts = 0;
        self.n_cwnd_cuts_undone = 0;
        self.n_loss_probes = 0;
    }
}
