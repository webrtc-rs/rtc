use opentelemetry::{
    metrics::{Counter, Meter, ObservableGauge, Unit},
    KeyValue,
};

pub(crate) struct Metrics {
    rtp_packet_in_count: Counter<u64>,
    rtp_packet_out_count: Counter<u64>,
    rtcp_packet_in_count: Counter<u64>,
    rtcp_packet_out_count: Counter<u64>,
    remote_srtp_context_not_set_count: Counter<u64>,
    local_srtp_context_not_set_count: Counter<u64>,
    rtp_packet_processing_time: ObservableGauge<u64>,
    rtcp_packet_processing_time: ObservableGauge<u64>,
}

impl Metrics {
    pub(crate) fn new(meter: Meter) -> Self {
        Self {
            rtp_packet_in_count: meter.u64_counter("rtp_packet_in_count").init(),
            rtp_packet_out_count: meter.u64_counter("rtp_packet_out_count").init(),
            rtcp_packet_in_count: meter.u64_counter("rtcp_packet_in_count").init(),
            rtcp_packet_out_count: meter.u64_counter("rtcp_packet_out_count").init(),
            remote_srtp_context_not_set_count: meter
                .u64_counter("remote_srtp_context_not_set_count")
                .init(),
            local_srtp_context_not_set_count: meter
                .u64_counter("local_srtp_context_not_set_count")
                .init(),
            rtp_packet_processing_time: meter
                .u64_observable_gauge("rtp_packet_processing_time")
                .with_unit(Unit::new("us"))
                .init(),
            rtcp_packet_processing_time: meter
                .u64_observable_gauge("rtcp_packet_processing_time")
                .with_unit(Unit::new("us"))
                .init(),
        }
    }

    pub(crate) fn record_rtp_packet_in_count(&self, value: u64, attributes: &[KeyValue]) {
        self.rtp_packet_in_count.add(value, attributes);
    }

    pub(crate) fn record_rtp_packet_out_count(&self, value: u64, attributes: &[KeyValue]) {
        self.rtp_packet_out_count.add(value, attributes);
    }

    pub(crate) fn record_rtcp_packet_in_count(&self, value: u64, attributes: &[KeyValue]) {
        self.rtcp_packet_in_count.add(value, attributes);
    }

    pub(crate) fn record_rtcp_packet_out_count(&self, value: u64, attributes: &[KeyValue]) {
        self.rtcp_packet_out_count.add(value, attributes);
    }

    pub(crate) fn record_remote_srtp_context_not_set_count(
        &self,
        value: u64,
        attributes: &[KeyValue],
    ) {
        self.remote_srtp_context_not_set_count
            .add(value, attributes);
    }

    pub(crate) fn record_local_srtp_context_not_set_count(
        &self,
        value: u64,
        attributes: &[KeyValue],
    ) {
        self.local_srtp_context_not_set_count.add(value, attributes);
    }

    pub(crate) fn record_rtp_packet_processing_time(&self, value: u64, attributes: &[KeyValue]) {
        self.rtp_packet_processing_time.observe(value, attributes);
    }

    pub(crate) fn record_rtcp_packet_processing_time(&self, value: u64, attributes: &[KeyValue]) {
        self.rtcp_packet_processing_time.observe(value, attributes);
    }
}
