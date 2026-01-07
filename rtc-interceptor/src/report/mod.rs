use crate::interceptors::{Interceptor, InterceptorBuilder};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub(crate) mod receiver_report;
pub(crate) mod receiver_stream;
pub(crate) mod sender_report;

use receiver_report::ReceiverReport;
use sender_report::SenderReport;

/// ReceiverBuilder can be used to configure ReceiverReport Interceptor.
#[derive(Default)]
pub struct ReportBuilder {
    is_rr: bool,
    interval: Option<Duration>,
}

impl ReportBuilder {
    /// with_interval sets send interval for the interceptor.
    pub fn with_interval(mut self, interval: Duration) -> ReportBuilder {
        self.interval = Some(interval);
        self
    }

    fn build_rr(&self) -> ReceiverReport {
        ReceiverReport {
            interval: if let Some(interval) = &self.interval {
                *interval
            } else {
                Duration::from_secs(1) //TODO: make it configurable
            },
            eto: Instant::now(),
            streams: HashMap::new(),
            next: None,
        }
    }

    fn build_sr(&self) -> SenderReport {
        SenderReport { next: None }
    }
}

impl InterceptorBuilder for ReportBuilder {
    fn build(&self, _id: &str) -> Box<dyn Interceptor> {
        if self.is_rr {
            Box::new(self.build_rr())
        } else {
            Box::new(self.build_sr())
        }
    }
}
