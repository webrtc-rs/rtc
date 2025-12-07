use crate::conn::*;
use crate::content::*;
use shared::error::*;

use log::*;
use std::fmt;
use std::time::Instant;

//use std::io::BufWriter;

// [RFC6347 Section-4.2.4]
//                      +-----------+
//                +---> | PREPARING | <--------------------+
//                |     +-----------+                      |
//                |           |                            |
//                |           | Buffer next flight         |
//                |           |                            |
//                |          \|/                           |
//                |     +-----------+                      |
//                |     |  SENDING  |<------------------+  | Send
//                |     +-----------+                   |  | HelloRequest
//        Receive |           |                         |  |
//           next |           | Send flight             |  | or
//         flight |  +--------+                         |  |
//                |  |        | Set retransmit timer    |  | Receive
//                |  |       \|/                        |  | HelloRequest
//                |  |  +-----------+                   |  | Send
//                +--)--|  WAITING  |-------------------+  | ClientHello
//                |  |  +-----------+   Timer expires   |  |
//                |  |         |                        |  |
//                |  |         +------------------------+  |
//        Receive |  | Send           Read retransmit      |
//           last |  | last                                |
//         flight |  | flight                              |
//                |  |                                     |
//               \|/\|/                                    |
//            +-----------+                                |
//            | FINISHED  | -------------------------------+
//            +-----------+
//                 |  /|\
//                 |   |
//                 +---+
//              Read retransmit
//           Retransmit last flight

#[derive(Copy, Clone, PartialEq)]
pub(crate) enum HandshakeState {
    Errored,
    Preparing,
    Sending,
    Waiting,
    Finished,
}

impl fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            HandshakeState::Errored => write!(f, "Errored"),
            HandshakeState::Preparing => write!(f, "Preparing"),
            HandshakeState::Sending => write!(f, "Sending"),
            HandshakeState::Waiting => write!(f, "Waiting"),
            HandshakeState::Finished => write!(f, "Finished"),
        }
    }
}

pub(crate) fn srv_cli_str(is_client: bool) -> String {
    if is_client {
        return "client".to_owned();
    }
    "state".to_owned()
}

impl DTLSConn {
    pub(crate) fn handshake(&mut self) -> Result<()> {
        loop {
            debug!(
                "[handshake:{}] {}: {}",
                srv_cli_str(self.state.is_client),
                self.current_flight,
                self.current_handshake_state
            );

            if self.current_handshake_state == HandshakeState::Finished
                && !self.is_handshake_completed()
            {
                self.set_handshake_completed();
                debug!(
                    "[handshake:{}] is completed",
                    srv_cli_str(self.state.is_client),
                );
                return Ok(());
            }

            let previous_handshake_state = self.current_handshake_state;
            self.current_handshake_state = match previous_handshake_state {
                HandshakeState::Preparing => self.prepare()?,
                HandshakeState::Sending => self.send()?,
                HandshakeState::Waiting => self.wait()?,
                HandshakeState::Finished => self.finish()?,
                _ => return Err(Error::ErrInvalidFsmTransition),
            };

            if previous_handshake_state == self.current_handshake_state
                && previous_handshake_state == HandshakeState::Waiting
            {
                // wait for timeout or incoming packet
                return Ok(());
            }
        }
    }

    fn prepare(&mut self) -> Result<HandshakeState> {
        self.flights = None;

        // Prepare flights
        self.current_retransmit_count = 0;
        self.retransmit = self.current_flight.has_retransmit();

        let result =
            self.current_flight
                .generate(&mut self.state, &self.cache, &self.handshake_config);

        match result {
            Err((a, err)) => {
                if let Some(a) = a {
                    self.notify(a.alert_level, a.alert_description);
                }
                if let Some(err) = err {
                    return Err(err);
                }
            }
            Ok(pkts) => self.flights = Some(pkts),
        };

        let epoch = self.handshake_config.initial_epoch;
        let mut next_epoch = epoch;
        if let Some(pkts) = &mut self.flights {
            for p in pkts {
                p.record.record_layer_header.epoch += epoch;
                if p.record.record_layer_header.epoch > next_epoch {
                    next_epoch = p.record.record_layer_header.epoch;
                }
                if let Content::Handshake(h) = &mut p.record.content {
                    h.handshake_header.message_sequence = self.state.handshake_send_sequence as u16;
                    self.state.handshake_send_sequence += 1;
                }
            }
        }
        if epoch != next_epoch {
            debug!(
                "[handshake:{}] -> changeCipherSpec (epoch: {})",
                srv_cli_str(self.state.is_client),
                next_epoch
            );
            self.set_local_epoch(next_epoch);
        }

        Ok(HandshakeState::Sending)
    }
    fn send(&mut self) -> Result<HandshakeState> {
        // Send flights
        if let Some(pkts) = self.flights.clone() {
            self.write_packets(pkts);
        }

        if self.current_flight.is_last_send_flight() {
            Ok(HandshakeState::Finished)
        } else {
            self.current_retransmit_timer =
                Some(Instant::now() + self.handshake_config.retransmit_interval);
            Ok(HandshakeState::Waiting)
        }
    }
    fn wait(&mut self) -> Result<HandshakeState> {
        if self.handshake_rx.take().is_some() {
            debug!(
                "[handshake:{}] {} received handshake packets",
                srv_cli_str(self.state.is_client),
                self.current_flight
            );
            self.current_retransmit_timer = None;
            let result = self.current_flight.parse(
                /*&mut self.handle_queue_tx,*/ &mut self.state,
                &self.cache,
                &self.handshake_config,
            );
            match result {
                Err((alert, err)) => {
                    debug!(
                        "[handshake:{}] {} result alert:{:?}, err:{:?}",
                        srv_cli_str(self.state.is_client),
                        self.current_flight,
                        alert,
                        err
                    );

                    if let Some(alert) = alert {
                        self.notify(alert.alert_level, alert.alert_description);
                    }
                    if let Some(err) = err {
                        return Err(err);
                    }
                }
                Ok(next_flight) => {
                    debug!(
                        "[handshake:{}] {} -> {}",
                        srv_cli_str(self.state.is_client),
                        self.current_flight,
                        next_flight
                    );
                    if next_flight.is_last_recv_flight()
                        && self.current_flight.to_string() == next_flight.to_string()
                    {
                        return Ok(HandshakeState::Finished);
                    }
                    self.current_flight = next_flight;
                    return Ok(HandshakeState::Preparing);
                }
            }
        }

        Ok(HandshakeState::Waiting)
    }
    fn finish(&mut self) -> Result<HandshakeState> {
        if self.handshake_rx.take().is_some() {
            debug!(
                "[handshake:{}] {} received handshake packets",
                srv_cli_str(self.state.is_client),
                self.current_flight
            );
            self.current_retransmit_timer = None;
            let result = self.current_flight.parse(
                /*&mut self.handle_queue_tx,*/ &mut self.state,
                &self.cache,
                &self.handshake_config,
            );
            if let Err((alert, err)) = result {
                if let Some(alert) = alert {
                    self.notify(alert.alert_level, alert.alert_description);
                }
                if let Some(err) = err {
                    return Err(err);
                }
            };
        }

        Ok(HandshakeState::Finished)
    }

    pub(crate) fn handshake_timeout(&mut self, _now: Instant) -> Result<()> {
        let next_handshake_state = if self.current_handshake_state == HandshakeState::Waiting {
            debug!(
                "[handshake:{}] {} retransmit_timer",
                srv_cli_str(self.state.is_client),
                self.current_flight
            );
            debug!(
                "[handshake:{}] {} current_retransmit_count {} vs maximum_retransmit_number {}",
                srv_cli_str(self.state.is_client),
                self.current_flight,
                self.current_retransmit_count,
                self.maximum_retransmit_number,
            );
            if self.retransmit {
                self.current_retransmit_count += 1;
                if self.current_retransmit_count > self.maximum_retransmit_number {
                    Some(HandshakeState::Errored)
                } else {
                    Some(HandshakeState::Sending)
                }
            } else {
                self.current_retransmit_timer =
                    Some(Instant::now() + self.handshake_config.retransmit_interval);
                Some(HandshakeState::Waiting)
            }
        } else if self.current_handshake_state == HandshakeState::Finished {
            // Retransmit last flight
            Some(HandshakeState::Sending)
        } else {
            None
        };

        if let Some(next_handshake_state) = next_handshake_state {
            self.current_handshake_state = next_handshake_state;
            self.handshake()
        } else {
            Ok(())
        }
    }
}
