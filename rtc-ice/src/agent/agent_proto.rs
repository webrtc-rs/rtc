use super::*;

impl sansio::Protocol<TransportMessage<Message>, (), ()> for Agent {
    type Rout = ();
    type Wout = TransportMessage<BytesMut>;
    type Eout = Event;
    type Error = Error;
    type Time = Instant;

    fn handle_read(
        &mut self,
        mut msg: TransportMessage<Message>,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(local_index) =
            self.find_local_candidate(msg.transport.local_addr, msg.transport.transport_protocol)
        {
            self.handle_inbound(&mut msg.message, local_index, msg.transport.peer_addr)
        } else {
            warn!(
                "[{}]: Discarded message, not a valid local candidate from {:?}:{}",
                self.get_name(),
                msg.transport.transport_protocol,
                msg.transport.local_addr,
            );
            Err(Error::ErrUnhandledStunpacket)
        }
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        None
    }

    fn handle_write(&mut self, _msg: ()) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.transmits.pop_front()
    }

    fn handle_event(&mut self, _evt: ()) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.events.pop_front()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> std::result::Result<(), Self::Error> {
        if self.ufrag_pwd.remote_credentials.is_some()
            && self.last_checking_time + self.get_timeout_interval() <= now
        {
            self.contact(now);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        if self.ufrag_pwd.remote_credentials.is_some() {
            Some(self.last_checking_time + self.get_timeout_interval())
        } else {
            None
        }
    }

    fn close(&mut self) -> std::result::Result<(), Self::Error> {
        self.set_selected_pair(None);
        self.delete_all_candidates(false);
        self.update_connection_state(ConnectionState::Closed);

        Ok(())
    }
}
