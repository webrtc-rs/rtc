use super::*;

impl Server {
    pub(super) fn permitted(allocation: &Allocation, peer: SocketAddr, now: Instant) -> bool {
        peer.ip().is_ipv4() == allocation.relay.is_ipv4()
            && allocation
                .permissions
                .get(&peer.ip())
                .is_some_and(|expires| *expires > now)
    }

    pub(super) fn send_indication(&mut self, tuple: FiveTuple, request: &Message) -> Result<()> {
        let Some(allocation) = self.allocations.get(&tuple) else {
            return Ok(());
        };
        if !message::unknown_attributes(request).is_empty() || request.contains(ATTR_DONT_FRAGMENT)
        {
            return Ok(());
        }
        let mut peer = PeerAddress::default();
        if peer.get_from(request).is_err() {
            return Ok(());
        }
        let peer = SocketAddr::new(peer.ip, peer.port);
        let Ok(data) = request.get(ATTR_DATA) else {
            return Ok(());
        };
        if peer == tuple.local_addr
            || peer == allocation.relay
            || data.len() > MAX_UDP_PAYLOAD
            || !Self::permitted(allocation, peer, self.now)
            || !self.authenticator.allow_peer(&allocation.username, peer)
        {
            return Ok(());
        }
        self.events.push_back(Event::SendToPeer {
            allocation_id: allocation.id,
            peer,
            data: BytesMut::from(data.as_slice()),
        });
        Ok(())
    }

    pub(super) fn channel_data(&mut self, tuple: FiveTuple, data: &[u8]) -> Result<()> {
        if data.len() < 4 || data.len() > MAX_UDP_PAYLOAD {
            return Ok(());
        }
        let number = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let padded = (length + 3) & !3;
        if !(0x4000..=0x4fff).contains(&number)
            || (data.len() != length + 4 && data.len() != padded + 4)
        {
            return Ok(());
        }
        let Some(allocation) = self.allocations.get(&tuple) else {
            return Ok(());
        };
        let Some(channel) = allocation.channels.get(&number) else {
            return Ok(());
        };
        if channel.peer == tuple.local_addr
            || channel.peer == allocation.relay
            || channel.expires <= self.now
            || !self
                .authenticator
                .allow_peer(&allocation.username, channel.peer)
        {
            return Ok(());
        }
        self.events.push_back(Event::SendToPeer {
            allocation_id: allocation.id,
            peer: channel.peer,
            data: BytesMut::from(&data[4..4 + length]),
        });
        Ok(())
    }
}
