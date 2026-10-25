use super::*;

impl Server {
    pub(super) fn allocate(
        &mut self,
        tuple: FiveTuple,
        request: Message,
        identity: auth::Identity,
    ) -> Result<()> {
        if let Some(pending) = self.pending.get(&tuple) {
            if pending.request.raw == request.raw {
                return Ok(());
            }
            return self.error_response(
                tuple,
                &request,
                CODE_ALLOC_MISMATCH,
                Some(identity.key.as_ref()),
                vec![],
            );
        }
        if self.allocations.contains_key(&tuple) {
            return self.error_response(
                tuple,
                &request,
                CODE_ALLOC_MISMATCH,
                Some(identity.key.as_ref()),
                vec![],
            );
        }
        if self.cache.len() + self.pending.len() >= self.config.max_replay_entries {
            return self.error_response(
                tuple,
                &request,
                CODE_INSUFFICIENT_CAPACITY,
                Some(identity.key.as_ref()),
                vec![],
            );
        }
        let mut protocol = RequestedTransport::default();
        if protocol.get_from(&request).is_err() {
            return self.error_response(
                tuple,
                &request,
                CODE_BAD_REQUEST,
                Some(identity.key.as_ref()),
                vec![],
            );
        }
        if protocol.protocol != PROTO_UDP {
            return self.error_response(
                tuple,
                &request,
                CODE_UNSUPPORTED_TRANS_PROTO,
                Some(identity.key.as_ref()),
                vec![],
            );
        }
        let family = if request.contains(ATTR_REQUESTED_ADDRESS_FAMILY) {
            let mut family = RequestedAddressFamily::default();
            if family.get_from(&request).is_err() {
                return self.error_response(
                    tuple,
                    &request,
                    CODE_BAD_REQUEST,
                    Some(identity.key.as_ref()),
                    vec![],
                );
            }
            if family == REQUESTED_FAMILY_IPV6 {
                AddressFamily::Ipv6
            } else {
                AddressFamily::Ipv4
            }
        } else {
            AddressFamily::Ipv4
        };
        if request.contains(ATTR_EVEN_PORT)
            || request.contains(ATTR_RESERVATION_TOKEN)
            || request.contains(ATTR_DONT_FRAGMENT)
        {
            let unsupported = [ATTR_EVEN_PORT, ATTR_RESERVATION_TOKEN, ATTR_DONT_FRAGMENT]
                .into_iter()
                .filter(|attr| request.contains(*attr))
                .collect();
            return self.error_response(
                tuple,
                &request,
                CODE_UNKNOWN_ATTRIBUTE,
                Some(identity.key.as_ref()),
                unsupported,
            );
        }
        let lifetime = match self.requested_lifetime(&request, false) {
            Ok(lifetime) => lifetime,
            Err(code) => {
                return self.error_response(
                    tuple,
                    &request,
                    code,
                    Some(identity.key.as_ref()),
                    vec![],
                );
            }
        };
        let user_count = self
            .allocations
            .values()
            .filter(|allocation| allocation.username == identity.username)
            .count()
            + self
                .pending
                .values()
                .filter(|pending| pending.username == identity.username)
                .count();
        if user_count >= self.config.max_allocations_per_user {
            return self.error_response(
                tuple,
                &request,
                CODE_ALLOC_QUOTA_REACHED,
                Some(identity.key.as_ref()),
                vec![],
            );
        }
        if self.allocations.len() + self.pending.len() >= self.config.max_allocations {
            return self.error_response(
                tuple,
                &request,
                CODE_INSUFFICIENT_CAPACITY,
                Some(identity.key.as_ref()),
                vec![],
            );
        }
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| Error::Other("TURN allocation IDs exhausted".into()))?;
        let id = AllocationId(self.next_id);
        self.pending.insert(
            tuple,
            Pending {
                id,
                username: identity.username,
                key: identity.key,
                request,
                family,
                lifetime,
                expires: self.now + self.config.pending_lifetime,
            },
        );
        self.events.push_back(Event::AllocateRelay {
            allocation_id: id,
            client: tuple,
            family,
        });
        Ok(())
    }

    fn requested_lifetime(
        &self,
        request: &Message,
        allow_zero: bool,
    ) -> std::result::Result<Duration, ErrorCode> {
        if !request.contains(ATTR_LIFETIME) {
            return Ok(self.config.default_lifetime);
        }
        let mut lifetime = Lifetime::default();
        lifetime.get_from(request).map_err(|_| CODE_BAD_REQUEST)?;
        if lifetime.0.is_zero() && !allow_zero {
            return Ok(self.config.default_lifetime);
        }
        Ok(lifetime.0.min(self.config.max_lifetime))
    }

    pub(super) fn refresh(
        &mut self,
        tuple: FiveTuple,
        request: &Message,
    ) -> std::result::Result<Message, ErrorCode> {
        let lifetime = self.requested_lifetime(request, true)?;
        if request.contains(ATTR_REQUESTED_ADDRESS_FAMILY) {
            let mut family = RequestedAddressFamily::default();
            family.get_from(request).map_err(|_| CODE_BAD_REQUEST)?;
            let address = self.allocations[&tuple].relay.ip();
            if (family == REQUESTED_FAMILY_IPV4) != address.is_ipv4() {
                return Err(CODE_PEER_ADDR_FAMILY_MISMATCH);
            }
        }
        let mut response = message::response(request, CLASS_SUCCESS_RESPONSE);
        Lifetime(lifetime)
            .add_to(&mut response)
            .map_err(|_| CODE_SERVER_ERROR)?;
        if lifetime.is_zero() {
            self.release(tuple);
        } else {
            self.allocations
                .get_mut(&tuple)
                .expect("authenticated allocation")
                .expires = self.now + lifetime;
        }
        Ok(response)
    }

    fn peers(
        &self,
        tuple: FiveTuple,
        request: &Message,
    ) -> std::result::Result<Vec<SocketAddr>, ErrorCode> {
        let allocation = &self.allocations[&tuple];
        let mut peers = Vec::new();
        for attr in &request.attributes.0 {
            if attr.typ != ATTR_XOR_PEER_ADDRESS {
                continue;
            }
            let mut single = request.clone();
            single
                .attributes
                .0
                .retain(|attribute| attribute.typ != ATTR_XOR_PEER_ADDRESS);
            single.attributes.0.push(attr.clone());
            let mut address = PeerAddress::default();
            address.get_from(&single).map_err(|_| CODE_BAD_REQUEST)?;
            let peer = SocketAddr::new(address.ip, address.port);
            if peer.ip().is_ipv4() != allocation.relay.is_ipv4() {
                return Err(CODE_PEER_ADDR_FAMILY_MISMATCH);
            }
            let policy_peer = if request.typ.method == METHOD_CREATE_PERMISSION {
                SocketAddr::new(peer.ip(), 1)
            } else {
                peer
            };
            if (request.typ.method != METHOD_CREATE_PERMISSION && peer.port() == 0)
                || peer.ip().is_unspecified()
                || peer.ip().is_multicast()
                || (request.typ.method != METHOD_CREATE_PERMISSION
                    && (peer == tuple.local_addr || peer == allocation.relay))
                || !self
                    .authenticator
                    .allow_peer(&allocation.username, policy_peer)
            {
                return Err(CODE_FORBIDDEN);
            }
            peers.push(peer);
        }
        if peers.is_empty() {
            return Err(CODE_BAD_REQUEST);
        }
        Ok(peers)
    }

    pub(super) fn create_permission(
        &mut self,
        tuple: FiveTuple,
        request: &Message,
    ) -> std::result::Result<Message, ErrorCode> {
        let peers = self.peers(tuple, request)?;
        let allocation = self
            .allocations
            .get_mut(&tuple)
            .expect("authenticated allocation");
        let new_ips: HashSet<_> = peers
            .iter()
            .map(|peer| peer.ip())
            .filter(|ip| !allocation.permissions.contains_key(ip))
            .collect();
        if allocation.permissions.len() + new_ips.len() > self.config.max_permissions {
            return Err(CODE_INSUFFICIENT_CAPACITY);
        }
        for peer in peers {
            allocation
                .permissions
                .insert(peer.ip(), self.now + PERMISSION_LIFETIME);
        }
        Ok(message::response(request, CLASS_SUCCESS_RESPONSE))
    }

    pub(super) fn bind_channel(
        &mut self,
        tuple: FiveTuple,
        request: &Message,
    ) -> std::result::Result<Message, ErrorCode> {
        let mut number = ChannelNumber::default();
        number.get_from(request).map_err(|_| CODE_BAD_REQUEST)?;
        // RFC 8656 reduced the usable range to 0x4000..=0x4fff.
        if !(0x4000..=0x4fff).contains(&number.0) {
            return Err(CODE_BAD_REQUEST);
        }
        let peers = self.peers(tuple, request)?;
        if peers.len() != 1 {
            return Err(CODE_BAD_REQUEST);
        }
        let peer = peers[0];
        let allocation = self
            .allocations
            .get_mut(&tuple)
            .expect("authenticated allocation");
        if allocation.channels.iter().any(|(other_number, channel)| {
            (*other_number == number.0 && channel.peer != peer)
                || (*other_number != number.0 && channel.peer == peer)
        }) {
            return Err(CODE_BAD_REQUEST);
        }
        if (!allocation.channels.contains_key(&number.0)
            && allocation.channels.len() >= self.config.max_channels)
            || (!allocation.permissions.contains_key(&peer.ip())
                && allocation.permissions.len() >= self.config.max_permissions)
        {
            return Err(CODE_INSUFFICIENT_CAPACITY);
        }
        allocation.channels.insert(
            number.0,
            Channel {
                peer,
                expires: self.now + CHANNEL_LIFETIME,
            },
        );
        allocation
            .permissions
            .insert(peer.ip(), self.now + PERMISSION_LIFETIME);
        Ok(message::response(request, CLASS_SUCCESS_RESPONSE))
    }
}
