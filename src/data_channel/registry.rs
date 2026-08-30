use crate::data_channel::RTCDataChannelId;
use crate::data_channel::internal::RTCDataChannelInternal;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use shared::error::{Error, Result};
use std::collections::HashMap;

/// Every data channel on a peer connection, indexed by both of its identifiers.
///
/// A channel has two: the [`RTCDataChannelId`] handle the application uses to address it, and
/// the SCTP stream identifier (a `u16`) it occupies on the wire. They are deliberately
/// different things, even though both are `u16` here.
///
/// The handle is allocated when the channel is created and never changes. The stream id cannot
/// be, because RFC 8832 §6 makes its parity depend on the DTLS role — even for the client, odd
/// for the server — and that role is not known until a remote description has been applied. An
/// in-band channel therefore has no stream id between `create_data_channel` and the SCTP
/// connected procedure, which is exactly the window in which an application wants to hold a
/// reference to it. Keying the collection by the handle is what lets it do so.
///
/// The reverse index exists because the two directions arrive differently: the application and
/// every event name a channel by handle, while SCTP hands us a stream id.
#[derive(Default)]
pub(crate) struct DataChannelRegistry {
    channels: HashMap<RTCDataChannelId, RTCDataChannelInternal>,

    /// Wire stream id -> handle, for every channel that has been assigned one. Doubles as the
    /// authoritative "which stream ids are taken" set consulted when assigning new ones: it is
    /// fed by all three channel origins (locally deferred, out-of-band, and accepted from the
    /// peer), so a generated id cannot collide with one the peer opened first.
    by_stream: HashMap<u16, RTCDataChannelId>,

    /// Cursor for the next handle to try. Advances monotonically and wraps; `alloc_handle`
    /// skips any value still occupied.
    next_handle: RTCDataChannelId,
}

impl DataChannelRegistry {
    pub(crate) fn new() -> Self {
        Self {
            channels: HashMap::new(),
            by_stream: HashMap::new(),
            next_handle: 0,
        }
    }

    /// Registers `data_channel`, assigning it a fresh handle and indexing its stream id if it
    /// already has one.
    ///
    /// Handles advance monotonically and wrap, skipping any still in use, so a handle is only
    /// reused once the whole `u16` space has been cycled — long after the channel that held it
    /// is gone. (The stream id it occupied becomes available again immediately, as before.)
    ///
    /// The handle space is `u16` on this branch to keep [`RTCDataChannelId`] source-compatible,
    /// so unlike a `usize` counter it can in principle be exhausted; `u16::MAX` simultaneously
    /// live channels is far beyond what SCTP itself allows, so the scan below always finds a
    /// free handle in practice.
    pub(crate) fn insert(&mut self, data_channel: RTCDataChannelInternal) -> RTCDataChannelId {
        let handle = self.alloc_handle();

        if let Some(stream_id) = data_channel.stream_id {
            self.by_stream.insert(stream_id, handle);
        }
        self.channels.insert(handle, data_channel);

        handle
    }

    /// The next free handle, advancing the cursor past it.
    fn alloc_handle(&mut self) -> RTCDataChannelId {
        // Skip any handle still occupied. Bounded: `channels` cannot hold more than
        // `u16::MAX` entries, so at least one value in the space is always free.
        for _ in 0..=RTCDataChannelId::MAX {
            let candidate = self.next_handle;
            self.next_handle = self.next_handle.wrapping_add(1);
            if !self.channels.contains_key(&candidate) {
                return candidate;
            }
        }
        // Unreachable while `channels.len() <= u16::MAX`, which the type itself guarantees.
        self.next_handle
    }

    pub(crate) fn get(&self, handle: &RTCDataChannelId) -> Option<&RTCDataChannelInternal> {
        self.channels.get(handle)
    }

    pub(crate) fn get_mut(
        &mut self,
        handle: &RTCDataChannelId,
    ) -> Option<&mut RTCDataChannelInternal> {
        self.channels.get_mut(handle)
    }

    pub(crate) fn contains(&self, handle: &RTCDataChannelId) -> bool {
        self.channels.contains_key(handle)
    }

    /// The handle of the channel occupying `stream_id`, if any.
    pub(crate) fn handle_of_stream(&self, stream_id: &u16) -> Option<RTCDataChannelId> {
        self.by_stream.get(stream_id).copied()
    }

    pub(crate) fn get_by_stream(&self, stream_id: &u16) -> Option<&RTCDataChannelInternal> {
        self.channels.get(self.by_stream.get(stream_id)?)
    }

    pub(crate) fn get_by_stream_mut(
        &mut self,
        stream_id: &u16,
    ) -> Option<&mut RTCDataChannelInternal> {
        let handle = *self.by_stream.get(stream_id)?;
        self.channels.get_mut(&handle)
    }

    /// Removes the channel occupying `stream_id`, freeing that id for reuse.
    /// Removes the channel occupying `stream_id`, returning its handle alongside it and
    /// freeing that stream id for reuse.
    pub(crate) fn remove_by_stream(
        &mut self,
        stream_id: &u16,
    ) -> Option<(RTCDataChannelId, RTCDataChannelInternal)> {
        let handle = self.by_stream.remove(stream_id)?;
        let data_channel = self.channels.remove(&handle)?;
        Some((handle, data_channel))
    }

    /// Whether `stream_id` is already claimed, by a channel of any origin.
    pub(crate) fn stream_id_in_use(&self, stream_id: &u16) -> bool {
        self.by_stream.contains_key(stream_id)
    }

    /// Handles of channels still awaiting a stream id, in a stable order.
    ///
    /// Sorting is what matters: `channels` is a `HashMap`, so without it two runs of the same
    /// program would hand out different stream ids. (Ascending handle order is usually creation
    /// order too, but handle reuse after a wrap can break that; determinism does not depend on
    /// it, and any assignment of distinct correct-parity ids is equally correct.)
    pub(crate) fn pending_stream_id_handles(&self) -> Vec<RTCDataChannelId> {
        let mut handles: Vec<_> = self
            .channels
            .iter()
            .filter(|(_, dc)| dc.stream_id.is_none())
            .map(|(handle, _)| *handle)
            .collect();
        handles.sort_unstable();
        handles
    }

    /// Assigns SCTP stream identifiers to every channel still awaiting one.
    ///
    /// This is the W3C "RTCSctpTransport connected procedure" step that RFC 8832 §6 governs:
    ///
    /// > The peer that initiates opening a data channel selects a stream identifier for which
    /// > the corresponding incoming and outgoing streams are unused. If the side is acting as
    /// > the DTLS client, it MUST choose an even stream identifier; if the side is acting as
    /// > the DTLS server, it MUST choose an odd one.
    ///
    /// `role` must already be resolved. An unresolved role is a caller bug, and returning an
    /// error rather than defaulting is the entire point: silently treating
    /// [`RTCDtlsRole::Auto`] as server parity — which is what the previous
    /// `generate_data_channel_id` did, at channel-creation time when the role could not yet be
    /// known — gave every channel an odd id regardless of role. The endpoint that later
    /// resolved to DTLS client was then holding ids it was not allowed to use, and which the
    /// peer acting as server was handing out at the same time
    /// (<https://github.com/webrtc-rs/rtc/issues/199>).
    ///
    /// `max_channels` is the association's negotiated stream limit, bounding the id space;
    /// `None` before the association reports one. Channels are served in creation order, so
    /// the assignment is deterministic across runs.
    ///
    /// Lives here, on the type that owns the id space, because both callers need it: the SCTP
    /// connected procedure in `DataChannelHandler`, which sees only the registry, and
    /// `RTCPeerConnection::create_data_channel` when an association already exists.
    pub(crate) fn assign_stream_ids(&mut self, role: RTCDtlsRole, max_channels: u16) -> Result<()> {
        let mut next: u16 = match role {
            RTCDtlsRole::Client => 0,
            RTCDtlsRole::Server => 1,
            // Never guess a parity.
            _ => return Err(Error::ErrDataChannelStreamIdNotAssigned),
        };

        // The negotiated stream count bounds stream ids, but only once it is known: a channel
        // may be created before the association exists, and until it connects there is nothing
        // to bound against. This matches W3C §6.1.1.3, which applies the limit at the connected
        // procedure rather than at creation.
        let max = max_channels;

        for handle in self.pending_stream_id_handles() {
            // Skip ids already claimed — by an out-of-band channel the application pinned, or
            // by one the peer opened first. Carrying the cursor across iterations rather than
            // restarting the scan keeps this a single pass.
            while next < max.saturating_sub(1) && self.stream_id_in_use(&next) {
                next += 2;
            }
            if next >= max.saturating_sub(1) {
                return Err(Error::ErrMaxDataChannelID);
            }
            self.assign_stream_id(handle, next);
            next += 2;
        }

        Ok(())
    }

    /// Binds `handle` to `stream_id`. No-op if the handle is unknown.
    pub(crate) fn assign_stream_id(&mut self, handle: RTCDataChannelId, stream_id: u16) {
        if let Some(data_channel) = self.channels.get_mut(&handle) {
            data_channel.stream_id = Some(stream_id);
            self.by_stream.insert(stream_id, handle);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.channels.len()
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &RTCDataChannelInternal> {
        self.channels.values()
    }

    pub(crate) fn values_mut(&mut self) -> impl Iterator<Item = &mut RTCDataChannelInternal> {
        self.channels.values_mut()
    }

    /// Handles paired with their channels, for callers that need to name what they are
    /// iterating — the handle lives only in the key, so this is the only way to get both.
    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (RTCDataChannelId, &mut RTCDataChannelInternal)> {
        self.channels.iter_mut().map(|(handle, dc)| (*handle, dc))
    }
}
