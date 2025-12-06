//#[cfg(test)]
//mod data_channel_test;

use crate::message::{message_channel_ack::*, message_channel_open::*, *};
use bytes::{Buf, BytesMut};
use log::{debug, error};
use sctp::{PayloadProtocolIdentifier, ReliabilityType};
use shared::error::{Error, Result};
use shared::marshal::*;
use std::collections::VecDeque;

const RECEIVE_MTU: usize = 8192;

/// Config is used to configure the data channel.
#[derive(Eq, PartialEq, Default, Clone, Debug)]
pub struct Config {
    pub channel_type: ChannelType,
    pub negotiated: bool,
    pub priority: u16,
    pub reliability_parameter: u32,
    pub label: String,
    pub protocol: String,
    pub max_message_size: u32,
}

/// DataChannelMessage is used to data sent over SCTP
#[derive(Debug, Default, Clone)]
pub struct DataChannelMessage {
    pub association_handle: usize,
    pub stream_id: u16,
    pub ppi: PayloadProtocolIdentifier,
    pub unordered: bool,
    pub reliability_type: ReliabilityType,
    pub payload: BytesMut,
}

/// DataChannel represents a data channel
#[derive(Debug, Default, Clone)]
pub struct DataChannel {
    config: Config,
    association_handle: usize,
    stream_id: u16,
    messages: VecDeque<DataChannelMessage>,

    // stats
    messages_sent: usize,
    messages_received: usize,
    bytes_sent: usize,
    bytes_received: usize,
}

impl DataChannel {
    fn new(config: Config, association_handle: usize, stream_id: u16) -> Self {
        Self {
            config,
            association_handle,
            stream_id,
            messages: VecDeque::new(),
            ..Default::default()
        }
    }

    /// Dial opens a data channels over SCTP
    pub fn dial(config: Config, association_handle: usize, stream_id: u16) -> Result<Self> {
        let mut data_channel = DataChannel::new(config.clone(), association_handle, stream_id);

        if !config.negotiated {
            let msg = Message::DataChannelOpen(DataChannelOpen {
                channel_type: config.channel_type,
                priority: config.priority,
                reliability_parameter: config.reliability_parameter,
                label: config.label.bytes().collect(),
                protocol: config.protocol.bytes().collect(),
            })
            .marshal()?;

            let (unordered, reliability_type) = data_channel.get_reliability_params();

            data_channel.messages.push_back(DataChannelMessage {
                association_handle,
                stream_id,
                ppi: PayloadProtocolIdentifier::Dcep,
                unordered,
                reliability_type,
                payload: msg,
            });
        }

        Ok(data_channel)
    }

    /// Accept is used to accept incoming data channels over SCTP
    pub fn accept(
        mut config: Config,
        association_handle: usize,
        stream_id: u16,
        ppi: PayloadProtocolIdentifier,
        buf: &[u8],
    ) -> Result<Self> {
        if ppi != PayloadProtocolIdentifier::Dcep {
            return Err(Error::InvalidPayloadProtocolIdentifier(ppi as u8));
        }

        let mut read_buf = buf;
        let msg = Message::unmarshal(&mut read_buf)?;

        if let Message::DataChannelOpen(dco) = msg {
            config.channel_type = dco.channel_type;
            config.priority = dco.priority;
            config.reliability_parameter = dco.reliability_parameter;
            config.label = String::from_utf8(dco.label)?;
            config.protocol = String::from_utf8(dco.protocol)?;
        } else {
            return Err(Error::InvalidMessageType(msg.message_type() as u8));
        };

        let mut data_channel = DataChannel::new(config, association_handle, stream_id);

        data_channel.write_data_channel_ack()?;

        Ok(data_channel)
    }

    /// Returns packets to transmit
    pub fn poll_transmit(&mut self) -> Option<DataChannelMessage> {
        self.messages.pop_front()
    }

    /// Read reads a packet of len(p) bytes as binary data.
    pub fn read(&mut self, ppi: PayloadProtocolIdentifier, buf: &[u8]) -> Result<BytesMut> {
        self.read_data_channel(ppi, buf).map(|(b, _)| b)
    }

    /// ReadDataChannel reads a packet of len(p) bytes. It returns the number of bytes read and
    /// `true` if the data read is a string.
    pub fn read_data_channel(
        &mut self,
        ppi: PayloadProtocolIdentifier,
        buf: &[u8],
    ) -> Result<(BytesMut, bool)> {
        let mut is_string = false;
        match ppi {
            PayloadProtocolIdentifier::Dcep => {
                let mut data_buf = buf;
                match self.handle_dcep(&mut data_buf) {
                    Ok(()) => {}
                    Err(err) => {
                        error!("Failed to handle DCEP: {:?}", err);
                        return Err(err);
                    }
                }
            }
            PayloadProtocolIdentifier::String | PayloadProtocolIdentifier::StringEmpty => {
                is_string = true;
            }
            _ => {}
        };

        let data = match ppi {
            PayloadProtocolIdentifier::StringEmpty | PayloadProtocolIdentifier::BinaryEmpty => {
                BytesMut::new()
            }
            _ => BytesMut::from(buf),
        };

        self.messages_received += 1;
        self.bytes_received += 1;

        Ok((data, is_string))
    }

    /// MessagesSent returns the number of messages sent
    pub fn messages_sent(&self) -> usize {
        self.messages_sent
    }

    /// MessagesReceived returns the number of messages received
    pub fn messages_received(&self) -> usize {
        self.messages_received
    }

    /// BytesSent returns the number of bytes sent
    pub fn bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    /// BytesReceived returns the number of bytes received
    pub fn bytes_received(&self) -> usize {
        self.bytes_received
    }

    /// association_handle returns the association handle
    pub fn association_handle(&self) -> usize {
        self.association_handle
    }

    /// StreamIdentifier returns the Stream identifier associated to the stream.
    pub fn stream_identifier(&self) -> u16 {
        self.stream_id
    }

    fn handle_dcep<B>(&mut self, data: &mut B) -> Result<()>
    where
        B: Buf,
    {
        let msg = Message::unmarshal(data)?;

        match msg {
            Message::DataChannelOpen(_) => {
                // Note: DATA_CHANNEL_OPEN message is handled inside Server() method.
                // Therefore, the message will not reach here.
                debug!("Received DATA_CHANNEL_OPEN");
                self.write_data_channel_ack()?;
            }
            Message::DataChannelAck(_) => {
                debug!("Received DATA_CHANNEL_ACK");
                //self.commit_reliability_params();
            }
        };

        Ok(())
    }

    /// Write writes len(p) bytes from p as binary data
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.write_data_channel(data, false)
    }

    /// WriteDataChannel writes len(p) bytes from p
    pub fn write_data_channel(&mut self, data: &[u8], is_string: bool) -> Result<usize> {
        let data_len = data.len();

        // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-12#section-6.6
        // SCTP does not support the sending of empty user messages.  Therefore,
        // if an empty message has to be sent, the appropriate PPID (WebRTC
        // String Empty or WebRTC Binary Empty) is used and the SCTP user
        // message of one zero byte is sent.  When receiving an SCTP user
        // message with one of these PPIDs, the receiver MUST ignore the SCTP
        // user message and process it as an empty message.
        let ppi = match (is_string, data_len) {
            (false, 0) => PayloadProtocolIdentifier::BinaryEmpty,
            (false, _) => PayloadProtocolIdentifier::Binary,
            (true, 0) => PayloadProtocolIdentifier::StringEmpty,
            (true, _) => PayloadProtocolIdentifier::String,
        };

        let (unordered, reliability_type) = self.get_reliability_params();

        let n = if data_len == 0 {
            self.messages.push_back(DataChannelMessage {
                association_handle: self.association_handle,
                stream_id: self.stream_id,
                ppi,
                unordered,
                reliability_type,
                payload: BytesMut::from(&[0][..]),
            });

            0
        } else {
            self.messages.push_back(DataChannelMessage {
                association_handle: self.association_handle,
                stream_id: self.stream_id,
                ppi,
                unordered,
                reliability_type,
                payload: BytesMut::from(data),
            });

            self.bytes_sent += data.len();
            data.len()
        };

        self.messages_sent += 1;
        Ok(n)
    }

    fn write_data_channel_ack(&mut self) -> Result<()> {
        let ack = Message::DataChannelAck(DataChannelAck {}).marshal()?;
        let (unordered, reliability_type) = self.get_reliability_params();
        self.messages.push_back(DataChannelMessage {
            association_handle: self.association_handle,
            stream_id: self.stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            unordered,
            reliability_type,
            payload: ack,
        });
        Ok(())
    }
    /*
    /// Close closes the DataChannel and the underlying SCTP stream.
    pub async fn close(&self) -> Result<()> {
        // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.7
        // Closing of a data channel MUST be signaled by resetting the
        // corresponding outgoing streams [RFC6525].  This means that if one
        // side decides to close the data channel, it resets the corresponding
        // outgoing stream.  When the peer sees that an incoming stream was
        // reset, it also resets its corresponding outgoing stream.  Once this
        // is completed, the data channel is closed.  Resetting a stream sets
        // the Stream Sequence Numbers (SSNs) of the stream back to 'zero' with
        // a corresponding notification to the application layer that the reset
        // has been performed.  Streams are available for reuse after a reset
        // has been performed.
        Ok(self.stream.shutdown(Shutdown::Both).await?)
    }

    /// BufferedAmount returns the number of bytes of data currently queued to be
    /// sent over this stream.
    pub fn buffered_amount(&self) -> usize {
        self.stream.buffered_amount()
    }

    /// BufferedAmountLowThreshold returns the number of bytes of buffered outgoing
    /// data that is considered "low." Defaults to 0.
    pub fn buffered_amount_low_threshold(&self) -> usize {
        self.stream.buffered_amount_low_threshold()
    }

    /// SetBufferedAmountLowThreshold is used to update the threshold.
    /// See BufferedAmountLowThreshold().
    pub fn set_buffered_amount_low_threshold(&self, threshold: usize) {
        self.stream.set_buffered_amount_low_threshold(threshold)
    }

    /// OnBufferedAmountLow sets the callback handler which would be called when the
    /// number of bytes of outgoing data buffered is lower than the threshold.
    pub fn on_buffered_amount_low(&self, f: OnBufferedAmountLowFn) {
        self.stream.on_buffered_amount_low(f)
    }*/

    fn get_reliability_params(&self) -> (bool, ReliabilityType) {
        let (unordered, reliability_type) = match self.config.channel_type {
            ChannelType::Reliable => (false, ReliabilityType::Reliable),
            ChannelType::ReliableUnordered => (true, ReliabilityType::Reliable),
            ChannelType::PartialReliableRexmit => (false, ReliabilityType::Rexmit),
            ChannelType::PartialReliableRexmitUnordered => (true, ReliabilityType::Rexmit),
            ChannelType::PartialReliableTimed => (false, ReliabilityType::Timed),
            ChannelType::PartialReliableTimedUnordered => (true, ReliabilityType::Timed),
        };

        (unordered, reliability_type)
    }
}
