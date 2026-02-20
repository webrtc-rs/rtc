use bytes::Bytes;
use shared::error::Result;

use crate::chunk::Chunk;
use crate::chunk::ErrorCause;
use crate::chunk::chunk_abort::ChunkAbort;
use crate::chunk::chunk_cookie_ack::ChunkCookieAck;
use crate::chunk::chunk_cookie_echo::ChunkCookieEcho;
use crate::chunk::chunk_error::ChunkError;
use crate::chunk::chunk_forward_tsn::{ChunkForwardTsn, ChunkForwardTsnStream};
use crate::chunk::chunk_header::ChunkHeader;
use crate::chunk::chunk_heartbeat::ChunkHeartbeat;
use crate::chunk::chunk_heartbeat_ack::ChunkHeartbeatAck;
use crate::chunk::chunk_init::ChunkInit;
use crate::chunk::chunk_payload_data::ChunkPayloadData;
use crate::chunk::chunk_reconfig::ChunkReconfig;
use crate::chunk::chunk_selective_ack::ChunkSelectiveAck;
use crate::chunk::chunk_shutdown::ChunkShutdown;
use crate::chunk::chunk_shutdown_ack::ChunkShutdownAck;
use crate::chunk::chunk_shutdown_complete::ChunkShutdownComplete;
use crate::packet::{Packet, PartialDecode};
use crate::param::Param;
use crate::param::param_chunk_list::ParamChunkList;
use crate::param::param_forward_tsn_supported::ParamForwardTsnSupported;
use crate::param::param_header::ParamHeader;
use crate::param::param_heartbeat_info::ParamHeartbeatInfo;
use crate::param::param_outgoing_reset_request::ParamOutgoingResetRequest;
use crate::param::param_random::ParamRandom;
use crate::param::param_reconfig_response::ParamReconfigResponse;
use crate::param::param_requested_hmac_algorithm::ParamRequestedHmacAlgorithm;
use crate::param::param_state_cookie::ParamStateCookie;
use crate::param::param_supported_extensions::ParamSupportedExtensions;
use crate::param::param_uknown::ParamUnknown;

fn to_bytes(data: &[u8]) -> Bytes {
    Bytes::copy_from_slice(data)
}

pub fn packet_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = Packet::unmarshal(&raw)?;
    Ok(())
}

pub fn packet_partial_decode_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = PartialDecode::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_header_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkHeader::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_abort_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkAbort::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_cookie_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkCookieAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_cookie_echo_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkCookieEcho::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_error_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkError::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_forward_tsn_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkForwardTsn::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_forward_tsn_stream_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkForwardTsnStream::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_heartbeat_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkHeartbeat::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_heartbeat_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkHeartbeatAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_init_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkInit::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_payload_data_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkPayloadData::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_reconfig_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkReconfig::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_selective_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkSelectiveAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_shutdown_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkShutdown::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_shutdown_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkShutdownAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_shutdown_complete_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkShutdownComplete::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_error_cause_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ErrorCause::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_header_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamHeader::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_forward_tsn_supported_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamForwardTsnSupported::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_supported_extensions_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamSupportedExtensions::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_random_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamRandom::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_requested_hmac_algorithm_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamRequestedHmacAlgorithm::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_chunk_list_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamChunkList::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_state_cookie_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamStateCookie::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_heartbeat_info_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamHeartbeatInfo::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_outgoing_reset_request_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamOutgoingResetRequest::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_reconfig_response_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamReconfigResponse::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_unknown_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamUnknown::unmarshal(&raw)?;
    Ok(())
}
