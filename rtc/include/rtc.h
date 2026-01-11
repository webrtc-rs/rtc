// Copyright (C) 2025, RTC Contributors
// All rights reserved.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#ifndef RTC_H
#define RTC_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#endif

#ifdef __unix__
#include <sys/types.h>
#endif
#ifdef _MSC_VER
#include <BaseTsd.h>
#define ssize_t SSIZE_T
#endif

#if defined(__cplusplus)
extern "C" {
#endif

// ============================================================================
// Version and Logging
// ============================================================================

/// Returns a human-readable string with the RTC library version.
const char *rtc_version(void);

/// Enables debug logging. The callback will be called with log messages.
///
/// # Parameters
/// * `cb` - Callback function that receives log messages
/// * `argp` - User-defined pointer passed to the callback
///
/// # Returns
/// * 0 on success
/// * -1 on error
int rtc_enable_debug_logging(void (*cb)(const char *line, void *argp), void *argp);

// ============================================================================
// Error Codes
// ============================================================================

enum rtc_error {
    RTC_ERR_DONE = -1,
    RTC_ERR_BUFFER_TOO_SHORT = -2,
    RTC_ERR_INVALID_STATE = -3,
    RTC_ERR_INVALID_PARAMETER = -4,
    RTC_ERR_INVALID_SDP = -5,
    RTC_ERR_INVALID_CANDIDATE = -6,
    RTC_ERR_CRYPTO_FAIL = -7,
    RTC_ERR_DTLS_FAIL = -8,
    RTC_ERR_ICE_FAIL = -9,
    RTC_ERR_SCTP_FAIL = -10,
    RTC_ERR_DATA_CHANNEL_NOT_FOUND = -11,
    RTC_ERR_TRACK_NOT_FOUND = -12,
    RTC_ERR_SENDER_NOT_FOUND = -13,
    RTC_ERR_RECEIVER_NOT_FOUND = -14,
    RTC_ERR_TIMEOUT = -15,
};

// ============================================================================
// Opaque Types
// ============================================================================

/// Opaque type representing the peer connection configuration.
typedef struct rtc_configuration rtc_configuration;

/// Opaque type representing a WebRTC peer connection.
typedef struct rtc_peer_connection rtc_peer_connection;

/// Opaque type representing a data channel.
typedef struct rtc_data_channel rtc_data_channel;

/// Opaque type representing an RTP sender.
typedef struct rtc_rtp_sender rtc_rtp_sender;

/// Opaque type representing an RTP receiver.
typedef struct rtc_rtp_receiver rtc_rtp_receiver;

/// Opaque type representing a media stream track.
typedef struct rtc_media_stream_track rtc_media_stream_track;

/// Opaque type representing an interceptor registry.
/// 
/// This is a type-erased container that hides the generic parameter of Registry<P>.
/// The C API uses a concrete interceptor chain built at runtime.
typedef struct rtc_interceptor_registry rtc_interceptor_registry;

// ============================================================================
// Configuration
// ============================================================================

/// Creates a new peer connection configuration with default settings.
///
/// # Returns
/// * Pointer to configuration on success
/// * NULL on failure
rtc_configuration *rtc_configuration_new(void);

/// Adds an ICE server to the configuration.
///
/// # Parameters
/// * `config` - Configuration object
/// * `urls` - Null-terminated string with ICE server URL (e.g., "stun:stun.l.google.com:19302")
/// * `username` - Optional username (can be NULL)
/// * `credential` - Optional credential (can be NULL)
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_configuration_add_ice_server(
    rtc_configuration *config,
    const char *urls,
    const char *username,
    const char *credential
);

/// Sets the interceptor registry for the configuration.
///
/// The configuration takes ownership of the registry. After calling this function,
/// the registry pointer should not be used or freed separately.
///
/// # Parameters
/// * `config` - Configuration object
/// * `registry` - Interceptor registry (ownership transferred)
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_configuration_set_interceptor_registry(
    rtc_configuration *config,
    rtc_interceptor_registry *registry
);

/// Frees a configuration object.
void rtc_configuration_free(rtc_configuration *config);

// ============================================================================
// Interceptor Registry
// ============================================================================

/// Creates a new empty interceptor registry.
///
/// # Returns
/// * Pointer to registry on success
/// * NULL on failure
rtc_interceptor_registry *rtc_interceptor_registry_new(void);

/// Adds NACK (Negative Acknowledgment) interceptor for packet loss recovery.
///
/// # Parameters
/// * `registry` - Registry object
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_interceptor_registry_add_nack(rtc_interceptor_registry *registry);

/// Adds RTCP Report interceptors (Sender Reports and Receiver Reports).
///
/// # Parameters
/// * `registry` - Registry object
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_interceptor_registry_add_rtcp_reports(rtc_interceptor_registry *registry);

/// Adds TWCC (Transport-Wide Congestion Control) interceptor.
///
/// # Parameters
/// * `registry` - Registry object
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_interceptor_registry_add_twcc(rtc_interceptor_registry *registry);

/// Adds all default interceptors (NACK, RTCP Reports, TWCC).
///
/// # Parameters
/// * `registry` - Registry object
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_interceptor_registry_add_defaults(rtc_interceptor_registry *registry);

/// Frees an interceptor registry.
void rtc_interceptor_registry_free(rtc_interceptor_registry *registry);

// ============================================================================
// Peer Connection
// ============================================================================

/// Creates a new peer connection.
///
/// # Parameters
/// * `config` - Configuration object (borrowed, not consumed)
///
/// # Returns
/// * Pointer to peer connection on success
/// * NULL on failure
rtc_peer_connection *rtc_peer_connection_new(const rtc_configuration *config);

/// Creates an SDP offer.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `out` - Buffer to store the offer SDP string
/// * `out_len` - Pointer to buffer size (input: buffer capacity, output: actual length)
///
/// # Returns
/// * 0 on success
/// * RTC_ERR_BUFFER_TOO_SHORT if buffer is too small (out_len will contain required size)
/// * Other negative error code on failure
int rtc_peer_connection_create_offer(
    rtc_peer_connection *pc,
    uint8_t *out,
    size_t *out_len
);

/// Creates an SDP answer.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `out` - Buffer to store the answer SDP string
/// * `out_len` - Pointer to buffer size (input: buffer capacity, output: actual length)
///
/// # Returns
/// * 0 on success
/// * RTC_ERR_BUFFER_TOO_SHORT if buffer is too small (out_len will contain required size)
/// * Other negative error code on failure
int rtc_peer_connection_create_answer(
    rtc_peer_connection *pc,
    uint8_t *out,
    size_t *out_len
);

/// Sets the local description (offer or answer).
///
/// # Parameters
/// * `pc` - Peer connection
/// * `sdp_type` - Type of SDP ("offer" or "answer")
/// * `sdp` - Null-terminated SDP string
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_peer_connection_set_local_description(
    rtc_peer_connection *pc,
    const char *sdp_type,
    const char *sdp
);

/// Sets the remote description (offer or answer).
///
/// # Parameters
/// * `pc` - Peer connection
/// * `sdp_type` - Type of SDP ("offer" or "answer")
/// * `sdp` - Null-terminated SDP string
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_peer_connection_set_remote_description(
    rtc_peer_connection *pc,
    const char *sdp_type,
    const char *sdp
);

/// Adds a local ICE candidate.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `candidate_json` - Null-terminated JSON string representing the candidate
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_peer_connection_add_local_candidate(
    rtc_peer_connection *pc,
    const char *candidate_json
);

/// Adds a remote ICE candidate.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `candidate_json` - Null-terminated JSON string representing the candidate
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_peer_connection_add_remote_candidate(
    rtc_peer_connection *pc,
    const char *candidate_json
);

// ============================================================================
// Sans-I/O Event Loop API
// ============================================================================

/// Network message for reading/writing.
typedef struct {
    uint8_t *data;
    size_t len;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    uint64_t timestamp_us; // Microseconds since epoch
} rtc_network_message;

/// Polls for outgoing network packets.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `msg` - Message structure to fill
///
/// # Returns
/// * 1 if a message was retrieved
/// * 0 if no more messages
/// * Negative error code on failure
int rtc_peer_connection_poll_write(
    rtc_peer_connection *pc,
    rtc_network_message *msg
);

/// Handles incoming network packet.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `msg` - Incoming network message
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_peer_connection_handle_read(
    rtc_peer_connection *pc,
    const rtc_network_message *msg
);

/// Gets the next timeout deadline.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `timeout_us` - Pointer to store timeout in microseconds from now
///
/// # Returns
/// * 1 if timeout is set
/// * 0 if no timeout is needed
/// * Negative error code on failure
int rtc_peer_connection_poll_timeout(
    rtc_peer_connection *pc,
    uint64_t *timeout_us
);

/// Handles timeout expiration.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `timestamp_us` - Current timestamp in microseconds since epoch
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_peer_connection_handle_timeout(
    rtc_peer_connection *pc,
    uint64_t timestamp_us
);

// ============================================================================
// Event Polling
// ============================================================================

/// Event types.
enum rtc_event_type {
    RTC_EVENT_NONE = 0,
    RTC_EVENT_ICE_CONNECTION_STATE_CHANGE,
    RTC_EVENT_CONNECTION_STATE_CHANGE,
    RTC_EVENT_SIGNALING_STATE_CHANGE,
    RTC_EVENT_ICE_GATHERING_STATE_CHANGE,
    RTC_EVENT_DATA_CHANNEL,
    RTC_EVENT_TRACK,
};

/// Connection states.
enum rtc_ice_connection_state {
    RTC_ICE_CONNECTION_STATE_NEW = 0,
    RTC_ICE_CONNECTION_STATE_CHECKING,
    RTC_ICE_CONNECTION_STATE_CONNECTED,
    RTC_ICE_CONNECTION_STATE_COMPLETED,
    RTC_ICE_CONNECTION_STATE_FAILED,
    RTC_ICE_CONNECTION_STATE_DISCONNECTED,
    RTC_ICE_CONNECTION_STATE_CLOSED,
};

enum rtc_peer_connection_state {
    RTC_PEER_CONNECTION_STATE_NEW = 0,
    RTC_PEER_CONNECTION_STATE_CONNECTING,
    RTC_PEER_CONNECTION_STATE_CONNECTED,
    RTC_PEER_CONNECTION_STATE_DISCONNECTED,
    RTC_PEER_CONNECTION_STATE_FAILED,
    RTC_PEER_CONNECTION_STATE_CLOSED,
};

/// Event structure.
typedef struct {
    enum rtc_event_type type;
    union {
        enum rtc_ice_connection_state ice_connection_state;
        enum rtc_peer_connection_state connection_state;
        struct {
            uint16_t channel_id;
            char label[256];
        } data_channel;
        struct {
            char track_id[256];
            uint64_t receiver_id;
        } track;
    } data;
} rtc_event;

/// Polls for connection events.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `event` - Event structure to fill
///
/// # Returns
/// * 1 if an event was retrieved
/// * 0 if no more events
/// * Negative error code on failure
int rtc_peer_connection_poll_event(
    rtc_peer_connection *pc,
    rtc_event *event
);

// ============================================================================
// Application Message Polling
// ============================================================================

/// Message types.
enum rtc_message_type {
    RTC_MESSAGE_NONE = 0,
    RTC_MESSAGE_RTP_PACKET,
    RTC_MESSAGE_RTCP_PACKET,
    RTC_MESSAGE_DATA_CHANNEL,
};

/// Application message structure.
typedef struct {
    enum rtc_message_type type;
    union {
        struct {
            char track_id[256];
            uint8_t *payload;
            size_t payload_len;
            uint32_t ssrc;
            uint16_t sequence_number;
            uint32_t timestamp;
        } rtp;
        struct {
            uint64_t receiver_id;
            uint8_t *data;
            size_t data_len;
        } rtcp;
        struct {
            uint16_t channel_id;
            uint8_t *data;
            size_t data_len;
            bool is_string;
        } data_channel;
    } data;
} rtc_message;

/// Polls for incoming application messages.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `msg` - Message structure to fill
///
/// # Returns
/// * 1 if a message was retrieved
/// * 0 if no more messages
/// * Negative error code on failure
int rtc_peer_connection_poll_read(
    rtc_peer_connection *pc,
    rtc_message *msg
);

// ============================================================================
// Data Channel API
// ============================================================================

/// Data channel configuration.
typedef struct {
    bool ordered;
    int max_retransmits; // -1 for unlimited
    bool negotiated;
    uint16_t id; // Only used if negotiated is true
} rtc_data_channel_init;

/// Creates a data channel.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `label` - Null-terminated label string
/// * `init` - Optional initialization parameters (can be NULL for defaults)
/// * `out_channel_id` - Pointer to store the created channel ID
///
/// # Returns
/// * 0 on success (out_channel_id will be set)
/// * Negative error code on failure
int rtc_peer_connection_create_data_channel(
    rtc_peer_connection *pc,
    const char *label,
    const rtc_data_channel_init *init,
    uint16_t *out_channel_id
);

/// Sends data on a data channel.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `channel_id` - Data channel ID
/// * `data` - Data buffer
/// * `len` - Data length
/// * `is_string` - true for text messages, false for binary
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_data_channel_send(
    rtc_peer_connection *pc,
    uint16_t channel_id,
    const uint8_t *data,
    size_t len,
    bool is_string
);

/// Gets the label of a data channel.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `channel_id` - Data channel ID
/// * `out` - Buffer to store label
/// * `out_len` - Pointer to buffer size (input: capacity, output: actual length)
///
/// # Returns
/// * 0 on success
/// * RTC_ERR_BUFFER_TOO_SHORT if buffer is too small
/// * RTC_ERR_DATA_CHANNEL_NOT_FOUND if channel doesn't exist
int rtc_data_channel_label(
    rtc_peer_connection *pc,
    uint16_t channel_id,
    uint8_t *out,
    size_t *out_len
);

// ============================================================================
// RTP Sender/Receiver API
// ============================================================================

/// Adds a media track to the peer connection.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `track` - Media stream track (ownership transferred)
/// * `out_sender_id` - Pointer to store the sender ID
///
/// # Returns
/// * 0 on success (out_sender_id will be set)
/// * Negative error code on failure
int rtc_peer_connection_add_track(
    rtc_peer_connection *pc,
    rtc_media_stream_track *track,
    uint64_t *out_sender_id
);

/// Sends an RTP packet.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `sender_id` - RTP sender ID
/// * `packet` - RTP packet data
/// * `packet_len` - Packet length
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_rtp_sender_write_rtp(
    rtc_peer_connection *pc,
    uint64_t sender_id,
    const uint8_t *packet,
    size_t packet_len
);

/// Sends RTCP packets.
///
/// # Parameters
/// * `pc` - Peer connection
/// * `receiver_id` - RTP receiver ID
/// * `packets` - RTCP packet data
/// * `packets_len` - Total length
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_rtp_receiver_write_rtcp(
    rtc_peer_connection *pc,
    uint64_t receiver_id,
    const uint8_t *packets,
    size_t packets_len
);

// ============================================================================
// Cleanup
// ============================================================================

/// Closes the peer connection.
///
/// # Parameters
/// * `pc` - Peer connection
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
int rtc_peer_connection_close(rtc_peer_connection *pc);

/// Frees a peer connection.
void rtc_peer_connection_free(rtc_peer_connection *pc);

#if defined(__cplusplus)
}
#endif

#endif // RTC_H
