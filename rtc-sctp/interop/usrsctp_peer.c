/* Test-only AF_CONN peer for the pinned usrsctp build. No IP socket is opened. */
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "usrsctp.h"

#define PORT 5000
#define STREAMS 1024
#define MAX_PACKET_HEX (32U * 1024U * 1024U)

static struct socket *endpoint;
static struct socket *listener;
static bool initialized;
static bool passive;
static int address_token;
/* Nonzero epoch avoids the stack's zero-time sentinel. TICK is the only clock. */
static uint64_t now_ms = UINT64_C(1700000000000);

/* Injected into library translation units by build_usrsctp.py. */
int rtc_usrsctp_gettimeofday(struct timeval *tv, void *timezone_unused) {
    (void)timezone_unused;
    tv->tv_sec = (time_t)(now_ms / 1000);
    tv->tv_usec = (suseconds_t)((now_ms % 1000) * 1000);
    return 0;
}

struct partial_message {
    uint16_t sid;
    uint16_t ssn;
    uint32_t ppid;
    uint8_t *bytes;
    size_t length;
    struct partial_message *next;
};
static struct partial_message *partials;

static void hex_print(const void *buffer, size_t length) {
    const uint8_t *bytes = buffer;
    if (!length) {
        putchar('-');
    }
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", bytes[i]);
    }
}

static int output_packet(void *addr, void *buffer, size_t length,
                         uint8_t tos, uint8_t set_df) {
    (void)addr;
    (void)tos;
    (void)set_df;
    fputs("PACKET ", stdout);
    hex_print(buffer, length);
    putchar('\n');
    return 0;
}

static void discard_partial(uint16_t sid) {
    struct partial_message **slot = &partials;
    while (*slot) {
        struct partial_message *p = *slot;
        if (p->sid == sid) {
            *slot = p->next;
            free(p->bytes);
            free(p);
        } else {
            slot = &p->next;
        }
    }
}

static void notification(const union sctp_notification *note, size_t length) {
    if (length < sizeof(note->sn_header) || note->sn_header.sn_length != length) {
        puts("EVENT error:invalid_notification");
        return;
    }
    switch (note->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE:
        if (note->sn_assoc_change.sac_state == SCTP_COMM_UP) {
            puts("EVENT ready");
        } else if (note->sn_assoc_change.sac_state == SCTP_SHUTDOWN_COMP) {
            puts("EVENT closed");
        } else if (note->sn_assoc_change.sac_state == SCTP_COMM_LOST ||
                   note->sn_assoc_change.sac_state == SCTP_CANT_STR_ASSOC) {
            printf("EVENT error:association:%u\n", note->sn_assoc_change.sac_error);
            puts("EVENT closed");
        }
        break;
    case SCTP_STREAM_RESET_EVENT: {
        const struct sctp_stream_reset_event *e = &note->sn_strreset_event;
        if (length < sizeof(*e)) {
            puts("EVENT error:invalid_reset_notification");
            break;
        }
        if (e->strreset_flags & (SCTP_STREAM_RESET_DENIED | SCTP_STREAM_RESET_FAILED)) {
            printf("EVENT error:reset:%u\n", e->strreset_flags);
            break;
        }
        size_t count = (length - sizeof(*e)) / sizeof(uint16_t);
        for (size_t i = 0; i < count; ++i) {
            uint16_t sid = e->strreset_stream_list[i];
            if (e->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
                discard_partial(sid);
                printf("EVENT reset_in:%u\n", sid);
            }
            if (e->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
                printf("EVENT reset_out:%u\n", sid);
            }
        }
        break;
    }
    case SCTP_PARTIAL_DELIVERY_EVENT:
        if (note->sn_pdapi_event.pdapi_indication == SCTP_PARTIAL_DELIVERY_ABORTED) {
            discard_partial((uint16_t)note->sn_pdapi_event.pdapi_stream);
        }
        break;
    case SCTP_SEND_FAILED_EVENT:
        printf("EVENT send_failed:%u:%u\n", note->sn_send_failed_event.ssfe_info.snd_sid,
               note->sn_send_failed_event.ssfe_error);
        break;
    default:
        break;
    }
}

static int receive_data(struct socket *sock, union sctp_sockstore addr, void *data,
                        size_t length, struct sctp_rcvinfo info, int flags,
                        void *ulp_info) {
    (void)sock;
    (void)addr;
    (void)ulp_info;
    if (!data) {
        puts("EVENT closed");
        return 1;
    }
    if (flags & MSG_NOTIFICATION) {
        notification(data, length);
    } else {
        /* Default fragment-interleave=0 keeps a partial delivery contiguous.
         * Still retain the message identity so no partial callback is exposed as
         * a complete application message. */
        struct partial_message **slot = &partials;
        while (*slot && ((*slot)->sid != info.rcv_sid || (*slot)->ssn != info.rcv_ssn)) {
            slot = &(*slot)->next;
        }
        if (!*slot) {
            *slot = calloc(1, sizeof(**slot));
            if (!*slot) {
                fputs("out of memory\n", stderr);
                exit(2);
            }
            (*slot)->sid = info.rcv_sid;
            (*slot)->ssn = info.rcv_ssn;
            (*slot)->ppid = ntohl(info.rcv_ppid);
        }
        struct partial_message *p = *slot;
        uint8_t *bytes = realloc(p->bytes, p->length + length);
        if (!bytes && length) {
            fputs("out of memory\n", stderr);
            exit(2);
        }
        p->bytes = bytes;
        if (length) {
            memcpy(bytes + p->length, data, length);
        }
        p->length += length;
        if (flags & MSG_EOR) {
            printf("MESSAGE %u %" PRIu32 " ", p->sid, p->ppid);
            hex_print(p->bytes, p->length);
            putchar('\n');
            *slot = p->next;
            free(p->bytes);
            free(p);
        }
    }
    free(data);
    return 1;
}

static int set_option(struct socket *sock, int level, int name,
                      const void *value, socklen_t length) {
    if (usrsctp_setsockopt(sock, level, name, value, length) < 0) {
        printf("ERROR setsockopt:%d:%s\n", name, strerror(errno));
        return -1;
    }
    return 0;
}

static struct sockaddr_conn conn_address(void) {
    struct sockaddr_conn addr;
    memset(&addr, 0, sizeof(addr));
    addr.sconn_family = AF_CONN;
#ifdef __APPLE__
    addr.sconn_len = sizeof(addr);
#endif
    addr.sconn_port = htons(PORT);
    addr.sconn_addr = &address_token;
    return addr;
}

static int init_peer(const char *role) {
    if (initialized || !role || (strcmp(role, "client") && strcmp(role, "server"))) {
        puts("ERROR expected_one_INIT_client_or_server");
        return -1;
    }
    passive = !strcmp(role, "server");
    usrsctp_init_nothreads(0, output_packet, NULL);
    initialized = true;
    usrsctp_sysctl_set_sctp_ecn_enable(0);
    usrsctp_sysctl_set_sctp_pr_enable(1);
    usrsctp_sysctl_set_sctp_reconfig_enable(1);
    usrsctp_register_address(&address_token);
    endpoint = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
                              receive_data, NULL, 0, &address_token);
    if (!endpoint) {
        printf("ERROR socket:%s\n", strerror(errno));
        return -1;
    }
    usrsctp_set_non_blocking(endpoint, 1);
    const int on = 1;
    const int buffer_size = 4 * 1024 * 1024;
    struct sctp_initmsg init = {STREAMS, STREAMS, 8, 0};
    struct sctp_assoc_value reset = {SCTP_ALL_ASSOC, SCTP_ENABLE_RESET_STREAM_REQ};
    struct sctp_paddrparams path;
    memset(&path, 0, sizeof(path));
    path.spp_address.ss_family = AF_CONN;
#ifdef __APPLE__
    path.spp_address.ss_len = sizeof(struct sockaddr_conn);
#endif
    path.spp_flags = SPP_PMTUD_DISABLE | SPP_HB_DISABLE;
    path.spp_pathmtu = 1200;
    if (set_option(endpoint, IPPROTO_SCTP, SCTP_NODELAY, &on, sizeof(on)) ||
        set_option(endpoint, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) ||
        set_option(endpoint, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) ||
        set_option(endpoint, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init)) ||
        set_option(endpoint, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &reset, sizeof(reset)) ||
        set_option(endpoint, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &path, sizeof(path))) {
        return -1;
    }
    uint16_t types[] = {SCTP_ASSOC_CHANGE, SCTP_STREAM_RESET_EVENT,
                        SCTP_PARTIAL_DELIVERY_EVENT, SCTP_SEND_FAILED_EVENT};
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        struct sctp_event event = {SCTP_ALL_ASSOC, types[i], 1};
        if (set_option(endpoint, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event))) {
            return -1;
        }
    }
    struct sockaddr_conn addr = conn_address();
    if (usrsctp_bind(endpoint, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("ERROR bind:%s\n", strerror(errno));
        return -1;
    }
    if (passive) {
        if (usrsctp_listen(endpoint, 1) < 0) {
            printf("ERROR listen:%s\n", strerror(errno));
            return -1;
        }
        listener = endpoint;
        endpoint = NULL;
    }
    return 0;
}

static void accept_peer(void) {
    if (listener && !endpoint) {
        endpoint = usrsctp_accept(listener, NULL, NULL);
        if (endpoint) {
            usrsctp_set_non_blocking(endpoint, 1);
            usrsctp_close(listener);
            listener = NULL;
        } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
            printf("ERROR accept:%s\n", strerror(errno));
        }
    }
}

static bool number(const char *text, uint32_t maximum, uint32_t *out) {
    if (!text || !*text || *text == '-') {
        return false;
    }
    char *end;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || *end || value > maximum) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t *unhex(const char *text, size_t *length) {
    if (!text) return NULL;
    size_t count = strcmp(text, "-") ? strlen(text) : 0;
    if (count > MAX_PACKET_HEX || count % 2) return NULL;
    uint8_t *bytes = malloc(count / 2 + 1);
    if (!bytes) return NULL;
    for (size_t i = 0; i < count; i += 2) {
        int a = nibble(text[i]), b = nibble(text[i + 1]);
        if (a < 0 || b < 0) {
            free(bytes);
            return NULL;
        }
        bytes[i / 2] = (uint8_t)((a << 4) | b);
    }
    *length = count / 2;
    return bytes;
}

static void send_message(char **args, size_t count) {
    uint32_t sid, ppid;
    if (count != 5 || !number(args[0], UINT16_MAX, &sid) ||
        !number(args[3], UINT32_MAX, &ppid) ||
        (strcmp(args[1], "ordered") && strcmp(args[1], "unordered"))) {
        puts("ERROR expected_SEND_sid_order_policy_ppid_hex");
        return;
    }
    struct sctp_sendv_spa spa;
    memset(&spa, 0, sizeof(spa));
    spa.sendv_flags = SCTP_SEND_SNDINFO_VALID | SCTP_SEND_PRINFO_VALID;
    spa.sendv_sndinfo.snd_sid = (uint16_t)sid;
    spa.sendv_sndinfo.snd_ppid = htonl(ppid);
    if (!strcmp(args[1], "unordered")) spa.sendv_sndinfo.snd_flags = SCTP_UNORDERED;
    if (!strcmp(args[2], "reliable")) {
        spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_NONE;
    } else {
        uint32_t value;
        const char *colon = strchr(args[2], ':');
        if (!colon || !number(colon + 1, UINT32_MAX, &value)) {
            puts("ERROR invalid_reliability_policy");
            return;
        }
        if (!strncmp(args[2], "timed:", 6)) {
            spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
        } else if (!strncmp(args[2], "rexmit:", 7)) {
            spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
        } else {
            puts("ERROR invalid_reliability_policy");
            return;
        }
        spa.sendv_prinfo.pr_value = value;
    }
    size_t length;
    uint8_t *data = unhex(args[4], &length);
    if (!data) {
        puts("ERROR invalid_hex");
        return;
    }
    ssize_t sent = usrsctp_sendv(endpoint, data, length, NULL, 0, &spa,
                                sizeof(spa), SCTP_SENDV_SPA, 0);
    if (sent < 0) printf("ERROR send:%s\n", strerror(errno));
    else if ((size_t)sent != length) puts("ERROR partial_send");
    free(data);
}

static void reset_streams(char *text) {
    size_t count = 1;
    for (const char *p = text; *p; ++p) if (*p == ',') ++count;
    if (count > STREAMS) {
        puts("ERROR too_many_streams");
        return;
    }
    size_t length = sizeof(struct sctp_reset_streams) + count * sizeof(uint16_t);
    struct sctp_reset_streams *reset = calloc(1, length);
    if (!reset) exit(2);
    reset->srs_flags = SCTP_STREAM_RESET_OUTGOING;
    reset->srs_number_streams = (uint16_t)count;
    char *state;
    char *sid_text = strtok_r(text, ",", &state);
    size_t i = 0;
    while (sid_text) {
        uint32_t sid;
        if (!number(sid_text, UINT16_MAX, &sid)) break;
        reset->srs_stream_list[i++] = (uint16_t)sid;
        sid_text = strtok_r(NULL, ",", &state);
    }
    if (i != count) puts("ERROR invalid_reset_streams");
    else set_option(endpoint, IPPROTO_SCTP, SCTP_RESET_STREAMS, reset, (socklen_t)length);
    free(reset);
}

static void cleanup(void) {
    if (endpoint) usrsctp_close(endpoint);
    if (listener) usrsctp_close(listener);
    endpoint = NULL;
    listener = NULL;
    if (initialized) {
        usrsctp_deregister_address(&address_token);
        /* No peer is expected to answer after QUIT. Drain the bounded closing
         * timers, then release the process even if graceful shutdown is pending. */
        for (int i = 0; i < 20 && usrsctp_finish() != 0; ++i) {
            now_ms += 1000;
            usrsctp_handle_timers(1000);
        }
        initialized = false;
    }
    while (partials) discard_partial(partials->sid);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    char *line = NULL;
    size_t capacity = 0;
    bool quit = false;
    while (!quit && getline(&line, &capacity, stdin) >= 0) {
        char *tokens[8];
        size_t count = 0;
        char *state;
        char *token = strtok_r(line, " \t\r\n", &state);
        while (token && count < sizeof(tokens) / sizeof(tokens[0])) {
            tokens[count++] = token;
            token = strtok_r(NULL, " \t\r\n", &state);
        }
        if (!count) {
            puts("ERROR empty_command");
        } else if (!strcmp(tokens[0], "QUIT") && count == 1) {
            cleanup();
            quit = true;
        } else if (!strcmp(tokens[0], "INIT") && count == 2) {
            init_peer(tokens[1]);
        } else if (!initialized) {
            puts("ERROR INIT_required");
        } else if (!strcmp(tokens[0], "CONNECT") && count == 1) {
            if (passive) {
                puts("ERROR server_is_passive");
            } else {
                struct sockaddr_conn addr = conn_address();
                if (usrsctp_connect(endpoint, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
                    errno != EINPROGRESS) printf("ERROR connect:%s\n", strerror(errno));
            }
        } else if (!strcmp(tokens[0], "INPUT") && count == 2) {
            size_t length;
            uint8_t *packet = unhex(tokens[1], &length);
            if (!packet || length < 12) puts("ERROR invalid_packet_hex");
            else usrsctp_conninput(&address_token, packet, length, 0);
            free(packet);
            accept_peer();
        } else if (!strcmp(tokens[0], "TICK") && count == 2) {
            uint32_t elapsed;
            if (!number(tokens[1], 3600000, &elapsed)) puts("ERROR invalid_elapsed_ms");
            else {
                /* Stepping callouts together with wall-clock time preserves the
                 * interval scheduled by a callback during a larger TICK. */
                while (elapsed) {
                    uint32_t step = elapsed > 10 ? 10 : elapsed;
                    now_ms += step;
                    usrsctp_handle_timers(step);
                    elapsed -= step;
                }
                accept_peer();
            }
        } else if (!strcmp(tokens[0], "POLL") && count == 1) {
            accept_peer();
        } else if (!endpoint) {
            puts("ERROR association_not_ready");
        } else if (!strcmp(tokens[0], "SEND")) {
            send_message(tokens + 1, count - 1);
        } else if (!strcmp(tokens[0], "RESET") && count == 2) {
            reset_streams(tokens[1]);
        } else {
            puts("ERROR unknown_command");
        }
        puts("DONE");
    }
    free(line);
    cleanup();
    return 0;
}
