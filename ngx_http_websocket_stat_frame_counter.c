#include "ngx_http_websocket_stat_frame_counter.h"
#include <assert.h>

const char *
frame_type_to_str(frame_type frame)
{
    switch (frame) {
    case CONTINUATION:
        return "cont";
    case TEXT:
        return "text";
    case BINARY:
        return "bin";
    case CLOSE:
        return "cls";
    case PING:
        return "ping";
    case PONG:
        return "pong";
    default:
        return "uknw";
    }
}

void
move_buffer(u_char **buffer, ssize_t *size, int step)
{
    *buffer += step;
    *size -= step;
}

char
frame_counter_process_message(u_char **buffer, ssize_t *size,
                              ngx_frame_counter_t *frame_counter)
{
    while (*size > 0) {
        switch (frame_counter->stage) {
        case HEADER:
            frame_counter->current_frame_type = **buffer & 0x0f;
            frame_counter->fragment_final = **buffer >> 7;

            if (frame_counter->current_frame_type != CONTINUATION) {
                frame_counter->current_message_size = 0;
            }

            move_buffer(buffer, size, 1);
            frame_counter->stage = PAYLOAD_LEN;
            frame_counter->bytes_consumed =
                frame_counter->current_payload_size = 0;
            break;
        case PAYLOAD_LEN:
            frame_counter->payload_masked = **buffer >> 7;
            u_char len = **buffer & 0x7f;
            move_buffer(buffer, size, 1);
            if (len < 126) {
                if (len == 0 && !frame_counter->payload_masked) {
                    frame_counter->stage = HEADER;
                    return 1;
                }
                frame_counter->current_payload_size = len;
                frame_counter->stage =
                    frame_counter->payload_masked ? MASK : PAYLOAD;
            } else if (len == 126) {
                frame_counter->stage = PAYLOAD_LEN_LARGE;
            } else if (len == 127) {
                frame_counter->stage = PAYLOAD_LEN_HUGE;
            } else {
                // WTF?
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "Wrong payload length");
                exit(-1);
            }
            break;
        case PAYLOAD_LEN_LARGE:
        case PAYLOAD_LEN_HUGE: {
            int i;
            if (frame_counter->stage == PAYLOAD_LEN_LARGE) {
                assert(*size >= 2);
                i = 2;
            } else {
                assert(*size >= 8);
                i = 8;
            }
            while (1) {
                frame_counter->current_payload_size |= **buffer;
                move_buffer(buffer, size, 1);
                if (--i)
                    frame_counter->current_payload_size <<= 8;
                else
                    break;
            }
            frame_counter->stage =
                frame_counter->payload_masked ? MASK : PAYLOAD;
            frame_counter->bytes_consumed = 0;
            break;
        }
        case MASK:
            assert(frame_counter->payload_masked);
            move_buffer(buffer, size, 1);
            frame_counter->bytes_consumed++;
            if (frame_counter->bytes_consumed == MASK_SIZE) {
                if (frame_counter->current_payload_size == 0) {
                    frame_counter->stage = HEADER;
                    return 1;
                }
                frame_counter->bytes_consumed = 0;
                frame_counter->stage = PAYLOAD;
            }
            break;
        case PAYLOAD:
            frame_counter->current_message_size += *size;
            if (*size >= (u_int)(frame_counter->current_payload_size -
                                 frame_counter->bytes_consumed)) {
                move_buffer(buffer, size,
                            frame_counter->current_payload_size -
                                frame_counter->bytes_consumed);
                frame_counter->stage = HEADER;
                return 1;
            } else {
                frame_counter->bytes_consumed += *size;
                if (frame_counter->bytes_consumed >
                    frame_counter->current_payload_size) {
                    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Unknown error");
                    frame_counter->stage = HEADER;
                }
                *buffer += *size;
                *size = 0;
            }
            break;
        default:
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Unknown stage");
            move_buffer(buffer, size, 1);
        }
    }
    return 0;
}
