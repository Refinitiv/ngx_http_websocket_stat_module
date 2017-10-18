#include "ngx_http_websocket_stat_frame_counter.h"
#include <assert.h>

const char *frame_type_to_str(frame_type frame) {
  switch (frame) {
  case CONTINUATION:
    return "continuation";
  case TEXT:
    return "text";
  case BINARY:
    return "binary";
  case CLOSE:
    return "close";
  case PING:
    return "ping";
  case PONG:
    return "pong";
  default:
    return "unknown";
  }
}
char buff[200];

void move_buffer(u_char **buffer, size_t *size, int step) {
  *buffer += step;
  *size -= step;
}

char parse_message(u_char **buffer, size_t *size,
                   ngx_frame_counter_t *frame_counter) {
  while (*size > 0) {
    switch (frame_counter->stage) {
    case HEADER:
      frame_counter->current_frame_type = **buffer & 0x0f;
      move_buffer(buffer, size, 1);
      frame_counter->stage = PAYLOAD_LEN;
      frame_counter->bytes_consumed = frame_counter->current_payload_size = 0;
      break;
    case PAYLOAD_LEN:
      frame_counter->payload_masked = **buffer >> 7;
      u_char len = **buffer & 0x7f;
      if (len < 126) {
        frame_counter->current_payload_size = len;
        frame_counter->stage = frame_counter->payload_masked ? MASK : PAYLOAD;
      } else if (len == 126) {
        frame_counter->stage = PAYLOAD_LEN_LARGE;
      } else if (len == 127) {
        frame_counter->stage = PAYLOAD_LEN_HUGE;
      } else {
        // WTF?
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Wrong payload length");
      }
      move_buffer(buffer, size, 1);
      break;
    case PAYLOAD_LEN_LARGE:
    case PAYLOAD_LEN_HUGE: {
      int i;
      if (frame_counter->stage == PAYLOAD_LEN_LARGE) {
        assert(*size >= 2);
        i = 2;
      } else {
        assert(*size >= 4);
        i = 4;
      }
      while (1) {
        frame_counter->current_payload_size |= **buffer;
        move_buffer(buffer, size, 1);
        if (--i)
          frame_counter->current_payload_size <<= 8;
        else
          break;
      }
      frame_counter->stage = frame_counter->payload_masked ? MASK : PAYLOAD;
      frame_counter->bytes_consumed = 0;
      break;
    }
    case MASK:
      assert(frame_counter->payload_masked);
      frame_counter->bytes_consumed++;
      move_buffer(buffer, size, 1);
      if (frame_counter->bytes_consumed == MASK_SIZE) {
        frame_counter->bytes_consumed = 0;
        frame_counter->stage = PAYLOAD;
      }
      break;
    case PAYLOAD:
      if (*size >= (u_int)(frame_counter->current_payload_size -
                           frame_counter->bytes_consumed)) {

        move_buffer(buffer, size, frame_counter->current_payload_size -
                                      frame_counter->bytes_consumed);
        frame_counter->stage = HEADER;
        return 1;
      } else {
        frame_counter->bytes_consumed += *size;
        if (frame_counter->bytes_consumed > frame_counter->total_payload_size) {
          ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "WTF?");
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

void frame_counter_process_data(u_char *buffer, size_t size,
                                ngx_frame_counter_t *frame_counter) {
  frame_counter->total_size += size;
  while (size) {
    if (parse_message(&buffer, &size, frame_counter)) {
      frame_counter->frames++;
      frame_counter->total_payload_size += frame_counter->current_payload_size;
      sprintf(buff, "received frame of type %s, payload is %lu",
              frame_type_to_str(frame_counter->current_frame_type),
              frame_counter->current_payload_size);
      ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, buff);
      sprintf(buff, "total size is %lu, total payload size is %lu",
              frame_counter->total_size, frame_counter->total_payload_size);
      ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, buff);
    }
  }
}
