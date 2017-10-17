#include "ngx_http_websocket_stat_frame_counter.h"
#include <assert.h>

const char * frame_type_to_str(frame_type frame)
{
   switch(frame)
   {
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
char  buff[200];

void frame_counter_process_data(u_char *buffer, size_t size, ngx_frame_counter_t *frame_counter)
{
  frame_counter->total_size += size;
  while(size > 0)
   {
     switch (frame_counter->stage)
     {
        case HEADER:
           frame_counter->current_frame_type = *(buffer)  & 0x0f;
           buffer++; 
           size--;
           frame_counter->stage = PAYLOAD_LEN;
           break;
        case PAYLOAD_LEN:
           frame_counter->payload_masked = *buffer >> 7;
           u_char len = *buffer & 0x7f;
           if (len < 126)
           {
              frame_counter->current_payload_size = len;
              frame_counter->stage = frame_counter->payload_masked ? MASK : PAYLOAD;
           }
           else if (len == 126)
           {
             //TODO: implement later
           }
           else if (len == 127)
           {
             //TODO: implement later
           }
           else
           {
               // WTF?
           }
           size--;
           buffer++;
           break;
        case EXT_PAYLOAD_LEN:
        case EXT_PAYLOAD_LEN2:
           // not implemented yet
           break;
        case MASK:
           assert(frame_counter->payload_masked);
           size -= MASK_SIZE;

           if (MASK_SIZE > size)
           {
              frame_counter->bytes_consumed+=size;
              size = 0;
           }
           else
           {
              buffer += MASK_SIZE;
              size -= MASK_SIZE;
           }
           break;
        case PAYLOAD:
           break;
        default: 
     
         ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      buff);
     }
  }
   
  sprintf (buff, "received frame of type %s, payload is %lu", 
                 frame_type_to_str(frame_counter->current_frame_type),
                 frame_counter->current_payload_size);
  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                buff);

   return;
}
