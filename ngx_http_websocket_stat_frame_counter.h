#include <ngx_core.h>

static const unsigned int MASK_SIZE=4;

typedef enum {
   HEADER,
   PAYLOAD_LEN,
   EXT_PAYLOAD_LEN,
   EXT_PAYLOAD_LEN2,
   MASK,
   PAYLOAD
} packet_reading_stage;

typedef enum 
{
   CONTINUATION,
   TEXT,
   BINARY,
   CLOSE = 8,
   PING,
   PONG
} frame_type;

// Structure representing frame statistic and parsing stage
typedef struct ngx_frame_counter_s {
   // statistic fields
   ngx_int_t frames;
   ngx_int_t total_payload_size; 
   ngx_int_t total_size;
   ngx_int_t bytes_consumed;

   // private fields representing current parcing stage
   packet_reading_stage stage;
   char payload_masked : 1;
   frame_type current_frame_type;
   ngx_int_t current_payload_size; 
} ngx_frame_counter_t;

typedef struct frame_head_s{
   unsigned int fin : 1;
   unsigned int rsv1 : 1;
   unsigned int rsv2 : 1;
   unsigned int rsv3 : 1;
   unsigned int opcode : 4;
} frame_head_t;

typedef struct frame_payload_s { 
   unsigned int mask : 1;
   unsigned int payload_len : 7;
} frame_payload_t;

void frame_counter_process_data(u_char *buffer, size_t size, ngx_frame_counter_t *frame_counter);
