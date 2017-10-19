#include "ngx_http_websocket_stat_frame_counter.h"
#include <assert.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
  ngx_frame_counter_t frame_counter_in;
  ngx_frame_counter_t frame_counter_out;
} ngx_http_websocket_stat_ctx;

ngx_http_websocket_stat_ctx *stat_counter;

static char *ngx_http_websocket_stat(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);
static char *ngx_http_ws_logfile(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_websocket_stat_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_websocket_stat_init(ngx_conf_t *cf);

static void *ngx_http_websocket_stat_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_websocket_stat_merge_loc_conf(ngx_conf_t *cf,
                                                    void *parent, void *child);

static ngx_atomic_t ngx_websocket_stat_active;

ngx_log_t *ws_log = NULL;

typedef struct ngx_http_websocket_local_conf_s {
} ngx_http_websocket_local_conf_t;


ssize_t (*orig_recv)(ngx_connection_t *c, u_char *buf, size_t size);

static ngx_command_t ngx_http_websocket_stat_commands[] = {

    {ngx_string("ws_stat"),        /* directive */
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, /* location context and takes
                                             no arguments*/
     ngx_http_websocket_stat,             /* configuration setup function */
     0, /* No offset. Only one context is supported. */
     0, /* No offset when storing the module configuration on struct. */
     NULL},
    {ngx_string("ws_log"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_ws_logfile, 0, 0, NULL},
    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_websocket_stat_module_ctx = {
    NULL,                         /* preconfiguration */
    ngx_http_websocket_stat_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_websocket_stat_create_loc_conf, /* create location configuration */
    ngx_http_websocket_stat_merge_loc_conf   /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_websocket_stat_module = {
    NGX_MODULE_V1,
    &ngx_http_websocket_stat_module_ctx, /* module context */
    ngx_http_websocket_stat_commands,    /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static u_char responce_template[] =
                                    "WebSocket connections: %lu\n"
                                    "Incoming Websocket data: %lu bytes\n"
                                    "Incoming TCP data: %lu bytes\n"
                                    "Outgoing websocket data: %lu bytes\n"
                                    "Outgoing TCP data: %lu bytes\n";

u_char msg[sizeof(responce_template) + 3 * NGX_ATOMIC_T_LEN];

static ngx_int_t ngx_http_websocket_stat_handler(ngx_http_request_t *r) {
  ngx_buf_t *b;
  ngx_chain_t out;

  /* Set the Content-Type header. */
  r->headers_out.content_type.len = sizeof("text/plain") - 1;
  r->headers_out.content_type.data = (u_char *)"text/plain:";

  /* Allocate a new buffer for sending out the reply. */
  b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

  /* Insertion in the buffer chain. */
  out.buf = b;
  out.next = NULL;
  sprintf((char *)msg, (char *)responce_template, 
                       ngx_websocket_stat_active, 
                       stat_counter->frame_counter_in.total_payload_size, 
                       stat_counter->frame_counter_in.total_size, 
                       stat_counter->frame_counter_out.total_payload_size,
                       stat_counter->frame_counter_out.total_size
                       );

  b->pos = msg; /* first position in memory of the data */
  b->last = msg + strlen((char *)msg); /* last position in memory of the data */
  b->memory = 1;                       /* content is in read-only memory */
  b->last_buf = 1; /* there will be buffers in the request */

  /* Sending the headers for the reply. */
  r->headers_out.status = NGX_HTTP_OK;
  /* Get the content length of the body. */
  r->headers_out.content_length_n = strlen((char *)msg);
  ngx_http_send_header(r); /* Send the headers */

  /* Send the body, and return the status code of the output filter chain. */
  return ngx_http_output_filter(r, &out);
}

/**
 * Configuration setup function that installs the content handler.
 *
 * @param cf
 *   Module configuration structure pointer.
 * @param cmd
 *   Module directives structure pointer.
 * @param conf
 *   Module configuration structure pointer.
 * @return string
 *   Status of the configuration setup.
 */
static char *ngx_http_websocket_stat(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf) {
  ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */

  /* Install the hello world handler. */
  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_websocket_stat_handler;

  return NGX_CONF_OK;
} /* ngx_http_hello_world */

static char *ngx_http_ws_logfile(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

   ws_log = ngx_palloc(cf->pool, sizeof(ngx_log_t));
   ngx_memzero(ws_log, sizeof(ngx_log_t));

   ngx_str_t *value;
   value = cf->args->elts;
   ws_log->log_level = NGX_LOG_NOTICE;
   assert(cf->args->nelts >= 2);
   ws_log->file = ngx_conf_open_file(cf->cycle, &value[1]);

  return NGX_CONF_OK;
}

ssize_t (*orig_recv)(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t (*orig_send)(ngx_connection_t *c, u_char *buf, size_t size);

// Packets that being send to a client
ssize_t my_send(ngx_connection_t *c, u_char *buf, size_t size) {


  ngx_log_error(NGX_LOG_NOTICE, ws_log, 0, "send");
  ngx_http_websocket_stat_ctx *ctx;
  ctx = stat_counter;
  ssize_t sz = size;
  u_char *buffer = buf;
  ngx_frame_counter_t *frame_counter = &ctx->frame_counter_out;
  frame_counter->total_size += sz;
  while(sz > 0)
  {
      if(frame_counter_process_message(&buffer, &sz,  frame_counter))
      {
         frame_counter->frames++;
         frame_counter->total_payload_size += frame_counter->current_payload_size;
         ngx_log_error(NGX_LOG_NOTICE, ws_log, 0, 
                 "outgoing frame type: %s, payload is %l",
                 frame_type_to_str(frame_counter->current_frame_type),
                 frame_counter->current_payload_size);
      }
  }
  return orig_send(c, buf, size);
}

// Packets received from a client
ssize_t my_recv(ngx_connection_t *c, u_char *buf, size_t size) {

  ngx_log_error(NGX_LOG_NOTICE, ws_log, 0, "recv");
  int n = orig_recv(c, buf, size);

  ngx_http_websocket_stat_ctx *ctx;
  ctx = stat_counter;
  ssize_t sz = n;
  ngx_frame_counter_t *frame_counter = &ctx->frame_counter_in;
  frame_counter->total_size += n;
  while(sz > 0)
  {
      if(frame_counter_process_message(&buf, &sz,  frame_counter))
      {
         frame_counter->frames++;
         frame_counter->total_payload_size += frame_counter->current_payload_size;
         ngx_log_error(NGX_LOG_NOTICE, ws_log, 0, 
                 "incoming frame type: %s, payload is %l",
                 frame_type_to_str(frame_counter->current_frame_type),
                 frame_counter->current_payload_size);
      }
  }

  return n;
}

static ngx_int_t ngx_http_websocket_stat_body_filter(ngx_http_request_t *r,
                                                     ngx_chain_t *in) {
  if (!r->upstream)
    return ngx_http_next_body_filter(r, in);

  if (r->upstream->upgrade) {
    if (r->upstream->peer.connection) {
      // connection opened
      ngx_log_error(NGX_LOG_NOTICE, ws_log, 0, "opened !!!!");
      ngx_http_websocket_stat_ctx *ctx;
      ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_websocket_stat_ctx));
      if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }
      ngx_http_set_ctx(r, ctx, ngx_http_websocket_stat_module);
      orig_recv = r->connection->recv;
      r->connection->recv = my_recv;
      orig_send = r->connection->send;
      r->connection->send = my_send;
      ngx_atomic_fetch_add(&ngx_websocket_stat_active, 1);
    } else {
      ngx_atomic_fetch_add(&ngx_websocket_stat_active, -1);
      ngx_log_error(NGX_LOG_NOTICE, ws_log, 0, "closed!!!!");
    }
  }

  return ngx_http_next_body_filter(r, in);
}

static void *ngx_http_websocket_stat_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_websocket_local_conf_t *conf;

  stat_counter = ngx_pcalloc(cf->pool, sizeof(ngx_http_websocket_stat_ctx));

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_websocket_local_conf_t));
  if (conf == NULL) {
    return NULL;
  }
  return conf;
}

static char *ngx_http_websocket_stat_merge_loc_conf(ngx_conf_t *cf,
                                                    void *parent, void *child) {
  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_websocket_stat_init(ngx_conf_t *cf) {
  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_websocket_stat_body_filter;

  return NGX_OK;
}
