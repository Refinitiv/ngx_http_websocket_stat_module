#include "ngx_http_websocket_stat_frame_counter.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
  ngx_frame_counter_t frame_counter_in;
  ngx_frame_counter_t frame_counter_out;
} ngx_http_websocket_stat_ctx;

static char *ngx_http_websocket_stat(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);
static char *ngx_http_ws_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ws_proxy_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_websocket_stat_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_websocket_stat_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_ws_stat_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ws_stat_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ws_stat_process_header(ngx_http_request_t *r);
static void ngx_http_ws_stat_abort_request(ngx_http_request_t *r);
static void ngx_http_ws_stat_finalize_request(ngx_http_request_t *r,
                                              ngx_int_t rc);

static void *ngx_http_websocket_stat_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_websocket_stat_merge_loc_conf(ngx_conf_t *cf,
                                                    void *parent, void *child);

static ngx_atomic_t ngx_websocket_stat_active;

typedef struct ngx_http_websocket_local_conf_s {
  ngx_http_upstream_conf_t upstream;
} ngx_http_websocket_local_conf_t;

static char ngx_http_proxy_version[] = " HTTP/1.0" CRLF;
// TODO: remove this !!
ngx_str_t url = ngx_string("http://brokerstats-test.financial.com/streaming");
ngx_str_t host_header = ngx_string("Host: brokerstats-test.financial.com");

ngx_http_upstream_conf_t upstream;

ssize_t (*orig_recv)(ngx_connection_t *c, u_char *buf, size_t size);

static ngx_command_t ngx_http_websocket_stat_commands[] = {

    {ngx_string("websocket_stat"),        /* directive */
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, /* location context and takes
                                             no arguments*/
     ngx_http_websocket_stat,             /* configuration setup function */
     0, /* No offset. Only one context is supported. */
     0, /* No offset when storing the module configuration on struct. */
     NULL},
    {ngx_string("ws_proxy"), NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_http_ws_proxy, 0, 0, NULL},
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

static u_char responce_template[] = "HTTP connections: %lu\n"
                                    "WebSocket connections: %lu\n"
                                    "Total connections: %lu";

u_char msg[sizeof(responce_template) + 3 * NGX_ATOMIC_T_LEN];

static ngx_int_t ngx_http_websocket_stat_handler(ngx_http_request_t *r) {
  ngx_buf_t *b;
  ngx_chain_t out;
  ngx_atomic_int_t ac, wac;
  ac = *ngx_stat_active;
  wac = ngx_websocket_stat_active;

  /* Set the Content-Type header. */
  r->headers_out.content_type.len = sizeof("text/plain") - 1;
  r->headers_out.content_type.data = (u_char *)"text/plain:";

  /* Allocate a new buffer for sending out the reply. */
  b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

  /* Insertion in the buffer chain. */
  out.buf = b;
  out.next = NULL;
  sprintf((char *)msg, (char *)responce_template, ac - wac, wac, ac);

  b->pos = msg; /* first position in memory of the data */
  b->last = msg + strlen((char *)msg); /* last position in memory of the data */
  b->memory = 1;                       /* content is in read-only memory */
  b->last_buf = 1; /* there will be buffers in the request */

  /* Sending the headers for the reply. */
  r->headers_out.status = NGX_HTTP_OK;
  /* Get the content length of the body. */
  r->headers_out.content_length_n = strlen((char *)msg);
  ngx_http_send_header(r); /* Send the headers */
  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Module handler invoked");

  /* Send the body, and return the status code of the output filter chain. */
  return ngx_http_output_filter(r, &out);
}

static ngx_int_t ngx_http_ws_stat_create_request(ngx_http_request_t *r) {
  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ws_stat_create_request");
  ngx_http_upstream_t *u;
  u = r->upstream;
  ngx_str_t uri = ngx_string("/streaming");
  u->uri = uri;

  ngx_table_elt_t *header;
  ngx_list_part_t *part;
  ngx_str_t method;
  method = r->method_name;
  // Calculate headers len
  u_int request_len = 0;
  request_len =
      method.len + 1 + sizeof(ngx_http_proxy_version) - 1 + sizeof(CRLF) - 1;

  part = &r->headers_in.headers.part;
  header = part->elts;
  u_int i = part->nelts;
  request_len += uri.len + 1;
  while (i != 0) {
    if (header[i].key.data && header[i].value.data) {
      request_len += header[i].key.len + sizeof(": ") - 1 +
                     header[i].value.len + sizeof(CRLF) - 1;
    }

    if (--i == 0) {
      if (part->next != NULL) {
        part = part->next;
        header = part->elts;
        i = part->nelts;
      }
    }
  }
  request_len += host_header.len + sizeof(CRLF) - 1;
  // Allocate buffer for request
  ngx_buf_t *buffer;
  buffer = ngx_create_temp_buf(r->pool, request_len);
  if (!buffer) {
    return NGX_ERROR;
  }
  ngx_chain_t *chain_link;
  chain_link = ngx_alloc_chain_link(r->pool);
  if (chain_link == NULL) {
    return NGX_ERROR;
  }
  chain_link->buf = buffer;
  // Fill request
  buffer->last = ngx_copy(buffer->last, method.data, method.len);
  *buffer->last++ = ' ';

  buffer->last = ngx_copy(buffer->last, uri.data, uri.len);

  buffer->last = ngx_cpymem(buffer->last, ngx_http_proxy_version,
                            sizeof(ngx_http_proxy_version) - 1);
  buffer->last = ngx_cpymem(buffer->last, host_header.data, host_header.len);
  *buffer->last++ = CR;
  *buffer->last++ = LF;

  part = &r->headers_in.headers.part;
  header = part->elts;
  i = part->nelts;
  while (i != 0) {
    if (header[i].key.data && header[i].value.data) {
      buffer->last =
          ngx_copy(buffer->last, header[i].key.data, header[i].key.len);

      *buffer->last++ = ':';
      *buffer->last++ = ' ';

      buffer->last =
          ngx_copy(buffer->last, header[i].value.data, header[i].value.len);

      *buffer->last++ = CR;
      *buffer->last++ = LF;
    }
    if (--i == 0) {
      if (part->next != NULL) {
        part = part->next;
        header = part->elts;
        i = part->nelts;
      }
    }
  }
  i = part->nelts;
  *buffer->last++ = CR;
  *buffer->last++ = LF;
  *(buffer->last) = '\0';

  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, (char *)buffer->pos);
  u->request_bufs = chain_link;
  buffer->flush = 1;
  chain_link->next = NULL;

  return NGX_OK;
}
static ngx_int_t ngx_http_ws_stat_reinit_request(ngx_http_request_t *r) {
  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ws_stat_reinit_request");
  if (r->header_sent) {
    return NGX_OK;
  }
  ngx_http_upstream_t *u;
  u = r->upstream;
  u->read_event_handler(r, r->upstream);
  return NGX_OK;
}
static ngx_int_t ngx_http_ws_stat_process_header(ngx_http_request_t *r) {
  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ws_stat_process_header");
  return NGX_OK;
}

static void ngx_http_ws_stat_abort_request(ngx_http_request_t *r) {
  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ws_stat_abort_request");
}

static void ngx_http_ws_stat_finalize_request(ngx_http_request_t *r,
                                              ngx_int_t rc) {
  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ws_stat_finalize_request");
}

static ngx_int_t ngx_http_ws_proxy_handler(ngx_http_request_t *r) {

  ngx_http_upstream_t *u;

  u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
  if (u == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  u->conf = &upstream;
  upstream.connect_timeout = 500000;
  upstream.read_timeout = 500000;
  upstream.send_timeout = 500000;

  u->schema = url;
  u->schema.len = 7;
  u->peer.log = ngx_cycle->log;
  u->peer.log_error = NGX_ERROR_ERR;
  u->output.tag = (ngx_buf_tag_t)&ngx_http_websocket_stat_module;

  u->create_request = ngx_http_ws_stat_create_request;
  u->reinit_request = ngx_http_ws_stat_reinit_request;
  u->process_header = ngx_http_ws_stat_process_header;
  u->abort_request = ngx_http_ws_stat_abort_request;
  u->finalize_request = ngx_http_ws_stat_finalize_request;
  // TODO:
  r->upstream = u;

  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_http_ws_proxy_handler");
  ngx_int_t rc;

  rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
  if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    return rc;
  }

  return NGX_DONE;
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

static char *ngx_http_ws_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_ws_proxy_handler;
  ngx_url_t u;
  ngx_memzero(&u, sizeof(ngx_url_t));
  u.url.data = url.data + 7;
  u.url.len = url.len - 7;
  u.default_port = 80;
  u.no_resolve = 1;
  u.uri_part = 1;

  upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
  if (!upstream.upstream) {
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Erro connecting to host");
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

ssize_t (*orig_recv)(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t (*orig_send)(ngx_connection_t *c, u_char *buf, size_t size);

ngx_frame_counter_t frame_cnt_in;
ngx_frame_counter_t frame_cnt_out;

// Packets that being send to a client
ssize_t my_send(ngx_connection_t *c, u_char *buf, size_t size) {

  ngx_http_request_t *r;
  ngx_http_websocket_stat_ctx *ctx;
  r = (ngx_http_request_t *)c->data;
  ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);

  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "send");
  frame_counter_process_data(buf, size, &ctx->frame_counter_in);
  return orig_send(c, buf, size);
}

// Packets received from a client
ssize_t my_recv(ngx_connection_t *c, u_char *buf, size_t size) {
  ngx_http_request_t *r;
  ngx_http_websocket_stat_ctx *ctx;
  r = (ngx_http_request_t *)c->data;
  ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);

  ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "recv");
  int n = orig_recv(c, buf, size);
  frame_counter_process_data(buf, n, &ctx->frame_counter_out);

  return n;
}

static ngx_int_t ngx_http_websocket_stat_body_filter(ngx_http_request_t *r,
                                                     ngx_chain_t *in) {
  if (!r->upstream)
    return ngx_http_next_body_filter(r, in);

  if (r->upstream->upgrade) {
    if (r->upstream->peer.connection) {
      // connection opened
      ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "opened !!!!");
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
      ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "closed!!!!");
    }
  }

  return ngx_http_next_body_filter(r, in);
}

static void *ngx_http_websocket_stat_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_websocket_local_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_websocket_local_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  /*
   * set by ngx_pcalloc():
   *
   *     conf->upstream.bufs.num = 0;
   *     conf->upstream.next_upstream = 0;
   *     conf->upstream.temp_path = NULL;
   *     conf->upstream.uri = { 0, NULL };
   *     conf->upstream.location = NULL;
   */

  conf->upstream.local = NGX_CONF_UNSET_PTR;
  conf->upstream.connect_timeout = 60000;
  conf->upstream.send_timeout = 60000;
  conf->upstream.read_timeout = 60000;

  conf->upstream.buffer_size = 20;
  // conf->upstream.buffer_size = BUFFER_SIZE;

  /* the hardcoded values */
  conf->upstream.cyclic_temp_file = 0;
  conf->upstream.buffering = 0;
  // conf->upstream.buffer_size = 0;
  // conf->upstream.busy_buffers_size = 0;
  conf->upstream.ignore_client_abort = 0;
  conf->upstream.send_lowat = 0;
  conf->upstream.bufs.num = 0;
  conf->upstream.busy_buffers_size = 0;
  conf->upstream.max_temp_file_size = 0;
  conf->upstream.temp_file_write_size = 0;
  conf->upstream.intercept_errors = 1;
  conf->upstream.intercept_404 = 1;
  conf->upstream.pass_request_headers = 0;
  conf->upstream.pass_request_body = 0;

  return conf;
}

static char *ngx_http_websocket_stat_merge_loc_conf(ngx_conf_t *cf,
                                                    void *parent, void *child) {
  ngx_http_websocket_local_conf_t *prev = parent;
  ngx_http_websocket_local_conf_t *conf = child;

  ngx_conf_merge_ptr_value(conf->upstream.local, prev->upstream.local, NULL);

  ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                            prev->upstream.connect_timeout, 60000);

  ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                            prev->upstream.send_timeout, 60000);

  ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                            prev->upstream.read_timeout, 60000);

  ngx_conf_merge_size_value(conf->upstream.buffer_size,
                            prev->upstream.buffer_size, (size_t)20);

  ngx_conf_merge_bitmask_value(
      conf->upstream.next_upstream, prev->upstream.next_upstream,
      (NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_ERROR |
       NGX_HTTP_UPSTREAM_FT_TIMEOUT));

  if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
    conf->upstream.next_upstream =
        NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF;
  }

  if (conf->upstream.upstream == NULL) {
    conf->upstream.upstream = prev->upstream.upstream;
  }

  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_websocket_stat_init(ngx_conf_t *cf) {
  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_websocket_stat_body_filter;

  return NGX_OK;
}
