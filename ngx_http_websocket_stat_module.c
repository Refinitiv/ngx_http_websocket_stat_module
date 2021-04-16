#include "ngx_http_websocket_stat_format.h"
#include "ngx_http_websocket_stat_frame_counter.h"
#include <assert.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define UID_LENGTH 32
#define KEY_SIZE 24
#define ACCEPT_SIZE 28
#define GUID_SIZE 36
// It contains 36 characters.
char const *const kWsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
char const *const kWsKey = "Sec-WebSocket-Key";

typedef struct {
    time_t ws_conn_start_time;
    ngx_frame_counter_t frame_counter;
    ngx_str_t connection_id;

} ngx_http_websocket_stat_ctx;

typedef struct {
    ngx_atomic_t *frames;
    ngx_atomic_t *total_payload_size;
    ngx_atomic_t *total_size;
} ngx_http_websocket_stat_statistic_t;

ngx_http_websocket_stat_statistic_t frames_in;
ngx_http_websocket_stat_statistic_t frames_out;

ngx_frame_counter_t frame_counter_in;
ngx_frame_counter_t frame_counter_out;

ngx_http_websocket_stat_ctx *stat_counter;
typedef struct {
    int from_client;
    ngx_http_websocket_stat_ctx *ws_ctx;

} template_ctx_s;

static char *ngx_http_websocket_stat(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);
static char *ngx_http_websocket_max_conn_setup(ngx_conf_t *cf,
                                               ngx_command_t *cmd, void *conf);
static char *ngx_http_websocket_max_conn_age(ngx_conf_t *cf, ngx_command_t *cmd,
                                             void *conf);
static char *ngx_http_ws_logfile(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);
static char *ngx_http_ws_log_format(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf);
static ngx_int_t ngx_http_websocket_stat_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_websocket_stat_init(ngx_conf_t *cf);

static void *ngx_http_websocket_stat_create_main_conf(ngx_conf_t *cf);
const char *get_core_var(ngx_http_request_t *r, const char *variable);

static void send_close_packet(ngx_connection_t *connection, int status,
                              const char *reason);

static ngx_atomic_t *ngx_websocket_stat_active;

char CARET_RETURN = '\n';
ngx_log_t *ws_log = NULL;
const char *UNKNOWN_VAR = "???";

static void
Base64Encode(unsigned char *hash, int hash_len, char *buffer, int len)
{
    BIO *b64, *mem;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, hash, hash_len);
    if (BIO_flush(b64) != 1) {
        printf("Error performing base64 encoding");
    }
    char *data;
    BIO_get_mem_data(mem, &data);
    memcpy(buffer, data, len);
    BIO_free_all(b64);
}

void
websocket_log(char *str)
{
    if (!ws_log)
        return;
    ngx_write_fd(ws_log->file->fd, str, strlen(str));
    ngx_write_fd(ws_log->file->fd, &CARET_RETURN, sizeof(char));
}

void
ws_do_log(compiled_template *template, ngx_http_request_t *r, void *ctx)
{
    if (ws_log) {
        char *log_line = apply_template(template, r, ctx);
        websocket_log(log_line);
        free(log_line);
    }
}

typedef struct ngx_http_websocket_main_conf_s {
    int max_ws_connections;
    int max_ws_age;
} ngx_http_websocket_main_conf_t;

compiled_template *log_template;
compiled_template *log_close_template;
compiled_template *log_open_template;

char *default_log_template_str =
    "$time_local: packet received from $ws_packet_source";
char *default_open_log_template_str = "websocket connection opened";
char *default_close_log_template_str = "websocket connection closed";

ssize_t (*orig_recv)(ngx_connection_t *c, u_char *buf, size_t size);

static ngx_command_t ngx_http_websocket_stat_commands[] = {

    {ngx_string("ws_stat"),               /* directive */
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, /* location context and takes
                                             no arguments*/
     ngx_http_websocket_stat,             /* configuration setup function */
     0, /* No offset. Only one context is supported. */
     0, /* No offset when storing the module configuration on struct. */
     NULL},
    {ngx_string("ws_max_connections"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_websocket_max_conn_setup, 0, 0, NULL},
    {ngx_string("ws_conn_age"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_websocket_max_conn_age, 0, 0, NULL},
    {ngx_string("ws_log"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_ws_logfile, 0, 0, NULL},
    {ngx_string("ws_log_format"), NGX_HTTP_SRV_CONF | NGX_CONF_1MORE,
     ngx_http_ws_log_format, 0, 0, NULL},
    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_websocket_stat_module_ctx = {
    NULL,                         /* preconfiguration */
    ngx_http_websocket_stat_init, /* postconfiguration */

    ngx_http_websocket_stat_create_main_conf, /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
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
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static u_char responce_template[] =
    "WebSocket connections: %lu\n"
    "client websocket frames  | client websocket payload | client tcp data\n"
    "%lu %lu %lu\n"
    "upstream websocket frames  | upstream websocket payload | upstream tcp "
    "data\n"
    "%lu %lu %lu\n";

u_char msg[sizeof(responce_template) + 6 * NGX_ATOMIC_T_LEN];

static ngx_int_t
ngx_http_websocket_stat_handler(ngx_http_request_t *r)
{
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
    sprintf((char *)msg, (char *)responce_template, *ngx_websocket_stat_active,
            *frames_in.frames, *frames_in.total_payload_size,
            *frames_in.total_size, *frames_out.frames,
            *frames_out.total_payload_size, *frames_out.total_size);

    b->pos = msg; /* first position in memory of the data */
    b->last =
        msg + strlen((char *)msg); /* last position in memory of the data */
    b->memory = 1;                 /* content is in read-only memory */
    b->last_buf = 1;               /* there will be buffers in the request */

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
static char *
ngx_http_websocket_stat(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */

    /* Install the hello world handler. */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_websocket_stat_handler;

    return NGX_CONF_OK;
} /* ngx_http_hello_world */

static char *
ngx_http_websocket_max_conn_setup(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf)
{
    ngx_str_t *value;
    value = cf->args->elts;
    ngx_http_websocket_main_conf_t *main_conf = conf;
    main_conf->max_ws_connections = atoi((char *)value[1].data);
    return NGX_CONF_OK;
}
static char *
ngx_http_websocket_max_conn_age(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    value = cf->args->elts;
    ngx_int_t timeout;
    timeout = ngx_parse_time(&value[1], 1);
    if (timeout == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }
    ngx_http_websocket_main_conf_t *main_conf = conf;
    main_conf->max_ws_age = timeout;

    return NGX_CONF_OK;
}

static char *
ngx_http_ws_logfile(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

    ws_log = ngx_palloc(cf->pool, sizeof(ngx_log_t));
    ngx_memzero(ws_log, sizeof(ngx_log_t));

    ngx_str_t *value;
    value = cf->args->elts;
    ws_log->log_level = NGX_LOG_NOTICE;
    assert(cf->args->nelts >= 2);
    ws_log->file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (!ws_log->file)
        return NGX_CONF_ERROR;

    return NGX_CONF_OK;
}
typedef ssize_t (*send_func)(ngx_connection_t *c, u_char *buf, size_t size);
send_func orig_recv, orig_send;

static int
check_ws_age(time_t conn_start_time, ngx_http_request_t *r)
{
    ngx_http_websocket_main_conf_t *conf;
    conf = ngx_http_get_module_main_conf(r, ngx_http_websocket_stat_module);
    if (conf->max_ws_age > 0 &&
        ngx_time() - conn_start_time >= conf->max_ws_age) {
        send_close_packet(r->connection, 4001, "Connection is Aged");
        return NGX_ERROR;
    }
    return NGX_OK;
}
// Packets that being send to a client
ssize_t
my_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "SEND START");

    ngx_http_websocket_stat_ctx *ctx;
    ssize_t sz = size;
    u_char *buffer = buf;
    ngx_http_websocket_stat_statistic_t *frame_counter = &frames_out;
    ngx_atomic_fetch_add(frame_counter->total_size, sz);
    ngx_http_request_t *r = c->data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);
    if (check_ws_age(ctx->ws_conn_start_time, r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "CONN TOO OLD");
        return NGX_ERROR;
    }
    template_ctx_s template_ctx;
    template_ctx.from_client = 0;
    template_ctx.ws_ctx = ctx;
    while (sz > 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PROCESS SEND FRAME");
        if (frame_counter_process_message(&buffer, &sz,
                                          &(ctx->frame_counter))) {
            ngx_atomic_fetch_add(frame_counter->frames, 1);
            ngx_atomic_fetch_add(frame_counter->total_payload_size,
                                 ctx->frame_counter.current_payload_size);
            ws_do_log(log_template, r, &template_ctx);
        }
    }
    int n = orig_send(c, buf, size);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PROCESS SEND RESP FRAME");
        if(!ngx_atomic_cmp_set(ngx_websocket_stat_active, 0, 0)){
          ngx_atomic_fetch_add(ngx_websocket_stat_active, -1);
          ws_do_log(log_close_template, r, &template_ctx);
        }
    }
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "SEND END");
    return n;
}

// Packets received from a client
ssize_t
my_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "RECV START");

    int n = orig_recv(c, buf, size);
    if (n <= 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "NO RESPONCE");
        return n;
    }

    ngx_http_websocket_stat_ctx *ctx;
    ssize_t sz = n;
    ngx_http_websocket_stat_statistic_t *frame_counter = &frames_in;
    ngx_http_request_t *r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);
    if (check_ws_age(ctx->ws_conn_start_time, r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "CONN TOO OLD");
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "INC COUNTER");
    ngx_atomic_fetch_add(frame_counter->total_size, n);
    template_ctx_s template_ctx;
    template_ctx.from_client = 1;
    template_ctx.ws_ctx = ctx;
    while (sz > 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PROCESS RECV FRAME");
        if (frame_counter_process_message(&buf, &sz, &ctx->frame_counter)) {

            ngx_atomic_fetch_add(frame_counter->frames, 1);
            ngx_atomic_fetch_add(frame_counter->total_payload_size,
                                 ctx->frame_counter.current_payload_size);
            ws_do_log(log_template, r, &template_ctx);
        }
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "END RECV");

    return n;
}

static ngx_int_t
ngx_http_websocket_stat_header_filter(ngx_http_request_t *r)
{
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_websocket_stat_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "START BODY FILTER");
    if (!r->upstream) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "NO UPSTREAM");
        return ngx_http_next_body_filter(r, in);
    }

    ngx_http_websocket_stat_ctx *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);
    template_ctx_s template_ctx;
    template_ctx.ws_ctx = ctx;

    if (r->headers_in.upgrade) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "UPGRADE FLAG FOUND");
        if (r->upstream->peer.connection) {
            // connection opened
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PEER.CONNECTION OPENED");
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_websocket_stat_ctx));
            if (ctx == NULL) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "NO CONTEXT");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            const char *request_id_str = get_core_var(r, "request_id");
            ctx->connection_id.data = ngx_pcalloc(r->pool, UID_LENGTH + 1);
            ctx->connection_id.len = UID_LENGTH;
            memcpy(ctx->connection_id.data, request_id_str, UID_LENGTH + 1);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "WS IS OPENED");
            ws_do_log(log_open_template, r, &template_ctx);
            ngx_http_set_ctx(r, ctx, ngx_http_websocket_stat_module);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PATCHED RECV");
            orig_recv = r->connection->recv;
            r->connection->recv = my_recv;
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PATCHED SEND");
            orig_send = r->connection->send;
            r->connection->send = my_send;
            ngx_atomic_fetch_add(ngx_websocket_stat_active, 1);
            ctx->ws_conn_start_time = ngx_time();
        } else {
          if(!ngx_atomic_cmp_set(ngx_websocket_stat_active, 0, 0)){
              ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "WS IS CLOSED");
              ngx_atomic_fetch_add(ngx_websocket_stat_active, -1);
              ws_do_log(log_close_template, r, &template_ctx);
            }
        }
    }
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "END BODY FILTER");

    return ngx_http_next_body_filter(r, in);
}

char buff[100];

const char *
ws_packet_type(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    ngx_frame_counter_t *frame_cntr = &(ctx->ws_ctx->frame_counter);
    if (!ctx || !frame_cntr)
        return UNKNOWN_VAR;
    sprintf(buff, "%d", frame_cntr->current_frame_type);
    return buff;
}

const char *
ws_packet_size(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    ngx_frame_counter_t *frame_cntr = &ctx->ws_ctx->frame_counter;
    if (!ctx || !frame_cntr)
        return UNKNOWN_VAR;
    sprintf(buff, "%lu", frame_cntr->current_payload_size);
    return (char *)buff;
}

const char *
ws_packet_source(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx)
        return UNKNOWN_VAR;
    if (ctx->from_client)
        return "client";
    return "upstream";
}

const char *
get_core_var(ngx_http_request_t *r, const char *variable)
{
    ngx_int_t key = 0;
    ngx_http_variable_value_t *vv;
    ngx_str_t var;
    var.data = (u_char *)variable;
    var.len = strlen(variable);
    while (*variable != '\0')
        key = ngx_hash(key, *(variable++));

    vv = ngx_http_get_variable(r, &var, key);
    memcpy(buff, vv->data, vv->len);
    buff[vv->len] = '\0';
    return buff;
}

const char *
ws_connection_age(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx)
        return UNKNOWN_VAR;
    sprintf(buff, "%lu", ngx_time() - ctx->ws_ctx->ws_conn_start_time);

    return (char *)buff;
}

const char *
local_time(ngx_http_request_t *r, void *data)
{
    return memcpy(buff, ngx_cached_http_time.data, ngx_cached_http_time.len);
}

const char *
remote_ip(ngx_http_request_t *r, void *data)
{
    memcpy(buff, r->connection->addr_text.data, r->connection->addr_text.len);
    buff[r->connection->addr_text.len] = '\0';

    return buff;
}

const char *
request_id(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx)
        return UNKNOWN_VAR;
    return (const char *)ctx->ws_ctx->connection_id.data;
}

const char *
upstream_addr(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx)
        return UNKNOWN_VAR;
    if (r->upstream_states == NULL || r->upstream_states->nelts == 0)
        return UNKNOWN_VAR;
    ngx_http_upstream_state_t *state;
    state = r->upstream_states->elts;
    return (const char *)state->peer->data;
}

#define GEN_CORE_GET_FUNC(fname, var)                                          \
    const char *fname(ngx_http_request_t *r, void *data)                       \
    {                                                                          \
        return get_core_var(r, var);                                           \
    }

GEN_CORE_GET_FUNC(request, "request")
GEN_CORE_GET_FUNC(uri, "uri")
GEN_CORE_GET_FUNC(remote_user, "remote_user")
GEN_CORE_GET_FUNC(remote_addr, "remote_addr")
GEN_CORE_GET_FUNC(remote_port, "remote_port")
GEN_CORE_GET_FUNC(server_addr, "server_addr")
GEN_CORE_GET_FUNC(server_port, "server_port")

const template_variable variables[] = {
    {VAR_NAME("$ws_opcode"), sizeof("ping") - 1, ws_packet_type},
    {VAR_NAME("$ws_payload_size"), NGX_SIZE_T_LEN, ws_packet_size},
    {VAR_NAME("$ws_packet_source"), sizeof("upstream") - 1, ws_packet_source},
    {VAR_NAME("$ws_conn_age"), NGX_SIZE_T_LEN, ws_connection_age},
    {VAR_NAME("$time_local"), sizeof("Mon, 23 Oct 2017 11:27:42 GMT") - 1,
     local_time},
    {VAR_NAME("$upstream_addr"), 60, upstream_addr},
    {VAR_NAME("$request"), 60, request},
    {VAR_NAME("$uri"), 60, uri},
    {VAR_NAME("$request_id"), UID_LENGTH, request_id},
    {VAR_NAME("$remote_user"), 60, remote_user},
    {VAR_NAME("$remote_addr"), 60, remote_addr},
    {VAR_NAME("$remote_port"), 60, remote_port},
    {VAR_NAME("$server_addr"), 60, server_addr},
    {VAR_NAME("$server_port"), 60, server_port},
    // TODO: Delete this since its duplicating $remote_add
    {VAR_NAME("$remote_ip"), sizeof("000.000.000.000") - 1, remote_ip},
    {NULL, 0, 0, NULL}};

static void *
ngx_http_websocket_stat_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_websocket_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_websocket_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->max_ws_connections = -1;
    conf->max_ws_age = -1;

    return conf;
}

static char *
ngx_http_ws_log_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *args = cf->args->elts;
    if (cf->args->nelts != 2 && cf->args->nelts != 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Wrong argument number");
        return NGX_CONF_ERROR;
    }
    if (cf->args->nelts == 2) {
        log_template =
            compile_template((char *)args[1].data, variables, cf->pool);
        return NGX_CONF_OK;
    }
    if (strcmp((char *)args[1].data, "close") == 0) {
        log_close_template =
            compile_template((char *)args[2].data, variables, cf->pool);
        return NGX_CONF_OK;
    } else if (strcmp((char *)args[1].data, "open") == 0) {
        log_open_template =
            compile_template((char *)args[2].data, variables, cf->pool);
        return NGX_CONF_OK;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Unknown log format keyword\"%V\"",
                           (ngx_str_t *)&args[1]);
        return NGX_CONF_ERROR;
    }
}

static void
allocate_counters()
{
    const int cl = 128; // cache line size
    const int variables = 7;
    ngx_shm_t shm;
    shm.size = cl * variables; //
    shm.log = ngx_cycle->log;
    ngx_str_set(&shm.name, "websocket_stat_shared_zone");
    if (ngx_shm_alloc(&shm) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "Failed to allocate shared memory");
        return;
    }
    int var_counter = 0;
    frames_in.frames = (ngx_atomic_t *)(shm.addr + (var_counter++) * cl);
    frames_in.total_payload_size =
        (ngx_atomic_t *)(shm.addr + (var_counter++) * cl);
    frames_in.total_size = (ngx_atomic_t *)(shm.addr + (var_counter++) * cl);
    frames_out.frames = (ngx_atomic_t *)(shm.addr + (var_counter++) * cl);
    frames_out.total_payload_size =
        (ngx_atomic_t *)(shm.addr + (var_counter++) * cl);
    frames_out.total_size = (ngx_atomic_t *)(shm.addr + (var_counter++) * cl);
    ngx_websocket_stat_active =
        (ngx_atomic_t *)(shm.addr + (var_counter++) * cl);
    assert(var_counter <= variables);
}

static ngx_table_elt_t *
find_header_in(ngx_http_request_t *r, const char *header_name)
{
    if (!r) {
        return NULL;
    }
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    part = &r->headers_in.headers.part;
    header = part->elts;
    int i = part->nelts - 1;
    while (1) {
        if (strcasecmp((char *)header[i].key.data, header_name) == 0) {
            return &header[i];
        }
        if (--i < 0) {
            if (!part->next)
                break;
            part = part->next;
            header = part->elts;
            i = part->nelts - 1;
        }
    }
    return NULL;
}

static void
send_close_packet(ngx_connection_t *connection, int status, const char *reason)
{
    // send close packet
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "SENDING CLOSE PACKET 1");
    char cbuf[256];
    memset(cbuf, 0, sizeof(cbuf));
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "SENDING CLOSE PACKET 2");
    cbuf[0] = 0x88; // Fin, Close : 1000 1000
    int rlen = strlen(reason);
    rlen += 2;                       // add 2b status
    const int max_payload_len = 125; // wo extended len
    rlen = (rlen > max_payload_len) ? max_payload_len : rlen;
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "SENDING CLOSE PACKET 3");
    cbuf[1] = rlen;                 // Payload Len: 0... ....
    cbuf[2] = 0xFF & (status >> 8); // Status MSB : .... .... (Big Endian)
    cbuf[3] = 0xFF & status;        // Status LSB : .... ....
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "SENDING CLOSE PACKET 4");
    memcpy(&cbuf[4], reason, rlen);
    int cbuflen = rlen + 2;
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "SENDING CLOSE PACKET 5");
    orig_send(connection, (unsigned char *)cbuf, cbuflen);
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PACKET SENT");
}

char salt[GUID_SIZE + KEY_SIZE + 1];
char access_key[ACCEPT_SIZE + 1];
unsigned char hash[SHA_DIGEST_LENGTH];

static const char *const resp_template = "HTTP/1.1 101 Switching Protocols\n"
                                         "Upgrade: WebSocket\n"
                                         "Connection: Upgrade\n"
                                         "Sec-WebSocket-Accept: %s\n\n";

static void
complete_ws_handshake(ngx_connection_t *connection, const char *ws_key)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    memcpy(salt, ws_key, KEY_SIZE);
    memcpy(salt + KEY_SIZE, kWsGUID, GUID_SIZE);

    SHA1((unsigned char *)salt, sizeof(salt) - 1, hash);

    Base64Encode(hash, SHA_DIGEST_LENGTH, access_key, ACCEPT_SIZE);
    access_key[ACCEPT_SIZE] = '\0';
    char resp[256];
    sprintf(resp, resp_template, access_key);
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                  "Websocket connection closed");
    connection->send(connection, (unsigned char *)resp, strlen(resp));
}

static ngx_int_t
ngx_http_websocket_request_handler(ngx_http_request_t *r)
{
    ngx_http_websocket_main_conf_t *conf;
    conf = ngx_http_get_module_main_conf(r, ngx_http_websocket_stat_module);
    if (conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "CONF NULL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (conf->max_ws_connections > 0 &&
        conf->max_ws_connections == (int)*ngx_websocket_stat_active) {
        ngx_table_elt_t *upgrade_hdr = find_header_in(r, "Upgrade");
        if (!upgrade_hdr ||
            strcasecmp((char *)upgrade_hdr->value.data, "websocket") != 0) {
            // This is not a websocket conenction, allow it.
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "NOT A WS");
            return NGX_OK;
        }
        ngx_table_elt_t *hdr = find_header_in(r, kWsKey);
        if (!hdr || hdr->value.len != KEY_SIZE) {
            // Request should contain a valid Sec-Webscoket-Key header.
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "NO HEADER");
            return NGX_HTTP_BAD_REQUEST;
        }
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "TOO MANY CONN");
        complete_ws_handshake(r->connection, (const char *)hdr->value.data);
        send_close_packet(r->connection, 1013, "Try Again Later");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "HANDLED");
    return NGX_OK;
}

static ngx_int_t
ngx_http_websocket_stat_init(ngx_conf_t *cf)
{
    allocate_counters();

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_websocket_stat_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_websocket_stat_body_filter;

    if (!log_template) {
        log_template =
            compile_template(default_log_template_str, variables, cf->pool);
    }
    if (!log_open_template) {
        log_open_template = compile_template(default_open_log_template_str,
                                             variables, cf->pool);
    }
    if (!log_close_template) {
        log_close_template = compile_template(default_close_log_template_str,
                                              variables, cf->pool);
    }

    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_websocket_request_handler;

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "INITIALIZED");
    return NGX_OK;
}
/*
2021/04/16 07:31:46 [debug] 38#38: epoll: fd:6 ev:0001 d:00007FFB365DD940
2021/04/16 07:31:46 [debug] 38#38: accept on 0.0.0.0:80, ready: 0
2021/04/16 07:31:46 [debug] 38#38: posix_memalign: 00007FFB3654ED90:512 @16
2021/04/16 07:31:46 [debug] 38#38: *83 accept: 172.17.0.1:56902 fd:3
2021/04/16 07:31:46 [debug] 38#38: *83 event timer add: 3: 60000:140989513
2021/04/16 07:31:46 [debug] 38#38: *83 reusable connection: 1
2021/04/16 07:31:46 [debug] 38#38: *83 epoll add event: fd:3 op:1 ev:80002001
2021/04/16 07:31:46 [debug] 38#38: timer delta: 4990
2021/04/16 07:31:46 [debug] 38#38: worker cycle
2021/04/16 07:31:46 [debug] 38#38: epoll timer: 60000
2021/04/16 07:31:46 [debug] 38#38: epoll: fd:3 ev:0001 d:00007FFB365DDBF9
2021/04/16 07:31:46 [debug] 38#38: *83 http wait request handler
2021/04/16 07:31:46 [debug] 38#38: *83 malloc: 00007FFB36566AE0:1024
2021/04/16 07:31:46 [debug] 38#38: *83 recv: eof:0, avail:-1
2021/04/16 07:31:46 [debug] 38#38: *83 recv: fd:3 223 of 1024
2021/04/16 07:31:46 [debug] 38#38: *83 reusable connection: 0
2021/04/16 07:31:46 [debug] 38#38: *83 posix_memalign: 00007FFB365750D0:4096 @16
2021/04/16 07:31:46 [debug] 38#38: *83 http process request line
2021/04/16 07:31:46 [debug] 38#38: *83 http request line: "GET / HTTP/1.1"
2021/04/16 07:31:46 [debug] 38#38: *83 http uri: "/"
2021/04/16 07:31:46 [debug] 38#38: *83 http args: ""
2021/04/16 07:31:46 [debug] 38#38: *83 http exten: ""
2021/04/16 07:31:46 [debug] 38#38: *83 posix_memalign: 00007FFB36576310:4096 @16
2021/04/16 07:31:46 [debug] 38#38: *83 http process request header line
2021/04/16 07:31:46 [debug] 38#38: *83 http header: "Sec-WebSocket-Version: 13"
2021/04/16 07:31:46 [debug] 38#38: *83 http header: "Sec-WebSocket-Key: IiAuDfibSTqN0YXkwaK73A=="
2021/04/16 07:31:46 [debug] 38#38: *83 http header: "Connection: Upgrade"
2021/04/16 07:31:46 [debug] 38#38: *83 http header: "Upgrade: websocket"
2021/04/16 07:31:46 [debug] 38#38: *83 http header: "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits"
2021/04/16 07:31:46 [debug] 38#38: *83 http header: "Host: localhost:8888"
2021/04/16 07:31:46 [debug] 38#38: *83 http header done
2021/04/16 07:31:46 [debug] 38#38: *83 event timer del: 3: 140989513
2021/04/16 07:31:46 [debug] 38#38: *83 generic phase: 0
2021/04/16 07:31:46 [debug] 38#38: *83 rewrite phase: 1
2021/04/16 07:31:46 [debug] 38#38: *83 test location: "/"
2021/04/16 07:31:46 [debug] 38#38: *83 using configuration "/"
2021/04/16 07:31:46 [debug] 38#38: *83 http cl:-1 max:1048576
2021/04/16 07:31:46 [debug] 38#38: *83 rewrite phase: 3
2021/04/16 07:31:46 [debug] 38#38: *83 post rewrite phase: 4
2021/04/16 07:31:46 [debug] 38#38: *83 generic phase: 5
2021/04/16 07:31:46 [debug] 38#38: *83 generic phase: 6
2021/04/16 07:31:46 [debug] 38#38: *83 generic phase: 7
2021/04/16 07:31:46 [debug] 38#38: *83 access phase: 8
2021/04/16 07:31:46 [debug] 38#38: *83 access phase: 9
2021/04/16 07:31:46 [debug] 38#38: *83 access phase: 10
2021/04/16 07:31:46 [debug] 38#38: *83 post access phase: 11
2021/04/16 07:31:46 [debug] 38#38: *83 generic phase: 12
2021/04/16 07:31:46 [debug] 38#38: *83 generic phase: 13
2021/04/16 07:31:46 [debug] 38#38: *83 http init upstream, client timer: 0
2021/04/16 07:31:46 [debug] 38#38: *83 epoll add event: fd:3 op:3 ev:80002005
2021/04/16 07:31:46 [debug] 38#38: *83 http script copy: "Authorization"
2021/04/16 07:31:46 [debug] 38#38: *83 http script copy: "Basic Z2FsbGFudC1oeXBhdGlhOmF0dGlyZS1kb2FibGUtc2F1Y3ktbmVwaGV3LW5lYXRseS1lY2FyZA=="
2021/04/16 07:31:46 [debug] 38#38: *83 http script copy: "Connection"
2021/04/16 07:31:46 [debug] 38#38: *83 http script copy: "upgrade"
2021/04/16 07:31:46 [debug] 38#38: *83 http script copy: "Upgrade"
2021/04/16 07:31:46 [debug] 38#38: *83 http script var: "websocket"
2021/04/16 07:31:46 [debug] 38#38: *83 http script copy: "Host"
2021/04/16 07:31:46 [debug] 38#38: *83 http script var: "ws-nd-366-962-854.int.chainstack.com"
2021/04/16 07:31:46 [debug] 38#38: *83 http script copy: ""
2021/04/16 07:31:46 [debug] 38#38: *83 http script copy: ""
2021/04/16 07:31:46 [debug] 38#38: *83 http proxy header: "Sec-WebSocket-Version: 13"
2021/04/16 07:31:46 [debug] 38#38: *83 http proxy header: "Sec-WebSocket-Key: IiAuDfibSTqN0YXkwaK73A=="
2021/04/16 07:31:46 [debug] 38#38: *83 http proxy header: "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits"
2021/04/16 07:31:46 [debug] 38#38: *83 http proxy header:
"GET / HTTP/1.1
Authorization: Basic Z2FsbGFudC1oeXBhdGlhOmF0dGlyZS1kb2FibGUtc2F1Y3ktbmVwaGV3LW5lYXRseS1lY2FyZA==
Connection: upgrade
Upgrade: websocket
Host: ws-nd-366-962-854.int.chainstack.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: IiAuDfibSTqN0YXkwaK73A==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits

"
2021/04/16 07:31:46 [debug] 38#38: *83 http cleanup add: 00007FFB36576DA8
2021/04/16 07:31:46 [debug] 38#38: *83 get rr peer, try: 1
2021/04/16 07:31:46 [debug] 38#38: *83 stream socket 4
2021/04/16 07:31:46 [debug] 38#38: *83 epoll add connection: fd:4 ev:80002005
2021/04/16 07:31:46 [debug] 38#38: *83 connect to 20.68.184.228:443, fd:4 #84
2021/04/16 07:31:46 [debug] 38#38: *83 http upstream connect: -2
2021/04/16 07:31:46 [debug] 38#38: *83 posix_memalign: 00007FFB3660C640:128 @16
2021/04/16 07:31:46 [debug] 38#38: *83 event timer add: 4: 60000:140989513
2021/04/16 07:31:46 [debug] 38#38: *83 http finalize request: -4, "/?" a:1, c:2
2021/04/16 07:31:46 [debug] 38#38: *83 http request count:2 blk:0
2021/04/16 07:31:46 [debug] 38#38: timer delta: 0
2021/04/16 07:31:46 [debug] 38#38: worker cycle
2021/04/16 07:31:46 [debug] 38#38: epoll timer: 60000
2021/04/16 07:31:46 [debug] 38#38: epoll: fd:3 ev:0004 d:00007FFB365DDBF9
2021/04/16 07:31:46 [debug] 38#38: *83 http run request: "/?"
2021/04/16 07:31:46 [debug] 38#38: *83 http upstream check client, write event:1, "/"
2021/04/16 07:31:46 [debug] 38#38: timer delta: 0
2021/04/16 07:31:46 [debug] 38#38: worker cycle
2021/04/16 07:31:46 [debug] 38#38: epoll timer: 60000
2021/04/16 07:31:46 [debug] 38#38: epoll: fd:4 ev:0004 d:00007FFB365DDCE1
2021/04/16 07:31:46 [debug] 38#38: *83 http upstream request: "/?"
2021/04/16 07:31:46 [debug] 38#38: *83 http upstream send request handler
2021/04/16 07:31:46 [debug] 38#38: *83 malloc: 00007FFB36648470:96
2021/04/16 07:31:46 [debug] 38#38: *83 set session: 00007FFB36678AB0
2021/04/16 07:31:46 [debug] 38#38: *83 tcp_nodelay
2021/04/16 07:31:46 [debug] 38#38: *83 SSL_do_handshake: -1
2021/04/16 07:31:46 [debug] 38#38: *83 SSL_get_error: 2
2021/04/16 07:31:46 [debug] 38#38: timer delta: 84
2021/04/16 07:31:46 [debug] 38#38: worker cycle
2021/04/16 07:31:46 [debug] 38#38: epoll timer: 59916
2021/04/16 07:31:47 [debug] 38#38: epoll: fd:4 ev:0005 d:00007FFB365DDCE1
2021/04/16 07:31:47 [debug] 38#38: *83 SSL handshake handler: 0
2021/04/16 07:31:47 [debug] 38#38: *83 SSL_do_handshake: 1
2021/04/16 07:31:47 [debug] 38#38: *83 SSL: TLSv1.2, cipher: "ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH Au=RSA Enc=AESGCM(128) Mac=AEAD"
2021/04/16 07:31:47 [debug] 38#38: *83 SSL reused session
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream ssl handshake: "/?"
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream send request
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream send request body
2021/04/16 07:31:47 [debug] 38#38: *83 chain writer buf fl:1 s:344
2021/04/16 07:31:47 [debug] 38#38: *83 chain writer in: 00007FFB36576DE8
2021/04/16 07:31:47 [debug] 38#38: *83 malloc: 00007FFB36B61D60:80
2021/04/16 07:31:47 [debug] 38#38: *83 malloc: 00007FFB366168F0:16384
2021/04/16 07:31:47 [debug] 38#38: *83 SSL buf copy: 344
2021/04/16 07:31:47 [debug] 38#38: *83 SSL to write: 344
2021/04/16 07:31:47 [debug] 38#38: *83 SSL_write: 344
2021/04/16 07:31:47 [debug] 38#38: *83 chain writer out: 0000000000000000
2021/04/16 07:31:47 [debug] 38#38: *83 event timer del: 4: 140989513
2021/04/16 07:31:47 [debug] 38#38: *83 event timer add: 4: 60000:140989672
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream process header
2021/04/16 07:31:47 [debug] 38#38: *83 malloc: 00007FFB365728A0:4096
2021/04/16 07:31:47 [debug] 38#38: *83 SSL_read: -1
2021/04/16 07:31:47 [debug] 38#38: *83 SSL_get_error: 2
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream request: "/?"
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream dummy handler
2021/04/16 07:31:47 [debug] 38#38: timer delta: 75
2021/04/16 07:31:47 [debug] 38#38: worker cycle
2021/04/16 07:31:47 [debug] 38#38: epoll timer: 60000
2021/04/16 07:31:47 [debug] 38#38: epoll: fd:4 ev:0005 d:00007FFB365DDCE1
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream request: "/?"
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream process header
2021/04/16 07:31:47 [debug] 38#38: *83 SSL_read: 302
2021/04/16 07:31:47 [debug] 38#38: *83 SSL_read: -1
2021/04/16 07:31:47 [debug] 38#38: *83 SSL_get_error: 2
2021/04/16 07:31:47 [debug] 38#38: *83 http proxy status 101 "101 Switching Protocols"
2021/04/16 07:31:47 [debug] 38#38: *83 http proxy header: "Date: Fri, 16 Apr 2021 07:31:47 GMT"
2021/04/16 07:31:47 [debug] 38#38: *83 http proxy header: "Connection: upgrade"
2021/04/16 07:31:47 [debug] 38#38: *83 http proxy header: "Upgrade: websocket"
2021/04/16 07:31:47 [debug] 38#38: *83 http proxy header: "Sec-WebSocket-Accept: Fdbg6yLCF0bNGadEXL/YfGqC19M="
2021/04/16 07:31:47 [debug] 38#38: *83 http proxy header: "Strict-Transport-Security: max-age=15724800; includeSubDomains"
2021/04/16 07:31:47 [debug] 38#38: *83 http proxy header: "Access-Control-Allow-Origin: *"
2021/04/16 07:31:47 [debug] 38#38: *83 http proxy header: "Access-Control-Allow-Credentials: true"
2021/04/16 07:31:47 [debug] 38#38: *83 http proxy header done
2021/04/16 07:31:47 [debug] 38#38: *83 HTTP/1.1 101 Switching Protocols
Server: nginx/1.19.6
Date: Fri, 16 Apr 2021 07:31:47 GMT
Connection: upgrade
Upgrade: websocket
Sec-WebSocket-Accept: Fdbg6yLCF0bNGadEXL/YfGqC19M=
Strict-Transport-Security: max-age=15724800; includeSubDomains
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

2021/04/16 07:31:47 [debug] 38#38: *83 write new buf t:1 f:0 00007FFB365771C8, pos 00007FFB365771C8, size: 324 file: 0, size: 0
2021/04/16 07:31:47 [debug] 38#38: *83 http write filter: l:0 f:0 s:324
2021/04/16 07:31:47 [debug] 38#38: *83 tcp_nodelay
2021/04/16 07:31:47 [debug] 38#38: *83 posix_memalign: 00007FFB36577570:4096 @16
2021/04/16 07:31:47 [debug] 38#38: *83 http output filter "/?"
2021/04/16 07:31:47 [debug] 38#38: *83 http copy filter: "/?"
2021/04/16 07:31:47 [debug] 38#38: *83 http postpone filter "/?" 00007FFCFD594FE0
2021/04/16 07:31:47 [debug] 38#38: *83 write old buf t:1 f:0 00007FFB365771C8, pos 00007FFB365771C8, size: 324 file: 0, size: 0
2021/04/16 07:31:47 [debug] 38#38: *83 write new buf t:0 f:0 0000000000000000, pos 0000000000000000, size: 0 file: 0, size: 0
2021/04/16 07:31:47 [debug] 38#38: *83 http write filter: l:0 f:1 s:324
2021/04/16 07:31:47 [debug] 38#38: *83 http write filter limit 0
2021/04/16 07:31:47 [debug] 38#38: *83 writev: 324 of 324
2021/04/16 07:31:47 [debug] 38#38: *83 http write filter 0000000000000000
2021/04/16 07:31:47 [debug] 38#38: *83 http copy filter: 0 "/?"
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream process upgraded, fu:0
2021/04/16 07:31:47 [debug] 38#38: *83 malloc: 00007FFB365715F0:4096
2021/04/16 07:31:47 [debug] 38#38: *83 event timer: 4, old: 140989672, new: 140989751
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream request: "/?"
2021/04/16 07:31:47 [debug] 38#38: *83 http upstream process upgraded, fu:0
2021/04/16 07:31:47 [debug] 38#38: *83 event timer: 4, old: 140989672, new: 140989751
2021/04/16 07:31:47 [debug] 38#38: timer delta: 79
2021/04/16 07:31:47 [debug] 38#38: worker cycle
2021/04/16 07:31:47 [debug] 38#38: epoll timer: 59921




2021/04/16 07:31:50 [debug] 38#38: epoll: fd:3 ev:0005 d:00007FFB365DDBF9
2021/04/16 07:31:50 [debug] 38#38: *83 http run request: "/?"
2021/04/16 07:31:50 [debug] 38#38: *83 http upstream process upgraded, fu:0
2021/04/16 07:31:50 [debug] 38#38: *83 recv: eof:0, avail:-1
2021/04/16 07:31:50 [debug] 38#38: *83 recv: fd:3 6 of 4096
2021/04/16 07:31:50 [debug] 38#38: *83 SSL to write: 6
2021/04/16 07:31:50 [debug] 38#38: *83 SSL_write: 6
2021/04/16 07:31:50 [debug] 38#38: *83 event timer del: 4: 140989672
2021/04/16 07:31:50 [debug] 38#38: *83 event timer add: 4: 60000:140993512
2021/04/16 07:31:50 [debug] 38#38: *83 http run request: "/?"
2021/04/16 07:31:50 [debug] 38#38: *83 http upstream process upgraded, fu:1
2021/04/16 07:31:50 [debug] 38#38: *83 event timer: 4, old: 140993512, new: 140993512
2021/04/16 07:31:50 [debug] 38#38: timer delta: 3761
2021/04/16 07:31:50 [debug] 38#38: worker cycle
2021/04/16 07:31:50 [debug] 38#38: epoll timer: 60000
2021/04/16 07:31:50 [debug] 38#38: epoll: fd:4 ev:2005 d:00007FFB365DDCE1
2021/04/16 07:31:50 [debug] 38#38: *83 http upstream request: "/?"
2021/04/16 07:31:50 [debug] 38#38: *83 http upstream process upgraded, fu:1
2021/04/16 07:31:50 [debug] 38#38: *83 SSL_read: 0
172.17.0.1 - - [16/Apr/2021:07:31:50 +0000] "GET / HTTP/1.1" 101 0 "-" "-"
2021/04/16 07:31:50 [debug] 38#38: *83 SSL_get_error: 6
2021/04/16 07:31:50 [debug] 38#38: *83 peer shutdown SSL cleanly
2021/04/16 07:31:50 [debug] 38#38: *83 http upstream upgraded done
2021/04/16 07:31:50 [debug] 38#38: *83 finalize http upstream request: 0
2021/04/16 07:31:50 [debug] 38#38: *83 finalize http proxy request
2021/04/16 07:31:50 [debug] 38#38: *83 free rr peer 1 0
2021/04/16 07:31:50 [debug] 38#38: *83 SSL_shutdown: 1
2021/04/16 07:31:50 [debug] 38#38: *83 close http upstream connection: 4
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB366168F0
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB36B61D60
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB36648470
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB3660C640, unused: 0
2021/04/16 07:31:50 [debug] 38#38: *83 event timer del: 4: 140993512
2021/04/16 07:31:50 [debug] 38#38: *83 reusable connection: 0
2021/04/16 07:31:50 [debug] 38#38: *83 http output filter "/?"
2021/04/16 07:31:50 [debug] 38#38: *83 http copy filter: "/?"
2021/04/16 07:31:50 [debug] 38#38: *83 http postpone filter "/?" 00007FFCFD594FD0
2021/04/16 07:31:50 [debug] 38#38: *83 write new buf t:0 f:0 0000000000000000, pos 0000000000000000, size: 0 file: 0, size: 0
2021/04/16 07:31:50 [debug] 38#38: *83 http write filter: l:1 f:0 s:0
2021/04/16 07:31:50 [debug] 38#38: *83 http copy filter: 0 "/?"
2021/04/16 07:31:50 [debug] 38#38: *83 http finalize request: 0, "/?" a:1, c:1
2021/04/16 07:31:50 [debug] 38#38: *83 http request count:1 blk:0
2021/04/16 07:31:50 [debug] 38#38: *83 http close request
2021/04/16 07:31:50 [debug] 38#38: *83 http log handler
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB365715F0
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB365728A0
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB365750D0, unused: 8
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB36576310, unused: 4
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB36577570, unused: 3625
2021/04/16 07:31:50 [debug] 38#38: *83 close http connection: 3
2021/04/16 07:31:50 [debug] 38#38: *83 reusable connection: 0
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB36566AE0
2021/04/16 07:31:50 [debug] 38#38: *83 free: 00007FFB3654ED90, unused: 136
2021/04/16 07:31:50 [debug] 38#38: timer delta: 85
2021/04/16 07:31:50 [debug] 38#38: worker cycle
2021/04/16 07:31:50 [debug] 38#38: epoll timer: -1
*/


/*
2021/04/16 07:25:52 [debug] 21#21: epoll: fd:6 ev:0001 d:00007FFB365308C0
2021/04/16 07:25:52 [debug] 21#21: accept on 0.0.0.0:80, ready: 0
2021/04/16 07:25:52 [debug] 21#21: posix_memalign: 00007FFB3654E260:512 @16
2021/04/16 07:25:52 [debug] 21#21: *75 accept: 172.17.0.1:64688 fd:4
2021/04/16 07:25:52 [debug] 21#21: *75 event timer add: 4: 60000:140635127
2021/04/16 07:25:52 [debug] 21#21: *75 reusable connection: 1
2021/04/16 07:25:52 [debug] 21#21: *75 epoll add event: fd:4 op:1 ev:80002001
2021/04/16 07:25:52 [debug] 21#21: timer delta: 10820
2021/04/16 07:25:52 [debug] 21#21: worker cycle
2021/04/16 07:25:52 [debug] 21#21: epoll timer: 60000
2021/04/16 07:25:52 [debug] 21#21: epoll: fd:4 ev:0001 d:00007FFB36530B78
2021/04/16 07:25:52 [debug] 21#21: *75 http wait request handler
2021/04/16 07:25:52 [debug] 21#21: *75 malloc: 00007FFB36566060:1024
2021/04/16 07:25:52 [debug] 21#21: *75 recv: eof:0, avail:-1
2021/04/16 07:25:52 [debug] 21#21: *75 recv: fd:4 223 of 1024
2021/04/16 07:25:52 [debug] 21#21: *75 reusable connection: 0
2021/04/16 07:25:52 [debug] 21#21: *75 posix_memalign: 00007FFB3664F9A0:4096 @16
2021/04/16 07:25:52 [debug] 21#21: *75 http process request line
2021/04/16 07:25:52 [debug] 21#21: *75 http request line: "GET / HTTP/1.1"
2021/04/16 07:25:52 [debug] 21#21: *75 http uri: "/"
2021/04/16 07:25:52 [debug] 21#21: *75 http args: ""
2021/04/16 07:25:52 [debug] 21#21: *75 http exten: ""
2021/04/16 07:25:52 [debug] 21#21: *75 posix_memalign: 00007FFB365680F0:4096 @16
2021/04/16 07:25:52 [debug] 21#21: *75 http process request header line
2021/04/16 07:25:52 [debug] 21#21: *75 http header: "Sec-WebSocket-Version: 13"
2021/04/16 07:25:52 [debug] 21#21: *75 http header: "Sec-WebSocket-Key: HlKCHZXb9OrEY3UdAiDDSg=="
2021/04/16 07:25:52 [debug] 21#21: *75 http header: "Connection: Upgrade"
2021/04/16 07:25:52 [debug] 21#21: *75 http header: "Upgrade: websocket"
2021/04/16 07:25:52 [debug] 21#21: *75 http header: "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits"
2021/04/16 07:25:52 [debug] 21#21: *75 http header: "Host: localhost:8888"
2021/04/16 07:25:52 [debug] 21#21: *75 http header done
2021/04/16 07:25:52 [debug] 21#21: *75 event timer del: 4: 140635127
2021/04/16 07:25:52 [debug] 21#21: *75 generic phase: 0
2021/04/16 07:25:52 [debug] 21#21: *75 rewrite phase: 1
2021/04/16 07:25:52 [debug] 21#21: *75 test location: "/"
2021/04/16 07:25:52 [debug] 21#21: *75 using configuration "/"
2021/04/16 07:25:52 [debug] 21#21: *75 http cl:-1 max:1048576
2021/04/16 07:25:52 [debug] 21#21: *75 rewrite phase: 3
2021/04/16 07:25:52 [debug] 21#21: *75 post rewrite phase: 4
2021/04/16 07:25:52 [debug] 21#21: *75 generic phase: 5
2021/04/16 07:25:52 [debug] 21#21: *75 generic phase: 6
2021/04/16 07:25:52 [debug] 21#21: *75 generic phase: 7
2021/04/16 07:25:52 [debug] 21#21: *75 access phase: 8
2021/04/16 07:25:52 [debug] 21#21: *75 access phase: 9
2021/04/16 07:25:52 [debug] 21#21: *75 access phase: 10
2021/04/16 07:25:52 [debug] 21#21: *75 access phase: 11
2021/04/16 07:25:52 [debug] 21#21: *75 post access phase: 12
2021/04/16 07:25:52 [debug] 21#21: *75 generic phase: 13
2021/04/16 07:25:52 [debug] 21#21: *75 generic phase: 14
2021/04/16 07:25:52 [debug] 21#21: *75 http init upstream, client timer: 0
2021/04/16 07:25:52 [debug] 21#21: *75 epoll add event: fd:4 op:3 ev:80002005
2021/04/16 07:25:52 [debug] 21#21: *75 http script copy: "Authorization"
2021/04/16 07:25:52 [debug] 21#21: *75 http script copy: "Basic Z2FsbGFudC1oeXBhdGlhOmF0dGlyZS1kb2FibGUtc2F1Y3ktbmVwaGV3LW5lYXRseS1lY2FyZA=="
2021/04/16 07:25:52 [debug] 21#21: *75 http script copy: "Connection"
2021/04/16 07:25:52 [debug] 21#21: *75 http script copy: "upgrade"
2021/04/16 07:25:52 [debug] 21#21: *75 http script copy: "Upgrade"
2021/04/16 07:25:52 [debug] 21#21: *75 http script var: "websocket"
2021/04/16 07:25:52 [debug] 21#21: *75 http script copy: "Host"
2021/04/16 07:25:52 [debug] 21#21: *75 http script var: "ws-nd-366-962-854.int.chainstack.com"
2021/04/16 07:25:52 [debug] 21#21: *75 http script copy: ""
2021/04/16 07:25:52 [debug] 21#21: *75 http script copy: ""
2021/04/16 07:25:52 [debug] 21#21: *75 http proxy header: "Sec-WebSocket-Version: 13"
2021/04/16 07:25:52 [debug] 21#21: *75 http proxy header: "Sec-WebSocket-Key: HlKCHZXb9OrEY3UdAiDDSg=="
2021/04/16 07:25:52 [debug] 21#21: *75 http proxy header: "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits"
2021/04/16 07:25:52 [debug] 21#21: *75 http proxy header:
"GET / HTTP/1.1
Authorization: Basic Z2FsbGFudC1oeXBhdGlhOmF0dGlyZS1kb2FibGUtc2F1Y3ktbmVwaGV3LW5lYXRseS1lY2FyZA==
Connection: upgrade
Upgrade: websocket
Host: ws-nd-366-962-854.int.chainstack.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: HlKCHZXb9OrEY3UdAiDDSg==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits

"
2021/04/16 07:25:52 [debug] 21#21: *75 http cleanup add: 00007FFB36568B88
2021/04/16 07:25:52 [debug] 21#21: *75 get rr peer, try: 1
2021/04/16 07:25:52 [debug] 21#21: *75 stream socket 12
2021/04/16 07:25:52 [debug] 21#21: *75 epoll add connection: fd:12 ev:80002005
2021/04/16 07:25:52 [debug] 21#21: *75 connect to 20.68.184.228:443, fd:12 #76
2021/04/16 07:25:52 [debug] 21#21: *75 http upstream connect: -2
2021/04/16 07:25:52 [debug] 21#21: *75 posix_memalign: 00007FFB365FBBD0:128 @16
2021/04/16 07:25:52 [debug] 21#21: *75 event timer add: 12: 60000:140635127
2021/04/16 07:25:52 [debug] 21#21: *75 http finalize request: -4, "/?" a:1, c:2
2021/04/16 07:25:52 [debug] 21#21: *75 http request count:2 blk:0
2021/04/16 07:25:52 [debug] 21#21: timer delta: 0
2021/04/16 07:25:52 [debug] 21#21: worker cycle
2021/04/16 07:25:52 [debug] 21#21: epoll timer: 60000
2021/04/16 07:25:52 [debug] 21#21: epoll: fd:4 ev:0004 d:00007FFB36530B78
2021/04/16 07:25:52 [debug] 21#21: *75 http run request: "/?"
2021/04/16 07:25:52 [debug] 21#21: *75 http upstream check client, write event:1, "/"
2021/04/16 07:25:52 [debug] 21#21: timer delta: 1
2021/04/16 07:25:52 [debug] 21#21: worker cycle
2021/04/16 07:25:52 [debug] 21#21: epoll timer: 59999
2021/04/16 07:25:52 [debug] 21#21: epoll: fd:12 ev:0004 d:00007FFB36530C60
2021/04/16 07:25:52 [debug] 21#21: *75 http upstream request: "/?"
2021/04/16 07:25:52 [debug] 21#21: *75 http upstream send request handler
2021/04/16 07:25:52 [debug] 21#21: *75 malloc: 00007FFB365FB020:96
2021/04/16 07:25:52 [debug] 21#21: *75 set session: 0000000000000000
2021/04/16 07:25:52 [debug] 21#21: *75 tcp_nodelay
2021/04/16 07:25:52 [debug] 21#21: *75 SSL_do_handshake: -1
2021/04/16 07:25:52 [debug] 21#21: *75 SSL_get_error: 2
2021/04/16 07:25:52 [debug] 21#21: timer delta: 71
2021/04/16 07:25:52 [debug] 21#21: worker cycle
2021/04/16 07:25:52 [debug] 21#21: epoll timer: 59928
2021/04/16 07:25:53 [debug] 21#21: epoll: fd:12 ev:0005 d:00007FFB36530C60
2021/04/16 07:25:53 [debug] 21#21: *75 SSL handshake handler: 0
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_do_handshake: -1
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_get_error: 2
2021/04/16 07:25:53 [debug] 21#21: *75 SSL handshake handler: 1
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_do_handshake: -1
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_get_error: 2
2021/04/16 07:25:53 [debug] 21#21: timer delta: 76
2021/04/16 07:25:53 [debug] 21#21: worker cycle
2021/04/16 07:25:53 [debug] 21#21: epoll timer: 59852
2021/04/16 07:25:53 [debug] 21#21: epoll: fd:12 ev:0005 d:00007FFB36530C60
2021/04/16 07:25:53 [debug] 21#21: *75 SSL handshake handler: 0
2021/04/16 07:25:53 [debug] 21#21: *75 save session: 00007FFB36678AB0
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_do_handshake: 1
2021/04/16 07:25:53 [debug] 21#21: *75 SSL: TLSv1.2, cipher: "ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH Au=RSA Enc=AESGCM(128) Mac=AEAD"
2021/04/16 07:25:53 [debug] 21#21: *75 http upstream ssl handshake: "/?"
2021/04/16 07:25:53 [debug] 21#21: *75 http upstream send request
2021/04/16 07:25:53 [debug] 21#21: *75 http upstream send request body
2021/04/16 07:25:53 [debug] 21#21: *75 chain writer buf fl:1 s:344
2021/04/16 07:25:53 [debug] 21#21: *75 chain writer in: 00007FFB36568BC8
2021/04/16 07:25:53 [debug] 21#21: *75 malloc: 00007FFB36644020:80
2021/04/16 07:25:53 [debug] 21#21: *75 malloc: 00007FFB36611FB0:16384
2021/04/16 07:25:53 [debug] 21#21: *75 SSL buf copy: 344
2021/04/16 07:25:53 [debug] 21#21: *75 SSL to write: 344
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_write: 344
2021/04/16 07:25:53 [debug] 21#21: *75 chain writer out: 0000000000000000
2021/04/16 07:25:53 [debug] 21#21: *75 event timer del: 12: 140635127
2021/04/16 07:25:53 [debug] 21#21: *75 event timer add: 12: 60000:140635349
2021/04/16 07:25:53 [debug] 21#21: *75 http upstream process header
2021/04/16 07:25:53 [debug] 21#21: *75 malloc: 00007FFB36569360:4096
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_read: -1
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_get_error: 2
2021/04/16 07:25:53 [debug] 21#21: *75 http upstream request: "/?"
2021/04/16 07:25:53 [debug] 21#21: *75 http upstream dummy handler
2021/04/16 07:25:53 [debug] 21#21: timer delta: 74
2021/04/16 07:25:53 [debug] 21#21: worker cycle
2021/04/16 07:25:53 [debug] 21#21: epoll timer: 60000
2021/04/16 07:25:53 [debug] 21#21: epoll: fd:12 ev:0005 d:00007FFB36530C60
2021/04/16 07:25:53 [debug] 21#21: *75 http upstream request: "/?"
2021/04/16 07:25:53 [debug] 21#21: *75 http upstream process header
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_read: 302
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_read: -1
2021/04/16 07:25:53 [debug] 21#21: *75 SSL_get_error: 2
2021/04/16 07:25:53 [debug] 21#21: *75 http proxy status 101 "101 Switching Protocols"
2021/04/16 07:25:53 [debug] 21#21: *75 http proxy header: "Date: Fri, 16 Apr 2021 07:25:53 GMT"
2021/04/16 07:25:53 [debug] 21#21: *75 http proxy header: "Connection: upgrade"
2021/04/16 07:25:53 [debug] 21#21: *75 http proxy header: "Upgrade: websocket"
2021/04/16 07:25:53 [debug] 21#21: *75 http proxy header: "Sec-WebSocket-Accept: LCgayA7RJ8pqVfjPnxgqJTQIWXc="
2021/04/16 07:25:53 [debug] 21#21: *75 http proxy header: "Strict-Transport-Security: max-age=15724800; includeSubDomains"
2021/04/16 07:25:53 [debug] 21#21: *75 http proxy header: "Access-Control-Allow-Origin: *"
2021/04/16 07:25:53 [debug] 21#21: *75 http proxy header: "Access-Control-Allow-Credentials: true"
2021/04/16 07:25:53 [debug] 21#21: *75 http proxy header done
2021/04/16 07:25:53 [debug] 21#21: *75 HTTP/1.1 101 Switching Protocols
Server: nginx/1.19.6
Date: Fri, 16 Apr 2021 07:25:53 GMT
Connection: upgrade
Upgrade: websocket
Sec-WebSocket-Accept: LCgayA7RJ8pqVfjPnxgqJTQIWXc=
Strict-Transport-Security: max-age=15724800; includeSubDomains
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

2021/04/16 07:25:53 [debug] 21#21: *75 write new buf t:1 f:0 00007FFB36568FA8, pos 00007FFB36568FA8, size: 324 file: 0, size: 0
2021/04/16 07:25:53 [debug] 21#21: *75 http write filter: l:0 f:0 s:324
2021/04/16 07:25:53 [debug] 21#21: *75 tcp_nodelay
2021/04/16 07:25:53 [debug] 21#21: *75 posix_memalign: 00007FFB3656A5A0:4096 @16
2021/04/16 07:25:53 [debug] 21#21: *75 http output filter "/?"
2021/04/16 07:25:53 [notice] 7#7: signal 17 (SIGCHLD) received from 21
2021/04/16 07:25:53 [alert] 7#7: worker process 21 exited on signal 11
2021/04/16 07:25:53 [debug] 7#7: shmtx forced unlock
2021/04/16 07:25:53 [debug] 7#7: wake up, sigio 0
2021/04/16 07:25:53 [debug] 7#7: reap children
2021/04/16 07:25:53 [debug] 7#7: child: 0 21 e:0 t:1 d:0 r:1 j:0
2021/04/16 07:25:53 [debug] 7#7: channel 4:5
2021/04/16 07:25:53 [notice] 7#7: start worker process 22
2021/04/16 07:25:53 [debug] 7#7: sigsuspend
2021/04/16 07:25:53 [debug] 22#22: add cleanup: 00007FFB36632130
2021/04/16 07:25:53 [debug] 22#22: malloc: 00007FFB36A44B40:8
2021/04/16 07:25:53 [debug] 22#22: notify eventfd: 9
2021/04/16 07:25:53 [debug] 22#22: eventfd: 10
2021/04/16 07:25:53 [debug] 22#22: testing the EPOLLRDHUP flag: success
2021/04/16 07:25:53 [debug] 22#22: malloc: 00007FFB366470B0:6144
2021/04/16 07:25:53 [debug] 22#22: malloc: 00007FFB365308C0:118784
2021/04/16 07:25:53 [debug] 22#22: malloc: 00007FFB3656E8D0:49152
2021/04/16 07:25:53 [debug] 22#22: malloc: 00007FFB365238E0:49152
2021/04/16 07:25:53 [debug] 22#22: epoll add event: fd:6 op:1 ev:00002001
2021/04/16 07:25:53 [debug] 22#22: epoll add event: fd:11 op:1 ev:80002001
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 1
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 10
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 28
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 15
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 3
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 12
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 14
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 2
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 29
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 17
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 31
2021/04/16 07:25:53 [debug] 22#22: setting SA_RESTART for signal 13
2021/04/16 07:25:53 [debug] 22#22: epoll add event: fd:5 op:1 ev:00002001
2021/04/16 07:25:53 [debug] 22#22: setproctitle: "nginx: worker process"
2021/04/16 07:25:53 [debug] 22#22: worker cycle
2021/04/16 07:25:53 [debug] 22#22: epoll timer: -1

*/