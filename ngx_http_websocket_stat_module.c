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
    char from_client : 1;
    ngx_http_websocket_stat_ctx *ws_ctx;

} template_ctx_s;

typedef ssize_t (*send_func)(ngx_connection_t *c, u_char *buf, size_t size);
send_func orig_recv, orig_send;

static char *ngx_http_websocket_max_conn_setup(ngx_conf_t *cf,
                                               ngx_command_t *cmd, void *conf);
static char *ngx_http_websocket_max_conn_age(ngx_conf_t *cf, ngx_command_t *cmd,
                                             void *conf);
static char *ngx_http_websocket_log_format(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);
static char *ngx_http_websocket_log_enabled(ngx_conf_t *cf, ngx_command_t *cmd,
                                            void *conf);
static char *ngx_http_websocket_log_file(ngx_conf_t *cf, ngx_command_t *cmd,
                                         void *conf);
static ngx_int_t ngx_http_websocket_stat_configure(ngx_conf_t *cf);

static void *ngx_http_websocket_stat_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_websocket_stat_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
const char *get_core_var(ngx_http_request_t *r, const char *variable);

static void send_close_packet(ngx_connection_t *connection, int status,
                              const char *reason);

static ngx_atomic_t *ngx_websocket_stat_active;

char CARET_RETURN = '\n';
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

typedef struct ngx_http_websocket_srv_conf_s {
    int max_ws_connections;
    int max_ws_age;
    ngx_flag_t enabled;
    compiled_template *log_template;
    compiled_template *log_message_template;
    compiled_template *log_open_template;
    compiled_template *log_close_template;
    ngx_log_t *ws_log;
} ngx_http_websocket_srv_conf_t;

ssize_t (*orig_recv)(ngx_connection_t *c, u_char *buf, size_t size);

static ngx_command_t ngx_http_websocket_stat_commands[] = {
    {ngx_string("ws_max_connections"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_websocket_max_conn_setup, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL},
    {ngx_string("ws_conn_age"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_websocket_max_conn_age, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL},
    {ngx_string("ws_log_enabled"), NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_http_websocket_log_enabled, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL},
    {ngx_string("ws_log"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_websocket_log_file, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL},
    {ngx_string("ws_log_format"), NGX_HTTP_SRV_CONF | NGX_CONF_1MORE,
     ngx_http_websocket_log_format, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL},
    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_websocket_stat_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_websocket_stat_configure, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    ngx_http_websocket_stat_create_srv_conf, /* create server configuration */
    ngx_http_websocket_stat_merge_srv_conf, /* merge server configuration */

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

void
ws_do_log(compiled_template *template, ngx_http_request_t *r, void *ctx)
{
    ngx_http_websocket_srv_conf_t *srvcf = ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);
    
    if (!srvcf->enabled || !template || !template->compiled_template_str) return;
    char *log_line = apply_template(template, r, ctx);
    if (!log_line) return;
    ngx_write_fd(srvcf->ws_log->file->fd, log_line, strlen(log_line));
    ngx_write_fd(srvcf->ws_log->file->fd, &CARET_RETURN, sizeof(char));
    free(log_line);
}

static int
check_ws_age(time_t conn_start_time, ngx_http_request_t *r)
{
    ngx_http_websocket_srv_conf_t *srvcf = ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);
    if (srvcf->max_ws_age > 0 &&
        ngx_time() - conn_start_time >= srvcf->max_ws_age) {
        send_close_packet(r->connection, 4001, "Connection is Aged");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static compiled_template *
get_ws_log_template(ngx_http_websocket_stat_ctx *ctx, ngx_http_websocket_srv_conf_t *srvcf) {
    if (srvcf->log_template) {
        return srvcf->log_template;
    } else if (ctx->frame_counter.fragment_final && ctx->frame_counter.current_frame_type < CLOSE) {
        return srvcf->log_message_template;
    }

    return NULL;
}

// Packets that being send to a client
ssize_t
my_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_http_request_t *r = c->data;
    ngx_http_websocket_srv_conf_t *srvcf =
        ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);
    ngx_http_websocket_stat_ctx *ctx;
    ssize_t sz = size;
    u_char *buffer = buf;
    ngx_http_websocket_stat_statistic_t *frame_counter = &frames_out;
    ngx_atomic_fetch_add(frame_counter->total_size, sz);

    ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);
    if (check_ws_age(ctx->ws_conn_start_time, r) != NGX_OK) {
        return NGX_ERROR;
    }
    template_ctx_s template_ctx;
    template_ctx.from_client = 0;
    template_ctx.ws_ctx = ctx;
    while (sz > 0) {
        if (frame_counter_process_message(&buffer, &sz,
                                          &(ctx->frame_counter))) {
            ngx_atomic_fetch_add(frame_counter->frames, 1);
            ngx_atomic_fetch_add(frame_counter->total_payload_size,
                                 ctx->frame_counter.current_payload_size);
            ws_do_log(get_ws_log_template(ctx, srvcf), r, &template_ctx);
        }
    }

    int n = orig_send(c, buf, size);
    if (n < 0) {
        if(!ngx_atomic_cmp_set(ngx_websocket_stat_active, 0, 0)){
          ngx_atomic_fetch_add(ngx_websocket_stat_active, -1);
          ws_do_log(srvcf->log_close_template, r, &template_ctx);
        }
    }
    return n;
}

// Packets received from a client
ssize_t
my_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_http_request_t *r = c->data;
    ngx_http_websocket_srv_conf_t *srvcf =
        ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);
    ngx_http_websocket_stat_ctx *ctx =
        ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);
    ngx_http_websocket_stat_statistic_t *frame_counter = &frames_in;
    template_ctx_s template_ctx;
    template_ctx.from_client = 1;
    template_ctx.ws_ctx = ctx;

    int n = orig_recv(c, buf, size);
    if (n <= 0) {
        return n;
    }

    ssize_t sz = n;

    if (check_ws_age(ctx->ws_conn_start_time, r) != NGX_OK) {
        return NGX_ERROR;
    }
    ngx_atomic_fetch_add(frame_counter->total_size, n);
    while (sz > 0) {
        if (frame_counter_process_message(&buf, &sz, &ctx->frame_counter)) {
            ngx_atomic_fetch_add(frame_counter->frames, 1);
            ngx_atomic_fetch_add(frame_counter->total_payload_size,
                                 ctx->frame_counter.current_payload_size);
            ws_do_log(get_ws_log_template(ctx, srvcf), r, &template_ctx);
        }
    }

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
    if (!r->upstream)
        return ngx_http_next_body_filter(r, in);

    ngx_http_websocket_srv_conf_t *srvcf =
        ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);

    if (!srvcf->enabled)
        return ngx_http_next_body_filter(r, in);

    if (r->headers_in.upgrade) {
        if (r->upstream->peer.connection) {
            // connection opened
            ngx_http_websocket_stat_ctx *ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_websocket_stat_ctx));
            if (ctx == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            const char *request_id_str = get_core_var(r, "request_id");
            ctx->connection_id.data = ngx_pcalloc(r->pool, UID_LENGTH + 1);
            ctx->connection_id.len = UID_LENGTH;
            memcpy(ctx->connection_id.data, request_id_str, UID_LENGTH + 1);

            ngx_http_set_ctx(r, ctx, ngx_http_websocket_stat_module);
            template_ctx_s template_ctx;
            template_ctx.ws_ctx = ctx;
            ws_do_log(srvcf->log_open_template, r, &template_ctx);
            orig_recv = r->connection->recv;
            r->connection->recv = my_recv;
            orig_send = r->connection->send;
            r->connection->send = my_send;
            ngx_atomic_fetch_add(ngx_websocket_stat_active, 1);
            ctx->ws_conn_start_time = ngx_time();
        } else {
            if(!ngx_atomic_cmp_set(ngx_websocket_stat_active, 0, 0)){
              ngx_atomic_fetch_add(ngx_websocket_stat_active, -1);
              ngx_http_websocket_stat_ctx *ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);
              template_ctx_s template_ctx;
              template_ctx.ws_ctx = ctx;
              ws_do_log(srvcf->log_close_template, r, &template_ctx);
            }
        }
    }

    return ngx_http_next_body_filter(r, in);
}

char buff[100];

const char *
ws_packet_type(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx)
        return UNKNOWN_VAR;
    sprintf(buff, "%d", ctx->ws_ctx->frame_counter.current_frame_type);
    return buff;
}

const char *
ws_packet_size(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx)
        return UNKNOWN_VAR;
    sprintf(buff, "%lu", ctx->ws_ctx->frame_counter.current_payload_size);
    return (char *)buff;
}

const char *
ws_message_size(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx)
        return UNKNOWN_VAR;
    sprintf(buff, "%lu", ctx->ws_ctx->frame_counter.current_message_size);
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
    {VAR_NAME("$ws_message_size"), NGX_SIZE_T_LEN, ws_message_size},
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

static char *
ngx_http_websocket_max_conn_setup(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf)
{
    ngx_http_websocket_srv_conf_t *srvcf = conf;
    ngx_str_t *args = cf->args->elts;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Wrong argument number");
        return NGX_CONF_ERROR;
    }

    srvcf->max_ws_connections = atoi((char *)args[1].data);

    return NGX_CONF_OK;
}

static char *
ngx_http_websocket_max_conn_age(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_websocket_srv_conf_t *srvcf = conf;
    ngx_str_t *args = cf->args->elts;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Wrong argument number");
        return NGX_CONF_ERROR;
    }

    ngx_int_t timeout;
    timeout = ngx_parse_time(&args[1], 1);
    if (timeout == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    srvcf->max_ws_age = timeout;

    return NGX_CONF_OK;
}

static char *
ngx_http_websocket_log_enabled(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_websocket_srv_conf_t *srvcf = conf;
    ngx_str_t *args = cf->args->elts;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Wrong argument number");
        return NGX_CONF_ERROR;
    }

    if (strcmp((char *)args[1].data, "on") == 0) {
        srvcf->enabled = 1;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_websocket_log_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_websocket_srv_conf_t *srvcf = conf;    
    ngx_str_t *args = cf->args->elts;
    if (cf->args->nelts != 2 && cf->args->nelts != 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Wrong argument number");
        return NGX_CONF_ERROR;
    }
    if (cf->args->nelts == 2) {
        srvcf->log_template =
            compile_template((char *)args[1].data, variables, cf->pool);
        return NGX_CONF_OK;
    }
    if (strcmp((char *)args[1].data, "close") == 0) {
        srvcf->log_close_template =
            compile_template((char *)args[2].data, variables, cf->pool);
        return NGX_CONF_OK;
    } else if (strcmp((char *)args[1].data, "open") == 0) {
        srvcf->log_open_template =
            compile_template((char *)args[2].data, variables, cf->pool);
        return NGX_CONF_OK;
    } else if (strcmp((char *)args[1].data, "message") == 0) {
        srvcf->log_message_template =
            compile_template((char *)args[2].data, variables, cf->pool);
        return NGX_CONF_OK;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Unknown log format keyword\"%V\"",
                           (ngx_str_t *)&args[1]);
        return NGX_CONF_ERROR;
    }
}

static void init_ws_log_file(ngx_conf_t *cf, ngx_http_websocket_srv_conf_t *srvcf, ngx_str_t *file_path) {
    srvcf->ws_log = ngx_pcalloc(cf->pool, sizeof(ngx_log_t));

    if (!srvcf->ws_log)
        return;

    srvcf->ws_log->log_level = NGX_LOG_NOTICE;
    srvcf->ws_log->file = ngx_conf_open_file(cf->cycle, file_path);
}

static char *
ngx_http_websocket_log_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_websocket_srv_conf_t *srvcf = conf;    
    ngx_str_t *args = cf->args->elts;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Wrong argument number");
        return NGX_CONF_ERROR;
    }
    
    init_ws_log_file(cf, srvcf, &args[1]);

    if (!srvcf->ws_log)
        return NGX_CONF_ERROR;

    if (!srvcf->ws_log->file)
        return NGX_CONF_ERROR;

    return NGX_CONF_OK;
}

static void *
ngx_http_websocket_stat_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_websocket_srv_conf_t *srvcf;

    srvcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_websocket_srv_conf_t));
    if (!srvcf) {
        return NULL;
    }

    srvcf->max_ws_connections = NGX_CONF_UNSET;
    srvcf->max_ws_age = NGX_CONF_UNSET;
    srvcf->enabled = NGX_CONF_UNSET;
    srvcf->log_template = NGX_CONF_UNSET_PTR;
    srvcf->log_message_template = NGX_CONF_UNSET_PTR;
    srvcf->log_close_template = NGX_CONF_UNSET_PTR;
    srvcf->log_open_template = NGX_CONF_UNSET_PTR;
    srvcf->ws_log = NGX_CONF_UNSET_PTR;

    return srvcf;
}

static char *
ngx_http_websocket_stat_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_websocket_srv_conf_t *prev = parent;
    ngx_http_websocket_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->max_ws_connections, prev->max_ws_connections, -1);
    ngx_conf_merge_value(conf->max_ws_age, prev->max_ws_age, -1);
    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_ptr_value(conf->log_template, prev->log_template, NULL);
    ngx_conf_merge_ptr_value(conf->log_message_template, prev->log_message_template, NULL);
    ngx_conf_merge_ptr_value(conf->log_close_template, prev->log_close_template, NULL);
    ngx_conf_merge_ptr_value(conf->log_open_template, prev->log_open_template, NULL);
    ngx_conf_merge_ptr_value(conf->ws_log, prev->ws_log, NULL);

    if (conf->enabled && !conf->ws_log) {
        init_ws_log_file(cf, conf, &cf->cycle->error_log);

        if (!conf->ws_log || !conf->ws_log->file)
            return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
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
    char cbuf[256];
    memset(cbuf, 0, sizeof(cbuf));
    cbuf[0] = 0x88; // Fin, Close : 1000 1000
    int rlen = strlen(reason);
    rlen += 2;                       // add 2b status
    const int max_payload_len = 125; // wo extended len
    rlen = (rlen > max_payload_len) ? max_payload_len : rlen;
    cbuf[1] = rlen;                 // Payload Len: 0... ....
    cbuf[2] = 0xFF & (status >> 8); // Status MSB : .... .... (Big Endian)
    cbuf[3] = 0xFF & status;        // Status LSB : .... ....
    memcpy(&cbuf[4], reason, rlen);
    int cbuflen = rlen + 2;
    orig_send(connection, (unsigned char *)cbuf, cbuflen);
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
    ngx_http_websocket_srv_conf_t *srvcf = ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);
    if (!srvcf) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (srvcf->max_ws_connections > 0 &&
        srvcf->max_ws_connections == (int)*ngx_websocket_stat_active) {
        ngx_table_elt_t *upgrade_hdr = find_header_in(r, "Upgrade");
        if (!upgrade_hdr ||
            strcasecmp((char *)upgrade_hdr->value.data, "websocket") != 0) {
            // This is not a websocket conenction, allow it.
            return NGX_OK;
        }
        ngx_table_elt_t *hdr = find_header_in(r, kWsKey);
        if (!hdr || hdr->value.len != KEY_SIZE) {
            // Request should contain a valid Sec-Webscoket-Key header.
            return NGX_HTTP_BAD_REQUEST;
        }
        complete_ws_handshake(r->connection, (const char *)hdr->value.data);
        send_close_packet(r->connection, 1013, "Try Again Later");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_websocket_stat_configure(ngx_conf_t *cf)
{
    allocate_counters();

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_websocket_stat_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_websocket_stat_body_filter;

    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_websocket_request_handler;

    return NGX_OK;
}
