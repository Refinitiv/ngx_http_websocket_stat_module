#include "ngx_http_websocket_stat_format.h"
#include "ngx_http_websocket_stat_frame_counter.h"
#include <assert.h>
#include <stdio.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

typedef struct {
    time_t ws_conn_start_time;
    ngx_frame_counter_t frame_counter;
} ngx_http_websocket_stat_ctx;

typedef struct {
    ngx_http_websocket_stat_ctx recv_ctx;
    ngx_http_websocket_stat_ctx send_ctx;
} ngx_http_websocket_stat_request_ctx;

typedef struct {
    char from_client : 1;
    ngx_http_websocket_stat_ctx *ws_ctx;

} template_ctx_s;

typedef ssize_t (*send_func)(ngx_connection_t *c, u_char *buf, size_t size);
send_func orig_recv, orig_send;

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
void get_core_var(ngx_http_request_t *r, const char *variable, char *buff, size_t size);

static void send_close_packet(ngx_connection_t *connection, int status,
                              const char *reason);

char CARET_RETURN = '\n';
const char *UNKNOWN_VAR = "???";

typedef struct ngx_http_websocket_srv_conf_s {
    int max_ws_age;
    ngx_flag_t enabled;
    compiled_template *log_template;
    compiled_template *log_send_message_template;
    compiled_template *log_recv_message_template;
    compiled_template *log_open_template;
    compiled_template *log_close_template;
    ngx_log_t *ws_log;
} ngx_http_websocket_srv_conf_t;

ssize_t (*orig_recv)(ngx_connection_t *c, u_char *buf, size_t size);

static ngx_command_t ngx_http_websocket_stat_commands[] = {
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

void
ws_do_log(compiled_template *template, ngx_http_request_t *r, void *ctx)
{
    ngx_http_websocket_srv_conf_t *srvcf = ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);
    
    if (!srvcf->enabled || !template || !template->compiled_template_str) return;
    char *log_line = apply_template(template, r, ctx);
    if (!log_line) return;
    ngx_write_fd(srvcf->ws_log->file->fd, log_line, strlen(log_line));
    ngx_write_fd(srvcf->ws_log->file->fd, &CARET_RETURN, sizeof(char));
    ngx_pfree(template->pool, log_line);
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
get_ws_log_template(template_ctx_s *ctx, ngx_http_websocket_srv_conf_t *srvcf) {
    ngx_http_websocket_stat_ctx *ws_ctx = ctx->ws_ctx;

    if (srvcf->log_template) {
        return srvcf->log_template;
    } else if (ws_ctx && ws_ctx->frame_counter.fragment_final && ws_ctx->frame_counter.current_frame_type < CLOSE) {
        return ctx->from_client ? srvcf->log_recv_message_template : srvcf->log_send_message_template;
    }
    return NULL;
}

// Packets that being send to a client
ssize_t
my_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_http_request_t *r = c->data;
    ngx_http_websocket_srv_conf_t *srvcf = ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);
    ngx_http_websocket_stat_request_ctx *request_ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);

    if (check_ws_age(request_ctx->send_ctx.ws_conn_start_time, r) != NGX_OK) {
        return NGX_ERROR;
    }

    template_ctx_s template_ctx;
    template_ctx.from_client = 0;
    template_ctx.ws_ctx = &request_ctx->send_ctx;

    int n = orig_send(c, buf, size);
    if (n <= 0) {
        ws_do_log(srvcf->log_close_template, r, &template_ctx);
        return n;
    }

    ssize_t sz = n;

    while (sz > 0) {
        if (frame_counter_process_message(&buf, &sz, &request_ctx->send_ctx.frame_counter)) {
            ws_do_log(get_ws_log_template(&template_ctx, srvcf), r, &template_ctx);
        }
    }

    return n;
}

// Packets received from a client
ssize_t
my_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_http_request_t *r = c->data;


    int n = orig_recv(c, buf, size);
    if (n <= 0) {
        return n;
    }
    if (r->srv_conf == NULL || r->ctx == NULL) {
        // Related to the bug when we calculated request right after reload and server config yet to load so it was NULL and caused crash.
        // Part r->ctx == NULL allows to prevents same problem in case module_ctx would be unloaded for some reason.
        // This message would would be not shown usually as all (or all i've seen) problematic requests had zero size
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "Websocket package was processed without billing due to issue CORE-4874.");
        return n;
    }
    ngx_http_websocket_srv_conf_t *srvcf = ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);
    ngx_http_websocket_stat_request_ctx *request_ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);

    ssize_t sz = n;
    template_ctx_s template_ctx;
    template_ctx.from_client = 1;
    template_ctx.ws_ctx = &request_ctx->recv_ctx;

    if (check_ws_age(request_ctx->recv_ctx.ws_conn_start_time, r) != NGX_OK) {
        return NGX_ERROR;
    }

    while (sz > 0) {
        if (frame_counter_process_message(&buf, &sz, &request_ctx->recv_ctx.frame_counter)) {
            ws_do_log(get_ws_log_template(&template_ctx, srvcf), r, &template_ctx);
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
            ngx_http_websocket_stat_request_ctx *ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_websocket_stat_request_ctx));
            if (!ctx) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_http_set_ctx(r, ctx, ngx_http_websocket_stat_module);
            template_ctx_s template_ctx;
            template_ctx.ws_ctx = &ctx->recv_ctx;
            ws_do_log(srvcf->log_open_template, r, &template_ctx);
            orig_recv = r->connection->recv;
            r->connection->recv = my_recv;
            orig_send = r->connection->send;
            r->connection->send = my_send;
            ctx->recv_ctx.ws_conn_start_time = ngx_time();
            ctx->send_ctx.ws_conn_start_time = ctx->recv_ctx.ws_conn_start_time;
        } else {
            ngx_http_websocket_stat_request_ctx *ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);
            template_ctx_s template_ctx;
            template_ctx.ws_ctx = &ctx->recv_ctx;
            ws_do_log(srvcf->log_close_template, r, &template_ctx);
        }
    }

    return ngx_http_next_body_filter(r, in);
}

void
ws_packet_type(ngx_http_request_t *r, void *data, char* buff, size_t size)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx) {
        snprintf(buff, size, UNKNOWN_VAR);
    } else {
        snprintf(buff, size, "%d", ctx->ws_ctx->frame_counter.current_frame_type);
    }
}

void
ws_packet_size(ngx_http_request_t *r, void *data, char* buff, size_t size)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx) {
        snprintf(buff, size, UNKNOWN_VAR);
    } else {
        snprintf(buff, size, "%lu", ctx->ws_ctx->frame_counter.current_payload_size);
    }
}

void
ws_message_size(ngx_http_request_t *r, void *data, char* buff, size_t size)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx) {
        snprintf(buff, size, UNKNOWN_VAR);
    } else {
        snprintf(buff, size, "%lu", ctx->ws_ctx->frame_counter.current_message_size);
    }
}

void
ws_packet_source(ngx_http_request_t *r, void *data, char *buff, size_t size)
{
    template_ctx_s *ctx = data;
    if (!ctx) {
        snprintf(buff, size, UNKNOWN_VAR);
    } else if (ctx->from_client) {
        snprintf(buff, size, "client");
    } else {
        snprintf(buff, size, "upstream");
    }
}

void
get_core_var(ngx_http_request_t *r, const char *variable, char *buff, size_t size)
{
    ngx_int_t key = 0;
    ngx_http_variable_value_t *vv;
    ngx_str_t var;
    var.data = (u_char *)variable;
    var.len = strlen(variable);
    key = ngx_hash_strlow(var.data, var.data, var.len);

    // while (*variable != '\0')
    //     key = ngx_hash(key, *(variable++));

    vv = ngx_http_get_variable(r, &var, key);
    snprintf(buff, size, (const char*)vv->data);
}

void
ws_connection_age(ngx_http_request_t *r, void *data, char *buff, size_t size)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx) {
        snprintf(buff, size, UNKNOWN_VAR);
    } else {
        snprintf(buff, size, "%lu", ngx_time() - ctx->ws_ctx->ws_conn_start_time);
    }
}

void
local_time(ngx_http_request_t *r, void *data, char *buff, size_t size)
{
    snprintf(buff, size, (char*)ngx_cached_http_time.data);
}

void
remote_ip(ngx_http_request_t *r, void *data, char *buff, size_t size)
{
    snprintf(buff, size, (char*)r->connection->addr_text.data);
}

void
upstream_addr(ngx_http_request_t *r, void *data, char *buff, size_t size)
{
    if (!r->upstream_states || r->upstream_states->nelts == 0) {
        snprintf(buff, size, UNKNOWN_VAR);
    } else {
        ngx_http_upstream_state_t *state = r->upstream_states->elts;
        snprintf(buff, size, (const char *)state->peer->data);
    }
}

#define GEN_CORE_GET_FUNC(fname, var)                                          \
    void fname(ngx_http_request_t *r, void *data, char *buff, size_t size)     \
    {                                                                          \
        get_core_var(r, var, buff, size);                                           \
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
    {VAR_NAME("$remote_user"), 60, remote_user},
    {VAR_NAME("$remote_addr"), 60, remote_addr},
    {VAR_NAME("$remote_port"), 60, remote_port},
    {VAR_NAME("$server_addr"), 60, server_addr},
    {VAR_NAME("$server_port"), 60, server_port},
    // TODO: Delete this since its duplicating $remote_add
    {VAR_NAME("$remote_ip"), sizeof("000.000.000.000") - 1, remote_ip},
    {NULL, 0, 0, NULL}};

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
    } else if (strcmp((char *)args[1].data, "server") == 0) {
        srvcf->log_send_message_template =
            compile_template((char *)args[2].data, variables, cf->pool);
        return NGX_CONF_OK;
    } else if (strcmp((char *)args[1].data, "client") == 0) {
        srvcf->log_recv_message_template =
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

    if (!srvcf->ws_log || !srvcf->ws_log->file)
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

    srvcf->max_ws_age = NGX_CONF_UNSET;
    srvcf->enabled = NGX_CONF_UNSET;
    srvcf->log_template = NGX_CONF_UNSET_PTR;
    srvcf->log_send_message_template = NGX_CONF_UNSET_PTR;
    srvcf->log_recv_message_template = NGX_CONF_UNSET_PTR;
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

    ngx_conf_merge_value(conf->max_ws_age, prev->max_ws_age, -1);
    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_ptr_value(conf->log_template, prev->log_template, NULL);
    ngx_conf_merge_ptr_value(conf->log_send_message_template, prev->log_send_message_template, NULL);
    ngx_conf_merge_ptr_value(conf->log_recv_message_template, prev->log_recv_message_template, NULL);
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
send_close_packet(ngx_connection_t *connection, int status, const char *reason)
{
    // send close packet
    char cbuf[256];
    memset(cbuf, 0, sizeof(cbuf));
    cbuf[0] = 0x88; // Fin, Close : 1000 1000
    int rlen = strlen(reason);
    const int max_payload_len = 125; // wo extended len
    rlen = (rlen > max_payload_len) ? max_payload_len : rlen;
    const int cbuflen = rlen + 2;   // add 2b status
    cbuf[1] = cbuflen;                 // Payload Len: 0... ....
    cbuf[2] = 0xFF & (status >> 8); // Status MSB : .... .... (Big Endian)
    cbuf[3] = 0xFF & status;        // Status LSB : .... ....
    memcpy(&cbuf[4], reason, rlen);
    orig_send(connection, (unsigned char *)cbuf, cbuflen);
}

unsigned char hash[SHA_DIGEST_LENGTH];

static ngx_int_t
ngx_http_websocket_stat_configure(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_websocket_stat_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_websocket_stat_body_filter;

    return NGX_OK;
}
