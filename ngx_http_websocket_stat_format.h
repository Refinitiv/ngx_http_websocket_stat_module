#ifndef _NGX_HTTP_WEBSOCKET_FMT
#define _NGX_HTTP_WEBSOCKET_FMT

#include <ngx_core.h>
#include <ngx_http.h>

// typedef const char (*template_op)(ngx_http_request_t *r);

typedef const char *(*template_op)(ngx_http_request_t *r, void *data);

typedef struct {
  char *name;
  size_t name_len;
  size_t len;
  template_op operation;
} template_variable;

#define VAR_NAME(name) name, sizeof(name) - 1

typedef struct {
  ngx_array_t *variable_occurances;
  char *compiled_template_str;
  size_t max_result_len;
  const template_variable *variables;
  char *template;
  ngx_pool_t *pool;
} compiled_template;

// Public functions
compiled_template *compile_template(ngx_str_t *template,
                                    const template_variable *variables,
                                    ngx_pool_t *pool);
char *apply_template(compiled_template *template_cmpl, ngx_http_request_t *r,
                     void *data);
#endif
