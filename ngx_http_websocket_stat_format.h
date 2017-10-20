#ifndef _NGX_HTTP_WEBSOCKET_FMT
#define _NGX_HTTP_WEBSOCKET_FMT

// typedef const char (*template_op)(ngx_http_request_t *r);

typedef char *(*template_op)();

typedef struct {
  char *name;
  size_t name_len;
  size_t len;
  template_op operation;
} template_variable;

char *no_fuck();

#define VAR_NAME(name) name, sizeof(name) - 1

typedef struct {
  const template_variable *variable;
  size_t pos;
} variable_occurance;

typedef struct {
  ngx_array_t *variable_occurances;
  char *compiled_template_str;
  const template_variable *variables;
  const char *template;
  ngx_pool_t *pool;
} compiled_template;

compiled_template *compile_template(const char *template,
                                    template_variable *variables,
                                    ngx_pool_t *pool);
char *apply_template(compiled_template *template_cmpl);
#endif
