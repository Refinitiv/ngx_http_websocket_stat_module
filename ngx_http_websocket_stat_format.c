#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ngx_http_websocket_stat_format.h"

const char PLACE_HOLDER_CHR = 'X';

const char *HTTP_VAR = "$http_";
size_t HTTP_VAR_LEN = sizeof("$http_") - 1;

template_variable null_variable = {NULL, 0, 0, NULL};
const char *http_header_var(ngx_http_request_t *r, void *data);
template_variable header_variable = {NULL, 0, 50, http_header_var};

typedef struct {
  const template_variable *variable;
  size_t pos;
  int http_hdr;
  int orig_pos;
} variable_occurance;

typedef struct {
  const char *template;
  variable_occurance *occ;
} http_hdr_coccurance_ctx;

static int compare_occurance(const void *_first, const void *_second) {
  const variable_occurance **first = (const variable_occurance **)_first;
  const variable_occurance **second = (const variable_occurance **)_second;
  assert((*first)->orig_pos != (*second)->orig_pos);
  return (*first)->orig_pos < (*second)->orig_pos ? -1 : 1;
}

#ifdef TEST
ngx_array_t *ngx_array_create(void *pool, size_t size, size_t el_size) {
  ngx_array_t *res = malloc(sizeof(ngx_array_t));
  res->nelts = 0;
  res->elts = malloc(100 * el_size);
  res->el_size = el_size;
  return res;
}

void *ngx_array_push(ngx_array_t *array) {
  return array->elts + array->nelts++ * array->el_size;
}
#endif
void insert_occurance(const template_variable *var, size_t pos,
                      compiled_template *template_cmlp, int http_hdr_len) {
  variable_occurance **oc = ngx_array_push(template_cmlp->variable_occurances);
  *oc = ngx_palloc(template_cmlp->pool, sizeof(variable_occurance));
  (*oc)->variable = var;
  (*oc)->orig_pos = pos;
  (*oc)->http_hdr = http_hdr_len;
}

static void locate_http_variables(compiled_template *template_cmlp) {
  const char *occurance = template_cmlp->template;
  while (1) {
    occurance = strstr(occurance, HTTP_VAR);
    if (!occurance)
      break;
    int pos = occurance - template_cmlp->template;
    int len = 0;
    occurance += HTTP_VAR_LEN;
    while (islower(*occurance) || *occurance == '_' || *occurance == '-') {
      occurance++;
      len++;
    }
    insert_occurance(&header_variable, pos, template_cmlp, len);
  }
}

static void find_variables(const char *template,
                           compiled_template *template_cmlp) {
  int i = 0;
  const template_variable *variables = template_cmlp->variables;
  locate_http_variables(template_cmlp);
  while (1) {
    if (!memcmp(&variables[i], &null_variable, sizeof(template_variable)))
      break;
    const char *occurance = template;
    while (1) {
      occurance = strstr(occurance, variables[i].name);
      if (occurance) {
        insert_occurance(variables + i, occurance - template, template_cmlp, 0);
        occurance += variables[i].name_len;
      } else {
        break;
      }
    }
    i++;
  }
  qsort(template_cmlp->variable_occurances->elts,
        template_cmlp->variable_occurances->nelts, sizeof(variable_occurance *),
        compare_occurance);
}

size_t estimate_size(compiled_template *template_cmpl) {
  size_t orig_size = strlen(template_cmpl->template);
  int size_dif = 0;
  for (unsigned int i = 0; i < template_cmpl->variable_occurances->nelts; i++) {
    variable_occurance *occ =
        ((variable_occurance **)template_cmpl->variable_occurances->elts)[i];
    if (occ->http_hdr) {
      size_dif += occ->variable->len - (occ->http_hdr + HTTP_VAR_LEN);
    } else {
      size_dif += occ->variable->len - occ->variable->name_len;
    }
  }
  return orig_size + size_dif;
}

void _compile_template(compiled_template *template_cmpl) {

  if (template_cmpl->variable_occurances->nelts == 0) {
    template_cmpl->compiled_template_str = template_cmpl->template;
    template_cmpl->max_result_len =
        strlen(template_cmpl->compiled_template_str);
    return;
  }

  size_t size = estimate_size(template_cmpl);
  template_cmpl->compiled_template_str =
      ngx_palloc(template_cmpl->pool, size + 1);
  char *result_ptr = template_cmpl->compiled_template_str;
  const char *template_ptr = template_cmpl->template;
  size_t template_len = strlen(template_cmpl->template);

  for (unsigned int i = 0; i < template_cmpl->variable_occurances->nelts; i++) {
    variable_occurance *occ =
        ((variable_occurance **)template_cmpl->variable_occurances->elts)[i];
    int s = occ->orig_pos - (template_ptr - template_cmpl->template);
    memcpy(result_ptr, template_ptr, s);
    template_ptr += s;
    result_ptr += s;
    memset(result_ptr, PLACE_HOLDER_CHR, occ->variable->len);
    occ->pos = result_ptr - template_cmpl->compiled_template_str;
    result_ptr += occ->variable->len;
    template_ptr += occ->http_hdr ? (occ->http_hdr + HTTP_VAR_LEN)
                                  : occ->variable->name_len;
  }
  int s = (template_len - (template_ptr - template_cmpl->template));
  memcpy(result_ptr, template_ptr, s);
  result_ptr += s;
  *result_ptr = '\0';
  template_cmpl->max_result_len = strlen(template_cmpl->compiled_template_str);
}

void _remove_placeholder_chars(char *str) {
  char *result_ptr = str;
  while (*str != '\0') {
    if (*str != PLACE_HOLDER_CHR) {
      *result_ptr = *str;
      result_ptr++;
    }
    str++;
  }
  *result_ptr = '\0';
}

char *apply_template(compiled_template *template_cmpl, ngx_http_request_t *r,
                     void *data) {
  char *result = malloc(strlen(template_cmpl->compiled_template_str) + 1);
  strcpy(result, template_cmpl->compiled_template_str);
  for (unsigned int i = 0; i < template_cmpl->variable_occurances->nelts; i++) {
    variable_occurance *occ =
        ((variable_occurance **)template_cmpl->variable_occurances->elts)[i];
    if (!occ->http_hdr) {
      const char *op = occ->variable->operation(r, data);
      size_t len = strlen(op);
      memcpy(result + occ->pos, op,
             occ->variable->len < len ? occ->variable->len : len);
    } else {
      http_hdr_coccurance_ctx ctx = {template_cmpl->template, occ};
      const char *op = occ->variable->operation(r, &ctx);
      size_t len = strlen(op);
      memcpy(result + occ->pos, op,
             occ->variable->len < len ? occ->variable->len : len);
    }
  }
  _remove_placeholder_chars(result);
  return result;
}

int compare_hdr(const char *hdr, size_t hdr_len, const char *template) {
  while (hdr_len) {
    if (*hdr == '_' && *template != ' ')
      return 0;
    if (tolower(*hdr) != tolower(*template))
      return 0;
    hdr++;
    template ++;
    hdr_len--;
  }
  return 1;
}

const char *http_header_var(ngx_http_request_t *r, void *data) {
#ifndef TEST
  ngx_list_part_t *part;
  ngx_table_elt_t *header;
  part = &r->headers_in.headers.part;
  header = part->elts;
  http_hdr_coccurance_ctx *ctx = data;
  int i = part->nelts - 1;
  while (1) {
    if (compare_hdr((char *)header[i].key.data, ctx->occ->http_hdr,
                    ctx->template + ctx->occ->orig_pos + HTTP_VAR_LEN))
      return (const char *)header[i].value.data;
    if (--i < 0) {
      if (!part->next)
        break;
      part = part->next;
      header = part->elts;
      i = part->nelts - 1;
    }
  }
#endif

  return "???";
}

compiled_template *compile_template(ngx_str_t *template,
                                    const template_variable *variables,
                                    ngx_pool_t *pool) {
  compiled_template *templ = ngx_palloc(pool, sizeof(compiled_template));
  templ->variable_occurances =
      ngx_array_create(pool, 10, sizeof(variable_occurance *));
  templ->variables = variables;
  templ->template = ngx_palloc(pool, template->len + 1);
  memcpy(templ->template, template->data, template->len);
  templ->template[template->len] = '\0';
  templ->pool = pool;
  find_variables(templ->template, templ);
  _compile_template(templ);
  return templ;
}
