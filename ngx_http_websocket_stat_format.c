#include <assert.h>
#include <ngx_core.h>
#include <stdlib.h>

#include "ngx_http_websocket_stat_format.h"

template_variable null_variable = {NULL, 0, 0, NULL};

const template_variable variables[] = {
    {VAR_NAME("fuck"), sizeof("sd") - 1, no_fuck},
    {VAR_NAME("hate"), sizeof("ss") - 1, no_fuck},
    {VAR_NAME("this"), sizeof("sd") - 1, no_fuck},
    {VAR_NAME("nginx"), sizeof("sd") - 1, no_fuck},
    {NULL, 0, 0, NULL}};

static int compare_occurance(const void *_first, const void *_second) {
  const variable_occurance **first = (const variable_occurance **)_first;
  const variable_occurance **second = (const variable_occurance **)_second;
  assert((*first)->pos != (*second)->pos);
  return (*first)->pos < (*second)->pos ? -1 : 1;
}

char *no_fuck() { return "df"; }

void insert_occurance(const template_variable *var, size_t pos,
                      compiled_template *template_cmlp) {
  variable_occurance **oc = ngx_array_push(template_cmlp->variable_occurances);
  *oc = ngx_palloc(template_cmlp->pool, sizeof(variable_occurance));
  (*oc)->variable = var;
  (*oc)->pos = pos;
}

static void find_variables(const char *template,
                           compiled_template *template_cmlp) {
  int i = 0;
  const template_variable *variables = template_cmlp->variables;
  while (1) {
    if (!memcmp(&variables[i], &null_variable, sizeof(template_variable)))
      break;
    const char *occurance = template;
    while (1) {
      occurance = strstr(occurance, variables[i].name);
      if (occurance) {
        insert_occurance(variables + i, occurance - template, template_cmlp);
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
    size_dif += occ->variable->len - occ->variable->name_len;
  }
  return orig_size + size_dif;
}

void _compile_template(compiled_template *template_cmpl) {

  if (template_cmpl->variable_occurances->nelts == 0)
    return;

  size_t size = estimate_size(template_cmpl);
  template_cmpl->compiled_template_str =
      ngx_palloc(template_cmpl->pool, size + 1);
  char *result_ptr = template_cmpl->compiled_template_str;
  const char *template_ptr = template_cmpl->template;

  for (unsigned int i = 0; i < template_cmpl->variable_occurances->nelts; i++) {
    variable_occurance *occ =
        ((variable_occurance **)template_cmpl->variable_occurances->elts)[i];
    int s = occ->pos - (template_ptr - template_cmpl->template);
    memcpy(result_ptr, template_ptr, s);
    template_ptr += s;
    result_ptr += s;
    memset(result_ptr, 'X', occ->variable->len);
    occ->pos = result_ptr - template_cmpl->compiled_template_str;
    result_ptr += occ->variable->len;
    template_ptr += occ->variable->name_len;
  }
  int s = (template_ptr - template_cmpl->template);
  memcpy(result_ptr, template_ptr, s);
  result_ptr += s;
  *result_ptr = '\0';
}

char *apply_template(compiled_template *template_cmpl) {
  char *result = malloc(strlen(template_cmpl->compiled_template_str) + 1);
  strcpy(result, template_cmpl->compiled_template_str);
  for (unsigned int i = 0; i < template_cmpl->variable_occurances->nelts; i++) {
    variable_occurance *occ =
        ((variable_occurance **)template_cmpl->variable_occurances->elts)[i];
    char *op = occ->variable->operation();
    memcpy(result + occ->pos, op, occ->variable->len);
  }
  return result;
}

compiled_template *compile_template(const char *template,
                                    template_variable *variables,
                                    ngx_pool_t *pool) {
  compiled_template *templ = ngx_palloc(pool, sizeof(compiled_template));
  templ->variable_occurances =
      ngx_array_create(pool, 10, sizeof(variable_occurance *));
  templ->variables = variables;
  templ->template = template;
  templ->pool = pool;
  find_variables(template, templ);
  _compile_template(templ);
  return templ;
}
