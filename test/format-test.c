#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../ngx_http_websocket_stat_format.h"

const char *test_func(ngx_http_request_t *r, void *data) { return "BINGO"; }

const template_variable variables[] = {
    {VAR_NAME("$ws_opcode"), sizeof("pding") - 1, test_func},
    {VAR_NAME("$ws_payload_size"), 10, test_func},
    {VAR_NAME("$ws_packet_source"), sizeof("upstream") - 1, test_func},
    {VAR_NAME("$ws_conn_age"), 10, test_func},
    {VAR_NAME("$time_local"), sizeof("Mon, 23 Oct 2017 11:27:42 GMT") - 1,
     test_func},
    {NULL, 0, 0, NULL}};

int main() {
  char *template = "Some template $ws_opcode sdkj $ws_packet_source f";
  ngx_str_t template_str;
  template_str.data = template;
  template_str.len = strlen(template);

  compiled_template *template_cmpl =
      compile_template(&template_str, variables, NULL);
  printf("test started\n");
  printf("%s\n", template_cmpl->compiled_template_str);
  char *res = apply_template(template_cmpl, NULL, NULL);
  char *exp_res = "Some template BINGO sdkj BINGO f";
  assert(!strcmp(res, exp_res));
  printf("%s\n", res);
  return 0;
}
