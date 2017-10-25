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

int test_template(const char *template, const char* expected_result)
{
  ngx_str_t template_str;
  template_str.data = template;
  template_str.len = strlen(template);

  compiled_template *template_cmpl =
      compile_template(&template_str, variables, NULL);
  char *res = apply_template(template_cmpl, NULL, NULL);
  if (strcmp(res, expected_result) == 0)
  {
     printf("test passed :)\n");
  }
  else
  {
     printf("Test failed :(\n"
            "actual  : %s\n"
            "expected: %s\n", res, expected_result );
     exit(1);
  }

  free(template_cmpl->variable_occurances->elts);
  free(template_cmpl->variable_occurances);
}

int main() {
  printf("test started\n");
  test_template("Some template $ws_opcode sdkj $ws_packet_source f", 
                "Some template BINGO sdkj BINGO f");
  test_template("Some template $ws_opcode sdkj f", 
                "Some template BINGO sdkj f");
  test_template("Some template f", 
                "Some template f");
  test_template("", 
                "");
  test_template("$time_local", 
                "BINGO");
  test_template("$time_", 
                "$time_");
  return 0;
}
