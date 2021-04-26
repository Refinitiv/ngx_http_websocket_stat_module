#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "../src/ngx_http_websocket_stat_format.h"

void
test_func(ngx_http_request_t *r, void *data, char* buff, size_t size)
{
    snprintf(buff, size, "BINGO");
}

const template_variable variables[] = {
    {VAR_NAME("$ws_opcode"), sizeof("pding") - 1, test_func},
    {VAR_NAME("$ws_payload_size"), 10, test_func},
    {VAR_NAME("$ws_message_size"), 10, test_func},
    {VAR_NAME("$ws_packet_source"), sizeof("upstream") - 1, test_func},
    {VAR_NAME("$ws_conn_age"), 10, test_func},
    {VAR_NAME("$request"), 10, test_func},
    {VAR_NAME("$request_id"), 10, test_func},
    {VAR_NAME("$time_local"), sizeof("Mon, 23 Oct 2017 11:27:42 GMT") - 1,
     test_func},
    {NULL, 0, 0, NULL}};

const char *templates[][2] = {
    {"Some template $ws_opcode sdkj $ws_packet_source f", "Some template BINGO sdkj BINGO f"},
    {"Some template $ws_opcode sdkj f", "Some template BINGO sdkj f"},
    {"Some template f", "Some template f"},
    {"", ""},
    {"$time_local", "BINGO"},
    {"$time_local$ws_opcode$ws_payload_size", "BINGOBINGOBINGO"},
    {"$time_", "$time_"},
    {"$request $request_id", "BINGO BINGO"},
    {"$ws_message_size", "BINGO"},
};

START_TEST (test_format_templates)
{
    compiled_template *template_cmpl = compile_template((char *)templates[_i][0], variables, NULL);
    char *res = apply_template(template_cmpl, NULL, NULL);

    ck_assert_str_eq(res, templates[_i][1]);
}
END_TEST


Suite*
test_format_suite (void)
{
  Suite* s = suite_create ("Format");

  TCase* tc_templates = tcase_create ("Templates");
  tcase_add_loop_test(tc_templates, test_format_templates, 0, sizeof(templates)/sizeof(templates[0]));

  suite_add_tcase (s, tc_templates);

  return s;
}

int main(void)
{
    SRunner *sr = srunner_create(test_format_suite());

    srunner_run_all(sr, CK_ENV);
    int nf = srunner_ntests_failed(sr);
    srunner_free(sr);

    return nf == 0 ? 0 : 1;
}