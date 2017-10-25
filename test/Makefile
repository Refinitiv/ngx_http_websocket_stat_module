CC_CMD= -g -DTEST

format-test: format-test.o ngx_http_websocket_stat_format.o
	gcc $(CC_CMD) format-test.o ngx_http_websocket_stat_format.o -o  format-test

format-test.o: format-test.c
	gcc $(CC_CMD) format-test.c -c

ngx_http_websocket_stat_format.o: ../ngx_http_websocket_stat_format.c
	gcc $(CC_CMD) -g -c ../ngx_http_websocket_stat_format.c

clean:
	rm -rf format-test *.o
