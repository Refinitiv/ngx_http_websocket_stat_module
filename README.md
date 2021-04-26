![Tests](https://github.com/github/docs/actions/workflows/test.yml/badge.svg)


# NGINX module websocket connection and traffic statistics

Nginx module developed for logging and displaying statistic of websocket proxy connections traffic, limiting number of websocket connections and closing long lasting websocket connections.

## Installation

   1. Configure nginx adding this module with or build this module as a dynamic module:
   ```sh
          ./configure (...) --add-module=./src/ngx_http_websocket_stat_module
          # or
          ./configure (...) --add-dynamic-module=./src/ngx_http_websocket_stat_module && make modules
   ```

## Usage

To enable websocket frames logging specify `log_enabled on` and `ws_log_format` in server section of nginx config file. Additionally, specify `ws_log` to override the log file, which is used to log ws frames.

To customize connection open and close log messages use "open" and "close" parameter for ws_log_format directive. 
To log only when the full message is received/sent use "server"/"client" parameters for ws_log_format directive.

To set maximum single connection lifetime use ws_conn_age parameter. Argument is time given in nginx time format (e.g. 1s, 1m 1h and so on). When connection's lifetime is exceeding specified value there is close websocket packet with 4001 error code generated and connection is closed.

Here is a list of variables you can use in log format string:

 * $ws_opcode - websocket packet opcode. Look into https://tools.ietf.org/html/rfc6455 Section 5.2, Base Framing Protocol.
 * $ws_payload_size - Size of the WS frame without protocol specific data. Only data that been sent or received by the client
 * $ws_message_size - Size of the WS message without protocol specific data. Only data that been sent or received by the client
 * $ws_packet_source - Could be "client" if packet has been sent by the user or "upstream" if it has been received from the server
 * $ws_conn_age - Number of seconds connection is alive
 * $time_local - Nginx local time, date and timezone
 * $request - Http reqeust string. Usual looks like "GET /uri HTTP/1.1"
 * $uri - Http request uri.
 * $request_id - unique random generated request id.
 * $remote_user - username if basic authentification is used
 * $remote_addr - Client's remote ip address
 * $remote_port - Client's remote port
 * $server_addr - Server's remote ip address
 * $server_port - Server's port
 * $upstream_addr - websocket backend address

See [nginx sample configuraion](docker/nginx.conf).

## Copyright

This document is licensed under BSD-2-Clause license. See LICENSE for details.

The code has been opened by (c) Thomson Reuters.
It is now maintained by (c) Refinitiv.
