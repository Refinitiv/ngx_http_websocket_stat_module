# NGINX module websocket connection and traffic statistics

Nginx module developed for logging and displaying statistic of websocket proxy connections traffic. 

## Installation

   1. Configure nginx adding this module with:
   ```sh
          ./configure (...) --add-module=./ngx_http_websocket_stat_module
   ```
   2. Build nginx with make -j<n> command where n is number of cpu cores on your build machine
   
   Alternatively could be used build script shipped along with module:
   From module directory run 
   ```sh
   test/build_helper.py build
   ```
   It would download and build nginx and all required libraries (openssl, pcre and zlib) and generate nginx configuration file.

## Usage

To enable websocket logging specify log file in server section of nginx config file with ws_log directibe.

You can specify your own websocket log format using ws_log_format directive in server section. To customize connection open and close log messages use "open" and "close" parameter for ws_log_format directive.

Here is a list of variables you can use in log format string:

 * $ws_opcode - websocket packet opcode. Look into https://tools.ietf.org/html/rfc6455 Section 5.2, Base Framing Protocol.
 * $ws_payload_size - Websocket packet size without protocol specific data. Only data that been sent or received by the client
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

To read websocket statistic there is GET request should be set up at "location" location of nginx config file with ws_stat command in it. Look into example section for details.

## Example of configuration

```

server
{
   ws_log <path/to/logfile>;
   ws_log_format "";
   ws_log_format open "$local_time: Connection opened";
   ws_log_format close "$local_time: Connection closed";
# set up location for statistic 
   location /websocket_status {
      ws_stat;
   }
   ...
}

```

