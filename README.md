# NGINX module showing websocket connection and traffic statistics

Nginx module developed for logging and displaying statistic of websocket proxy connections traffic. 

## Installation

   1. Configure nginx adding this module with:
          
          ./configure (...) --add-module=./ngx_http_websocket_stat_module
       
   2. Build nginx with make -j<n> command where n is number of cpu cores on your build machine
   
   Alternatively could be used build script shipped along with module:
   From module directory run "test/build_helper.py build"
   It would download and build nginx and all required libraries (openssl, pcre and zlib) and generate nginx configuration file.

## Usage

To enable websocket logging specify log file in server section of nginx config file with ws_log directibe.

You can specify your own websocket log format using ws_log_format directive in server section. To customize connection open and close log messages use "open" and "close" parameter for ws_log_format directive.

Here is a list of variables you can use in log format string:
    $ws_opcode
    $ws_payload_size
    $ws_packet_source
    $ws_conn_age
    $time_local
    $request
    $uri
    $request_id
    $remote_user
    $remote_addr
    $remote_port
    $server_addr
    $server_port
    $remote_ip

To read websocket statistic there is GET request should be set up at "location" location of nginx config file with ws_stat command in it. Look into example section for details.

## Example of configuration
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

