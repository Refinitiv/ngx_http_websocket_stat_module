import os

ngx_dir = "nginx"
download_dir = os.path.join(ngx_dir, "download")
conf_file = "nginx.conf"

links = {
"pcre" : "ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.41.tar.gz",
"zlib" : "http://zlib.net/zlib-1.2.11.tar.gz",
"openssl": "http://www.openssl.org/source/openssl-1.0.2k.tar.gz",
"nginx": "http://nginx.org/download/nginx-1.13.5.tar.gz"
}

ws_backend = "http://brokerstats-test.financial.com/streaming"
ws_backend = "http://127.0.0.1:5000/streaming"
ws_log_file = "logs/websocket.log"
proxy_port = 8080
workers = 1

conf_template = """
events
{{
   worker_connections 4096;
}}

worker_processes  {workers};

http
{{
   server
   {{
      ws_log {log};
      ws_log_format "$time_local: packet from $ws_packet_source, type: $ws_opcode, payload: $ws_payload_size";
      ws_log_format open "$time_local: Connection opened";
      ws_log_format close "$time_local: Connection closed";
      listen {port};
      location /stat {{
         ws_stat;
      }}
      location /status {{
         stub_status;
      }}
      location /streaming {{
         proxy_pass {backend};
         proxy_set_header Upgrade $http_upgrade;
         proxy_set_header Connection "keep-alive, Upgrade";
         proxy_http_version 1.1;                           
      }}
   }}

}}
"""
