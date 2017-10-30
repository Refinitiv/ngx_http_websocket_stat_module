#!/bin/bash
CONFIG_PARAMS="\
--with-openssl=/home/drezchykov/nginx/openssl-1.0.2k \
--add-module=./ngx-websocket-stat \
--with-http_stub_status_module \
--with-http_sub_module \
"
CONFIG_PARAMS+=" --with-debug"
CONFIG_PARAMS+=" --add-module=./websockify-nginx-module"
#CONFIG_PARAMS+=" --add-module=./Nginx-limit-traffic-rate-module"

case $1 in
rebuild)
echo stoping nginx...
sudo objs/nginx -p ./ -c nginx.conf -s stop
make -j8
echo starting nginx...
sudo objs/nginx -p ./ -c nginx.conf
;;
*)
./configure $CONFIG_PARAMS 
;;
esac 
