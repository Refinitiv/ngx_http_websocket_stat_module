# ngx_http_websocket_stat_module
# NGINX module showing websocket connection and traffic statistics

## Installation

   1. Configure nginx adding this module with:
          
          ./configure (...) --add-module=./ngx-websocket-stat
       
   2. Build nginx with make -j<n> command where n is number of cpu cores on your build machine
   
   3. Configure the module. Use websocket_stat directive on location context to obtain gethered statistic over GET request:
      location =/ws_stat {
         websocket_stat;
      }

## TODO

 1. Add connection aging
 2. Add single connection statistic counter
 ...
