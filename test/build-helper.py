#!/usr/bin/python3
from plumbum import local 
from plumbum import cli
import os

download_dir = "../download"
this_dir =  os.path.join("..", local.cwd.split("/")[-1])
wget_cmd = local["wget"]
untar_cmd = local["tar"]["xz", "-C", "../", "-f"]
files_cmd =  local["ls"][download_dir]
make_cmd = local["make"]["-j4"]
rm_cmd = local["rm"]["-rf"]

links = {
"pcre" : "ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.41.tar.gz",
"zlib" : "http://zlib.net/zlib-1.2.11.tar.gz",
"openssl": "http://www.openssl.org/source/openssl-1.0.2k.tar.gz",
"nginx": "http://nginx.org/download/nginx-1.13.5.tar.gz"
}

ws_backend = "http://brokerstats-test.financial.com/streaming"

def getLinkFilename(link):
    return link.split("/")[-1]

def getLinkDir(link):
    return os.path.join("../", getLinkFilename(link).replace(".tar.gz", ""))

def download(links):
    local["mkdir"]["-p", os.path.join("..", download_dir)]
    for lib in links: 
       link = links[lib]
       filename = getLinkFilename(link)
       path = os.path.join(download_dir , filename)
       if os.path.exists(path):
           continue
       print("Downloading {}".format(filename))
       wget_cmd(link, '--directory-prefix', download_dir)

def untar(links):
    for lib in links:
       filename = getLinkFilename(links[lib])
       print("Extracting {}".format(filename))
       untar_cmd(os.path.join(download_dir, filename))

def make(links):
    for lib in links:
       if lib == "nginx":
           continue
       filename = getLinkFilename(links[lib])
       directory = getLinkDir(links[lib])
       local.cwd.chdir(directory)
       print("compiling {}".format(directory))
       if lib == "openssl":
           local["./config"]()
       else:
           local["./configure"]()
       make_cmd()
    local.cwd.chdir(this_dir)

def make_nginx(links):
    nginx_fn = getLinkFilename(links["nginx"])
    nginx_dir = getLinkDir(links["nginx"])
    local.cwd.chdir(nginx_dir)
    conf_cmd = local["./configure"]["--with-pcre=" + getLinkDir(links["pcre"]),
                    "--with-zlib=" + getLinkDir(links["zlib"]),
                    "--with-openssl=" + getLinkDir(links["openssl"]),
                    "--add-module="+this_dir
                    ]
    print("Configuring {}".format( conf_cmd))
    conf_cmd()
    print("Building")
    make_cmd()
def clean(links):
    dirs = [download_dir]
    for lib in links:
        dirs.append(getLinkDir(links[lib]))
    rm_cmd(dirs)

def make_nginx_conf(filename):
    conf = """
events
{{
   worker_connections 4096;
}}

http
{{
   server
   {{
      ws_log logs/websocket.log;
      listen 8080;
      location /stat {{
         ws_stat;
      }}
      location /streaming {{
         proxy_pass {backend};
         proxy_set_header Upgrade $http_upgrade;
      }}
   }}

}}
"""
    with open(filename, "w") as f:
        f.write(conf.format(backend=ws_backend))

class ThisApp(cli.Application):
    def main(self, action):
        if action == "clean":
            clean(links)
        elif action == "build":
            print("Downloading...")
            download(links)
            print("Exctracting...")
            untar(links) 
            print("Building libraries...")
            make(links)
            print("Building nginx...")
            make_nginx(links)
        elif action == "conf":
            print("Configuring nginx...")
            make_nginx_conf("../nginx.conf")
        else:
            print("Unknown action: {}".format(action))
ThisApp.run()

