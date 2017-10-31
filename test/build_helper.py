#!/usr/bin/python3

from plumbum import local 
from plumbum import cli
from plumbum.commands.processes import ProcessExecutionError
from test_config import links, download_dir, conf_file, ws_backend, ws_log_file, conf_template
import os
import time

def getLinkFilename(link):
    return link.split("/")[-1]

def getLinkDir(link):
    return os.path.join("../", getLinkFilename(link).replace(".tar.gz", ""))

if local.cwd.split("/")[-1]!= "ngx_http_websocket_stat_module":
    print("this script is supposed to be run from repo root dir")
    exit(1)
this_dir =  os.path.join("..", local.cwd.split("/")[-1])
wget_cmd = local["wget"]
untar_cmd = local["tar"]["xz", "-C", "../", "-f"]
files_cmd =  local["ls"][download_dir]
make_cmd = local["make"]["-j4"]
rm_cmd = local["rm"]["-rf"]


nginx_dir = getLinkDir(links["nginx"])
nginx_cmd = local[os.path.join(nginx_dir, "objs/nginx")]["-p", "..", "-c", conf_file]

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
                    "--with-http_stub_status_module",
                    "--with-openssl=" + getLinkDir(links["openssl"]),
                    "--add-module="+this_dir
                    ]
    print("Configuring {}".format(conf_cmd))
    conf_cmd()
    print("Building")
    make_cmd()
def clean(links):
    dirs = [download_dir]
    for lib in links:
        dirs.append(getLinkDir(links[lib]))
    rm_cmd(dirs)

def make_nginx_conf(filename):
    with open(filename, "w") as f:
        f.write(conf_template.format(backend=ws_backend, log=ws_log_file))

def isNginxRunning():
    try:
      local["pgrep"]["nginx"]()
    except ProcessExecutionError:
      return False
    return True

def nginxCtl(cmd=None):
    if cmd is None:
        nginx_cmd()
    elif cmd == "restart":
        if (isNginxRunning()):
          nginxCtl("stop")
        nginxCtl()
    else:
        nginx_cmd(["-s", cmd])

def clearLog():
    rm_cmd(os.path.join("..", ws_log_file))

    
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
            make_nginx_conf(os.path.join("..", conf_file))
        else:
            print("Unknown action: {}".format(action))

if __name__ == "__main__":
    ThisApp.run()

