#!/usr/bin/python3

from plumbum import local 
from plumbum import cli
from plumbum.commands.processes import ProcessExecutionError
from test_config import links, download_dir, ngx_dir, \
                        conf_file, ws_backend, \
                        ws_log_file, conf_template, proxy_port, \
                        workers
import os
import time

mkdir_cmd = local["mkdir"]["-p"]

def getLinkFilename(link):
    return link.split("#")[0].split("/")[-1]

def getLinkDir(link):
    if "#" in link:
        return os.path.join(ngx_dir, link.split("#")[1])
    return os.path.join(ngx_dir, getLinkFilename(link).replace(".tar.gz", ""))

if local.cwd.split("/")[-1]!= "ngx_http_websocket_stat_module":
    print("this script is supposed to be run from repo root dir")
    exit(1)
this_dir =  "../.."
wget_cmd = local["wget"]
untar_cmd = local["tar"]["xz", "-C", ngx_dir, "-f"]
files_cmd =  local["ls"][download_dir]
make_cmd = local["make"]["-j4"]
rm_cmd = local["rm"]["-rf"]


nginx_dir = getLinkDir(links["nginx"])
nginx_cmd = local[os.path.join(nginx_dir, "objs/nginx")]["-p", ngx_dir, "-c", conf_file]

def download(links):
    mkdir_cmd(download_dir)
    for lib in links: 
       link = links[lib]
       filename = getLinkFilename(link)
       path = os.path.join(download_dir , filename)
       if os.path.exists(path):
           continue
       print("Downloading {}".format(filename))
       wget_cmd(link.split("#")[0], '--directory-prefix', download_dir)

def untar(links):
    for lib in links:
       filename = getLinkFilename(links[lib])
       print("Extracting {}".format(filename))
       untar_cmd(os.path.join(download_dir, filename))

def make(links):
    for lib in links:
       if lib.startswith("nginx"):
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
    conf_cmd = local["./configure"]["--with-pcre=" + os.path.join(this_dir, getLinkDir(links["pcre"])),
                    "--with-zlib=" + os.path.join(this_dir, getLinkDir(links["zlib"])),
                    "--with-http_stub_status_module",
                    "--with-openssl=" + os.path.join(this_dir, getLinkDir(links["openssl"])),
                    "--add-module=../nginx_upstream_check_module-master",
                    "--with-http_ssl_module",
                    "--with-file-aio",
                    "--with-http_addition_module",
                    "--with-http_auth_request_module",
                    "--with-http_dav_module",
                    "--with-http_degradation_module",
                    "--with-http_flv_module",
                    "--with-http_gunzip_module",
                    "--with-http_gzip_static_module",
                    "--with-http_image_filter_module",
                    "--with-http_random_index_module",
                    "--with-http_realip_module",
                    "--with-http_secure_link_module",
                    "--with-http_ssl_module",
                    "--with-http_stub_status_module",
                    "--with-http_sub_module",
                    "--with-http_v2_module",
                    "--with-http_xslt_module",
                    "--with-mail",
                    "--with-mail_ssl_module",
                    "--with-debug",
                    "--add-module="+this_dir,
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
        f.write(conf_template.format(
                backend = ws_backend, 
                log = ws_log_file,
                port = proxy_port,
                workers = workers
                ))

def isNginxRunning():
    try:
      local["pgrep"]["nginx"]()
    except ProcessExecutionError:
      return False
    return True

def nginxCtl(cmd=None):
    if cmd is None:
        mkdir_cmd(os.path.join(ngx_dir, "logs"))
        nginx_cmd()
    elif cmd == "restart":
        if (isNginxRunning()):
          nginxCtl("stop")
        nginxCtl()
    else:
        nginx_cmd(["-s", cmd])

def clearLog():
    rm_cmd(os.path.join(ngx_dir, ws_log_file))
    
class ThisApp(cli.Application):
    skip_lib_build = cli.Flag(['--skip-lib-build'])
    def main(self, action):
        if action == "clean":
            clean(links)
        elif action == "build":
            print("Downloading...")
            download(links)
            print("Exctracting...")
            untar(links) 
            if not self.skip_lib_build:
                print("Building libraries...")
                make(links)
            print("Building nginx...")
            make_nginx(links)
        elif action == "conf":
            print("Configuring nginx...")
            make_nginx_conf(os.path.join(ngx_dir, conf_file))
        elif action == "start_nginx":
            clearLog()
            nginxCtl()
        else:
            print("Unknown action: {}".format(action))

if __name__ == "__main__":
    ThisApp.run()

