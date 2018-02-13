import http.client
import logging
import math
from plumbum import local 
from plumbum.commands.processes import ProcessExecutionError

logger = logging.getLogger('ws_test')

def ws_stat(host):
    try:
        conn = http.client.HTTPConnection(host)
        conn.request("GET", "/stat")
        resp = conn.getresponse()
        data = resp.read()
        return data.decode('ascii')
    except http.client.RemoteDisconnected:
        return None

def parseLogs(logfile):
    try:
        chain = local["cat"][logfile] | local["grep"] ["packet from client"] | local["wc"]["-l"]
        frames = int(chain())
        chain = local["cat"][logfile] | local["grep"] ["packet from client"] | \
                local["sed"]["-n", 's/.*payload: \\(.*\\)/\\1/p'] | local["paste"]["-sd+"] | local["bc"]
        payload = int(chain())
        return frames, payload
    except ProcessExecutionError as e:
        logger.error("Error parsing log files:\n{}".format(e))
        return 0,0

def parseStat(host):
    try:
        data = ws_stat(host)
        data = data.split('\n')
        cons = data[0].split()[2]
        instat_line = data[2].split()
        frames = instat_line[0]
        payload = instat_line[1]
        return  cons, frames, payload
    except IndexError: 
        logger.info("Wrong data: {}".format(data))
        return 0,0,0

def getNginxPids():
    chain = local["pgrep"]["nginx"] | local["tail"]["-n+2"]
    return chain().split()

def getMemUsage(pids):
    result = []
    for pid in pids:
        chain = local["sudo"]["pmap"][pid] | local["tail"]["-n1"]
        result.append(chain().split()[1])
    return result

def getVarnishPids():
    return local["pgrep"]["varnishd"]().split()

def humanReadableSize(size):
    size = int(size)
    modifiers = ['B', 'KB', 'MB', 'GB', 'TB']
    if size <= 0:
        return str(size)
    dim = math.floor(math.log(size, 1024))
    if dim > len(modifiers) - 1:
        dim = len(modifiers) - 1
    num = size / (1024 ** dim)
    return "{:0.1f}{}".format(num, modifiers[dim])




