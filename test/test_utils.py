import http.client
from plumbum import local 

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

