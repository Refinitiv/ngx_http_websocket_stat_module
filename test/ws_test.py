#!/usr/bin/python3
from plumbum import cli
from plumbum import local 
from plumbum import BG
import threading
import http.client
import time
import re
from websocket import create_connection
from functools import reduce
import operator
from build_helper import nginxCtl, clearLog, make_nginx_conf
from test_config import ws_log_file, conf_file
import os

class RequestThread(threading.Thread):

    def __init__(self, app):
        super(RequestThread, self).__init__()
        self.app = app
        self.stopped = False
        self.frames_sent = 0
        self.bytes_sent = 0
        self.seconds = app.seconds
        self.fps = app.fps

    def stop(self):
        self.stopped = True

    def startHTTPConnection(self):
        conn = http.client.HTTPConnection(self.app.host)
        try:
            while not self.stopped:
                conn.request("GET", "/")
                resp = conn.getresponse()
                data = resp.read()
                time.sleep(1)
        except http.client.RemoteDisconnected:
            print ("connection dropped")

    def startWebSocketConnection(self):
        ws = create_connection("ws://{}/streaming".format(self.app.host))
        try:
            while not self.stopped:
                time.sleep(1)        
                self.seconds -=1
                for f in range(0, self.fps):
                    data = self.app.packet_size * 'a'
                    ws.send(data)
                    self.frames_sent += 1
                    self.bytes_sent += len(data)
                if self.seconds <= 0:
                    break
            ws.close()
            self.frames_sent += 1
            self.bytes_sent += 2
        except BrokenPipeError:
            print("connection closed")
        except ConnectionRefusedError:
            print("Cannot connect to server")
        

    def run(self):
        if self.app.websocket:
            self.startWebSocketConnection()
        else:
            self.startHTTPConnection()

def parseLogs(logfile):
    chain = local["cat"][logfile] | local["grep"] ["packet from client"] | local["wc"]["-l"]
    frames = int(chain())
    chain = local["cat"][logfile] | local["grep"] ["packet from client"] | \
            local["sed"]["-n", 's/.*payload: \\(.*\\)/\\1/p'] | local["paste"]["-sd+"] | local["bc"]
    payload = int(chain())
    return frames, payload

def ws_stat(host):
    try:
        conn = http.client.HTTPConnection(host)
        conn.request("GET", "/stat")
        resp = conn.getresponse()
        data = resp.read()
        return data.decode('ascii')
    except http.client.RemoteDisconnected:
        return None

def parseStat(host):
    data = ws_stat(host)
    data = data.split('\n')
    cons = data[0].split()[2]
    instat_line = data[2].split()
    frames = instat_line[0]
    payload = instat_line[1]
    print("conn {},  frame {}, payload: {}".format(cons, frames, payload) )

result_exp = re.compile("Total frames: (\d+), total bytes: (\d+)")
class TestApp(cli.Application):
    
    connections = cli.SwitchAttr(['-c', '--connections'], int, default = 1) 
    host = cli.SwitchAttr(['-h', '--host'], str, default = '10.24.9.13') 
    websocket = cli.Flag(['-w', '--websocket']) 
    slave = cli.Flag(['--slave']) 
    fps = cli.SwitchAttr(['-f', '--fps'], int, default = 1)
    seconds = cli.SwitchAttr(['-s', '--seconds'], int, default = 3)
    instances = cli.SwitchAttr(['-n'], int, default = 1)
    packet_size = cli.SwitchAttr(['-p', '--packet'], int, default = 10)
    def main(self):
        if not self.slave:
            make_nginx_conf(os.path.join("..", conf_file))
            clearLog()
            nginxCtl("restart")
            self_run_cmd = local['test/ws_test.py']["-h",self.host, 
                           "--slave","-w",
                           "--fps", self.fps,
                           "--seconds", self.seconds,
                           "--connections", self.connections,
                           "--packet", self.packet_size
                           ]
            runs = []
            print("Starting {} instances".format(self.instances))
            for i in range(self.instances):
                runs.append(self_run_cmd & BG)
            for run in runs:
                run.wait()
            total_frames = 0
            total_payload = 0
            for run in runs:
                out = run.stdout
                res = result_exp.search(out)
                if not res:
                    print("bad output: {}".format(out))
                else:
                    frames, payload =  res.groups()
                    total_frames += int(frames)
                    total_payload += int(payload)
            print("Frames sent: {}, payload:{}".format(total_frames, total_payload))
            print("Parcing log files...")
            print ("{} {}".format(*parseLogs(os.path.join("..", ws_log_file))))
            print("Stat output:")
            parseStat(self.host)
        else:
            threads = []
            print ("Starting {} connections to {}".format(self.connections, self.host) )
            for i in range(0, self.connections):
                threads.append(RequestThread(self))
            try:
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            except KeyboardInterrupt:
                print ("stopping threads")
                for t in threads:
                    t.stop()
                for t in threads:
                    t.join()
            frames =reduce(operator.add, [t.frames_sent for t in threads])
            payload =reduce(operator.add, [t.bytes_sent for t in threads])
            print("Total frames: {}, total bytes: {}".format(frames, payload))
            
TestApp.run()
