#!/usr/bin/python3
from plumbum import cli
import threading
import http.client
import time
from websocket import create_connection

class RequestThread(threading.Thread):

    def __init__(self, app):
        super(RequestThread, self).__init__()
        self.app = app
        self.stopped = False

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
                ws.ping()
        except BrokenPipeError:
            print("connection closed")
        except ConnectionRefusedError:
            print("Cannot connect to server")
        

    def run(self):
        if self.app.websocket:
            self.startWebSocketConnection()
        else:
            self.startHTTPConnection()

    
class TestApp(cli.Application):
    
    connections = cli.SwitchAttr(['-c', '--connection'], int, default = 1) 
    host = cli.SwitchAttr(['-h', '--host'], str, default = '10.24.9.13') 
    websocket = cli.Flag(['-w', '--websocket']) 

    def main(self):
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
            
TestApp.run()

