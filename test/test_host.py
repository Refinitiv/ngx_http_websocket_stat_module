#!/usr/bin/python3
import Pyro4
import time
import logging
from plumbum import local, BG, cli

class ClientProcess(object):

    host_cmd = local["python3"]["test/client_process.py"]
    def __init__(self):
        self._host = ClientProcess.host_cmd & BG
        uri = self._host.proc.stdout.readline().decode('ascii').strip()
        print ("uri is {}".format(uri))
        self._cmd = Pyro4.Proxy(uri)

    def uri(self):
        return self._uri

    def kill(self):
        self._host.proc.kill()

    def cmd(self):
        return self._cmd


class TestApplication(cli.Application):
    connections = cli.SwitchAttr(['-c'], int, default = 1 )
    instances = cli.SwitchAttr(['-i'], int, default = 3 )

    def main(self):
        self.procs = []
        for i in range(0, self.instances):
            self.procs.append(ClientProcess())
        for proc in self.procs:
            proc.cmd().start(self.connections, "ws://127.0.0.1:8080/streaming", 2 * 10**3, 0.1)
        try:
            for i in range(0, 20):
                print("Pausing")
                for proc in self.procs:
                    cmd = proc.cmd()
                    print(cmd.pause())
                    print(cmd.stat())
                for proc in self.procs:
                    cmd = proc.cmd()
                    print("Unpausing")
                    print(cmd.unpause())
                time.sleep(1)
            for proc in self.procs:
                cmd = proc.cmd()
                print(cmd.stop_proc())
            print ("Get stat")
            frames = data = 0
            for proc in self.procs:
                stats = proc.cmd().stat()
                frames += stats[0]
                data += stats[1]
            print ("Frames: {}, Bytes: {}".format(frames, data))

        finally:
            for proc in self.procs:
                print("kill")
                proc.kill()
        print ("Bye")
TestApplication.run()
