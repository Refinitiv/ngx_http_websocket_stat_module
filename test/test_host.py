#!/usr/bin/python3
import Pyro4
import time
import logging
from plumbum import local, BG, cli
from test_utils import parseStat, getVarnishPids, getNginxPids, getMemUsage

logger = logging.getLogger("test-host")
logger.setLevel(logging.INFO)
h = logging.StreamHandler()
fmt = logging.Formatter("%(asctime)s: %(message)s")
h.setFormatter(fmt)
logger.addHandler(h)

class ClientProcess(object):

    host_cmd = local["python3"]["test/client_process.py"]
    def __init__(self):
        self._host = ClientProcess.host_cmd & BG
        uri = self._host.proc.stdout.readline().decode('ascii').strip()
        logger.debug ("Process spawned, Pyro4 uri: {}".format(uri))
        self._cmd = Pyro4.Proxy(uri)

    def uri(self):
        return self._uri

    def kill(self):
        self._host.proc.kill()

    def cmd(self):
        return self._cmd

class TestApplication(cli.Application):
    connections = cli.SwitchAttr(['-c'], int, default = 1, help = "Number of connections per instance" )
    instances = cli.SwitchAttr(['-i'], int, default = 3, help = "Number of instances to spawn" )
    delay = cli.SwitchAttr(['-d'], int , default = 1, help = "Delay in seconds for probing test results")
    packet_size = cli.SwitchAttr(['-s'], int, default = 10 ** 3, help = "Size of websocket frame")
    ws_server = cli.SwitchAttr(['-w'], str, default = "127.0.0.1:8080", help = "Websocket server host[:port]")

    def main(self):
        self.procs = []
        start_time  = time.time()
        nginx_pids = getNginxPids()
        varnish_pids = getVarnishPids()
        logger.info("Inital memory usage per worker:")
        logger.info("nginx: {}, Varnish: {}".format(getMemUsage(nginx_pids), getMemUsage(varnish_pids)))
        logger.info("Spawning workers")
        for i in range(0, self.instances):
            self.procs.append(ClientProcess())
        logger.info("Starting connections")
        for proc in self.procs:
            proc.cmd().start(self.connections, "ws://{}/streaming".format(self.ws_server), self.packet_size, 0.1)
        logger.info("Monitoring stats")
        try:
            def getStat():
                frames = data = 0
                for proc in self.procs:
                    stats = proc.cmd().stat()
                    frames += stats[0]
                    data += stats[1]
                return frames, data

            for i in range(0, 20):
                logger.info("Wait {} sec".format(self.delay))
                tm = time.time()
                time.sleep(self.delay)
                logger.info("Pausing")
                for proc in self.procs:
                    cmd = proc.cmd()
                    cmd.pause()
                    (cmd.stat())
                logger.info("Gathering stat") 
                frames, data = getStat()
                logger.info("Frames: {}, Bytes: {}, time elapsed: {:0.2f} seconds".format(frames, data, time.time() - tm))
                stat = parseStat(self.ws_server)
                logger.info("Reported:")
                logger.info("Frames: {}, Bytes: {}, Webscoket connections: {}".format(stat[1], stat[2], stat[0]))
                logger.info("Mem usage: nginx: {}, Varnish: {}".format(getMemUsage(nginx_pids), getMemUsage(varnish_pids)))
                logger.info("Unpausing")
                for proc in self.procs:
                    cmd = proc.cmd()
                    cmd.unpause()
            logger.info ("Stopping worker threads")
            for proc in self.procs:
                cmd = proc.cmd()
                cmd.stop_proc()
            logger.info("Gathering stat") 
            frames, data = getStat()
            logger.info ("Frames: {}, Bytes: {}, total time elapsed: {:0.2f} seconds".format(
                         frames, data, time.time()-start_time))
            stat = parseStat(self.ws_server)
            logger.info("Reported:\nFrames: {}, Bytes: {}".format(stat[1], stat[2]))

        finally:
            logger.info("Terminating worker process")
            for proc in self.procs:
                proc.kill()
            logger.info("Done")
TestApplication.run()
