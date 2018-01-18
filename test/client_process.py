#!/usr/bin/python
from plumbum import cli
import Pyro4
import sys
import os
import time
from threading import Thread, Event
from functools import reduce
from websocket import create_connection, WebSocketException
from test_utils import ws_stat, parseLogs

import logging

logging.basicConfig(filename='client.log'.format(os.getpid()), level=logging.INFO)
logger  = logging.getLogger('client.{}'.format(os.getpid()))

watchdogTimeout = 5 * 60

"""
Watchdog class that to kill this process if there where
no commands from the test host for some period of time.
"""
class WatchDog(Thread):
    def __init__(self, timeout):
        Thread.__init__(self)
        self.timeout = timeout
        self.lastSeen = time.time()

    def run(self):
        while True:
            time.sleep(3)
            if time.time() - self.lastSeen > self.timeout:
                logger.info("Client exited on timeout")
                os._exit(0)

    def update(self):
        self.lastSeen = time.time()

"""
This thread does all the work. It sends single websocket packet of siz
<packet_size> on ws server specifid in <url> every <send_delay>
seconds (could be fractional e.g. 0.3 for 300 milliseconds).
"""
class ConnectionThread(Thread):
    def __init__(self, url, packet_size, send_delay):
        Thread.__init__(self)
        self._val = 0
        self.paused = False
        self.stopped = False
        self.unpaused_ev = Event()
        self.paused_ev = Event()
        self.stopped_ev = Event()
        logger.info("Connecting to {}".format(url))
        try:
            self.ws = create_connection(url)
        except ConnectionRefusedError:
            logger.warn("Cannot connect to {}".format(url))
        except WebSocketException as e:
            logger.warn("Websocket connection error: {}".format(e))
            self.ws = None
        self.packet_size = packet_size
        self.send_delay = float(send_delay)
        self.frames_sent = 0
        self.bytes_sent = 0

    def run(self):
        while not self.stopped:
            data = self.packet_size * 'a'
            try:
                if self.ws:
                    self.ws.send(data)
                    self.frames_sent += 1
                    self.bytes_sent += len(data)
                if self.send_delay:
                    time.sleep(self.send_delay)
            except BrokenPipeError:
                logger.warn("connection closed")
                self.ws = None
            except ConnectionRefusedError:
                logger.warn("Cannot connect to server")
                self.ws = None
            if self.paused:
                self.paused_ev.set()
                self.unpaused_ev.clear()
                logger.debug("wait till unpause")
                self.unpaused_ev.wait()
        self.stopped_ev.set()

    def pause(self):
        self.paused_ev.clear()
        self.paused = True

    def pause_wait(self):
        if self.paused_ev.is_set():
            return
        self.paused_ev.wait()

    def unpause(self):
        self.paused = False
        self.unpaused_ev.set()

    def stop(self):
        self.stopped = True

    def stop_wait(self):
        if self.paused:
            self.unpause()
        if self.stopped_ev.is_set():
            return
        self.stopped_ev.wait()

thrs = []
watchdog = WatchDog(watchdogTimeout)
watchdog.start()

"""
Wrapper for rpc function to update watchdog when some command from the
test_host arrives.
"""
def watchdogUpdate(func):
    def f_wrapper(*args, **kwargs):
        watchdog.update()
        return func(*args, **kwargs)
    return f_wrapper

"""
Class to receive command from the teest_host.
It is sync call i.e. server wait until command would return a result.
"""
@Pyro4.expose
class RemoteCommander(object):

    @watchdogUpdate
    def init(self, connections, url, packet_size, send_delay):
        logger.info("Initializing {} connections".format(connections))
        for i in range(0, connections):
            thrs.append(ConnectionThread(url, packet_size, send_delay))

    @watchdogUpdate
    def start(self):
        logger.info("Starting {} threads".format(len(thrs)))
        for t in thrs:
            t.start()

    @watchdogUpdate
    def stat(self):
        return reduce(lambda x, y: (x[0] + y.frames_sent, x[1] + y.bytes_sent) ,thrs, (0, 0))

    @watchdogUpdate
    def pause(self):
        for t in thrs:
            t.pause()
        for t in thrs:
            t.pause_wait()
        return "paused"

    @watchdogUpdate
    def unpause(self):
        for t in thrs:
            t.unpause()
        return "unpaused"

    @watchdogUpdate
    def exit(self):
        logger.info("Client exited on request")
        os._exit(0)

    @watchdogUpdate
    def stop_proc(self):
        try:
            logger.debug("stopping")
            for t in thrs:
                t.stop()
            logger.debug("waiting for stop")
            for t in thrs:
                t.stop_wait()
            logger.debug("stopped")
            return "stopped"
        except Error as e:
            logger.info("exception")
            logger.info(e)

class App(cli.Application):
    host = cli.SwitchAttr(['-h'], str, default = "localhost")
    def main(self):
        daemon = Pyro4.Daemon(host = self.host)
        uri = daemon.register(RemoteCommander)
        logger.info("URI is {}".format(uri))
        sys.stdout.write("{}\n".format(uri))
        sys.stdout.flush()
        daemon.requestLoop()
        logger.debug('bb')

if __name__ == "__main__":
    App.run()
