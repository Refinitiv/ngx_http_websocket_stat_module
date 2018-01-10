#!/usr/bin/python
import plumbum
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
@Pyro4.expose
class RemoteCommander(object):
    def start(self, connections, url, packet_size, send_delay):
        logger.info("Starting {} connections".format(connections))
        for i in range(0, connections):
            thrs.append(ConnectionThread(url, packet_size, send_delay))
        for t in thrs:
            t.start()

    def stat(self):
        return reduce(lambda x, y: (x[0] + y.frames_sent, x[1] + y.bytes_sent) ,thrs, (0, 0))

    def pause(self):
        for t in thrs:
            t.pause()
        for t in thrs:
            t.pause_wait()
        return "paused"

    def unpause(self):
        for t in thrs:
            t.unpause()
        return "unpaused"

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

if __name__ == "__main__":
    daemon = Pyro4.Daemon()
    uri = daemon.register(RemoteCommander)
    logger.info("URI is {}".format(uri))
    sys.stdout.write("{}\n".format(uri))
    sys.stdout.flush()
    daemon.requestLoop()
    logger.debug('bb')
