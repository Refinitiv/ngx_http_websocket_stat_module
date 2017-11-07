#!/usr/bin/python3
import unittest
from plumbum import local, cli, BG
from plumbum.commands.processes import ProcessExecutionError

build_hlpr_cmd = local["test/build_helper.py"]

def getNginxPID():
    chain = local["pgrep"]["nginx"] | local["tail"]["-n1"]
    pid = int(chain())
    return pid

def startNginx():
    try:
        local["pkill"]["-9", "nginx"]()
    except ProcessExecutionError:
        pass
    build_hlpr_cmd("conf")
    build_hlpr_cmd("start_nginx")
    return getNginxPID()

def getTotalMem(pid):
    chain = local["pmap"][pid] | local["sed"]["-n", 's/total\\ *\\(.*\\)/\\1/p']
    out = chain()
    return (int(out.replace('K','')))

class TestWebStat(unittest.TestCase):
    def regularCheck(self, sent_frames, sent_payload, 
                     logged_frames, logged_payload, 
                     connections, 
                     reported_frames, reported_payload):
        self.assertEqual(sent_frames, reported_frames)
        self.assertEqual(sent_frames, logged_frames)
        self.assertEqual(logged_frames, reported_frames)
        self.assertEqual(sent_payload, reported_payload)
        self.assertEqual(sent_payload, logged_payload)
        self.assertEqual(logged_payload, reported_payload)
        self.assertEqual(connections, 0)
    
    def testSimple(self):
        self_run_cmd = local['test/ws_test.py'] \
                       [
                       "-h", "127.0.0.1:8080",
                       "-w",
                       "--fps", 3,
                       "--seconds", 1,
                       "--connections", 5,
                       "--packet", 10,
                       "--instances", 5,
                       "--robot_friendly"
                       ]
        self.regularCheck(*[int(x) for x in self_run_cmd().split()])


    def test500Cons(self):
        self_run_cmd = local['test/ws_test.py'] \
                       [
                       "-h", "127.0.0.1:8080",
                       "-w",
                       "--fps", 3,
                       "--seconds", 5,
                       "--connections", 5,
                       "--packet", 100,
                       "--instances", 100,
                       "--robot_friendly"
                       ]
        self.regularCheck(*[int(x) for x in self_run_cmd().split()])

    def testLongRun500Cons(self):
        self_run_cmd = local['test/ws_test.py'] \
                       [
                       "-h", "127.0.0.1:8080",
                       "-w",
                       "--fps", 3,
                       "--seconds", 60,
                       "--connections", 5,
                       "--packet", 100,
                       "--instances", 100,
                       "--robot_friendly"
                       ]
        self.regularCheck(*[int(x) for x in self_run_cmd().split()])

    def testLargePackets(self):
        self_run_cmd = local['test/ws_test.py'] \
                       [
                       "-h", "127.0.0.1:8080",
                       "-w",
                       "--fps", 3,
                       "--seconds", 30,
                       "--connections", 5,
                       "--packet", 3000,
                       "--instances", 100,
                       "--robot_friendly"
                       ]
        self.regularCheck(*[int(x) for x in self_run_cmd().split()])

    def testMemoryLeak(self):
        pid = startNginx()
        memory = local["pmap"]
        memBefore = getTotalMem(pid)
        self_run_cmd = local['test/ws_test.py'] \
                       [
                       "-h", "127.0.0.1:8080",
                       "-w",
                       "--fps", 3,
                       "--seconds", 60,
                       "--connections", 5,
                       "--packet", 3000,
                       "--instances", 100,
                       "--robot_friendly",
                       "--keepNginx"
                       ]
        self.regularCheck(*[int(x) for x in self_run_cmd().split()])
        self.assertEqual(pid, getNginxPID())
        memAfter = getTotalMem(pid)
        self.assertTrue(memAfter - memBefore <= 4)

if __name__ == "__main__":
    f = local["test/test_server.py"] & BG
    try:
        unittest.main()
    finally:
        f.proc.kill()

