import os
import subprocess
import threading
import xmlrpc.server as rpc
import time
import sys
import multiprocessing as mp

try:
    import pydivert
except ImportError:
    pass

class UnixDelayHandler:

    @staticmethod
    def get_interface_name():
        """ Get the first interface name that is not the localhost. """
        net = os.listdir("/sys/class/net")
        net.remove("lo")
        return net[0]

    def _set_delay(self, sec, duration=10.0):
        thr = threading.Timer(duration, self._remove_delay)
        thr.start()
        return subprocess.call(["tc", "qdisc", "add", "dev",
                                self.get_interface_name(), "root",
                                "handle", "1:0", "netem", "delay",
                                ("%dmsec" % (sec * 1000))])

    def set_delay(self, sec, duration=10.0):
        """ Set network delay, return with the call's result. """
        thr = threading.Timer(2.0, self._set_delay, (sec, duration))
        thr.start()
        return True

    def _remove_delay(self):
        return subprocess.call(["tc", "qdisc", "del", "dev",
                                self.get_interface_name(), "root"])

    def remove_delay(self):
        """ Remove network delay, return with the call's result. """
        thr = threading.Timer(1.0, self._remove_delay)
        thr.start()
        return True

class WinDelayHandler:
    proc = None

    def delay(self, sec, duration=10.0):
        netfil = "tcp.DstPort == 389 or tcp.SrcPort == 389"
        start = time.time()
        with pydivert.WinDivert(netfil) as divert:
            for packet in divert:
                time.sleep(sec)
                divert.send(packet)
                if time.time() - start >= duration:
                    break

    def set_delay(self, sec, duration=10.0):
        """ Set network delay, return with the call's result. """
        WinDelayHandler.stop = False
        self.proc = mp.Process(target=self.delay, args=(sec, duration))
        self.proc.start()
        return True
    
    def remove_delay(self):
        """ Remove network delay, return with the call's result. """
        if self.proc is not None and self.proc.is_alive():
            self.proc.terminate()
        return True

if __name__ == "__main__":
    if sys.platform == "win32":
        handler = WinDelayHandler()
    else:
        handler = UnixDelayHandler()
    server = rpc.SimpleXMLRPCServer(("0.0.0.0", 8000))
    server.register_function(handler.set_delay, "set_delay")
    server.register_function(handler.remove_delay, "remove_delay")
    server.serve_forever()