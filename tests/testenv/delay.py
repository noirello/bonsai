import os
import subprocess
import threading
import xmlrpc.server as rpc

def get_interface_name():
    """ Get the first interface name that is not the localhost. """
    net = os.listdir("/sys/class/net")
    net.remove("lo")
    return net[0]

def _set_delay(sec, duration=10.0):
    thr = threading.Timer(duration, remove_delay)
    thr.start()
    return subprocess.call(["tc", "qdisc", "add", "dev",
                            get_interface_name(), "root",
                            "handle", "1:0", "netem", "delay",
                            ("%dmsec" % (sec * 1000))])

def set_delay(sec, duration=10.0):
    """ Set network delay, return with the call's result. """
    thr = threading.Timer(2.0, _set_delay, (sec, duration))
    thr.start()
    return True

def _remove_delay():
    return subprocess.call(["tc", "qdisc", "del", "dev",
                            get_interface_name(), "root"])
def remove_delay():
    """ Remove network delay, return with the call's result. """
    thr = threading.Timer(1.0, _remove_delay)
    thr.start()
    return True

if __name__ == "__main__":
    server = rpc.SimpleXMLRPCServer(("0.0.0.0", 8000))
    server.register_function(set_delay, "set_delay")
    server.register_function(remove_delay, "remove_delay")
    server.serve_forever()