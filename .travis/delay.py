import os
import subprocess
import xmlrpc.server as rpc
import time
import sys
import multiprocessing as mp

try:
    import pydivert
except ImportError:
    pass


class LinuxDelayHandler:
    @staticmethod
    def get_interface_name():
        """ Get the first interface name that is not the localhost. """
        net = os.listdir("/sys/class/net")
        net.remove("lo")
        if "eth0" in net:
            return "eth0"
        return net[0]

    def set_delay(self, sec, duration=10.0):
        """ Set network delay, return with the call's result. """
        try:
            subprocess.check_call(
                [
                    "tc",
                    "qdisc",
                    "add",
                    "dev",
                    self.get_interface_name(),
                    "root",
                    "handle",
                    "1:",
                    "prio",
                ]
            )
            subprocess.check_call(
                [
                    "tc",
                    "qdisc",
                    "add",
                    "dev",
                    self.get_interface_name(),
                    "parent",
                    "1:3",
                    "handle",
                    "30:",
                    "netem",
                    "delay",
                    ("%dmsec" % (sec * 1000)),
                ]
            )
            for port in ("389", "636"):
                subprocess.check_call(
                    [
                        "tc",
                        "filter",
                        "add",
                        "dev",
                        self.get_interface_name(),
                        "protocol",
                        "ip",
                        "parent",
                        "1:0",
                        "u32",
                        "match",
                        "ip",
                        "sport",
                        port,
                        "0xffff",
                        "flowid",
                        "1:3",
                    ]
                )

            return True
        except subprocess.CalledProcessError:
            return False

    def remove_delay(self):
        """ Remove network delay. """
        try:
            subprocess.check_call(
                ["tc", "qdisc", "del", "dev", self.get_interface_name(), "root"]
            )
            return True
        except subprocess.CalledProcessError:
            return False


class MacDelayHandler:
    def set_delay(self, sec, duration=10.0):
        with open("/etc/pf.conf") as fp:
            conf = fp.read()
            conf += '\ndummynet-anchor "mop"\nanchor "mop"\n'
            rule = (
                "dummynet in quick proto tcp from any to any port {389, 636} pipe 1\n"
            )

            try:
                subprocess.run(
                    ["pfctl", "-f", "-"], input=conf, encoding="utf-8", check=True
                )
                subprocess.run(
                    ["pfctl", "-a", "mop", "-f", "-"],
                    input=rule,
                    encoding="utf-8",
                    check=True,
                )
                subprocess.check_call(
                    ["dnctl", "pipe", "1", "config", "delay", "%d" % int(sec * 1000)]
                )

                return True
            except subprocess.CalledProcessError:
                return False

    def remove_delay(self):
        try:
            subprocess.check_call(["dnctl", "-q", "flush"])
            subprocess.check_call(["pfctl", "-f", "/etc/pf.conf"])
            return True
        except subprocess.CalledProcessError:
            return False


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
    elif sys.platform == "darwin":
        handler = MacDelayHandler()
    else:
        handler = LinuxDelayHandler()
        # Fix network collapse on certain Linux distros.
        subprocess.call(
            ["ip", "link", "set", handler.get_interface_name(), "qlen", "1000"]
        )

    server = rpc.SimpleXMLRPCServer(("0.0.0.0", 8000))
    server.register_function(handler.set_delay, "set_delay")
    server.register_function(handler.remove_delay, "remove_delay")
    server.serve_forever()
