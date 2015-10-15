from functools import partial

from tornado.ioloop import IOLoop
from tornado.concurrent import Future

from ..ldapconnection import LDAPConnection

class TornadoLDAPConnection(LDAPConnection):
    def __init__(self, client, ioloop):
        suprt().__init__(self, is_async=True)
        self._ioloop = ioloop or IOLoop.instance()
        self._fileno = None
        
    def _io_callback(self, fut, msg_id, fd=None, events=None):
        try:
            self._ioloop.remove_handler(self._fileno)
            res = super().get_result(msg_id)
            if res is not None:
                fut.set_result(res)
            else:
                self._fileno = self.fileno()
                self.ioloop.add_handler(self._fileno, callback, IOLoop.WRITE | IOLoop.READ)
        except LDAPError as exc:
            fut.set_exception(exc)
    
    def _evaluate(self, msg_id, timeout=None):
        fut = Future()
        callback = partial(self._io_callback, fut, msg_id)
        self._fileno = self.fileno()
        self.ioloop.add_handler(self._fileno, callback, IOLoop.WRITE | IOLoop.READ)
        return fut
    
    def search(self, base=None, scope=None, filter=None, attrlist=None,
               timeout=0, sizelimit=0, attrsonly=False):
        msg_id = super().search(base, scope, filter, attrlist, timeout,
                                sizelimit, attrsonly)
        return self._evaluate(msg_id)