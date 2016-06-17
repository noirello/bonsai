import asyncio

from ..ldapconnection import LDAPConnection, LDAPSearchScope
from ..errors import LDAPError, NotAllowedOnNonleaf

class AIOLDAPConnection(LDAPConnection):
    def __init__(self, client, loop=None):
        self._loop = loop or asyncio.get_event_loop()
        super().__init__(client, is_async=True)
        
    def _ready(self, msg_id, fut):
        self._loop.remove_reader(self.fileno())
        try:
            res = super().get_result(msg_id)
            if res is not None:
                fut.set_result(res)
            else:
                self._loop.add_reader(self.fileno(), self._ready, msg_id, fut)
        except LDAPError as exc:
            fut.set_exception(exc)

    def _poll(self, msg_id, timeout=None):
        fut = asyncio.Future()
        self._loop.add_reader(self.fileno(), self._ready, msg_id, fut)
        res = yield from asyncio.wait_for(fut, timeout, loop=self._loop)
        return res
    
    def _evaluate(self, msg_id, timeout=None):
        return self._poll(msg_id, timeout)

    def delete(self, dname, timeout=None, recursive=False):
        try:
            res = yield from super().delete(dname, timeout, recursive)
            return res
        except NotAllowedOnNonleaf as exc:
            if recursive:
                results = yield from self.search(dname,
                                                 LDAPSearchScope.ONELEVEL,
                                                 attrlist=['1.1'],
                                                 timeout=timeout)
                for res in results:
                    yield from self.delete(res.dn, timeout, True)
                res = yield from self.delete(dname, timeout, False)
                return res
            else:
                raise exc
