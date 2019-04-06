from typing import Any, Optional, Union
from gevent.socket import wait_readwrite

from ..ldapconnection import BaseLDAPConnection, LDAPSearchScope
from ..ldapdn import LDAPDN
from ..errors import NotAllowedOnNonleaf

MYPY = False

if MYPY:
    from ..ldapclient import LDAPClient

class GeventLDAPConnection(BaseLDAPConnection):
    """
    Asynchronous LDAP connection object that works with Gevent.
    It has the same methods and properties as :class:`bonsai.LDAPConnection`.

    :param LDAPClient client: a client object.
    """

    def __init__(self, client: 'LDAPClient') -> None:
        super().__init__(client, is_async=True)

    def _poll(self, msg_id: int, timeout: Optional[float] = None) -> Any:
        while True:
            res = self.get_result(msg_id)
            if res is not None:
                return res
            wait_readwrite(self.fileno(), timeout=timeout)

    def _evaluate(self, msg_id: int, timeout: Optional[float] = None) -> Any:
        return self._poll(msg_id, timeout)

    def delete(self, dname: Union[str, LDAPDN], timeout: Optional[float] = None,
               recursive: bool = False) -> bool:
        try:
            return super().delete(dname, timeout, recursive)
        except NotAllowedOnNonleaf as exc:
            if recursive:
                results = self.search(dname, LDAPSearchScope.ONELEVEL,
                                      attrlist=['1.1'], timeout=timeout)
                for res in results:
                    self.delete(res.dn, timeout, True)
                return self.delete(dname, timeout, False)
            else:
                raise exc
