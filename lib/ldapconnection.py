from enum import IntEnum
from typing import Union, Any, List, Iterator, Tuple

from ._bonsai import ldapconnection
from .ldapdn import LDAPDN
from .ldapentry import LDAPEntry
from .errors import UnwillingToPerform, NotAllowedOnNonleaf

class LDAPSearchScope(IntEnum):
    """ Enumeration for LDAP search scopes. """
    BASE = 0  #: For searching only the base DN.
    ONELEVEL = 1  #: For searching one tree level under the base DN.
    ONE = ONELEVEL  #: Alias for :attr:`LDAPSearchScope.ONELEVEL`.
    SUBTREE = 2  #: For searching the entire subtree, including the base DN.
    SUB = SUBTREE  #: Alias for :attr:`LDAPSearchScope.SUBTREE`.

class LDAPConnection(ldapconnection):
    """
    Handles the connection to an LDAP server.
    If `is_async` is set to True, then all LDAP operations that belong \
    to this connection will return a message ID. This ID can be used to \
    poll the status of the operation.

    :param LDAPClient client: a client object.
    :param bool is_async: set True to create an asynchronous connection.
    """
    def __init__(self, client, is_async: bool=False):
        self.__client = client
        super().__init__(client, is_async)

    def __enter__(self):
        """ Context manager entry point. """
        return self

    def __exit__(self, *exc):
        """ Context manager exit point. """
        self.close()

    def _evaluate(self, msg_id: int, timeout: float=None) -> Any:
        """
        Depending on the connection's type (asynchronous or synchronous),
        it returns a message ID or the result of the LDAP operation.

        :param int msg_id: the ID of the LDAP operation.
        :param float timeout: time limit in seconds for the operation.
        :return: msg_id if the connection is async, otherwise the result \
        of the operation.
        """
        if self.is_async:
            return msg_id
        else:
            return self.get_result(msg_id, timeout)

    def add(self, entry: LDAPEntry, timeout: float=None) -> Union[int, bool]:
        """
        Add new entry to the directory server.

        :param LDAPEntry entry: the new entry.
        :param float timeout: time limit in seconds for the operation.
        :return: True, if the operation is finished.
        :rtype: bool
        """
        return self._evaluate(super().add(entry), timeout)

    def delete(self, dname: Union[str, LDAPDN],
               timeout: float=None, recursive: bool=False) -> Union[int, bool]:
        """
        Remove entry from the directory server.

        :param str|LDAPDN dname: the string or LDAPDN format of the \
        entry's DN.
        :param float timeout: time limit in seconds for the operation.
        :param bool recursive: remove every entry of the given subtree \
        recursively.
        :return: True, if the operation is finished.
        :rtype: bool
        """
        try:
            if type(dname) == LDAPDN:
                dname = str(dname)
            return self._evaluate(super().delete(dname), timeout)
        except NotAllowedOnNonleaf as exc:
            if recursive and self.is_async == False:
                results = self.search(dname, LDAPSearchScope.ONELEVEL,
                                     attrlist=['1.1'], timeout=timeout)
                for res in results:
                    self.delete(res.dn, timeout, True)
                return self.delete(dname, timeout, False)
            else:
                raise exc

    def open(self, timeout: float=None) -> Union[int, 'LDAPConnection', Iterator]:
        """
        Open the LDAP connection.

        :param float timeout: time limit in seconds for the operation.
        :return: The :class:`LDAPConnection` object itself, if \
        it is a synchronous or a message ID if it's an asynchronous connection.
        :rtype: :class:`LDAPConnection` or iterator.
        """
        return self._evaluate(super().open(), timeout)

    def search(self, base: Union[str, LDAPDN]=None,
               scope: Union[LDAPSearchScope, int]=None, filter: str=None,
               attrlist: List[str]=None, timeout: float=None,
               sizelimit: int=0, attrsonly: bool=False,
               sort_order: List[str]=None, page_size: int=0, offset: int=0,
               before_count: int=0, after_count: int=0, est_list_count: int=0,
               attrvalue: str=None) -> Union[int, List[LDAPEntry], Iterator,
                                             Tuple[List[LDAPEntry],dict]]:
        # Documentation in the docs/api.rst with detailed examples.
        # Load values from the LDAPURL, if it is not presented on the
        # parameter list.
        _base = str(base) if base is not None else str(self.__client.url.basedn)
        _scope = scope if scope is not None else self.__client.url.scope_num
        _filter = filter if filter is not None else self.__client.url.filter
        _attrlist = attrlist if attrlist is not None else self.__client.url.attributes
        _timeout = timeout if timeout is not None else 0.0
        if sort_order is not None:
            _sort_order = self.__create_sort_list(sort_order)
        else:
            _sort_order= []
        if _sort_order == [] and (offset != 0 or attrvalue is not None):
            raise UnwillingToPerform("Sort control is required with"
                                     " virtual list view.")
        if page_size != 0 and (offset != 0 or attrvalue is not None):
            raise UnwillingToPerform("Virual list view incompatible"
                                     " with paged search.")
        msg_id = super().search(_base, _scope, _filter, _attrlist,
                                _timeout, sizelimit, attrsonly, _sort_order,
                                page_size, offset, before_count, after_count,
                                est_list_count, attrvalue)
        return self._evaluate(msg_id, timeout)


    @staticmethod
    def __create_sort_list(sort_list: List[str]):
        """
        Set a list of attribute names to sort entries in a search result. For
        reverse order set '-' before to the attribute name.

        :param list sort_list: List of attribute names.
        :raises ValueError: if any element of the list is not a string or an \
        empty string, and if any of the attributes is in the list more then \
        once.
        """
        sort_attrs = []
        for attr in sort_list:
            if type(attr) != str or len(attr) == 0:
                raise ValueError("All element of sort_list must be"
                                 " a non empty string.")
            if attr[0] == '-':
                # Set reverse order.
                sort_attrs.append((attr[1:], True))
            else:
                sort_attrs.append((attr, False))
        if len(sort_list) > len(set(map(lambda x: x[0].lower, sort_attrs))):
            raise ValueError("Attribute names must be different"
                             " from each other.")
        return sort_attrs

    def modify_password(self, user: Union[str, LDAPDN]=None,
                        new_password:str=None, old_password: str=None,
                        timeout: float=None) -> Union[str, int, None]:
        """
        Set a new password for the given user.

        :param str|LDAPDN user: the identification of the user. If not set, \
        the owner of the current LDAP session will be associated.
        :param str new_password: the new password. If not set, the server \
        will generate one and the new password will be returned by this method.
        :param str old_password: the current password of the user.
        :param float timeout: time limit in seconds for the operation.

        :return: if the `new_password` is not set, then the generated \
        password, None otherwise.
        :rtype: str|None
        """
        if type(user) == LDAPDN:
            user = str(user)
        return self._evaluate(super().modify_password(user, new_password,
                                                      old_password), timeout)

    def whoami(self, timeout: float=None) -> Union[str, int]:
        """
        This method can be used to obtain authorization identity.
        
        :param float timeout: time limit in seconds for the operation.

        :return: the authorization ID.
        :rtype: str
         """
        return self._evaluate(super().whoami(), timeout)

