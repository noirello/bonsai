from ._bonsai import ldapconnection
from .ldapdn import LDAPDN

class LDAPConnection(ldapconnection):
    """
    Handles the connection to an LDAP server.
    If `is_async` is set to True, then all LDAP operations that belong \
    to this connection will return a message ID. This ID can be used to \
    poll the status of the operation.

    :param LDAPClient client: a client object.
    :param bool is_async: set True to create an asynchronous connection.
    """
    def __init__(self, client, is_async=False):
        self.__client = client
        super().__init__(client, is_async)

    def __enter__(self):
        """ Context manager entry point. """
        return self

    def __exit__(self, *exc):
        """ Context manager exit point. """
        self.close()

    def _evaluate(self, msg_id, timeout=None):
        """
        Depending on the connection's type (asynchronous or synchronous),
        it returns a message ID or the result of the LDAP operation.

        :param int msg_id: the ID of the LDAP operation.
        :param float timeout: time limit in seconds for the operation.
        :return: msg_id if the connection is async, otherwise the result \
        of the operation.
        """
        if self.async:
            return msg_id
        else:
            return self.get_result(msg_id, timeout)

    def add(self, entry, timeout=None):
        """
        Add new entry to the directory server.

        :param LDAPEntry entry: the new entry.
        :param float timeout: time limit in seconds for the operation.
        :return: True, if the operation is finished.
        :rtype: bool
        """
        return self._evaluate(super().add(entry), timeout)

    def delete(self, dnstr, timeout=None):
        """
        Remove entry from the directory server.

        :param str dnstr: the string format of the entry's DN.
        :param float timeout: time limit in seconds for the operation.
        :return: True, if the operation is finished.
        :rtype: bool
        """
        if type(dnstr) == LDAPDN:
            dnstr = str(dnstr)
        return self._evaluate(super().delete(dnstr), timeout)

    def open(self, timeout=None):
        """
        Open the LDAP connection.

        :param float timeout: time limit in seconds for the operation.
        :return: The :class:`LDAPConnection` object itself, if \
        it is a synchronous or a message ID if it's an asynchronous connection.
        :rtype: :class:`LDAPConnection` or iterator.
        """
        return self._evaluate(super().open(), timeout)

    def search(self, base=None, scope=None, filter=None, attrlist=None,
               timeout=None, sizelimit=0, attrsonly=False):
        # Documentation in the docs/api.rst with detailed examples.
        # Load values from the LDAPURL, if it is not presented on the
        # parameter list.
        _base = str(base) if base is not None else str(self.__client.url.basedn)
        _scope = scope if scope is not None else self.__client.url.scope_num
        _filter = filter if filter is not None else self.__client.url.filter
        _attrlist = attrlist if attrlist is not None else self.__client.url.attributes
        _timeout = timeout if timeout is not None else 0.0
        msg_id = super().search(_base, _scope, _filter, _attrlist,
                                _timeout, sizelimit, attrsonly)
        if self.async:
            return msg_id
        else:
            if self.page_size > 1:
                return self.__paged_search(self.get_result(msg_id, timeout))
            return list(self.get_result(msg_id, timeout))

    def __paged_search(self, res):
        while True:
            yield from res
            msg_id = res.acquire_next_page()
            if msg_id is None:
                break
            res = self.get_result(msg_id)

    def set_sort_order(self, sort_list):
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
                raise ValueError("All element of sort_list must be a non empty string.")
            if attr[0] == '-':
                # Set reverse order.
                sort_attrs.append((attr[1:], True))
            else:
                sort_attrs.append((attr, False))
        if len(sort_list) > len(set(map(lambda x: x[0].lower, sort_attrs))):
            raise ValueError("Attribute names must be different from each other.")
        super().set_sort_order(sort_attrs)

    def whoami(self, timeout=None):
        """
        This method can be used to obtain authorization identity.
        
        :param float timeout: time limit in seconds for the operation.

        :return: the authorization ID.
        :rtype: str
         """
        return self._evaluate(super().whoami(), timeout)

