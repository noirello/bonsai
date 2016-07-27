from typing import Union

from ._bonsai import ldapentry
from .ldapdn import LDAPDN

class LDAPEntry(ldapentry):
    def __init__(self, dn: Union[LDAPDN, str], conn=None):
        super().__init__(str(dn), conn)

    def delete(self, timeout: float=None) -> Union[bool, int]:
        """
        Remove LDAP entry from the dictionary server.

        :param float timeout: time limit in seconds for the operation.        
        :return: True, if the operation is finished.
        :rtype: bool
        """
        return self.connection._evaluate(super().delete(), timeout)

    def modify(self, timeout: float=None) -> Union[bool, int]:
        """
        Send entry's modifications to the dictionary server.

        :param float timeout: time limit in seconds for the operation.
        :return: True, if the operation is finished.
        :rtype: bool
        """
        return self.connection._evaluate(super().modify(), timeout)

    def rename(self, newdn: Union[str, LDAPDN],
               timeout: float=None) -> Union[bool, int]:
        """
        Change the entry's distinguished name.

        :param str|LDAPDN newdn: the new DN of the entry.
        :param float timeout: time limit in seconds for the operation.
        :return: True, if the operation is finished.
        :rtype: bool
        """
        if type(newdn) == LDAPDN:
            newdn = str(newdn)
        return self.connection._evaluate(super().rename(newdn), timeout)

    def update(self, *args, **kwds) -> None:
        """
        Update the LDAPEntry with the key/value pairs from other, overwriting existing keys.
        (Same as dict's update method.)
        """
        if args:
            if hasattr(args[0], "keys"):
                # Working with a dict on the parameter list.
                for key, value in args[0].items():
                    self.__setitem__(key, value)
            else:
                # Working with a sequence.
                for tup in args[0]:
                    if len(tup) != 2:
                        raise ValueError("Sequence element has more then 2 element.")
                    self.__setitem__(tup[0], tup[1])
        if kwds:
            # Key/value pairs are listed on the parameter list.
            for key, value in kwds.items():
                self.__setitem__(key, value)

    def clear(self) -> None:
        keys = list(self.keys())
        for key in keys:
            del self[key]

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def pop(self, *args):
        """
        LDAPEntry.pop(k[,d]) -> v, remove specified key and return the
        corresponding value. If key is not found, d is returned if given,
        otherwise KeyError is raised.

        :param key: the key.
        :param dflt: if key is not found, d is returned.
        :return: the value from the LDAPEntry.
        """
        if len(args) > 2:
            raise TypeError("pop expected at most 2 arguments, got %d" % len(args))
        try:
            key = args[0]
            value = self[key]
            del self[key]
            return value
        except IndexError:
            raise TypeError("pop expected at least 1 arguments, got 0")
        except KeyError as err:
            try:
                dflt = args[1]
                return dflt
            except IndexError:
                raise err

    def popitem(self):
        """
        LDAPEntry.popitem() -> (k, v), remove and return some (key, value)
        pair as a 2-tuple; but raise KeyError if LDAPEntry is empty.
        """
        try:
            key = list(self.keys()).pop(0)
            value = self[key]
            del self[key]
            return (key, value)
        except IndexError:
            raise KeyError("popitem(): LDAPEntry is empty")


    def __eq__(self, other):
        """
        Two LDAPEntry objects are considered equals, if their DN is the same.
        
        :param other: the other comparable object.
        :return: True if the two object are equals.
        :rtyype: bool
        """
        if isinstance(other, self.__class__):
            return self.dn == other.dn
        else:
            return super().__eq__(other)

    def _status(self):
        status = {}
        for key, value in self.items():
            status[key] = value._status_dict
        status['@deleted_keys'] = self.deleted_keys
        return status