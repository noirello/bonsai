from typing import List, Union

from .ldapclient import LDAPClient
from .ldapurl import LDAPURL


class LDAPReference:
    """
    Object for handling an LDAP reference.

    :param LDAPClient client: a client object.
    :param list references: list of valid LDAP URLs (as string or \
    :class:`LDAPURL` objects).
    """

    def __init__(
        self, client: LDAPClient, references: List[Union[str, LDAPURL]]
    ) -> None:
        if not isinstance(client, LDAPClient):
            raise TypeError("Client parameter must be an LDAPClient.")
        self.__client = client
        self.__refs = []  # type: List[LDAPURL]
        for ref in references:
            if isinstance(ref, str):
                self.__refs.append(LDAPURL(ref))
            elif isinstance(ref, LDAPURL):
                self.__refs.append(ref)
            else:
                raise TypeError("Reference must be string or LDAPURL.")

    @property
    def client(self) -> LDAPClient:
        """The LDAP client."""
        return self.__client

    @client.setter
    def client(self, value: LDAPClient) -> None:
        if not isinstance(value, LDAPClient):
            raise TypeError("Client property must be an LDAPClient.")
        self.__client = value

    @property
    def references(self) -> List[LDAPURL]:
        """The list of LDAPURLs of the references."""
        return self.__refs
