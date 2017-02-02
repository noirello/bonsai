from .ldapclient import LDAPClient
from .ldapurl import LDAPURL
from .errors import LDAPError

class LDAPReference:
    """
    Object for handling an LDAP reference.

    :param LDAPClient client: a client object.
    :param list references: list of valid LDAP URLs (as string or LDAPURL \
     objects).
    """
    def __init__(self, client, references):
        if type(client) != LDAPClient:
            raise TypeError("Client parameter must be an LDAPClient.")
        self.__client = client
        self.__refs = []
        for ref in references:
            if type(ref) == str:
                self.__refs.append(LDAPURL(ref))
            elif type(ref) == LDAPURL:
                self.__refs.append(ref)
            else:
                raise TypeError("Reference must be string or LDAPURL.")

    @property
    def client(self):
        """ The LDAP client. """
        return self.__client

    @client.setter
    def client(self, value):
       if type(value) != LDAPClient:
            raise TypeError("Client property must be an LDAPClient.")

    @property
    def references(self):
        """ The list of LDAPURLs of the references. """
        return self.__refs

    @references.setter
    def references(self, value):
        raise ValueError("The references attribute cannot be set.")
