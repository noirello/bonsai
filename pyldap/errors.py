class LDAPError(Exception):
    """General LDAP error."""

class NotConnected(LDAPError):
    """Raised, when an operation needs an open LDAP connection."""

class InvalidDN(LDAPError):
    """Raised, when dn string is not a valid distinguished name."""

class ConnectionError(LDAPError):
    """Raised, when client is not able to connect to the server."""

class AuthenticationError(LDAPError):
    """Raised, when authentication is failed with the server."""

def get_error(code):
    """ Return an error by code number. """
    if code == -1:
        return ConnectionError
    elif code == 0x31:
        return AuthenticationError
    else:
        return LDAPError
