class LDAPError(Exception):
    """General LDAP error."""

class InvalidDN(LDAPError):
    """Raised, when dn string is not a valid distinguished name."""

class ConnectionError(LDAPError):
    """Raised, when client is not able to connect to the server."""

class AuthenticationError(LDAPError):
    """Raised, when authentication is failed with the server."""

class ObjectClassViolation(LDAPError):
    """Raised, when try to add or modify an LDAP entry and it violates the
    object class rules."""

class AlreadyExists(LDAPError):
    """Raised, when try to add an entry and it already exists in the
    dictionary. """

class InvalidMessageID(LDAPError):
    """Raised, when try to get the result with a message ID that belongs to an
    unpending or already finished operation."""

class ClosedConnection(LDAPError):
    """Raised, when try to perform LDAP operation with closed connection."""

def __get_error(code):
    """ Return an error by code number. """
    if code == -1 or code == 0x51:
	    # WinLDAP returns 0x51 for Server Down.
        return ConnectionError
    elif code == 0x22:
        return InvalidDN
    elif code == 0x31:
        return AuthenticationError
    elif code == 0x41:
        return ObjectClassViolation
    elif code == 0x44:
        return AlreadyExists
    elif code == -10:
        return InvalidMessageID
    elif code == -11:
        return ClosedConnection
    else:
        return LDAPError
