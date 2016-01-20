class LDAPError(Exception):
    """General LDAP error."""

class InvalidDN(LDAPError):
    """Raised, when dn string is not a valid distinguished name."""

class ConnectionError(LDAPError):
    """Raised, when client is not able to connect to the server."""

class AuthenticationError(LDAPError):
    """Raised, when authentication is failed with the server."""

class AuthMethodNotSupported(LDAPError):
    """Raised, when the chosen authentication method is not supported. """

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

class InsufficientAccess(LDAPError):
    """Raised, when the user has insufficient access rights."""

class TimeoutError(LDAPError):
    """Raised, when the specified timeout is exceeded. """

class ProtocolError(LDAPError):
    """Raised, when protocol error is happened."""

def _get_error(code):
    """ Return an error by code number. """
    if code == -1 or code == 0x51 or code == -11:
        # WinLDAP returns 0x51 for Server Down.
        # OpenLDAP returns -11 for Connection error.
        return ConnectionError
    elif code == 0x02:
        return ProtocolError
    elif code == 0x07:
        return AuthMethodNotSupported
    elif code == 0x22:
        return InvalidDN
    elif code == 0x31:
        return AuthenticationError
    elif code == 0x32:
        return InsufficientAccess
    elif code == 0x41:
        return ObjectClassViolation
    elif code == 0x44:
        return AlreadyExists
    elif code == -5 or code == 0x55:
        return TimeoutError
    elif code == -100:
        return InvalidMessageID
    elif code == -101:
        return ClosedConnection
    else:
        return LDAPError
