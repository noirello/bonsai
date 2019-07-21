from typing import Optional, Type


class LDAPError(Exception):
    """General LDAP error."""

    code = 0

    @classmethod
    def create(cls, code: int) -> Type["LDAPError"]:
        """ Create a new LDAPError type with `code` error code. """
        cls.code = code
        return cls

    @property
    def hexcode(self) -> int:
        """ Error code in 16 bit length hexadecimal format. """
        return (self.code + (1 << 16)) % (1 << 16)

    def __str__(self) -> str:
        return "{} (0x{:04X} [{:d}])".format(
            self.args[0] if self.args else "", self.hexcode, self.code
        )


class InvalidDN(LDAPError):
    """Raised, when dn string is not a valid distinguished name."""

    code = 0x22


class ConnectionError(LDAPError):
    """Raised, when client is not able to connect to the server."""

    code = -1


class AuthenticationError(LDAPError):
    """Raised, when authentication is failed with the server."""

    code = 0x31


class AuthMethodNotSupported(LDAPError):
    """Raised, when the chosen authentication method is not supported. """

    code = 0x07


class ObjectClassViolation(LDAPError):
    """Raised, when try to add or modify an LDAP entry and it violates the
    object class rules."""

    code = 0x41


class AlreadyExists(LDAPError):
    """Raised, when try to add an entry and it already exists in the
    dictionary. """

    code = 0x44


class InvalidMessageID(LDAPError):
    """Raised, when try to get the result with a message ID that belongs to an
    unpending or already finished operation."""

    code = -100


class ClosedConnection(LDAPError):
    """Raised, when try to perform LDAP operation with closed connection."""

    code = -101


class InsufficientAccess(LDAPError):
    """Raised, when the user has insufficient access rights."""

    code = 0x32


class TimeoutError(LDAPError):
    """Raised, when the specified timeout is exceeded. """

    code = -5


class ProtocolError(LDAPError):
    """Raised, when protocol error is happened."""

    code = 0x02


class UnwillingToPerform(LDAPError):
    """Raised, when the server is not willing to handle requests."""

    code = 0x35


class NoSuchObjectError(LDAPError):
    """
    Raised, when operation (except search) is performed on
    an entry that is not found in the directory.
    """

    code = 0x20


class AffectsMultipleDSA(LDAPError):
    """Raised, when multiple directory server agents are affected. """

    code = 0x47


class SizeLimitError(LDAPError):
    """
    Raised, when the search operation exceeds the client side size
    limit or server side size limit that's applied to the bound user.
    """

    code = 0x04


class NotAllowedOnNonleaf(LDAPError):
    """Raised, when the operation is not allowed on a nonleaf object."""

    code = 0x42


class NoSuchAttribute(LDAPError):
    """Raised, when the given attribute of an entry does not exist."""

    code = 0x10


class TypeOrValueExists(LDAPError):
    """
    Raised, when the attribute already exists or the value
    has been already assigned.
    """

    code = 0x14


class PasswordPolicyError(LDAPError):
    """ General exception for password policy errors. """

    _dflt_args = ("Password policy error.",)

    def __init__(self, msg: Optional[str] = None) -> None:
        super().__init__(msg)
        self.args = self._dflt_args if msg is None else (msg,)


class PasswordExpired(PasswordPolicyError, AuthenticationError):
    """
    Raised, when the password policy is set, available on the server
    and the user's password is expired.
    """

    code = -200
    _dflt_args = ("User's password is expired.",)


class AccountLocked(PasswordPolicyError, AuthenticationError):
    """
    Raised, when the password policy is set, available on the server
    and the user's account is locked.
    """

    code = -201
    _dflt_args = ("User's account is locked.",)


class ChangeAfterReset(PasswordPolicyError):
    """
    Raised, when the password policy is set, available on the server
    and it signifies that the password must be changed before the user
    will be allowed to perform any operation (except bind and modify).
    """

    code = -202
    _dflt_args = ("User's password is expired.",)


class PasswordModNotAllowed(PasswordPolicyError):
    """
    Raised, when the password policy is set, available on the server
    and the user is restricted from changing her password.
    """

    code = -203
    _dflt_args = ("Password modification is not allowed.",)


class MustSupplyOldPassword(PasswordPolicyError):
    """
    Raised, when the password policy is set, available on the server
    and the existing password is not specified.
    """

    code = -204
    _dflt_args = ("Old password must be provided.",)


class InsufficientPasswordQuality(PasswordPolicyError):
    """
    Raised, when the password policy is set, available on the server
    and the user's password is not strong enough.
    """

    code = -205
    _dflt_args = ("Password does not pass quality checking.",)


class PasswordTooShort(PasswordPolicyError):
    """
    Raised, when the password policy is set, available on the server
    and the user's password is too short to be set.
    """

    code = -206
    _dflt_args = ("Password is too short.",)


class PasswordTooYoung(PasswordPolicyError):
    """
    Raised, when the password policy is set, available on the server
    and the user's password is too young to be modified.
    """

    code = -207
    _dflt_args = ("Password is too young to be modified.",)


class PasswordInHistory(PasswordPolicyError):
    """
    Raised, when the password policy is set, available on the server
    and the user's password is in the history.
    """

    code = -208
    _dflt_args = ("User's password is in the history.",)


def _get_error(code: int) -> type:
    """ Return an error by code number. """
    if code == -1 or code == 0x51 or code == -11:
        # WinLDAP returns 0x51 for Server Down.
        # OpenLDAP returns -11 for Connection error.
        return ConnectionError.create(code)
    elif code == 0x02:
        return ProtocolError
    elif code == 0x04:
        return SizeLimitError
    elif code == 0x07:
        return AuthMethodNotSupported
    elif code == 0x10:
        return NoSuchAttribute
    elif code == 0x14:
        return TypeOrValueExists
    elif code == 0x20:
        return NoSuchObjectError
    elif code == 0x22:
        return InvalidDN
    elif code == 0x31:
        return AuthenticationError
    elif code == 0x32:
        return InsufficientAccess
    elif code == 0x35:
        return UnwillingToPerform
    elif code == 0x41:
        return ObjectClassViolation
    elif code == 0x42:
        return NotAllowedOnNonleaf
    elif code == 0x44:
        return AlreadyExists
    elif code == 0x47:
        return AffectsMultipleDSA
    elif code == -5 or code == 0x55:
        return TimeoutError.create(code)
    elif code == -100:
        return InvalidMessageID
    elif code == -101:
        return ClosedConnection
    elif code == -200:
        return PasswordExpired
    elif code == -201:
        return AccountLocked
    elif code == -202:
        return ChangeAfterReset
    elif code == -203:
        return PasswordModNotAllowed
    elif code == -204:
        return MustSupplyOldPassword
    elif code == -205:
        return InsufficientPasswordQuality
    elif code == -206:
        return PasswordTooShort
    elif code == -207:
        return PasswordTooYoung
    elif code == -208:
        return PasswordInHistory
    else:
        return LDAPError.create(code)
