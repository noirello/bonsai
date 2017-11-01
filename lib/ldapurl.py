from ipaddress import IPv6Address
from typing import Any, List, Union

import re
import urllib.parse
from .ldapdn import LDAPDN

class LDAPURL:
    """
    LDAP URL object for handling LDAP connection informations, such as
    hostname, port, LDAP bind DN, search attributes, scope (base,sub or
    one) filter, and extensions. If `strurl` is None, then the default
    url is `ldap://localhost:389`.

    :param str strurl: string representation of a valid LDAP URL. Must \
    be started with `ldap://` or `ldaps://`.

    :raises ValueError: if the string parameter is not a valid LDAP URL.
    """
    __slots__ = ("__hostinfo", "__searchinfo", "__extensions", "__ipv6")

    def __init__(self, strurl: str=None) -> None:
        """ Init method. """
        self.__hostinfo = ['ldap', 'localhost', 389] # type: List[Any]
        # Default values to the search parameters.
        self.__searchinfo = ["", [], "", ""]  # type: List[Any]
        self.__extensions = [] # type: List[str]
        self.__ipv6 = False
        if strurl:
            self.__str2url(strurl)

    def __delattr__(self, attr):
        """ None of the attributions can be deleted. """
        raise AttributeError("%s cannot be deleted." % attr)

    def __str2url(self, strurl):
        """ Parsing string url to LDAPURL."""
        # RegExp for [ldap|ldaps]://[host]:[port]/[basedn]?[attrs]?[scope]
        # ?[filter]?[exts]
        valid = re.compile(r"^(ldap|ldaps)://(([^:/?]*)?([:]([1-9][0-9]{0,4}))?"
                           r"|[[]?([^/?\]]*)([]][:]([1-9][0-9]{0,4}))?)[/]?"
                           r"([^]/:?]*)?[\?]?([^]:?]*)?[\?]?([^]:?]*)?[\?]?"
                           r"([^]:?]*)?[\?]?([^]:?]*)?$",
                           re.IGNORECASE)
        match = valid.match(strurl)
        if match:
            self.__hostinfo[0] = match.group(1).lower()
            if self.__hostinfo[0] == "ldaps":
                self.__hostinfo[2] = 636
            # The hostname
            if match.group(3) or match.group(6):
                hostname = match.group(3) or match.group(6)
                if self.is_valid_hostname(hostname):
                    self.__hostinfo[1] = hostname
                    if match.group(6):
                        self.__ipv6 = True
                else:
                    raise ValueError("'%s' has an invalid hostname." % strurl)
            # The portnumber for IPv4
            if match.group(5):
                self.__hostinfo[2] = int(match.group(5))
            # The portnumber for IPv6
            if match.group(8):
                self.__hostinfo[2] = int(match.group(8))
            # The LDAP bind DN
            if match.group(9):
                self.__searchinfo[0] = LDAPDN(urllib.parse.unquote(match.group(9)))
            # Attributes
            if match.group(10):
                self.__searchinfo[1] = match.group(10).split(',')
            # Scope (base/one/sub)
            if match.group(11):
                scope = match.group(11).lower()
                if scope != "base" and scope != "one" and scope != "sub":
                    raise ValueError("Invalid scope type.")
                self.__searchinfo[2] = scope
            # Filter
            if match.group(12):
                self.__searchinfo[3] = urllib.parse.unquote(match.group(12))
            # Extensions
            if match.group(13):
                self.__extensions = match.group(13).split(',')
        else:
            raise ValueError("'%s' is not a valid LDAP URL." % strurl)

    @staticmethod
    def is_valid_hostname(hostname: str):
        """
        Validate a hostname.
        """
        hostname_regex = re.compile(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]"
                                    r"*[a-zA-Z0-9])\.)*([A-Za-z0-9]|"
                                    r"[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")
        try:
            # Try parsing IPv6 address.
            IPv6Address(hostname)
            return True
        except ValueError:
            # Try IPv4 and standard hostname.
            if hostname_regex.match(hostname):
                return True
            return False

    @property
    def host(self) -> str:
        """ The hostname. """
        return self.__hostinfo[1]

    @host.setter
    def host(self, value: str):
        """ Setter for hostname. """
        # RegExp for valid hostname.
        if not self.is_valid_hostname(value):
            raise ValueError("'%s' is not a valid host name." % value)
        else:
            self.__hostinfo[1] = value

    @property
    def port(self) -> int:
        """ The portnumber. """
        return self.__hostinfo[2]

    @port.setter
    def port(self, value: int):
        """ Setter for portnumber. """
        if type(value) == int and (value > 0 and value < 65535):
            self.__hostinfo[2] = value
        else:
            raise ValueError("Port must be an int between 1 and 65535.")

    @property
    def scheme(self) -> str:
        """ The URL scheme."""
        return self.__hostinfo[0]

    @scheme.setter
    def scheme(self, value: str):
        """ Setter for URL scheme."""
        # It must be ldap or ldaps
        if type(value) == str and value.lower() == 'ldap' \
            or value.lower() == 'ldaps':
            self.__hostinfo[0] = value.lower()
        else:
            raise ValueError("Scheme only be 'ldap' or 'ldaps'.")

    @property
    def basedn(self) -> LDAPDN:
        """ The LDAP distinguished name for binding. """
        return self.__searchinfo[0]

    @basedn.setter
    def basedn(self, value: Union[LDAPDN, str]):
        """ Setter for LDAP distinguished name for binding. """
        self.__searchinfo[0] = LDAPDN(str(value))

    @property
    def attributes(self):
        """ The searching attributes. """
        return self.__searchinfo[1]

    @property
    def scope(self) -> str:
        """ The searching scope. """
        return self.__searchinfo[2]

    @scope.setter
    def scope(self, value: str):
        """ Setter for searching scope. """
        if type(value) == str:
            if value.lower() == "base" or value.lower() == "one" \
                or value.lower() == "sub":
                self.__searchinfo[2] = value
            else:
                raise ValueError("""Scope must be one of these:
                            'base', 'one', 'sub'.""")
        else:
            raise TypeError("Scope must be a string.")

    @property
    def scope_num(self) -> int:
        """ Return the searching scope number. """
        if self.scope == "base":
            return 0
        if self.scope == "one":
            return 1
        if self.scope == "sub":
            return 2
        else:
            return -1

    @property
    def filter(self) -> str:
        """ The searching filter. """
        return self.__searchinfo[3]

    def get_address(self) -> str:
        """
        Return the full address of the host.
        """
        if self.__ipv6:
            return "%s://[%s]:%d" % tuple(self.__hostinfo)
        else:
            return "%s://%s:%d" % tuple(self.__hostinfo)

    def __eq__(self, other) -> bool:
        """
        Check equality of two LDAPURL or an LDAPURL and a string.
        """
        if isinstance(other, LDAPURL):
            return (self.scheme == other.scheme and
                    self.host == other.host and
                    self.port == other.port and
                    self.basedn == other.basedn and
                    self.scope == other.scope and
                    self.filter == other.filter and
                    self.attributes == other.attributes)
        elif isinstance(other, str):
            try:
                other = LDAPURL(other)
            except ValueError:
                return False
            return self == other
        else:
            return False

    def __str__(self) -> str:
        """ Returns the full format of LDAP URL. """
        strurl = self.get_address()
        strattrs = ""
        strexts = ""
        if self.__searchinfo[1]:
            strattrs = ",".join(self.__searchinfo[1])
        if self.__extensions:
            strexts = ",".join(self.__extensions)
        strbind = "?".join((str(self.__searchinfo[0]), strattrs,
                            self.__searchinfo[2], self.__searchinfo[3],
                            strexts))
        # Remove unnecessary question marks at the end of the string.
        while strbind[-1] == '?':
            strbind = strbind[:-1]
            if len(strbind) == 0:
                break
        if len(strbind) != 0:
            strurl = "%s/%s" % (strurl, strbind)
        return strurl

    def __repr__(self) -> str:
        """ The LDAPURL representation. """
        return "<LDAPURL %s>" % str(self)
