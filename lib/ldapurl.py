from ipaddress import IPv6Address
from typing import Any, List, Union, Tuple, Optional, NoReturn

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

    def __init__(self, strurl: Optional[str] = None) -> None:
        """ Init method. """
        self.__hostinfo = ('ldap', 'localhost', 389) # type: Tuple[str, str, int]
        # Default values to the search parameters.
        self.__searchinfo = (LDAPDN(""), [], "", "")  # type: Tuple[LDAPDN, List[str], str, str]
        self.__extensions = [] # type: List[str]
        self.__ipv6 = False
        if strurl:
            self.__str2url(strurl)

    def __delattr__(self, attr: str) -> NoReturn:
        """ None of the attributions can be deleted. """
        raise AttributeError("%s cannot be deleted." % attr)

    def __str2url(self, strurl: str) -> None:
        """ Parsing string url to LDAPURL."""
        # RegExp for [ldap|ldaps]://[host]:[port]/[basedn]?[attrs]?[scope]
        # ?[filter]?[exts]
        valid = re.compile(r"^(ldap|ldaps)://(([^:/?]*)?([:]([1-9][0-9]{0,4}))?"
                           r"|[[]?([^/?\]]*)([]][:]([1-9][0-9]{0,4}))?)[/]?"
                           r"([^]/:?]*)?[\?]?([^]:?]*)?[\?]?([^]:?]*)?[\?]?"
                           r"([^]:?]*)?[\?]?([^]:?]*)?$",
                           re.IGNORECASE)
        scheme, host, port = self.__hostinfo
        binddn, attrlist, scope, filterexp = self.__searchinfo
        match = valid.match(strurl)
        if match:
            scheme = match.group(1).lower()
            if scheme == "ldaps":
                port = 636
            # The hostname
            if match.group(3) or match.group(6):
                hostname = match.group(3) or match.group(6)
                if self.is_valid_hostname(hostname):
                    host = hostname
                    if match.group(6):
                        self.__ipv6 = True
                else:
                    raise ValueError("'%s' has an invalid hostname." % strurl)
            # The portnumber for IPv4
            if match.group(5):
                port = int(match.group(5))
            # The portnumber for IPv6
            if match.group(8):
                port = int(match.group(8))
            # The LDAP bind DN
            if match.group(9):
                binddn = LDAPDN(urllib.parse.unquote(match.group(9)))
            # Attributes
            if match.group(10):
                attrlist = match.group(10).split(',')
            # Scope (base/one/sub)
            if match.group(11):
                _scope = match.group(11).lower()
                if _scope != "base" and _scope != "one" and _scope != "sub":
                    raise ValueError("Invalid scope type.")
                scope = _scope
            # Filter
            if match.group(12):
                filterexp = urllib.parse.unquote(match.group(12))
            # Extensions
            if match.group(13):
                self.__extensions = match.group(13).split(',')
            self.__hostinfo = (scheme, host, port)
            self.__searchinfo = (binddn, attrlist, scope, filterexp)
        else:
            raise ValueError("'%s' is not a valid LDAP URL." % strurl)

    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
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
    def host(self, value: str) -> None:
        """ Setter for hostname. """
        # RegExp for valid hostname.
        if not self.is_valid_hostname(value):
            raise ValueError("'%s' is not a valid host name." % value)
        else:
            self.__hostinfo = (self.__hostinfo[0], value, self.__hostinfo[2])

    @property
    def port(self) -> int:
        """ The portnumber. """
        return self.__hostinfo[2]

    @port.setter
    def port(self, value: int) -> None:
        """ Setter for portnumber. """
        if isinstance(value, int) and (value > 0 and value < 65535):
            self.__hostinfo = (self.__hostinfo[0], self.__hostinfo[1], value)
        else:
            raise ValueError("Port must be an int between 1 and 65535.")

    @property
    def scheme(self) -> str:
        """ The URL scheme."""
        return self.__hostinfo[0]

    @scheme.setter
    def scheme(self, value: str) -> None:
        """ Setter for URL scheme."""
        # It must be ldap or ldaps
        if isinstance(value, str) and value.lower() == 'ldap' \
            or value.lower() == 'ldaps':
            self.__hostinfo = (value.lower(), self.__hostinfo[1], self.__hostinfo[2])
        else:
            raise ValueError("Scheme only be 'ldap' or 'ldaps'.")

    @property
    def basedn(self) -> LDAPDN:
        """ The LDAP distinguished name for binding. """
        return self.__searchinfo[0]

    @basedn.setter
    def basedn(self, value: Union[LDAPDN, str]) -> None:
        """ Setter for LDAP distinguished name for binding. """
        self.__searchinfo = (LDAPDN(str(value)), self.__searchinfo[1],
                             self.__searchinfo[2], self.__searchinfo[3])

    @property
    def attributes(self) -> List[str]:
        """ The searching attributes. """
        return self.__searchinfo[1]

    @property
    def scope(self) -> str:
        """ The searching scope. """
        return self.__searchinfo[2]

    @scope.setter
    def scope(self, value: str) -> None:
        """ Setter for searching scope. """
        if isinstance(value, str):
            if value.lower() == "base" or value.lower() == "one" \
                or value.lower() == "sub":
                self.__searchinfo = (self.__searchinfo[0],
                                     self.__searchinfo[1],
                                     value, self.__searchinfo[3])
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
            return "{0}://[{1}]:{2:d}".format(*self.__hostinfo)
        else:
            return "{0}://{1}:{2:d}".format(*self.__hostinfo)

    def __eq__(self, other: Any) -> bool:
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
