import re
import urllib.parse
from pyLDAP.ldapdn import LDAPDN

class LDAPURL(object):
    __slots__ = ("__hostinfo", "__bindinfo", "__extensions")

    def __init__(self, strurl=None):
        """
            LDAP URL object for handling LDAP connection informations,
            such as hostname, port, LDAP bind DN, search attributes, 
            scope (base,sub or one) and filter, extensions. 
            If `strurl` is None, then the default url is 
            ldap://localhost:389.
            :param strurl: String representation of a valid LDAP URL. 
            Must be started with ldap:// or ldaps://.
        """
        self.__hostinfo = ['ldap', 'localhost', 389]
        self.__bindinfo = [None, None, None, None]
        self.__extensions = None
        if strurl:
            self.__str2url(strurl)

    def __delattr__(self, attr):
        """ None of the attributions can be deleted. """
        raise Exception("%s cannot be deleted." % attr)

    def __str2url(self, strurl):
        """
            Parsing string url to LDAPURL.
        """
        # RegExp for [ldap|ldaps]://[host]:[port]/[binddn]?[attrs]?[scope]?[filter]?[exts]
        valid = re.compile(r"^(ldap|ldaps)://((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))?([:][1-9][0-9]{0,4})?(/.*)?$", re.IGNORECASE)
        match = valid.match(strurl)     
        if match:
            self.__hostinfo[0] = match.group(1).lower()
            if self.__hostinfo[0] == "ldaps":
                self.__hostinfo[2] = 636
            # The full hostname
            if match.group(2):
                 self.__hostinfo[1] = match.group(2)
            # The portnumber
            if match.group(6):
                 self.__hostinfo[2] = int(match.group(6)[1:])
            # The rest of the LDAP URL.
            if match.group(7):
                rest = match.group(7)[1:].split("?")
                # Bind DN
                self.__bindinfo[0] = LDAPDN(urllib.parse.unquote(rest[0]))
                if len(rest) > 1:
                    # Attributes
                    if len(rest[1]) != 0:
                        self.__bindinfo[1] = rest[1].split(',')
                if len(rest) > 2:
                    # Scope (base/one/sub)
                    scope = rest[2].lower()
                    if scope != "base" and scope != "one" and scope != "sub":
                        raise ValueError()
                    self.__bindinfo[2] = scope
                if len(rest) > 3:
                    # Filter
                    self.__bindinfo[3] = urllib.parse.unquote(rest[3])
                if len(rest) > 4:
                    # Extensions
                    self.__extensions = rest[4].split(',')
        else:
            raise ValueError()

    @property
    def host(self):
        """ The hostname."""
        return self.__hostinfo[1] 

    @host.setter
    def host(self, value):
        # RegExp for valid hostname.
        valid = re.compile(r"((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))", re.IGNORECASE)
        match = valid.match(value)
        if match is None:
            raise ValueError("'%s' is not a valid host name." % value)
        else:
            self.__hostinfo[1] = value 

    @property
    def port(self):
        """ The portnumber. """
        return self.__hostinfo[2]
    
    @port.setter
    def port(self, value):
        if type(value) == int and (value > 0 and value < 65535):
            self.__hostinfo[2] = value
        else:
            raise ValueError("Port must be an int between 1 and 65535.")

    @property
    def scheme(self):
        """ The url scheme."""
        return self.__hostinfo[0]

    @scheme.setter
    def scheme(self, value):
        # It must be ldap or ldaps
        if type(value) == str and value.lower() == 'ldap' or value.lower() == 'ldaps':
            self.__hostinfo[0] = value.lower()
        else:
            raise ValueError("Scheme only be 'ldap' or 'ldaps'.")

    @property
    def binddn(self):
        """ The LDAP distinguished name for binding. """
        return self.__bindinfo[0]

    @binddn.setter
    def binddn(self, value):
        if type(value) == LDAPDN:
            self.__bindinfo[0] = value
        else:
            raise ValueError("Bind DN must be a type of LDAPDN.")

    @property
    def attributes(self):
        """ The searching attributes. """
        return self.__bindinfo[1]

    @property
    def scope(self):
        """ The searching scope. """
        return self.__bindinfo[2]

    @scope.setter
    def scope(self, value):
        if type(value) == str:
            if value.lower() == "base" or value.lower() == "one" or value.lower() == "sub":
                self.__bindinfo[2] = value
            else:
                raise ValueError("Scope must be one of these: 'base', 'one', 'sub'.")
        else:
            raise ValueError("Scope must be a string.")

    @property
    def filter(self):
        """ The seasrching filter. """ 
        return self.__bindinfo[3]
    
    def get_address(self):
        """ Return the full address of the host. """
        return "%s://%s:%d" % tuple(self.__hostinfo)
    
    def __str__(self):
        """
            Returns the full format of LDAP URL.
        """       
        strurl = self.get_address()
        strattrs = ""
        strdn = ""
        strscope = ""
        strfilter = ""
        strexts = ""
        if self.__bindinfo[0]:
            strdn = str(self.__bindinfo[0])
        if self.__bindinfo[1]:
            strattrs = ",".join(self.__bindinfo[1])
        if self.__bindinfo[2]:
            strscope = self.__bindinfo[2]
        if self.__bindinfo[3]:
            strfilter = self.__bindinfo[3]
        if self.__extensions:    
            strexts = ",".join(self.__extensions)
        strbind = "?".join((strdn, strattrs, strscope, strfilter, strexts))
        # Remove unneccesary question marks at the end of the string.
        while strbind[-1] == '?':
            strbind = strbind[:-1]
            if len(strbind) == 0:
                break
        if len(strbind) != 0:
            strurl = "%s/%s" % (strurl, strbind)
        return strurl
    
    def __repr__(self):
        return "<LDAPURL %s>" % str(self) 