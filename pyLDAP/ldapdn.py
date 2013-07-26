import re
import pyLDAP.errors

class LDAPDN(object):
    """LDAP distinguished name object."""
    __slots__ = ("__rdns")

    def __init__(self, strdn):
        """
            An object for handling valid LDAP distinguished name. 
            :param strdn: The string representation of LDAP distinguished name.
        """
        self.__rdns = self.__str2dn__(strdn)
        # Checking validation by rebuilding the parsed string.
        if str(self) != strdn:
            raise pyLDAP.errors.InvalidDN(strdn)

    def __str2ava__(self, strava):
        """
            Generate attribute type and value tuple from relative distinguished name.
        """
        rdn = []
        # Split relative distinguished name to attribute types and values.
        avas = strava.split("+")
        for av in avas:
            # Get attribute type and value.
            value = av.split("=")
            if len(value) != 2:
                raise pyLDAP.errors.InvalidDN(strava) 
            value[1] = self.__non_escape(value[1])
            rdn.append(tuple(value))
        return tuple(rdn)
    
    def __escape(self, strdn):
        """
            Escaping special characters.
        """
        if strdn:
            strdn = strdn.replace('\\\\', '\\5C')
            strdn = strdn.replace('\,', '\\2C')
            strdn = strdn.replace('\+', '\\2B')
            strdn = strdn.replace('\"', '\\22')
            strdn = strdn.replace('\<' ,'\\3C')
            strdn = strdn.replace('\>' ,'\\3E')
            strdn = strdn.replace('\;' ,'\\3B')
            strdn = strdn.replace('\=' ,'\\3D')  
        return strdn

    def __non_escape(self, strdn):
        """
            Undoing the __escape() function.
        """
        if strdn:
            strdn = strdn.replace('\\5C', '\\\\')
            strdn = strdn.replace('\\2C', '\,')
            strdn = strdn.replace('\\2B', '\+')
            strdn = strdn.replace('\\22', '\"')
            strdn = strdn.replace('\\3C', '\<')
            strdn = strdn.replace('\\3E', '\>')
            strdn = strdn.replace('\\3B', '\;')
            strdn = strdn.replace('\\3D', '\=')  
        return strdn
    
    def __str2dn__(self, strdn):
        """
            Parsing string value to a list of rdns.
        """
        rdns = []
        strdn_ex = self.__escape(strdn)
        # Iterate over the relative distinguished names.
        regex = re.compile(r'([\w]+=([\w\s\\-]|[.])+|[+])*')
        for match in regex.finditer(strdn_ex):
            grp = match.group(0)
            if grp:
                rdns.append(self.__str2ava__(grp))
        return rdns
    
    def __rdn2str(self, rdn):
        """
            Converts RDN to string.
        """
        avs = [] 
        for av in rdn:
            avs.append("=".join((av[0], av[1])))
        rdnstr = "+".join(avs)
        return rdnstr;
    
    def get_rdn(self, i):
        """
            Returns the string representation of the indexed RDN.
            :param i: The index. 
        """
        return self.__rdn2str(self.__rdns[i])
    
    def get_ancestors(self):
        """
            Returns the ancestors of the full distinguished name.
        """
        dn = [] 
        for rdn in self.__rdns[1:]:
            rdnstr = self.__rdn2str(rdn)
            dn.append(rdnstr)
        return ",".join(dn)

    def __str__(self):
        """ The full string format of the distinguished name. """
        if self.__rdns:
            return ",".join((self.get_rdn(0), self.get_ancestors()))
        else:
            return ""
    
    def __repr__(self):
        return "<LDAPDN %s>" % str(self)
    
    @property    
    def rdns(self):
        """ The tuple of relative distinguished name. """
        return tuple(self.__rdns)

    @rdns.setter
    def rdns(self, value):
        raise ValueError("RDNs attribute cannot be set.")
