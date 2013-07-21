import re
import pyLDAP.errors

class LDAPDN(object):
    """LDAP distinguished name object."""
    __slots__ = ("__rdns")

    def __init__(self, strdn):
        self.__rdns = self.__str2dn__(strdn)
        # Checking validation by rebuilding the parsed string.
        if str(self) != strdn:
            raise pyLDAP.errors.InvalidDN(strdn)

    """
        Generate attribute type and value tuple from relative distinguished name.
    """
    def __str2ava__(self, strava):   
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
        return rdn
    """
        Escaping special characters.
    """
    def __escape(self, strdn):
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

    """
        Undoing the __escape() function.
    """
    def __non_escape(self, strdn):
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
    
    """
        Parsing string value to a list of rdns.
    """
    def __str2dn__(self, strdn):
        rdns = []
        strdn_ex = self.__escape(strdn)
        # Iterate over the relative distinguished names.
        regex = re.compile(r'([\w]+=([\w\s\\-]|[.])+|[+])*')
        for match in regex.finditer(strdn_ex):
            grp = match.group(0)
            if grp:
                rdns.append(self.__str2ava__(grp))
        return rdns

    def __str__(self):
        dn = [] 
        for rdn in self.__rdns:
            avs = [] 
            for av in rdn:
                avs.append("=".join((av[0], av[1])))
            rdnstr = "+".join(avs)
            dn.append(rdnstr)
        return ",".join(dn)
    
    @property    
    def rdns(self):
        return self.__rdns

    @rdns.setter
    def rdns(self, value):
        raise ValueError("RDNs attribute cannot be set.")
