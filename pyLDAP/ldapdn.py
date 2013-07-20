import re

class InvalidDN(Exception):
    pass

class LDAPDN(object):
    __slots__ = ("__rdns")

    def __init__(self, strdn):
        self.__rdns = self.__str2dn__(strdn)
        if str(self) != strdn:
            raise InvalidDN

    def __str2ava__(self, strava):   
        rdn = []
        avas = strava.split("+")
        for av in avas:
            value = av.split("=")
            if len(value) != 2:
                raise InvalidDN 
            value[1] = self.__non_escape(value[1])
            rdn.append(tuple(value))
        return rdn

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
    
    def __str2dn__(self, strdn):
        rdns = []
        strdn_ex = self.__escape(strdn)
        #regex = re.compile(r'([\w]+=([\w]|[\s]|\\,|["]|[\\]|[.]|[\\=]|\<|\>|\;|\+)+|[+])*')
        regex = re.compile(r'(([\w])+=([\w]|[\s]|[\\]|[.])+|[+])*')
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
