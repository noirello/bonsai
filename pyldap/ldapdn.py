import pyldap.errors

class LDAPDN(object):
    """
    A class for handling valid LDAP distinguished name.

    :param str strdn: a string representation of LDAP distinguished name.
    """
    __slots__ = ("__rdns")

    def __init__(self, strdn):
        if strdn != "":
            escaped_str = self.__escape_special_char(strdn)
            # Get RDN strings.
            str_rdns = escaped_str.split(',')
            self.__rdns = [self.__str_rdn_to_tuple(rdn) for rdn in str_rdns]
            # Validate by rebuilding the parsed string.
        else:
            self.__rdns = []
        if str(self) != strdn and \
        self.__escape_special_char(str(self)) != strdn:
            raise pyldap.errors.InvalidDN(strdn)

    def __escape_special_char(self, strdn, reverse=False):
        """ Escaping special characters."""
        char_list = [(r'\\\\', '\\5C'),
                     (r'\,', '\\2C'),
                     (r'\+', '\\2B'),
                     (r'\"', '\\22'),
                     (r'\<', '\\3C'),
                     (r'\>', '\\3E'),
                     (r'\;', '\\3B'),
                     (r'\=', '\\3D')]
        if reverse:
            i, j = 1, 0
        else:
            i, j = 0, 1
        if strdn:
            for pair in char_list:
                strdn = strdn.replace(pair[i], pair[j])
        return strdn

    def __str_rdn_to_tuple(self, str_rdn):
        """
        Generate attribute type and value tuple from relative
        distinguished name.
        """
        rdn = []
        # Split relative distinguished name to attribute types and values.
        type_value_list = str_rdn.split("+")
        for attr in type_value_list:
            # Get attribute type and value.
            try:
                atype, avalue = attr.split("=")
                avalue = self.__escape_special_char(avalue, True)
                rdn.append((atype, avalue))
            except ValueError:
                # Expected when the splitting returns more, then 2 component.
                raise pyldap.errors.InvalidDN(str_rdn)
        return tuple(rdn)

    def __rdns_to_str(self, rdns):
        """
        Convert RDN tuples to string.
        Warning: the string value must be 3 depth deep!
        """
        return ','.join(
            map(lambda attr: "+".join(
                map(lambda type_value: "=".join(type_value), attr)), rdns))

    def __getitem__(self, idx):
        """
        Return the string format of the relative distinguished names
        in the LDAPDN.

        :param int idx: the indeces of the RDNs.
        :return: the string format of the RDNS.
        :rtype: str
        """
        if type(idx) == int:
            if idx >= len(self):
                raise IndexError("Index is out of range.")
            # Convert integer index to slice, because self.__rdns_to_str()
            # needs an extra tuple/list to convert right.
            idx = slice(idx, idx+1)
        elif type(idx) != slice:
            raise TypeError("Indices must be integers or slices.")
        return self.__rdns_to_str(self.__rdns[idx])

    def __setitem__(self, idx, value):
        """
        Set the string format of the relative distinguished names
        in the LDAPDN.

        :param int idx: the indeces of the RDNs.
        :param str value: the new RDNs.
        """
        if type(value) != str:
            raise ValueError("New value must be string.")
        if type(idx) == int:
            idx = slice(idx, idx+1)
        elif type(idx) != slice:
            raise TypeError("Indices must be integers or slices.")
        escaped_str = self.__escape_special_char(value)
        str_rdns = escaped_str.split(',')
        rdns = [self.__str_rdn_to_tuple(rdn) for rdn in str_rdns]
        self.__rdns[idx] = rdns

    def __eq__(self, other):
        """ Check equality of two LDAPDN by their string format. """
        return str(self) == str(other)

    def __str__(self):
        """ Return the full string format of the distinguished name. """
        return self.__rdns_to_str(self.__rdns)

    def __len__(self):
        """ Return the number of RDNs of the distinguished name. """
        return len(self.__rdns)

    def __repr__(self):
        """ The representation of LDAPDN class. """
        return "<LDAPDN %s>" % str(self)

    @property
    def rdns(self):
        """ The tuple of relative distinguished name."""
        return tuple(self.__rdns)

    @rdns.setter
    def rdns(self, value=None):
        """ The tuple of relative distinguished names."""
        raise ValueError("RDNs attribute cannot be set.")
