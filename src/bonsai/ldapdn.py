import re
from typing import Union, Tuple, Any

from .errors import InvalidDN


class LDAPDN:
    """
    A class for handling valid LDAP distinguished name.

    :param str strdn: a string representation of LDAP distinguished name.
    """

    __slots__ = ("__strdn",)

    _attrtype = r"[A-Za-z ][\w-]*|\d+(?:\.\d+)*"
    _attrvalue = (
        r'#(?:[\dA-Fa-f]{2})+|(?:[^,=\+<>#;\\"]|\\[,=\+<>#;\\" ]'
        r'|\\[\dA-Fa-f]{2})*|"(?:[^\\"]|\\[,=\+<>#;\\"]|\\[\dA-Fa-f]{2})*"'
    )
    _namecomp = r"({typ})=({val})(?:\+({typ})=({val}))*".format(
        typ=_attrtype, val=_attrvalue
    )
    _dnregex = re.compile(
        r"({comp})(?:,({comp}))*\Z".format(comp=_namecomp), re.IGNORECASE
    )

    def __init__(self, strdn: str) -> None:
        if strdn != "" and not self._dnregex.match(strdn):
            raise InvalidDN(strdn)
        self.__strdn = self.__sanitize(strdn, True)

    def __str_rdn_to_tuple(self, str_rdn: str) -> Tuple[Tuple[str, str], ...]:
        """
        Generate attribute type and value tuple from relative
        distinguished name.
        """
        rdn = []
        # Split relative distinguished name to attribute types and values.
        type_value_list = re.split(r"(?<!\\)[+]", str_rdn)
        for attr in type_value_list:
            # Get attribute type and value.
            atype, avalue = re.split(r"(?<!\\)=", attr)
            rdn.append((atype.strip(), self.__sanitize(avalue, True)))
        return tuple(rdn)

    @staticmethod
    def __sanitize(strdn: str, reverse: bool = False) -> str:
        """Sanitizing special characters."""
        char_list = [
            (r"\\", "\\5C"),
            (r"\,", "\\2C"),
            (r"\+", "\\2B"),
            (r"\"", "\\22"),
            (r"\<", "\\3C"),
            (r"\>", "\\3E"),
            (r"\;", "\\3B"),
            (r"\=", "\\3D"),
            (r"\ ", "\\20"),
        ]
        if strdn:
            for pair in char_list:
                if reverse:
                    strdn = strdn.replace(pair[1], pair[0])
                else:
                    strdn = strdn.replace(pair[0], pair[1])
        return strdn

    def __getitem__(self, idx: Union[int, slice]) -> str:
        """
        Return the string format of the relative distinguished names
        in the LDAPDN.

        :param int idx: the indices of the RDNs.
        :return: the string format of the RDNs.
        :rtype: str
        """
        rdns = re.split(r"(?<!\\),", self.__strdn)
        if isinstance(idx, int):
            if idx >= len(rdns):
                raise IndexError("Index is out of range.")
            # Create a slice to avoid join string characters.
            idx = slice(idx, idx + 1)
        elif not isinstance(idx, slice):
            raise TypeError("Indices must be integers or slices.")
        return ",".join(rdns[idx])

    def __setitem__(self, idx: Union[int, slice], value: str) -> None:
        """
        Set the string format of the relative distinguished names
        in the LDAPDN.

        :param int idx: the indices of the RDNs.
        :param str value: the new RDNs.
        """
        if not isinstance(value, str):
            raise ValueError("New value must be string.")
        if isinstance(idx, int):
            idx = slice(idx, idx + 1)
        elif not isinstance(idx, slice):
            raise TypeError("Indices must be integers or slices.")
        if not self._dnregex.match(value):
            raise InvalidDN(value)
        rdns = re.split(r"(?<!\\),", self.__strdn)
        rdns[idx] = re.split(r"(?<!\\),", value)
        self.__strdn = ",".join(rdns)

    def __eq__(self, other: object) -> bool:
        """
        Check equality of two LDAPDNs by their string formats or
        their sanitized string formats.
        """
        return (
            str(self).lower() == str(other).lower()
            or self.__sanitize(str(self)).lower() == self.__sanitize(str(other)).lower()
        )

    def __str__(self) -> str:
        """Return the full string format of the distinguished name."""
        return self.__strdn

    def __len__(self) -> int:
        """Return the number of RDNs of the distinguished name."""
        return len(re.split(r"(?<!\\),", self.__strdn))

    def __repr__(self) -> str:
        """The representation of LDAPDN class."""
        return "<LDAPDN %s>" % str(self)

    @property
    def rdns(self) -> Tuple[Tuple[Tuple[str, str], ...], ...]:
        """The tuple of relative distinguished name."""
        return tuple(
            self.__str_rdn_to_tuple(rdn)
            for rdn in re.split(r"(?<!\\),", self.__sanitize(self.__strdn))
        )

    @rdns.setter
    def rdns(self, value: Any = None) -> None:
        """The tuple of relative distinguished names."""
        raise ValueError("RDNs attribute cannot be set.")
