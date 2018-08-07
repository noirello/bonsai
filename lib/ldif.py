import base64
import io
from typing import TextIO, Iterable, Any

from .ldapentry import LDAPEntry


class LDIFWriter:
    """
    Create an object for serialising LDAP entries in LDIF format as 
    described in RFC 2849.

    :param TextIO output_file: a file-like output object in text mode.
    :param int max_length: the maximal line length of the LDIF file.
    :raises TypeError: if the output_file is not a file-like object \
    or max_length is not an int.
    """

    def __init__(self, output_file: TextIO, max_length: int = 76) -> None:
        """ Init method. """
        if not isinstance(max_length, int):
            raise TypeError("The max_length must be int.")
        self.output_file = output_file
        self.max_length = max_length

    def __write_attribute(self, attrname: str, attrvalue: Iterable[Any]) -> None:
        for val in attrvalue:
            if isinstance(val, (bytes, bytearray)):
                # If it's a binary has to be base64 encoded anyway.
                has_not_safe_char = True
                has_not_safe_init_char = True
            else:
                val = str(val)
                has_not_safe_char = any(
                    char
                    for char in val
                    if ord(char) > 127 or ord(char) in (0x0A, 0x0D, 0x00)
                ) or val.endswith(" ")
                has_not_safe_init_char = val[0] in (" ", ":", "<")
                val = val.encode("UTF-8")
            if has_not_safe_char or has_not_safe_init_char:
                val = base64.b64encode(val)
                name = "{0}:".format(attrname)  # Add extra colon.
            else:
                name = attrname
            line = "{attr}: {value}".format(attr=name, value=val.decode("UTF-8"))
            for i in range(0, len(line), self.max_length):
                # Split the line into self.max_length.
                if i != 0:
                    self.__file.write(" {0}\n".format(line[i : i + self.max_length]))
                else:
                    self.__file.write("{0}\n".format(line[i : i + self.max_length]))

    def write_entry(self, entry: LDAPEntry) -> None:
        """
        Write an LDAP entry to the file in LDIF format.

        :param LDAPEntry entry: the LDAP entry to serialise.
        """
        self.__write_attribute("dn", (entry.dn,))
        for attrname, attrvalue in entry.items():
            self.__write_attribute(attrname, attrvalue)

    def write_entries(
        self, entries: Iterable[LDAPEntry], write_version: bool = True
    ) -> None:
        """
        Write multiple LDAP entry to file in LDIF format, separated
        with newline and with optional version header.

        :param list entries: list of LDAP entries.
        :param bool write_version: if it's True, write version header.
        """
        if write_version:
            self.__write_attribute("version", (1,))
        for ent in entries:
            self.write_entry(ent)
            self.__file.write("\n")

    def write_changes(self, entry: LDAPEntry) -> None:
        """
        Write an LDAP entry's changes to file in an LDIF-CHANGE format.
        Only attribute modifications are serialised.

        :param LDAPEntry entry: the LDAP entry to serialise.
        """
        self.__write_attribute("dn", (entry.dn,))
        self.__write_attribute("changetype", ("modify",))
        changes = dict(entry._status())
        deleted_keys = changes.pop("@deleted_keys")
        for attrname, stat in sorted(changes.items(), key=lambda s: s[1]["@status"]):
            if stat["@status"] == 1 and stat["@added"]:
                self.__write_attribute("add", (attrname,))
                self.__write_attribute(attrname, stat["@added"])
                self.__file.write("-\n")
            elif stat["@status"] == 1 and stat["@deleted"]:
                self.__write_attribute("delete", (attrname,))
                self.__write_attribute(attrname, stat["@deleted"])
                self.__file.write("-\n")
            elif stat["@status"] == 2:
                self.__write_attribute("replace", (attrname,))
                self.__write_attribute(attrname, stat["@added"])
                self.__file.write("-\n")
        for key in deleted_keys:
            self.__write_attribute("delete", (key,))
            self.__file.write("-\n")
        self.__file.write("\n")

    @property
    def output_file(self):
        """ The file-like object for an LDIF file. """
        return self.__file

    @output_file.setter
    def output_file(self, value: io.TextIOBase):
        if not isinstance(value, io.TextIOBase):
            raise TypeError("The output_file must be file-like object in text mode.")
        self.__file = value
