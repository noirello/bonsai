import base64
import io
import os
from collections import defaultdict
from itertools import groupby
from typing import (
    Dict,
    TextIO,
    Iterable,
    Iterator,
    Any,
    Optional,
    List,
    Union,
    Mapping,
    Callable,
    KeysView
)

from .ldapentry import LDAPEntry, LDAPModOp
from .ldapvaluelist import LDAPValueList

from .errors import LDAPError


class LDIFError(LDAPError):
    """General exception that is raised during reading or writing an LDIF file."""

    code = -300


class LDIFReader:
    """
    Create an object for reading LDAP entries from an LDIF format file \
    as described in RFC 2849.

    :param TextIO input_file: a file-like input object in text mode.
    :param bool autoload: allow to automatically load external \
    sources from URL.
    :param int max_length: the maximal line length of the LDIF file.
    :raises TypeError: if the input_file is not a file-like object \
    or max_length is not an int.
    """

    def __init__(
        self, input_file: TextIO, autoload: bool = True, max_length: int = 76
    ) -> None:
        """Init method."""
        if not isinstance(max_length, int):
            raise TypeError("The max_length must be int.")
        self.__file: TextIO
        self.input_file = input_file
        self.autoload = autoload
        self.max_length = max_length
        self.version: Optional[int] = None
        self.__entries = self.__read_attributes()
        self.__num_of_entries = 0
        self.__resource_handlers = {"file": self.__load_file}

    def __read_attributes(self) -> Iterator[List[str]]:
        buffer: List[str] = []
        comment = False
        for num, line in enumerate(self.__file):
            try:
                if len(line) > self.max_length:
                    raise LDIFError(f"Line {num + 1} is too long.")
                if len(line.strip()) == 0:
                    yield buffer
                    buffer.clear()
                    continue
                if line[0] == " ":
                    if not comment:
                        # Concat line with the previous one.
                        buffer[-1] = "".join((buffer[-1], line[1:].rstrip()))
                    continue
                elif line[0] == "#":
                    comment = True
                else:
                    comment = False
                if comment:
                    # Drop comment lines.
                    continue
                else:
                    buffer.append(line.rstrip())
            except IndexError:
                raise LDIFError(f"Parser error at line: {num + 1}.") from None
        if buffer:
            yield buffer

    @staticmethod
    def __convert(val: Union[str, bytes]) -> Union[str, bytes, int]:
        try:
            return int(val)
        except ValueError:
            try:
                return val.decode("UTF-8")
            except (ValueError, AttributeError):
                pass
        return val

    @staticmethod
    def __find_key(searched_key: str, keylist: KeysView[str]) -> Optional[str]:
        for key in keylist:
            if key.lower() == searched_key.lower():
                return key
        else:
            raise KeyError(searched_key)

    def __load_file(self, url: str) -> bytes:
        _, path = url.split("file://")
        abs_filepath = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(self.__file.name)), path)
        )
        with open(abs_filepath, "rb") as resource:
            return resource.read()

    def load_resource(self, url: str) -> bytes:
        try:
            scheme, _ = url.split(":", maxsplit=1)
            return self.__resource_handlers[scheme](url)
        except (KeyError, ValueError):
            raise LDIFError(f"Unsupported URL format: {url}.") from None

    def __iter__(self) -> "LDIFReader":
        return self

    def __next__(self) -> LDAPEntry:
        entry = LDAPEntry("")
        change_type = "add"
        attr_blocks = [
            list(group)
            for key, group in groupby(next(self.__entries), lambda line: line == "-")
            if not key
        ]
        self.__num_of_entries += 1
        for block in attr_blocks:
            attr_dict: Dict[str, LDAPValueList] = defaultdict(LDAPValueList)
            for attrval in block:
                try:
                    if ":: " in attrval:
                        attr, val = attrval.split(":: ")
                        val = base64.b64decode(val)
                    elif ": " in attrval:
                        attr, val = attrval.split(": ", maxsplit=1)
                        if ord(val[0]) > 127 or val[0] in (
                            "\0",
                            "\n",
                            "\r",
                            " ",
                            ":",
                            "<",
                        ):
                            raise ValueError("Not a safe first character in value.")
                    elif ":< " in attrval:
                        attr, val = attrval.split(":< ")
                        if self.__autoload:
                            val = self.load_resource(val)
                    else:
                        raise ValueError("Missing valid attribute value separator.")
                except ValueError as err:
                    raise LDIFError(
                        f"Invalid attribute value pair: '{attrval}'"
                        f" for entry #{self.__num_of_entries}."
                    ) from err
                if attr.lower() == "changetype":
                    change_type = val.lower()
                elif attr.lower() == "dn":
                    entry.dn = self.__convert(val)
                elif attr.lower() == "version":
                    self.version = self.__convert(val)
                else:
                    attr_dict[attr].append(self.__convert(val))
            if change_type == "modify":
                try:
                    for key in attr_dict.pop("add", []):
                        key = self.__find_key(key, attr_dict.keys())
                        entry.change_attribute(key, LDAPModOp.ADD, *attr_dict[key])
                    for key in attr_dict.pop("replace", []):
                        key = self.__find_key(key, attr_dict.keys())
                        entry.change_attribute(key, LDAPModOp.REPLACE, *attr_dict[key])
                    for key in attr_dict.pop("delete", []):
                        try:
                            key = self.__find_key(key, attr_dict.keys())
                        except KeyError:
                            pass
                        entry.change_attribute(key, LDAPModOp.DELETE, *attr_dict[key])
                except KeyError as err:
                    raise LDIFError(
                        f"Missing attribute: '{err.args[0]}' for entry #{self.__num_of_entries}."
                    )
            elif change_type == "add":
                for key, vals in attr_dict.items():
                    entry[key] = vals
        if entry.dn == "":
            raise LDIFError(
                f"Missing distinguished name for entry #{self.__num_of_entries}."
            )
        return entry

    @property
    def input_file(self) -> TextIO:
        """The file-like object of an LDIF file."""
        return self.__file

    @input_file.setter
    def input_file(self, value: TextIO) -> None:
        if not isinstance(value, io.TextIOBase):
            raise TypeError("The input_file must be file-like object in text mode.")
        self.__file = value

    @property
    def autoload(self) -> bool:
        """Enable/disable autoloading resources in LDIF files."""
        return self.__autoload

    @autoload.setter
    def autoload(self, value: bool) -> None:
        if not isinstance(value, bool):
            raise TypeError("The autoload property must be bool.")
        self.__autoload = value

    @property
    def resource_handlers(self) -> Mapping[str, Callable[[str], bytes]]:
        """
        A dictionary of supported resource types. The keys are the schemes,
        while the values are functions that expect the full URL parameters
        and return the loaded content in preferably bytes format.
        """
        return self.__resource_handlers


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
        """Init method."""
        if not isinstance(max_length, int):
            raise TypeError("The max_length must be int.")
        self.__file: TextIO
        self.output_file = output_file
        self.max_length = max_length

    def _get_attr_lines(self, attrname: str, attrvalue: Iterable[Any]) -> Iterator[str]:
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
                name = f"{attrname}:"  # Add extra colon.
            else:
                name = attrname
            line = f"{name}: {val.decode('UTF-8')}"
            for i in range(0, len(line), self.max_length):
                # Split the line into self.max_length.
                if i != 0:
                    yield f" {line[i : i + self.max_length]}\n"
                else:
                    yield f"{line[i : i + self.max_length]}\n"

    def write_entry(self, entry: LDAPEntry) -> None:
        """
        Write an LDAP entry to the file in LDIF format.

        :param LDAPEntry entry: the LDAP entry to serialise.
        """
        for line in self._get_attr_lines("dn", (entry.dn,)):
            self.__file.write(line)
        for attrname, attrvalue in entry.items(exclude_dn=True):
            for line in self._get_attr_lines(attrname, attrvalue):
                self.__file.write(line)

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
            self.__file.write(next(self._get_attr_lines("version", (1,))))
        for ent in entries:
            self.write_entry(ent)
            self.__file.write("\n")

    def write_changes(self, entry: LDAPEntry) -> None:
        """
        Write an LDAP entry's changes to file in an LDIF-CHANGE format.
        Only attribute modifications are serialised.

        :param LDAPEntry entry: the LDAP entry to serialise.
        """
        self.__file.write(next(self._get_attr_lines("dn", (entry.dn,))))
        self.__file.write(next(self._get_attr_lines("changetype", ("modify",))))
        changes = dict(entry._status())
        deleted_keys = changes.pop("@deleted_keys")
        for attrname, stat in sorted(changes.items(), key=lambda s: s[1]["@status"]):
            if stat["@status"] == 1 and stat["@added"]:
                self.__file.write(next(self._get_attr_lines("add", (attrname,))))
                for line in self._get_attr_lines(attrname, stat["@added"]):
                    self.__file.write(line)
                self.__file.write("-\n")
            elif stat["@status"] == 1 and stat["@deleted"]:
                self.__file.write(next(self._get_attr_lines("delete", (attrname,))))
                for line in self._get_attr_lines(attrname, stat["@deleted"]):
                    self.__file.write(line)
                self.__file.write("-\n")
            elif stat["@status"] == 2:
                self.__file.write(next(self._get_attr_lines("replace", (attrname,))))
                for line in self._get_attr_lines(attrname, stat["@added"]):
                    self.__file.write(line)
                self.__file.write("-\n")
        for key in deleted_keys:
            self.__file.write(next(self._get_attr_lines("delete", (key,))))
            self.__file.write("-\n")
        self.__file.write("\n")

    @property
    def output_file(self) -> TextIO:
        """The file-like object for an LDIF file."""
        return self.__file

    @output_file.setter
    def output_file(self, value: TextIO) -> None:
        if not isinstance(value, io.TextIOBase):
            raise TypeError("The output_file must be file-like object in text mode.")
        self.__file = value
