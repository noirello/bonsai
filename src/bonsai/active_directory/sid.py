import struct

from typing import Any, Optional, Tuple


class SID:
    """
    A class for representing a Security Identifier, that identifies users,
    groups, and computer accounts on a Microsoft Windows platform.

    :param str|None str_rep: a string representation of a SID.
    :param bytes|None bytes_le: a bytes representation of a SID in little-endian
        byte order.
    :raises TypeError: when the type of the parameters are invalid, or both
        parameters are given.
    :raises ValueError: when the given parameter cannot be parsed as a valid
        SID.
    """

    def __init__(
        self, str_rep: Optional[str] = None, bytes_le: Optional[bytes] = None
    ) -> None:
        if str_rep is not None and bytes_le is not None:
            raise TypeError(
                "Only one of the `str_rep` or `bytes_le` parameter must be given"
            )
        if str_rep is not None:
            try:
                if not isinstance(str_rep, str):
                    raise TypeError("The `str_rep` parameter must be a string")
                parts = str_rep.split("-")
                if parts[0] != "S":
                    raise ValueError()
                self.__revision = int(parts[1])
                self.__identifier_authority = (
                    int(parts[2], 16) if "0x" in parts[2] else int(parts[2])
                )
                self.__subauthorities = tuple(int(sub) for sub in parts[3:])
            except (ValueError, IndexError):
                raise ValueError(f"String `{str_rep}` is not a valid SID")
        if bytes_le is not None:
            try:
                if not isinstance(bytes_le, bytes):
                    raise TypeError("The `bytes_le` parameter must be bytes")
                self.__revision, subauth_count, *identifier_auth = struct.unpack(
                    "<BB6B", bytes_le[:8]
                )
                self.__subauthorities = struct.unpack(
                    f"<{subauth_count}I", bytes_le[8 : 8 + (subauth_count * 4)]
                )
                self.__identifier_authority = sum(
                    num << ((5 - i) * 8) for i, num in enumerate(identifier_auth)
                )
            except struct.error as err:
                raise ValueError(f"Not a valid binary SID, {err}")

    def __str__(self) -> str:
        """Return the string format of the SID."""
        ident_auth = (
            hex(self.__identifier_authority)
            if self.__identifier_authority > 2**32
            else self.__identifier_authority
        )
        subauths = (
            "-".join(str(sub) for sub in self.__subauthorities)
            if self.__subauthorities
            else "0"
        )
        return f"S-1-{ident_auth}-{subauths}"

    def __repr__(self) -> str:
        """The representation of SID class."""
        return f"<{self.__class__.__name__}: {str(self)}>"

    def __eq__(self, other: object) -> bool:
        """
        Check equality of two SIDs by their identifier_authority and list
        of subauthorities, or if the other object is a string than by their
        string formats.
        """
        if isinstance(other, SID):
            return (
                self.revision == other.revision
                and self.identifier_authority == other.identifier_authority
                and self.subauthorities == other.subauthorities
            )
        elif isinstance(other, str):
            return str(self) == other
        else:
            return NotImplemented

    def __hash__(self) -> int:
        return hash(str(self))

    @property
    def revision(self) -> int:
        """The revision level of the SID."""
        return self.__revision

    @property
    def identifier_authority(self) -> int:
        """
        The indentifier that indicates the authority under which
        the SID was created.
        """
        return self.__identifier_authority

    @property
    def subauthorities(self) -> Tuple[int, ...]:
        """
        A tuple of subauthorities that uniquely identifies a principal
        relative to the identifier authority.
        """
        return self.__subauthorities

    @property
    def bytes_le(self) -> bytes:
        """The byte format of the SID in little-endian byte order."""
        subauth_count = len(self.subauthorities)
        identifier_auth = [
            item for item in struct.pack(">Q", self.identifier_authority)[2:]
        ]
        return struct.pack(
            f"<BB6B{subauth_count}I",
            self.revision,
            subauth_count,
            *identifier_auth,
            *self.subauthorities,
        )

    @property
    def sddl_alias(self) -> Optional[str]:
        """
        The string SDDL alias of the SID if it exists, otherwise it's None.
        """
        aliases = {
            "S-1-1-0": "WD",
            "S-1-15-2-1": "AC",
            "S-1-16-12288": "HI",
            "S-1-16-16384": "SI",
            "S-1-16-4096": "LW",
            "S-1-16-8192": "ME",
            "S-1-16-8448": "MP",
            "S-1-3-0": "CO",
            "S-1-3-1": "CG",
            "S-1-3-4": "OW",
            "S-1-5-10": "PS",
            "S-1-5-11": "AU",
            "S-1-5-12": "RC",
            "S-1-5-14": "IU",
            "S-1-5-18": "SY",
            "S-1-5-19": "LS",
            "S-1-5-2": "NU",
            "S-1-5-20": "NS",
            "S-1-5-32-544": "BA",
            "S-1-5-32-545": "BU",
            "S-1-5-32-546": "BG",
            "S-1-5-32-547": "PU",
            "S-1-5-32-548": "AO",
            "S-1-5-32-549": "SO",
            "S-1-5-32-550": "PO",
            "S-1-5-32-551": "BO",
            "S-1-5-32-552": "RE",
            "S-1-5-32-554": "RU",
            "S-1-5-32-555": "RD",
            "S-1-5-32-556": "NO",
            "S-1-5-32-558": "MU",
            "S-1-5-32-559": "LU",
            "S-1-5-32-568": "IS",
            "S-1-5-32-569": "CY",
            "S-1-5-32-573": "ER",
            "S-1-5-32-574": "CD",
            "S-1-5-32-575": "RA",
            "S-1-5-32-576": "ES",
            "S-1-5-32-577": "MS",
            "S-1-5-32-578": "HA",
            "S-1-5-32-579": "AA",
            "S-1-5-32-580": "RM",
            "S-1-5-33": "WR",
            "S-1-5-6": "SU",
            "S-1-5-7": "AN",
            "S-1-5-84-0-0-0-0-0": "UD",
            "S-1-5-9": "ED",
        }
        domain_aliases = {
            498: "RO",
            500: "LA",
            501: "LG",
            512: "DA",
            513: "DU",
            514: "DG",
            515: "DC",
            516: "DD",
            517: "CA",
            518: "SA",
            519: "EA",
            520: "PA",
            522: "CN",
        }
        alias = aliases.get(str(self), None)
        if alias:
            return alias
        elif self.identifier_authority == 5 and self.subauthorities[0] == 21:
            alias = domain_aliases.get(self.subauthorities[-1], None)
        return alias

    @property
    def size(self) -> int:
        """The binary size of the SID in bytes."""
        return 8 + len(self.subauthorities) * 4
