import struct

from typing import Any, Optional, Tuple


class SID:
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
                raise ValueError("String `{0}` is not a valid SID".format(str_rep))
        if bytes_le is not None:
            try:
                if not isinstance(bytes_le, bytes):
                    raise TypeError("The `bytes_le` parameter must be bytes")
                self.__revision, subauth_count, *identifier_auth = struct.unpack(
                    "<BB6B", bytes_le[:8]
                )
                self.__subauthorities = struct.unpack(
                    "<{0}I".format(subauth_count), bytes_le[8 : 8 + (subauth_count * 4)]
                )
                self.__identifier_authority = sum(
                    num << ((5 - i) * 8) for i, num in enumerate(identifier_auth)
                )
            except struct.error as err:
                raise ValueError("Not a valid binary SID, {0}".format(err))

    def __str__(self) -> str:
        ident_auth = (
            hex(self.__identifier_authority)
            if self.__identifier_authority > 2 ** 32
            else self.__identifier_authority
        )
        subauths = (
            "-".join(str(sub) for sub in self.__subauthorities)
            if self.__subauthorities
            else "0"
        )
        return "S-1-{0}-{1}".format(ident_auth, subauths)

    def __repr__(self) -> str:
        return "<{0}: {1}>".format(self.__class__.__name__, str(self))

    def __eq__(self, other: Any) -> bool:
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
        return self.__revision

    @property
    def identifier_authority(self) -> int:
        return self.__identifier_authority

    @property
    def subauthorities(self) -> Tuple[int, ...]:
        return self.__subauthorities

    @property
    def bytes_le(self) -> bytes:
        subauth_count = len(self.subauthorities)
        identifier_auth = [
            item for item in struct.pack(">Q", self.identifier_authority)[2:]
        ]
        return struct.pack(
            "<BB6B{0}I".format(subauth_count),
            self.revision,
            subauth_count,
            *identifier_auth,
            *self.subauthorities
        )
