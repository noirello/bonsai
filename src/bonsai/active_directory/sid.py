import struct

from typing import List

class SID:
    def __init__(
        self, revision: int, identifier_authority: int, subauthorities: List[int]
    ) -> None:
        self.__revision = revision
        self.__identifier_authority = identifier_authority
        self.__subauthorities = subauthorities

    @classmethod
    def from_binary(cls, data: bytes) -> "SID":
        try:
            if not isinstance(data, bytes):
                raise TypeError("The `data` parameter must be bytes")
            rev, subauth_count, *identifier_auth = struct.unpack("<BB6B", data[:8])
            subauths = struct.unpack(
                "<{0}I".format(subauth_count), data[8 : 8 + (subauth_count * 4)]
            )
            identifier_auth = sum(
                num << ((5 - i) * 8) for i, num in enumerate(identifier_auth)
            )
            return cls(rev, identifier_auth, subauths)
        except struct.error as err:
            raise ValueError("Not a valid binary SID, {0}".format(err))

    @classmethod
    def from_string(cls, data: str) -> "SID":
        try:
            if not isinstance(data, str):
                raise TypeError("The `data` parameter must be a string")
            parts = data.split("-")
            if parts[0] != "S":
                raise ValueError()
            rev = int(parts[1])
            identifier_auth = int(parts[2], 16) if "0x" in parts[2] else int(parts[2])
            subauths = tuple(int(sub) for sub in parts[3:])
            return cls(rev, identifier_auth, subauths)
        except (ValueError, IndexError):
            raise ValueError("String `{0}` is not a valid SID".format(data))

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

    @property
    def revision(self) -> int:
        return self.__revision

    @property
    def identifier_authority(self) -> int:
        return self.__identifier_authority

    @property
    def subauthorities(self) -> List[int]:
        return self.__subauthorities
