import struct
import uuid

from enum import IntEnum
from typing import List, Optional, Set

from .sid import SID


class ACEFlag(IntEnum):
    OBJECT_INHERIT = 0x01
    CONTAINER_INHERIT = 0x02
    NO_PROPAGATE_INHERIT = 0x04
    INHERIT_ONLY = 0x08
    INHERITED = 0x10
    SUCCESSFUL_ACCESS = 0x40
    FAILED_ACCESS = 0x80


class ACEType(IntEnum):
    ACCESS_ALLOWED = 0
    ACCESS_DENIED = 1
    SYSTEM_AUDIT = 2
    SYSTEM_ALARM = 3
    ACCESS_ALLOWED_COMPOUND = 4
    ACCESS_ALLOWED_OBJECT = 5
    ACCESS_DENIED_OBJECT = 6
    SYSTEM_AUDIT_OBJECT = 7
    SYSTEM_ALARM_OBJECT = 8
    ACCESS_ALLOWED_CALLBACK = 9
    ACCESS_DENIED_CALLBACK = 10
    ACCESS_ALLOWED_CALLBACK_OBJECT = 11
    ACCESS_DENIED_CALLBACK_OBJECT = 12
    SYSTEM_AUDIT_CALLBACK = 13
    SYSTEM_ALARM_CALLBACK = 14
    SYSTEM_AUDIT_CALLBACK_OBJECT = 15
    SYSTEM_ALARM_CALLBACK_OBJECT = 16
    SYSTEM_MANDATORY_LABEL = 17
    SYSTEM_RESOURCE_ATTRIBUTE = 18
    SYSTEM_SCOPED_POLICY_ID = 19


class ACLRevision(IntEnum):
    ACL_REVISION = 0x02
    ACL_REVISION_DS = 0x04


class ACE:
    def __init__(
        self,
        ace_type: ACEType,
        flags: Set[ACEFlag],
        size: int,
        mask: bytes,
        trustee_sid: SID,
        object_type: Optional[uuid.UUID],
        inherited_object_type: Optional[uuid.UUID],
        application_data: Optional[bytes],
    ) -> None:
        self.__type = ace_type
        self.__flags = flags
        self.__size = size
        self.__mask = mask
        self.__object_type = object_type
        self.__inherited_object_type = inherited_object_type
        self.__trustee_sid = trustee_sid
        self.__application_data = application_data

    @classmethod
    def from_binary(cls, data: bytes) -> "ACE":
        try:
            if not isinstance(data, bytes):
                raise TypeError("The `data` parameter must be bytes")
            object_type = None
            inherited_object_type = None
            application_data = None
            pos = 8
            ace_type, flags, size, *mask = struct.unpack("<BBH4c", data[:pos])
            if ACEType(ace_type) in (
                ACEType.ACCESS_ALLOWED_OBJECT,
                ACEType.ACCESS_DENIED_OBJECT,
                ACEType.SYSTEM_AUDIT_OBJECT,
                ACEType.SYSTEM_ALARM_OBJECT,
                ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT,
                ACEType.ACCESS_DENIED_CALLBACK_OBJECT,
                ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT,
                ACEType.SYSTEM_ALARM_CALLBACK_OBJECT,
            ):
                obj_flag = struct.unpack("<I", data[pos:12])[0]
                pos += 4
                if obj_flag & 0x00000001:
                    object_type = uuid.UUID(bytes_le=data[pos : pos + 16])
                    pos += 16
                if obj_flag & 0x00000002:
                    inherited_object_type = uuid.UUID(bytes_le=data[pos : pos + 16])
                    pos += 16
            trustee_sid = SID.from_binary(data[pos:])
            pos += 8 + len(trustee_sid.subauthorities) * 4
            if ACEType(ace_type) in (
                ACEType.ACCESS_ALLOWED_CALLBACK,
                ACEType.ACCESS_DENIED_CALLBACK,
                ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT,
                ACEType.ACCESS_DENIED_CALLBACK_OBJECT,
                ACEType.SYSTEM_AUDIT_OBJECT,
                ACEType.SYSTEM_AUDIT_CALLBACK,
            ):
                application_data = data[pos:size]
            return cls(
                ACEType(ace_type),
                {flg for flg in ACEFlag if flags & flg},
                size,
                b"".join(mask),
                trustee_sid,
                object_type,
                inherited_object_type,
                application_data,
            )
        except struct.error as err:
            raise ValueError("Not a valid binary ACE, {0}".format(err))

    @property
    def type(self) -> ACEType:
        return self.__type

    @property
    def flags(self) -> Set[ACEFlag]:
        return self.__flags

    @property
    def size(self) -> int:
        return self.__size

    @property
    def mask(self) -> bytes:
        return self.__mask

    @property
    def object_type(self) -> Optional[uuid.UUID]:
        return self.__object_type

    @property
    def inherited_object_type(self) -> Optional[uuid.UUID]:
        return self.__inherited_object_type

    @property
    def trustee_sid(self) -> SID:
        return self.__trustee_sid

    @property
    def application_data(self) -> Optional[bytes]:
        return self.__application_data


class ACL:
    def __init__(
        self,
        revision: ACLRevision,
        sbz1: int,
        size: int,
        count: int,
        sbz2: int,
        aces: List[ACE],
    ) -> None:
        self.__revision = revision
        self.__sbz1 = sbz1
        self.__size = size
        self.__count = count
        self.__sbz2 = sbz2
        self.__aces = aces

    @classmethod
    def from_binary(cls, data: bytes) -> "ACL":
        try:
            if not isinstance(data, bytes):
                raise TypeError("The `data` parameter must be bytes")
            rev, sbz1, size, count, sbz2 = struct.unpack("<BBHHH", data[:8])
            start_pos = 8
            aces = []
            for _ in range(count):
                ace = ACE.from_binary(data[start_pos:])
                aces.append(ace)
                start_pos += ace.size
            return cls(ACLRevision(rev), sbz1, size, count, sbz2, aces)
        except struct.error as err:
            raise ValueError("Not a valid binary ACL, {0}".format(err))

    @property
    def revision(self) -> ACLRevision:
        return self.__revision

    @property
    def sbz1(self) -> int:
        return self.__sbz1

    @property
    def size(self) -> int:
        return self.__size

    @property
    def count(self) -> int:
        return self.__count

    @property
    def sbz2(self) -> int:
        return self.__sbz2

    @property
    def aces(self) -> List[ACE]:
        return self.__aces
