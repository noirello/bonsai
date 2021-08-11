import struct

from typing import Dict, Optional

from .sid import SID
from .acl import ACL


class SecurityDescriptor:
    def __init__(
        self,
        revision: int,
        sbz1: int,
        control: Dict[str, bool],
        owner_sid: Optional[SID],
        group_sid: Optional[SID],
        sacl: Optional[ACL],
        dacl: Optional[ACL],
    ) -> None:
        self.__revision = revision
        self.__sbz1 = sbz1
        self.__control = control
        self.__owner_sid = owner_sid
        self.__group_sid = group_sid
        self.__sacl = sacl
        self.__dacl = dacl

    @staticmethod
    def __convert_ctrl(ctrl):
        values = {
            "self_relative": 0x8000,
            "rm_control_valid": 0x4000,
            "sacl_protected": 0x2000,
            "dacl_protected": 0x1000,
            "sacl_auto_inherited": 0x800,
            "dacl_auto_inherited": 0x400,
            "sacl_computed_inheritance_required": 0x200,
            "dacl_computed_inheritance_required": 0x100,
            "server_security": 0x80,
            "dacl_trusted": 0x40,
            "sacl_defaulted": 0x20,
            "sacl_present": 0x10,
            "dacl_defaulted": 0x8,
            "dacl_present": 0x4,
            "group_defaulted": 0x2,
            "owner_defaulted": 0x1,
        }
        return {key: bool(ctrl & val) for key, val in values.items()}

    @classmethod
    def from_binary(cls, data: bytes) -> "SecurityDescriptor":
        try:
            if not isinstance(data, bytes):
                raise TypeError("The `data` parameter must be bytes")
            sacl = None
            dacl = None
            (
                rev,
                sbz1,
                ctrl,
                offset_owner,
                offset_group,
                offset_sacl,
                offset_dacl,
            ) = struct.unpack("<BBHIIII", data[:20])
            ctrl = cls.__convert_ctrl(ctrl)
            owner_sid = SID(bytes_le=data[offset_owner:]) if offset_owner else None
            group_sid = SID(bytes_le=data[offset_group:]) if offset_group else None
            if ctrl["sacl_present"] and offset_sacl != 0:
                sacl = ACL.from_binary(data[offset_sacl:])
            if ctrl["dacl_present"] and offset_dacl != 0:
                dacl = ACL.from_binary(data[offset_dacl:])
            return cls(rev, sbz1, ctrl, owner_sid, group_sid, sacl, dacl)
        except struct.error as err:
            raise ValueError("Not a valid binary SecurityDescriptor, {0}".format(err))

    @property
    def sbz1(self) -> int:
        return self.__sbz1

    @property
    def revision(self) -> int:
        return self.__revision

    @property
    def control(self) -> Dict[str, bool]:
        return self.__control

    @property
    def owner_sid(self) -> Optional[SID]:
        return self.__owner_sid

    @property
    def group_sid(self) -> Optional[SID]:
        return self.__group_sid

    @property
    def sacl(self) -> Optional[ACL]:
        return self.__sacl

    @property
    def dacl(self) -> Optional[ACL]:
        return self.__dacl
