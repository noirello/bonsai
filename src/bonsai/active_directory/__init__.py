import struct

from typing import Dict, Optional, Union

from .sid import SID
from .acl import ACL, ACLRevision, ACE, ACEFlag, ACERight, ACEType


class SecurityDescriptor:
    """
    A class that defines the security attributes of an object. These
    attributes specify who owns the object; who can access the object and
    what they can do with it; what level of audit logging can be applied to
    the object; and what kind of restrictions apply to the use of the
    security descriptor. It can contain two types of :class:`ACL`:

    * A discretionary access control list (DACL) is controlled by the
      owner of an object or anyone granted WRITE_DAC access to the object.
      It specifies the access particular users and groups can have to an
      object. For example, the owner of a file can use a DACL to control
      which users and groups can and cannot have access to the file.
    * A system access control list (SACL) is similar to the DACL, except
      that the SACL is used to audit rather than control access to an
      object. When an audited action occurs, the operating system records
      the event in the security log. Each ACE in a SACL has a header that
      indicates whether auditing is triggered by success, failure, or
      both; a SID that specifies a particular user or security group to
      monitor; and an access mask that lists the operations to audit.

    :param dict control: a dict that specifies control access bit flags.
    :param SID|None owner_sid: the SID of the owner of the object.
    :param SID|None group_sid: the SID of the group of the object.
    :param ACL|None sacl: the system access control list.
    :param ACL|None dacl: the discretionary access control list.
    :param int revision: the revision of the security descriptor.
    :param int sbz1: reserved value.
    """

    def __init__(
        self,
        control: Dict[str, bool],
        owner_sid: Optional[SID],
        group_sid: Optional[SID],
        sacl: Optional[ACL],
        dacl: Optional[ACL],
        revision: int = 1,
        sbz1: int = 0,
    ) -> None:
        self.__revision = revision
        self.__sbz1 = sbz1
        self.__control = control
        self.__owner_sid = owner_sid
        self.__group_sid = group_sid
        self.__sacl = sacl
        self.__dacl = dacl

    @staticmethod
    def __convert_ctrl(ctrl, to_int=False):
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
        if to_int:
            return sum(values[key] for key, val in ctrl.items() if val)
        else:
            return {key: bool(ctrl & val) for key, val in values.items()}

    @classmethod
    def from_binary(cls, data: bytes) -> "SecurityDescriptor":
        """
        Create a SecurityDescriptor object from a binary blob.

        :param bytes data: a little-endian byte ordered byte input.
        :returns: A new SecurityDescriptor instance.
        :rtype: SecurityDescriptor
        :raises TypeError: when the parameter is not bytes.
        :raises ValueError: when the input cannot be parsed as a
            SecurityDescriptor object.
        """
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
            return cls(ctrl, owner_sid, group_sid, sacl, dacl, rev, sbz1)
        except struct.error as err:
            raise ValueError(f"Not a valid binary SecurityDescriptor, {err}")

    def to_binary(self) -> bytes:
        """
        Convert SecurityDescriptor object to binary form with little-endian byte order.

        :returns: Bytes of the binary SecurityDescriptor instance
        :rtype: bytes
        """
        owner = b""
        group = b""
        sacl = b""
        dacl = b""
        offset_owner = 0
        offset_group = 0
        offset_sacl = 0
        offset_dacl = 0
        ctrl = self.__convert_ctrl(self.control, True)
        data = bytearray(20)
        if self.owner_sid:
            owner = self.owner_sid.bytes_le
            offset_owner = 20
        if self.group_sid:
            group = self.group_sid.bytes_le
            offset_group = 20 + len(owner)
        if self.sacl:
            sacl = self.sacl.to_binary()
            offset_sacl = 20 + len(owner) + len(group)
        if self.dacl:
            dacl = self.dacl.to_binary()
            offset_dacl = 20 + len(owner) + len(group) + len(sacl)
        struct.pack_into(
            "<BBHIIII",
            data,
            0,
            self.revision,
            self.sbz1,
            ctrl,
            offset_owner,
            offset_group,
            offset_sacl,
            offset_dacl,
        )
        data.extend(owner)
        data.extend(group)
        data.extend(sacl)
        data.extend(dacl)
        return bytes(data)

    def set_control(self, control: Union[Dict[str, bool], int]) -> None:
        """
        Set the control access bit flags for the SecurityDescriptor object.

        :param dict|int control: the control flag either as an int or a dict.
        :raises ValueError: if the provided number is not valid.
        :raises TypeError: if the parameter neither an int nor a bool value \
        only dict.
        """
        if isinstance(control, int):
            ctrl = self.__convert_ctrl(control)
            if control != self.__convert_ctrl(ctrl, to_int=True):
                raise ValueError(f"{control} is not a valid controll flag.")
            self.__control = ctrl
        elif isinstance(control, dict) and all(
            isinstance(val, bool) for val in control.values()
        ):
            self.__control = control
        else:
            raise TypeError(
                "The control parameter must be an int or bool value only dictionary."
            )

    def set_owner_sid(self, owner_sid: SID) -> None:
        """
        Set the owner SID for the the SecurityDescriptor object.

        :param SID owner_sid: the new owner SID.
        :raises TypeError: if the parameter is not a SID object.
        """
        if not isinstance(owner_sid, SID):
            raise TypeError("The owner_sid must be a SID object.")
        self.__owner_sid = owner_sid

    def set_group_sid(self, group_sid: SID) -> None:
        """
        Set the group SID for the the SecurityDescriptor object.

        :param SID group_sid: the new group SID.
        :raises TypeError: if the parameter is not a SID object.
        """
        if not isinstance(group_sid, SID):
            raise TypeError("The group_sid must be a SID object.")
        self.__group_sid = group_sid

    def set_dacl(self, dacl: Optional[ACL]) -> None:
        """
        Set the discretionary ACL for the the SecurityDescriptor object.
        It also sets the `dacl_present` in the control access bit flags
        accordingly.

        :param ACL|None dacl: the ACL object or None.
        :raises TypeError: if the parameter is not a ACL object or None.
        """
        if dacl is not None and not isinstance(dacl, ACL):
            raise TypeError("The dacl must be an ACL object or None.")
        self.__dacl = dacl
        if dacl is not None:
            self.__control["dacl_present"] = True
        else:
            self.__control["dacl_present"] = False

    def set_sacl(self, sacl: Optional[ACL]) -> None:
        """
        Set the system ACL for the the SecurityDescriptor object.
        It also sets the `sacl_present` in the control access bit flags
        accordingly.

        :param ACL|None dacl: the ACL object or None.
        :raises TypeError: if the parameter is not a ACL object or None.
        """
        if sacl is not None and not isinstance(sacl, ACL):
            raise TypeError("The sacl must be an ACL object or None.")
        self.__sacl = sacl
        if sacl is not None:
            self.__control["sacl_present"] = True
        else:
            self.__control["sacl_present"] = False

    @property
    def sbz1(self) -> int:
        """Reserved field in the security descriptor structure."""
        return self.__sbz1

    @property
    def revision(self) -> int:
        """The revision of the security descriptor."""
        return self.__revision

    @property
    def control(self) -> Dict[str, bool]:
        """The dict of the control access bit flags."""
        return self.__control

    @control.setter
    def control(self, value: Union[Dict[str, bool], int]) -> None:
        self.set_control(value)

    @property
    def owner_sid(self) -> Optional[SID]:
        """The :class:`SID` of the owner."""
        return self.__owner_sid

    @owner_sid.setter
    def owner_sid(self, value: SID) -> None:
        self.set_owner_sid(value)

    @property
    def group_sid(self) -> Optional[SID]:
        """The :class:`SID` of the group."""
        return self.__group_sid

    @group_sid.setter
    def group_sid(self, value: SID) -> None:
        self.set_group_sid(value)

    @property
    def sacl(self) -> Optional[ACL]:
        """The system :class:`ACL`."""
        return self.__sacl

    @sacl.setter
    def sacl(self, value: Optional[ACL]) -> None:
        self.set_sacl(value)

    @property
    def dacl(self) -> Optional[ACL]:
        """The discretionary :class:`ACL`."""
        return self.__dacl

    @dacl.setter
    def dacl(self, value: Optional[ACL]) -> None:
        self.set_dacl(value)


class UserAccountControl:
    """
    A class for parsing UserAccountControl field.

    :param int flags: integer representing the property flags.
    :raises TypeError: if flags parameter is not an int.
    """

    def __init__(self, flags: int) -> None:
        if not isinstance(flags, int):
            raise TypeError("The `flags` parameter must be an integer")
        self.__flag_values = {
            "script": 0x1,
            "accountdisable": 0x2,
            "homedir_required": 0x8,
            "lockout": 0x10,
            "passwd_notreqd": 0x20,
            "passwd_cant_change": 0x40,
            "encrypted_text_pwd_allowed": 0x80,
            "temp_duplicate_account": 0x100,
            "normal_account": 0x200,
            "interdomain_trust_account": 0x800,
            "workstation_trust_account": 0x1000,
            "server_trust_account": 0x2000,
            "dont_expire_password": 0x10000,
            "mns_logon_account": 0x20000,
            "smartcard_required": 0x40000,
            "trusted_for_delegation": 0x80000,
            "not_delegated": 0x100000,
            "use_des_key_only": 0x200000,
            "dont_req_preauth": 0x400000,
            "password_expired": 0x800000,
            "trusted_to_auth_for_delegation": 0x1000000,
            "partial_secrets_account": 0x4000000,
        }
        self.__properties = {
            key: bool(flags & val) for key, val in self.__flag_values.items()
        }

    @property
    def properties(self) -> Dict[str, bool]:
        """Dictionary of the UserAccountControl properties."""
        return self.__properties

    @property
    def value(self) -> int:
        """The integer value of the properties."""
        return sum(
            self.__flag_values[key] for key, val in self.properties.items() if val
        )


__all__ = [
    "ACE",
    "ACEFlag",
    "ACERight",
    "ACEType",
    "ACL",
    "ACLRevision",
    "SecurityDescriptor",
    "SID",
    "UserAccountControl",
]
