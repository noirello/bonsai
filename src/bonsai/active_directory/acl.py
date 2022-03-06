import struct
import uuid

from enum import IntEnum
from typing import List, Optional, Set

from .sid import SID


class ACEFlag(IntEnum):
    """ ACE type-specific control flags. """

    OBJECT_INHERIT = 0x01
    CONTAINER_INHERIT = 0x02
    NO_PROPAGATE_INHERIT = 0x04
    INHERIT_ONLY = 0x08
    INHERITED = 0x10
    SUCCESSFUL_ACCESS = 0x40
    FAILED_ACCESS = 0x80

    @property
    def short_name(self) -> str:
        """ The SDDL short name of the flag. """
        short_names = {
            "OBJECT_INHERIT": "OI",
            "CONTAINER_INHERIT": "CI",
            "NO_PROPAGATE_INHERIT": "NP",
            "INHERIT_ONLY": "IO",
            "INHERITED": "ID",
            "SUCCESSFUL_ACCESS": "SA",
            "FAILED_ACCESS": "FA",
        }
        return short_names[self.name]


class ACEType(IntEnum):
    """ Type of the ACE. """

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

    @property
    def short_name(self) -> str:
        """ The SDDL short name of the type. """
        short_names = {
            "ACCESS_ALLOWED": "A",
            "ACCESS_DENIED": "D",
            "SYSTEM_AUDIT": "AU",
            "SYSTEM_ALARM": "AL",
            "ACCESS_ALLOWED_COMPOUND": "",
            "ACCESS_ALLOWED_OBJECT": "OA",
            "ACCESS_DENIED_OBJECT": "OD",
            "SYSTEM_AUDIT_OBJECT": "OU",
            "SYSTEM_ALARM_OBJECT": "OL",
            "ACCESS_ALLOWED_CALLBACK": "XA",
            "ACCESS_DENIED_CALLBACK": "XD",
            "ACCESS_ALLOWED_CALLBACK_OBJECT": "ZA",
            "ACCESS_DENIED_CALLBACK_OBJECT": "ZD",
            "SYSTEM_AUDIT_CALLBACK": "XU",
            "SYSTEM_ALARM_CALLBACK": "XL",
            "SYSTEM_AUDIT_CALLBACK_OBJECT": "ZU",
            "SYSTEM_ALARM_CALLBACK_OBJECT": "ZL",
            "SYSTEM_MANDATORY_LABEL": "ML",
            "SYSTEM_RESOURCE_ATTRIBUTE": "RA",
            "SYSTEM_SCOPED_POLICY_ID": "SP",
        }
        return short_names[self.name]

    @property
    def is_object_type(self) -> bool:
        """ Flag for ACE types with objects. """
        return self in (
            ACEType.ACCESS_ALLOWED_OBJECT,
            ACEType.ACCESS_DENIED_OBJECT,
            ACEType.SYSTEM_AUDIT_OBJECT,
            ACEType.SYSTEM_ALARM_OBJECT,
            ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT,
            ACEType.ACCESS_DENIED_CALLBACK_OBJECT,
            ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT,
            ACEType.SYSTEM_ALARM_CALLBACK_OBJECT,
        )


class ACERight(IntEnum):
    """ The rights of the ACE. """

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x4000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
    MAXIMUM_ALLOWED = 0x02000000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    SYNCHRONIZE = 0x00100000
    WRITE_OWNER = 0x00080000
    WRITE_DACL = 0x00040000
    READ_CONTROL = 0x00020000
    DELETE = 0x00010000
    DS_CONTROL_ACCESS = 0x00000100
    DS_CREATE_CHILD = 0x00000001
    DS_DELETE_CHILD = 0x00000002
    ACTRL_DS_LIST = 0x00000004
    DS_SELF = 0x00000008
    DS_READ_PROP = 0x00000010
    DS_WRITE_PROP = 0x00000020
    DS_DELETE_TREE = 0x00000040
    DS_LIST_OBJECT = 0x00000080

    @property
    def short_name(self) -> str:
        """ The SDDL short name of the access right. """
        short_names = {
            "GENERIC_READ": "GR",
            "GENERIC_WRITE": "GW",
            "GENERIC_EXECUTE": "GX",
            "GENERIC_ALL": "GA",
            "MAXIMUM_ALLOWED": "MA",
            "ACCESS_SYSTEM_SECURITY": "AS",
            "SYNCHRONIZE": "SY",
            "WRITE_OWNER": "WO",
            "WRITE_DACL": "WD",
            "READ_CONTROL": "RC",
            "DELETE": "SD",
            "DS_CONTROL_ACCESS": "CR",
            "DS_CREATE_CHILD": "CC",
            "DS_DELETE_CHILD": "DC",
            "ACTRL_DS_LIST": "LC",
            "DS_SELF": "SW",
            "DS_READ_PROP": "RP",
            "DS_WRITE_PROP": "WP",
            "DS_DELETE_TREE": "DT",
            "DS_LIST_OBJECT": "LO",
        }
        return short_names[self.name]


class ACLRevision(IntEnum):
    """ The ACL revision. """

    ACL_REVISION = 0x02
    ACL_REVISION_DS = 0x04


class ACE:
    """
    A class for the access control entry, that encodes the user rights
    afforded to a principal.

    :param ACEType ace_type: the type of the ACE.
    :param Set[ACEFlag] flags: the set of flags for the ACE.
    :param int mask: the access mask to encode the user rights as an int.
    :param SID trustee_sid: the SID of the trustee.
    :param uuid.UUID|None object_type: a UUID that identifies a property
        set, property, extended right, or type of child object.
    :param uuid.UUID|None inherited_object_type: a UUID that identifies the
        type of child object that can inherit the ACE.
    :param bytes application_data: optional application data.
    """

    def __init__(
        self,
        ace_type: ACEType,
        flags: Set[ACEFlag],
        mask: int,
        trustee_sid: SID,
        object_type: Optional[uuid.UUID],
        inherited_object_type: Optional[uuid.UUID],
        application_data: bytes,
    ) -> None:
        self.__type = ace_type
        self.__flags = flags
        self.__mask = mask
        self.__object_type = object_type
        self.__inherited_object_type = inherited_object_type
        self.__trustee_sid = trustee_sid
        self.__application_data = application_data

    @classmethod
    def from_binary(cls, data: bytes) -> "ACE":
        """
        Create an ACE object from a binary blob.

        :param bytes data: a little-endian byte ordered byte input.
        :returns: A new ACE instance.
        :rtype: ACE
        :raises TypeError: when the parameter is not bytes.
        :raises ValueError: when the input cannot be parsed as an ACE
            object.
        """
        try:
            if not isinstance(data, bytes):
                raise TypeError("The `data` parameter must be bytes")
            object_type = None
            inherited_object_type = None
            application_data = None
            ace_type, flags, size, mask = struct.unpack("<BBHL", data[:8])
            pos = 8
            if ACEType(ace_type).is_object_type:
                obj_flag = struct.unpack("<I", data[8:12])[0]
                pos += 4
                if obj_flag & 0x00000001:
                    object_type = uuid.UUID(bytes_le=data[pos : pos + 16])
                    pos += 16
                if obj_flag & 0x00000002:
                    inherited_object_type = uuid.UUID(bytes_le=data[pos : pos + 16])
                    pos += 16
            trustee_sid = SID(bytes_le=data[pos:])
            pos += trustee_sid.size
            application_data = data[pos:size]
            this = cls(
                ACEType(ace_type),
                {flg for flg in ACEFlag if flags & flg},
                mask,
                trustee_sid,
                object_type,
                inherited_object_type,
                application_data,
            )
            return this
        except struct.error as err:
            raise ValueError(f"Not a valid binary ACE, {err}") from None

    def __str__(self):
        """ Return the SDDL string representation of the ACE object. """
        flags = "".join(
            flg.short_name for flg in sorted(self.flags, key=lambda f: f.value)
        )
        rights = "".join(
            rgt.short_name for rgt in sorted(self.rights, key=lambda r: r.value)
        )
        object_guid = self.object_type if self.object_type else ""
        inherit_object_guid = (
            self.inherited_object_type if self.inherited_object_type else ""
        )
        sid = (
            self.trustee_sid.sddl_alias
            if self.trustee_sid.sddl_alias
            else str(self.trustee_sid)
        )
        return f"({self.type.short_name};{flags};{rights};{object_guid};{inherit_object_guid};{sid})"

    def to_binary(self) -> bytes:
        """
        Convert ACE object to binary form with little-endian byte order.

        :returns: Bytes of the binary ACE instance
        :rtype: bytes
        """
        size = self.size
        data = bytearray(size)
        struct.pack_into(
            "<BBHL", data, 0, self.type.value, sum(self.flags), size, self.mask
        )
        pos = 8
        if self.type.is_object_type:
            obj_flag = 0x00000001 if self.object_type else 0
            obj_flag |= 0x00000002 if self.inherited_object_type else 0
            struct.pack_into("<L", data, pos, obj_flag)
            pos += 4
            if self.object_type:
                data[pos : pos + 16] = self.object_type.bytes_le
                pos += 16
            if self.inherited_object_type:
                data[pos : pos + 16] = self.inherited_object_type.bytes_le
                pos += 16
        data[pos : pos + self.trustee_sid.size] = self.trustee_sid.bytes_le
        pos += self.trustee_sid.size
        data[pos : pos + size] = self.application_data
        return bytes(data)

    @property
    def type(self) -> ACEType:
        """ The type of the ACE. """
        return self.__type

    @property
    def flags(self) -> Set[ACEFlag]:
        """ The flags of the ACE. """
        return self.__flags

    @property
    def size(self) -> int:
        """ The binary size of ACE in bytes. """
        size = 8
        if self.type.is_object_type:
            size += 4
            if self.object_type:
                size += 16
            if self.inherited_object_type:
                size += 16
        size += self.trustee_sid.size
        size += len(self.application_data)
        return size

    @property
    def mask(self) -> int:
        """ The acces mask """
        return self.__mask

    @property
    def rights(self) -> Set[ACERight]:
        """ The set of ACERights based on the access mask."""
        return {rgt for rgt in ACERight if self.mask & rgt}

    @property
    def object_type(self) -> Optional[uuid.UUID]:
        """ The uuid of the object type. """
        return self.__object_type

    @property
    def inherited_object_type(self) -> Optional[uuid.UUID]:
        """ The uuid of the inherited object type. """
        return self.__inherited_object_type

    @property
    def trustee_sid(self) -> SID:
        """ The sid of the trustee. """
        return self.__trustee_sid

    @property
    def application_data(self) -> bytes:
        """ The possible application data. """
        return self.__application_data


class ACL:
    """
    The access control list (ACL) is used to specify a list of individual
    access control entries (ACEs). An ACL and an array of ACEs comprise a
    complete access control list.

    :param ACLRevision revision: the revision of the ACL.
    :param List[ACE] aces: list of :class:`ACE`.
    """

    def __init__(self, revision: ACLRevision, aces: List[ACE]) -> None:
        self.__revision = revision
        self.__aces = aces

    @classmethod
    def from_binary(cls, data: bytes) -> "ACL":
        """
        Create an ACL object from a binary blob.

        :param bytes data: a little-endian byte ordered byte input.
        :returns: A new ACL instance.
        :rtype: ACL
        :raises TypeError: when the parameter is not bytes.
        :raises ValueError: when the input cannot be parsed as an ACL
            object.
        """
        try:
            if not isinstance(data, bytes):
                raise TypeError("The `data` parameter must be bytes")
            # Unwanted values are the reserved sbz1, size and sbz2.
            rev, _, _, count, _ = struct.unpack("<BBHHH", data[:8])
            pos = 8
            aces = []
            for _ in range(count):
                ace = ACE.from_binary(data[pos:])
                aces.append(ace)
                pos += ace.size
            this = cls(ACLRevision(rev), aces)
            return this
        except struct.error as err:
            raise ValueError(f"Not a valid binary ACL, {err}") from None

    def to_binary(self) -> bytes:
        """
        Convert ACL object to binary form with little-endian byte order.

        :returns: Bytes of the binary ACL instance
        :rtype: bytes
        """
        size = self.size
        data = bytearray(8)
        struct.pack_into("<BBHHH", data, 0, self.revision, 0, size, len(self.aces), 0)
        for ace in self.aces:
            data.extend(ace.to_binary())
        return bytes(data)

    @property
    def revision(self) -> ACLRevision:
        """ The revision of ACL. """
        return self.__revision

    @property
    def size(self) -> int:
        """ The binary size in bytes. """
        return 8 + sum(ace.size for ace in self.aces)

    @property
    def aces(self) -> List[ACE]:
        """ The list of :class:`ACE` objects. """
        return self.__aces
