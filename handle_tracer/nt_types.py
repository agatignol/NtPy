import icebox
from utils import *
import collections
import logging

INTEGRITY_LEVEL = {
    0x0000: "Untrusted",
    0x1000: "Low",
    0x2000: "Medium",
    0x3000: "High",
    0x4000: "System"
}

MITIGATIONS = {
    0x00000001: "ControlFlowGuardEnabled",
    0x00000002: "ControlFlowGuardExportSuppressionEnabled",
    0x00000004: "ControlFlowGuardStrict",
    0x00000008: "DisallowStrippedImages",
    0x00000010: "ForceRelocateImages",
    0x00000020: "HighEntropyASLREnabled",
    0x00000040: "StackRandomizationDisabled",
    0x00000080: "ExtensionPointDisable",
    0x00000100: "DisableDynamicCode",
    0x00000200: "DisableDynamicCodeAllowOptOut",
    0x00000400: "DisableDynamicCodeAllowRemoteDowngrade",
    0x00000800: "AuditDisableDynamicCode",
    0x00001000: "DisallowWin32kSystemCalls",
    0x00002000: "AuditDisallowWin32kSystemCalls",
    0x00004000: "EnableFilteredWin32kAPIs",
    0x00008000: "AuditFilteredWin32kAPIs",
    0x00010000: "DisableNonSystemFonts",
    0x00020000: "AuditNonSystemFontLoading",
    0x00040000: "PreferSystem32Images",
    0x00080000: "ProhibitRemoteImageMap",
    0x00100000: "AuditProhibitRemoteImageMap",
    0x00200000: "ProhibitLowILImageMap",
    0x00400000: "AuditProhibitLowILImageMap",
    0x00800000: "SignatureMitigationOptIn",
    0x01000000: "AuditBlockNonMicrosoftBinaries",
    0x02000000: "AuditBlockNonMicrosoftBinariesAllowStore",
    0x04000000: "LoaderIntegrityContinuityEnabled",
    0x08000000: "AuditLoaderIntegrityContinuity",
    0x10000000: "EnableModuleTamperingProtection",
    0x20000000: "EnableModuleTamperingProtectionNoInherit"
}

MITIGATIONS2 = {
    0x00000001:	"EnableExportAddressFilter",
    0x00000002:	"AuditExportAddressFilter",
    0x00000004:	"EnableExportAddressFilterPlus",
    0x00000008:	"AuditExportAddressFilterPlus",
    0x00000010:	"EnableRopStackPivot",
    0x00000020:	"AuditRopStackPivot",
    0x00000040:	"EnableRopCallerCheck",
    0x00000080:	"AuditRopCallerCheck",
    0x00000100:	"EnableRopSimExec",
    0x00000200:	"AuditRopSimExec",
    0x00000400:	"EnableImportAddressFilter",
    0x00000800:	"AuditImportAddressFilter"
}

WELLKNOWN_SIDS = {
    "S-1-0": ("Null Authority", "USER"),
    "S-1-0-0": ("Nobody", "USER"),
    "S-1-1": ("World Authority", "USER"),
    "S-1-1-0": ("Everyone", "GROUP"),
    "S-1-2": ("Local Authority", "USER"),
    "S-1-2-0": ("Local", "GROUP"),
    "S-1-2-1": ("Console Logon", "GROUP"),
    "S-1-3": ("Creator Authority", "USER"),
    "S-1-3-0": ("Creator Owner", "USER"),
    "S-1-3-1": ("Creator Group", "GROUP"),
    "S-1-3-2": ("Creator Owner Server", "COMPUTER"),
    "S-1-3-3": ("Creator Group Server", "COMPUTER"),
    "S-1-3-4": ("Owner Rights", "GROUP"),
    "S-1-4": ("Non-unique Authority", "USER"),
    "S-1-5": ("NT Authority", "USER"),
    "S-1-5-1": ("Dialup", "GROUP"),
    "S-1-5-2": ("Network", "GROUP"),
    "S-1-5-3": ("Batch", "GROUP"),
    "S-1-5-4": ("Interactive", "GROUP"),
    "S-1-5-6": ("Service", "GROUP"),
    "S-1-5-7": ("Anonymous", "GROUP"),
    "S-1-5-8": ("Proxy", "GROUP"),
    "S-1-5-9": ("Enterprise Domain Controllers", "GROUP"),
    "S-1-5-10": ("Principal Self", "USER"),
    "S-1-5-11": ("Authenticated Users", "GROUP"),
    "S-1-5-12": ("Restricted Code", "GROUP"),
    "S-1-5-13": ("Terminal Server Users", "GROUP"),
    "S-1-5-14": ("Remote Interactive Logon", "GROUP"),
    "S-1-5-15": ("This Organization ", "GROUP"),
    "S-1-5-17": ("This Organization ", "GROUP"),
    "S-1-5-18": ("Local System", "USER"),
    "S-1-5-19": ("NT Authority", "USER"),
    "S-1-5-20": ("NT Authority", "USER"),
    "S-1-5-80-0": ("All Services ", "GROUP"),
    "S-1-5-32-544": ("Administrators", "GROUP"),
    "S-1-5-32-545": ("Users", "GROUP"),
    "S-1-5-32-546": ("Guests", "GROUP"),
    "S-1-5-32-547": ("Power Users", "GROUP"),
    "S-1-5-32-548": ("Account Operators", "GROUP"),
    "S-1-5-32-549": ("Server Operators", "GROUP"),
    "S-1-5-32-550": ("Print Operators", "GROUP"),
    "S-1-5-32-551": ("Backup Operators", "GROUP"),
    "S-1-5-32-552": ("Replicators", "GROUP"),
    "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "GROUP"),
    "S-1-5-32-555": ("Remote Desktop Users", "GROUP"),
    "S-1-5-32-556": ("Network Configuration Operators", "GROUP"),
    "S-1-5-32-557": ("Incoming Forest Trust Builders", "GROUP"),
    "S-1-5-32-558": ("Performance Monitor Users", "GROUP"),
    "S-1-5-32-559": ("Performance Log Users", "GROUP"),
    "S-1-5-32-560": ("Windows Authorization Access Group", "GROUP"),
    "S-1-5-32-561": ("Terminal Server License Servers", "GROUP"),
    "S-1-5-32-562": ("Distributed COM Users", "GROUP"),
    "S-1-5-32-568": ("IIS_IUSRS", "GROUP"),
    "S-1-5-32-569": ("Cryptographic Operators", "GROUP"),
    "S-1-5-32-573": ("Event Log Readers", "GROUP"),
    "S-1-5-32-574": ("Certificate Service DCOM Access", "GROUP"),
    "S-1-5-32-575": ("RDS Remote Access Servers", "GROUP"),
    "S-1-5-32-576": ("RDS Endpoint Servers", "GROUP"),
    "S-1-5-32-577": ("RDS Management Servers", "GROUP"),
    "S-1-5-32-578": ("Hyper-V Administrators", "GROUP"),
    "S-1-5-32-579": ("Access Control Assistance Operators", "GROUP"),
    "S-1-5-32-580": ("Access Control Assistance Operators", "GROUP")
}

HeaderCreatorInfoFlag = 0x1
HeaderNameInfoFlag = 0x2
HeaderHandleInfoFlag = 0x4
HeaderQuotaInfoFlag = 0x8
HeaderProcessInfoFlag = 0x10

SE_OWNER_DEFAULTED = 0x0001
SE_GROUP_DEFAULTED = 0x0002
SE_DACL_PRESENT = 0x0004
SE_DACL_DEFAULTED = 0x0008
SE_SACL_PRESENT = 0x0010
SE_SACL_DEFAULTED = 0x0020
SE_DACL_AUTO_INHERIT_REQ = 0x0100
SE_SACL_AUTO_INHERIT_REQ = 0x0200
SE_DACL_AUTO_INHERITED = 0x0400
SE_SACL_AUTO_INHERITED = 0x0800
SE_DACL_PROTECTED = 0x1000
SE_SACL_PROTECTED = 0x2000
SE_SELF_RELATIVE = 0x8000

OBJECT_INHERIT_ACE = 0x01
CONTAINER_INHERIT_ACE = 0x02
NO_PROPAGATE_INHERIT_ACE = 0x04
INHERIT_ONLY_ACE = 0x08
INHERITED_ACE = 0x10
SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
FAILED_ACCESS_ACE_FLAG = 0x80

ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1
SYSTEM_AUDIT_ACE_TYPE = 2

DELETE = 0x00010000  # DE
READ_CONTROL = 0x00020000  # RC
WRITE_DAC = 0x00040000  # WDAC
WRITE_OWNER = 0x00080000  # WO
SYNCHRONIZE = 0x00100000  # S
ACCESS_SYSTEM_SECURITY = 0x01000000  # AS
GENERIC_READ = 0x80000000  # GR
GENERIC_WRITE = 0x40000000  # GW
GENERIC_EXECUTE = 0x20000000  # GE
GENERIC_ALL = 0x10000000  # GA

FILE_READ_DATA = 0x00000001  # RD
FILE_LIST_DIRECTORY = 0x00000001
FILE_WRITE_DATA = 0x00000002  # WD
FILE_ADD_FILE = 0x00000002
FILE_APPEND_DATA = 0x00000004  # AD
FILE_ADD_SUBDIRECTORY = 0x00000004
FILE_READ_EA = 0x00000008  # REA
FILE_WRITE_EA = 0x00000010  # WEA
FILE_EXECUTE = 0x00000020  # X
FILE_TRAVERSE = 0x00000020
FILE_DELETE_CHILD = 0x00000040  # DC
FILE_READ_ATTRIBUTES = 0x00000080  # RA
FILE_WRITE_ATTRIBUTES = 0x00000100  # WA

FILE_GENERIC_READ = (FILE_READ_DATA |
                     FILE_READ_EA |
                     FILE_READ_ATTRIBUTES |
                     READ_CONTROL |
                     SYNCHRONIZE)

FILE_GENERIC_WRITE = (FILE_WRITE_DATA |
                      FILE_APPEND_DATA |
                      FILE_WRITE_EA |
                      FILE_WRITE_ATTRIBUTES |
                      READ_CONTROL |
                      SYNCHRONIZE)

FILE_GENERIC_EXECUTE = (FILE_EXECUTE |
                        FILE_READ_ATTRIBUTES |
                        READ_CONTROL |
                        SYNCHRONIZE)

FILE_ALL_ACCESS = 0x001F01FF

FILE_MODIFY_ACCESS = FILE_ALL_ACCESS & ~(FILE_DELETE_CHILD |
                                         WRITE_DAC |
                                         WRITE_OWNER)

FILE_READ_EXEC_ACCESS = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE

FILE_DELETE_ACCESS = DELETE | SYNCHRONIZE

_ObjectInformation = collections.namedtuple('_ObjectInformation',
                                            'object type name creator body')


class ObjectInformation(_ObjectInformation):
    def __str__(self):
        out = ("\nObject : %s \n" % hex(self.object))
        if self.type is not None:
            out += ("Object type : %s\n" % self.type)
        if self.name != 0:
            out += ("Object name : %s\n" % self.name)
        if self.creator:
            out += ("Object created by : %s\n" % self.creator)

        if self.body:
            out += self.body.__str__()
        return out


_ObjectSecurity = collections.namedtuple('_ObjectSecurity',
                                         'path sd')


class ObjectSecurity(_ObjectSecurity):
    def __str__(self):
        if self.sd != 0:
            sacl_ace_list = []
            dacl_ace_list = []
            self.dacl = self.sd.get_dacl()
            self.sacl = self.sd.get_sacl()

            owner = self.sd.get_owner_sid()
            group = self.sd.get_group_sid()

            if owner in WELLKNOWN_SIDS.keys():
                owner = WELLKNOWN_SIDS[owner][0]

            if group in WELLKNOWN_SIDS.keys():
                group = WELLKNOWN_SIDS[group][0]

            items = ['\nPath:  %s' % self.path,
                     'Owner: %s' % owner,
                     'Group: %s' % group]

            if self.dacl != 0 and not None:
                ace_count = self.dacl.get_ace_count()
                dacl_ace_list = self.dacl.get_ace_list()
                if dacl_ace_list:
                    items += ['DACL:  \n\t%s' %
                              '       \n\t'.join(str(x) for x in dacl_ace_list)]
            if self.sacl != 0 and not None:
                ace_count = self.sacl.get_ace_count()
                sacl_ace_list = self.sacl.get_ace_list()
                if sacl_ace_list:
                    items += ['SACL:  \n\t%s' %
                              '       \n\t'.join(str(x) for x in sacl_ace_list)]
            return '\n'.join(items)
        else:
            return "\nSecurity Descriptor : NULL"


class nt_Section():
    def __init__(self, proc, body):
        pass

    def __str__(self):
        out = "\n"
        return out

    def get_path(self):
        return


class nt_Driver():
    def __init__(self, proc, body):
        pass

    def __str__(self):
        out = "\n"
        return out

    def get_path(self):
        return


class nt_Device():
    def __init__(self, proc, body):
        pass

    def __str__(self):
        out = "\n"
        return out

    def get_path(self):
        return


class nt_AlpcPort():
    def __init__(self, proc, body):
        self.port = body
        self.owner_process = self.__get_owner_process(proc)

    def __str__(self):
        out = "\n"
        return out

    def get_path(self):
        return

    def __get_owner_process(self, proc):
        o_process = get_symbol_offset(
            proc, "nt!_ALPC_PORT", "OwnerProcess")
        a_process = self.port + o_process

        process = read_uint64(proc, a_process)

        return nt_Process(proc, process)


class nt_File():
    def __init__(self, proc, body):
        self.file = body
        self.filename = self.__get_filename(proc)

    def __str__(self):
        out = "\n"
        return out

    def get_path(self):
        return

    def __get_filename(self, proc):
        o_filename = get_symbol_offset(
            proc, "nt!_FILE_OBJECT", "FileName")
        a_filename = self.file + o_filename
        return get_unicode_string(proc, a_filename)


class nt_Process():
    def __init__(self, proc, body):
        self.process = body
        self.name = self.__get_process_name(proc)
        self.pid = self.__get_pid(proc)
        self.token = self.__get_token(proc)
        self.parent = self.__get_parent(proc)
        self.mitigations = self.__get_mitigations(proc)

        self.il = ""
        if self.token != 0:
            self.il = self.token.get_il()

    def __str__(self):
        info = str()
        info += "Process : " + self.name + " " + \
            "(" + str(self.pid) + ")" + "\n"
        info += "ParentId : " + str(self.parent) + "\n"
        if self.mitigations:
            info += "Mitigations : \n"
            for m in self.mitigations:
                info += "\t" + m + "\n"
        info += "Integrity level : " + self.il + "\n"
        return info

    def get_name(self):
        return self.name

    def get_pid(self):
        return self.pid

    def get_mitigations(self):
        return self.mitigations

    def get_parent_pid(self):
        return self.parent

    def __get_token(self, proc):
        if self.process == 0:
            return 0

        o_token = get_symbol_offset(
            proc, "nt!_EPROCESS", "Token")
        a_token = self.process + o_token

        token = read_uint64(proc, a_token)
        token = token & 0xfffffffffffffff0

        if token == 0:
            return 0

        return nt_Token(proc, token)

    def __get_parent(self, proc):
        if self.process == 0:
            return 0

        o_pid = get_symbol_offset(
            proc, "nt!_EPROCESS", "OwnerProcessId")
        a_pid = self.process + o_pid
        return read_uint64(proc, a_pid)

    def __resolve_mitigations(self, proc, mitigationflag, mitigationflag2):
        mitigations = []
        for k, v in MITIGATIONS.items():
            if k & mitigationflag:
                mitigations.append(v)

        for k, v in MITIGATIONS2.items():
            if k & mitigationflag2:
                mitigations.append(v)

        return mitigations

    def __get_mitigations(self, proc):
        if self.process == 0:
            return 0

        o_flag = get_symbol_offset(
            proc, "nt!_EPROCESS", "MitigationFlags")
        a_flag = self.process + o_flag

        flag_b = proc.memory[a_flag:a_flag + 4]
        flag = unpack_from("<I", flag_b)[0]

        o_flag2 = get_symbol_offset(
            proc, "nt!_EPROCESS", "MitigationFlags2")
        a_flag2 = self.process + o_flag2
        flag2_b = proc.memory[a_flag2:a_flag2 + 4]
        flag2 = unpack_from("<I", flag2_b)[0]
        mitigations = self.__resolve_mitigations(proc, flag, flag2)
        return mitigations

    def __get_pid(self, proc):
        if self.process == 0:
            return 0

        o_pid = get_symbol_offset(
            proc, "nt!_EPROCESS", "UniqueProcessId")
        a_pid = self.process + o_pid
        return read_uint64(proc, a_pid)

    def __get_process_name(self, proc):
        if self.process == 0:
            return 0

        o_name = get_symbol_offset(
            proc, "nt!_EPROCESS", "ImageFileName")
        a_name = self.process + o_name
        return self.__read_process_name(proc, a_name)

    def __read_process_name(self, proc, a_name):
        name = bytearray()
        for i in range(15):
            name += read_byte(proc, a_name + i)
        return name.decode("utf8", "ignore")


class nt_Token():
    def __init__(self, proc, p_token):
        self.token = p_token
        self.il = self.__get_il(proc)

    def __str__(self):
        return "test_token"

    def get_path(self):
        return

    def get_il(self):
        return self.il

    def __get_il(self, proc):

        if self.token == 0:
            return 0

        o_sidhash = get_symbol_offset(
            proc, "nt!_TOKEN", "SidHash")
        a_sidhash = self.token + o_sidhash

        if a_sidhash == 0:
            return 0

        count = read_uint64(proc, a_sidhash)

        o_arraysid = get_symbol_offset(
            proc, "nt!_TOKEN", "UserAndGroups")
        a_arraysid = self.token + o_arraysid

        arraysid = read_uint64(proc, a_arraysid)

        size = proc.symbols.struc("nt!_SID_AND_ATTRIBUTES").size

        sid = None
        ptr = arraysid

        if arraysid == 0:
            return 0

        for sid in range(count):

            o_attributes = get_symbol_offset(
                proc, "nt!_SID_AND_ATTRIBUTES", "Attributes")
            a_attributes = ptr + o_attributes
            attributes = read_uint64(proc, a_attributes)
            if attributes & 0x20:  # SE_GROUP_INTEGRITY = 0x00000020L
                o_sid = get_symbol_offset(
                    proc, "nt!_SID_AND_ATTRIBUTES", "Sid")
                a_sid = ptr + o_sid
                sid = read_uint64(proc, a_sid)

                subauthority = get_sid_subauthority(proc, sid)
                for k, v in INTEGRITY_LEVEL.items():
                    if k & subauthority:
                        return v
            ptr += size

        return 0


class nt_Object():
    def __init__(self, proc, p_object):
        self.object = p_object
        self.object_header = self.__get_object_header(proc)
        self.object_header_info_mask = self.__get_object_header_info_mask(proc)
        self.sd = self.__get_object_sd(proc)
        self.object_type = self.__get_object_type(proc)
        self.object_body = self.__get_object_body(proc)

        self.object_creator_info_offset, self.object_name_info_offset = self.__get_object_header_info_offset(
            proc)

        self.path = self.__get_object_path(proc)
        self.object_name = self.__get_object_name(proc)
        self.object_creator = self.__get_object_creator(proc)

        creator = ""
        if(self.object_creator != 0):
            creator = self.object_creator.get_name()
            exit(0)

        self.object_information = ObjectInformation(
            self.object, self.object_type, self.object_name, creator, self.object_body)
        self.object_security = ObjectSecurity(self.path, self.sd)

    def get_object_security(self):
        return self.object_security

    def get_object_information(self):
        return self.object_information

    def __get_object_header_info_mask(self, proc):
        if self.object == 0:
            return 0
        if self.object_header == 0:
            return 0

        o_infomask = get_symbol_offset(
            proc, "nt!_OBJECT_HEADER", "InfoMask")
        a_infomask = self.object_header + o_infomask

        infomask_b = proc.memory[a_infomask:a_infomask + 1]
        infomask = unpack_from("<B", infomask_b)[0]

        return infomask

    def __get_object_name(self, proc):
        # nt!ObQueryNameStringMode

        if self.object == 0:
            return 0
        if self.object_header == 0:
            return 0
        if self.object_name_info_offset == 0:
            return 0

        object_name_info = self.object_header - self.object_name_info_offset

        o_name = get_symbol_offset(
            proc, "nt!_OBJECT_HEADER_NAME_INFO", "Name")
        a_name = object_name_info + o_name
        return get_unicode_string(proc, a_name)

    def __get_object_creator(self, proc):

        if self.object == 0:
            return 0
        if self.object_header == 0:
            return 0
        if self.object_creator_info_offset == 0:
            return 0

        object_creator_info = self.object_header - self.object_creator_info_offset

        o_creator = get_symbol_offset(
            proc, "nt!_OBJECT_HEADER_CREATOR_INFO", "CreatorUniqueProcess")
        a_creator = object_creator_info + o_creator

        return nt_Process(proc, a_creator)

    def __get_object_header_info_offset(self, proc):
        if self.object == 0:
            return 0
        if self.object_header == 0:
            return 0

        creator = 0
        name = 0

        if (self.object_header_info_mask & HeaderCreatorInfoFlag):
            size = proc.symbols.struc(
                "nt!_OBJECT_HEADER_CREATOR_INFO").size
            creator = size
        if (self.object_header_info_mask & HeaderNameInfoFlag):
            size = proc.symbols.struc(
                "nt!_OBJECT_HEADER_NAME_INFO").size
            name = size + creator

        return creator, name

    def __get_object_header(self, proc):

        if self.object == 0:
            return 0

        object_header = self.object - \
            proc.symbols.struc("nt!_OBJECT_HEADER").size + 8
        # p.symbols.dump_type("nt!_OBJECT_HEADER", object_header)
        return object_header

    def __get_object_sd(self, proc):

        # nt!ObGetObjectSecurity

        o_sd = get_symbol_offset(
            proc, "nt!_OBJECT_HEADER", "SecurityDescriptor")
        a_sd = self.object_header + o_sd
        sd = read_uint64(proc, a_sd)

        if sd == 0:
            return 0

        sd = sd & 0xfffffffffffffff0

        # proc.symbols.dump_type("nt!_SECURITY_DESCRIPTOR", sd)

        return nt_SecurityDescriptor(proc, sd)

    def __get_object_path(self, proc):
        # FIXME
        return "FakePath"
        # return self.object_body.get_path()

    def __get_type_index(self, proc, ObHeaderCookie):
        offset = get_symbol_offset(proc, "nt!_OBJECT_HEADER", "TypeIndex")
        typeindex = read_byte(proc, self.object_header + offset)[0]
        cookie = read_byte(proc, ObHeaderCookie)[0]
        addr_lsb = get_n_byte(self.object_header, 1)

        index = typeindex ^ cookie ^ int(addr_lsb, 16)

        return index

    def __get_object_type(self, proc):

        # nt!ObGetObjectType

        if self.object_header == 0:
            return 0

        ObTypeIndexTable = proc.symbols.address("nt!ObTypeIndexTable")
        ObHeaderCookie = proc.symbols.address("nt!ObHeaderCookie")

        index = self.__get_type_index(proc, ObHeaderCookie)

        a_object_type = ObTypeIndexTable + (index * 8)
        object_type = read_uint64(proc, a_object_type)
        # p.symbols.dump_type("nt!_OBJECT_TYPE", object_type)

        o_name = get_symbol_offset(proc, "nt!_OBJECT_TYPE", "Name")
        name_string = object_type + o_name

        object_type_name = get_unicode_string(proc, name_string)

        return object_type_name

    def __get_object_body(self, proc):
        if (self.object_type == "ActivationObject"):
            return
        elif (self.object_type == "ActivityReference"):
            return
        elif (self.object_type == "Adapater"):
            return
        elif (self.object_type == "ALPC Port"):
            return nt_AlpcPort(proc, self.object)
        elif (self.object_type == "Callback"):
            # nt!_CALLBACK_OBJECT
            return
        elif (self.object_type == "Composition"):
            return
        elif (self.object_type == "Controller"):
            return
        elif (self.object_type == "CoreMessaging"):
            return
        elif (self.object_type == "CoverageSampler"):
            return
        elif (self.object_type == "DebugObject"):
            # nt!_DEBUG_OBJECT
            return
        elif (self.object_type == "Desktop"):
            return
        elif (self.object_type == "Device"):
            return nt_Device(proc, self.object)
        elif (self.object_type == "Directory"):
            # nt!_OBJECT_DIRECTORY
            return
        elif (self.object_type == "DmaAdaptater"):
            return
        elif (self.object_type == "Driver"):
            return nt_Driver(proc, self.object)
        elif (self.object_type == "DxgkCompositionObject"):
            return
        elif (self.object_type == "DxgkCurrentDxgProcessObject"):
            return
        elif (self.object_type == "DxgkDisplayManagerObject"):
            return
        elif (self.object_type == "DxgkSharedBundleObject"):
            return
        elif (self.object_type == "DxgkSharedKeyedMutexObject"):
            return
        elif (self.object_type == "DxgkSharedProtectedSessionObject"):
            return
        elif (self.object_type == "DxgkSharedResource"):
            return
        elif (self.object_type == "DxgkSharedSwapChainObject"):
            return
        elif (self.object_type == "DxgkSharedSyncObject"):
            return
        elif (self.object_type == "EnergyTracker"):
            return
        elif (self.object_type == "EtwConsumer"):
            return
        elif (self.object_type == "EtwRegistration"):
            return
        elif (self.object_type == "EtwSessionDemuxEntry"):
            return
        elif (self.object_type == "Event"):
            # nt!_EEVENT
            return
        elif (self.object_type == "File"):
            return nt_File(proc, self.object)
        elif (self.object_type == "FilterCommunicationPort"):
            return
        elif (self.object_type == "FilterConnectionPort"):
            return
        elif (self.object_type == "IoCompletion"):
            return
        elif (self.object_type == "IoCompletionReserve"):
            return
        elif (self.object_type == "IRTimer"):
            return
        elif (self.object_type == "Job"):
            return
        elif (self.object_type == "Key"):
            return
        elif (self.object_type == "KeyedEvent"):
            return
        elif (self.object_type == "Mutant"):
            return
        elif (self.object_type == "NdisCmState"):
            return
        elif (self.object_type == "Partition"):
            return
        elif (self.object_type == "PcwObject"):
            return
        elif (self.object_type == "PowerRequest"):
            return
        elif (self.object_type == "Process"):
            return nt_Process(proc, self.object)
        elif (self.object_type == "Profile"):
            return
        elif (self.object_type == "PsSiloContextNonPaged"):
            return
        elif (self.object_type == "PsSiloContextPaged"):
            return
        elif (self.object_type == "RawInputManager"):
            return
        elif (self.object_type == "RegistryTransaction"):
            return
        elif (self.object_type == "Section"):
            return nt_Section(proc, self.object)
        elif (self.object_type == "Semaphore"):
            return
        elif (self.object_type == "Session"):
            return
        elif (self.object_type == "SymbolicLink"):
            return
        elif (self.object_type == "Thread"):
            return
        elif (self.object_type == "Timer"):
            return
        elif (self.object_type == "TmEn"):
            return
        elif (self.object_type == "TmRm"):
            return
        elif (self.object_type == "TmTm"):
            return
        elif (self.object_type == "TmTx"):
            return
        elif (self.object_type == "Token"):
            return nt_Token(proc, self.object)
        elif (self.object_type == "TmTx"):
            return
        elif (self.object_type == "TpWorkerFactory"):
            return
        elif (self.object_type == "Type"):
            return
        elif (self.object_type == "UserApcReserve"):
            return
        elif (self.object_type == "VRegConfigurationContext"):
            return
        elif (self.object_type == "WaitCompletionPacket"):
            return
        elif (self.object_type == "WindowStation"):
            return
        elif (self.object_type == "WmiGuid"):
            return
        else:
            return


class nt_SecurityDescriptor():
    def __init__(self, proc, sd):
        self.sd = sd
        self.revision = self.__get_revision(proc)
        self.control = self.__get_control_flags(proc)
        self.dacl = 0
        self.sacl = 0
        if self.control & SE_DACL_PRESENT:
            self.dacl = self.__get_dacl(proc)
        if self.control & SE_DACL_PRESENT:
            self.sacl = self.__get_sacl(proc)

        self.owner_sid = self.__get_owner_sid(proc)
        self.group_sid = self.__get_group_sid(proc)

    def __get_revision(self, proc):

        if self.sd == 0:
            return 0

        o_revision = get_symbol_offset(
            proc, "nt!_SECURITY_DESCRIPTOR", "Revision")
        a_revision = self.sd + o_revision
        revision = read_byte(proc, a_revision)[0]

        return revision

    def get_revision(self):
        return self.revision

    def __get_control_flags(self, proc):

        if self.sd == 0:
            return 0

        o_control = get_symbol_offset(
            proc, "nt!_SECURITY_DESCRIPTOR", "Control")
        a_control = self.sd + o_control
        control_flags = read_uint64(proc, a_control)
        control_flags = control_flags & 0x000000000000ffff
        return control_flags

    def __get_dacl(self, proc):

        # nt!RtlGetDaclSecurityDescriptor

        if self.sd == 0:
            return 0

        if self.revision != 1:
            return 0

        # if (control & SE_DACL_PRESENT) == 0:
        #    return 0

        # if (control & SE_SELF_RELATIVE) == 0:
        #    return 0

        o_group = get_symbol_offset(
            proc, "nt!_SECURITY_DESCRIPTOR", "Group")

        group_value = read_uint64(proc, self.sd + o_group)
        group_value = group_value & 0x00000000ffffffff
        dacl = self.sd + group_value

        # proc.symbols.dump_type("nt!_ACL", a_dacl)

        return nt_Acl(proc, dacl)

    def __get_sacl(self, proc):

        # nt!RtlGetSaclSecurityDescriptor

        if self.sd == 0:
            return 0

        if self.revision != 1:
            return 0

        control = self.control
        control = control & 0x000000000000ffff

        if (control & 0x10) == 0:  # SE_SACL_PRESENT
            return 0

        o_sacl = read_uint64(proc, self.sd + 0xC)
        o_sacl = o_sacl & 0x00000000ffffffff

        sacl = self.sd + o_sacl

        return nt_Acl(proc, sacl)

    def __get_owner_sid(self, proc):
        # nt!RtlGetOwnerSecurityDescriptor

        if self.sd == 0:
            return 0

        if self.revision != 1:
            return 0

        if self.control >= 0:

            i = read_uint64(proc, self.sd + 4)
            i = i & 0x00000000ffffffff
            if i == 0:
                o_owner = get_symbol_offset(
                    proc, "nt!_SECURITY_DESCRIPTOR", "Owner")
                a_owner = sd + o_owner
            else:
                a_owner = self.sd + i

        return get_sid_string(proc, a_owner)

    def __get_group_sid(self, proc):
        # nt!RtlGetGroupSecurityDescriptor

        if self.sd == 0:
            return 0

        if self.revision != 1:
            return 0

        if self.control >= 0:
            o_group = get_symbol_offset(
                proc, "nt!_SECURITY_DESCRIPTOR", "Group")
            group = self.sd + o_group
        else:
            owner = self.owner & 0x00000000ffffffff
            if owner != 0:
                group = self.sd + owner
            else:
                return 0

        return get_sid_string(proc, group)

    def get_owner_sid(self):
        return self.owner_sid

    def get_group_sid(self):
        return self.group_sid

    def get_control(self):
        return self.control

    def get_dacl(self):
        return self.dacl

    def get_sacl(self):
        return self.sacl


class nt_Acl():
    def __init__(self, proc, acl):
        self.acl = acl
        self.revision, sbz, self.acl_size, self.ace_count, sbz2 = self.__get_acl_info(
            proc)
        self.ace_list = self.__get_ace_list(proc)

    def get_acl(self):
        return self.acl

    def __get_acl_info(self, proc):
        acl = proc.memory[self.acl:self.acl + 8]
        rev, _sbz, size, count, _sbz2 = unpack_from("<BBHHH", acl)
        return rev, _sbz, size, count, _sbz2

    def get_ace_list(self):
        return self.ace_list

    def get_ace_count(self):
        return self.ace_count

    def __get_ace(self, proc, ace_type, ace_flags, ace_mask, sid, trustee):
        if ace_mask < 0:
            ace_mask += 2 ** 32
        ace = nt_Ace(ace_type, ace_flags, ace_mask,
                     sid, trustee)
        return ace

    def __get_ace_list(self, proc):

        # nt!RtlGetAce

        if self.acl is None:
            return

        if self.acl == 0:
            return

        if self.revision < 2:
            return

        if self.revision > 4:
            return

        # proc.symbols.dump_type("nt!_ACL", self.acl)

        ace_list = []

        ace_array = self.acl + proc.symbols.struc("nt!_ACL").size

        # define FirstAce(Acl) ((PVOID)((PUCHAR)(Acl) + sizeof(ACL)))
        # define NextAce(Ace) ((PVOID)((PUCHAR)(Ace) + ((PACE_HEADER)(Ace))->AceSize))

        if self.ace_count <= 0:
            return ace_list

        # proc.symbols.dump_type("nt!_ACE", ace_array)

        # _ACE_HEADER structure is not published in symbols
        # _ACE structure is not published in symbols

        # kd > dt nt!_ACL
        # +0x000 AclRevision      : UChar
        # +0x001 Sbz1             : UChar
        # +0x002 AclSize          : Uint2B
        # +0x004 AceCount         : Uint2B
        # +0x006 Sbz2             : Uint2B

        # 00000000 _ACE            struc
        # (sizeof=0x8, align=0x4, copyof_2324)
        # 00000000 Header          ACE_HEADER ?
        # 00000004 AccessMask      dd ?
        # 00000008 _ACE            ends

        # 00000000 ACE_HEADER      struc
        # (sizeof=0x4, align=0x2, copyof_2325)
        # 00000000 AceType         db ?
        # 00000001 AceFlags        db ?
        # 00000002 AceSize         dw ?
        # 00000004 ACE_HEADER      ends

        # 00000000 _ACCESS_ALLOWED_ACE struc
        # (sizeof=0xC, align=0x4, copyof_2328)
        # 00000000 Header          ACE_HEADER ?
        # 00000004 Mask            dd ?
        # 00000008 SidStart        dd ?
        # 0000000C _ACCESS_ALLOWED_ACE ends

        offset = 0
        for ace in range(self.ace_count):
            if (ace_array + offset >= self.acl + self.acl_size):
                break

            ace_addr = ace_array + offset
            acestr = proc.memory[ace_addr:ace_addr + 4]
            ace_type, ace_flags, ace_size = unpack_from("<BBH", acestr)

            if (ace_size == 0):
                break

            # ACCESS_ALLOWED_ACE_TYPE 0x00
            # ACCESS_DENIED_ACE_TYPE 0x01
            # documentation : windows_protocols/ms-dtyp

            if (ace_type == 0x00):
                # struct ACCESS_ALLOWED_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            elif (ace_type == 0x01):
                # struct ACCESS_DENIED_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            elif (ace_type == 0x02):
                # struct SYSTEM_AUDIT_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            elif (ace_type == 0x05):
                # struct ACCESS_ALLOWED_OBJECT_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 0x2c + offset)
            elif (ace_type == 0x06):
                # struct ACCESS_DENIED_OBJECT_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 0x2c + offset)
            elif (ace_type == 0x07):
                # struct SYSTEM_AUDIT_OBJECT_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 0x2c + offset)
            elif (ace_type == 0x09):
                # struct ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            elif (ace_type == 0x0A):
                # struct ACCESS_DENIED_CALLBACK_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            elif (ace_type == 0x0B):
                # struct ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 0x2c + offset)
            elif (ace_type == 0x0C):
                # struct ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 0x2c + offset)
            elif (ace_type == 0x0D):
                # struct SYSTEM_AUDIT_CALLBACK_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            elif (ace_type == 0x0F):
                # struct SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 0x2c + offset)
            elif (ace_type == 0x11):
                # struct SYSTEM_MANDATORY_LABEL_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            elif (ace_type == 0x12):
                # struct SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            elif (ace_type == 0x13):
                # struct SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            else:
                # ACE Type not handled
                break

            offset = offset + ace_size

            trustee = None
            ace = self.__get_ace(proc, ace_type,
                                 ace_flags, ace_mask, ace_sid, trustee)
            ace_list.append(ace)
        return ace_list


_nt_Ace = collections.namedtuple('_nt_Ace',
                                 'ace_type flags mask mapped_mask sid trustee')


class nt_Ace(_nt_Ace):
    def __new__(cls, ace_type, flags, mask, sid, trustee):
        mapped_mask = cls._map_generic(mask)
        return super(nt_Ace, cls).__new__(cls, ace_type, flags,
                                          mask, mapped_mask, sid, trustee)

    @staticmethod
    def _map_generic(mask):
        if mask & GENERIC_READ:
            mask = (mask & ~GENERIC_READ) | FILE_GENERIC_READ
        if mask & GENERIC_WRITE:
            mask = (mask & ~GENERIC_WRITE) | FILE_GENERIC_WRITE
        if mask & GENERIC_EXECUTE:
            mask = (mask & ~GENERIC_EXECUTE) | FILE_GENERIC_EXECUTE
        if mask & GENERIC_ALL:
            mask = (mask & ~GENERIC_ALL) | FILE_ALL_ACCESS
        return mask

    def inherited(self):         # I
        return bool(self.flags & INHERITED_ACE)

    def object_inherit(self):    # OI
        return bool(self.flags & OBJECT_INHERIT_ACE)

    def container_inherit(self):  # CI
        return bool(self.flags & CONTAINER_INHERIT_ACE)

    def inherit_only(self):      # IO
        return bool(self.flags & INHERIT_ONLY_ACE)

    def no_propagate(self):      # NP
        return bool(self.flags & NO_PROPAGATE_INHERIT_ACE)

    def no_access(self):         # N
        return self.mapped_mask == 0

    def full_access(self):       # F
        return self.mapped_mask == FILE_ALL_ACCESS

    def modify_access(self):     # M
        return self.mapped_mask == FILE_MODIFY_ACCESS

    def read_exec_access(self):  # RX
        return self.mapped_mask == FILE_READ_EXEC_ACCESS

    def read_only_access(self):  # R
        return self.mapped_mask == FILE_GENERIC_READ

    def write_only_access(self):  # W
        return self.mapped_mask == FILE_GENERIC_WRITE

    def delete_access(self):     # D
        return self.mapped_mask == FILE_DELETE_ACCESS

    def get_file_rights(self):
        if self.no_access():
            return ['N']
        if self.full_access():
            return ['F']
        if self.modify_access():
            return ['M']
        if self.read_exec_access():
            return ['RX']
        if self.read_only_access():
            return ['R']
        if self.write_only_access():
            return ['W']
        if self.delete_access():
            return ['D']
        rights = []
        for right, name in ((DELETE, 'DE'), (READ_CONTROL, 'RC'),
                            (WRITE_DAC, 'WDAC'), (WRITE_OWNER, 'WO'),
                            (SYNCHRONIZE, 'S'),
                            (ACCESS_SYSTEM_SECURITY, 'AS'),
                            (GENERIC_READ, 'GR'), (GENERIC_WRITE, 'GW'),
                            (GENERIC_EXECUTE, 'GE'), (GENERIC_ALL, 'GA'),
                            (FILE_READ_DATA, 'RD'), (FILE_WRITE_DATA, 'WD'),
                            (FILE_APPEND_DATA, 'AD'), (FILE_READ_EA, 'REA'),
                            (FILE_WRITE_EA, 'WEA'), (FILE_EXECUTE, 'X'),
                            (FILE_DELETE_CHILD, 'DC'),
                            (FILE_READ_ATTRIBUTES, 'RA'),
                            (FILE_WRITE_ATTRIBUTES, 'WA')):
            if self.mask & right:
                rights.append(name)
        return rights

    def granted_access(self, mask):
        return bool(self.mapped_mask & self._map_generic(mask))

    def __str__(self):
        trustee = self.trustee if self.trustee else self.sid
        access = []
        if self.ace_type == ACCESS_DENIED_ACE_TYPE:
            access.append('(DENY)')
        elif self.ace_type == SYSTEM_AUDIT_ACE_TYPE:
            access.append('(AUDIT)')
        if self.inherited():
            access.append('(I)')
        if self.object_inherit():
            access.append('(OI)')
        if self.container_inherit():
            access.append('(CI)')
        if self.inherit_only():
            access.append('(IO)')
        if self.no_propagate():
            access.append('(NP)')
        access.append('(%s)' % ','.join(self.get_file_rights()))
        return '%s:%s' % (trustee, ''.join(access))
