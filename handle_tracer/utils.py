from struct import unpack_from
import collections


def read_guid(proc, ptr):
    a, b = unpack_from('>QQ', proc.memory[ptr: ptr + 16])
    unpacked = (a << 64) | b
    return unpacked


def read_uint64(proc, ptr):
    return unpack_from("<Q", proc.memory[ptr:ptr+8])[0]


def read_uint32(proc, ptr):
    return unpack_from("<I", proc.memory[ptr:ptr+4])[0]


def read_int32(proc, ptr):
    return unpack_from("<i", proc.memory[ptr:ptr+4])[0]


def read_byte(proc, ptr):
    return unpack_from("c", proc.memory[ptr:ptr+1])[0]


def read_bytes(proc, ptr, n):
    return unpack_from("c", proc.memory[ptr:ptr + 1 + n])[0]


def read_n_bytes(proc, ptr, n):
    return unpack_from("c", proc.memory[ptr:ptr + n])


def get_n_byte(target, n):
    return hex((target & (0xFF << (8*n))) >> (8*n))


def get_symbol_offset(proc, struct_type, member_name):
    struct = proc.symbols.struc(struct_type)
    member = [x for x in struct.members if x.name == member_name][0]
    return member.offset


def get_unicode_string(proc, unicode_string):

    o_buffer = get_symbol_offset(proc, "nt!_UNICODE_STRING", "Buffer")
    buffer = read_uint64(proc, unicode_string + o_buffer)

    o_size = get_symbol_offset(proc, "nt!_UNICODE_STRING", "Length")
    size = read_bytes(proc, unicode_string + o_size, 2)
    i_size = int.from_bytes(size, byteorder='big')

    i = 0
    name = bytearray()
    for char in range(i_size):
        u = read_byte(proc, buffer + i)
        if u == b'\x00':
            break
        name += u
        i += 2

    return name.decode("utf8", "ignore")


def valid_sid(proc, p_sid):
    if p_sid == 0:
        return False

    o_revision = get_symbol_offset(
        proc, "nt!_SID", "Revision")
    a_revision = p_sid + o_revision
    revision = read_byte(proc, a_revision)[0]

    if revision != 1:
        return False

    o_SubAuthority_count = get_symbol_offset(
        proc, "nt!_SID", "SubAuthorityCount")
    p_SubAuthority_count = p_sid + o_SubAuthority_count

    SubAuthorityCount = proc.memory[p_SubAuthority_count:p_SubAuthority_count + 1][0]

    if SubAuthorityCount > 15:
        return False

    return True


def get_sid_subauthority(proc, p_sid):
    return read_uint32(proc, p_sid + 8)


def get_sid_string(proc, p_sid):

    # nt!RtlConvertSidToUnicodeString

    # kd> dt nt!_SID
    # +0x000 Revision: UChar
    # +0x001 SubAuthorityCount: UChar
    # +0x002 IdentifierAuthority: _SID_IDENTIFIER_AUTHORITY
    # +0x008 SubAuthority: [1] Uint4B

    if not valid_sid(proc, p_sid):
        return "Invalid SID"

    wcs = u"S-1-"

    o_IdentifierAuthority = get_symbol_offset(
        proc, "nt!_SID", "IdentifierAuthority")
    p_IdentifierAuthority = p_sid + o_IdentifierAuthority

    IdentifierAuthority = proc.memory[p_IdentifierAuthority:p_IdentifierAuthority+6]

    if (IdentifierAuthority[0] != 0 or
            IdentifierAuthority[1] != 0):

        wcs += u"0x%02hx%02hx%02hx%02hx%02hx%02hx" % (
            IdentifierAuthority[0] << 8,
            IdentifierAuthority[1],
            IdentifierAuthority[5],
            IdentifierAuthority[4] << 8,
            IdentifierAuthority[3] << 16,
            IdentifierAuthority[2] << 24,
        )
    else:
        wcs += u"%lu" % (
            IdentifierAuthority[5] |
            IdentifierAuthority[4] << 8 |
            IdentifierAuthority[3] << 16 |
            IdentifierAuthority[2] << 24
        )

    o_SubAuthority = get_symbol_offset(
        proc, "nt!_SID", "SubAuthority")
    p_SubAuthority = p_sid + o_SubAuthority

    s_SubAuthority = 4

    o_SubAuthority_count = get_symbol_offset(
        proc, "nt!_SID", "SubAuthorityCount")
    p_SubAuthority_count = p_sid + o_SubAuthority_count

    SubAuthorityCount = proc.memory[p_SubAuthority_count: p_SubAuthority_count + 1][0]

    for i in range(SubAuthorityCount):
        SubAuthority = p_SubAuthority + (s_SubAuthority * i)
        sub = read_uint32(proc, SubAuthority)
        wcs += u"-%u" % sub

    return wcs
