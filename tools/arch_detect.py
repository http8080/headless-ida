"""
arch_detect.py — Binary header parsing, architecture/file format detection (for display purposes)

Since IDA detects the architecture on its own, the results of this module are
used only for user information display and CLI output.
The actual decompiler plugin loading is determined by ida_server.py
based on ida_ida.inf_get_procname().
"""

import struct


# ─────────────────────────────────────────────
# ELF
# ─────────────────────────────────────────────

_ELF_MACHINE = {
    0x03: "x86",
    0x3E: "x86",
    0x28: "arm",
    0xB7: "arm",
    0x08: "mips",
    0x14: "ppc",
    0x15: "ppc",
    0xF3: "riscv",
}


def _detect_elf(f):
    f.seek(4)
    ei_class = struct.unpack("B", f.read(1))[0]
    bits = 64 if ei_class == 2 else 32
    f.seek(18)
    e_machine = struct.unpack("<H", f.read(2))[0]
    arch = _ELF_MACHINE.get(e_machine, f"em_{e_machine:#x}")
    return {"arch": arch, "bits": bits, "file_format": "ELF"}


# ─────────────────────────────────────────────
# PE
# ─────────────────────────────────────────────

_PE_MACHINE = {
    0x014C: ("x86", 32),
    0x8664: ("x86", 64),
    0x01C0: ("arm", 32),    # IMAGE_FILE_MACHINE_ARM
    0x01C4: ("arm", 32),    # IMAGE_FILE_MACHINE_ARMNT (Thumb-2)
    0xAA64: ("arm", 64),
}


def _detect_pe(f):
    f.seek(0x3C)
    pe_off = struct.unpack("<I", f.read(4))[0]
    f.seek(pe_off + 4)
    machine = struct.unpack("<H", f.read(2))[0]
    info = _PE_MACHINE.get(machine)
    if info:
        return {"arch": info[0], "bits": info[1], "file_format": "PE"}
    return {"arch": f"pe_{machine:#x}", "bits": 0, "file_format": "PE"}


# ─────────────────────────────────────────────
# Mach-O
# ─────────────────────────────────────────────

_MACHO_MAGIC_32 = {b"\xFE\xED\xFA\xCE", b"\xCE\xFA\xED\xFE"}
_MACHO_MAGIC_64 = {b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE"}
_MACHO_MAGIC_ALL = _MACHO_MAGIC_32 | _MACHO_MAGIC_64

# Little-endian host reads (reversed byte order)
_MACHO_LE = {b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE"}

_MACHO_CPUTYPE = {
    0x00000007: ("x86", 32),    # CPU_TYPE_X86
    0x01000007: ("x86", 64),    # CPU_TYPE_X86_64
    0x0000000C: ("arm", 32),    # CPU_TYPE_ARM
    0x0100000C: ("arm", 64),    # CPU_TYPE_ARM64
    0x00000012: ("ppc", 32),    # CPU_TYPE_POWERPC
    0x01000012: ("ppc", 64),    # CPU_TYPE_POWERPC64
}

# FAT binary magic values
_FAT_MAGIC = {
    b"\xCA\xFE\xBA\xBE",  # FAT_MAGIC (big-endian)
    b"\xBE\xBA\xFE\xCA",  # FAT_CIGAM (little-endian host)
    b"\xCA\xFE\xBA\xBF",  # FAT_MAGIC_64
    b"\xBF\xBA\xFE\xCA",  # FAT_CIGAM_64
}


def _detect_macho(f, magic):
    bits = 64 if magic in _MACHO_MAGIC_64 else 32
    endian = "<" if magic in _MACHO_LE else ">"
    f.seek(4)
    cputype = struct.unpack(f"{endian}I", f.read(4))[0]
    info = _MACHO_CPUTYPE.get(cputype)
    if info:
        return {"arch": info[0], "bits": info[1], "file_format": "Mach-O"}
    return {"arch": f"cpu_{cputype:#x}", "bits": bits, "file_format": "Mach-O"}


def _detect_fat(f, magic):
    """FAT (Universal) binary → Returns list of slices"""
    is_le = magic in {b"\xBE\xBA\xFE\xCA", b"\xBF\xBA\xFE\xCA"}
    endian = "<" if is_le else ">"
    f.seek(4)
    nfat = struct.unpack(f"{endian}I", f.read(4))[0]
    # 0xCAFEBABE == Java .class magic, if nfat > 100 it is likely Java
    if nfat > 100:
        return {"arch": "java", "bits": 0, "file_format": "Java class"}
    slices = []
    for _ in range(min(nfat, 20)):
        cputype = struct.unpack(f"{endian}I", f.read(4))[0]
        f.read(16) if magic in {b"\xCA\xFE\xBA\xBF", b"\xBF\xBA\xFE\xCA"} else f.read(16)
        info = _MACHO_CPUTYPE.get(cputype)
        if info:
            slices.append(f"{info[0]} {info[1]}bit")
        else:
            slices.append(f"cpu_{cputype:#x}")
    return {
        "arch": "fat",
        "bits": 0,
        "file_format": "Mach-O FAT",
        "slices": slices,
    }


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def arch_detect(binary_path, arch_override=None):
    """Opens a binary file and returns architecture information.

    Returns:
        dict: {"arch", "bits", "file_format"[, "slices"]}
    """
    result = {"arch": "unknown", "bits": 0, "file_format": "unknown"}
    if arch_override:
        result["arch"] = arch_override
        return result
    try:
        with open(binary_path, "rb") as f:
            magic = f.read(4)
            if magic == b"\x7fELF":
                return _detect_elf(f)
            elif magic[:2] == b"MZ":
                return _detect_pe(f)
            elif magic in _MACHO_MAGIC_ALL:
                return _detect_macho(f, magic)
            elif magic in _FAT_MAGIC:
                return _detect_fat(f, magic)
    except Exception:
        pass
    return result
