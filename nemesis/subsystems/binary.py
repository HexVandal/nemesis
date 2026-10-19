"""Static binary triage.

This is deliberately a *triage* tool, not an exploit framework. It parses
the container formats - ELF, PE, Mach-O - far enough to answer the
questions that decide what to do next: what architecture is this, is it
stripped, are the exploit mitigations on, does it import the dangerous
functions, is it packed, and does it contain a credential.

Everything here is pure parsing of bytes on disk. Nothing is executed.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

#: Magic numbers for the formats we recognise.
ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",  # 32-bit big endian
    b"\xce\xfa\xed\xfe",  # 32-bit little endian
    b"\xfe\xed\xfa\xcf",  # 64-bit big endian
    b"\xcf\xfa\xed\xfe",  # 64-bit little endian
    b"\xca\xfe\xba\xbe",  # universal / fat
)

#: ELF machine types worth naming.
_ELF_MACHINES = {
    0x03: ("x86", "Intel 80386"),
    0x08: ("mips", "MIPS"),
    0x14: ("ppc", "PowerPC"),
    0x15: ("ppc64", "PowerPC 64-bit"),
    0x16: ("s390", "IBM S/390"),
    0x28: ("arm", "ARM"),
    0x2A: ("superh", "SuperH"),
    0x32: ("ia64", "Intel IA-64"),
    0x3E: ("x86-64", "x86-64"),
    0xB7: ("aarch64", "ARM 64-bit"),
    0xF3: ("riscv", "RISC-V"),
}

#: Import names that make a binary worth a closer look.
DANGEROUS_IMPORTS = {
    "execve": "arbitrary command execution",
    "execl": "arbitrary command execution",
    "execvp": "arbitrary command execution",
    "system": "arbitrary command execution",
    "popen": "command execution with output",
    "dlopen": "loading of arbitrary shared objects",
    "dlsym": "dynamic symbol resolution",
    "mprotect": "memory permission changes, used in shellcode loaders",
    "mmap": "executable memory mapping",
    "mprotect_exec": "executable memory",
    "strcpy": "unbounded copy, a classic overflow",
    "strcat": "unbounded concatenation, a classic overflow",
    "sprintf": "unbounded formatting, a classic overflow",
    "gets": "unbounded read, removed from the C standard for this reason",
    "memcpy": "unbounded copy",
    "CreateProcessA": "process creation",
    "CreateProcessW": "process creation",
    "ShellExecuteA": "shell execution",
    "ShellExecuteW": "shell execution",
    "WinExec": "shell execution",
    "VirtualAlloc": "executable memory allocation",
    "VirtualProtect": "memory permission changes",
    "LoadLibraryA": "dynamic library loading",
    "LoadLibraryW": "dynamic library loading",
    "URLDownloadToFileA": "remote file download",
    "InternetOpenA": "outbound network access",
}

#: Signatures of common packers.
PACKER_SIGNATURES = {
    "UPX": (b"UPX!", "UPX packer"),
    "ASPack": (b".aspack", "ASPack"),
    "Themida": (b".themida", "Themida"),
    "VMProtect": (b".vmp", "VMProtect"),
    "MPRESS": (b".MPRESS1", "MPRESS"),
    "PEtite": (b"PEtite", "PEtite"),
}

#: Credential-shaped strings inside a binary.
_EMBEDDED_CREDENTIAL = re.compile(
    rb"(?:AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{30,}|xox[baprs]-[0-9A-Za-z-]{10,}"
    rb"|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


@dataclass
class BinaryInfo:
    """Everything triage learned about one file."""

    path: str
    format: str = "unknown"
    arch: str = ""
    bits: int = 0
    endian: str = ""
    is_dynamically_linked: bool = False
    is_stripped: bool = False
    has_nx: bool | None = None
    has_pie: bool | None = None
    has_relro: str | None = None
    has_canary: bool | None = None
    is_pie: bool | None = None
    imports: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    packer: str = ""
    embedded_credentials: list[str] = field(default_factory=list)
    size: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.format,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "dynamically_linked": self.is_dynamically_linked,
            "stripped": self.is_stripped,
            "nx": self.has_nx,
            "pie": self.has_pie,
            "relro": self.has_relro,
            "canary": self.has_canary,
            "imports": list(self.imports),
            "sections": list(self.sections),
            "packer": self.packer,
            "embedded_credentials": list(self.embedded_credentials),
            "size": self.size,
            "notes": list(self.notes),
        }


def identify(data: bytes) -> str:
    """Name the container format of *data*."""
    if data.startswith(ELF_MAGIC):
        return "elf"
    if data.startswith(MACHO_MAGICS):
        return "macho"
    if data[:2] == PE_MAGIC:
        return "pe"
    return "unknown"


def triage(path: str | Path) -> BinaryInfo:
    """Parse *path* and report what a triage needs to know."""
    path = Path(path)
    info = BinaryInfo(path=str(path))
    try:
        data = path.read_bytes()
    except OSError as exc:
        info.notes.append(f"could not read: {exc}")
        return info

    info.size = len(data)
    info.format = identify(data)
    info.embedded_credentials = [
        match.decode("utf-8", errors="replace")[:80]
        for match in _EMBEDDED_CREDENTIAL.findall(data)
    ]

    for marker, name in PACKER_SIGNATURES.values():
        if marker in data:
            info.packer = name
            info.notes.append(
                f"packed with {name}; section headers and symbols are likely "
                f"unreliable"
            )
            break

    if info.format == "elf":
        _triage_elf(data, info)
    elif info.format == "pe":
        _triage_pe(data, info)
    elif info.format == "macho":
        _triage_macho(data, info)

    return info


# -- ELF -----------------------------------------------------------------
def _triage_elf(data: bytes, info: BinaryInfo) -> None:
    if len(data) < 64:
        info.notes.append("truncated ELF header")
        return

    bits = data[4]  # EI_CLASS: 1 = 32-bit, 2 = 64-bit
    info.bits = 32 if bits == 1 else 64
    endian = "little" if data[5] == 1 else "big"
    info.endian = endian

    prefix = "<" if endian == "little" else ">"
    machine = struct.unpack_from(prefix + "H", data, 18)[0]
    arch, description = _ELF_MACHINES.get(machine, ("unknown", f"machine {machine}"))
    info.arch = f"{arch} ({description})"

    if info.bits == 64:
        e_type, = struct.unpack_from(prefix + "H", data, 16)
        e_phoff, = struct.unpack_from(prefix + "Q", data, 32)
        e_phentsize, e_phnum = struct.unpack_from(prefix + "HH", data, 54)
        e_shoff, = struct.unpack_from(prefix + "Q", data, 40)
        e_shentsize, e_shnum = struct.unpack_from(prefix + "HH", data, 58)
    else:
        e_type, = struct.unpack_from(prefix + "H", data, 16)
        e_phoff, = struct.unpack_from(prefix + "I", data, 28)
        e_phentsize, e_phnum = struct.unpack_from(prefix + "HH", data, 42)
        e_shoff, = struct.unpack_from(prefix + "I", data, 32)
        e_shentsize, e_shnum = struct.unpack_from(prefix + "HH", data, 46)

    info.is_pie = e_type == 3  # ET_DYN
    info.has_pie = e_type == 3

    # Program headers: PT_GNU_STACK governs NX.
    has_exec_stack = False
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        if offset + e_phentsize > len(data):
            break
        p_type, = struct.unpack_from(prefix + "I", data, offset)
        if p_type == 0x6474E551:  # PT_GNU_STACK
            p_flags, = struct.unpack_from(prefix + "I", data, offset + 4)
            has_exec_stack = bool(p_flags & 0x1)
    info.has_nx = not has_exec_stack
    if has_exec_stack:
        info.notes.append("executable stack: NX is not enforced")

    # Section headers: names, and whether the symbol table survived.
    for index in range(min(e_shnum, 256)):
        offset = e_shoff + index * e_shentsize
        if offset + e_shentsize > len(data):
            break
        if info.bits == 64:
            sh_name, = struct.unpack_from(prefix + "I", data, offset)
            sh_type, = struct.unpack_from(prefix + "I", data, offset + 4)
            sh_offset, = struct.unpack_from(prefix + "Q", data, offset + 24)
            sh_size, = struct.unpack_from(prefix + "Q", data, offset + 32)
        else:
            sh_name, = struct.unpack_from(prefix + "I", data, offset)
            sh_type, = struct.unpack_from(prefix + "I", data, offset + 4)
            sh_offset, = struct.unpack_from(prefix + "I", data, offset + 16)
            sh_size, = struct.unpack_from(prefix + "I", data, offset + 20)

        name = _cstring(data, sh_offset)
        if name:
            info.sections.append(name)
        if sh_type == 2:  # SHT_SYMTAB
            info.is_stripped = False
        if sh_type == 0x6:  # SHT_DYNAMIC
            info.is_dynamically_linked = True

    if info.bits == 64:
        shstrndx, = struct.unpack_from(prefix + "H", data, 62)
        if shstrndx < e_shnum:
            offset = e_shoff + shstrndx * e_shentsize
            sh_offset, = struct.unpack_from(prefix + "Q", data, offset + 24)
            sh_size, = struct.unpack_from(prefix + "Q", data, offset + 32)
            table = data[sh_offset : sh_offset + sh_size]
            for index in range(min(e_shnum, 256)):
                sec_offset = e_shoff + index * e_shentsize
                if sec_offset + e_shentsize > len(data):
                    break
                sh_name, = struct.unpack_from(prefix + "I", data, sec_offset)
                if sh_name < len(table):
                    end = table.find(b"\x00", sh_name)
                    name = table[sh_name : end if end != -1 else len(table)]
                    info.sections.append(name.decode("utf-8", errors="replace"))

    # Symbol table presence and the dangerous imports in it.
    symbols = _elf_symbols(data, info, prefix)
    info.is_stripped = not symbols and ".symtab" not in info.sections
    for symbol in symbols:
        if symbol in DANGEROUS_IMPORTS:
            info.imports.append(symbol)
    info.has_canary = "__stack_chk_fail" in symbols or "___stack_chk_fail" in symbols
    info.has_relro = "full" if "BIND_NOW" in symbols else ("partial" if symbols else None)


def _elf_symbols(data: bytes, info: BinaryInfo, prefix: str) -> list[str]:
    """Pull symbol names out of the dynamic symbol table."""
    names: list[str] = []
    for marker in (b"libc.so", b"GLIBC_2"):
        if marker in data:
            info.is_dynamically_linked = True
    # The dynamic string table holds the imported names.
    for match in re.finditer(rb"[\x20-\x7e]{4,64}\x00", data):
        text = match.group(0)[:-1].decode("ascii", errors="replace")
        if text in DANGEROUS_IMPORTS or text in ("__stack_chk_fail", "__stack_chk_fail_local"):
            names.append(text)
    # A stack canary reference shows up as a versioned symbol string.
    if b"stack_chk_fail" in data:
        names.append("__stack_chk_fail")
    return names


# -- PE ------------------------------------------------------------------
def _triage_pe(data: bytes, info: BinaryInfo) -> None:
    if len(data) < 0x40:
        info.notes.append("truncated PE header")
        return
    pe_offset, = struct.unpack_from("<I", data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        info.notes.append("PE signature not found")
        return

    machine, = struct.unpack_from("<H", data, pe_offset + 4)
    info.arch = {
        0x014C: "x86 (Intel 386)",
        0x8664: "x86-64 (AMD64)",
        0x01C0: "arm",
        0xAA64: "aarch64",
        0x0200: "ia64",
    }.get(machine, f"machine {machine:#x}")

    magic, = struct.unpack_from("<H", data, pe_offset + 24)
    info.bits = 64 if magic == 0x20B else 32
    info.endian = "little"

    characteristics, = struct.unpack_from("<H", data, pe_offset + 22)
    info.is_dynamically_linked = bool(characteristics & 0x0002)  # IMAGE_FILE_DLL
    info.is_pie = bool(characteristics & 0x0020)  # IMAGE_FILE_DLL
    info.has_nx = bool(characteristics & 0x0100)  # IMAGE_FILE_NX_COMPAT
    info.has_pie = bool(characteristics & 0x0020)

    for match in re.finditer(rb"[\x20-\x7e]{4,64}\x00", data):
        text = match.group(0)[:-1].decode("ascii", errors="replace")
        if text in DANGEROUS_IMPORTS:
            info.imports.append(text)
    if b"__security_check_cookie" in data or b"__security_cookie" in data:
        info.has_canary = True
    if b".reloc" in data or b".rsrc" in data:
        info.sections.append(".reloc" if b".reloc" in data else ".rsrc")
    if b"ASLR" in data or b"DynamicBase" in data:
        info.has_pie = True


# -- Mach-O --------------------------------------------------------------
def _triage_macho(data: bytes, info: BinaryInfo) -> None:
    magic = data[:4]
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        endian = "big"
    else:
        endian = "little"
    info.endian = endian
    prefix = "<" if endian == "little" else ">"

    cputype, = struct.unpack_from(prefix + "I", data, 4)
    info.arch = {
        7: "x86",
        0x01000007: "x86-64",
        12: "arm",
        0x0100000C: "aarch64",
    }.get(cputype, f"cpu {cputype}")

    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        info.bits = 64 if magic == b"\xcf\xfa\xed\xfe" else 32
    else:
        info.bits = 64 if magic in (b"\xfe\xed\xfa\xcf",) else 32

    info.is_pie = True
    info.has_pie = True
    for match in re.finditer(rb"[\x20-\x7e]{4,64}\x00", data):
        text = match.group(0)[:-1].decode("ascii", errors="replace")
        if text in DANGEROUS_IMPORTS:
            info.imports.append(text)
    if b"__stack_chk_fail" in data:
        info.has_canary = True
    if b"RESTRICT" in data:
        info.has_nx = True


def _cstring(data: bytes, offset: int) -> str:
    if offset <= 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        return ""
    return data[offset:end].decode("utf-8", errors="replace")
