from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Optional

from binaryninja import BinaryView, log_error

ELF_HEADER_FORMAT = "<16sHHIIIIIHHHHHH"
ELF_HEADER_SIZE = 52

# e_ident offsets
EI_MAG0 = 0
EI_MAG1 = 1
EI_MAG2 = 2
EI_MAG3 = 3
EI_CLASS = 4
EI_DATA = 5

# e_ident values
ELFCLASS32 = 1
ELFDATA2LSB = 1

# e_type values
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3

# PS2 IRX values (signed short in Ghidra, represented as unsigned here)
ET_IRX = 0xFF80
ET_IRX2 = 0xFF81
ET_ERX2 = 0xFF91

# e_machine values
EM_MIPS = 8

# Program headers
P_HEADER_FORMAT = "<IIIIIIII"
P_HEADER_SIZE = 32

PT_NULL = 0
PT_LOAD = 1

PF_X = 1
PF_W = 2
PF_R = 4

# Section headers
S_HEADER_FORMAT = "<IIIIIIIIII"
S_HEADER_SIZE = 40

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11

SHT_MIPS_IOPMOD = 0x70000080
SHT_DVP_OVERLAY_TABLE = 0x7FFFF420
SHT_DVP_OVERLAY = 0x7FFFF421

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# MIPS-specific e_flags values (subset)
EF_MIPS_ARCH_MASK = 0xF0000000
EF_MIPS_ARCH_1 = 0x00000000  # MIPS I
EF_MIPS_ARCH_2 = 0x10000000
EF_MIPS_ARCH_3 = 0x20000000
EF_MIPS_ARCH_4 = 0x30000000
EF_MIPS_ARCH_5 = 0x40000000
EF_MIPS_ARCH_32 = 0x50000000
EF_MIPS_ARCH_64 = 0x60000000

EF_MIPS_32BITMODE = 0x00000100

# PS2 EE machine variant (emotionengine)
E_MIPS_MACH_5900 = 0x00920000


@dataclass(frozen=True)
class ElfHeader32:
    e_ident: bytes
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int


@dataclass(frozen=True)
class ProgramHeader32:
    p_type: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_flags: int
    p_align: int


@dataclass(frozen=True)
class SectionHeader32:
    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int


@dataclass(frozen=True)
class ElfSymbol32:
    st_name: int
    st_value: int
    st_size: int
    st_info: int
    st_other: int
    st_shndx: int

    @property
    def bind(self) -> int:
        return (self.st_info >> 4) & 0xF

    @property
    def typ(self) -> int:
        return self.st_info & 0xF


def read_elf_header(raw: BinaryView) -> Optional[ElfHeader32]:
    if raw.length < ELF_HEADER_SIZE:
        return None
    blob = raw.read(0, ELF_HEADER_SIZE)
    if len(blob) != ELF_HEADER_SIZE:
        return None
    if not (
        blob[EI_MAG0] == 0x7F
        and blob[EI_MAG1] == ord("E")
        and blob[EI_MAG2] == ord("L")
        and blob[EI_MAG3] == ord("F")
    ):
        return None
    if blob[EI_CLASS] != ELFCLASS32 or blob[EI_DATA] != ELFDATA2LSB:
        return None
    try:
        fields = struct.unpack(ELF_HEADER_FORMAT, blob)
    except struct.error as exc:
        log_error(f"[PS2] ELF header unpack failed: {exc}")
        return None
    return ElfHeader32(*fields)


def read_program_headers(raw: BinaryView, header: ElfHeader32) -> list[ProgramHeader32]:
    if header.e_phoff == 0 or header.e_phnum == 0:
        return []
    entsize = header.e_phentsize or P_HEADER_SIZE
    if entsize < P_HEADER_SIZE:
        return []
    headers: list[ProgramHeader32] = []
    for i in range(header.e_phnum):
        off = header.e_phoff + i * entsize
        if off + P_HEADER_SIZE > raw.length:
            break
        blob = raw.read(off, P_HEADER_SIZE)
        if len(blob) != P_HEADER_SIZE:
            break
        try:
            headers.append(ProgramHeader32(*struct.unpack(P_HEADER_FORMAT, blob)))
        except struct.error:
            break
    return headers


def read_section_headers(raw: BinaryView, header: ElfHeader32) -> list[SectionHeader32]:
    if header.e_shoff == 0 or header.e_shnum == 0:
        return []
    entsize = header.e_shentsize or S_HEADER_SIZE
    if entsize < S_HEADER_SIZE:
        return []
    headers: list[SectionHeader32] = []
    for i in range(header.e_shnum):
        off = header.e_shoff + i * entsize
        if off + S_HEADER_SIZE > raw.length:
            break
        blob = raw.read(off, S_HEADER_SIZE)
        if len(blob) != S_HEADER_SIZE:
            break
        try:
            headers.append(SectionHeader32(*struct.unpack(S_HEADER_FORMAT, blob)))
        except struct.error:
            break
    return headers


def read_section_names(
    raw: BinaryView, header: ElfHeader32, sections: list[SectionHeader32]
) -> list[str]:
    if not sections:
        return []
    if header.e_shstrndx >= len(sections):
        return []
    shstr = sections[header.e_shstrndx]
    if shstr.sh_type != SHT_STRTAB or shstr.sh_size == 0:
        return []
    if shstr.sh_offset + shstr.sh_size > raw.length:
        return []
    blob = raw.read(shstr.sh_offset, shstr.sh_size)
    if len(blob) != shstr.sh_size:
        return []
    names: list[str] = []
    for sh in sections:
        off = sh.sh_name
        if off < 0 or off >= len(blob):
            names.append("")
            continue
        end = blob.find(b"\x00", off)
        if end == -1:
            end = len(blob)
        try:
            names.append(blob[off:end].decode("utf-8", errors="replace"))
        except Exception:
            names.append("")
    return names
