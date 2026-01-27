from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterable


DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_BIND_NOW = 24
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_RUNPATH = 29
DT_FLAGS = 30
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33

DT_GNU_HASH = 0x6FFFFEF5
DT_RELR = 0x6FFFE000
DT_RELRSZ = 0x6FFFE001
DT_RELRENT = 0x6FFFE003

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6

SHN_UNDEF = 0


@dataclass(frozen=True)
class DynamicEntry:
    tag: int
    value: int


@dataclass(frozen=True)
class ElfSymbol:
    name: str
    value: int
    size: int
    info: int
    other: int
    shndx: int

    @property
    def bind(self) -> int:
        return (self.info >> 4) & 0xF

    @property
    def typ(self) -> int:
        return self.info & 0xF

    @property
    def is_undef(self) -> bool:
        return self.shndx == SHN_UNDEF


class DynamicParseError(RuntimeError):
    pass


def _to_offset(value: int, base_addr: int, image_len: int) -> int:
    if 0 <= value < image_len:
        return value
    if base_addr and value >= base_addr and (value - base_addr) < image_len:
        return value - base_addr
    return value


def parse_dynamic_table(
    image: bytes, dyn_offset: int, is_aarch32: bool
) -> list[DynamicEntry]:
    entries: list[DynamicEntry] = []
    off = dyn_offset
    entry_size = 0x8 if is_aarch32 else 0x10
    while off + entry_size <= len(image):
        if is_aarch32:
            tag, value = struct.unpack_from("<II", image, off)
        else:
            tag, value = struct.unpack_from("<QQ", image, off)
        entries.append(DynamicEntry(tag=tag, value=value))
        off += entry_size
        if tag == DT_NULL:
            break
    return entries


def dynamic_values(entries: Iterable[DynamicEntry]) -> dict[int, list[int]]:
    out: dict[int, list[int]] = {}
    for entry in entries:
        out.setdefault(entry.tag, []).append(entry.value)
    return out


def dynamic_first(
    entries: Iterable[DynamicEntry], tag: int, default: int | None = None
) -> int | None:
    for entry in entries:
        if entry.tag == tag:
            return entry.value
    return default


def parse_dynstr(image: bytes, strtab_addr: int, size: int, base_addr: int) -> bytes:
    if size <= 0:
        return b""
    off = _to_offset(strtab_addr, base_addr, len(image))
    if off < 0 or off + size > len(image):
        raise DynamicParseError("dynstr range outside image")
    return image[off : off + size]


def symbol_table_size(
    image: bytes,
    entries: list[DynamicEntry],
    base_addr: int,
    is_aarch32: bool,
) -> int:
    symtab_addr = dynamic_first(entries, DT_SYMTAB)
    if symtab_addr is None:
        return 0
    syment = dynamic_first(entries, DT_SYMENT)
    if syment is None:
        syment = 0x10 if is_aarch32 else 0x18

    hash_addr = dynamic_first(entries, DT_HASH)
    if hash_addr is not None:
        off = _to_offset(hash_addr, base_addr, len(image))
        if off + 8 <= len(image):
            _, nchain = struct.unpack_from("<II", image, off)
            return int(nchain * syment)

    strtab_addr = dynamic_first(entries, DT_STRTAB)
    if strtab_addr is None:
        return 0
    symtab_off = _to_offset(symtab_addr, base_addr, len(image))
    strtab_off = _to_offset(strtab_addr, base_addr, len(image))
    if strtab_off > symtab_off:
        return int(strtab_off - symtab_off)

    return 0


def parse_dynsym(
    image: bytes,
    entries: list[DynamicEntry],
    base_addr: int,
    is_aarch32: bool,
) -> list[ElfSymbol]:
    symtab_addr = dynamic_first(entries, DT_SYMTAB)
    if symtab_addr is None:
        return []
    strtab_addr = dynamic_first(entries, DT_STRTAB)
    strtab_size = dynamic_first(entries, DT_STRSZ, 0) or 0
    if strtab_addr is None or strtab_size <= 0:
        return []

    syment = dynamic_first(entries, DT_SYMENT)
    if syment is None:
        syment = 0x10 if is_aarch32 else 0x18

    total_size = symbol_table_size(image, entries, base_addr, is_aarch32)
    if total_size <= 0:
        return []

    symtab_off = _to_offset(symtab_addr, base_addr, len(image))
    strtab = parse_dynstr(image, strtab_addr, strtab_size, base_addr)

    symbols: list[ElfSymbol] = []
    count = total_size // syment
    for i in range(count):
        off = symtab_off + i * syment
        if off + syment > len(image):
            break
        if is_aarch32:
            st_name, st_value, st_size, st_info, st_other, st_shndx = (
                struct.unpack_from("<IIIBBH", image, off)
            )
        else:
            st_name, st_info, st_other, st_shndx, st_value, st_size = (
                struct.unpack_from("<IBBHQQ", image, off)
            )
        name = ""
        if st_name < len(strtab):
            end = strtab.find(b"\x00", st_name)
            if end == -1:
                end = len(strtab)
            name = strtab[st_name:end].decode("utf-8", errors="replace")

        symbols.append(
            ElfSymbol(
                name=name,
                value=st_value,
                size=st_size,
                info=st_info,
                other=st_other,
                shndx=st_shndx,
            )
        )

    return symbols
