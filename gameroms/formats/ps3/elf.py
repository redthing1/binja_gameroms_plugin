"""Bounded ELF64 big-endian PPU parsing."""

from dataclasses import dataclass
import hashlib
import struct


ELF_HEADER = struct.Struct(">16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct(">IIQQQQQQ")
SECTION_HEADER = struct.Struct(">IIQQQQIIQQ")
SYMBOL = struct.Struct(">IBBHQQ")
EXECUTABLE = 2
PRX = 0xFFA4


def checked_range(offset: int, size: int, limit: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > limit:
        raise ValueError(f"{label} range exceeds its container")


def validate_ranges(ranges: list[tuple[int, int]], label: str) -> None:
    ordered = sorted((start, end) for start, end in ranges if end > start)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        raise ValueError(f"overlapping {label}")


@dataclass(frozen=True)
class ProgramHeader:
    kind: int
    flags: int
    offset: int
    address: int
    physical_address: int
    file_size: int
    memory_size: int
    alignment: int


@dataclass(frozen=True)
class Section:
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True)
class ElfSymbol:
    name: str
    value: int
    size: int
    section: int
    kind: int
    binding: int
    visibility: int


class ElfImage:
    def __init__(self, name: str, data: bytes):
        self.name, self.data = name, data
        self.slice(0, ELF_HEADER.size)
        header = ELF_HEADER.unpack_from(data)
        ident, kind, machine, version, self.entry, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, names = header
        if ident[:7] != b"\x7fELF\x02\x02\x01" or machine != 21 or version != 1:
            raise ValueError("expected big-endian ELF64 PPU")
        if kind not in (EXECUTABLE, PRX) or ehsize != ELF_HEADER.size:
            raise ValueError("expected a PPU executable or Sony PRX")
        if not phnum or phnum == 0xFFFF or phsize != PROGRAM_HEADER.size:
            raise ValueError("unsupported ELF program-header table")
        self.slice(phoff, phsize * phnum)
        self.kind = kind
        self.program_headers = tuple(ProgramHeader(*PROGRAM_HEADER.unpack_from(data, phoff + index * phsize))
                                     for index in range(phnum))
        for program in self.program_headers:
            self.slice(program.offset, program.file_size)
            if program.kind in (1, 7):
                if program.file_size > program.memory_size:
                    raise ValueError("ELF file bytes exceed segment memory")
                if program.alignment > 1 and program.alignment & (program.alignment - 1):
                    raise ValueError("ELF segment alignment is not a power of two")
        # PT_LOAD ordinals include empty segments; Sony relocations use these identities.
        self.segments = tuple(program for program in self.program_headers if program.kind == 1)
        if not self.segments:
            raise ValueError("ELF has no loadable segments")
        self.sections = self._sections(shoff, shsize, shnum, names)
        self.sha256 = hashlib.sha256(data).hexdigest()

    def slice(self, offset: int, size: int) -> bytes:
        checked_range(offset, size, len(self.data), self.name)
        return self.data[offset:offset + size]

    def symbols(self):
        for table in self.sections:
            if table.kind not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
                continue
            if table.entry_size != SYMBOL.size or table.size % SYMBOL.size:
                raise ValueError("invalid ELF symbol-table entry size")
            if not 0 < table.link < len(self.sections) or self.sections[table.link].kind != 3:
                raise ValueError("ELF symbol table has no string table")
            names = self.sections[table.link]
            strings = self.slice(names.offset, names.size)
            for offset in range(table.offset, table.offset + table.size, SYMBOL.size):
                name, info, other, section, value, size = SYMBOL.unpack_from(self.data, offset)
                if name >= len(strings) or (end := strings.find(b"\0", name)) < 0:
                    raise ValueError("invalid ELF symbol name")
                if section == 0xFFFF:
                    raise ValueError("extended ELF symbol section indices are unsupported")
                if section < 0xFF00 and section >= len(self.sections):
                    raise ValueError("invalid ELF symbol section index")
                yield ElfSymbol(strings[name:end].decode("utf-8", errors="replace"), value, size,
                                section, info & 15, info >> 4, other & 7)

    def _sections(self, offset: int, width: int, count: int, names: int) -> tuple[Section, ...]:
        if not offset and not count:
            return ()
        if not count or width != SECTION_HEADER.size or names == 0xFFFF or names >= count:
            raise ValueError("unsupported ELF section-header table")
        self.slice(offset, width * count)
        headers = [SECTION_HEADER.unpack_from(self.data, offset + index * width) for index in range(count)]
        strings = b""
        if names:
            table = headers[names]
            if table[1] != 3:
                raise ValueError("section-name table is not a string table")
            strings = self.slice(table[4], table[5])
        sections = []
        for item in headers:
            name_offset, kind, flags, address, source, size, link, info, alignment, entry_size = item
            if kind not in (0, 8):
                self.slice(source, size)
            name = ""
            if name_offset:
                if name_offset >= len(strings) or (end := strings.find(b"\0", name_offset)) < 0:
                    raise ValueError("invalid ELF section name")
                name = strings[name_offset:end].decode("utf-8", errors="replace")
            sections.append(Section(name, kind, flags, address, source, size, link, info, alignment, entry_size))
        return tuple(sections)
