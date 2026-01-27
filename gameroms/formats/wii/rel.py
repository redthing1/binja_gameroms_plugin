from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, List, TYPE_CHECKING

if TYPE_CHECKING:
    from binaryninja import BinaryView


R_PPC_NONE = 0
R_PPC_ADDR32 = 1
R_PPC_ADDR24 = 2
R_PPC_ADDR16 = 3
R_PPC_ADDR16_LO = 4
R_PPC_ADDR16_HI = 5
R_PPC_ADDR16_HA = 6
R_PPC_ADDR14 = 7
R_PPC_ADDR14_BRTAKEN = 8
R_PPC_ADDR14_BRNTAKEN = 9
R_PPC_REL24 = 10
R_PPC_REL14 = 11
R_PPC_REL14_BRTAKEN = 12
R_PPC_REL14_BRNTAKEN = 13

R_DOLPHIN_NOP = 201
R_DOLPHIN_SECTION = 202
R_DOLPHIN_END = 203
R_DOLPHIN_MRKREF = 204


@dataclass
class RelSection:
    offset: int
    size: int
    is_executable: bool
    addr: int = 0


@dataclass
class RelImport:
    module_id: int
    offset: int


@dataclass
class RelHeader:
    module_id: int
    section_count: int
    section_table_offset: int
    module_name_offset: int
    module_name_length: int
    module_version: int
    bss_size: int
    relocation_table_offset: int
    import_table_offset: int
    import_table_size: int
    prolog_section_id: int
    epilog_section_id: int
    unresolved_section_id: int
    bss_section_id: int
    prolog_section_offset: int
    epilog_section_offset: int
    unresolved_section_offset: int
    section_alignment: int
    bss_section_alignment: int
    fix_size: int

    def size(self) -> int:
        if self.module_version in (0, 1):
            return 0x40
        if self.module_version == 2:
            return 0x48
        return 0x4C

    def full_size(self) -> int:
        return self.size() + self.section_count * 8


@dataclass
class RelModule:
    name: str
    header: RelHeader
    sections: list[RelSection]
    imports: list[RelImport]
    data: bytes


class RelParseError(RuntimeError):
    pass


def _read_u32(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def parse_rel(data: bytes, name: str) -> RelModule:
    if len(data) < 0x40:
        raise RelParseError("REL file too small")

    module_id = _read_u32(data, 0x00)
    section_count = _read_u32(data, 0x0C)
    section_table_offset = _read_u32(data, 0x10)
    module_name_offset = _read_u32(data, 0x14)
    module_name_length = _read_u32(data, 0x18)
    module_version = _read_u32(data, 0x1C)
    bss_size = _read_u32(data, 0x20)
    relocation_table_offset = _read_u32(data, 0x24)
    import_table_offset = _read_u32(data, 0x28)
    import_table_size = _read_u32(data, 0x2C)

    prolog_section_id = data[0x30]
    epilog_section_id = data[0x31]
    unresolved_section_id = data[0x32]
    bss_section_id = data[0x33]
    prolog_section_offset = _read_u32(data, 0x34)
    epilog_section_offset = _read_u32(data, 0x38)
    unresolved_section_offset = _read_u32(data, 0x3C)

    section_alignment = 32
    bss_section_alignment = 32
    fix_size = 0
    if module_version > 1:
        section_alignment = _read_u32(data, 0x40)
        bss_section_alignment = _read_u32(data, 0x44)
    if module_version > 2:
        fix_size = _read_u32(data, 0x48)

    header = RelHeader(
        module_id=module_id,
        section_count=section_count,
        section_table_offset=section_table_offset,
        module_name_offset=module_name_offset,
        module_name_length=module_name_length,
        module_version=module_version,
        bss_size=bss_size,
        relocation_table_offset=relocation_table_offset,
        import_table_offset=import_table_offset,
        import_table_size=import_table_size,
        prolog_section_id=prolog_section_id,
        epilog_section_id=epilog_section_id,
        unresolved_section_id=unresolved_section_id,
        bss_section_id=bss_section_id,
        prolog_section_offset=prolog_section_offset,
        epilog_section_offset=epilog_section_offset,
        unresolved_section_offset=unresolved_section_offset,
        section_alignment=section_alignment,
        bss_section_alignment=bss_section_alignment,
        fix_size=fix_size,
    )

    if section_table_offset + section_count * 8 > len(data):
        raise RelParseError("REL section table out of bounds")

    sections: list[RelSection] = []
    for i in range(section_count):
        base = section_table_offset + i * 8
        addr_field = _read_u32(data, base)
        size = _read_u32(data, base + 4)
        is_exec = (addr_field & 1) != 0
        offset = addr_field & ~1
        sections.append(RelSection(offset=offset, size=size, is_executable=is_exec))

    imports: list[RelImport] = []
    if import_table_offset + import_table_size <= len(data):
        count = import_table_size // 8
        for i in range(count):
            base = import_table_offset + i * 8
            mod_id = _read_u32(data, base)
            offs = _read_u32(data, base + 4)
            imports.append(RelImport(module_id=mod_id, offset=offs))

    return RelModule(
        name=name, header=header, sections=sections, imports=imports, data=data
    )


def _read_be32(bv: "BinaryView", addr: int) -> int:
    raw = bv.read(addr, 4)
    if len(raw) != 4:
        return 0
    return struct.unpack(">I", raw)[0]


def _write_be32(bv: "BinaryView", addr: int, value: int) -> None:
    bv.write(addr, struct.pack(">I", value & 0xFFFFFFFF))


def _write_be16(bv: "BinaryView", addr: int, value: int) -> None:
    bv.write(addr, struct.pack(">H", value & 0xFFFF))


def apply_rel_relocations(
    bv: "BinaryView",
    rel_module: RelModule,
    modules_by_id: dict[int, RelModule],
) -> None:
    from binaryninja import log_info

    if bv.file.has_database:
        return

    applied = 0
    for imp in rel_module.imports:
        other_module = modules_by_id.get(imp.module_id)
        write_addr = 0
        pos = imp.offset

        while True:
            if pos + 8 > len(rel_module.data):
                break
            offset = struct.unpack_from(">H", rel_module.data, pos)[0]
            r_type = rel_module.data[pos + 2]
            section = rel_module.data[pos + 3]
            addend = struct.unpack_from(">I", rel_module.data, pos + 4)[0]
            pos += 8

            if r_type == R_DOLPHIN_END:
                break
            if r_type == R_DOLPHIN_SECTION:
                if section < len(rel_module.sections):
                    write_addr = rel_module.sections[section].addr & ~1
                continue
            if r_type == R_DOLPHIN_NOP or r_type == R_PPC_NONE:
                continue
            if r_type == R_DOLPHIN_MRKREF:
                continue

            write_addr += offset
            target_addr = write_addr & 0xFFFFFFFF

            if imp.module_id == 0:
                import_section_addr = 0
            else:
                if other_module is None or section >= len(other_module.sections):
                    continue
                import_section_addr = other_module.sections[section].addr & ~1

            if r_type == R_PPC_ADDR16_HA:
                addr_val = (import_section_addr + addend) & 0xFFFFFFFF
                value = (addr_val >> 16) & 0xFFFF
                if addr_val & 0x8000:
                    value = (value + 1) & 0xFFFF
                _write_be16(bv, target_addr, value)
                applied += 1
            elif r_type == R_PPC_ADDR24:
                orig = _read_be32(bv, target_addr)
                value = ((import_section_addr + addend) & 0x3FFFFFC) | (
                    orig & 0xFC000003
                )
                _write_be32(bv, target_addr, value)
                applied += 1
            elif r_type == R_PPC_ADDR32:
                _write_be32(bv, target_addr, import_section_addr + addend)
                applied += 1
            elif r_type in (R_PPC_ADDR16, R_PPC_ADDR16_LO):
                _write_be16(bv, target_addr, (import_section_addr + addend) & 0xFFFF)
                applied += 1
            elif r_type == R_PPC_ADDR16_HI:
                _write_be16(
                    bv, target_addr, ((import_section_addr + addend) >> 16) & 0xFFFF
                )
                applied += 1
            elif r_type == R_PPC_REL24:
                orig = _read_be32(bv, target_addr)
                value = ((import_section_addr + addend - write_addr) & 0x3FFFFFC) | (
                    orig & 0xFC000003
                )
                _write_be32(bv, target_addr, value)
                applied += 1
            elif r_type in (R_PPC_ADDR14, R_PPC_ADDR14_BRNTAKEN, R_PPC_ADDR14_BRTAKEN):
                orig = _read_be32(bv, target_addr)
                value = ((import_section_addr + addend) & 0xFFFC) | (orig & 0xFFFF0003)
                _write_be32(bv, target_addr, value)
                applied += 1
            elif r_type in (R_PPC_REL14, R_PPC_REL14_BRNTAKEN, R_PPC_REL14_BRTAKEN):
                orig = _read_be32(bv, target_addr)
                value = ((import_section_addr + addend - write_addr) & 0xFFFC) | (
                    orig & 0xFFFF0003
                )
                _write_be32(bv, target_addr, value)
                applied += 1

    if applied:
        log_info(
            f"[WII REL] applied {applied} relocations for module {rel_module.name}"
        )
