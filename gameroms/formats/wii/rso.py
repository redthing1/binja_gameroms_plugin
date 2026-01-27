from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from binaryninja import BinaryView

from .rel import (
    R_PPC_ADDR14,
    R_PPC_ADDR14_BRNTAKEN,
    R_PPC_ADDR14_BRTAKEN,
    R_PPC_ADDR16,
    R_PPC_ADDR16_HA,
    R_PPC_ADDR16_HI,
    R_PPC_ADDR16_LO,
    R_PPC_ADDR24,
    R_PPC_ADDR32,
    R_PPC_NONE,
    R_PPC_REL14,
    R_PPC_REL14_BRNTAKEN,
    R_PPC_REL14_BRTAKEN,
    R_PPC_REL24,
)


@dataclass
class RsoSection:
    offset: int
    size: int
    addr: int = 0


@dataclass
class RsoExport:
    name: str
    value: int
    section: int


@dataclass
class RsoImport:
    name: str
    rel_offset: int


@dataclass
class RsoRelocation:
    offset: int
    info: int
    addend: int

    @property
    def relocation_type(self) -> int:
        return self.info & 0xFF

    @property
    def section_index(self) -> int:
        return (self.info >> 8) & 0xFFFFFF


@dataclass
class RsoHeader:
    num_sections: int
    section_info_offset: int
    name_offset: int
    name_size: int
    version: int
    bss_size: int
    prolog_section: int
    epilog_section: int
    unresolved_section: int
    bss_section: int
    prolog_offset: int
    epilog_offset: int
    unresolved_offset: int
    internal_rel_offset: int
    internal_rel_size: int
    external_rel_offset: int
    external_rel_size: int
    export_symbol_table_offset: int
    export_symbol_table_size: int
    export_symbol_names_offset: int
    import_symbol_table_offset: int
    import_symbol_table_size: int
    import_symbol_names_offset: int


@dataclass
class RsoModule:
    name: str
    header: RsoHeader
    sections: List[RsoSection]
    internal_relocs: List[RsoRelocation]
    external_relocs: List[RsoRelocation]
    exports: List[RsoExport]
    imports: List[RsoImport]
    data: bytes


class RsoParseError(RuntimeError):
    pass


def _read_u32(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def _read_str(data: bytes, off: int) -> str:
    end = data.find(b"\x00", off)
    if end == -1:
        return ""
    return data[off:end].decode("ascii", errors="replace")


def parse_rso(data: bytes, name: str) -> RsoModule:
    if len(data) < 0x58:
        raise RsoParseError("RSO file too small")

    num_sections = _read_u32(data, 0x08)
    section_info_offset = _read_u32(data, 0x0C)
    name_offset = _read_u32(data, 0x10)
    name_size = _read_u32(data, 0x14)
    version = _read_u32(data, 0x18)
    bss_size = _read_u32(data, 0x1C)
    prolog_section = data[0x20]
    epilog_section = data[0x21]
    unresolved_section = data[0x22]
    bss_section = data[0x23]
    prolog_offset = _read_u32(data, 0x24)
    epilog_offset = _read_u32(data, 0x28)
    unresolved_offset = _read_u32(data, 0x2C)
    internal_rel_offset = _read_u32(data, 0x30)
    internal_rel_size = _read_u32(data, 0x34)
    external_rel_offset = _read_u32(data, 0x38)
    external_rel_size = _read_u32(data, 0x3C)
    export_symbol_table_offset = _read_u32(data, 0x40)
    export_symbol_table_size = _read_u32(data, 0x44)
    export_symbol_names_offset = _read_u32(data, 0x48)
    import_symbol_table_offset = _read_u32(data, 0x4C)
    import_symbol_table_size = _read_u32(data, 0x50)
    import_symbol_names_offset = _read_u32(data, 0x54)

    header = RsoHeader(
        num_sections=num_sections,
        section_info_offset=section_info_offset,
        name_offset=name_offset,
        name_size=name_size,
        version=version,
        bss_size=bss_size,
        prolog_section=prolog_section,
        epilog_section=epilog_section,
        unresolved_section=unresolved_section,
        bss_section=bss_section,
        prolog_offset=prolog_offset,
        epilog_offset=epilog_offset,
        unresolved_offset=unresolved_offset,
        internal_rel_offset=internal_rel_offset,
        internal_rel_size=internal_rel_size,
        external_rel_offset=external_rel_offset,
        external_rel_size=external_rel_size,
        export_symbol_table_offset=export_symbol_table_offset,
        export_symbol_table_size=export_symbol_table_size,
        export_symbol_names_offset=export_symbol_names_offset,
        import_symbol_table_offset=import_symbol_table_offset,
        import_symbol_table_size=import_symbol_table_size,
        import_symbol_names_offset=import_symbol_names_offset,
    )

    if section_info_offset + num_sections * 8 > len(data):
        raise RsoParseError("RSO section table out of bounds")

    sections: list[RsoSection] = []
    for i in range(num_sections):
        base = section_info_offset + i * 8
        offs = _read_u32(data, base)
        size = _read_u32(data, base + 4)
        sections.append(RsoSection(offset=offs, size=size))

    internal_relocs: list[RsoRelocation] = []
    external_relocs: list[RsoRelocation] = []
    for rel_offset, rel_size, target in (
        (internal_rel_offset, internal_rel_size, internal_relocs),
        (external_rel_offset, external_rel_size, external_relocs),
    ):
        if rel_offset + rel_size > len(data):
            continue
        count = rel_size // 12
        for i in range(count):
            base = rel_offset + i * 12
            offset = _read_u32(data, base)
            info = _read_u32(data, base + 4)
            addend = _read_u32(data, base + 8)
            target.append(RsoRelocation(offset=offset, info=info, addend=addend))

    exports: list[RsoExport] = []
    if export_symbol_table_offset + export_symbol_table_size <= len(data):
        count = export_symbol_table_size // 16
        for i in range(count):
            base = export_symbol_table_offset + i * 16
            str_off = _read_u32(data, base)
            value = _read_u32(data, base + 4)
            section = _read_u32(data, base + 8)
            name = _read_str(data, export_symbol_names_offset + str_off)
            exports.append(RsoExport(name=name, value=value, section=section))

    imports: list[RsoImport] = []
    if import_symbol_table_offset + import_symbol_table_size <= len(data):
        count = import_symbol_table_size // 12
        for i in range(count):
            base = import_symbol_table_offset + i * 12
            str_off = _read_u32(data, base)
            rel_offset = _read_u32(data, base + 8)
            name = _read_str(data, import_symbol_names_offset + str_off)
            imports.append(RsoImport(name=name, rel_offset=rel_offset))

    return RsoModule(
        name=name,
        header=header,
        sections=sections,
        internal_relocs=internal_relocs,
        external_relocs=external_relocs,
        exports=exports,
        imports=imports,
        data=data,
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


def _translate_physical(
    rso: RsoModule, physical: int, sections: list[RsoSection]
) -> int:
    for idx, sec in enumerate(rso.sections):
        if sec.size == 0 or sec.offset == 0:
            continue
        start = sec.offset
        end = start + sec.size
        if physical >= start and physical < end:
            offset = physical - start
            return sections[idx].addr + offset
    raise RsoParseError(f"RSO relocation target out of range: 0x{physical:X}")


def apply_rso_relocations(
    bv: "BinaryView",
    rso: RsoModule,
    runtime_sections: list[RsoSection],
    external_base: int,
) -> None:
    from binaryninja import log_info

    if bv.file.has_database:
        return

    applied = 0

    # External relocations
    import_count = len(rso.imports)
    for imp_index, imp in enumerate(rso.imports):
        imported_addr = external_base + imp_index * 4
        rel_index = imp.rel_offset // 12
        while rel_index < len(rso.external_relocs):
            rel = rso.external_relocs[rel_index]
            rel_index += 1
            if imp_index != rel.section_index:
                break
            _apply_rso_relocation(bv, rso, rel, imported_addr, runtime_sections)
            applied += 1

    # Internal relocations
    for rel in rso.internal_relocs:
        if rel.section_index >= len(runtime_sections):
            continue
        section_addr = runtime_sections[rel.section_index].addr
        _apply_rso_relocation(bv, rso, rel, section_addr, runtime_sections)
        applied += 1

    if applied:
        log_info(f"[WII RSO] applied {applied} relocations for module {rso.name}")


def _apply_rso_relocation(
    bv: BinaryView,
    rso: RsoModule,
    rel: RsoRelocation,
    addr_base: int,
    runtime_sections: list[RsoSection],
) -> None:
    target_addr = _translate_physical(rso, rel.offset, runtime_sections)
    address_value = (addr_base + rel.addend) & 0xFFFFFFFF

    original = _read_be32(bv, target_addr)
    rtype = rel.relocation_type

    if rtype == R_PPC_ADDR16_HA:
        value = (address_value >> 16) & 0xFFFF
        if address_value & 0x8000:
            value = (value + 1) & 0xFFFF
        _write_be16(bv, target_addr, value)
    elif rtype == R_PPC_ADDR24:
        value = (address_value & 0x3FFFFFC) | (original & 0xFC000003)
        _write_be32(bv, target_addr, value)
    elif rtype == R_PPC_ADDR32:
        _write_be32(bv, target_addr, address_value)
    elif rtype in (R_PPC_ADDR16, R_PPC_ADDR16_LO):
        _write_be16(bv, target_addr, address_value & 0xFFFF)
    elif rtype == R_PPC_ADDR16_HI:
        _write_be16(bv, target_addr, (address_value >> 16) & 0xFFFF)
    elif rtype == R_PPC_NONE:
        return
    elif rtype == R_PPC_REL24:
        value = ((address_value - target_addr) & 0x3FFFFFC) | (original & 0xFC000003)
        _write_be32(bv, target_addr, value)
    elif rtype in (R_PPC_ADDR14, R_PPC_ADDR14_BRNTAKEN, R_PPC_ADDR14_BRTAKEN):
        value = (address_value & 0xFFFC) | (original & 0xFFFF0003)
        _write_be32(bv, target_addr, value)
    elif rtype in (R_PPC_REL14, R_PPC_REL14_BRNTAKEN, R_PPC_REL14_BRTAKEN):
        value = ((address_value - target_addr) & 0xFFFC) | (original & 0xFFFF0003)
        _write_be32(bv, target_addr, value)
