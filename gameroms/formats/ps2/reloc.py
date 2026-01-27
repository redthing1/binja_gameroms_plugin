from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable

from binaryninja import BinaryView, log_info

from .parse import (
    SectionHeader32,
    SHT_REL,
    SHT_RELA,
)

# MIPS relocation types (subset)
R_MIPS_NONE = 0
R_MIPS_16 = 1
R_MIPS_32 = 2
R_MIPS_REL32 = 3
R_MIPS_26 = 4
R_MIPS_HI16 = 5
R_MIPS_LO16 = 6


@dataclass(frozen=True)
class RelocationRel:
    offset: int
    info: int

    @property
    def sym(self) -> int:
        return self.info >> 8

    @property
    def typ(self) -> int:
        return self.info & 0xFF


@dataclass(frozen=True)
class RelocationRela:
    offset: int
    info: int
    addend: int

    @property
    def sym(self) -> int:
        return self.info >> 8

    @property
    def typ(self) -> int:
        return self.info & 0xFF


def _read_relocations_rel(blob: bytes, entsize: int) -> list[RelocationRel]:
    rels: list[RelocationRel] = []
    if entsize < 8:
        return rels
    count = len(blob) // entsize
    for i in range(count):
        base = i * entsize
        try:
            offset, info = struct.unpack_from("<II", blob, base)
        except struct.error:
            break
        rels.append(RelocationRel(offset=offset, info=info))
    return rels


def _read_relocations_rela(blob: bytes, entsize: int) -> list[RelocationRela]:
    rels: list[RelocationRela] = []
    if entsize < 12:
        return rels
    count = len(blob) // entsize
    for i in range(count):
        base = i * entsize
        try:
            offset, info, addend = struct.unpack_from("<III", blob, base)
        except struct.error:
            break
        rels.append(RelocationRela(offset=offset, info=info, addend=addend))
    return rels


def _apply_write32(bv: BinaryView, addr: int, value: int) -> None:
    bv.write(addr, struct.pack("<I", value & 0xFFFFFFFF))


def _apply_write16(bv: BinaryView, addr: int, value: int) -> None:
    bv.write(addr, struct.pack("<H", value & 0xFFFF))


def apply_relocations(
    bv: BinaryView,
    raw: BinaryView,
    sections: list[SectionHeader32],
    symbol_values_by_index: dict[int, dict[int, int]],
) -> None:
    if bv.file.has_database:
        return

    pending_hi16: dict[int, list[tuple[int, int]]] = {}
    unsupported = 0
    applied = 0

    for idx, sh in enumerate(sections):
        if sh.sh_type not in (SHT_REL, SHT_RELA):
            continue
        if sh.sh_offset + sh.sh_size > raw.length or sh.sh_size == 0:
            continue
        entsize = sh.sh_entsize or (12 if sh.sh_type == SHT_RELA else 8)
        blob = raw.read(sh.sh_offset, sh.sh_size)
        if len(blob) != sh.sh_size:
            continue

        target_section = sections[sh.sh_info] if sh.sh_info < len(sections) else None
        base_addr = target_section.sh_addr if target_section is not None else 0

        symbols = symbol_values_by_index.get(sh.sh_link)
        if symbols is None:
            unsupported += 1
            continue

        if sh.sh_type == SHT_RELA:
            rels = _read_relocations_rela(blob, entsize)
        else:
            rels = _read_relocations_rel(blob, entsize)

        for rel in rels:
            sym_value = symbols.get(rel.sym)
            if sym_value is None:
                unsupported += 1
                continue
            reloc_addr = (base_addr + rel.offset) & 0xFFFFFFFF

            if isinstance(rel, RelocationRela):
                addend = rel.addend
            else:
                # For REL, derive addend from existing content where possible.
                try:
                    addend = struct.unpack("<I", bv.read(reloc_addr, 4))[0]
                except Exception:
                    addend = 0

            if rel.typ == R_MIPS_32:
                try:
                    _apply_write32(bv, reloc_addr, sym_value + addend)
                    applied += 1
                except Exception:
                    unsupported += 1
                continue
            if rel.typ == R_MIPS_26:
                try:
                    insn = struct.unpack("<I", bv.read(reloc_addr, 4))[0]
                    if isinstance(rel, RelocationRela):
                        target = (sym_value + addend) >> 2
                    else:
                        field = (insn & 0x03FFFFFF) << 2
                        target = (sym_value + field) >> 2
                    insn = (insn & 0xFC000000) | (target & 0x03FFFFFF)
                    _apply_write32(bv, reloc_addr, insn)
                    applied += 1
                except Exception:
                    unsupported += 1
                continue
            if rel.typ == R_MIPS_HI16:
                try:
                    insn = struct.unpack("<I", bv.read(reloc_addr, 4))[0]
                    imm = insn & 0xFFFF
                    pending_hi16.setdefault(rel.sym, []).append((reloc_addr, imm))
                except Exception:
                    unsupported += 1
                continue
            if rel.typ == R_MIPS_LO16:
                try:
                    insn = struct.unpack("<I", bv.read(reloc_addr, 4))[0]
                    lo = insn & 0xFFFF
                    hi_list = pending_hi16.get(rel.sym, [])
                    if hi_list:
                        hi_addr, hi_imm = hi_list.pop(0)
                        value = (sym_value + ((hi_imm << 16) | lo)) & 0xFFFFFFFF
                        hi = ((value + 0x8000) >> 16) & 0xFFFF
                        lo_fixed = value & 0xFFFF
                        hi_insn = (
                            struct.unpack("<I", bv.read(hi_addr, 4))[0] & 0xFFFF0000
                        ) | hi
                        lo_insn = (insn & 0xFFFF0000) | lo_fixed
                        try:
                            _apply_write32(bv, hi_addr, hi_insn)
                            _apply_write32(bv, reloc_addr, lo_insn)
                            applied += 1
                        except Exception:
                            unsupported += 1
                    else:
                        unsupported += 1
                except Exception:
                    unsupported += 1
                continue

            unsupported += 1

    if applied or unsupported:
        log_info(f"[PS2] relocations applied={applied} unsupported={unsupported}")
