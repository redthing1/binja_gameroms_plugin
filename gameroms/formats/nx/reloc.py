from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Callable

from .dynamic import (
    DT_JMPREL,
    DT_PLTRELSZ,
    DT_REL,
    DT_RELA,
    DT_RELASZ,
    DT_RELSZ,
    DT_RELR,
    DT_RELRSZ,
    DynamicEntry,
    dynamic_first,
)

R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE = 1027

R_ARM_ABS32 = 2
R_ARM_GLOB_DAT = 21
R_ARM_JUMP_SLOT = 22
R_ARM_RELATIVE = 23


@dataclass(frozen=True)
class Relocation:
    offset: int
    r_type: int
    sym_index: int
    addend: int


@dataclass(frozen=True)
class RelocationBundle:
    relocs: list[Relocation]
    plt_relocs: list[Relocation]
    relr_offsets: list[int]


class RelocationParseError(RuntimeError):
    pass


def _to_offset(value: int, base_addr: int, image_len: int) -> int:
    if 0 <= value < image_len:
        return value
    if base_addr and value >= base_addr and (value - base_addr) < image_len:
        return value - base_addr
    return value


def _parse_rel(
    image: bytes,
    rel_offset: int,
    rel_size: int,
    base_addr: int,
    is_aarch32: bool,
) -> list[Relocation]:
    relocs: list[Relocation] = []
    if rel_offset is None or rel_size <= 0:
        return relocs

    rel_off = _to_offset(rel_offset, base_addr, len(image))
    if rel_off < 0 or rel_off + rel_size > len(image):
        raise RelocationParseError("REL table outside image")

    entry_size = 0x8 if is_aarch32 else 0x10
    count = rel_size // entry_size
    for i in range(count):
        off = rel_off + i * entry_size
        if is_aarch32:
            r_offset, r_info = struct.unpack_from("<II", image, off)
            r_offset = _to_offset(r_offset, base_addr, len(image))
            r_type = r_info & 0xFF
            r_sym = r_info >> 8
            relocs.append(Relocation(r_offset, r_type, r_sym, 0))
        else:
            r_offset, r_info = struct.unpack_from("<QQ", image, off)
            r_offset = _to_offset(r_offset, base_addr, len(image))
            r_type = r_info & 0xFFFFFFFF
            r_sym = r_info >> 32
            relocs.append(Relocation(r_offset, r_type, r_sym, 0))
    return relocs


def _parse_rela(
    image: bytes,
    rela_offset: int,
    rela_size: int,
    base_addr: int,
    is_aarch32: bool,
) -> list[Relocation]:
    relocs: list[Relocation] = []
    if rela_offset is None or rela_size <= 0:
        return relocs

    rela_off = _to_offset(rela_offset, base_addr, len(image))
    if rela_off < 0 or rela_off + rela_size > len(image):
        raise RelocationParseError("RELA table outside image")

    entry_size = 0xC if is_aarch32 else 0x18
    count = rela_size // entry_size
    for i in range(count):
        off = rela_off + i * entry_size
        if is_aarch32:
            r_offset, r_info, r_addend = struct.unpack_from("<III", image, off)
            r_offset = _to_offset(r_offset, base_addr, len(image))
            r_type = r_info & 0xFF
            r_sym = r_info >> 8
        else:
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", image, off)
            r_offset = _to_offset(r_offset, base_addr, len(image))
            r_type = r_info & 0xFFFFFFFF
            r_sym = r_info >> 32
        relocs.append(Relocation(r_offset, r_type, r_sym, r_addend))
    return relocs


def _parse_relr(
    image: bytes,
    relr_offset: int,
    relr_size: int,
    base_addr: int,
) -> list[int]:
    relr_offsets: list[int] = []
    if relr_offset is None or relr_size <= 0:
        return relr_offsets
    relr_off = _to_offset(relr_offset, base_addr, len(image))
    if relr_off < 0 or relr_off + relr_size > len(image):
        raise RelocationParseError("RELR table outside image")

    reloc_size = 8
    entry_count = relr_size // reloc_size
    where = 0
    for i in range(entry_count):
        entry = struct.unpack_from("<Q", image, relr_off + i * reloc_size)[0]
        if entry & 1:
            entry >>= 1
            bit = 0
            while bit < (reloc_size * 8) - 1:
                if entry & (1 << bit):
                    relr_offsets.append(where + bit * reloc_size)
                bit += 1
            where += reloc_size * ((reloc_size * 8) - 1)
        else:
            where = _to_offset(entry, base_addr, len(image))
            relr_offsets.append(where)
            where += reloc_size
    return relr_offsets


def parse_relocations(
    image: bytes,
    entries: list[DynamicEntry],
    base_addr: int,
    is_aarch32: bool,
) -> RelocationBundle:
    rel_offset = dynamic_first(entries, DT_REL)
    rel_size = dynamic_first(entries, DT_RELSZ, 0) or 0
    rela_offset = dynamic_first(entries, DT_RELA)
    rela_size = dynamic_first(entries, DT_RELASZ, 0) or 0
    jmprel_offset = dynamic_first(entries, DT_JMPREL)
    jmprel_size = dynamic_first(entries, DT_PLTRELSZ, 0) or 0
    relr_offset = dynamic_first(entries, DT_RELR)
    relr_size = dynamic_first(entries, DT_RELRSZ, 0) or 0

    relocs = []
    relocs.extend(_parse_rel(image, rel_offset, rel_size, base_addr, is_aarch32))
    relocs.extend(_parse_rela(image, rela_offset, rela_size, base_addr, is_aarch32))
    # JMPREL can be REL or RELA depending on arch; use RELA for aarch64, REL for aarch32
    if is_aarch32:
        plt_relocs = _parse_rel(
            image, jmprel_offset, jmprel_size, base_addr, is_aarch32
        )
    else:
        plt_relocs = _parse_rela(
            image, jmprel_offset, jmprel_size, base_addr, is_aarch32
        )

    relr_offsets = _parse_relr(image, relr_offset, relr_size, base_addr)

    return RelocationBundle(
        relocs=relocs, plt_relocs=plt_relocs, relr_offsets=relr_offsets
    )


def apply_relocations(
    bv,
    relocs: RelocationBundle,
    resolve_symbol: Callable[[int], int | None],
    base_addr: int,
    is_aarch32: bool,
) -> None:
    # Apply REL/RELA
    for reloc in relocs.relocs + relocs.plt_relocs:
        addr = base_addr + reloc.offset
        if is_aarch32:
            if reloc.r_type == R_ARM_RELATIVE:
                original = int.from_bytes(bv.read(addr, 4), "little")
                bv.write(
                    addr,
                    (original + base_addr).to_bytes(4, "little"),
                    except_on_relocation=False,
                )
            elif reloc.r_type in (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT, R_ARM_ABS32):
                sym_val = resolve_symbol(reloc.sym_index)
                if sym_val is None:
                    continue
                bv.write(
                    addr, int(sym_val).to_bytes(4, "little"), except_on_relocation=False
                )
        else:
            if reloc.r_type == R_AARCH64_RELATIVE:
                bv.write(
                    addr,
                    int(base_addr + reloc.addend).to_bytes(8, "little", signed=False),
                    except_on_relocation=False,
                )
            elif reloc.r_type in (
                R_AARCH64_GLOB_DAT,
                R_AARCH64_JUMP_SLOT,
                R_AARCH64_ABS64,
            ):
                sym_val = resolve_symbol(reloc.sym_index)
                if sym_val is None:
                    continue
                value = int(sym_val + reloc.addend)
                bv.write(
                    addr,
                    value.to_bytes(8, "little", signed=False),
                    except_on_relocation=False,
                )

    # Apply RELR (aarch64)
    if not is_aarch32:
        for off in relocs.relr_offsets:
            addr = base_addr + off
            original = int.from_bytes(bv.read(addr, 8), "little")
            bv.write(
                addr,
                int(base_addr + original).to_bytes(8, "little", signed=False),
                except_on_relocation=False,
            )
