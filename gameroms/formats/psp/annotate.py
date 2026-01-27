from __future__ import annotations

import struct
from typing import Iterable

from binaryninja import (
    BinaryView,
    BinaryViewType,
    SectionSemantics,
    SegmentFlag,
    Symbol,
    SymbolType,
    Type,
    log_error,
    log_info,
)

from ...core.tags import add_tag
from .mmio import psp_mmio_registers

ELF_HEADER_SIZE = 52
EI_MAG0 = 0
EI_MAG1 = 1
EI_MAG2 = 2
EI_MAG3 = 3
EI_CLASS = 4
EI_DATA = 5
ELFCLASS32 = 1
ELFDATA2LSB = 1
EM_MIPS = 8


class PspRegion:
    def __init__(
        self,
        name: str,
        start: int,
        length: int,
        flags: SegmentFlag,
        section: str,
        semantics: SectionSemantics,
        section_type: str,
    ):
        self.name = name
        self.start = start
        self.length = length
        self.flags = flags
        self.section = section
        self.semantics = semantics
        self.section_type = section_type


def _is_psp_elf(bv: BinaryView) -> bool:
    if bv.view_type != "ELF":
        return False
    if bv.arch is None or "mips" not in bv.arch.name:
        return False
    raw = bv.parent_view or bv
    if raw.length < ELF_HEADER_SIZE:
        return False
    header = raw.read(0, ELF_HEADER_SIZE)
    if len(header) < ELF_HEADER_SIZE:
        return False
    if not (
        header[EI_MAG0] == 0x7F
        and header[EI_MAG1] == ord("E")
        and header[EI_MAG2] == ord("L")
        and header[EI_MAG3] == ord("F")
    ):
        return False
    if header[EI_CLASS] != ELFCLASS32:
        return False
    if header[EI_DATA] != ELFDATA2LSB:
        return False
    try:
        e_machine = struct.unpack_from("<H", header, 18)[0]
    except struct.error:
        return False
    if e_machine != EM_MIPS:
        return False
    for section_name in bv.sections:
        if section_name in (".sceModuleInfo", ".rodata.sceModuleInfo"):
            return True
    if bv.get_symbol_by_name("sceModuleInfo"):
        return True
    return False


def _segments_overlap(bv: BinaryView, start: int, length: int) -> bool:
    end = start + length
    for seg in bv.segments:
        try:
            seg_start = seg.start
            seg_end = seg.start + seg.length
        except Exception:
            return False
        if seg_start < end and seg_end > start:
            return True
    return False


def _add_region(bv: BinaryView, region: PspRegion) -> None:
    if region.section in bv.sections:
        return
    if _segments_overlap(bv, region.start, region.length):
        # If a segment already covers this area, add a section for labeling.
        if bv.get_segment_at(region.start) is not None:
            bv.add_user_section(
                name=region.section,
                start=region.start,
                length=region.length,
                semantics=region.semantics,
                type=region.section_type,
            )
        return
    bv.add_user_segment(region.start, region.length, 0, 0, region.flags)
    bv.add_user_section(
        name=region.section,
        start=region.start,
        length=region.length,
        semantics=region.semantics,
        type=region.section_type,
    )


def _add_mmio_symbols(bv: BinaryView) -> None:
    for reg in psp_mmio_registers():
        if bv.get_symbol_at(reg.addr) is not None:
            continue
        try:
            reg_type = Type.int(reg.width, sign=False)
            bv.define_data_var(reg.addr, reg_type, reg.name)
            if reg.description:
                bv.set_comment_at(reg.addr, reg.description)
        except Exception as exc:
            log_error(
                f"[PSP] failed to define MMIO {reg.name} at 0x{reg.addr:08x}: {exc}"
            )


def annotate_psp_elf(bv: BinaryView) -> None:
    if bv.view_type != "ELF":
        return
    if not _is_psp_elf(bv):
        return

    log_info("[PSP] applying PSP annotations")

    rw = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    rx = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable

    regions = [
        PspRegion(
            name="Scratchpad",
            start=0x00010000,
            length=0x00004000,
            flags=rw,
            section=".scratchpad",
            semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        ),
        PspRegion(
            name="VRAM",
            start=0x04000000,
            length=0x00200000,
            flags=rw,
            section=".vram",
            semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        ),
        PspRegion(
            name="Main RAM",
            start=0x08000000,
            length=0x02000000,
            flags=rw,
            section=".ram",
            semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        ),
        PspRegion(
            name="IO Block 1",
            start=0x1C000000,
            length=0x01000000,
            flags=rw,
            section=".mmio.1c",
            semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        ),
        PspRegion(
            name="IO Block 2",
            start=0x1D000000,
            length=0x02000000,
            flags=rw,
            section=".mmio.1d",
            semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        ),
        PspRegion(
            name="IO Block 3",
            start=0x1F000000,
            length=0x00C00000,
            flags=rw,
            section=".mmio.1f",
            semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        ),
        PspRegion(
            name="NAND DMA Buffers",
            start=0x1FF00000,
            length=0x00000A00,
            flags=rw,
            section=".nand",
            semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        ),
        PspRegion(
            name="Boot ROM Vectors",
            start=0xBFC00000,
            length=0x00004000,
            flags=rx,
            section=".bootrom",
            semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            section_type="ROM",
        ),
    ]

    for region in regions:
        _add_region(bv, region)
        add_tag(bv, region.start, "Region", region.name)
        if region.section_type == "MMIO":
            add_tag(bv, region.start, "MMIO", region.name)

    # Exception vector symbols
    if bv.get_symbol_at(0xBFC00000) is None:
        bv.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, 0xBFC00000, "Reset_Vector")
        )
    if bv.get_symbol_at(0xBFC00180) is None:
        bv.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, 0xBFC00180, "General_Exception_Vector")
        )
    add_tag(bv, 0xBFC00000, "Vector", "Reset_Vector")
    add_tag(bv, 0xBFC00180, "Vector", "General_Exception_Vector")

    entry = bv.entry_point
    if entry is not None:
        add_tag(bv, entry, "Entry", "psp_entry")

    _add_mmio_symbols(bv)


def register_psp_hooks() -> None:
    global _PSP_HOOK_REGISTERED
    if _PSP_HOOK_REGISTERED:
        return
    BinaryViewType.add_binaryview_finalized_event(_PSP_CALLBACK)
    _PSP_HOOK_REGISTERED = True


_PSP_CALLBACK = annotate_psp_elf
_PSP_HOOK_REGISTERED = False
