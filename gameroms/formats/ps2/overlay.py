from __future__ import annotations

import struct
from typing import Optional

from binaryninja import BinaryView, SectionSemantics, SegmentFlag, log_error

from ...core.tags import add_tag
from .parse import SectionHeader32, SHF_EXECINSTR, SHF_WRITE, SHT_STRTAB

DVP_OVERLAY_TABLE = ".DVP.ovlytab"
DVP_OVERLAY_STRTAB = ".DVP.ovlystrtab"
VU1_TEXT_ADDRESS = 0x11008000
VU1_DATA_ADDRESS = 0x1100C000


def _read_cstring(blob: bytes, off: int) -> str:
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end == -1:
        end = len(blob)
    try:
        return blob[off:end].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _find_section_index(names: list[str], name: str) -> Optional[int]:
    for idx, candidate in enumerate(names):
        if candidate == name:
            return idx
    return None


def _map_overlay_segment(
    bv: BinaryView,
    raw: BinaryView,
    name: str,
    addr: int,
    size: int,
    file_offset: int,
    flags: SegmentFlag,
) -> None:
    if size <= 0:
        return
    seg = bv.get_segment_at(addr)
    if seg is None:
        bv.add_auto_segment(addr, size, file_offset, size, flags)
    elif seg.data_length == 0 and not bv.file.has_database:
        if file_offset + size <= raw.length:
            data = raw.read(file_offset, size)
            if data:
                bv.memory_map.add_memory_region(name, addr, data, flags)
    bv.add_auto_section(
        name=name,
        start=addr,
        length=size,
        semantics=SectionSemantics.ReadWriteDataSectionSemantics,
        type="Overlay",
    )


def apply_vu_sections(
    bv: BinaryView, raw: BinaryView, sections: list[SectionHeader32], names: list[str]
) -> None:
    for idx, sh in enumerate(sections):
        if idx >= len(names):
            continue
        name = names[idx]
        if name not in (".vutext", ".vudata"):
            continue
        base = VU1_TEXT_ADDRESS if name == ".vutext" else VU1_DATA_ADDRESS
        addr = base
        if sh.sh_offset + sh.sh_size > raw.length or sh.sh_size == 0:
            continue
        perms = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
        _map_overlay_segment(
            bv,
            raw,
            f"{name}_overlay",
            addr,
            sh.sh_size,
            sh.sh_offset,
            perms,
        )
        add_tag(bv, addr, "Overlay", name)


def apply_dvp_overlays(
    bv: BinaryView, raw: BinaryView, sections: list[SectionHeader32], names: list[str]
) -> None:
    tab_idx = _find_section_index(names, DVP_OVERLAY_TABLE)
    str_idx = _find_section_index(names, DVP_OVERLAY_STRTAB)
    if tab_idx is None or str_idx is None:
        apply_vu_sections(bv, raw, sections, names)
        return

    tab = sections[tab_idx]
    strtab = sections[str_idx]
    if tab.sh_size == 0 or strtab.sh_size == 0:
        apply_vu_sections(bv, raw, sections, names)
        return
    if tab.sh_offset + tab.sh_size > raw.length:
        return
    if strtab.sh_type != SHT_STRTAB or strtab.sh_offset + strtab.sh_size > raw.length:
        return

    tab_blob = raw.read(tab.sh_offset, tab.sh_size)
    str_blob = raw.read(strtab.sh_offset, strtab.sh_size)
    if len(tab_blob) != tab.sh_size or len(str_blob) != strtab.sh_size:
        return

    entry_size = 12
    count = len(tab_blob) // entry_size
    for i in range(count):
        base = i * entry_size
        try:
            name_off, lma, vma = struct.unpack_from("<III", tab_blob, base)
        except struct.error:
            break
        sec_name = _read_cstring(str_blob, name_off)
        if not sec_name:
            continue
        sec_idx = _find_section_index(names, sec_name)
        if sec_idx is None:
            continue
        sh = sections[sec_idx]
        overlay_base = (
            VU1_TEXT_ADDRESS if (sh.sh_flags & SHF_EXECINSTR) else VU1_DATA_ADDRESS
        )
        overlay_addr = (overlay_base + (vma & 0xFFFFFFFF)) & 0xFFFFFFFF
        perms = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable

        if sh.sh_offset + sh.sh_size <= raw.length and sh.sh_size > 0:
            _map_overlay_segment(
                bv,
                raw,
                f"{sec_name}_overlay",
                overlay_addr,
                sh.sh_size,
                sh.sh_offset,
                perms,
            )
        else:
            # Fallback: copy bytes from mapped address (LMA) into a memory region.
            if not bv.file.has_database and sh.sh_size > 0:
                try:
                    data = bv.read(lma, sh.sh_size)
                    if data:
                        bv.memory_map.add_memory_region(
                            f"{sec_name}_overlay",
                            overlay_addr,
                            data,
                            perms,
                        )
                except Exception as exc:
                    log_error(f"[PS2] overlay {sec_name} copy failed: {exc}")
        add_tag(bv, overlay_addr, "Overlay", sec_name)
