from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from binaryninja import BinaryView, log_error

from .parse import (
    NdsHeader,
    NdsOverlayEntry,
    NdsOverlayTable,
    NdsFatEntry,
    parse_header,
    read_overlay_table,
    read_fat,
)


@dataclass(frozen=True)
class NdsBinary:
    rom_offset: int
    rom_size: int
    ram_address: int
    entry_address: int


@dataclass(frozen=True)
class NdsOverlayInfo:
    overlay_id: int
    ram_address: int
    ram_size: int
    bss_size: int
    static_initializer_start_address: int
    static_initializer_end_address: int
    file_id: int
    flags: int
    compressed_offset: int
    is_compressed: bool
    has_auth_code: bool
    file_start: int
    file_end: int

    @property
    def file_size(self) -> int:
        return max(0, self.file_end - self.file_start)


@dataclass(frozen=True)
class NdsImage:
    raw: BinaryView
    header: NdsHeader
    arm9: NdsBinary
    arm7: NdsBinary
    arm9_overlays: list[NdsOverlayInfo]
    arm7_overlays: list[NdsOverlayInfo]
    fat_entries: list[NdsFatEntry]


def _build_overlay_infos(
    raw: BinaryView,
    table: Optional[NdsOverlayTable],
    fat_entries: list[NdsFatEntry],
    label: str,
) -> list[NdsOverlayInfo]:
    overlays: list[NdsOverlayInfo] = []
    if table is None:
        return overlays
    for entry in table.entries:
        if entry.file_id == 0xFFFF:
            continue
        if entry.file_id >= len(fat_entries):
            log_error(
                f"[NDS] {label} overlay file_id out of FAT bounds: {entry.file_id}"
            )
            continue
        fat = fat_entries[entry.file_id]
        overlays.append(
            NdsOverlayInfo(
                overlay_id=entry.overlay_id,
                ram_address=entry.ram_address,
                ram_size=entry.ram_size,
                bss_size=entry.bss_size,
                static_initializer_start_address=entry.static_initializer_start_address,
                static_initializer_end_address=entry.static_initializer_end_address,
                file_id=entry.file_id,
                flags=entry.flags,
                compressed_offset=entry.compressed_offset,
                is_compressed=entry.is_compressed,
                has_auth_code=entry.has_auth_code,
                file_start=fat.start_address,
                file_end=fat.end_address,
            )
        )
    return overlays


def read_nds_image(raw: BinaryView) -> Optional[NdsImage]:
    header = parse_header(raw)
    if header is None:
        return None

    arm9_ovt = read_overlay_table(
        raw, header.arm9_overlay_offset, header.arm9_overlay_size
    )
    arm7_ovt = read_overlay_table(
        raw, header.arm7_overlay_offset, header.arm7_overlay_size
    )
    fat_entries = read_fat(raw, header.fat_offset, header.fat_size)

    arm9 = NdsBinary(
        rom_offset=header.arm9_rom_offset,
        rom_size=header.arm9_size,
        ram_address=header.arm9_ram_address,
        entry_address=header.arm9_entry_address,
    )
    arm7 = NdsBinary(
        rom_offset=header.arm7_rom_offset,
        rom_size=header.arm7_size,
        ram_address=header.arm7_ram_address,
        entry_address=header.arm7_entry_address,
    )

    arm9_overlays = _build_overlay_infos(raw, arm9_ovt, fat_entries, "ARM9")
    arm7_overlays = _build_overlay_infos(raw, arm7_ovt, fat_entries, "ARM7")

    return NdsImage(
        raw=raw,
        header=header,
        arm9=arm9,
        arm7=arm7,
        arm9_overlays=arm9_overlays,
        arm7_overlays=arm7_overlays,
        fat_entries=fat_entries,
    )
