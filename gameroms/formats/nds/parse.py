from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import Optional

from binaryninja import BinaryView, log_error

NDS_HEADER_SIZE = 0x160

NITRO_SDK_MODULE_PARAMS_MAGIC = b"\x21\x06\xc0\xde\xde\xc0\x06\x21"
NITRO_SDK_MODULE_PARAMS_SIZE = 36
NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET = 0x1C


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for ch in data:
        crc ^= ch
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


@dataclass(frozen=True)
class NdsHeader:
    arm9_rom_offset: int
    arm9_entry_address: int
    arm9_ram_address: int
    arm9_size: int
    arm7_rom_offset: int
    arm7_entry_address: int
    arm7_ram_address: int
    arm7_size: int
    fnt_offset: int
    fnt_size: int
    fat_offset: int
    fat_size: int
    arm9_overlay_offset: int
    arm9_overlay_size: int
    arm7_overlay_offset: int
    arm7_overlay_size: int
    arm9_bss_size: int = 0
    arm7_bss_size: int = 0


@dataclass(frozen=True)
class NdsOverlayEntry:
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


@dataclass(frozen=True)
class NdsOverlayTable:
    entries: list[NdsOverlayEntry] = field(default_factory=list)


@dataclass(frozen=True)
class NdsFatEntry:
    start_address: int
    end_address: int


@dataclass(frozen=True)
class NdsRom:
    header: NdsHeader
    arm9_overlay_table: Optional[NdsOverlayTable]
    arm7_overlay_table: Optional[NdsOverlayTable]
    fat_entries: list[NdsFatEntry]


@dataclass(frozen=True)
class ModuleParamsInfo:
    autoload_end_addr: int
    compressed_static_end_marker: int
    bss_start: int
    bss_end: int


def is_valid_nds(data: BinaryView) -> bool:
    header = data.read(0, NDS_HEADER_SIZE)
    if len(header) < NDS_HEADER_SIZE:
        return False
    try:
        logo_crc = struct.unpack_from("<H", header, 0x15C)[0]
        header_crc = struct.unpack_from("<H", header, 0x15E)[0]
    except struct.error:
        return False
    return logo_crc == crc16(header[0xC0:0x15C]) and header_crc == crc16(
        header[0:0x15E]
    )


def parse_header(data: BinaryView) -> Optional[NdsHeader]:
    header = data.read(0, 0x200)
    if len(header) < NDS_HEADER_SIZE:
        return None
    try:
        return NdsHeader(
            arm9_rom_offset=struct.unpack_from("<I", header, 0x20)[0],
            arm9_entry_address=struct.unpack_from("<I", header, 0x24)[0],
            arm9_ram_address=struct.unpack_from("<I", header, 0x28)[0],
            arm9_size=struct.unpack_from("<I", header, 0x2C)[0],
            arm7_rom_offset=struct.unpack_from("<I", header, 0x30)[0],
            arm7_entry_address=struct.unpack_from("<I", header, 0x34)[0],
            arm7_ram_address=struct.unpack_from("<I", header, 0x38)[0],
            arm7_size=struct.unpack_from("<I", header, 0x3C)[0],
            fnt_offset=struct.unpack_from("<I", header, 0x40)[0],
            fnt_size=struct.unpack_from("<I", header, 0x44)[0],
            fat_offset=struct.unpack_from("<I", header, 0x48)[0],
            fat_size=struct.unpack_from("<I", header, 0x4C)[0],
            arm9_overlay_offset=struct.unpack_from("<I", header, 0x50)[0],
            arm9_overlay_size=struct.unpack_from("<I", header, 0x54)[0],
            arm7_overlay_offset=struct.unpack_from("<I", header, 0x58)[0],
            arm7_overlay_size=struct.unpack_from("<I", header, 0x5C)[0],
        )
    except struct.error as exc:
        log_error(f"[NDS] header parse failed: {exc}")
        return None


def read_overlay_table(
    raw: BinaryView, offset: int, size: int
) -> Optional[NdsOverlayTable]:
    if offset == 0 or size == 0:
        return None
    if offset + size > raw.length:
        log_error(f"[NDS] overlay table out of bounds (0x{offset:x}+0x{size:x})")
        return None
    data = raw.read(offset, size)
    return parse_overlay_table(data)


def parse_overlay_table(data: bytes) -> Optional[NdsOverlayTable]:
    entry_size = 0x20
    if len(data) < entry_size:
        return None
    entries: list[NdsOverlayEntry] = []
    num_entries = len(data) // entry_size
    for i in range(num_entries):
        base = i * entry_size
        try:
            flags = struct.unpack_from("<I", data, base + 28)[0]
            flag_byte = (flags >> 24) & 0xFF
            compressed_offset = flags & 0x00FFFFFF
            entries.append(
                NdsOverlayEntry(
                    overlay_id=struct.unpack_from("<I", data, base + 0)[0],
                    ram_address=struct.unpack_from("<I", data, base + 4)[0],
                    ram_size=struct.unpack_from("<I", data, base + 8)[0],
                    bss_size=struct.unpack_from("<I", data, base + 12)[0],
                    static_initializer_start_address=struct.unpack_from(
                        "<I", data, base + 16
                    )[0],
                    static_initializer_end_address=struct.unpack_from(
                        "<I", data, base + 20
                    )[0],
                    file_id=struct.unpack_from("<I", data, base + 24)[0],
                    flags=flags,
                    compressed_offset=compressed_offset,
                    is_compressed=bool(flag_byte & 0x1),
                    has_auth_code=bool(flag_byte & 0x2),
                )
            )
        except struct.error as exc:
            log_error(f"[NDS] overlay entry parse failed at index {i}: {exc}")
            return None
    return NdsOverlayTable(entries=entries)


def read_fat(raw: BinaryView, offset: int, size: int) -> list[NdsFatEntry]:
    if offset == 0 or size == 0:
        return []
    if offset + size > raw.length:
        log_error(f"[NDS] FAT out of bounds (0x{offset:x}+0x{size:x})")
        return []
    data = raw.read(offset, size)
    entries: list[NdsFatEntry] = []
    entry_size = 8
    num_entries = len(data) // entry_size
    for i in range(num_entries):
        base = i * entry_size
        try:
            start = struct.unpack_from("<I", data, base)[0]
            end = struct.unpack_from("<I", data, base + 4)[0]
            entries.append(NdsFatEntry(start_address=start, end_address=end))
        except struct.error as exc:
            log_error(f"[NDS] FAT parse failed at index {i}: {exc}")
            break
    return entries


def read_nds(raw: BinaryView) -> Optional[NdsRom]:
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
    return NdsRom(
        header=header,
        arm9_overlay_table=arm9_ovt,
        arm7_overlay_table=arm7_ovt,
        fat_entries=fat_entries,
    )


def find_module_params(data: bytes) -> Optional[int]:
    idx = data.find(NITRO_SDK_MODULE_PARAMS_MAGIC)
    if idx == -1:
        return None
    start = idx - NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET
    if start < 0:
        return None
    if start + NITRO_SDK_MODULE_PARAMS_SIZE > len(data):
        return None
    return start


def parse_module_params(data: bytes) -> Optional[ModuleParamsInfo]:
    offset = find_module_params(data)
    if offset is None:
        return None
    try:
        autoload_end = struct.unpack_from("<I", data, offset + 8)[0]
        bss_start = struct.unpack_from("<I", data, offset + 12)[0]
        bss_end = struct.unpack_from("<I", data, offset + 16)[0]
        compressed_static_end = struct.unpack_from("<I", data, offset + 20)[0]
        return ModuleParamsInfo(
            autoload_end_addr=autoload_end,
            compressed_static_end_marker=compressed_static_end,
            bss_start=bss_start,
            bss_end=bss_end,
        )
    except struct.error:
        return None
