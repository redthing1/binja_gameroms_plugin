from __future__ import annotations

from dataclasses import dataclass

from binaryninja import BinaryView, log_error

GBA_FIXED_VALUE_OFFSET = 0xB2
GBA_FIXED_VALUE = 0x96
GBA_HEADER_MIN_SIZE = 0xC0


@dataclass(frozen=True)
class GbaHeader:
    rom_size: int


def is_valid_gba(data: BinaryView) -> bool:
    if data.length < GBA_HEADER_MIN_SIZE:
        return False
    try:
        magic = data.read(GBA_FIXED_VALUE_OFFSET, 1)
        if len(magic) != 1:
            return False
        return magic[0] == GBA_FIXED_VALUE
    except Exception as exc:
        log_error(f"[GBA] validation error: {exc}")
        return False


def parse_header(data: BinaryView) -> GbaHeader:
    return GbaHeader(rom_size=data.length)
