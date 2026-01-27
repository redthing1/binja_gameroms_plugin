from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List

TEXT_SECTION_COUNT = 7
DATA_SECTION_COUNT = 11

TEXT_NAMES = [
    ".init",
    ".text",
    ".text1",
    ".text2",
    ".text3",
    ".text4",
    ".text5",
]

DATA_NAMES = [
    "extab",
    "extabindex",
    ".ctors",
    ".dtors",
    ".rodata",
    ".data",
    ".sdata",
    ".sdata2",
    ".bss",
    ".sbss",
    ".sbss2",
]

DOL_HEADER_SIZE = 0x100


@dataclass(frozen=True)
class DolSection:
    index: int
    offset: int
    addr: int
    size: int
    is_text: bool

    @property
    def name(self) -> str:
        if self.is_text:
            base = (
                TEXT_NAMES[self.index]
                if self.index < len(TEXT_NAMES)
                else f".text{self.index}"
            )
            return f"MAIN_{base}"
        base = (
            DATA_NAMES[self.index]
            if self.index < len(DATA_NAMES)
            else f".data{self.index}"
        )
        return f"MAIN_{base}"


@dataclass(frozen=True)
class DolInfo:
    sections: List[DolSection]
    bss_addr: int
    bss_size: int
    entry_point: int

    @property
    def max_end(self) -> int:
        end = self.bss_addr + self.bss_size if self.bss_size else 0
        for sec in self.sections:
            if sec.size:
                end = max(end, sec.addr + sec.size)
        return end


class DolParseError(RuntimeError):
    pass


def parse_dol(data: bytes) -> DolInfo:
    if len(data) < DOL_HEADER_SIZE:
        raise DolParseError("DOL file too small")

    # Header layout is big-endian u32 arrays
    off = 0

    def _read_u32(count: int) -> list[int]:
        nonlocal off
        size = 4 * count
        if off + size > len(data):
            raise DolParseError("DOL header truncated")
        values = list(struct.unpack_from(">" + "I" * count, data, off))
        off += size
        return values

    text_offsets = _read_u32(TEXT_SECTION_COUNT)
    data_offsets = _read_u32(DATA_SECTION_COUNT)
    text_addrs = _read_u32(TEXT_SECTION_COUNT)
    data_addrs = _read_u32(DATA_SECTION_COUNT)
    text_sizes = _read_u32(TEXT_SECTION_COUNT)
    data_sizes = _read_u32(DATA_SECTION_COUNT)

    bss_addr = struct.unpack_from(">I", data, off)[0]
    off += 4
    bss_size = struct.unpack_from(">I", data, off)[0]
    off += 4
    entry_point = struct.unpack_from(">I", data, off)[0]

    sections: list[DolSection] = []
    for i in range(TEXT_SECTION_COUNT):
        sections.append(
            DolSection(
                index=i,
                offset=text_offsets[i],
                addr=text_addrs[i],
                size=text_sizes[i],
                is_text=True,
            )
        )
    for i in range(DATA_SECTION_COUNT):
        sections.append(
            DolSection(
                index=i,
                offset=data_offsets[i],
                addr=data_addrs[i],
                size=data_sizes[i],
                is_text=False,
            )
        )

    return DolInfo(
        sections=sections,
        bss_addr=bss_addr,
        bss_size=bss_size,
        entry_point=entry_point,
    )
