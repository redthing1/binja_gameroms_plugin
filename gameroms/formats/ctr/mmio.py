from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from binaryninja import SectionSemantics, SegmentFlag

from ...core.regions import RegionSpec
from ...core.view_base import MmioRegister
from .mmio_data import MMIO_REGISTERS


def ctr_mmio_registers() -> list[MmioRegister]:
    regs: list[MmioRegister] = []
    for item in MMIO_REGISTERS:
        regs.append(
            MmioRegister(
                addr=item["address"],
                name=item["name"],
                width=item["width"],
                description=item.get("description", ""),
            )
        )
    return regs


def _sanitize_section_name(name: str) -> str:
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9]+", "_", name)
    name = name.strip("_")
    return name or "mmio"


def ctr_mmio_regions() -> list[RegionSpec]:
    groups: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for item in MMIO_REGISTERS:
        groups[item.get("group", "MMIO")].append((item["address"], item["width"]))

    regions: list[RegionSpec] = []
    flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    for group, entries in sorted(groups.items()):
        min_addr = min(addr for addr, _ in entries)
        max_addr = max(addr + width for addr, width in entries)
        start = min_addr & ~0xFFF
        end = (max_addr + 0xFFF) & ~0xFFF
        length = max(0x1000, end - start)
        section_name = f".io.{_sanitize_section_name(group)}"
        regions.append(
            RegionSpec(
                name=f"{group} MMIO",
                vaddr=start,
                length=length,
                flags=flags,
                section=section_name,
                section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                section_type="MMIO",
            )
        )
    return regions
