from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from binaryninja import BinaryView, SectionSemantics, SegmentFlag


@dataclass(frozen=True)
class RegionSpec:
    name: str
    vaddr: int
    length: int
    flags: SegmentFlag
    file_offset: int = 0
    file_length: int = 0
    section: Optional[str] = None
    section_semantics: Optional[SectionSemantics] = None
    section_type: str = ""


def apply_regions(bv: BinaryView, regions: Iterable[RegionSpec]) -> None:
    for region in regions:
        bv.add_auto_segment(
            region.vaddr,
            region.length,
            region.file_offset,
            region.file_length,
            region.flags,
        )
        if region.section:
            bv.add_auto_section(
                name=region.section,
                start=region.vaddr,
                length=region.length,
                semantics=region.section_semantics
                if region.section_semantics is not None
                else SectionSemantics.DefaultSectionSemantics,
                type=region.section_type,
            )
