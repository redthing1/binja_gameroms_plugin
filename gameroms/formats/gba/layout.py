from __future__ import annotations

from binaryninja import SegmentFlag, SectionSemantics

from ...core.regions import RegionSpec
from .parse import GbaHeader


def gba_regions(header: GbaHeader) -> list[RegionSpec]:
    rom_size = header.rom_size
    regions: list[RegionSpec] = []

    regions.append(
        RegionSpec(
            name="BIOS",
            vaddr=0x00000000,
            length=0x00004000,
            flags=SegmentFlag.SegmentReadable,
            section=".bios",
            section_semantics=SectionSemantics.ReadOnlyDataSectionSemantics,
            section_type="BIOS",
        )
    )
    regions.append(
        RegionSpec(
            name="EWRAM",
            vaddr=0x02000000,
            length=0x00040000,
            flags=SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            section=".ewram",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="IWRAM",
            vaddr=0x03000000,
            length=0x00008000,
            flags=SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            section=".iwram",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="IO",
            vaddr=0x04000000,
            length=0x00000400,
            flags=SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            section=".io",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        )
    )
    regions.append(
        RegionSpec(
            name="Palette RAM",
            vaddr=0x05000000,
            length=0x00000400,
            flags=SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            section=".palette",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="VRAM",
            vaddr=0x06000000,
            length=0x00018000,
            flags=SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            section=".vram",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="OAM",
            vaddr=0x07000000,
            length=0x00000400,
            flags=SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            section=".oam",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="ROM",
            vaddr=0x08000000,
            length=rom_size,
            flags=SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
            file_offset=0,
            file_length=rom_size,
            section=".text",
            section_semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            section_type="ROM",
        )
    )
    regions.append(
        RegionSpec(
            name="SRAM",
            vaddr=0x0E000000,
            length=0x00010000,
            flags=SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            section=".sram",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )

    return regions
