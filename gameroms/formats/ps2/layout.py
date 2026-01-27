from __future__ import annotations

from binaryninja import SectionSemantics, SegmentFlag

from ...core.regions import RegionSpec


def ps2_ee_regions() -> list[RegionSpec]:
    rw = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    rx = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable

    return [
        RegionSpec(
            name="EE Main RAM",
            vaddr=0x00000000,
            length=0x02000000,
            flags=rw,
            section=None,
        ),
        RegionSpec(
            name="EE Main RAM (uncached)",
            vaddr=0x20000000,
            length=0x02000000,
            flags=rw,
            section=None,
        ),
        RegionSpec(
            name="EE Main RAM (uncached accelerated)",
            vaddr=0x30100000,
            length=0x01F00000,
            flags=rw,
            section=None,
        ),
        RegionSpec(
            name="EE I/O Registers",
            vaddr=0x10000000,
            length=0x00010000,
            flags=rw,
            section=".ee.mmio",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        ),
        RegionSpec(
            name="VU0 Code Memory",
            vaddr=0x11000000,
            length=0x00001000,
            flags=rw,
            section=".vu0.code",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="VU",
        ),
        RegionSpec(
            name="VU0 Data Memory",
            vaddr=0x11004000,
            length=0x00001000,
            flags=rw,
            section=".vu0.data",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="VU",
        ),
        RegionSpec(
            name="VU1 Code Memory",
            vaddr=0x11008000,
            length=0x00004000,
            flags=rw,
            section=".vu1.code",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="VU",
        ),
        RegionSpec(
            name="VU1 Data Memory",
            vaddr=0x1100C000,
            length=0x00004000,
            flags=rw,
            section=".vu1.data",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="VU",
        ),
        RegionSpec(
            name="GS Privileged Registers",
            vaddr=0x12000000,
            length=0x00002000,
            flags=rw,
            section=".gs.mmio",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        ),
        RegionSpec(
            name="IOP RAM (mapped into EE)",
            vaddr=0x1C000000,
            length=0x00200000,
            flags=rw,
            section=None,
        ),
        RegionSpec(
            name="EE BIOS ROM",
            vaddr=0x1FC00000,
            length=0x00400000,
            flags=rx,
            section=".ee.bios",
            section_semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            section_type="ROM",
        ),
        RegionSpec(
            name="EE BIOS ROM (cached alias)",
            vaddr=0x9FC00000,
            length=0x00400000,
            flags=rx,
            section=".ee.bios.cached",
            section_semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            section_type="ROM",
        ),
        RegionSpec(
            name="EE BIOS ROM (uncached alias)",
            vaddr=0xBFC00000,
            length=0x00400000,
            flags=rx,
            section=".ee.bios.uc",
            section_semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            section_type="ROM",
        ),
        RegionSpec(
            name="Scratchpad RAM",
            vaddr=0x70000000,
            length=0x00004000,
            flags=rw,
            section=".ee.scratchpad",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        ),
    ]


def ps2_iop_regions() -> list[RegionSpec]:
    rw = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    rx = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable

    return [
        RegionSpec(
            name="IOP Main RAM",
            vaddr=0x00000000,
            length=0x00200000,
            flags=rw,
            section=None,
        ),
        RegionSpec(
            name="IOP Main RAM (KSEG0 alias)",
            vaddr=0x80000000,
            length=0x00200000,
            flags=rw,
            section=None,
        ),
        RegionSpec(
            name="IOP Main RAM (KSEG1 alias)",
            vaddr=0xA0000000,
            length=0x00200000,
            flags=rw,
            section=None,
        ),
        RegionSpec(
            name="IOP I/O Registers",
            vaddr=0x1F800000,
            length=0x00010000,
            flags=rw,
            section=".iop.mmio",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        ),
        RegionSpec(
            name="IOP SIF Registers",
            vaddr=0x1D000000,
            length=0x00010000,
            flags=rw,
            section=".iop.sif",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        ),
        RegionSpec(
            name="IOP SPU2 Registers",
            vaddr=0x1F900000,
            length=0x00000400,
            flags=rw,
            section=".iop.spu2",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        ),
        RegionSpec(
            name="IOP BIOS ROM",
            vaddr=0x1FC00000,
            length=0x00400000,
            flags=rx,
            section=".iop.bios",
            section_semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            section_type="ROM",
        ),
        RegionSpec(
            name="IOP BIOS ROM (cached alias)",
            vaddr=0x9FC00000,
            length=0x00400000,
            flags=rx,
            section=".iop.bios.cached",
            section_semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            section_type="ROM",
        ),
        RegionSpec(
            name="IOP BIOS ROM (uncached alias)",
            vaddr=0xBFC00000,
            length=0x00400000,
            flags=rx,
            section=".iop.bios.uc",
            section_semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            section_type="ROM",
        ),
    ]
