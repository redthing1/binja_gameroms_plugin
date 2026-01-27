from __future__ import annotations

from binaryninja import (
    Architecture,
    SegmentFlag,
    SectionSemantics,
    Symbol,
    SymbolType,
    log_error,
)

from ...core.tags import add_tag
from ...core.view_base import BaseRomView
from ...core.regions import RegionSpec
from .decompress import mii_uncompress_backward
from .mmio import nds_mmio_registers
from .parse import (
    NdsOverlayEntry,
    NdsOverlayTable,
    NdsRom,
    is_valid_nds,
    parse_module_params,
    read_nds,
)


def nds_common_regions() -> list[RegionSpec]:
    rw = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    regions: list[RegionSpec] = []
    regions.append(
        RegionSpec(
            name="Main RAM",
            vaddr=0x02000000,
            length=0x00400000,
            flags=rw,
            section=".wram",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="Shared WRAM",
            vaddr=0x03000000,
            length=0x00008000,
            flags=rw,
            section=".wram.shared",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="ARM7 WRAM",
            vaddr=0x03800000,
            length=0x00010000,
            flags=rw,
            section=".wram.arm7",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="IO",
            vaddr=0x04000000,
            length=0x00001000,
            flags=rw,
            section=".io",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        )
    )
    regions.append(
        RegionSpec(
            name="IO-IPC",
            vaddr=0x04100000,
            length=0x00000020,
            flags=rw,
            section=".io.ipc",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        )
    )
    regions.append(
        RegionSpec(
            name="Wifi",
            vaddr=0x04800000,
            length=0x00008000,
            flags=rw,
            section=".wifi",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="MMIO",
        )
    )
    regions.append(
        RegionSpec(
            name="Palette",
            vaddr=0x05000000,
            length=0x00000800,
            flags=rw,
            section=".palette",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="VRAM",
            vaddr=0x06000000,
            length=0x000A4000,
            flags=rw,
            section=".vram",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="VRAM LCDC",
            vaddr=0x06800000,
            length=0x000A4000,
            flags=rw,
            section=".vram.lcdc",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    regions.append(
        RegionSpec(
            name="OAM",
            vaddr=0x07000000,
            length=0x00000800,
            flags=rw,
            section=".oam",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    return regions


class NdsViewBase(BaseRomView):
    cpu_name = "ARM9"

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        return is_valid_nds(data)

    def init(self) -> bool:
        try:
            self.arch = Architecture["armv7"]
            self.platform = self.arch.standalone_platform
            nds = read_nds(self.raw)
            if nds is None:
                return False
            self._map_common_memory()
            self._map_main_binary(nds)
            self._map_overlays(nds)
            self.define_mmio_registers(nds_mmio_registers())
            return True
        except Exception as exc:
            log_error(f"[NDS {self.cpu_name}] init failed: {exc}")
            return False

    def _map_common_memory(self) -> None:
        regions = nds_common_regions()
        self.map_regions(regions)
        for region in regions:
            add_tag(self, region.vaddr, "Region", region.name)
            if region.section_type == "MMIO":
                add_tag(self, region.vaddr, "MMIO", region.name)

    def _map_main_binary(self, nds: NdsRom) -> None:
        header = nds.header
        if self.cpu_name == "ARM9":
            rom_offset = header.arm9_rom_offset
            rom_size = header.arm9_size
            load_addr = header.arm9_ram_address
            entry = header.arm9_entry_address
        else:
            rom_offset = header.arm7_rom_offset
            rom_size = header.arm7_size
            load_addr = header.arm7_ram_address
            entry = header.arm7_entry_address

        if rom_size == 0:
            return

        raw_data = self.raw.read(rom_offset, rom_size)
        if len(raw_data) != rom_size:
            log_error(f"[NDS {self.cpu_name}] failed to read main binary")
            return

        effective_size = rom_size
        decompressed_data: bytes | None = None
        bss_start: int | None = None
        bss_size: int | None = None

        if self.cpu_name == "ARM9":
            module_params = parse_module_params(raw_data)
            if module_params is not None:
                expected_size = module_params.autoload_end_addr - load_addr
                compressed = module_params.compressed_static_end_marker != 0
                if expected_size > 0 and expected_size < rom_size * 25:
                    effective_size = expected_size
                if compressed:
                    try:
                        decompressed_data = mii_uncompress_backward(raw_data)
                        effective_size = len(decompressed_data)
                    except Exception as exc:
                        log_error(f"[NDS ARM9] decompression failed: {exc}")
                        decompressed_data = None
                if module_params.bss_end > module_params.bss_start:
                    candidate_size = module_params.bss_end - module_params.bss_start
                    if (
                        module_params.bss_start >= load_addr
                        and candidate_size < 0x10000000
                    ):
                        bss_start = module_params.bss_start
                        bss_size = candidate_size

        self.add_auto_segment(
            load_addr,
            effective_size,
            rom_offset,
            rom_size,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
        )
        self.add_auto_section(
            name=f".{self.cpu_name.lower()}",
            start=load_addr,
            length=effective_size,
            semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            type="Code",
        )
        self.add_entry_point(entry, self.platform)
        self._entry_point = entry
        entry_name = "nds_arm9_entry" if self.cpu_name == "ARM9" else "nds_arm7_entry"
        self.define_auto_symbol_and_var_or_function(
            Symbol(SymbolType.FunctionSymbol, entry, entry_name),
            plat=self.platform,
        )
        add_tag(self, entry, "Entry", entry_name)
        add_tag(self, load_addr, "Region", f"{self.cpu_name} main code")

        if decompressed_data is not None and not self.file.has_database:
            self.memory_map.add_memory_region(
                f"{self.cpu_name.lower()}_code_decompressed",
                load_addr,
                decompressed_data,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
            )
        if bss_start is not None and bss_size is not None and bss_size > 0:
            self.add_auto_segment(
                bss_start,
                bss_size,
                0,
                0,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            )
            self.add_auto_section(
                name=f".{self.cpu_name.lower()}.bss",
                start=bss_start,
                length=bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="BSS",
            )

    def _map_overlays(self, nds: NdsRom) -> None:
        table = (
            nds.arm9_overlay_table
            if self.cpu_name == "ARM9"
            else nds.arm7_overlay_table
        )
        if table is None:
            return
        if not nds.fat_entries:
            return
        for entry in table.entries:
            self._map_overlay_entry(nds, entry)

    def _map_overlay_entry(self, nds: NdsRom, entry: NdsOverlayEntry) -> None:
        if entry.file_id == 0xFFFF:
            return
        if entry.file_id >= len(nds.fat_entries):
            return

        fat = nds.fat_entries[entry.file_id]
        rom_size = max(0, fat.end_address - fat.start_address)
        raw_data = self.raw.read(fat.start_address, rom_size) if rom_size > 0 else b""

        effective_size = entry.ram_size if entry.ram_size > 0 else rom_size
        decompressed: bytes | None = None

        if entry.is_compressed and raw_data:
            try:
                decompressed = mii_uncompress_backward(raw_data)
                effective_size = len(decompressed)
            except Exception as exc:
                log_error(
                    f"[NDS {self.cpu_name}] overlay {entry.overlay_id} decompression failed: {exc}"
                )

        if effective_size > 0:
            self.add_auto_segment(
                entry.ram_address,
                effective_size,
                fat.start_address,
                rom_size,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
            )
            self.add_auto_section(
                name=f".{self.cpu_name.lower()}.ovl.{entry.overlay_id}",
                start=entry.ram_address,
                length=effective_size,
                semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                type="Overlay",
            )
            add_tag(
                self,
                entry.ram_address,
                "Overlay",
                f"{self.cpu_name} overlay {entry.overlay_id}",
            )

            if decompressed is not None and not self.file.has_database:
                self.memory_map.add_memory_region(
                    f"{self.cpu_name.lower()}_ovl_{entry.overlay_id}",
                    entry.ram_address,
                    decompressed,
                    SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
                )

        if entry.bss_size > 0:
            bss_start = entry.ram_address + effective_size
            self.add_auto_segment(
                bss_start,
                entry.bss_size,
                0,
                0,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            )
            self.add_auto_section(
                name=f".{self.cpu_name.lower()}.ovl.{entry.overlay_id}.bss",
                start=bss_start,
                length=entry.bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="BSS",
            )

        if entry.static_initializer_start_address:
            init_addr = entry.static_initializer_start_address
            sym_name = f"{self.cpu_name.lower()}_overlay_{entry.overlay_id}_init"
            self.define_auto_symbol_and_var_or_function(
                Symbol(SymbolType.FunctionSymbol, init_addr, sym_name),
                plat=self.platform,
            )


class NdsArm9View(NdsViewBase):
    name = "NDS ARM9"
    long_name = "DS ROM (ARM9)"
    cpu_name = "ARM9"


class NdsArm7View(NdsViewBase):
    name = "NDS ARM7"
    long_name = "DS ROM (ARM7)"
    cpu_name = "ARM7"


NdsArm9View.register()
NdsArm7View.register()
