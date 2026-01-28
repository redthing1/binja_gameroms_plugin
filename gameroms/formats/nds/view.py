from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Optional

from binaryninja import (
    Architecture,
    SegmentFlag,
    SectionSemantics,
    Settings,
    Symbol,
    SymbolType,
    log_error,
)

from ...core.tags import add_tag
from ...core.view_base import BaseRomView
from ...core.regions import RegionSpec
from .loader import (
    load_main_binary,
    load_overlay_bytes,
    overlay_effective_size,
    pad_overlay_data,
)
from .mmio import nds_mmio_registers
from .model import NdsImage, NdsOverlayInfo, read_nds_image
from .parse import is_valid_nds

OVERLAY_SETTING_KEY = "loader.nds.overlay"
OVERLAY_SETTING_GROUP = "loader.nds"
OVERLAY_SETTING_GROUP_TITLE = "NDS"


@dataclass(frozen=True)
class OverlaySelection:
    entry: NdsOverlayInfo
    data: bytes
    size: int


def _root_view(view):
    root = view
    while getattr(root, "parent_view", None) is not None:
        root = root.parent_view
    return root


def nds_common_regions() -> list[RegionSpec]:
    rw_data = (
        SegmentFlag.SegmentReadable
        | SegmentFlag.SegmentWritable
        | SegmentFlag.SegmentContainsData
    )
    regions: list[RegionSpec] = []
    regions.append(
        RegionSpec(
            name="Main RAM",
            vaddr=0x02000000,
            length=0x00400000,
            flags=rw_data,
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
            flags=rw_data,
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
            flags=rw_data,
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
            flags=rw_data,
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
            flags=rw_data,
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
            flags=rw_data,
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
            flags=rw_data,
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
            flags=rw_data,
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
            flags=rw_data,
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
            flags=rw_data,
            section=".oam",
            section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            section_type="RAM",
        )
    )
    return regions


def _resolve_arch(cpu_name: str) -> Architecture | None:
    if cpu_name == "ARM9":
        candidates = ["armv5t", "armv5te", "armv5tej", "armv5", "armv7"]
    else:
        candidates = ["armv4t", "armv4", "armv5t", "armv5te", "armv5tej", "armv7"]
    for name in candidates:
        try:
            return Architecture[name]
        except KeyError:
            continue
    log_error(f"[NDS {cpu_name}] failed to resolve architecture")
    return None


def _resolve_thumb_arch() -> Architecture | None:
    for name in ("thumb2", "thumb2eb"):
        try:
            return Architecture[name]
        except KeyError:
            continue
    return None


def _platform_for_address(addr: int, arm_platform, thumb_platform) -> object:
    if addr & 1 and thumb_platform is not None:
        return thumb_platform
    return arm_platform


def _strip_thumb_bit(addr: int) -> int:
    return addr & ~1


def _split_range(
    base: int, size: int, hole: Optional[tuple[int, int]]
) -> list[tuple[int, int]]:
    if size <= 0:
        return []
    if hole is None:
        return [(base, size)]
    hole_start, hole_end = hole
    end = base + size
    if hole_end <= base or hole_start >= end:
        return [(base, size)]
    segments: list[tuple[int, int]] = []
    if hole_start > base:
        segments.append((base, hole_start - base))
    if hole_end < end:
        segments.append((hole_end, end - hole_end))
    return segments


def _overlay_choices(overlays: list[NdsOverlayInfo]) -> tuple[list[str], list[str]]:
    overlay_ids = sorted({ovl.overlay_id for ovl in overlays})
    choices = ["none"] + [str(oid) for oid in overlay_ids]
    descs = ["No overlay mapped at runtime addresses"]
    by_id: dict[int, NdsOverlayInfo] = {ovl.overlay_id: ovl for ovl in overlays}
    for oid in overlay_ids:
        ovl = by_id[oid]
        size = ovl.ram_size if ovl.ram_size > 0 else ovl.file_size
        comp = "compressed" if ovl.is_compressed else "raw"
        descs.append(
            f"ram=0x{ovl.ram_address:08x} size=0x{size:x} file_id={ovl.file_id} {comp}"
        )
    return choices, descs


def _load_settings_with_defaults(cls, data):
    registered_view = cls.registered_view_type
    if registered_view is not None:
        try:
            parsed = registered_view.parse(data)
        except Exception:
            parsed = None
        if parsed is not None:
            try:
                return registered_view.get_default_load_settings_for_data(parsed)
            except Exception:
                pass
    if registered_view is not None:
        try:
            return registered_view.get_default_load_settings_for_data(data)
        except Exception:
            pass
    return Settings("nds_load_settings")


class NdsViewBase(BaseRomView):
    cpu_name = "ARM9"

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        return is_valid_nds(data)

    @classmethod
    def get_load_settings_for_data(cls, data):
        load_settings = _load_settings_with_defaults(cls, data)
        load_settings.register_group(OVERLAY_SETTING_GROUP, OVERLAY_SETTING_GROUP_TITLE)

        overlays: list[NdsOverlayInfo] = []
        try:
            raw = _root_view(data)
            image = read_nds_image(raw)
            if image is not None:
                overlays = (
                    image.arm9_overlays
                    if cls.cpu_name == "ARM9"
                    else image.arm7_overlays
                )
        except Exception:
            overlays = []

        choices, descs = _overlay_choices(overlays)
        props = {
            "title": "Overlay",
            "type": "string",
            "default": "none",
            "description": "Select a single overlay to map at runtime addresses.",
            "optional": True,
            "enum": choices,
            "enumDescriptions": descs,
        }

        if not load_settings.contains(OVERLAY_SETTING_KEY):
            load_settings.register_setting(OVERLAY_SETTING_KEY, json.dumps(props))
        load_settings.update_property(OVERLAY_SETTING_KEY, json.dumps(props))
        return load_settings

    def init(self) -> bool:
        try:
            arch = _resolve_arch(self.cpu_name)
            if arch is None:
                return False
            thumb_arch = _resolve_thumb_arch()
            self.arch = arch
            self.platform = self.arch.standalone_platform
            self._thumb_platform = (
                thumb_arch.standalone_platform if thumb_arch is not None else None
            )

            image = read_nds_image(self.raw)
            if image is None:
                return False

            self._map_common_memory()

            selection = self._select_overlay(image)
            overlay_range = None
            if selection is not None:
                overlay_range = (
                    selection.entry.ram_address,
                    selection.entry.ram_address + selection.size,
                )

            self._map_main_binary(image, overlay_range)

            if selection is not None:
                self._map_overlay(selection)

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

    def _get_overlay_choice(self) -> Optional[int]:
        load_settings = self.get_load_settings(self.name)
        if load_settings is None:
            return None
        if not load_settings.contains(OVERLAY_SETTING_KEY):
            return None
        choice = load_settings.get_string(OVERLAY_SETTING_KEY, self)
        if not choice or choice == "none":
            return None
        try:
            return int(choice, 10)
        except ValueError:
            return None

    def _select_overlay(self, image: NdsImage) -> Optional[OverlaySelection]:
        overlay_id = self._get_overlay_choice()
        if overlay_id is None:
            return None
        overlays = (
            image.arm9_overlays if self.cpu_name == "ARM9" else image.arm7_overlays
        )
        entry = None
        for ovl in overlays:
            if ovl.overlay_id == overlay_id:
                entry = ovl
                break
        if entry is None:
            return None
        data = load_overlay_bytes(image, entry)
        size = overlay_effective_size(entry, data)
        if size <= 0:
            return None
        return OverlaySelection(entry=entry, data=data, size=size)

    def _map_segment(
        self,
        name: str,
        addr: int,
        size: int,
        file_offset: int,
        file_len: int,
        flags: SegmentFlag,
        section_name: str,
        section_semantics: SectionSemantics,
        section_type: str,
        data: Optional[bytes] = None,
    ) -> None:
        if size <= 0:
            return
        self.add_auto_segment(addr, size, file_offset, file_len, flags)
        self.add_auto_section(
            name=section_name,
            start=addr,
            length=size,
            semantics=section_semantics,
            type=section_type,
        )
        if data and not self.file.has_database:
            self.memory_map.add_memory_region(name, addr, data, flags)

    def _map_main_binary(
        self, image: NdsImage, overlay_range: Optional[tuple[int, int]]
    ) -> None:
        loaded = load_main_binary(image, self.cpu_name)
        if loaded is None:
            return

        exec_flags = (
            SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentWritable
            | SegmentFlag.SegmentExecutable
            | SegmentFlag.SegmentContainsCode
            | SegmentFlag.SegmentContainsData
        )

        segments = _split_range(loaded.load_addr, loaded.effective_size, overlay_range)
        for idx, (seg_addr, seg_size) in enumerate(segments):
            file_offset = 0
            file_len = 0
            data = None
            if loaded.decompressed:
                data_offset = seg_addr - loaded.load_addr
                data = loaded.data[data_offset : data_offset + seg_size]
            else:
                file_offset = loaded.rom_offset + (seg_addr - loaded.load_addr)
                file_end = loaded.rom_offset + loaded.rom_size
                file_len = max(0, min(file_end, file_offset + seg_size) - file_offset)

            section_name = f".{self.cpu_name.lower()}"
            if len(segments) > 1:
                section_name = f"{section_name}.part{idx}"
            region_name = f"{self.cpu_name.lower()}_main_{idx}"
            self._map_segment(
                region_name,
                seg_addr,
                seg_size,
                file_offset,
                file_len,
                exec_flags,
                section_name,
                SectionSemantics.ReadWriteDataSectionSemantics,
                "RAM",
                data,
            )

        entry_addr = _strip_thumb_bit(loaded.entry)
        entry_platform = _platform_for_address(
            loaded.entry, self.platform, getattr(self, "_thumb_platform", None)
        )
        self.add_entry_point(entry_addr, entry_platform)
        self._entry_point = entry_addr
        entry_name = "nds_arm9_entry" if self.cpu_name == "ARM9" else "nds_arm7_entry"
        self.define_auto_symbol_and_var_or_function(
            Symbol(SymbolType.FunctionSymbol, entry_addr, entry_name),
            plat=entry_platform,
        )
        add_tag(self, entry_addr, "Entry", entry_name)
        add_tag(self, loaded.load_addr, "Region", f"{self.cpu_name} main")

        if loaded.bss_start is not None and loaded.bss_size is not None:
            bss_segments = _split_range(
                loaded.bss_start, loaded.bss_size, overlay_range
            )
            for idx, (bss_addr, bss_size) in enumerate(bss_segments):
                section_name = f".{self.cpu_name.lower()}.bss"
                if len(bss_segments) > 1:
                    section_name = f"{section_name}.part{idx}"
                region_name = f"{self.cpu_name.lower()}_bss_{idx}"
                bss_flags = (
                    SegmentFlag.SegmentReadable
                    | SegmentFlag.SegmentWritable
                    | SegmentFlag.SegmentContainsData
                )
                self._map_segment(
                    region_name,
                    bss_addr,
                    bss_size,
                    0,
                    0,
                    bss_flags,
                    section_name,
                    SectionSemantics.ReadWriteDataSectionSemantics,
                    "BSS",
                    None,
                )

    def _map_overlay(self, selection: OverlaySelection) -> None:
        entry = selection.entry
        data = selection.data
        size = selection.size
        overlay_addr = entry.ram_address
        overlay_end = overlay_addr + size

        overlay_flags = (
            SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentWritable
            | SegmentFlag.SegmentExecutable
            | SegmentFlag.SegmentContainsCode
            | SegmentFlag.SegmentContainsData
        )

        file_offset = 0
        file_len = 0
        data_region = None
        if entry.is_compressed:
            data_region = pad_overlay_data(data, size)
        else:
            file_len = min(entry.file_size, size)
            file_offset = entry.file_start
            if entry.file_size < size:
                data_region = pad_overlay_data(data, size)

        self._map_segment(
            f"{self.cpu_name.lower()}_ovl_{entry.overlay_id}",
            overlay_addr,
            size,
            file_offset,
            file_len,
            overlay_flags,
            f".{self.cpu_name.lower()}.ovl.{entry.overlay_id}",
            SectionSemantics.ReadWriteDataSectionSemantics,
            "Overlay",
            data_region,
        )

        self.define_auto_symbol(
            Symbol(
                SymbolType.DataSymbol,
                overlay_addr,
                f"{self.cpu_name.lower()}_overlay_{entry.overlay_id}",
            )
        )
        add_tag(
            self,
            overlay_addr,
            "Overlay",
            f"{self.cpu_name} overlay {entry.overlay_id}",
        )
        self.set_comment_at(
            overlay_addr,
            (
                f"Overlay {entry.overlay_id} file_id={entry.file_id} "
                f"ram=0x{entry.ram_address:08x} size=0x{size:x} "
                f"compressed={entry.is_compressed}"
            ),
        )

        if entry.static_initializer_start_address:
            init_addr = entry.static_initializer_start_address
            init_addr_stripped = _strip_thumb_bit(init_addr)
            if overlay_addr <= init_addr_stripped < overlay_end:
                init_platform = _platform_for_address(
                    init_addr,
                    self.platform,
                    getattr(self, "_thumb_platform", None),
                )
                self.add_entry_point(init_addr_stripped, init_platform)
                self.define_auto_symbol_and_var_or_function(
                    Symbol(
                        SymbolType.FunctionSymbol,
                        init_addr_stripped,
                        f"{self.cpu_name.lower()}_overlay_{entry.overlay_id}_init",
                    ),
                    plat=init_platform,
                )

        if entry.bss_size > 0:
            bss_flags = (
                SegmentFlag.SegmentReadable
                | SegmentFlag.SegmentWritable
                | SegmentFlag.SegmentContainsData
            )
            bss_start = overlay_end
            self._map_segment(
                f"{self.cpu_name.lower()}_ovl_{entry.overlay_id}_bss",
                bss_start,
                entry.bss_size,
                0,
                0,
                bss_flags,
                f".{self.cpu_name.lower()}.ovl.{entry.overlay_id}.bss",
                SectionSemantics.ReadWriteDataSectionSemantics,
                "BSS",
                None,
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
