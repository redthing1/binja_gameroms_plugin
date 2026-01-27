from __future__ import annotations

from binaryninja import Architecture, Symbol, SymbolType, log_error

from ...core.tags import add_tag
from ...core.view_base import BaseRomView
from .layout import gba_regions
from .mmio import gba_mmio_registers
from .parse import is_valid_gba, parse_header


class GbaView(BaseRomView):
    name = "GBA"
    long_name = "Game Boy Advance ROM"

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        return is_valid_gba(data)

    def init(self) -> bool:
        try:
            self.arch = Architecture["armv7"]
            self.platform = self.arch.standalone_platform
            header = parse_header(self.raw)
            regions = gba_regions(header)
            self.map_regions(regions)
            for region in regions:
                add_tag(self, region.vaddr, "Region", region.name)
                if region.section_type == "MMIO":
                    add_tag(self, region.vaddr, "MMIO", region.name)
            self.define_mmio_registers(gba_mmio_registers())
            self._entry_point = 0x08000000
            self.add_entry_point(self._entry_point, self.platform)
            self.define_auto_symbol_and_var_or_function(
                Symbol(SymbolType.FunctionSymbol, self._entry_point, "gba_entry"),
                plat=self.platform,
            )
            add_tag(self, self._entry_point, "Entry", "gba_entry")
            return True
        except Exception as exc:
            log_error(f"[GBA] init failed: {exc}")
            return False


GbaView.register()
