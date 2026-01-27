from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from binaryninja import BinaryView, Type, log_error

from .regions import RegionSpec, apply_regions


@dataclass(frozen=True)
class MmioRegister:
    addr: int
    name: str
    width: int
    description: str = ""


class BaseRomView(BinaryView):
    def __init__(self, data: BinaryView):
        root = data
        while root.parent_view is not None:
            root = root.parent_view
        # ensure file-offset reads use the raw/root view even if a parent view is ELF/PE
        BinaryView.__init__(self, parent_view=root, file_metadata=root.file)
        self.raw = root
        self._entry_point = 0

    def map_regions(self, regions: Iterable[RegionSpec]) -> None:
        apply_regions(self, regions)

    def define_mmio_register(self, reg: MmioRegister) -> None:
        try:
            if reg.width in (1, 2, 4, 8):
                reg_type = Type.int(reg.width, sign=False)
            else:
                reg_type = Type.array(Type.int(1, sign=False), reg.width)
            self.define_data_var(reg.addr, reg_type, reg.name)
            if reg.description:
                self.set_comment_at(reg.addr, reg.description)
        except Exception as exc:
            log_error(
                f"failed to define MMIO register {reg.name} at 0x{reg.addr:08x}: {exc}"
            )

    def define_mmio_registers(self, regs: Iterable[MmioRegister]) -> None:
        for reg in regs:
            self.define_mmio_register(reg)

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_entry_point(self) -> int:
        return self._entry_point

    def perform_get_address_size(self) -> int:
        return self.arch.address_size if self.arch is not None else 4
