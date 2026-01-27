from __future__ import annotations

import json
import struct

from binaryninja import (
    Architecture,
    SectionSemantics,
    SegmentFlag,
    Symbol,
    SymbolType,
    log_error,
)

from ...core.tags import add_tag
from ...core.view_base import BaseRomView
from .mmio import ctr_mmio_regions, ctr_mmio_registers

CXIEXE_MAGIC = b"CXIEXE\x00\x00"
CXIEXE_HEADER_STRUCT = struct.Struct("<8sIIII")
CXIEXE_VERSION = 1


class CtrCxiExeView(BaseRomView):
    name = "3DS CXI"
    long_name = "3DS CXI Executable"

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        header = data.read(0, CXIEXE_HEADER_STRUCT.size)
        if len(header) != CXIEXE_HEADER_STRUCT.size:
            return False
        magic, version, _, _, _ = CXIEXE_HEADER_STRUCT.unpack(header)
        return magic == CXIEXE_MAGIC and version == CXIEXE_VERSION

    def init(self) -> bool:
        try:
            self.arch = Architecture["armv7"]
            self.platform = self.arch.standalone_platform

            header = self.raw.read(0, CXIEXE_HEADER_STRUCT.size)
            magic, version, json_len, blob_len, _ = CXIEXE_HEADER_STRUCT.unpack(header)
            if magic != CXIEXE_MAGIC or version != CXIEXE_VERSION:
                return False

            meta_bytes = self.raw.read(CXIEXE_HEADER_STRUCT.size, json_len)
            meta = json.loads(meta_bytes.decode("utf-8"))
            blob_offset = CXIEXE_HEADER_STRUCT.size + json_len

            text_addr = int(meta["text_addr"])
            text_size = int(meta["text_size"])
            ro_addr = int(meta["rodata_addr"])
            ro_size = int(meta["rodata_size"])
            data_addr = int(meta["data_addr"])
            data_size = int(meta["data_size"])
            bss_addr = int(meta["bss_addr"])
            bss_size = int(meta["bss_size"])

            text_off = int(meta["text_offset"])
            ro_off = int(meta["rodata_offset"])
            data_off = int(meta["data_offset"])

            entry = int(meta.get("entry", text_addr))

            self.add_auto_segment(
                text_addr,
                text_size,
                blob_offset + text_off,
                text_size,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
            )
            self.add_auto_section(
                name=".text",
                start=text_addr,
                length=text_size,
                semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                type="Code",
            )
            add_tag(self, text_addr, "Region", "CXI .text")

            if ro_size:
                self.add_auto_segment(
                    ro_addr,
                    ro_size,
                    blob_offset + ro_off,
                    ro_size,
                    SegmentFlag.SegmentReadable,
                )
                self.add_auto_section(
                    name=".rodata",
                    start=ro_addr,
                    length=ro_size,
                    semantics=SectionSemantics.ReadOnlyDataSectionSemantics,
                    type="Data",
                )
                add_tag(self, ro_addr, "Region", "CXI .rodata")

            if data_size:
                self.add_auto_segment(
                    data_addr,
                    data_size,
                    blob_offset + data_off,
                    data_size,
                    SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
                )
                self.add_auto_section(
                    name=".data",
                    start=data_addr,
                    length=data_size,
                    semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                    type="Data",
                )
                add_tag(self, data_addr, "Region", "CXI .data")

            if bss_size:
                self.add_auto_segment(
                    bss_addr,
                    bss_size,
                    0,
                    0,
                    SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
                )
                self.add_auto_section(
                    name=".bss",
                    start=bss_addr,
                    length=bss_size,
                    semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                    type="BSS",
                )
                add_tag(self, bss_addr, "Region", "CXI .bss")

            self._entry_point = entry
            self.add_entry_point(entry, self.platform)
            self.define_auto_symbol_and_var_or_function(
                Symbol(SymbolType.FunctionSymbol, entry, "ctr_entry"),
                plat=self.platform,
            )
            add_tag(self, entry, "Entry", "ctr_entry")

            mmio_regions = ctr_mmio_regions()
            self.map_regions(mmio_regions)
            for region in mmio_regions:
                add_tag(self, region.vaddr, "Region", region.name)
                add_tag(self, region.vaddr, "MMIO", region.name)
            self.define_mmio_registers(ctr_mmio_registers())

            return True
        except Exception as exc:
            log_error(f"[3DS CXI] init failed: {exc}")
            return False


CtrCxiExeView.register()
