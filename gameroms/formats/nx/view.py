from __future__ import annotations

import json
import struct

from binaryninja import (
    Architecture,
    SectionSemantics,
    SegmentFlag,
    Symbol,
    SymbolType,
    Type,
    log_error,
)

from ...core.tags import add_tag
from ...core.view_base import BaseRomView
from .constants import NXEXE_HEADER_STRUCT, NXEXE_MAGIC, NXEXE_VERSION
from .dynamic import (
    DT_FINI_ARRAY,
    DT_FINI_ARRAYSZ,
    DT_GNU_HASH,
    DT_HASH,
    DT_INIT_ARRAY,
    DT_INIT_ARRAYSZ,
    DT_JMPREL,
    DT_PLTGOT,
    DT_PLTRELSZ,
    DT_RELA,
    DT_RELASZ,
    DT_REL,
    DT_RELR,
    DT_RELRSZ,
    DT_RELSZ,
    DT_STRTAB,
    DT_STRSZ,
    DT_SYMENT,
    DT_SYMTAB,
    DynamicEntry,
    STT_FUNC,
    STT_OBJECT,
    STT_SECTION,
    dynamic_first,
    parse_dynamic_table,
    parse_dynstr,
    parse_dynsym,
    symbol_table_size,
)
from .mod0 import Mod0ParseError, parse_mod0
from .reloc import RelocationBundle, apply_relocations, parse_relocations


class SwitchNxExeView(BaseRomView):
    name = "Switch NXEXE"
    long_name = "Switch NX Executable"

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        header = data.read(0, NXEXE_HEADER_STRUCT.size)
        if len(header) != NXEXE_HEADER_STRUCT.size:
            return False
        magic, version, _, _, _ = NXEXE_HEADER_STRUCT.unpack(header)
        return magic == NXEXE_MAGIC and version == NXEXE_VERSION

    def init(self) -> bool:
        try:
            header = self.raw.read(0, NXEXE_HEADER_STRUCT.size)
            magic, version, json_len, blob_len, _ = NXEXE_HEADER_STRUCT.unpack(header)
            if magic != NXEXE_MAGIC or version != NXEXE_VERSION:
                return False

            meta_bytes = self.raw.read(NXEXE_HEADER_STRUCT.size, json_len)
            meta = json.loads(meta_bytes.decode("utf-8"))
            blob_offset = NXEXE_HEADER_STRUCT.size + json_len

            arch_name = meta.get("arch", "aarch64")
            if arch_name == "aarch32":
                self.arch = Architecture["armv7"]
            else:
                self.arch = Architecture["aarch64"]
            self.platform = self.arch.standalone_platform

            base_addr = int(meta["base_addr"])
            text_off = int(meta["text_offset"])
            text_size = int(meta["text_size"])
            ro_off = int(meta["rodata_offset"])
            ro_size = int(meta["rodata_size"])
            data_off = int(meta["data_offset"])
            data_size = int(meta["data_size"])
            bss_off = int(meta["bss_offset"])
            bss_size = int(meta["bss_size"])

            if text_size:
                self.add_auto_segment(
                    base_addr + text_off,
                    text_size,
                    blob_offset + text_off,
                    text_size,
                    SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
                )
                self.add_auto_section(
                    name=".text",
                    start=base_addr + text_off,
                    length=text_size,
                    semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                    type="Code",
                )
                add_tag(self, base_addr + text_off, "Region", "NX .text")

            if ro_size:
                self.add_auto_segment(
                    base_addr + ro_off,
                    ro_size,
                    blob_offset + ro_off,
                    ro_size,
                    SegmentFlag.SegmentReadable,
                )
                self.add_auto_section(
                    name=".rodata",
                    start=base_addr + ro_off,
                    length=ro_size,
                    semantics=SectionSemantics.ReadOnlyDataSectionSemantics,
                    type="Data",
                )
                add_tag(self, base_addr + ro_off, "Region", "NX .rodata")

            if data_size:
                self.add_auto_segment(
                    base_addr + data_off,
                    data_size,
                    blob_offset + data_off,
                    data_size,
                    SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
                )
                self.add_auto_section(
                    name=".data",
                    start=base_addr + data_off,
                    length=data_size,
                    semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                    type="Data",
                )
                add_tag(self, base_addr + data_off, "Region", "NX .data")

            if bss_size:
                self.add_auto_segment(
                    base_addr + bss_off,
                    bss_size,
                    0,
                    0,
                    SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
                )
                self.add_auto_section(
                    name=".bss",
                    start=base_addr + bss_off,
                    length=bss_size,
                    semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                    type="BSS",
                )
                add_tag(self, base_addr + bss_off, "Region", "NX .bss")

            # Load blob for metadata parsing
            image = self.raw.read(blob_offset, blob_len)
            if len(image) != blob_len:
                return False

            mod0_offset = int(meta.get("mod0_offset", 0))
            mod0 = parse_mod0(image, mod0_offset)

            is_aarch32 = arch_name == "aarch32"
            dyn_entries = parse_dynamic_table(image, mod0.dynamic_offset, is_aarch32)
            dyn_size = len(dyn_entries) * (0x8 if is_aarch32 else 0x10)
            if dyn_size:
                self.add_auto_section(
                    name=".dynamic",
                    start=base_addr + mod0.dynamic_offset,
                    length=dyn_size,
                    semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                    type="Data",
                )
                add_tag(self, base_addr + mod0.dynamic_offset, "Region", "NX .dynamic")

            self._add_dyn_sections(base_addr, image, dyn_entries, is_aarch32)

            relocs = parse_relocations(image, dyn_entries, base_addr, is_aarch32)

            dynsyms = parse_dynsym(image, dyn_entries, base_addr, is_aarch32)
            sym_values = self._define_symbols(base_addr, dynsyms)

            self._add_got_plt_sections(
                base_addr, image, dyn_entries, relocs, mod0, is_aarch32
            )

            apply_relocations(
                self,
                relocs,
                lambda idx: sym_values.get(idx),
                base_addr,
                is_aarch32,
            )

            self._define_dynstr_strings(base_addr, image, dyn_entries)

            return True
        except Exception as exc:
            log_error(f"[NXEXE] init failed: {exc}")
            return False

    def _add_dyn_sections(
        self,
        base_addr: int,
        image: bytes,
        entries: list[DynamicEntry],
        is_aarch32: bool,
    ) -> None:
        def _to_offset(value: int) -> int:
            if 0 <= value < len(image):
                return value
            if value >= base_addr and (value - base_addr) < len(image):
                return value - base_addr
            return value

        def _section(
            name: str, addr: int, size: int, semantics: SectionSemantics, typ: str
        ) -> None:
            if size <= 0:
                return
            addr = _to_offset(addr)
            self.add_auto_section(
                name=name,
                start=base_addr + addr,
                length=size,
                semantics=semantics,
                type=typ,
            )
            add_tag(self, base_addr + addr, "Region", f"NX {name}")

        strtab_addr = dynamic_first(entries, DT_STRTAB)
        strtab_size = dynamic_first(entries, DT_STRSZ, 0) or 0
        if strtab_addr is not None:
            _section(
                ".dynstr",
                _to_offset(strtab_addr),
                strtab_size,
                SectionSemantics.ReadOnlyDataSectionSemantics,
                "Data",
            )

        symtab_addr = dynamic_first(entries, DT_SYMTAB)
        if symtab_addr is not None:
            symtab_size = symbol_table_size(image, entries, base_addr, is_aarch32)
            _section(
                ".dynsym",
                _to_offset(symtab_addr),
                symtab_size,
                SectionSemantics.ReadOnlyDataSectionSemantics,
                "Data",
            )

        rel_addr = dynamic_first(entries, DT_REL)
        rel_size = dynamic_first(entries, DT_RELSZ, 0) or 0
        if rel_addr is not None:
            _section(
                ".rel.dyn",
                _to_offset(rel_addr),
                rel_size,
                SectionSemantics.ReadOnlyDataSectionSemantics,
                "Data",
            )

        rela_addr = dynamic_first(entries, DT_RELA)
        rela_size = dynamic_first(entries, DT_RELASZ, 0) or 0
        if rela_addr is not None:
            _section(
                ".rela.dyn",
                _to_offset(rela_addr),
                rela_size,
                SectionSemantics.ReadOnlyDataSectionSemantics,
                "Data",
            )

        relr_addr = dynamic_first(entries, DT_RELR)
        relr_size = dynamic_first(entries, DT_RELRSZ, 0) or 0
        if relr_addr is not None:
            _section(
                ".relr.dyn",
                _to_offset(relr_addr),
                relr_size,
                SectionSemantics.ReadOnlyDataSectionSemantics,
                "Data",
            )

        jmprel_addr = dynamic_first(entries, DT_JMPREL)
        jmprel_size = dynamic_first(entries, DT_PLTRELSZ, 0) or 0
        if jmprel_addr is not None:
            _section(
                ".rel.plt" if is_aarch32 else ".rela.plt",
                _to_offset(jmprel_addr),
                jmprel_size,
                SectionSemantics.ReadOnlyDataSectionSemantics,
                "Data",
            )

        gnu_hash_addr = dynamic_first(entries, DT_GNU_HASH)
        if gnu_hash_addr is not None:
            end = dynamic_first(entries, DT_SYMTAB, gnu_hash_addr) or gnu_hash_addr
            start_off = _to_offset(gnu_hash_addr)
            end_off = _to_offset(end)
            if end_off > start_off:
                _section(
                    ".gnu.hash",
                    start_off,
                    end_off - start_off,
                    SectionSemantics.ReadOnlyDataSectionSemantics,
                    "Data",
                )

        hash_addr = dynamic_first(entries, DT_HASH)
        if hash_addr is not None:
            end = dynamic_first(entries, DT_GNU_HASH, hash_addr) or hash_addr
            start_off = _to_offset(hash_addr)
            end_off = _to_offset(end)
            if end_off > start_off:
                _section(
                    ".hash",
                    start_off,
                    end_off - start_off,
                    SectionSemantics.ReadOnlyDataSectionSemantics,
                    "Data",
                )

        init_addr = dynamic_first(entries, DT_INIT_ARRAY)
        init_size = dynamic_first(entries, DT_INIT_ARRAYSZ, 0) or 0
        if init_addr is not None:
            _section(
                ".init_array",
                _to_offset(init_addr),
                init_size,
                SectionSemantics.ReadOnlyDataSectionSemantics,
                "Data",
            )

        fini_addr = dynamic_first(entries, DT_FINI_ARRAY)
        fini_size = dynamic_first(entries, DT_FINI_ARRAYSZ, 0) or 0
        if fini_addr is not None:
            _section(
                ".fini_array",
                _to_offset(fini_addr),
                fini_size,
                SectionSemantics.ReadOnlyDataSectionSemantics,
                "Data",
            )

    def _define_dynstr_strings(
        self,
        base_addr: int,
        image: bytes,
        entries: list[DynamicEntry],
    ) -> None:
        strtab_addr = dynamic_first(entries, DT_STRTAB)
        strtab_size = dynamic_first(entries, DT_STRSZ, 0) or 0
        if strtab_addr is None or strtab_size <= 0:
            return
        try:
            strtab = parse_dynstr(image, strtab_addr, strtab_size, base_addr)
        except Exception:
            return

        if strtab_addr >= base_addr and (strtab_addr - base_addr) < len(image):
            strtab_addr = strtab_addr - base_addr

        cursor = 0
        while cursor < len(strtab):
            end = strtab.find(b"\x00", cursor)
            if end == -1:
                end = len(strtab)
            length = end - cursor
            if length > 0:
                addr = base_addr + strtab_addr + cursor
                if self.get_data_var_at(addr) is None:
                    self.define_data_var(addr, Type.array(Type.char(), length))
            cursor = end + 1

    def _define_symbols(self, base_addr: int, symbols: list) -> dict[int, int]:
        sym_values: dict[int, int] = {}
        undefined = [s for s in symbols if s.is_undef and s.name]
        ext_base = None
        if undefined:
            max_addr = 0
            for seg in self.segments:
                try:
                    end = seg.start + seg.length
                    max_addr = max(max_addr, end)
                except Exception:
                    continue
            ext_base = (max_addr + 0xFFF) & ~0xFFF
            ext_size = len(undefined) * 0x1000
            self.add_auto_segment(
                ext_base,
                ext_size,
                0,
                0,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            )
            self.add_auto_section(
                name="EXTERNAL",
                start=ext_base,
                length=ext_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="Data",
            )
            add_tag(self, ext_base, "Region", "NX EXTERNAL")

        undef_index = 0
        for idx, sym in enumerate(symbols):
            if not sym.name:
                continue
            if sym.typ == STT_SECTION:
                continue
            if sym.is_undef:
                if ext_base is None:
                    continue
                addr = ext_base + undef_index * 0x1000
                undef_index += 1
                sym_values[idx] = addr
                sym_type = (
                    SymbolType.ImportedFunctionSymbol
                    if sym.typ == STT_FUNC
                    else SymbolType.ImportedDataSymbol
                )
                self.define_auto_symbol_and_var_or_function(
                    Symbol(sym_type, addr, sym.name),
                    plat=self.platform,
                )
            else:
                addr = base_addr + sym.value
                sym_values[idx] = addr
                if sym.typ == STT_FUNC:
                    sym_type = SymbolType.FunctionSymbol
                elif sym.typ == STT_OBJECT:
                    sym_type = SymbolType.DataSymbol
                else:
                    sym_type = SymbolType.DataSymbol
                self.define_auto_symbol_and_var_or_function(
                    Symbol(sym_type, addr, sym.name),
                    plat=self.platform,
                )
        return sym_values

    def _add_got_plt_sections(
        self,
        base_addr: int,
        image: bytes,
        entries: list[DynamicEntry],
        relocs: RelocationBundle,
        mod0,
        is_aarch32: bool,
    ) -> None:
        offset_size = 4 if is_aarch32 else 8
        plt_offsets = sorted({r.offset for r in relocs.plt_relocs})
        plt_got_start = None
        plt_got_end = None
        pltgot_addr = dynamic_first(entries, DT_PLTGOT)
        if (
            pltgot_addr is not None
            and pltgot_addr >= base_addr
            and (pltgot_addr - base_addr) < len(image)
        ):
            pltgot_addr = pltgot_addr - base_addr
        if pltgot_addr is not None and plt_offsets:
            plt_got_start = pltgot_addr
            plt_got_end = plt_offsets[-1] + offset_size
            if plt_got_end > plt_got_start:
                self.add_auto_section(
                    name=".got.plt",
                    start=base_addr + plt_got_start,
                    length=plt_got_end - plt_got_start,
                    semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                    type="Data",
                )
                add_tag(self, base_addr + plt_got_start, "Region", "NX .got.plt")

        got_start = 0
        got_end = 0
        if getattr(mod0, "has_libnx", False):
            got_start = mod0.libnx_got_start
            got_end = mod0.libnx_got_end
        else:
            reloc_offsets = {r.offset for r in relocs.relocs}
            reloc_offsets.update({r.offset for r in relocs.plt_relocs})
            reloc_offsets.update(relocs.relr_offsets)

            dyn_offset = mod0.dynamic_offset
            dyn_size = len(entries) * (0x8 if is_aarch32 else 0x10)

            if plt_got_end is not None:
                got_start = plt_got_end
            else:
                got_start = dyn_offset + dyn_size
            got_end = got_start + offset_size

            init_array = dynamic_first(entries, DT_INIT_ARRAY)
            while (
                got_end in reloc_offsets
                or (plt_got_end is None and init_array and got_end < init_array)
            ) and (
                init_array is None or got_end < init_array or got_start > init_array
            ):
                got_end += offset_size

        if got_end > got_start:
            self.add_auto_section(
                name=".got",
                start=base_addr + got_start,
                length=got_end - got_start,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="Data",
            )
            add_tag(self, base_addr + got_start, "Region", "NX .got")

        # Attempt to locate .plt for aarch64 by scanning for br x17 pattern
        if not is_aarch32 and plt_got_start is not None and plt_got_end is not None:
            self._scan_aarch64_plt(base_addr, image, plt_got_start, plt_got_end)

    def _scan_aarch64_plt(
        self,
        base_addr: int,
        image: bytes,
        plt_got_start: int,
        plt_got_end: int,
    ) -> None:
        text = self.get_section_by_name(".text")
        if text is None:
            return
        text_start = text.start - base_addr
        text_end = text.start + text.length - base_addr
        if text_start < 0 or text_end > len(image):
            return

        plt_entries = []
        last = 12
        for i in range(text_start + last, text_end, 4):
            if i + 4 > text_end:
                break
            insn = struct.unpack_from("<I", image, i)[0]
            if insn != 0xD61F0220:
                continue
            off = i - 12
            if off < text_start:
                continue
            a = struct.unpack_from("<I", image, off)[0]
            b = struct.unpack_from("<I", image, off + 4)[0]
            d = struct.unpack_from("<I", image, off + 12)[0]
            if d != 0xD61F0220:
                continue
            if (a & 0x9F00001F) != 0x90000010:
                continue
            if (b & 0xFFE003FF) != 0xF9400211:
                continue
            base = off & ~0xFFF
            immhi = (a >> 5) & 0x7FFFF
            immlo = (a >> 29) & 0x3
            paddr = base + ((immlo << 12) | (immhi << 14))
            poff = ((b >> 10) & 0xFFF) << 3
            target = paddr + poff
            if plt_got_start <= target < plt_got_end:
                plt_entries.append(off)

        if not plt_entries:
            return
        plt_start = min(plt_entries)
        plt_end = max(plt_entries) + 0x10
        self.add_auto_section(
            name=".plt",
            start=base_addr + plt_start,
            length=plt_end - plt_start,
            semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            type="Code",
        )
        add_tag(self, base_addr + plt_start, "Region", "NX .plt")


SwitchNxExeView.register()
