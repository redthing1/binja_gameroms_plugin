from __future__ import annotations

import json

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
from .constants import WIIEXE_HEADER_STRUCT, WIIEXE_MAGIC, WIIEXE_VERSION
from .dol import DolParseError, parse_dol
from .rel import RelParseError, apply_rel_relocations, parse_rel
from .rso import RsoParseError, apply_rso_relocations, parse_rso, RsoSection


class WiiExeView(BaseRomView):
    name = "Wii WIIEXE"
    long_name = "Wii Executable"

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        header = data.read(0, WIIEXE_HEADER_STRUCT.size)
        if len(header) != WIIEXE_HEADER_STRUCT.size:
            return False
        magic, version, _, _, _ = WIIEXE_HEADER_STRUCT.unpack(header)
        return magic == WIIEXE_MAGIC and version == WIIEXE_VERSION

    def init(self) -> bool:
        try:
            header = self.raw.read(0, WIIEXE_HEADER_STRUCT.size)
            magic, version, json_len, blob_len, _ = WIIEXE_HEADER_STRUCT.unpack(header)
            if magic != WIIEXE_MAGIC or version != WIIEXE_VERSION:
                return False

            meta_bytes = self.raw.read(WIIEXE_HEADER_STRUCT.size, json_len)
            meta = json.loads(meta_bytes.decode("utf-8"))
            blob_offset = WIIEXE_HEADER_STRUCT.size + json_len
            blob = self.raw.read(blob_offset, blob_len)
            if len(blob) != blob_len:
                return False

            self.arch = Architecture["ppc_ps"]
            self.platform = self.arch.standalone_platform

            modules = meta.get("modules", [])
            dol_mod = next((m for m in modules if m.get("type") == "dol"), None)
            if dol_mod is None:
                return False

            dol_blob = blob[
                dol_mod["blob_offset"] : dol_mod["blob_offset"] + dol_mod["blob_size"]
            ]
            dol_info = parse_dol(dol_blob)
            self._map_dol(dol_mod, dol_info, blob_offset)

            # Map overlays
            rel_modules = []
            rso_modules = []
            modules_by_id: dict[int, object] = {0: None}

            for mod in modules:
                mtype = mod.get("type")
                if mtype == "rel":
                    rel_blob = blob[
                        mod["blob_offset"] : mod["blob_offset"] + mod["blob_size"]
                    ]
                    rel = parse_rel(rel_blob, mod.get("name", "rel"))
                    rel_modules.append((mod, rel))
                    modules_by_id[rel.header.module_id] = rel
                elif mtype == "rso":
                    rso_blob = blob[
                        mod["blob_offset"] : mod["blob_offset"] + mod["blob_size"]
                    ]
                    rso = parse_rso(rso_blob, mod.get("name", "rso"))
                    rso_modules.append((mod, rso))

            for mod, rel in rel_modules:
                self._map_rel(mod, rel, blob_offset)
            for mod, rso in rso_modules:
                self._map_rso(mod, rso, blob_offset)

            # Apply REL relocations
            for _, rel in rel_modules:
                apply_rel_relocations(self, rel, modules_by_id)

            # Apply RSO relocations
            for mod, rso in rso_modules:
                external_base = mod.get("external_base")
                if external_base is None:
                    continue
                runtime_sections = [
                    RsoSection(offset=sec.offset, size=sec.size, addr=sec.addr)
                    for sec in rso.sections
                ]
                apply_rso_relocations(self, rso, runtime_sections, external_base)

            return True
        except Exception as exc:
            log_error(f"[WIIEXE] init failed: {exc}")
            return False

    def _map_dol(self, mod: dict, dol_info, blob_offset: int) -> None:
        base_file_off = blob_offset + mod["blob_offset"]
        for sec in dol_info.sections:
            if sec.size == 0:
                continue
            file_off = base_file_off + sec.offset
            perms = SegmentFlag.SegmentReadable
            semantics = SectionSemantics.ReadOnlyDataSectionSemantics
            section_type = "Data"
            if sec.is_text:
                perms |= SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
                semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
                section_type = "Code"
            else:
                perms |= SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
                semantics = SectionSemantics.ReadWriteDataSectionSemantics
            self.add_auto_segment(sec.addr, sec.size, file_off, sec.size, perms)
            self.add_auto_section(
                name=sec.name,
                start=sec.addr,
                length=sec.size,
                semantics=semantics,
                type=section_type,
            )
            add_tag(self, sec.addr, "Region", sec.name)

        if dol_info.bss_size:
            self.add_auto_segment(
                dol_info.bss_addr,
                dol_info.bss_size,
                0,
                0,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            )
            self.add_auto_section(
                name="MAIN_.bss",
                start=dol_info.bss_addr,
                length=dol_info.bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="BSS",
            )
            add_tag(self, dol_info.bss_addr, "Region", "MAIN_.bss")

        self._entry_point = dol_info.entry_point
        self.add_entry_point(dol_info.entry_point)
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, dol_info.entry_point, "wii_entry")
        )
        add_tag(self, dol_info.entry_point, "Entry", "wii_entry")

    def _map_rel(self, mod: dict, rel, blob_offset: int) -> None:
        base_addr = int(mod.get("base_addr", 0))
        base_file_off = blob_offset + mod["blob_offset"]
        max_end = base_addr
        add_tag(self, base_addr, "Overlay", f"{rel.name} base")

        for idx, sec in enumerate(rel.sections):
            if sec.size == 0 or sec.offset == 0:
                continue
            vaddr = base_addr + sec.offset
            sec.addr = vaddr
            max_end = max(max_end, vaddr + sec.size)
            perms = SegmentFlag.SegmentReadable
            semantics = SectionSemantics.ReadOnlyDataSectionSemantics
            section_type = "Data"
            if sec.is_executable:
                perms |= SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
                semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
                section_type = "Code"
            else:
                perms |= SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
                semantics = SectionSemantics.ReadWriteDataSectionSemantics
            self.add_auto_segment(
                vaddr,
                sec.size,
                base_file_off + sec.offset,
                sec.size,
                perms,
            )
            self.add_auto_section(
                name=f"{rel.name}.section{idx}",
                start=vaddr,
                length=sec.size,
                semantics=semantics,
                type=section_type,
            )

        # BSS
        bss_size = rel.header.bss_size
        if bss_size:
            align = rel.header.bss_section_alignment or 0x20
            if max_end % align:
                max_end = (max_end + align - 1) & ~(align - 1)
            bss_addr = max_end
            if rel.header.bss_section_id < len(rel.sections):
                rel.sections[rel.header.bss_section_id].addr = bss_addr
            self.add_auto_segment(
                bss_addr,
                bss_size,
                0,
                0,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            )
            self.add_auto_section(
                name=f"{rel.name}.bss",
                start=bss_addr,
                length=bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="BSS",
            )

        # Entry points
        for label, section_id, offset in (
            ("prolog", rel.header.prolog_section_id, rel.header.prolog_section_offset),
            ("epilog", rel.header.epilog_section_id, rel.header.epilog_section_offset),
            (
                "unresolved",
                rel.header.unresolved_section_id,
                rel.header.unresolved_section_offset,
            ),
        ):
            if section_id == 0 or section_id >= len(rel.sections):
                continue
            addr = (rel.sections[section_id].addr + offset) & ~1
            if addr:
                sym_name = f"{rel.name}_{label}"
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, addr, sym_name)
                )
                add_tag(self, addr, "Overlay", sym_name)

    def _map_rso(self, mod: dict, rso, blob_offset: int) -> None:
        base_addr = int(mod.get("base_addr", 0))
        base_file_off = blob_offset + mod["blob_offset"]
        current = base_addr
        runtime_sections: list[RsoSection] = []

        section_names = [
            "",
            ".init",
            ".text",
            ".ctors",
            ".dtors",
            ".rodata",
            ".data",
            ".bss",
            ".sdata",
            ".sdata2",
            "",
            ".sbss",
            ".sbss2",
        ]

        for idx, sec in enumerate(rso.sections):
            if sec.size == 0 or sec.offset == 0:
                runtime_sections.append(
                    RsoSection(offset=sec.offset, size=sec.size, addr=0)
                )
                continue
            vaddr = current
            sec.addr = vaddr
            runtime_sections.append(
                RsoSection(offset=sec.offset, size=sec.size, addr=vaddr)
            )
            current += sec.size

            name = section_names[idx] if idx < len(section_names) else f".section{idx}"
            exec_names = (".init", ".text")
            if name in exec_names:
                perms = (
                    SegmentFlag.SegmentReadable
                    | SegmentFlag.SegmentExecutable
                    | SegmentFlag.SegmentContainsCode
                )
                semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
                section_type = "Code"
            elif name in (".rodata", ".sdata2"):
                perms = SegmentFlag.SegmentReadable
                semantics = SectionSemantics.ReadOnlyDataSectionSemantics
                section_type = "Data"
            else:
                perms = (
                    SegmentFlag.SegmentReadable
                    | SegmentFlag.SegmentWritable
                    | SegmentFlag.SegmentContainsData
                )
                semantics = SectionSemantics.ReadWriteDataSectionSemantics
                section_type = "Data"

            self.add_auto_segment(
                vaddr,
                sec.size,
                base_file_off + sec.offset,
                sec.size,
                perms,
            )
            self.add_auto_section(
                name=f"{rso.name}{name}",
                start=vaddr,
                length=sec.size,
                semantics=semantics,
                type=section_type,
            )

        # BSS
        if rso.header.bss_size:
            if current % 4:
                current = (current + 3) & ~3
            bss_addr = current
            if rso.header.bss_section < len(rso.sections):
                rso.sections[rso.header.bss_section].addr = bss_addr
                runtime_sections[rso.header.bss_section].addr = bss_addr
            self.add_auto_segment(
                bss_addr,
                rso.header.bss_size,
                0,
                0,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            )
            self.add_auto_section(
                name=f"{rso.name}.bss",
                start=bss_addr,
                length=rso.header.bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="BSS",
            )
            current = bss_addr + rso.header.bss_size

        # External block for imports
        import_count = len(rso.imports)
        external_base = int(mod.get("external_base", 0))
        if import_count and external_base == 0:
            if current % 4:
                current = (current + 3) & ~3
            external_base = current
        if import_count and external_base:
            self.add_auto_segment(
                external_base,
                import_count * 4,
                0,
                0,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
            )
            self.add_auto_section(
                name=f"{rso.name}.external",
                start=external_base,
                length=import_count * 4,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="External",
            )
            for idx, imp in enumerate(rso.imports):
                addr = external_base + idx * 4
                self.define_auto_symbol(
                    Symbol(SymbolType.DataSymbol, addr, imp.name or f"imp_{idx}")
                )

        # Export symbols
        for exp in rso.exports:
            if exp.section >= len(runtime_sections):
                continue
            addr = runtime_sections[exp.section].addr + exp.value
            if addr:
                sym_type = SymbolType.FunctionSymbol
                self.define_auto_symbol(Symbol(sym_type, addr, exp.name))

        mod["external_base"] = external_base
        mod["runtime_sections"] = runtime_sections


WiiExeView.register()
