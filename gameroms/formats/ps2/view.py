from __future__ import annotations

import struct
from typing import Optional
import traceback

from binaryninja import (
    Architecture,
    SectionSemantics,
    SegmentFlag,
    Symbol,
    SymbolType,
    log_error,
)
from binaryninja.variable import ConstantPointerRegisterValue

from ...core.tags import add_tag
from ...core.view_base import BaseRomView
from .layout import ps2_ee_regions, ps2_iop_regions
from .mmio import ps2_ee_mmio_registers, ps2_iop_mmio_registers
from .overlay import apply_dvp_overlays
from .parse import (
    ElfHeader32,
    ElfSymbol32,
    EM_MIPS,
    ET_DYN,
    ET_EXEC,
    ET_IRX,
    ET_IRX2,
    ET_ERX2,
    ET_REL,
    EF_MIPS_ARCH_1,
    EF_MIPS_ARCH_MASK,
    PF_R,
    PF_W,
    PF_X,
    PT_LOAD,
    SHT_DYNSYM,
    SHT_NOBITS,
    SHT_REL,
    SHT_RELA,
    SHT_SYMTAB,
    SHT_MIPS_IOPMOD,
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHF_WRITE,
    read_elf_header,
    read_program_headers,
    read_section_headers,
    read_section_names,
)
from .reloc import apply_relocations


class Ps2ViewBase(BaseRomView):
    arch_name = "r5900l"
    cpu_name = "EE"
    entry_symbol = "ps2_ee_entry"

    def __init__(self, data):
        super().__init__(data)
        self._elf_header: Optional[ElfHeader32] = None
        self._program_headers = []
        self._section_headers = []
        self._section_names: list[str] = []
        self._symbol_values_by_index: dict[int, dict[int, int]] = {}

    def perform_is_relocatable(self) -> bool:
        if self._elf_header is None:
            return False
        return self._elf_header.e_type in (ET_REL, ET_DYN)

    def _map_system_memory(self) -> None:
        raise NotImplementedError

    def _mmio_registers(self) -> list:
        raise NotImplementedError

    def _alias_addresses_from_phys(self, phys: int) -> list[int]:
        return []

    def init(self) -> bool:
        try:
            self.arch = Architecture[self.arch_name]
            self.platform = self.arch.standalone_platform

            if getattr(self, "parse_only", False):
                return True

            header = read_elf_header(self.raw)
            if header is None:
                return False
            self._elf_header = header
            self._program_headers = read_program_headers(self.raw, header)
            self._section_headers = read_section_headers(self.raw, header)
            self._section_names = read_section_names(
                self.raw, header, self._section_headers
            )

            self._map_system_memory()
            self._map_pt_load_segments()
            self._map_sections()
            apply_dvp_overlays(
                self, self.raw, self._section_headers, self._section_names
            )
            self.define_mmio_registers(self._mmio_registers())

            self._define_entrypoint()
            self._define_bios_vectors()
            self._define_elf_symbols()
            self._maybe_set_global_pointer()
            apply_relocations(
                self, self.raw, self._section_headers, self._symbol_values_by_index
            )
            return True
        except Exception:
            log_error(f"[PS2 {self.cpu_name}] init failed:\n{traceback.format_exc()}")
            return False

    def _map_pt_load_segments(self) -> None:
        for ph in self._program_headers:
            if ph.p_type != PT_LOAD or ph.p_memsz == 0:
                continue
            vaddr = ph.p_vaddr & 0xFFFFFFFF
            memsz = ph.p_memsz
            filesz = ph.p_filesz
            fileoff = ph.p_offset

            if fileoff > self.raw.length:
                fileoff = 0
                filesz = 0
            else:
                max_avail = self.raw.length - fileoff
                if filesz > max_avail:
                    filesz = max_avail
            if filesz > memsz:
                filesz = memsz

            perms = 0
            is_exec = (ph.p_flags & PF_X) != 0
            is_write = (ph.p_flags & PF_W) != 0
            if ph.p_flags & PF_R:
                perms |= SegmentFlag.SegmentReadable
            if is_write:
                perms |= SegmentFlag.SegmentWritable
            if is_exec:
                perms |= SegmentFlag.SegmentExecutable
                perms |= SegmentFlag.SegmentContainsCode
            # Mark non-exec or writable segments as data-bearing to help analysis.
            if is_write or not is_exec:
                perms |= SegmentFlag.SegmentContainsData

            self.add_auto_segment(vaddr, memsz, fileoff, filesz, perms)

            phys = vaddr & 0x1FFFFFFF
            for alias in self._alias_addresses_from_phys(phys):
                if alias == vaddr:
                    continue
                seg = self.get_segment_at(alias)
                if seg is None:
                    self.add_auto_segment(alias, memsz, fileoff, filesz, perms)
                elif seg.data_length == 0 and not self.file.has_database:
                    if filesz > 0 and fileoff + filesz <= self.raw.length:
                        data = self.raw.read(fileoff, filesz)
                        if data:
                            self.memory_map.add_memory_region(
                                f"alias_{alias:08x}",
                                alias,
                                data,
                                perms,
                            )

    def _map_sections(self) -> None:
        for idx, sh in enumerate(self._section_headers):
            if not (sh.sh_flags & SHF_ALLOC):
                continue
            if sh.sh_size == 0 or sh.sh_addr == 0:
                continue
            name = (
                self._section_names[idx]
                if idx < len(self._section_names) and self._section_names[idx]
                else f"section_{idx}"
            )
            semantics = SectionSemantics.ReadOnlyDataSectionSemantics
            section_type = "Data"
            if sh.sh_flags & SHF_EXECINSTR:
                semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
                section_type = "Code"
            elif sh.sh_flags & SHF_WRITE:
                semantics = SectionSemantics.ReadWriteDataSectionSemantics
                section_type = "Data"
            if sh.sh_type == SHT_NOBITS:
                section_type = "BSS"
            try:
                self.add_auto_section(
                    name=name,
                    start=sh.sh_addr & 0xFFFFFFFF,
                    length=sh.sh_size,
                    semantics=semantics,
                    type=section_type,
                )
            except Exception:
                pass

    def _define_entrypoint(self) -> None:
        if self._elf_header is None:
            return
        entry = self._elf_header.e_entry & 0xFFFFFFFF
        if entry == 0 and self._program_headers:
            entry = self._program_headers[0].p_vaddr & 0xFFFFFFFF
        self._entry_point = entry
        self.add_entry_point(entry, self.platform)
        self.define_auto_symbol_and_var_or_function(
            Symbol(SymbolType.FunctionSymbol, entry, self.entry_symbol),
            plat=self.platform,
        )
        add_tag(self, entry, "Entry", self.entry_symbol)

    def _define_bios_vectors(self) -> None:
        base = 0xBFC00000
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, base + 0x000, "Reset_Vector")
        )
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, base + 0x180, "General_Exception_Vector")
        )
        add_tag(self, base + 0x000, "Vector", "Reset_Vector")
        add_tag(self, base + 0x180, "Vector", "General_Exception_Vector")

    def _parse_symbol_table(self, sh) -> tuple[list[ElfSymbol32], bytes]:
        entsize = sh.sh_entsize or 16
        if entsize < 16:
            return [], b""
        if sh.sh_offset + sh.sh_size > self.raw.length:
            return [], b""
        blob = self.raw.read(sh.sh_offset, sh.sh_size)
        if len(blob) != sh.sh_size:
            return [], b""
        strtab = b""
        if 0 <= sh.sh_link < len(self._section_headers):
            str_sh = self._section_headers[sh.sh_link]
            if str_sh.sh_offset + str_sh.sh_size <= self.raw.length:
                strtab = self.raw.read(str_sh.sh_offset, str_sh.sh_size)
        syms: list[ElfSymbol32] = []
        count = len(blob) // entsize
        for i in range(count):
            base = i * entsize
            ent = blob[base : base + entsize]
            if len(ent) < 16:
                break
            try:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(
                    "<IIIBBH", ent[:16]
                )
            except struct.error:
                break
            syms.append(
                ElfSymbol32(
                    st_name=st_name,
                    st_value=st_value,
                    st_size=st_size,
                    st_info=st_info,
                    st_other=st_other,
                    st_shndx=st_shndx,
                )
            )
        return syms, strtab

    def _read_cstring(self, blob: bytes, off: int) -> str:
        if off < 0 or off >= len(blob):
            return ""
        end = blob.find(b"\x00", off)
        if end == -1:
            end = len(blob)
        try:
            return blob[off:end].decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _define_elf_symbols(self) -> None:
        for idx, sh in enumerate(self._section_headers):
            if sh.sh_type not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            syms, strtab = self._parse_symbol_table(sh)
            if not syms or not strtab:
                continue
            symbol_values: dict[int, int] = {}
            for sym_index, sym in enumerate(syms):
                if sym.st_shndx == 0:
                    continue
                addr = sym.st_value & 0xFFFFFFFF
                if addr == 0 and sym.st_shndx < len(self._section_headers):
                    addr = self._section_headers[sym.st_shndx].sh_addr & 0xFFFFFFFF
                if addr == 0:
                    continue
                symbol_values[sym_index] = addr

                if sym.st_name == 0:
                    continue
                name = self._read_cstring(strtab, sym.st_name)
                if not name or name.startswith("."):
                    continue
                sym_type = SymbolType.DataSymbol
                is_func = sym.typ == 2
                if is_func:
                    sym_type = SymbolType.FunctionSymbol
                try:
                    if is_func:
                        self.define_auto_symbol_and_var_or_function(
                            Symbol(sym_type, addr, name),
                            plat=self.platform,
                        )
                    else:
                        self.define_auto_symbol(Symbol(sym_type, addr, name))
                except Exception:
                    pass
            if symbol_values:
                self._symbol_values_by_index[idx] = symbol_values

    def _maybe_set_global_pointer(self) -> None:
        if self._elf_header is None:
            return
        if getattr(self, "user_global_pointer_value_set", False):
            return

        gp_value: Optional[int] = None
        for candidate in ("_gp", "__gnu_local_gp", "_GP"):
            try:
                syms = self.get_symbols_by_name(candidate)
            except Exception:
                syms = []
            if syms:
                gp_value = syms[0].address
                break

        if gp_value is None:
            for idx, sh in enumerate(self._section_headers):
                if (
                    idx < len(self._section_names)
                    and self._section_names[idx] == ".reginfo"
                ):
                    if (
                        sh.sh_offset + sh.sh_size <= self.raw.length
                        and sh.sh_size >= 24
                    ):
                        blob = self.raw.read(sh.sh_offset, sh.sh_size)
                        if len(blob) >= 24:
                            try:
                                gp_value = struct.unpack("<I", blob[20:24])[0]
                            except struct.error:
                                gp_value = None
                    break

        if gp_value is None or gp_value == 0:
            return
        entry = self._entry_point
        if entry >= 0x80000000 and gp_value < 0x20000000:
            gp_value = (gp_value | 0x80000000) & 0xFFFFFFFF
        try:
            self.set_user_global_pointer_value(ConstantPointerRegisterValue(gp_value))
        except Exception:
            pass


class Ps2EeView(Ps2ViewBase):
    name = "PS2 EE ELF"
    long_name = "PS2 ELF (EE)"
    arch_name = "r5900l"
    cpu_name = "EE"
    entry_symbol = "ps2_ee_entry"

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        raw = data
        while raw is not None and raw.parent_view is not None:
            raw = raw.parent_view
        header = read_elf_header(raw)
        if header is None:
            return False
        if header.e_machine != EM_MIPS:
            return False
        if header.e_type in (ET_IRX, ET_IRX2, ET_ERX2):
            return False
        if header.e_type not in (ET_EXEC, ET_REL, ET_DYN):
            return False

        addrs = [header.e_entry & 0xFFFFFFFF]
        for ph in read_program_headers(raw, header):
            if ph.p_type == PT_LOAD:
                addrs.append(ph.p_vaddr & 0xFFFFFFFF)
                addrs.append(ph.p_paddr & 0xFFFFFFFF)

        def looks_ee_addr(a: int) -> bool:
            return (
                (0x00000000 <= a < 0x02000000)
                or (0x20000000 <= a < 0x22000000)
                or (0x30100000 <= a < 0x32000000)
                or (0x70000000 <= a < 0x70004000)
                or (0x80000000 <= a < 0x82000000)
                or (0xA0000000 <= a < 0xA2000000)
                or (0x10000000 <= a < 0x13000000)
                or (0x1C000000 <= a < 0x1C200000)
                or (0x1FC00000 <= a < 0x20000000)
            )

        return any(looks_ee_addr(a) for a in addrs)

    def _map_system_memory(self) -> None:
        regions = ps2_ee_regions()
        self.map_regions(regions)
        for region in regions:
            add_tag(self, region.vaddr, "Region", region.name)
            if region.section_type == "MMIO":
                add_tag(self, region.vaddr, "MMIO", region.name)

    def _mmio_registers(self) -> list:
        return ps2_ee_mmio_registers()

    def _alias_addresses_from_phys(self, phys: int) -> list[int]:
        aliases: list[int] = []
        if phys < 0x02000000:
            aliases.append((phys | 0x20000000) & 0xFFFFFFFF)
            aliases.append((phys | 0x80000000) & 0xFFFFFFFF)
            aliases.append((phys | 0xA0000000) & 0xFFFFFFFF)
            if phys >= 0x00100000:
                aliases.append((phys + 0x30000000) & 0xFFFFFFFF)
        return aliases


class Ps2IopView(Ps2ViewBase):
    name = "PS2 IOP ELF"
    long_name = "PS2 ELF (IOP)"
    arch_name = "mipsel32"
    cpu_name = "IOP"
    entry_symbol = "ps2_iop_entry"

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        raw = data
        while raw is not None and raw.parent_view is not None:
            raw = raw.parent_view
        header = read_elf_header(raw)
        if header is None:
            return False
        if header.e_machine != EM_MIPS:
            return False
        addrs = [header.e_entry & 0xFFFFFFFF]
        for ph in read_program_headers(raw, header):
            if ph.p_type == PT_LOAD:
                addrs.append(ph.p_vaddr & 0xFFFFFFFF)
                addrs.append(ph.p_paddr & 0xFFFFFFFF)

        def looks_iop_addr(a: int) -> bool:
            return (
                (0x00000000 <= a < 0x00200000)
                or (0x80000000 <= a < 0x80200000)
                or (0xA0000000 <= a < 0xA0200000)
                or (0x1D000000 <= a < 0x1D010000)
                or (0x1F800000 <= a < 0x1F900000)
                or (0x1F900000 <= a < 0x1F900400)
                or (0x1FC00000 <= a < 0x20000000)
            )

        if header.e_type in (ET_IRX, ET_IRX2, ET_ERX2):
            return True

        has_iop_section = False
        for sh in read_section_headers(raw, header):
            if sh.sh_type == SHT_MIPS_IOPMOD:
                has_iop_section = True
                break

        has_iop_addr = any(looks_iop_addr(a) for a in addrs)
        is_arch1 = (header.e_flags & EF_MIPS_ARCH_MASK) == EF_MIPS_ARCH_1

        return has_iop_section or (is_arch1 and has_iop_addr) or has_iop_addr

    def _map_system_memory(self) -> None:
        regions = ps2_iop_regions()
        self.map_regions(regions)
        for region in regions:
            add_tag(self, region.vaddr, "Region", region.name)
            if region.section_type == "MMIO":
                add_tag(self, region.vaddr, "MMIO", region.name)

    def _mmio_registers(self) -> list:
        return ps2_iop_mmio_registers()

    def _alias_addresses_from_phys(self, phys: int) -> list[int]:
        aliases: list[int] = []
        if phys < 0x00200000:
            aliases.append((phys | 0x80000000) & 0xFFFFFFFF)
            aliases.append((phys | 0xA0000000) & 0xFFFFFFFF)
        return aliases


Ps2EeView.register()
Ps2IopView.register()
