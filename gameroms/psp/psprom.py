"""
PSP ROM loader using the refactored base loader architecture.
"""

import struct
import traceback
from typing import Optional, List, Dict, Tuple

from binaryninja import (
    BinaryView,
    SegmentFlag,
    SymbolType,
    Symbol,
    TagType,
    Tag,
    Platform,
    Architecture,
    SectionSemantics,
    log_error,
    log_warn,
    log_info,
    log_debug,
)

from ..common.base_loader import BaseROMLoader
from .hardware import (
    PSP_TAG_TYPE_DEFINITIONS,
    PSP_IO_REGISTERS,
    ELFHeader32,
    ProgramHeader32,
    ELF_HEADER_FORMAT,
    ELF_HEADER_SIZE,
    EI_MAG0,
    EI_MAG1,
    EI_MAG2,
    EI_MAG3,
    EI_CLASS,
    EI_DATA,
    EI_VERSION,
    ELFCLASS32,
    ELFDATA2LSB,
    ET_EXEC,
    EM_MIPS,
    P_HEADER_FORMAT,
    P_HEADER_SIZE,
    PT_LOAD,
    PF_X,
    PF_W,
    PF_R,
    S_HEADER_FORMAT,
    S_HEADER_SIZE,
    SHT_NULL,
    SHT_PROGBITS,
    SHT_SYMTAB,
    SHT_STRTAB,
    SHT_RELA,
    SHT_HASH,
    SHT_DYNAMIC,
    SHT_NOTE,
    SHT_NOBITS,
    SHT_REL,
    SHT_SHLIB,
    SHT_DYNSYM,
    SHF_WRITE,
    SHF_ALLOC,
    SHF_EXECINSTR,
)


class PSPView(BaseROMLoader):
    """
    BinaryView class for loading and analyzing PlayStation Portable (PSP) ELF executables.
    
    Handles ELF parsing, maps memory regions according to PSP's hardware layout
    and ELF segments, and defines known hardware registers.
    """

    name = "PSPELF"
    long_name = "PlayStation Portable ELF"

    def __init__(self, data: BinaryView):
        super().__init__(data)
        
        # PSP-specific attributes
        self.elf_header: Optional[ELFHeader32] = None
        self._primary_entry_point_address: Optional[int] = None

    def get_loader_name(self) -> str:
        """Return the name for this loader (used for logging)."""
        return self.name

    def get_tag_type_definitions(self) -> Dict[str, str]:
        """Return dictionary mapping tag type names to icons."""
        return PSP_TAG_TYPE_DEFINITIONS

    def _setup_architecture_and_platform(self) -> None:
        """Set up self.arch and self.platform for PSP ELFs."""
        # The PSP uses a MIPS III-based Allegrex CPU, which is a 32-bit little-endian MIPS processor
        selected_arch: Architecture | None = None
        selected_platform: Platform | None = None

        # Prioritize 'mipsel32' as it explicitly denotes little-endian MIPS 32-bit
        arch_candidates = ["mipsel32", "mips32"]
        for arch_name_candidate in arch_candidates:
            self.logger.log_debug(f"attempting to get architecture '{arch_name_candidate}'...")
            try:
                current_arch_attempt = Architecture[arch_name_candidate]  # type: ignore
                if current_arch_attempt:
                    self.logger.log_debug(f"found architecture: {current_arch_attempt.name}")
                    current_platform_attempt = current_arch_attempt.standalone_platform
                    if current_platform_attempt:
                        selected_arch = current_arch_attempt
                        selected_platform = current_platform_attempt
                        self.logger.log_info(
                            f"successfully selected architecture '{selected_arch.name}' and platform '{selected_platform.name}'"
                        )
                        break
                    else:
                        self.logger.log_warn(
                            f"architecture '{current_arch_attempt.name}' found, but no standalone platform associated"
                        )
            except KeyError:
                self.logger.log_warn(f"architecture '{arch_name_candidate}' not found")
            except Exception as e:
                self.logger.log_error(f"unexpected error looking up architecture '{arch_name_candidate}': {e}")

        if not selected_arch or not selected_platform:
            self.logger.log_error(
                f"critical error: failed to find a suitable MIPS architecture and platform from candidates: {arch_candidates}. "
                "PSP analysis cannot proceed. Ensure Binary Ninja has MIPS support installed."
            )
            raise RuntimeError("mips architecture/platform not found or not suitable for PSP")

        self.arch: Architecture = selected_arch
        self.platform: Platform = selected_platform

        self.logger.log_info(
            f"PSPView instance fully initialized with platform: {self.platform.name}, architecture: {self.arch.name}"
        )

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        Check if the provided data is likely a valid PSP ELF file.
        """
        if data.length < ELF_HEADER_SIZE:
            log_debug(f"[{cls.name}] file size {data.length} is smaller than ELF header size {ELF_HEADER_SIZE}")
            return False

        try:
            header_bytes = data.read(0, ELF_HEADER_SIZE)
            if len(header_bytes) < ELF_HEADER_SIZE:
                log_debug(f"[{cls.name}] could not read full ELF header")
                return False

            e_ident = header_bytes[:16]

            # Check ELF magic number: 0x7f 'E' 'L' 'F'
            if not (
                e_ident[EI_MAG0] == 0x7F
                and e_ident[EI_MAG1] == ord("E")
                and e_ident[EI_MAG2] == ord("L")
                and e_ident[EI_MAG3] == ord("F")
            ):
                log_debug(f"[{cls.name}] invalid ELF magic number")
                return False

            # Check for 32-bit class (PSP uses 32-bit MIPS)
            if e_ident[EI_CLASS] != ELFCLASS32:
                log_debug(f"[{cls.name}] incorrect ELF class (expected 32-bit)")
                return False

            # Check for little-endian data encoding (PSP MIPS is little-endian)
            if e_ident[EI_DATA] != ELFDATA2LSB:
                log_debug(f"[{cls.name}] incorrect data encoding (expected little-endian)")
                return False

            # Check for MIPS architecture
            e_machine_val = struct.unpack_from("<H", header_bytes, 18)[0]
            if e_machine_val != EM_MIPS:
                log_debug(f"[{cls.name}] incorrect machine type (expected MIPS)")
                return False

            log_info(f"[{cls.name}] validation successful: file appears to be a valid MIPS32 little-endian ELF")
            return True

        except (struct.error, IndexError) as unpack_err:
            log_error(f"[{cls.name}] error during ELF header validation: {unpack_err}")
            return False
        except Exception as e:
            log_error(f"[{cls.name}] unexpected error during ELF validation: {e}")
            return False

    def _parse_elf_header(self) -> bool:
        """
        Parse the ELF header from the raw data and store the parsed fields in self.elf_header.
        """
        self.logger.log_info("parsing ELF header from raw data...")
        if self.raw_data.length < ELF_HEADER_SIZE:
            self.logger.log_error(
                f"file is too small ({self.raw_data.length} bytes) for ELF header (requires {ELF_HEADER_SIZE} bytes)"
            )
            return False

        header_bytes = self.raw_data.read(0, ELF_HEADER_SIZE)
        if len(header_bytes) < ELF_HEADER_SIZE:
            self.logger.log_error(f"could not read full ELF header")
            return False

        try:
            header_values_tuple = struct.unpack(ELF_HEADER_FORMAT, header_bytes)
            self.elf_header = ELFHeader32(*header_values_tuple)

            self.logger.log_info(f"  ELF Entry Point Address: 0x{self.elf_header.e_entry:08x}")
            self.logger.log_info(
                f"  Program Header Table: File Offset=0x{self.elf_header.e_phoff:x}, "
                f"Number of Entries={self.elf_header.e_phnum}, Size of Entry={self.elf_header.e_phentsize} bytes"
            )
            self.logger.log_info(
                f"  Section Header Table: File Offset=0x{self.elf_header.e_shoff:x}, "
                f"Number of Entries={self.elf_header.e_shnum}, Size of Entry={self.elf_header.e_shentsize} bytes"
            )
            self.logger.log_info("ELF header parsed successfully")
            return True
        except struct.error as unpack_err:
            self.logger.log_error(f"failed to unpack ELF header data: {unpack_err}")
            self.elf_header = None
            return False
        except Exception as e:
            self.logger.log_error(f"unexpected error occurred while parsing ELF header: {e}")
            self.elf_header = None
            return False

    def _map_psp_hardware_memory_regions(self) -> None:
        """
        Map the core PSP hardware memory regions (e.g., main RAM, VRAM, I/O ports, scratchpad, boot ROM alias).
        """
        self.logger.log_info("mapping core PSP hardware memory regions...")

        def add_psp_hardware_memory_region(
            address: int,
            size: int,
            permissions: SegmentFlag,
            name: str,
            tag_name: str = "Memory Region",
            tag_icon: str = "🗺️",
        ):
            """Helper to add PSP hardware memory regions with consistent logging and tagging."""
            self.logger.log_debug(
                f"  preparing to map hardware region '{name}': addr=0x{address:08x}, size=0x{size:x} ({size // 1024}KB)"
            )
            try:
                # Hardware regions are not backed by the ELF file itself
                self.add_auto_segment(address, size, 0, 0, permissions)

                # Get the appropriate tag type for this memory region
                tag_type_object = self._get_or_create_tag_type(tag_name, tag_icon)
                if tag_type_object:
                    self.add_tag(address, tag_type_object.name, data=f"{name} Start")

                # Add a comment at the start of the region
                self.set_comment_at(address, f"PSP Hardware: {name} ({size // 1024}KB)")
                self.logger.log_info(f"  successfully mapped hardware region '{name}'")
            except Exception as e:
                self.logger.log_error(f"failed to map hardware memory region '{name}' at 0x{address:08x}: {e}")

        # Define standard PSP memory regions
        # SC (System Control) CPU Scratchpad RAM (16KB): fast internal RAM for the CPU
        add_psp_hardware_memory_region(
            0x00010000, 0x4000, self.PERM_RWX, "SC CPU Scratchpad RAM", tag_name="Memory Management"
        )

        # VRAM / EDRAM (Embedded DRAM for graphics)
        add_psp_hardware_memory_region(
            0x04000000, 0x00200000, self.PERM_RW, 
            "VRAM / Display Memory (2MB CPU Accessible)", tag_name="Graphics Engine"
        )

        # Main RAM: PSP-1000 models have 32MB, PSP-2000/3000/Go models have 64MB
        # User applications typically have access to a partition starting at 0x08000000
        main_ram_base = 0x08000000
        main_ram_size = 0x02000000  # 32MB default (user partition size for PSP-1000)
        add_psp_hardware_memory_region(
            main_ram_base, main_ram_size, self.PERM_RWX, 
            f"Main RAM ({main_ram_size // (1024*1024)}MB User Partition)"
        )

        # I/O ports: memory-mapped hardware registers
        add_psp_hardware_memory_region(
            0x1C000000, 0x01000000, self.PERM_RW,
            "I/O Ports Block 1 (Syscon, Media Engine, etc.)", tag_name="Hardware Register"
        )
        add_psp_hardware_memory_region(
            0x1D000000, 0x02000000, self.PERM_RW,
            "I/O Ports Block 2 (Graphics, Audio, etc.)", tag_name="Hardware Register"
        )
        add_psp_hardware_memory_region(
            0x1F000000, 0x00C00000, self.PERM_RW,
            "I/O Ports Block 3 (NAND, Kirk, etc.)", tag_name="Hardware Register"
        )

        # NAND DMA I/O buffers
        add_psp_hardware_memory_region(
            0x1FF00000, 0x00000A00, self.PERM_RW, "NAND DMA I/O Buffers", tag_name="NAND Flash"
        )

        # Boot ROM / Kernel RAM (exception vectors)
        boot_rom_kseg1_base = 0xBFC00000
        boot_rom_vector_area_size = 0x4000  # 16KB, standard MIPS size for initial vectors
        add_psp_hardware_memory_region(
            boot_rom_kseg1_base, boot_rom_vector_area_size, self.PERM_RX, "Boot ROM Exception Vectors (KSEG1 Alias)"
        )
        
        # Define symbols for common MIPS exception vectors
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, boot_rom_kseg1_base + 0x000, "Reset_Vector"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, boot_rom_kseg1_base + 0x180, "General_Exception_Vector"))

        self.logger.log_info("finished mapping PSP hardware memory regions")

    def _map_elf_loadable_segments(self) -> None:
        """
        Map the loadable program segments (those with type PT_LOAD) from the ELF header.
        """
        if not self.elf_header:
            self.logger.log_error("cannot map ELF segments, ELF header not parsed or is invalid")
            return

        e_phoff = self.elf_header.e_phoff
        e_phnum = self.elf_header.e_phnum
        e_phentsize = self.elf_header.e_phentsize

        program_headers_exist = e_phoff > 0 and e_phnum > 0
        self.logger.log_info(
            f"mapping ELF program segments (PT_LOAD type)... Found {e_phnum} program header entries at file offset 0x{e_phoff:x}"
        )

        if not program_headers_exist:
            self.logger.log_info("no program headers found in ELF file. No ELF segments to map")
            return

        # Validate program header table information
        if e_phoff + e_phnum * e_phentsize > self.raw_data.length:
            self.logger.log_error("program header table definition exceeds total file size")
            return
        if e_phentsize != P_HEADER_SIZE:
            self.logger.log_error(f"unexpected program header entry size ({e_phentsize} bytes, expected {P_HEADER_SIZE})")
            return

        for i in range(e_phnum):
            ph_file_offset = e_phoff + i * e_phentsize
            ph_bytes = self.raw_data.read(ph_file_offset, P_HEADER_SIZE)
            if len(ph_bytes) < P_HEADER_SIZE:
                self.logger.log_error(f"could not read full program header entry {i}. skipping")
                continue

            try:
                ph = ProgramHeader32(*struct.unpack(P_HEADER_FORMAT, ph_bytes))
            except struct.error as unpack_err:
                self.logger.log_error(f"failed to unpack program header entry {i}: {unpack_err}. skipping")
                continue

            # We are primarily interested in loadable segments (type PT_LOAD)
            if ph.p_type == PT_LOAD:
                map_vaddr = ph.p_vaddr
                map_memsz = ph.p_memsz
                segment_file_offset = ph.p_offset
                segment_file_data_len = ph.p_filesz

                # Basic validation for the segment's parameters
                if map_memsz == 0:
                    self.logger.log_warn(f"skipping PT_LOAD segment {i} due to zero memory size")
                    continue
                if segment_file_data_len > map_memsz:
                    self.logger.log_warn(
                        f"PT_LOAD segment {i}: file size greater than memory size. Will clamp file data length"
                    )
                    segment_file_data_len = map_memsz
                if segment_file_offset + segment_file_data_len > self.raw_data.length:
                    self.logger.log_error(f"PT_LOAD segment {i} data exceeds ELF file bounds. skipping")
                    continue

                # Determine Binary Ninja segment permissions from ELF p_flags
                bn_segment_permissions = 0
                perm_str_log = ""
                if ph.p_flags & PF_R:
                    bn_segment_permissions |= SegmentFlag.SegmentReadable
                    perm_str_log += "R"
                else:
                    perm_str_log += "-"
                if ph.p_flags & PF_W:
                    bn_segment_permissions |= SegmentFlag.SegmentWritable
                    perm_str_log += "W"
                else:
                    perm_str_log += "-"
                if ph.p_flags & PF_X:
                    bn_segment_permissions |= SegmentFlag.SegmentExecutable
                    perm_str_log += "X"
                else:
                    perm_str_log += "-"

                self.logger.log_info(
                    f"  mapping ELF PT_LOAD segment {i}: VAddr=0x{map_vaddr:08x}, MemSize=0x{map_memsz:x}, "
                    f"FileOffset=0x{segment_file_offset:x}, FileDataLen=0x{segment_file_data_len:x}, Perms='{perm_str_log}'"
                )

                # Add the segment to Binary Ninja
                self.add_auto_segment(
                    map_vaddr, map_memsz, segment_file_offset, segment_file_data_len, bn_segment_permissions
                )
                self.set_comment_at(
                    map_vaddr, f"ELF Segment {i} (PT_LOAD): File Offset=0x{segment_file_offset:x}, File Size=0x{segment_file_data_len:x}"
                )

                # If p_memsz > p_filesz, the difference is the BSS portion of this segment
                if map_memsz > segment_file_data_len:
                    bss_start_addr_in_segment = map_vaddr + segment_file_data_len
                    bss_size_in_segment = map_memsz - segment_file_data_len
                    if bss_start_addr_in_segment < map_vaddr + map_memsz:
                        self.set_comment_at(
                            bss_start_addr_in_segment, f"ELF Segment {i} BSS Area Start (Size: 0x{bss_size_in_segment:x})"
                        )
            else:
                self.logger.log_debug(f"  skipping program header entry {i}: type=0x{ph.p_type:x} (not PT_LOAD)")
        
        self.logger.log_info("finished mapping ELF program (PT_LOAD) segments")

    def _map_elf_sections(self) -> None:
        """
        Parse the ELF section header table and define corresponding sections in Binary Ninja.
        """
        if not self.elf_header:
            self.logger.log_error("cannot map ELF sections, ELF header not parsed or is invalid")
            return

        e_shoff = self.elf_header.e_shoff
        e_shnum = self.elf_header.e_shnum
        e_shentsize = self.elf_header.e_shentsize
        e_shstrndx = self.elf_header.e_shstrndx

        self.logger.log_info("mapping ELF sections...")
        if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
            self.logger.log_warn("ELF section header table information is missing or invalid. skipping ELF section mapping")
            return
        if e_shentsize != S_HEADER_SIZE:
            self.logger.log_error(f"unexpected section header entry size: {e_shentsize} bytes (expected {S_HEADER_SIZE})")
            return
        if e_shstrndx >= e_shnum:
            self.logger.log_error(
                f"invalid section header string table index: {e_shstrndx} (must be < number of sections {e_shnum})"
            )
            return

        # Read the section header for the string table first to get section names
        strtab_sheader_file_offset = e_shoff + e_shstrndx * e_shentsize
        if strtab_sheader_file_offset + S_HEADER_SIZE > self.raw_data.length:
            self.logger.log_error("section header string table's own header offset is out of file bounds")
            return
        strtab_sheader_bytes = self.raw_data.read(strtab_sheader_file_offset, S_HEADER_SIZE)
        if len(strtab_sheader_bytes) < S_HEADER_SIZE:
            self.logger.log_error("could not read the full section header for the string table")
            return

        try:
            (
                _sh_name_idx_strtab,
                strtab_sh_type,
                _sh_flags_strtab,
                _sh_addr_strtab,
                strtab_data_file_offset,
                strtab_data_size,
                _sh_link_strtab,
                _sh_info_strtab,
                _sh_addralign_strtab,
                _sh_entsize_strtab,
            ) = struct.unpack(S_HEADER_FORMAT, strtab_sheader_bytes)
        except struct.error as unpack_err:
            self.logger.log_error(f"failed to unpack section header for the string table: {unpack_err}")
            return

        section_names_data_buffer: bytes = b""
        if strtab_sh_type != SHT_STRTAB:
            self.logger.log_warn(
                f"section header string table index {e_shstrndx} does not point to a SHT_STRTAB section"
            )
        elif strtab_data_file_offset + strtab_data_size > self.raw_data.length:
            self.logger.log_error("section header string table data is out of file bounds")
        else:
            section_names_data_buffer = self.raw_data.read(strtab_data_file_offset, strtab_data_size)
            if len(section_names_data_buffer) < strtab_data_size:
                self.logger.log_warn("could not read full section header string table data")

        # Helper function to get a section name string from the string table data buffer
        def get_section_name_from_strtab(name_index: int) -> str:
            if not section_names_data_buffer or name_index >= len(section_names_data_buffer):
                return f"section_{name_index}"
            try:
                null_terminator_pos = section_names_data_buffer.find(b"\x00", name_index)
                if null_terminator_pos == -1:
                    null_terminator_pos = len(section_names_data_buffer)
                return section_names_data_buffer[name_index:null_terminator_pos].decode("utf-8", errors="replace")
            except Exception as decode_err:
                self.logger.log_warn(f"error decoding section name at index {name_index}: {decode_err}")
                return f"section_{name_index}_decode_error"

        # Iterate through all section headers to define sections in Binary Ninja
        for i in range(e_shnum):
            if i == SHT_NULL:
                continue  # section at index 0 (SHT_NULL) is unused
            if i == e_shstrndx and section_names_data_buffer:
                self.logger.log_debug(f"  skipping section {i} as it is the section header string table itself")
                continue

            sh_file_offset = e_shoff + i * e_shentsize
            sh_bytes = self.raw_data.read(sh_file_offset, S_HEADER_SIZE)
            if len(sh_bytes) < S_HEADER_SIZE:
                self.logger.log_error(f"could not read full section header {i}. skipping")
                continue

            try:
                (
                    sh_name_idx,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset_in_file,
                    sh_size,
                    sh_link,
                    sh_info,
                    sh_addralign,
                    sh_entsize,
                ) = struct.unpack(S_HEADER_FORMAT, sh_bytes)
            except struct.error as unpack_err:
                self.logger.log_error(f"failed to unpack section header {i}: {unpack_err}. skipping")
                continue

            # Skip sections that are not allocated in memory or have zero size
            if (not (sh_flags & SHF_ALLOC) and sh_type != SHT_NOBITS) or sh_size == 0:
                self.logger.log_debug(f"  skipping section {i}: not allocated in memory or has zero size")
                continue

            section_name = get_section_name_from_strtab(sh_name_idx)
            bn_section_semantics = SectionSemantics.DefaultSectionSemantics
            bn_section_type_str = ""

            # Determine Binary Ninja section semantics based on ELF section flags and type
            is_code_section = bool(sh_flags & SHF_EXECINSTR)
            is_writable_section = bool(sh_flags & SHF_WRITE)
            is_bss_section_type = sh_type == SHT_NOBITS

            if is_code_section:
                bn_section_semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
                bn_section_type_str = "Code"
            elif is_bss_section_type:
                bn_section_semantics = SectionSemantics.ReadWriteDataSectionSemantics
                bn_section_type_str = "BSS"
            elif sh_type == SHT_PROGBITS:
                if is_writable_section:
                    bn_section_semantics = SectionSemantics.ReadWriteDataSectionSemantics
                    bn_section_type_str = "Data"
                else:
                    bn_section_semantics = SectionSemantics.ReadOnlyDataSectionSemantics
                    bn_section_type_str = "ReadOnlyData"

            self.logger.log_info(
                f"  adding ELF section '{section_name}': VAddr=0x{sh_addr:08x}, Size=0x{sh_size:x}, "
                f"ELFType={sh_type}, ELFFlags=0x{sh_flags:x}, BN_Semantics='{bn_section_semantics.name}'"
            )

            # Provide a warning if a section commonly expected to be code doesn't have executable semantics
            if section_name.startswith(".text") and bn_section_semantics != SectionSemantics.ReadOnlyCodeSectionSemantics:
                self.logger.log_warn(
                    f"section '{section_name}' starts with '.text' but does not have ReadOnlyCodeSectionSemantics"
                )

            try:
                self.add_auto_section(
                    name=section_name,
                    start=sh_addr,
                    length=sh_size,
                    semantics=bn_section_semantics,
                    type=bn_section_type_str,
                    align=int(sh_addralign) if sh_addralign > 0 else 1,
                    entry_size=int(sh_entsize),
                )
            except Exception as sec_add_err:
                self.logger.log_error(f"failed to add section '{section_name}' at vaddr 0x{sh_addr:x}: {sec_add_err}")
        
        self.logger.log_info("finished mapping ELF sections")

    def _define_psp_io_registers(self) -> None:
        """
        Define symbols and tags for known PSP I/O hardware registers.
        """
        self.logger.log_info("defining PSP I/O hardware registers...")
        if not PSP_IO_REGISTERS:
            self.logger.log_info("PSP_IO_REGISTERS list is empty. no PSP-specific I/O registers will be defined")
            return

        defined_count = 0
        for addr, name, tag_name, desc in PSP_IO_REGISTERS:
            self.logger.log_debug(f"  defining I/O register: {name} at 0x{addr:08x} (Category: {tag_name})")
            self._define_hardware_register(addr, name, tag_name, desc)
            defined_count += 1
        self.logger.log_info(f"defined {defined_count}/{len(PSP_IO_REGISTERS)} PSP I/O registers")

    def _define_elf_entry_point(self) -> None:
        """
        Define the program entry point based on the e_entry field from the parsed ELF header.
        """
        if not self.elf_header:
            self.logger.log_error("cannot define ELF entry point, ELF header not parsed or is invalid")
            return

        entry_point_addr = self.elf_header.e_entry
        self.logger.log_info(f"defining program entry point at 0x{entry_point_addr:08x} as specified in ELF header")

        # Validate the entry point address before adding it
        segment_at_entry = self.get_segment_at(entry_point_addr)
        if segment_at_entry:
            self.logger.log_debug(
                f"  entry point 0x{entry_point_addr:08x} is within segment: "
                f"Start=0x{segment_at_entry.start:08x}, Length=0x{segment_at_entry.length:x}, Executable={segment_at_entry.executable}"
            )
            if segment_at_entry.executable:
                self.add_entry_point(entry_point_addr)
                self._primary_entry_point_address = entry_point_addr
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, entry_point_addr, "_start"))
                try:
                    self.add_function(entry_point_addr)
                    self.logger.log_info(f"  successfully added entry point and function hint for '_start' at 0x{entry_point_addr:08x}")
                except Exception as func_add_err:
                    self.logger.log_warn(f"  could not define function hint at entry point: {func_add_err}")
            else:
                self.logger.log_warn(
                    f"  entry point 0x{entry_point_addr:08x} is within a non-executable segment. "
                    "defining as a data symbol '_entry_point_data' instead"
                )
                self.define_auto_symbol(Symbol(SymbolType.DataSymbol, entry_point_addr, "_entry_point_data"))
        else:
            self.logger.log_error(
                f"  entry point 0x{entry_point_addr:08x} from ELF header is not within any mapped memory segment"
            )

    def init(self) -> bool:
        """
        Initialize the PSPView using the refactored architecture.
        """
        if not self.arch or not self.platform:
            self.logger.log_error("critical: architecture or platform is not set. cannot initialize PSPView")
            return False

        try:
            self.logger.log_info(f"starting PSP ELF loading process for '{self.file.filename}'...")

            # Step 1: Parse the ELF header
            if not self._parse_elf_header():
                self.logger.log_error("failed to parse ELF header. aborting PSPView initialization")
                return False

            # Step 2: Define PSP-specific tag types (using inherited method)
            self._initialize_tag_types()

            # Step 3: Map fixed PSP hardware memory regions
            self._map_psp_hardware_memory_regions()

            # Step 4: Map loadable segments (PT_LOAD) from the ELF program header table
            self._map_elf_loadable_segments()

            # Step 5: Define sections based on the ELF section header table
            self._map_elf_sections()

            # Step 6: Define known PSP I/O hardware registers
            self._define_psp_io_registers()

            # Step 7: Define the program entry point from the ELF header
            self._define_elf_entry_point()

            self.logger.log_info("PSP ELF loading and setup steps complete. View is ready for analysis")
            return True

        except Exception as e:
            self.logger.log_error(f"a critical failure occurred during PSPView initialization: {e}")
            return False

    def perform_is_executable(self) -> bool:
        """Indicate that PSP ELF files typically contain executable code."""
        return True

    def perform_get_entry_point(self) -> int:
        """
        Return the primary entry point address of the PSP ELF.
        """
        if self._primary_entry_point_address is not None:
            return self._primary_entry_point_address
        elif self.elf_header:
            self.logger.log_warn(
                "_primary_entry_point_address was not set during init. "
                f"falling back to e_entry directly from parsed ELF header (0x{self.elf_header.e_entry:08x})"
            )
            return self.elf_header.e_entry
        else:
            default_entry = self.start if self.start is not None else 0
            self.logger.log_error(
                "perform_get_entry_point called but no entry point was stored and ELF header is not available. "
                f"returning start of view (0x{default_entry:08x}) as a last resort"
            )
            return default_entry

    def perform_get_address_size(self) -> int:
        """Return the address size for the PSP platform, which is 4 bytes (32-bit addresses)."""
        return 4


# Register the PSPView class with Binary Ninja
PSPView.register()