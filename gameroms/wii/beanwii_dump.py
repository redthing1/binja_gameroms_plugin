import struct
import traceback
from typing import Optional, Dict, List
from dataclasses import dataclass

from binaryninja import (
    BinaryView,
    SegmentFlag,
    SymbolType,
    Symbol,
    TagType,
    Platform,
    Architecture,
    SectionSemantics,
    Endianness,
    log_error,
    log_warn,
    log_info,
    log_debug,
)
from binaryninja.log import Logger

# import wii and gamecube definitions
from .defs import (
    WII_TAG_TYPE_DEFINITIONS,
    WII_IO_REGISTERS,
    WII_GLOBAL_SYMBOLS,
    GAMECUBE_IO_REGISTERS,
)

# - bean dump format constants
WII_DUMP_MAGIC = b"NAEB"
MAGIC_SIZE = len(WII_DUMP_MAGIC)
ENTRY_POINT_FIELD_SIZE = 4
BEAN_DUMP_CURRENT_HEADER_SIZE = MAGIC_SIZE + ENTRY_POINT_FIELD_SIZE

# - default file offsets for memory regions
DEFAULT_MEM1_FILE_OFFSET = BEAN_DUMP_CURRENT_HEADER_SIZE
DEFAULT_MEM2_FILE_OFFSET = DEFAULT_MEM1_FILE_OFFSET + (24 * 1024 * 1024)

# - expected full memory sizes
FULL_MEM1_SIZE = 24 * 1024 * 1024
FULL_MEM2_SIZE = 64 * 1024 * 1024
MIN_VALID_DUMP_FILE_SIZE = BEAN_DUMP_CURRENT_HEADER_SIZE + 1

# - wii memory map constants (ppc virtual addresses unless noted)
MEM1_BASE_ADDR = 0x80000000
MEM1_SIZE = FULL_MEM1_SIZE
MEM2_BASE_ADDR = 0x90000000
MEM2_SIZE = FULL_MEM2_SIZE
MEM1_UNCACHED_BASE_ADDR = 0xC0000000
MEM1_UNCACHED_SIZE = FULL_MEM1_SIZE
MEM2_UNCACHED_BASE_ADDR = 0xD0000000
MEM2_UNCACHED_SIZE = FULL_MEM2_SIZE

# - wii hollywood i/o
HOLLYWOOD_IO_VIRTUAL_BASE_ADDR = 0xCD000000
HOLLYWOOD_IO_SIZE = 0x8000  # main 32kb block
HOLLYWOOD_IO_PHYSICAL_DIRECT_BASE_ADDR = 0x0D000000
HOLLYWOOD_IO_PHYSICAL_STARLET_BASE_ADDR = 0x0D800000
MEM_PROT_VIRTUAL_AREA_BASE_ADDR = 0xCD0B4200
MEM_PROT_PHYSICAL_STARLET_AREA_BASE_ADDR = 0x0D8B4200
MEM_PROT_AREA_SIZE = 0x100  # covers known mem_prot registers

# - gamecube hardware i/o (direct ppc access)
GAMECUBE_MMIO_BASE_ADDR = 0xCC000000
# covers 0xCC000000 (CP) to 0xCC008000 (GX FIFO), rounded up for a simple segment.
# yagcd shows CP (0x80), PE (0x100), VI (0x100), PI (0x100), MI (0x80), DSP (0x200), DI (0x40), SI (0x100), GXFIFO (0x04)
# largest block is DSP at 0xCC005000. GX FIFO is at 0xCC008000.
# a 64kb segment (0x10000) covers all these distinct blocks.
GAMECUBE_MMIO_SIZE = 0x10000

# - wii broadway cpu internal registers (physical)
BROADWAY_REGS_PHYSICAL_BASE_ADDR = 0x0C000000
BROADWAY_REGS_SIZE = 0x8000  # typically 32kb

# - wii boot rom / ipl
BOOT_ROM_ALIAS_BASE_ADDR = 0xFFF00000
BOOT_ROM_ALIAS_SIZE = 0x00100000

FALLBACK_DEFAULT_ENTRY_POINT = 0x80003F00


@dataclass
class BeanDumpHeader:
    magic: bytes = b""
    entry_point: int = 0


class BeanWiiDumpView(BinaryView):
    name = "BeanWii"
    long_name = "BeanWii Dump"

    PERM_RWX = (
        SegmentFlag.SegmentReadable
        | SegmentFlag.SegmentWritable
        | SegmentFlag.SegmentExecutable
    )
    PERM_RW = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    PERM_RX = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
    PERM_R = SegmentFlag.SegmentReadable

    def __init__(self, data: BinaryView):
        super().__init__(file_metadata=data.file, parent_view=data)
        self.logger: Logger = self.create_logger(self.name)
        self.raw_data: BinaryView = data
        self._created_tag_types: Dict[str, TagType] = {}
        self._primary_entry_point_address: Optional[int] = None
        self.parsed_header: Optional[BeanDumpHeader] = None

        try:
            # wii's broadway cpu is a powerpc variant (ppc_ps for paired singles).
            self.arch = Architecture["ppc_ps"]
            if not self.arch:
                self.logger.log_error(
                    "ppc_ps architecture definition not found in binary ninja. "
                    "this is required for wii/gc analysis."
                )
                raise RuntimeError("ppc_ps architecture definition not found.")

            # wii/gc is big-endian.
            if self.arch.endianness != Endianness.BigEndian:
                self.logger.log_warn(
                    f"selected architecture '{self.arch.name}' reports endianness {self.arch.endianness.name}, "
                    "but wii/gc (powerpc) is big-endian. disassembly or data interpretation might be incorrect if "
                    "the architecture definition does not correctly enforce big-endian behavior."
                )

            self.platform = self.arch.standalone_platform
            if not self.platform:
                self.logger.log_error(
                    f"could not get standalone platform for architecture '{self.arch.name}'. "
                    "analysis might lack platform-specific features."
                )
                raise RuntimeError(
                    f"failed to get standalone platform for {self.arch.name}."
                )

            self.logger.log_info(
                f"using platform: {self.platform.name}, architecture: {self.arch.name}"
            )

        except KeyError:
            self.logger.log_error(
                "ppc_ps architecture key not found in binary ninja. wii/gc analysis requires it."
            )
            raise RuntimeError("ppc_ps architecture key not found.")
        except Exception as e:
            self.logger.log_error(
                f"critical error during architecture or platform setup: {e}\n{traceback.format_exc()}"
            )
            raise

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        if data.length < BEAN_DUMP_CURRENT_HEADER_SIZE:
            log_debug(f"[{cls.name}] validation: data too short for header.")
            return False
        magic_bytes = data.read(0, MAGIC_SIZE)
        if magic_bytes != WII_DUMP_MAGIC:
            log_debug(f"[{cls.name}] validation: invalid magic bytes.")
            return False
        if data.length < MIN_VALID_DUMP_FILE_SIZE:
            log_warn(
                f"[{cls.name}] validation: file has magic but is too short for memory data."
            )
            return False
        log_info(
            f"[{cls.name}] validation: identified as a potential bean wii/gc dump."
        )
        return True

    def _parse_bean_dump_header(self) -> bool:
        self.logger.log_info("parsing bean dump header...")
        if self.raw_data.length < BEAN_DUMP_CURRENT_HEADER_SIZE:
            self.logger.log_error(f"file is too small for the bean dump header.")
            return False
        header_data = self.raw_data.read(0, BEAN_DUMP_CURRENT_HEADER_SIZE)
        if len(header_data) < BEAN_DUMP_CURRENT_HEADER_SIZE:
            self.logger.log_error("could not read the full header data from file.")
            return False
        try:
            magic = header_data[:MAGIC_SIZE]
            if magic != WII_DUMP_MAGIC:
                self.logger.log_error("magic bytes mismatch during parsing stage.")
                return False
            # entry point is a 4-byte little-endian unsigned integer (custom dump)
            entry_point_raw = struct.unpack_from("<I", header_data, MAGIC_SIZE)[0]
            self.parsed_header = BeanDumpHeader(
                magic=magic, entry_point=entry_point_raw
            )
            self.logger.log_info(
                f"bean dump header parsed: magic='{self.parsed_header.magic.decode()}', "
                f"entry_point=0x{self.parsed_header.entry_point:08x}"
            )
            return True
        except struct.error as e:
            self.logger.log_error(f"error unpacking header data (entry point): {e}")
            return False
        except Exception as e:
            self.logger.log_error(
                f"unexpected error parsing bean dump header: {e}\n{traceback.format_exc()}"
            )
            return False

    def _initialize_tag_types(self) -> None:
        self.logger.log_info("initializing wii/gamecube-specific tag types...")
        initialized_count = 0
        for name, icon in WII_TAG_TYPE_DEFINITIONS.items():
            if self._get_or_create_tag_type(name, icon):
                initialized_count += 1
        self.logger.log_info(
            f"initialized {initialized_count}/{len(WII_TAG_TYPE_DEFINITIONS)} tag types."
        )

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        name_lower = name.lower()
        if name_lower in self._created_tag_types:
            return self._created_tag_types[name_lower]
        existing_tag_type = self.get_tag_type(name)
        if existing_tag_type:
            self._created_tag_types[name_lower] = existing_tag_type
            return existing_tag_type
        try:
            new_tag_type = self.create_tag_type(name, icon)
            self._created_tag_types[name_lower] = new_tag_type
            return new_tag_type
        except Exception as e:
            self.logger.log_error(
                f"failed to create tag type '{name}': {e}\n{traceback.format_exc()}"
            )
            return None

    def _map_wii_hardware_and_fixed_regions(self) -> None:
        self.logger.log_info(
            "mapping fixed wii & gamecube hardware memory regions (not from dump file)..."
        )

        # - mem1 uncached mirror (0xc0000000 - 0xc17fffff, 24mb)
        self.add_auto_segment(
            MEM1_UNCACHED_BASE_ADDR, MEM1_UNCACHED_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            MEM1_UNCACHED_BASE_ADDR,
            "Wii/GameCube MEM1 (Main RAM, 24MB, Uncached Mirror)",
        )
        tag_mem1u = self._get_or_create_tag_type(
            "MEM1", WII_TAG_TYPE_DEFINITIONS.get("MEM1", "💾")
        )
        if tag_mem1u:
            self.add_tag(
                MEM1_UNCACHED_BASE_ADDR, tag_mem1u.name, "MEM1 Uncached Mirror"
            )

        # - mem2 uncached mirror (0xd0000000 - 0xd3ffffff, 64mb) - wii only
        self.add_auto_segment(
            MEM2_UNCACHED_BASE_ADDR, MEM2_UNCACHED_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            MEM2_UNCACHED_BASE_ADDR, "Wii MEM2 (Aux RAM, 64MB, Uncached Mirror)"
        )
        tag_mem2u = self._get_or_create_tag_type(
            "MEM2", WII_TAG_TYPE_DEFINITIONS.get("MEM2", "🗳️")
        )
        if tag_mem2u:
            self.add_tag(
                MEM2_UNCACHED_BASE_ADDR, tag_mem2u.name, "MEM2 Uncached Mirror"
            )

        # - wii hollywood i/o registers (ppc virtual view: 0xcd000000 - 0xcd007fff)
        self.add_auto_segment(
            HOLLYWOOD_IO_VIRTUAL_BASE_ADDR, HOLLYWOOD_IO_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            HOLLYWOOD_IO_VIRTUAL_BASE_ADDR,
            "Wii Hollywood I/O Registers (PPC Virtual View - Primary Access)",
        )
        tag_hwio_virt = self._get_or_create_tag_type(
            "Hollywood Register",
            WII_TAG_TYPE_DEFINITIONS.get("Hollywood Register", "🎬"),
        )
        if tag_hwio_virt:
            self.add_tag(
                HOLLYWOOD_IO_VIRTUAL_BASE_ADDR,
                tag_hwio_virt.name,
                "Hollywood I/O (PPC Virtual) Block",
            )

        # - wii hollywood i/o registers (physical - direct/ppc subset view: 0x0d000000 - 0x0d007fff)
        self.add_auto_segment(
            HOLLYWOOD_IO_PHYSICAL_DIRECT_BASE_ADDR,
            HOLLYWOOD_IO_SIZE,
            0,
            0,
            self.PERM_RW,
        )
        self.set_comment_at(
            HOLLYWOOD_IO_PHYSICAL_DIRECT_BASE_ADDR,
            "Wii Hollywood I/O Registers (Physical - Direct/PPC Subset View)",
        )
        if tag_hwio_virt:
            self.add_tag(
                HOLLYWOOD_IO_PHYSICAL_DIRECT_BASE_ADDR,
                tag_hwio_virt.name,
                "Hollywood I/O (Physical Direct) Block",
            )

        # - wii hollywood i/o registers (physical - starlet full access view: 0x0d800000 - 0x0d807fff)
        self.add_auto_segment(
            HOLLYWOOD_IO_PHYSICAL_STARLET_BASE_ADDR,
            HOLLYWOOD_IO_SIZE,
            0,
            0,
            self.PERM_RW,
        )
        self.set_comment_at(
            HOLLYWOOD_IO_PHYSICAL_STARLET_BASE_ADDR,
            "Wii Hollywood I/O Registers (Physical - Starlet Full Access View)",
        )
        if tag_hwio_virt:
            self.add_tag(
                HOLLYWOOD_IO_PHYSICAL_STARLET_BASE_ADDR,
                tag_hwio_virt.name,
                "Hollywood I/O (Physical Starlet) Block",
            )

        # - wii mem_prot registers area (ppc virtual view: e.g., 0xcd0b4200 - 0xcd0b42ff)
        self.add_auto_segment(
            MEM_PROT_VIRTUAL_AREA_BASE_ADDR, MEM_PROT_AREA_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            MEM_PROT_VIRTUAL_AREA_BASE_ADDR,
            "Wii MEM_PROT Registers Area (PPC Virtual View)",
        )
        tag_mem_iface = self._get_or_create_tag_type(
            "Memory Interface", WII_TAG_TYPE_DEFINITIONS.get("Memory Interface", "🐏")
        )
        if tag_mem_iface:
            self.add_tag(
                MEM_PROT_VIRTUAL_AREA_BASE_ADDR,
                tag_mem_iface.name,
                "MEM_PROT Area (PPC Virtual)",
            )

        # - wii mem_prot registers area (physical - starlet view: e.g., 0x0d8b4200 - 0x0d8b42ff)
        self.add_auto_segment(
            MEM_PROT_PHYSICAL_STARLET_AREA_BASE_ADDR,
            MEM_PROT_AREA_SIZE,
            0,
            0,
            self.PERM_RW,
        )
        self.set_comment_at(
            MEM_PROT_PHYSICAL_STARLET_AREA_BASE_ADDR,
            "Wii MEM_PROT Registers Area (Physical - Starlet View)",
        )
        if tag_mem_iface:
            self.add_tag(
                MEM_PROT_PHYSICAL_STARLET_AREA_BASE_ADDR,
                tag_mem_iface.name,
                "MEM_PROT Area (Physical Starlet)",
            )

        # - gamecube mmio block (0xcc000000 - 0xcc00ffff)
        self.add_auto_segment(
            GAMECUBE_MMIO_BASE_ADDR, GAMECUBE_MMIO_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            GAMECUBE_MMIO_BASE_ADDR,
            "GameCube MMIO Registers Block (CP, PE, VI, PI, MI, DSP, DI, SI, EXI, GXFIFO)",
        )
        tag_gc_mmio_block = self._get_or_create_tag_type(
            "Hardware Register", WII_TAG_TYPE_DEFINITIONS.get("Hardware Register", "🔩")
        )
        if tag_gc_mmio_block:
            self.add_tag(
                GAMECUBE_MMIO_BASE_ADDR, tag_gc_mmio_block.name, "GameCube MMIO Block"
            )

        # - wii broadway cpu internal registers (physical view: 0x0c000000 - 0x0c007fff)
        self.add_auto_segment(
            BROADWAY_REGS_PHYSICAL_BASE_ADDR, BROADWAY_REGS_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            BROADWAY_REGS_PHYSICAL_BASE_ADDR,
            "Wii Broadway CPU Internal Registers (Physical View - SPRs, etc.)",
        )
        tag_bway_regs = self._get_or_create_tag_type(
            "Broadway Register", WII_TAG_TYPE_DEFINITIONS.get("Broadway Register", "⚙️")
        )
        if tag_bway_regs:
            self.add_tag(
                BROADWAY_REGS_PHYSICAL_BASE_ADDR,
                tag_bway_regs.name,
                "Broadway CPU Registers (Physical)",
            )

        # - wii/gc boot rom / ipl alias (0xfff00000 - 0xffffffff, 1mb)
        self.add_auto_segment(
            BOOT_ROM_ALIAS_BASE_ADDR, BOOT_ROM_ALIAS_SIZE, 0, 0, self.PERM_RX
        )
        self.set_comment_at(
            BOOT_ROM_ALIAS_BASE_ADDR, "Wii/GameCube Boot ROM / IPL Alias (1MB)"
        )
        tag_bootrom = self._get_or_create_tag_type(
            "Memory Region", WII_TAG_TYPE_DEFINITIONS.get("Memory Region", "🗺️")
        )
        if tag_bootrom:
            self.add_tag(BOOT_ROM_ALIAS_BASE_ADDR, tag_bootrom.name, "Boot ROM Alias")

        ppc_reset_vector_addr = BOOT_ROM_ALIAS_BASE_ADDR + 0x100
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, ppc_reset_vector_addr, "_ResetVector_IPL")
        )
        self.set_comment_at(ppc_reset_vector_addr, "PowerPC Reset Vector (in IPL)")
        tag_vector = self._get_or_create_tag_type(
            "Exception Vector", WII_TAG_TYPE_DEFINITIONS.get("Exception Vector", "❗")
        )
        if tag_vector:
            self.add_tag(ppc_reset_vector_addr, tag_vector.name, "IPL Reset Vector")

        self.logger.log_info("finished mapping fixed hardware memory regions.")

    def _map_dumped_memory_segments(self) -> None:
        self.logger.log_info("mapping dumped memory segments (mem1, mem2) from file...")
        if not self.parsed_header:
            self.logger.log_error("header not parsed, cannot map dumped segments.")
            raise RuntimeError("internal error: parsed_header is none.")

        mem1_file_offset_in_dump = DEFAULT_MEM1_FILE_OFFSET
        mem2_file_offset_in_dump = DEFAULT_MEM2_FILE_OFFSET
        available_data_for_mem1 = 0
        if self.raw_data.length > mem1_file_offset_in_dump:
            available_data_for_mem1 = self.raw_data.length - mem1_file_offset_in_dump
        actual_mem1_size_to_map = min(FULL_MEM1_SIZE, available_data_for_mem1)

        if actual_mem1_size_to_map > 0:
            self.add_auto_segment(
                MEM1_BASE_ADDR,
                actual_mem1_size_to_map,
                mem1_file_offset_in_dump,
                actual_mem1_size_to_map,
                self.PERM_RWX,
            )
            self.add_auto_section(
                ".mem1",
                MEM1_BASE_ADDR,
                actual_mem1_size_to_map,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )
            self.set_comment_at(
                MEM1_BASE_ADDR,
                f"Wii/GameCube MEM1 (Dumped, Size: 0x{actual_mem1_size_to_map:X})",
            )
            tag_mem1 = self._get_or_create_tag_type(
                "MEM1", WII_TAG_TYPE_DEFINITIONS.get("MEM1", "💾")
            )
            if tag_mem1:
                self.add_tag(MEM1_BASE_ADDR, tag_mem1.name, "MEM1 (Primary) Start")
            if actual_mem1_size_to_map < FULL_MEM1_SIZE:
                self.logger.log_warn(
                    f"mem1 dump is partial: mapped 0x{actual_mem1_size_to_map:x} bytes."
                )
        else:
            self.logger.log_error("no data available in dump for mem1.")
            raise RuntimeError("mem1 data missing in dump file.")

        available_data_for_mem2 = 0
        if self.raw_data.length > mem2_file_offset_in_dump:
            available_data_for_mem2 = self.raw_data.length - mem2_file_offset_in_dump
        actual_mem2_size_to_map = min(FULL_MEM2_SIZE, available_data_for_mem2)

        if actual_mem2_size_to_map > 0:  # mem2 is wii-specific
            self.add_auto_segment(
                MEM2_BASE_ADDR,
                actual_mem2_size_to_map,
                mem2_file_offset_in_dump,
                actual_mem2_size_to_map,
                self.PERM_RWX,
            )
            self.add_auto_section(
                ".mem2",
                MEM2_BASE_ADDR,
                actual_mem2_size_to_map,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )
            self.set_comment_at(
                MEM2_BASE_ADDR,
                f"Wii MEM2 (Dumped, Size: 0x{actual_mem2_size_to_map:X})",
            )
            tag_mem2 = self._get_or_create_tag_type(
                "MEM2", WII_TAG_TYPE_DEFINITIONS.get("MEM2", "🗳️")
            )
            if tag_mem2:
                self.add_tag(MEM2_BASE_ADDR, tag_mem2.name, "MEM2 (Primary) Start")
            if actual_mem2_size_to_map < FULL_MEM2_SIZE:
                self.logger.log_warn(
                    f"mem2 dump is partial: mapped 0x{actual_mem2_size_to_map:x} bytes."
                )
        else:
            self.logger.log_info(
                "no data found for mem2 in dump file (or not a wii dump)."
            )
        self.logger.log_info("finished mapping dumped memory segments.")

    def _define_hardware_register(
        self,
        address: int,
        name: str,
        tag_category_name: str,
        description: str,
        size_bits: int,
    ):
        c_type_base = ""
        if size_bits == 8:
            c_type_base = "uint8_t"
        elif size_bits == 16:
            c_type_base = "uint16_t"
        elif size_bits == 32:
            c_type_base = "uint32_t"
        elif size_bits == (0x80 * 8):
            c_type_base = "uint8_t"  # special case for si_io_buffer
        else:
            self.logger.log_warn(
                f"unsupported size_bits {size_bits} for register '{name}' at 0x{address:08x}. defaulting to uint32_t."
            )
            c_type_base = "uint32_t"

        if name == "SI_IO_BUFFER" and size_bits == (0x80 * 8):
            mmio_type_declaration = f"volatile uint8_t {name}_reg_type[0x80];"
        else:
            mmio_type_declaration = f"volatile {c_type_base} {name}_reg_type;"

        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))
        if description:
            self.set_comment_at(address, description)

        try:
            parsed_type, _ = self.parse_type_string(mmio_type_declaration)
            if parsed_type:
                if self.get_data_var_at(address) is None:
                    self.define_user_data_var(address, parsed_type)
                    self.logger.log_debug(
                        f"  defined mmio register '{name}' at 0x{address:08x} as '{mmio_type_declaration.split(' ')[0]} {c_type_base}'."
                    )
                else:
                    self.logger.log_debug(
                        f"  data var exists at 0x{address:08x} for '{name}'. type not overridden."
                    )
            else:
                self.logger.log_warn(
                    f"could not parse '{mmio_type_declaration}' for '{name}'."
                )
        except Exception as e:
            self.logger.log_warn(
                f"failed to define mmio register '{name}' as '{c_type_base}': {e}"
            )

        tag_icon = WII_TAG_TYPE_DEFINITIONS.get(tag_category_name, "🔩")
        tag_type_object = self._get_or_create_tag_type(tag_category_name, tag_icon)
        if tag_type_object:
            self.add_tag(address, tag_type_object.name, data=name)
        else:
            self.logger.log_warn(
                f"could not get/create tag type '{tag_category_name}' for '{name}'."
            )

    def _define_wii_io_registers(self) -> None:
        self.logger.log_info(
            "defining wii i/o hardware registers (at ppc virtual addresses)..."
        )
        if not WII_IO_REGISTERS:
            self.logger.log_info("  wii_io_registers list from defs.py is empty.")
            return
        defined_count = 0
        for addr, name, tag_category, desc, size_bits in WII_IO_REGISTERS:
            segment = self.get_segment_at(addr)
            if segment and (segment.readable or segment.writable):
                self._define_hardware_register(
                    addr, name, tag_category, desc, size_bits
                )
                defined_count += 1
            else:
                self.logger.log_debug(
                    f"  skipping wii i/o register '{name}' at 0x{addr:08x}: address not in a mapped r/w segment."
                )
        self.logger.log_info(
            f"defined {defined_count}/{len(WII_IO_REGISTERS)} wii i/o registers."
        )

    def _define_gamecube_io_registers(self) -> None:
        self.logger.log_info(
            "defining gamecube i/o hardware registers (at 0xCC00xxxx)..."
        )
        if not GAMECUBE_IO_REGISTERS:
            self.logger.log_info("  gamecube_io_registers list from defs.py is empty.")
            return
        defined_count = 0
        for addr, name, tag_category, desc, size_bits in GAMECUBE_IO_REGISTERS:
            segment = self.get_segment_at(addr)
            if segment and (segment.readable or segment.writable):
                self._define_hardware_register(
                    addr, name, tag_category, desc, size_bits
                )
                defined_count += 1
            else:
                self.logger.log_debug(
                    f"  skipping gamecube i/o register '{name}' at 0x{addr:08x}: address not in a mapped r/w segment."
                )
        self.logger.log_info(
            f"defined {defined_count}/{len(GAMECUBE_IO_REGISTERS)} gamecube i/o registers."
        )

    def _define_wii_global_symbols(self) -> None:
        self.logger.log_info(
            "defining wii global symbols and data variables (typically located in mem1)..."
        )
        if not WII_GLOBAL_SYMBOLS:
            self.logger.log_info("  wii_global_symbols list from defs.py is empty.")
            return
        defined_count = 0
        for addr, name, tag_category, desc, type_str in WII_GLOBAL_SYMBOLS:
            segment = self.get_segment_at(addr)
            if segment:
                self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))
                if desc:
                    self.set_comment_at(addr, desc)
                tag_icon = WII_TAG_TYPE_DEFINITIONS.get(tag_category, "🌍")
                tag_type_obj = self._get_or_create_tag_type(tag_category, tag_icon)
                if tag_type_obj:
                    self.add_tag(addr, tag_type_obj.name, data=name)

                if type_str:
                    try:
                        c_decl_for_parsing = type_str
                        if (
                            " " not in type_str
                            and "[" not in type_str
                            and "*" not in type_str
                            and "(" not in type_str
                        ):
                            c_decl_for_parsing = f"{type_str} {name}_global_var_type"
                        elif type_str.endswith("()") and not type_str.startswith(
                            "(*"
                        ):  # e.g. "void()"
                            base_return_type = type_str[:-2]
                            c_decl_for_parsing = (
                                f"{base_return_type} (*{name}_func_ptr_type)()"
                            )

                        if not c_decl_for_parsing.strip().endswith(";"):
                            c_decl_for_parsing += ";"

                        parsed_type, _ = self.parse_type_string(c_decl_for_parsing)
                        if parsed_type:
                            if self.get_data_var_at(addr) is None:
                                self.define_user_data_var(addr, parsed_type)
                            else:
                                self.logger.log_debug(
                                    f"data variable already exists at 0x{addr:08x}, not redefining type for '{name}'."
                                )
                        else:
                            self.logger.log_warn(
                                f"could not parse type string '{c_decl_for_parsing}' for global symbol '{name}'."
                            )
                    except Exception as e:
                        self.logger.log_warn(
                            f"failed to parse or define type '{type_str}' for global symbol '{name}' at 0x{addr:08x}: {e}"
                        )
                defined_count += 1
            else:
                self.logger.log_debug(
                    f"  skipping global symbol '{name}' at 0x{addr:08x}: address not in any mapped segment."
                )
        self.logger.log_info(
            f"defined {defined_count}/{len(WII_GLOBAL_SYMBOLS)} wii global symbols."
        )

    def _define_entry_point(self) -> None:
        entry_point_to_use = FALLBACK_DEFAULT_ENTRY_POINT
        entry_point_source = "fallback default"
        if self.parsed_header and self.parsed_header.entry_point != 0:
            entry_point_to_use = self.parsed_header.entry_point
            entry_point_source = "header"
        self.logger.log_info(
            f"using entry point 0x{entry_point_to_use:08x} (from {entry_point_source})."
        )

        segment_at_entry = self.get_segment_at(entry_point_to_use)
        if segment_at_entry and segment_at_entry.executable:
            self._primary_entry_point_address = entry_point_to_use
            self.add_entry_point(self._primary_entry_point_address)
            self.define_auto_symbol(
                Symbol(
                    SymbolType.FunctionSymbol,
                    self._primary_entry_point_address,
                    "_start",
                )
            )
            try:
                self.add_function(self._primary_entry_point_address)
                self.logger.log_info(
                    f"defined entry point and function '_start' at 0x{self._primary_entry_point_address:08x}."
                )
            except Exception as e:
                self.logger.log_warn(
                    f"could not create function at entry point 0x{self._primary_entry_point_address:08x}: {e}. entry point symbol still added."
                )
        else:
            self.logger.log_warn(
                f"chosen entry point 0x{entry_point_to_use:08x} (from {entry_point_source}) is not within a mapped executable segment. no primary entry point set."
            )
            self._primary_entry_point_address = None

    def init(self) -> bool:
        try:
            self.logger.log_info(
                f"starting wii/gc dump ('{self.name}') loading process for '{self.file.filename}'..."
            )
            if not self._parse_bean_dump_header():
                self.logger.log_error(
                    "failed to parse bean dump header. aborting load."
                )
                return False
            self._initialize_tag_types()
            self._map_wii_hardware_and_fixed_regions()
            self._map_dumped_memory_segments()
            self._define_wii_io_registers()
            self._define_gamecube_io_registers()
            self._define_wii_global_symbols()
            self._define_entry_point()
            self.logger.log_info(
                "wii/gc memory dump loading and setup steps complete. triggering analysis..."
            )
            self.update_analysis()
            return True
        except Exception as e:
            self.logger.log_error(
                f"a critical failure occurred during wii/gc memory dump initialization: {e}\n{traceback.format_exc()}"
            )
            return False

    def perform_get_entry_point(self) -> int:
        if self._primary_entry_point_address is not None:
            return self._primary_entry_point_address
        if self.entry_points:
            self.logger.log_warn(
                "loader's primary entry point not set or invalid. falling back to the first entry point in binary ninja's list."
            )
            return self.entry_points[0]
        self.logger.log_warn(
            f"no valid entry point found. falling back to start of mem1 (0x{MEM1_BASE_ADDR:08x}) or view start."
        )
        mem1_segment = self.get_segment_at(MEM1_BASE_ADDR)
        if mem1_segment:
            return mem1_segment.start
        return self.start if self.start is not None else 0

    def perform_get_address_size(self) -> int:
        return 4  # wii/gc uses 32-bit addresses

    def perform_is_executable(self) -> bool:
        return True


BeanWiiDumpView.register()
