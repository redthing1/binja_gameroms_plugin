# PATH: gameroms/wii/wiirom.py
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

# import wii definitions. these provide hardware register addresses, memory map details,
# and known global symbol locations essential for wii analysis.
from .defs import WII_TAG_TYPE_DEFINITIONS, WII_IO_REGISTERS, WII_GLOBAL_SYMBOLS

# - bean dump format constants
WII_DUMP_MAGIC = b"NAEB"  # bean backwards because big endian sucks
MAGIC_SIZE = len(WII_DUMP_MAGIC)
ENTRY_POINT_FIELD_SIZE = 4  # 4-byte entry point address field

# current total size of the "bean" dump header.
# this will need to be updated if more fields are added to the header.
BEAN_DUMP_CURRENT_HEADER_SIZE = MAGIC_SIZE + ENTRY_POINT_FIELD_SIZE

# - default file offsets for memory regions within the dump file.
# these are used if a future, more complex header doesn't specify them.
# assumes mem1 data immediately follows the header, then mem2 data.
DEFAULT_MEM1_FILE_OFFSET = BEAN_DUMP_CURRENT_HEADER_SIZE
DEFAULT_MEM2_FILE_OFFSET = DEFAULT_MEM1_FILE_OFFSET + (
    24 * 1024 * 1024
)  # 24mb after mem1 start

# expected full sizes for mem1 and mem2, used for mapping and checks for partial dumps.
FULL_MEM1_SIZE = 24 * 1024 * 1024  # 24mb
FULL_MEM2_SIZE = 64 * 1024 * 1024  # 64mb

# minimum valid dump file size: requires the full header and at least one byte of actual memory data.
MIN_VALID_DUMP_FILE_SIZE = BEAN_DUMP_CURRENT_HEADER_SIZE + 1

# - wii memory map constants (ppc virtual addresses)
# these define the standard wii memory layout.
# primary ram regions (typically accessed via their cached addresses by the cpu).
MEM1_BASE_ADDR = 0x80000000
MEM1_SIZE = FULL_MEM1_SIZE  # address space size for mem1
MEM2_BASE_ADDR = 0x90000000
MEM2_SIZE = FULL_MEM2_SIZE  # address space size for mem2

# uncached mirrors of mem1 and mem2. these are fixed hardware mappings.
MEM1_UNCACHED_BASE_ADDR = 0xC0000000
MEM1_UNCACHED_SIZE = FULL_MEM1_SIZE
MEM2_UNCACHED_BASE_ADDR = 0xD0000000
MEM2_UNCACHED_SIZE = FULL_MEM2_SIZE

# hardware i/o: main hollywood mmio block.
HOLLYWOOD_IO_BASE_ADDR = 0xCD000000
HOLLYWOOD_IO_SIZE = 0x8000  # 32kb block

# boot rom / ipl (initial program load) high-memory alias.
# the physical boot rom is mapped here for the ppc.
BOOT_ROM_ALIAS_BASE_ADDR = 0xFFF00000
BOOT_ROM_ALIAS_SIZE = (
    0x00100000  # 1mb, covering standard ppc reset vectors (e.g., 0xfff00100)
)

# fallback default entry point if the header doesn't specify a valid one.
# this address is the start of the "standard application executable area" in mem1.
FALLBACK_DEFAULT_ENTRY_POINT = 0x80003F00


# - dataclass for parsed header information
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
                    "this is required for wii analysis."
                )
                raise RuntimeError("ppc_ps architecture definition not found.")

            # wii is big-endian. verify the selected architecture's default.
            if self.arch.endianness != Endianness.BigEndian:
                self.logger.log_warn(
                    f"selected architecture '{self.arch.name}' reports endianness {self.arch.endianness.name}, "
                    "but wii (powerpc) is big-endian. disassembly or data interpretation might be incorrect if "
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
                "ppc_ps architecture key not found in binary ninja. wii analysis requires it."
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
            log_debug(
                f"[{cls.name}] validation: data too short for header "
                f"(size: {data.length} bytes, requires: {BEAN_DUMP_CURRENT_HEADER_SIZE} bytes)."
            )
            return False

        magic_bytes = data.read(0, MAGIC_SIZE)
        if magic_bytes != WII_DUMP_MAGIC:
            log_debug(
                f"[{cls.name}] validation: invalid magic bytes {magic_bytes!r}, expected {WII_DUMP_MAGIC!r}."
            )
            return False

        if data.length < MIN_VALID_DUMP_FILE_SIZE:
            log_warn(
                f"[{cls.name}] validation: file has '{WII_DUMP_MAGIC.decode()}' magic but is too short "
                f"(size: {data.length} bytes, min required with data: {MIN_VALID_DUMP_FILE_SIZE} bytes) "
                "to contain any actual memory data. treating as invalid."
            )
            return False

        log_info(
            f"[{cls.name}] validation: found '{WII_DUMP_MAGIC.decode()}' magic and basic size requirements met. "
            "identified as a potential bean wii dump."
        )
        return True

    def _parse_bean_dump_header(self) -> bool:
        self.logger.log_info("parsing bean dump header...")
        if self.raw_data.length < BEAN_DUMP_CURRENT_HEADER_SIZE:
            self.logger.log_error(
                f"file is too small (size: {self.raw_data.length} bytes) for the bean dump header "
                f"(requires: {BEAN_DUMP_CURRENT_HEADER_SIZE} bytes)."
            )
            return False

        header_data = self.raw_data.read(0, BEAN_DUMP_CURRENT_HEADER_SIZE)
        if len(header_data) < BEAN_DUMP_CURRENT_HEADER_SIZE:
            self.logger.log_error("could not read the full header data from file.")
            return False

        try:
            magic = header_data[:MAGIC_SIZE]
            # this check is slightly redundant if is_valid_for_data passed, but ensures consistency.
            if magic != WII_DUMP_MAGIC:
                self.logger.log_error(
                    "magic bytes mismatch during parsing stage. "
                    "this should have been caught by is_valid_for_data."
                )
                return False

            # entry point is a 4-byte big-endian unsigned integer immediately following the magic bytes.
            entry_point_raw = struct.unpack_from(">I", header_data, MAGIC_SIZE)[0]

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
        except Exception as e:  # catch any other unexpected errors during parsing
            self.logger.log_error(
                f"unexpected error parsing bean dump header: {e}\n{traceback.format_exc()}"
            )
            return False

    def _initialize_tag_types(self) -> None:
        self.logger.log_info("initializing wii-specific tag types...")
        initialized_count = 0
        total_to_define = len(WII_TAG_TYPE_DEFINITIONS)
        for name, icon in WII_TAG_TYPE_DEFINITIONS.items():
            if self._get_or_create_tag_type(name, icon):
                initialized_count += 1
            else:
                self.logger.log_warn(
                    f"could not initialize wii tag type: '{name}' with icon '{icon}'."
                )
        self.logger.log_info(
            f"initialized {initialized_count}/{total_to_define} wii tag types."
        )

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        name_lower = name.lower()
        if name_lower in self._created_tag_types:
            self.logger.log_debug(f"retrieved cached tag type: '{name}'.")
            return self._created_tag_types[name_lower]

        existing_tag_type = self.get_tag_type(name)
        if existing_tag_type:
            self.logger.log_debug(
                f"found existing tag type in binaryview: '{name}'. caching it."
            )
            self._created_tag_types[name_lower] = existing_tag_type
            return existing_tag_type

        try:
            self.logger.log_debug(
                f"creating new tag type: '{name}' with icon '{icon}'."
            )
            new_tag_type = self.create_tag_type(name, icon)
            self._created_tag_types[name_lower] = new_tag_type
            return new_tag_type
        except Exception as e:
            self.logger.log_error(
                f"failed to create tag type '{name}': {e}\n{traceback.format_exc()}"
            )
            return None

    def _map_wii_hardware_and_fixed_regions(self) -> None:
        """
        maps fixed hardware regions of the wii that are not part of the dump file,
        such as i/o ports, memory mirrors, and the boot rom alias.
        these segments are not file-backed (file_offset=0, file_length=0).
        """
        self.logger.log_info(
            "mapping fixed wii hardware memory regions (not from dump file)..."
        )

        # mem1 uncached mirror (0xc0000000 - 0xc17fffff, 24mb)
        self.add_auto_segment(
            MEM1_UNCACHED_BASE_ADDR, MEM1_UNCACHED_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            MEM1_UNCACHED_BASE_ADDR, "Wii MEM1 (Main RAM, 24MB, Uncached Mirror)"
        )
        tag_mem1u = self._get_or_create_tag_type(
            "MEM1", WII_TAG_TYPE_DEFINITIONS.get("MEM1", "💾")
        )
        if tag_mem1u:
            self.add_tag(
                MEM1_UNCACHED_BASE_ADDR, tag_mem1u.name, "MEM1 Uncached Mirror Start"
            )

        # mem2 uncached mirror (0xd0000000 - 0xd3ffffff, 64mb)
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
                MEM2_UNCACHED_BASE_ADDR, tag_mem2u.name, "MEM2 Uncached Mirror Start"
            )

        # hollywood i/o registers (main 32kb block: 0xcd000000 - 0xcd007fff)
        self.add_auto_segment(
            HOLLYWOOD_IO_BASE_ADDR, HOLLYWOOD_IO_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            HOLLYWOOD_IO_BASE_ADDR, "Wii Hollywood I/O Registers (Main Block)"
        )
        tag_hwio = self._get_or_create_tag_type(
            "Hollywood Register",
            WII_TAG_TYPE_DEFINITIONS.get("Hollywood Register", "🎬"),
        )
        if tag_hwio:
            self.add_tag(
                HOLLYWOOD_IO_BASE_ADDR, tag_hwio.name, "Hollywood I/O Block Start"
            )

        # boot rom / ipl alias (e.g., 0xfff00000 - 0xffffffff, typically 1mb for powerpc boot rom area)
        self.add_auto_segment(
            BOOT_ROM_ALIAS_BASE_ADDR, BOOT_ROM_ALIAS_SIZE, 0, 0, self.PERM_RX
        )
        self.set_comment_at(BOOT_ROM_ALIAS_BASE_ADDR, "Wii Boot ROM / IPL Alias (1MB)")
        tag_bootrom = self._get_or_create_tag_type(
            "Memory Region", WII_TAG_TYPE_DEFINITIONS.get("Memory Region", "🗺️")
        )
        if tag_bootrom:
            self.add_tag(
                BOOT_ROM_ALIAS_BASE_ADDR, tag_bootrom.name, "Boot ROM Alias Start"
            )

        # powerpc reset vector is typically at offset 0x100 in this high memory region.
        ppc_reset_vector_addr = BOOT_ROM_ALIAS_BASE_ADDR + 0x100
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, ppc_reset_vector_addr, "_ResetVector_IPL")
        )
        self.set_comment_at(
            ppc_reset_vector_addr,
            "PowerPC Reset Vector (in IPL, e.g., physical 0x1FC00100)",
        )
        tag_vector = self._get_or_create_tag_type(
            "Exception Vector", WII_TAG_TYPE_DEFINITIONS.get("Exception Vector", "❗")
        )
        if tag_vector:
            self.add_tag(ppc_reset_vector_addr, tag_vector.name, "IPL Reset Vector")

        self.logger.log_info("finished mapping fixed wii hardware memory regions.")

    def _map_dumped_memory_segments(self) -> None:
        """maps mem1 and mem2 data from the dump file itself into their primary (cached) address ranges."""
        self.logger.log_info("mapping dumped memory segments (mem1, mem2) from file...")

        if not self.parsed_header:
            self.logger.log_error(
                "bean dump header not parsed, cannot map dumped segments from file."
            )
            raise RuntimeError(
                "internal error: parsed_header is none during dumped segment mapping."
            )

        # determine file offsets for mem1 and mem2 data.
        # for the current simple "magic + entry_point" header, these offsets are fixed relative to header size.
        # future header versions might store these offsets explicitly.
        mem1_file_offset_in_dump = DEFAULT_MEM1_FILE_OFFSET
        mem2_file_offset_in_dump = DEFAULT_MEM2_FILE_OFFSET

        # map mem1 (primary mapping: 0x80000000)
        available_data_for_mem1 = 0
        if self.raw_data.length > mem1_file_offset_in_dump:
            available_data_for_mem1 = self.raw_data.length - mem1_file_offset_in_dump

        # actual size of mem1 data to map from the file.
        actual_mem1_size_to_map = min(FULL_MEM1_SIZE, available_data_for_mem1)

        if actual_mem1_size_to_map > 0:
            self.logger.log_info(
                f"  mapping mem1 (primary): addr=0x{MEM1_BASE_ADDR:08x}, file_offset=0x{mem1_file_offset_in_dump:x}, size=0x{actual_mem1_size_to_map:x}"
            )
            self.add_auto_segment(
                MEM1_BASE_ADDR,
                actual_mem1_size_to_map,
                mem1_file_offset_in_dump,
                actual_mem1_size_to_map,
                self.PERM_RWX,  # mem1 is general purpose ram, can contain code, data, bss.
            )
            # create a section for this mem1 block.
            self.add_auto_section(
                ".mem1",
                MEM1_BASE_ADDR,
                actual_mem1_size_to_map,
                SectionSemantics.ReadWriteDataSectionSemantics,  # general ram section.
            )
            self.set_comment_at(
                MEM1_BASE_ADDR,
                f"Wii MEM1 (Main RAM, 24MB, Primary Mapping, Dumped, Size: 0x{actual_mem1_size_to_map:X})",
            )
            tag_mem1 = self._get_or_create_tag_type(
                "MEM1", WII_TAG_TYPE_DEFINITIONS.get("MEM1", "💾")
            )
            if tag_mem1:
                self.add_tag(MEM1_BASE_ADDR, tag_mem1.name, "MEM1 (Primary) Start")
            if actual_mem1_size_to_map < FULL_MEM1_SIZE:
                self.logger.log_warn(
                    f"  mem1 dump is partial: mapped 0x{actual_mem1_size_to_map:x} bytes, expected full 0x{FULL_MEM1_SIZE:x}."
                )
        else:
            # this is critical, as mem1 is the primary component of the dump after the header.
            self.logger.log_error(
                "  no data available in dump file to map any part of mem1. "
                "this may indicate a corrupt or unexpectedly small dump file. loading cannot proceed meaningfully."
            )
            raise RuntimeError("mem1 data missing or inaccessible in dump file.")

        # map mem2 (primary mapping: 0x90000000)
        available_data_for_mem2 = 0
        if self.raw_data.length > mem2_file_offset_in_dump:
            available_data_for_mem2 = self.raw_data.length - mem2_file_offset_in_dump

        # actual size of mem2 data to map from the file.
        actual_mem2_size_to_map = min(FULL_MEM2_SIZE, available_data_for_mem2)

        if actual_mem2_size_to_map > 0:
            self.logger.log_info(
                f"  mapping mem2 (primary): addr=0x{MEM2_BASE_ADDR:08x}, file_offset=0x{mem2_file_offset_in_dump:x}, size=0x{actual_mem2_size_to_map:x}"
            )
            self.add_auto_segment(
                MEM2_BASE_ADDR,
                actual_mem2_size_to_map,
                mem2_file_offset_in_dump,
                actual_mem2_size_to_map,
                self.PERM_RWX,  # mem2 is also general purpose ram.
            )
            self.add_auto_section(
                ".mem2",
                MEM2_BASE_ADDR,
                actual_mem2_size_to_map,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )
            self.set_comment_at(
                MEM2_BASE_ADDR,
                f"Wii MEM2 (Aux RAM, 64MB, Primary Mapping, Dumped, Size: 0x{actual_mem2_size_to_map:X})",
            )
            tag_mem2 = self._get_or_create_tag_type(
                "MEM2", WII_TAG_TYPE_DEFINITIONS.get("MEM2", "🗳️")
            )
            if tag_mem2:
                self.add_tag(MEM2_BASE_ADDR, tag_mem2.name, "MEM2 (Primary) Start")
            if actual_mem2_size_to_map < FULL_MEM2_SIZE:
                self.logger.log_warn(
                    f"  mem2 dump is partial: mapped 0x{actual_mem2_size_to_map:x} bytes, expected full 0x{FULL_MEM2_SIZE:x}."
                )
        else:
            # log absence of mem2 data based on whether full mem1 was present.
            if self.raw_data.length >= mem2_file_offset_in_dump:
                self.logger.log_warn(
                    "  not enough data in dump file to map any part of mem2 (file length indicates mem2 data "
                    "should start, but calculated available size is zero or less)."
                )
            elif actual_mem1_size_to_map < FULL_MEM1_SIZE:
                self.logger.log_info(
                    "  mem1 dump was partial, so no data available for mem2 mapping from file."
                )
            else:  # full mem1 mapped, but file ends exactly there.
                self.logger.log_info(
                    "  dump file appears to contain only mem1 data; no data found for mem2."
                )

        self.logger.log_info("finished mapping dumped memory segments.")

    def _define_hardware_register(
        self, address: int, name: str, tag_category_name: str, description: str
    ):
        # memory-mapped i/o registers should generally be typed as 'volatile'
        # to ensure the compiler does not optimize away accesses.
        # wii hardware registers are typically 32-bit.
        mmio_type_declaration = f"volatile uint32_t {name}_reg_type;"

        # determine if this register likely qualifies as mmio based on its tag category.
        # this heuristic can be refined if more specific type information is available per register.
        is_mmio_heuristic = (
            "register" in tag_category_name.lower()  # general catch-all
            or tag_category_name
            in [  # specific known mmio categories
                "Hollywood Register",
                "Hardware Register",
                "I2C",
                "EXI",
                "Drive Interface",
                "Audio Interface",
                "Processor Interface",
                "Memory Interface",
                "Timer",
                "Video Interface",
                "GPIO",
                "PLL/Clock",
                "OTP",
                "USB",
                "NAND/Flash",
                "Bus Control",
            ]
        )

        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))
        if description:
            self.set_comment_at(
                address, description
            )  # use proper casing for ui comments

        if is_mmio_heuristic:
            try:
                parsed_type, _ = self.parse_type_string(mmio_type_declaration)
                if parsed_type:
                    # only define if no data variable (e.g. from auto-analysis) already exists.
                    if self.get_data_var_at(address) is None:
                        self.define_user_data_var(address, parsed_type)
                        self.logger.log_debug(
                            f"  defined mmio register '{name}' at 0x{address:08x} as volatile uint32_t."
                        )
                    else:
                        self.logger.log_debug(
                            f"  data variable already exists at 0x{address:08x} for mmio register '{name}'. type not overridden."
                        )
                else:
                    self.logger.log_warn(
                        f"could not parse '{mmio_type_declaration}' for mmio register '{name}'."
                    )
            except Exception as e:
                self.logger.log_warn(
                    f"failed to define mmio register '{name}' as volatile uint32_t: {e}"
                )

        tag_icon = WII_TAG_TYPE_DEFINITIONS.get(tag_category_name, "🔩")  # default icon
        tag_type_object = self._get_or_create_tag_type(tag_category_name, tag_icon)

        if tag_type_object:
            self.add_tag(address, tag_type_object.name, data=name)
        else:
            self.logger.log_warn(
                f"could not get or create tag type '{tag_category_name}' for register '{name}'."
            )

    def _define_wii_io_registers(self) -> None:
        self.logger.log_info("defining wii i/o hardware registers...")
        if not WII_IO_REGISTERS:
            self.logger.log_info(
                "  wii_io_registers list from defs.py is empty or not available. "
                "no wii-specific i/o registers will be defined."
            )
            return

        defined_count = 0
        for addr, name, tag_category, desc in WII_IO_REGISTERS:
            segment = self.get_segment_at(addr)
            if segment and (segment.readable or segment.writable):
                self.logger.log_debug(
                    f"  defining i/o register: {name} at 0x{addr:08x} (category: {tag_category})"
                )
                # _define_hardware_register now handles applying 'volatile' type for mmio
                self._define_hardware_register(addr, name, tag_category, desc)
                defined_count += 1
            else:
                self.logger.log_debug(
                    f"  skipping i/o register '{name}' at 0x{addr:08x}: address not in a mapped r/w segment (segment: {segment})."
                )
        self.logger.log_info(
            f"defined {defined_count}/{len(WII_IO_REGISTERS)} wii i/o registers from the provided list."
        )

    def _define_wii_global_symbols(self) -> None:
        self.logger.log_info(
            "defining wii global symbols and data variables (typically located in mem1)..."
        )
        if not WII_GLOBAL_SYMBOLS:
            self.logger.log_info(
                "  wii_global_symbols list from defs.py is empty or not available. "
                "no wii global symbols will be defined."
            )
            return

        defined_count = 0
        for addr, name, tag_category, desc, type_str in WII_GLOBAL_SYMBOLS:
            segment = self.get_segment_at(addr)
            if segment:  # ensure symbol address is within a mapped segment
                self.logger.log_debug(
                    f"  defining global symbol: {name} at 0x{addr:08x} (category: {tag_category})"
                )
                self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))
                if desc:
                    self.set_comment_at(addr, desc)  # use proper casing for ui comments

                tag_icon = WII_TAG_TYPE_DEFINITIONS.get(tag_category, "🌍")
                tag_type_obj = self._get_or_create_tag_type(tag_category, tag_icon)
                if tag_type_obj:
                    self.add_tag(addr, tag_type_obj.name, data=name)
                else:
                    self.logger.log_warn(
                        f"could not get or create tag type '{tag_category}' for global symbol '{name}'."
                    )

                if type_str:
                    try:
                        # construct a valid c-style declaration for parsing.
                        # assumes type_str is either a base type (e.g. "uint32_t") or a full declarator (e.g. "char[4]").
                        # if it's just a base type, a dummy variable name is appended for the parser.
                        c_decl_for_parsing = (
                            f"{type_str} {name}_global_var_type;"  # use a distinct temp name
                            if " " not in type_str
                            and "[" not in type_str
                            and "*" not in type_str
                            and "(" not in type_str  # heuristic for base type
                            else type_str  # assume it's already a declarator or function type
                        )
                        # ensure it ends with a semicolon for the parser
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
            # use entry point from header if it's non-zero (0 usually means undefined or invalid).
            entry_point_to_use = self.parsed_header.entry_point
            entry_point_source = "header"
            self.logger.log_info(
                f"using entry point 0x{entry_point_to_use:08x} specified in dump header."
            )
        else:
            self.logger.log_info(
                f"no valid entry point in dump header (or header not parsed fully), "
                f"using fallback default 0x{FALLBACK_DEFAULT_ENTRY_POINT:08x}."
            )

        segment_at_entry = self.get_segment_at(entry_point_to_use)
        if segment_at_entry and segment_at_entry.executable:
            self._primary_entry_point_address = entry_point_to_use
            self.add_entry_point(self._primary_entry_point_address)
            self.define_auto_symbol(
                Symbol(
                    SymbolType.FunctionSymbol,
                    self._primary_entry_point_address,
                    "_start",  # standard name for program entry
                )
            )
            try:
                # attempt to create a function at this address to kickstart analysis.
                self.add_function(self._primary_entry_point_address)
                self.logger.log_info(
                    f"defined wii entry point (from {entry_point_source}) and function '_start' at 0x{self._primary_entry_point_address:08x}."
                )
            except Exception as e:
                self.logger.log_warn(
                    f"could not create function at entry point 0x{self._primary_entry_point_address:08x} (from {entry_point_source}): {e}. "
                    "entry point symbol still added."
                )
        else:
            self.logger.log_warn(
                f"chosen entry point 0x{entry_point_to_use:08x} (from {entry_point_source}) is not within a mapped executable segment. "
                f"(segment found: {segment_at_entry}). no primary entry point set by loader. "
                "analysis may require manual intervention."
            )
            self._primary_entry_point_address = None  # invalidate if not suitable

    def init(self) -> bool:
        try:
            self.logger.log_info(
                f"starting wii memory dump ('{self.name}') loading process for '{self.file.filename}'..."
            )

            if not self._parse_bean_dump_header():
                self.logger.log_error(
                    "failed to parse bean dump header. aborting load."
                )
                return False

            self._initialize_tag_types()
            self._map_wii_hardware_and_fixed_regions()  # map non-dumped regions like i/o and mirrors
            self._map_dumped_memory_segments()  # map mem1 & mem2 from the dump file contents

            # define symbols and registers after all memory regions are established
            self._define_wii_io_registers()
            self._define_wii_global_symbols()

            self._define_entry_point()

            self.logger.log_info(
                "wii memory dump loading and setup steps complete. triggering analysis..."
            )
            self.update_analysis()  # initiate binary ninja's analysis passes
            return True

        except Exception as e:
            # catch any unhandled exceptions during the init process
            self.logger.log_error(
                f"a critical failure occurred during wii memory dump initialization: {e}\n{traceback.format_exc()}"
            )
            return False

    def perform_get_entry_point(self) -> int:
        if self._primary_entry_point_address is not None:
            self.logger.log_debug(
                f"perform_get_entry_point: returning stored entry point 0x{self._primary_entry_point_address:08x}."
            )
            return self._primary_entry_point_address

        # if the loader didn't set a primary entry point, check if any were added to bn's list
        if self.entry_points:
            self.logger.log_warn(
                "perform_get_entry_point: loader's primary entry point not set or invalid. "
                f"falling back to the first entry point in binary ninja's list: 0x{self.entry_points[0]:08x}"
            )
            return self.entry_points[0]

        # absolute fallback: start of mem1 (if mapped) or start of the view
        self.logger.log_warn(
            "perform_get_entry_point: no valid entry point found. "
            f"falling back to start of mem1 (0x{MEM1_BASE_ADDR:08x}) or view start."
        )
        mem1_segment = self.get_segment_at(MEM1_BASE_ADDR)
        if mem1_segment:
            return mem1_segment.start
        return self.start if self.start is not None else 0

    def perform_get_address_size(self) -> int:
        return 4  # wii uses 32-bit addresses

    def perform_is_executable(self) -> bool:
        return True


BeanWiiDumpView.register()
