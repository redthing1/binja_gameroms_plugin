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

# import wii definitions (ensure this file exists in the same 'wii' package directory)
from .defs import WII_TAG_TYPE_DEFINITIONS, WII_IO_REGISTERS, WII_GLOBAL_SYMBOLS

# - bean dump format constants
WII_DUMP_MAGIC = b"BEAN"
MAGIC_SIZE = len(WII_DUMP_MAGIC)

# the header currently only consists of the magic bytes.
# future extensions could add a version field, then offsets and sizes for memory regions.
BEAN_DUMP_CURRENT_HEADER_SIZE = MAGIC_SIZE

# default file offsets for memory regions if not specified in a future extended header.
# these assume mem1 data immediately follows the header, then mem2 data.
DEFAULT_MEM1_FILE_OFFSET = BEAN_DUMP_CURRENT_HEADER_SIZE
DEFAULT_MEM2_FILE_OFFSET = DEFAULT_MEM1_FILE_OFFSET + (24 * 1024 * 1024)

# expected full sizes for mem1 and mem2, used for mapping and partial dump checks.
FULL_MEM1_SIZE = 24 * 1024 * 1024  # 24mb
FULL_MEM2_SIZE = 64 * 1024 * 1024  # 64mb

# minimum valid dump size is magic + at least 1 byte of data (for mem1).
MIN_VALID_DUMP_SIZE = BEAN_DUMP_CURRENT_HEADER_SIZE + 1

# - wii memory map constants (ppc virtual addresses)
# primary ram regions (cached views are standard for general use).
# the loader will map data from the dump file into these cached addresses.
MEM1_BASE_ADDR = 0x80000000
MEM1_SIZE = FULL_MEM1_SIZE  # this is the *address space size*, actual mapped data depends on dump file
MEM2_BASE_ADDR = 0x90000000
MEM2_SIZE = FULL_MEM2_SIZE

# uncached mirrors of mem1 and mem2. these are fixed hardware mappings, not loaded from the dump.
MEM1_UNCACHED_BASE_ADDR = 0xC0000000
MEM1_UNCACHED_SIZE = FULL_MEM1_SIZE
MEM2_UNCACHED_BASE_ADDR = 0xD0000000
MEM2_UNCACHED_SIZE = FULL_MEM2_SIZE

# hardware i/o: main hollywood mmio block. fixed hardware mapping.
HOLLYWOOD_IO_BASE_ADDR = 0xCD000000
HOLLYWOOD_IO_SIZE = 0x8000  # 32kb

# boot rom / ipl alias: ppc high-memory alias for the physical boot rom. fixed hardware mapping.
BOOT_ROM_ALIAS_BASE_ADDR = 0xFFF00000
BOOT_ROM_ALIAS_SIZE = (
    0x00100000  # 1mb, standard size covering vectors like 0xfff00100 (reset)
)

# default entry point candidate within mem1.
# this is the start of the "standard application executable area" from wii_memmap_info.txt.
DEFAULT_ENTRY_POINT = 0x80003F00


# - dataclass for parsed header information
@dataclass
class BeanDumpHeader:
    """
    stores information parsed from the bean dump header.
    designed for future extensibility: new fields for versioning, memory region
    offsets/sizes within the dump file, or entry point information can be added here.
    the `_parse_bean_dump_header` method would then be updated to read these fields.
    """

    magic: bytes = b""
    # example future fields (not used in current simple "magic-only" header):
    # version: int = 1
    # mem1_offset_in_file: int = DEFAULT_MEM1_FILE_OFFSET
    # mem1_size_in_file: int = 0 # 0 indicates to calculate from file end or use full_mem1_size
    # mem2_offset_in_file: int = DEFAULT_MEM2_FILE_OFFSET
    # mem2_size_in_file: int = 0
    # entry_point_offset_mem1: Optional[int] = None # offset relative to mem1_base_addr


class BeanWiiDumpView(BinaryView):
    name = "BeanWii"
    long_name = "BeanWii Dump"

    # segment permission flags for convenience
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
        self.parsed_header: Optional[BeanDumpHeader] = None  # stores parsed header data

        try:
            # wii's broadway cpu is powerpc (big-endian) with paired singles support.
            # 'ppc_ps' is used as it implies paired singles, common for game consoles using powerpc.
            self.arch = Architecture["ppc_ps"]
            if not self.arch:
                self.logger.log_error(
                    "ppc_ps architecture definition not found in binary ninja. this is required for wii analysis."
                )
                raise RuntimeError("ppc_ps architecture definition not found.")

            # verify expected endianness for powerpc on wii.
            if self.arch.endianness != Endianness.BigEndian:
                self.logger.log_warn(
                    f"selected architecture '{self.arch.name}' reports endianness {self.arch.endianness.name}, "
                    "but wii (powerpc) is big-endian. disassembly or data interpretation might be incorrect if the "
                    "architecture definition does not correctly enforce big-endian behavior."
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

        except KeyError:  # specific exception for architecture not found
            self.logger.log_error(
                "ppc_ps architecture key not found in binary ninja. wii analysis requires it."
            )
            raise RuntimeError("ppc_ps architecture key not found.")
        except Exception as e:  # catch-all for other setup issues
            self.logger.log_error(
                f"critical error during architecture or platform setup: {e}\n{traceback.format_exc()}"
            )
            raise

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        # check if data is large enough for the current defined header size.
        if data.length < BEAN_DUMP_CURRENT_HEADER_SIZE:
            log_debug(
                f"[{cls.name}] validation: data too short for header (size: {data.length} bytes, requires: {BEAN_DUMP_CURRENT_HEADER_SIZE} bytes)."
            )
            return False

        magic_bytes = data.read(0, MAGIC_SIZE)
        if magic_bytes != WII_DUMP_MAGIC:
            log_debug(
                f"[{cls.name}] validation: invalid magic bytes {magic_bytes!r}, expected {WII_DUMP_MAGIC!r}."
            )
            return False

        # additionally, ensure the file is large enough to contain at least some data beyond the header.
        if data.length < MIN_VALID_DUMP_SIZE:
            log_warn(
                f"[{cls.name}] validation: file has '{WII_DUMP_MAGIC.decode()}' magic but is too short "
                f"(size: {data.length} bytes, min required with data: {MIN_VALID_DUMP_SIZE} bytes) "
                "to contain any actual memory data. treating as invalid."
            )
            return False

        log_info(
            f"[{cls.name}] validation: found '{WII_DUMP_MAGIC.decode()}' magic and basic size requirements met. "
            "identified as a potential bean wii dump."
        )
        return True

    def _parse_bean_dump_header(self) -> bool:
        """
        parses the bean dump header.
        currently, this only involves reading the magic bytes.
        this method is designed to be extended if the header format evolves.
        """
        self.logger.log_info("parsing bean dump header...")
        if self.raw_data.length < BEAN_DUMP_CURRENT_HEADER_SIZE:
            self.logger.log_error(
                f"file is too small (size: {self.raw_data.length} bytes) for the current bean dump header "
                f"(requires: {BEAN_DUMP_CURRENT_HEADER_SIZE} bytes)."
            )
            return False

        # read and verify magic (this is a bit redundant if is_valid_for_data passed, but good for robustness).
        magic = self.raw_data.read(0, MAGIC_SIZE)
        if magic != WII_DUMP_MAGIC:
            self.logger.log_error(
                "invalid magic bytes encountered during header parsing stage. "
                "this should have been caught by is_valid_for_data."
            )
            return False

        self.parsed_header = BeanDumpHeader(magic=magic)

        # example: if a version field was added after the magic (e.g., 1 byte version):
        # if BEAN_DUMP_CURRENT_HEADER_SIZE > MAGIC_SIZE: # check if header is expected to be larger
        #     try:
        #         version_byte = self.raw_data.read(MAGIC_SIZE, 1)
        #         if version_byte:
        #             self.parsed_header.version = version_byte[0]
        #             self.logger.log_info(f"  parsed header version: {self.parsed_header.version}")
        #             # based on version, you might read other fields like mem1_offset_in_file etc.
        #         else:
        #             self.logger.log_error("could not read version byte from header.")
        #             return False # or handle as default version
        #     except Exception as e:
        #         self.logger.log_error(f"error parsing extended header fields: {e}")
        #         return False

        self.logger.log_info(
            f"bean dump header parsed successfully (magic: {self.parsed_header.magic.decode()})."
        )
        return True

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
        such as i/o ports and memory mirrors.
        """
        self.logger.log_info(
            "mapping fixed wii hardware memory regions (not from dump file)..."
        )

        # mem1 uncached mirror (0xc0000000 - 0xc17fffff, 24mb)
        self.add_auto_segment(
            MEM1_UNCACHED_BASE_ADDR, MEM1_UNCACHED_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            MEM1_UNCACHED_BASE_ADDR, "wii mem1 (main ram, 24mb, uncached mirror)"
        )
        tag_mem1u = self._get_or_create_tag_type(
            "MEM1", WII_TAG_TYPE_DEFINITIONS.get("MEM1", "💾")
        )
        if tag_mem1u:
            self.add_tag(
                MEM1_UNCACHED_BASE_ADDR, tag_mem1u.name, "mem1 uncached mirror start"
            )

        # mem2 uncached mirror (0xd0000000 - 0xd3ffffff, 64mb)
        self.add_auto_segment(
            MEM2_UNCACHED_BASE_ADDR, MEM2_UNCACHED_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            MEM2_UNCACHED_BASE_ADDR, "wii mem2 (aux ram, 64mb, uncached mirror)"
        )
        tag_mem2u = self._get_or_create_tag_type(
            "MEM2", WII_TAG_TYPE_DEFINITIONS.get("MEM2", "🗳️")
        )
        if tag_mem2u:
            self.add_tag(
                MEM2_UNCACHED_BASE_ADDR, tag_mem2u.name, "mem2 uncached mirror start"
            )

        # hollywood i/o registers (main 32kb block: 0xcd000000 - 0xcd007fff)
        self.add_auto_segment(
            HOLLYWOOD_IO_BASE_ADDR, HOLLYWOOD_IO_SIZE, 0, 0, self.PERM_RW
        )
        self.set_comment_at(
            HOLLYWOOD_IO_BASE_ADDR, "wii hollywood i/o registers (main block)"
        )
        tag_hwio = self._get_or_create_tag_type(
            "Hollywood Register",
            WII_TAG_TYPE_DEFINITIONS.get("Hollywood Register", "🎬"),
        )
        if tag_hwio:
            self.add_tag(
                HOLLYWOOD_IO_BASE_ADDR, tag_hwio.name, "hollywood i/o block start"
            )

        # boot rom / ipl alias (e.g., 0xfff00000 - 0xffffffff, typically 1mb for powerpc boot rom area)
        # this region contains the cpu's initial reset vector.
        self.add_auto_segment(
            BOOT_ROM_ALIAS_BASE_ADDR, BOOT_ROM_ALIAS_SIZE, 0, 0, self.PERM_RX
        )
        self.set_comment_at(BOOT_ROM_ALIAS_BASE_ADDR, "wii boot rom / ipl alias (1mb)")
        tag_bootrom = self._get_or_create_tag_type(
            "Memory Region", WII_TAG_TYPE_DEFINITIONS.get("Memory Region", "🗺️")
        )
        if tag_bootrom:
            self.add_tag(
                BOOT_ROM_ALIAS_BASE_ADDR, tag_bootrom.name, "boot rom alias start"
            )

        # ppc reset vector is typically at offset 0x100 in this high memory region.
        ppc_reset_vector_addr = BOOT_ROM_ALIAS_BASE_ADDR + 0x100
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, ppc_reset_vector_addr, "_ResetVector_IPL")
        )
        self.set_comment_at(
            ppc_reset_vector_addr,
            "powerpc reset vector (in ipl, physical 0x1fc00100 or similar)",
        )
        tag_vector = self._get_or_create_tag_type(
            "Exception Vector", WII_TAG_TYPE_DEFINITIONS.get("Exception Vector", "❗")
        )
        if tag_vector:
            self.add_tag(ppc_reset_vector_addr, tag_vector.name, "ipl reset vector")

        self.logger.log_info("finished mapping fixed wii hardware memory regions.")

    def _map_dumped_memory_segments(self) -> None:
        """maps mem1 and mem2 data from the dump file itself into their cached address ranges."""
        self.logger.log_info("mapping dumped memory segments (mem1, mem2)...")

        if not self.parsed_header:
            self.logger.log_error(
                "bean dump header not parsed, cannot map dumped segments from file."
            )
            raise RuntimeError(
                "internal error: parsed_header is none during segment mapping."
            )

        # determine file offsets and sizes.
        # for current simple "magic-only" header, use defaults.
        # if header was extended, these would come from self.parsed_header.
        mem1_file_offset_in_dump = DEFAULT_MEM1_FILE_OFFSET
        mem2_file_offset_in_dump = DEFAULT_MEM2_FILE_OFFSET

        # map mem1 (primary cached region: 0x80000000)
        available_data_for_mem1 = 0
        if self.raw_data.length > mem1_file_offset_in_dump:
            available_data_for_mem1 = self.raw_data.length - mem1_file_offset_in_dump

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
                self.PERM_RWX,
            )
            self.add_auto_section(
                ".mem1",  # section name for the primary mem1 mapping
                MEM1_BASE_ADDR,
                actual_mem1_size_to_map,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )
            self.set_comment_at(
                MEM1_BASE_ADDR,
                f"wii mem1 (main ram, 24mb, primary mapping, dumped, size: 0x{actual_mem1_size_to_map:x})",
            )
            tag_mem1c = self._get_or_create_tag_type(
                "MEM1", WII_TAG_TYPE_DEFINITIONS.get("MEM1", "💾")
            )
            if tag_mem1c:
                self.add_tag(MEM1_BASE_ADDR, tag_mem1c.name, "mem1 (primary) start")
            if actual_mem1_size_to_map < FULL_MEM1_SIZE:
                self.logger.log_warn(
                    f"  mem1 dump is partial: mapped 0x{actual_mem1_size_to_map:x} bytes, expected full 0x{FULL_MEM1_SIZE:x}."
                )
        else:
            self.logger.log_error(
                "  no data available in dump file to map any part of mem1. this is critical for a beandump. loading cannot proceed meaningfully."
            )
            raise RuntimeError(
                "mem1 data missing or inaccessible in dump file. dump may be corrupt or too small."
            )

        # map mem2 (primary cached region: 0x90000000)
        available_data_for_mem2 = 0
        if self.raw_data.length > mem2_file_offset_in_dump:
            available_data_for_mem2 = self.raw_data.length - mem2_file_offset_in_dump

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
                self.PERM_RWX,
            )
            self.add_auto_section(
                ".mem2",  # section name for the primary mem2 mapping
                MEM2_BASE_ADDR,
                actual_mem2_size_to_map,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )
            self.set_comment_at(
                MEM2_BASE_ADDR,
                f"wii mem2 (aux ram, 64mb, primary mapping, dumped, size: 0x{actual_mem2_size_to_map:x})",
            )
            tag_mem2c = self._get_or_create_tag_type(
                "MEM2", WII_TAG_TYPE_DEFINITIONS.get("MEM2", "🗳️")
            )
            if tag_mem2c:
                self.add_tag(MEM2_BASE_ADDR, tag_mem2c.name, "mem2 (primary) start")
            if actual_mem2_size_to_map < FULL_MEM2_SIZE:
                self.logger.log_warn(
                    f"  mem2 dump is partial: mapped 0x{actual_mem2_size_to_map:x} bytes, expected full 0x{FULL_MEM2_SIZE:x}."
                )
        else:
            # log based on whether full mem1 was present (implying mem2 should have started)
            if (
                self.raw_data.length >= mem2_file_offset_in_dump
            ):  # if file theoretically reached mem2 offset
                self.logger.log_warn(
                    "  not enough data in dump file to map any part of mem2 (file length indicates mem2 data should start but size is 0 or less)."
                )
            elif actual_mem1_size_to_map < FULL_MEM1_SIZE:  # if mem1 was partial
                self.logger.log_info(
                    "  mem1 dump was partial, so no data available for mem2 mapping from file."
                )
            else:  # if full mem1 mapped, but file ends exactly there
                self.logger.log_info(
                    "  dump file appears to contain only mem1 data; no data for mem2."
                )

        self.logger.log_info("finished mapping dumped memory segments.")

    def _define_hardware_register(
        self, address: int, name: str, tag_category_name: str, description: str
    ):
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))
        if description:
            self.set_comment_at(address, description)

        tag_icon = WII_TAG_TYPE_DEFINITIONS.get(tag_category_name, "🔩")
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
                "  wii_io_registers list is empty or not available (from defs.py). "
                "no wii-specific i/o registers will be defined."
            )
            return

        defined_count = 0
        for addr, name, tag_category, desc in WII_IO_REGISTERS:
            segment = self.get_segment_at(addr)
            # ensure register address falls within a mapped region, typically an r/w i/o segment.
            if segment and (segment.readable or segment.writable):
                self.logger.log_debug(
                    f"  defining i/o register: {name} at 0x{addr:08x} (category: {tag_category})"
                )
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
            "defining wii global symbols and data variables (typically in mem1)..."
        )
        if not WII_GLOBAL_SYMBOLS:
            self.logger.log_info(
                "  wii_global_symbols list is empty or not available (from defs.py). "
                "no wii global symbols will be defined."
            )
            return

        defined_count = 0
        for addr, name, tag_category, desc, type_str in WII_GLOBAL_SYMBOLS:
            segment = self.get_segment_at(addr)
            # ensure global symbol address is within a mapped segment (usually mem1).
            if segment:
                self.logger.log_debug(
                    f"  defining global symbol: {name} at 0x{addr:08x} (category: {tag_category})"
                )
                self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))
                if desc:
                    self.set_comment_at(addr, desc)

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
                        # if type_str is just "uint32_t", make it "uint32_t var_name;"
                        # if type_str is "char[4]", it's already a declarator.
                        # a robust way is to always add a dummy name if it's not a full decl.
                        # for simplicity, assume type_str is either a base type or includes a name.
                        c_decl_for_parsing = (
                            f"{type_str} {name}_temp_type_def;"
                            if " " not in type_str
                            and "[" not in type_str
                            and "*" not in type_str
                            else type_str
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
                                f"could not parse type string '{c_decl_for_parsing}' for symbol '{name}'."
                            )
                    except Exception as e:
                        self.logger.log_warn(
                            f"failed to parse or define type '{type_str}' for '{name}' at 0x{addr:08x}: {e}"
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
        self.logger.log_info(
            f"attempting to define default entry point at 0x{DEFAULT_ENTRY_POINT:08x}."
        )

        segment_at_default_entry = self.get_segment_at(DEFAULT_ENTRY_POINT)
        if segment_at_default_entry and segment_at_default_entry.executable:
            self._primary_entry_point_address = DEFAULT_ENTRY_POINT
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
                    f"defined wii entry point and function '_start' at 0x{self._primary_entry_point_address:08x}."
                )
            except Exception as e:
                self.logger.log_warn(
                    f"could not create function at entry point 0x{self._primary_entry_point_address:08x}: {e}. "
                    "entry point symbol still added."
                )
        else:
            self.logger.log_warn(
                f"default entry point 0x{DEFAULT_ENTRY_POINT:08x} is not within a mapped executable segment. "
                f"(segment found: {segment_at_default_entry}). no primary entry point set by loader. "
                "analysis may require manual intervention or may start from other known code locations."
            )
            self._primary_entry_point_address = None

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
            self._map_wii_hardware_and_fixed_regions()  # map non-dumped regions like mirrors and i/o
            self._map_dumped_memory_segments()  # map mem1 & mem2 from the dump file

            self._define_wii_io_registers()
            self._define_wii_global_symbols()

            self._define_entry_point()

            self.logger.log_info(
                "wii memory dump loading and setup steps complete. triggering analysis..."
            )
            self.update_analysis()
            return True

        except Exception as e:
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

        if self.entry_points:
            self.logger.log_warn(
                "perform_get_entry_point: loader's primary entry point not set. "
                f"falling back to the first entry point in binary ninja's list: 0x{self.entry_points[0]:08x}"
            )
            return self.entry_points[0]

        self.logger.log_warn(
            "perform_get_entry_point: no valid entry point found. falling back to start of mem1 (0x{MEM1_BASE_ADDR:08x}) or view start."
        )
        # attempt to return start of mem1 as a sensible default if it's mapped
        mem1_segment = self.get_segment_at(MEM1_BASE_ADDR)
        if mem1_segment:
            return mem1_segment.start
        return self.start if self.start is not None else 0  # absolute fallback

    def perform_get_address_size(self) -> int:
        return 4

    def perform_is_executable(self) -> bool:
        return True


BeanWiiDumpView.register()
