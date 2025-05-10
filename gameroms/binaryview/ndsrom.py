import struct
import traceback
from typing import Optional, List, Dict, Tuple

from binaryninja import (
    BinaryView,
    SegmentFlag,
    SymbolType,
    Symbol,
    TagType,
    Platform,
    Architecture,
    SectionSemantics,
    log_error,
    log_warn,
    log_info,
    log_debug,
)
from binaryninja.log import Logger

from ..readers.nds_cartridge import (
    NDSRomReader,
    NDSRom,
    NDSOverlayTable,
    NDSOverlayEntry,
)
from ..defs.nds import NDS_IO_REGISTERS

# - nds hardware definitions

# dictionary mapping tag type names (proper case) to icons for ui categorization.
# these help visually distinguish different hardware components and memory regions.
NDS_TAG_TYPE_DEFINITIONS: Dict[str, str] = {
    "Display": "🖼️",  # lcd, 2d/3d engines' display aspects
    "DMA": "➡️",  # direct memory access controllers
    "Timers": "⏱️",  # hardware timers
    "Keypad": "🎮",  # button inputs
    "IPC": "↔️",  # inter-processor communication fifos
    "Gamecard": "💾",  # nds game card slot interface
    "Interrupts": "⚡",  # interrupt controller registers
    "Power": "🔋",  # power management registers
    "Memory Control": "🐏",  # main ram, wram, vram, tcm control
    "Math": "➗",  # hardware math units (divider, square root)
    "3D Engine": "🧊",  # 3d graphics rendering engine registers
    "Sound": "🔊",  # sound controller registers
    "SPI": "〰️",  # serial peripheral interface (touchscreen, firmware, power man.)
    "RTC": "🕒",  # real-time clock
    "Wifi": "📡",  # wireless communication module
    "System": "⚙️",  # general system control, bios protection, etc.
    "ARM9 Specific": "9️⃣",  # registers only accessible/relevant to arm9
    "ARM7 Specific": "7️⃣",  # registers only accessible/relevant to arm7
    "Hardcoded Addr": "📍",  # special hardcoded ram addresses (e.g., irq handlers in ram)
    "Memory Region": "🗺️",  # for mapped memory segments (ram, rom, io blocks)
    "Hardware Register": "🔩",  # generic fallback for i/o registers
}

# - nitro sdk constants
# these constants relate to the _start_moduleparams structure found in many
# official nds sdk compiled binaries, particularly for the arm9 processor.
# this structure provides metadata, including information about compression.

# magic bytes to identify the _start_moduleparams structure.
NITRO_SDK_MODULE_PARAMS_MAGIC = b"\x21\x06\xc0\xde\xde\xc0\x06\x21"
# size of the _start_moduleparams structure in bytes.
NITRO_SDK_MODULE_PARAMS_SIZE = 36
# offset of the magic bytes from the start of the _start_moduleparams structure.
NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET = 0x1C


# - ndsview class definition
class NDSView(BinaryView):
    """
    BinaryView class for loading and analyzing Nintendo DS (NDS) ROM files.
    It handles parsing the NDS ROM structure, mapping memory regions for both
    ARM9 and ARM7 processors, loading their respective binaries and overlays
    (including decompression), and defining known hardware registers and entry points.
    """

    name = "NDS"
    long_name = "Nintendo DS ROM"

    # - segment permission flags
    # common combinations for defining memory segment permissions using binary ninja's SegmentFlag enum.
    PERM_RWX: SegmentFlag = (
        SegmentFlag.SegmentReadable
        | SegmentFlag.SegmentWritable
        | SegmentFlag.SegmentExecutable
    )
    PERM_RW: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    PERM_RX: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
    PERM_R: SegmentFlag = SegmentFlag.SegmentReadable

    def __init__(self, data: BinaryView):
        super().__init__(file_metadata=data.file, parent_view=data)

        # store a reference to the raw data view for direct access if needed.
        self.raw_data: BinaryView = data
        # create a logger instance specific to this plugin for organized logging.
        self.logger: Logger = self.create_logger("NDS")  # logger name "NDS"
        # cache for created tagtypes to avoid redundant api calls and improve performance.
        self._created_tag_types: Dict[str, TagType] = {}
        # placeholder for parsed rom data, populated by _parse_rom_structure.
        self.nds_rom: Optional[NDSRom] = None
        # store defined entry point addresses for perform_get_entry_point.
        self._primary_arm9_entry_point: Optional[int] = None
        self._primary_arm7_entry_point: Optional[int] = None

        # set architecture and platform.
        # the nds features an arm946e-s (armv5tej architecture) and an arm7tdmi (armv4t architecture).
        # "armv7" is selected as a practical choice in binary ninja. it generally supports
        # the necessary arm and thumb instruction sets for both processors, especially
        # for the more complex arm9.
        try:
            # type ignore justification: architecture names are string literals used as keys.
            self.arch: Optional[Architecture] = Architecture["armv7"]  # type: ignore
            if not self.arch:
                # this is a critical failure if the architecture isn't available in binary ninja.
                self.logger.log_error(
                    "critical: armv7 architecture definition not found. nds analysis requires it."
                )
                raise RuntimeError("armv7 architecture definition not found.")

            self.platform: Optional[Platform] = self.arch.standalone_platform
            if not self.platform:
                self.logger.log_error(
                    f"critical: could not get standalone platform for architecture '{self.arch.name}'. nds analysis cannot proceed."
                )
                raise RuntimeError(
                    f"failed to get standalone platform for {self.arch.name}."
                )
            self.logger.log_info(
                f"successfully set platform: {self.platform.name}, architecture: {self.arch.name}"
            )
        except KeyError:
            # handle the specific case where "armv7" is not a recognized architecture key.
            available_archs = [arch.name for arch in Architecture]  # type: ignore
            self.logger.log_error(
                f"critical: armv7 architecture key not found. available: {available_archs}. this architecture is required for nds analysis."
            )
            raise RuntimeError("armv7 architecture key not found.")
        except Exception as e:
            # catch any other unexpected errors during this critical setup phase.
            self.logger.log_error(
                f"critical error during architecture or platform setup: {e}\n{traceback.format_exc()}"
            )
            raise  # re-raise to ensure initialization fails clearly.

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        checks if the provided data is likely an nds rom.
        this performs a basic heuristic check for the nintendo logo magic bytes
        found in the nds rom header. full validation (e.g., crc checks via
        ndsromreader) is deferred to the init method for performance reasons,
        as `is_valid_for_data` might be called frequently.

        args:
            data: the binaryview object containing the data to validate.

        returns:
            true if the data is likely an nds rom, false otherwise.
        """
        # the nds header contains a nintendo logo starting at offset 0xc0.
        # we check for specific 4 bytes (0x24, 0xff, 0xae, 0x51) from this logo.
        # minimum file size required to read these 4 bytes from that offset.
        min_header_size_for_logo_check = 0xC0 + 4
        if data.length < min_header_size_for_logo_check:
            # log at debug level as this is a common scenario for non-nds files.
            log_debug(  # use global logger for classmethod
                f"[{cls.name}] validation: data length {data.length} is less than min size {min_header_size_for_logo_check} for logo check. not an nds rom."
            )
            return False

        try:
            logo_magic_offset = 0xC0
            logo_magic_bytes_to_check = data.read(logo_magic_offset, 4)

            # expected magic bytes: b"\x24\xff\xae\x51"
            if logo_magic_bytes_to_check == b"\x24\xff\xae\x51":
                log_info(
                    f"[{cls.name}] validation: found nintendo logo magic bytes at offset 0x{logo_magic_offset:x}. identified as potential nds rom."
                )
                return True
            else:
                log_debug(
                    f"[{cls.name}] validation: nintendo logo magic bytes not found at offset 0x{logo_magic_offset:x}. got {logo_magic_bytes_to_check!r}. not an nds rom."
                )
                return False
        except Exception as e:
            # log an error if reading the bytes fails for any unexpected reason.
            log_error(
                f"[{cls.name}] validation: error reading nintendo logo magic bytes: {e}\n{traceback.format_exc()}"
            )
            return False

    # - helper methods for initialization

    def _parse_rom_structure(self) -> bool:
        """
        parses the complete nds rom structure using the external `NDSRomReader`.
        this involves reading the entire rom file into memory, performing validation
        (e.g., header crc checks by the reader), and then parsing header fields,
        file allocation table (fat), overlay tables, etc. the parsed result, an
        `NDSRom` object, is stored in `self.nds_rom`.

        note: reading the entire rom can be memory-intensive for large roms.
        this approach is retained as per the original loader's core logic,
        presumably due to the requirements of the `NDSRomReader` utility.

        returns:
            true if parsing was successful and `self.nds_rom` is populated with valid data,
            false otherwise (e.g., read error, parsing error, validation failure by reader).
        """
        self.logger.log_info(
            "reading entire rom into memory for parsing with ndsromreader..."
        )
        rom_length = self.raw_data.length
        if rom_length == 0:
            self.logger.log_error("rom file is empty (0 bytes). cannot parse.")
            return False

        # attempt to read the entire rom data.
        rom_data_bytes: bytes = self.raw_data.read(0, rom_length)
        if not rom_data_bytes or len(rom_data_bytes) != rom_length:
            self.logger.log_error(
                f"failed to read full rom data (read {len(rom_data_bytes)} bytes, expected {rom_length} bytes) from parent view."
            )
            return False
        self.logger.log_info(
            f"successfully read {rom_length // (1024*1024)} MB of rom data into memory."
        )

        # perform header validation using ndsromreader's static method.
        # ndsromreader.is_valid typically checks header crcs and other structural consistencies.
        # validation_data_slice limits how much data is passed for this initial validation step.
        self.logger.log_info(
            "performing nds rom header validation via ndsromreader.is_valid()..."
        )
        validation_data_slice = rom_data_bytes[
            : min(0x1000, rom_length)
        ]  # use up to first 4kb for validation
        if not NDSRomReader.is_valid(validation_data_slice):
            self.logger.log_warn(
                "ndsromreader.is_valid() reported header validation failure. "
                "the rom might be malformed, a bad dump, or unsupported. "
                "attempting to parse the structure anyway, but results may be unreliable."
            )
            # for some use cases, attempting to parse a technically invalid rom might still be desired.
            # if strict validation is required, one might choose to `return False` here.
        else:
            self.logger.log_info(
                "ndsromreader.is_valid() reported successful header validation."
            )

        # now, attempt to parse the full rom structure.
        self.logger.log_info(
            "parsing full nds rom structure using ndsromreader.read()..."
        )
        try:
            self.nds_rom = NDSRomReader.read(rom_data_bytes)
        except Exception as e:
            self.logger.log_error(f"ndsromreader.read() failed with an exception: {e}")
            self.logger.log_error(f"traceback:\n{traceback.format_exc()}")
            self.nds_rom = None  # ensure self.nds_rom is none on failure
            del rom_data_bytes  # ensure memory is freed even on exception
            return False
        finally:
            # rom_data_bytes can be a large buffer; explicitly delete it to free memory
            # once parsing is done (successfully or not), if it hasn't been deleted in an except block.
            if "rom_data_bytes" in locals():
                del rom_data_bytes
                self.logger.log_debug(
                    "rom_data_bytes buffer has been cleared from memory."
                )

        if not self.nds_rom or not self.nds_rom.header:
            self.logger.log_error(
                "failed to parse nds rom: ndsromreader.read() returned none, or the parsed rom object is missing its header."
            )
            return False

        self.logger.log_info(
            "successfully parsed nds rom structure using ndsromreader."
        )
        return True

    def _initialize_tag_types(self) -> None:
        """
        defines and caches all necessary tag types used by this view for nds-specific elements.
        it iterates through the global `NDS_TAG_TYPE_DEFINITIONS` dictionary.
        this setup allows for visually distinct and organized tagging in the binary ninja ui.
        """
        self.logger.log_info("initializing nds hardware tag types...")
        initialized_count = 0
        total_defined = len(NDS_TAG_TYPE_DEFINITIONS)
        for name, icon in NDS_TAG_TYPE_DEFINITIONS.items():
            if self._get_or_create_tag_type(name, icon):
                initialized_count += 1
            else:
                # log a warning if a specific tag type couldn't be set up.
                self.logger.log_warn(
                    f"could not initialize nds tag type: '{name}' with icon '{icon}'."
                )
        self.logger.log_info(
            f"{initialized_count}/{total_defined} nds tag types are now ready for use."
        )

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        """
        retrieves an existing tag type by its name or creates a new one if it doesn't exist.
        results are cached in `self._created_tag_types` to avoid redundant api calls to
        binary ninja and improve performance during the loading process.

        args:
            name: the name of the tag type (e.g., "Memory Region"). use proper case for creation.
            icon: the icon (emoji or short string) for the tag type (e.g., "🗺️").

        returns:
            the TagType object if successfully found or created, or none if both attempts fail.
        """
        # use lowercase for the internal cache key for consistent lookups.
        name_lower = name.lower()
        if name_lower in self._created_tag_types:
            self.logger.log_debug(f"retrieved cached tag type: '{name}'.")
            return self._created_tag_types[name_lower]

        # attempt to get the tag type using binary ninja's built-in lookup by name.
        # binary ninja's `get_tag_type` is case-insensitive.
        existing_tag_type = self.get_tag_type(name)
        if existing_tag_type:
            self.logger.log_debug(
                f"found existing tag type in binaryview: '{name}'. caching it."
            )
            self._created_tag_types[name_lower] = existing_tag_type
            return existing_tag_type

        # if the tag type does not exist in the view, create it.
        try:
            # use the original (proper) casing for the name when creating the new tag type.
            self.logger.log_info(f"creating new tag type: '{name}' with icon '{icon}'.")
            new_tag_type = self.create_tag_type(name, icon)
            self._created_tag_types[name_lower] = (
                new_tag_type  # cache the newly created type.
            )
            return new_tag_type
        except Exception as e:
            # log an error if tag type creation fails for any reason.
            self.logger.log_error(
                f"failed to create tag type '{name}': {e}\n{traceback.format_exc()}"
            )
            return None

    def _define_hardware_register(
        self,
        address: int,
        name: str,  # the symbol name for the register, e.g., "REG_DISPCNT"
        tag_category_name: str,  # e.g., "Display", must be a key in NDS_TAG_TYPE_DEFINITIONS
        description: str = "",  # a comment for the register
    ):
        """
        helper method to define a symbol for a hardware register at a given address
        and apply a descriptive tag to it for better organization and identification
        within the binary ninja user interface.

        args:
            address: the memory-mapped i/o address of the hardware register.
            name: the conventional name for the register symbol.
            tag_category_name: the category name of the tag type (e.g., "Display").
                               this must match a key in NDS_TAG_TYPE_DEFINITIONS.
            description: an optional comment to add for the register at its address.
        """
        try:
            # define the symbol for the register at its memory-mapped address.
            # DataSymbol is appropriate for hardware registers.
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))

            # add the provided description as a comment at the register's address if a description is given.
            if description:
                self.set_comment_at(address, description)

            # retrieve the icon associated with the tag category from our definitions.
            # default to a generic hardware icon if the category is not found.
            tag_icon = NDS_TAG_TYPE_DEFINITIONS.get(
                tag_category_name, "🔩"
            )  # "🔩" is a generic nut/bolt icon.
            tag_type_object = self._get_or_create_tag_type(tag_category_name, tag_icon)

            # if the tag type was successfully obtained or created, add the tag to the register's address.
            if tag_type_object:
                # self.add_tag expects the tag type's name (a string) as its second argument.
                self.add_tag(
                    address, tag_type_object.name, data=name
                )  # using register name as tag data
            else:
                # this indicates an issue with tag type creation/retrieval for this category.
                self.logger.log_warn(
                    f"could not obtain or create tag type '{tag_category_name}' for register '{name}' at 0x{address:08x}. tag not applied."
                )
        except Exception as e:
            # log any errors encountered during register definition, but continue loading other registers.
            self.logger.log_error(
                f"error processing hardware register '{name}' at 0x{address:08x}: {e}\n{traceback.format_exc()}"
            )

    def _map_memory_regions(self) -> None:
        """
        maps the core nds memory regions such as main ram, wram, vram, i/o ports,
        tightly coupled memories (tcm), and bios roms. each region is defined as a
        segment with appropriate permissions (read, write, execute) and tagged.
        ram regions intended for code execution are given minimal file backing
        to help binary ninja persist function definitions in the bndb database.
        """
        self.logger.log_info("mapping nds memory regions...")

        # internal helper function to simplify adding memory regions as segments.
        def add_memory_segment(
            address: int,  # starting virtual address of the segment.
            size: int,  # size of the segment in bytes.
            permissions: SegmentFlag,  # r/w/x permissions for the segment.
            name: str,  # descriptive name for the segment (e.g., "Main RAM").
            tag_name: str = "Memory Region",  # category for the tag, from NDS_TAG_TYPE_DEFINITIONS.
            is_ram_for_code: bool = False,  # if true, provides minimal file backing for bndb function persistence.
        ):
            self.logger.log_debug(
                f"  preparing to map '{name}': addr=0x{address:08x}, size=0x{size:x} ({size // 1024}KB), perms={permissions}"
            )

            file_offset_for_backing = (
                0  # default for non-backed (i/o) or zero-filled (bss) regions.
            )
            file_length_for_backing = 0  # default.

            if is_ram_for_code:
                # provide minimal file backing (e.g., 1 byte from start of rom) for ram regions
                # that might contain executable code. this helps binary ninja save
                # functions defined in these regions to the .bndb file. the actual byte read
                # is insignificant as the region is ram and will be overwritten or zeroed by the program.
                if self.raw_data.length > 0:
                    file_offset_for_backing = (
                        0  # use a valid small offset from the start of the raw file.
                    )
                    file_length_for_backing = (
                        1  # must be non-zero to indicate "file-backed" to binary ninja.
                    )
                else:
                    # if raw file is empty, cannot provide backing.
                    self.logger.log_warn(
                        f"raw rom file length is 0, cannot provide file backing for ram region '{name}'. mapping as non-backed."
                    )
            try:
                self.add_auto_segment(
                    address,
                    size,
                    file_offset_for_backing,
                    file_length_for_backing,
                    permissions,
                )

                tag_icon = NDS_TAG_TYPE_DEFINITIONS.get(
                    tag_name, "🗺️"
                )  # default map icon.
                tag_type_object = self._get_or_create_tag_type(tag_name, tag_icon)
                if tag_type_object:
                    # add a tag at the start of the region for easy identification in the ui.
                    self.add_tag(address, tag_type_object.name, data=f"{name} Start")

                self.set_comment_at(address, f"{name} ({size // 1024}KB)")
                self.logger.log_info(f"  successfully mapped '{name}'.")
            except Exception as e:
                self.logger.log_error(
                    f"failed to map memory region '{name}' at 0x{address:08x}: {e}\n{traceback.format_exc()}"
                )

        # - define standard nds memory regions based on common nds technical documentation.
        # main ram: 4mb, primarily accessible by arm9. code can be loaded here (arm9 main binary, overlays).
        add_memory_segment(
            0x02000000, 0x00400000, self.PERM_RWX, "Main RAM", is_ram_for_code=True
        )

        # shared wram: a portion of wram (work ram) can be allocated to either arm9 or arm7.
        # commonly, a 32kb block is used. arm9 often sees it starting at 0x03000000.
        # arm7 might see it mirrored at a different address (e.g., 0x037f8000), but we map one primary region.
        add_memory_segment(
            0x03000000,
            0x00008000,
            self.PERM_RWX,
            "Shared WRAM (32KB Block)",
            is_ram_for_code=True,
        )

        # arm7 wram: 64kb, typically exclusive to arm7. can contain arm7 code.
        add_memory_segment(
            0x03800000,
            0x00010000,
            self.PERM_RWX,
            "ARM7 WRAM (64KB)",
            is_ram_for_code=True,
        )

        # - i/o ports (memory-mapped hardware registers)
        # main i/o block: shared registers for arm9/arm7, plus arm9-specific (engines, math, etc.)
        add_memory_segment(
            0x04000000,
            0x00001000,
            self.PERM_RW,
            "I/O Registers (Main Block, 0x04000xxx)",
            tag_name="Hardware Register",
        )
        # i/o for ipc fifos, gamecard data input (shared between arm9 and arm7)
        add_memory_segment(
            0x04100000,
            0x00000020,
            self.PERM_RW,
            "I/O Registers (IPC/Card, 0x04100xxx)",
            tag_name="Hardware Register",
        )
        # wireless communications (wifi) i/o and internal ram (primarily used by arm7)
        # the region 0x04800000 - 0x04807FFF covers wifi i/o and 8kb of ram (from 0x04804000).
        add_memory_segment(
            0x04800000,
            0x00008000,
            self.PERM_RW,
            "Wireless Comm (I/O & RAM)",
            tag_name="Wifi",
        )

        # - graphics memory (palette, vram, oam - object attribute memory)
        add_memory_segment(
            0x05000000, 0x00000800, self.PERM_RW, "Standard Palette RAM (2KB)"
        )
        # vram total is 656kb, comprising various banks (a-i). this maps the main contiguous block.
        add_memory_segment(
            0x06000000, 0x000A4000, self.PERM_RW, "VRAM (Main Banks A-I, 656KB)"
        )
        # lcdc (lcd controller) direct access mirror of vram
        add_memory_segment(
            0x06800000, 0x000A4000, self.PERM_RW, "VRAM (LCDC Mapped Alias)"
        )
        add_memory_segment(
            0x07000000, 0x00000800, self.PERM_RW, "OAM - OBJ Attribute Memory (2KB)"
        )

        # - bios roms (read-only memory containing system firmware)
        # arm9 bios: typically 4kb mapped at 0xffff0000.
        add_memory_segment(
            0xFFFF0000,
            0x00001000,
            self.PERM_RX,
            "ARM9 BIOS (4KB)",
            is_ram_for_code=True,
        )  # minimal backing for potential symbols
        # arm7 bios: 16kb, mapped at 0x00000000 from the arm7's perspective (physical address 0x0).
        add_memory_segment(
            0x00000000,
            0x00004000,
            self.PERM_RX,
            "ARM7 BIOS (16KB at Physical 0x0)",
            is_ram_for_code=True,
        )  # minimal backing

        # - tightly coupled memories (tcm) for arm9 (fast, on-chip ram)
        # arm9 itcm (instruction tcm): 32kb. often mirrored from physical 0x0 to virtual 0x01000000.
        # mapping the common 0x01xxxxxx mirror.
        self.logger.log_info(
            "arm9 itcm is typically at physical 0x0, mirrored to 0x01000000. mapping the 0x01xxxxxx mirror (32kb)."
        )
        add_memory_segment(
            0x01000000,
            0x00008000,
            self.PERM_RWX,
            "ARM9 ITCM (32KB Code, Mapped at 0x01xxxxxx)",
            is_ram_for_code=True,
        )

        # arm9 dtcm (data tcm): 16kb. its base address is configurable via a register.
        # a common default observed in software is 0x027c0000 (or near end of main ram).
        # mapping at a common default; actual runtime address can vary based on software configuration.
        dtcm_common_base = 0x027C0000
        self.logger.log_info(
            f"mapping arm9 dtcm at common default 0x{dtcm_common_base:08x} (16kb). actual base is configurable by software."
        )
        add_memory_segment(
            dtcm_common_base,
            0x00004000,
            self.PERM_RWX,
            "ARM9 DTCM (16KB Data, Common Default)",
            is_ram_for_code=True,
        )

        # gba slot memory (game pak waitstate regions like 0x08000000 for rom, 0x0a000000 for ram)
        # are part of the nds memory map but not typically used by nds-mode games for execution.
        # thus, they are not mapped by default by this loader to keep focus on nds-mode areas.

        self.logger.log_info("finished mapping nds memory regions.")

    def _find_nitro_sdk_module_params(self, data: bytes) -> Optional[int]:
        """
        searches for the nitro sdk's `_start_moduleparams` magic bytes within the provided data.
        this structure, if present, contains metadata about the binary, such as its
        compressed size and layout, which is crucial for correct loading of arm9 binaries.

        args:
            data: the byte string (e.g., raw arm9 binary data from rom) to search within.

        returns:
            the starting offset of the `_start_moduleparams` structure relative to the beginning
            of `data` if found and appears valid, otherwise none.
        """
        try:
            # find the first occurrence of the magic byte sequence.
            magic_index = data.find(NITRO_SDK_MODULE_PARAMS_MAGIC)
            if magic_index != -1:
                # the magic bytes are at a fixed offset within the structure.
                # calculate the start of the structure based on this known offset.
                struct_start_offset = magic_index - NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET

                # basic validation: ensure the calculated offset is non-negative and
                # the full structure (given its known size) fits within the provided data.
                if (
                    struct_start_offset >= 0
                    and struct_start_offset + NITRO_SDK_MODULE_PARAMS_SIZE <= len(data)
                ):
                    self.logger.log_info(
                        f"found _start_moduleparams structure at offset 0x{struct_start_offset:x} within provided data block."
                    )
                    return struct_start_offset
                else:
                    self.logger.log_warn(
                        f"found moduleparams magic at index 0x{magic_index:x}, but calculated struct start offset 0x{struct_start_offset:x} is invalid or structure would be out of bounds. structure ignored."
                    )
            else:
                # magic sequence not found.
                self.logger.log_info(
                    "_start_moduleparams magic sequence not found. the binary might be non-sdk, custom-built, or the magic is not present/corrupted."
                )
        except Exception as e:
            # catch any unexpected errors during the search.
            self.logger.log_error(
                f"error searching for nitro sdk moduleparams: {e}\n{traceback.format_exc()}"
            )
        return None  # return none if not found, invalid, or error occurs.

    def _mii_uncompress_backward(self, data: bytes) -> bytes:
        """
        decompresses data assumed to be in a MII LZ77 variant format (backward decompression).
        this implementation aims to preserve the core logic of the original loader,
        particularly its handling of the footer/header structure for determining
        compression type and size, and its fallback behaviors.

        args:
            data: the raw byte string containing the (potentially) compressed data.

        returns:
            a byte string with the decompressed data.

        raises:
            valueerror: if data is too short for essential parts, or decompressed size is invalid.
            eoferror: if source data is exhausted unexpectedly during decompression.
            indexerror: if lz77 copy operations go out of bounds.
        """
        if len(data) < 4:
            raise ValueError(
                "data too short for mii decompression (minimum 4 bytes for footer-like info)."
            )

        # last 4 bytes are treated as a footer containing the decompressed size.
        footer_val_bytes = data[-4:]
        decompressed_size_from_footer = struct.unpack_from("<I", footer_val_bytes, 0)[0]

        # sanity check on decompressed size (e.g., > 256mb is unreasonable for nds).
        if decompressed_size_from_footer > 0x10000000:
            raise ValueError(
                f"invalid mii decompressed_size_from_footer: 0x{decompressed_size_from_footer:x} (too large)."
            )

        # handle cases based on data length and decompressed_size_from_footer
        if len(data) < 8:
            # data is too short for the 8-byte header/footer structure assumed for type 1 lz77.
            if decompressed_size_from_footer == 0:
                self.logger.log_debug(
                    "mii: data length < 8 and decompressed_size is 0. returning empty."
                )
                return b""
            # if size matches data length minus footer, assume uncompressed.
            if decompressed_size_from_footer == len(data) - 4:
                self.logger.log_info(
                    "mii: data length < 8, size matches (data_len - 4). assuming uncompressed."
                )
                return data[:-4]
            # otherwise, it's an error condition for short data with non-matching/non-zero size.
            raise ValueError(
                f"mii: data length {len(data)} is < 8. decompressed_size {decompressed_size_from_footer} "
                "is non-zero and does not match uncompressed expectation. cannot determine format."
            )

        # if len(data) >= 8, we can check the "header_val" (bytes at data[-8:-4])
        header_val_bytes = data[-8:-4]
        header_val_u32 = struct.unpack_from("<I", header_val_bytes, 0)[0]
        comp_type = (header_val_u32 >> 24) & 0xF  # compression type from upper bits

        self.logger.log_debug(
            f"mii: 'header_val' (bytes -8 to -4) is 0x{header_val_u32:08x}, derived comp_type: 0x{comp_type:x}, footer_size: 0x{decompressed_size_from_footer:x}"
        )

        if decompressed_size_from_footer == 0:
            # specific pattern for an empty type 1 compressed block.
            if comp_type == 0x1 and header_val_u32 == 0x10000000:
                self.logger.log_debug(
                    "mii: identified specific empty compressed block pattern (size 0, type 1, header_val 0x10000000)."
                )
                return b""
            else:
                # size is 0, but not the specific empty block pattern. assume empty based on size.
                self.logger.log_warn(
                    f"mii: decompressed_size is 0, but 'header_val' (0x{header_val_u32:x}) or comp_type (0x{comp_type:x}) "
                    "doesn't match standard empty block pattern. assuming empty based on size in footer."
                )
                return b""

        # if compression type is not 0x1 (common nds lz77), treat as uncompressed.
        if comp_type != 0x1:
            self.logger.log_warn(
                f"mii: compression type is 0x{comp_type:x} (not type 1 lz77). "
                "treating as uncompressed (returning raw data minus last 4 bytes as per original logic)."
            )
            # original logic returned data[:-4] here. log if size expectation matches.
            if decompressed_size_from_footer == len(data) - 4:
                self.logger.log_info(
                    "mii: uncompressed fallback, size matches (data_len - 4)."
                )
            else:
                self.logger.log_warn(
                    f"mii: uncompressed fallback, but footer size 0x{decompressed_size_from_footer:x} != data_len-4 (0x{len(data)-4:x})."
                )
            return data[:-4]

        # proceed with type 1 lz77 backward decompression.
        # source reading starts effectively before the 8-byte block used for header/footer vals.
        result_buffer = bytearray(decompressed_size_from_footer)
        dest_offset = decompressed_size_from_footer  # current write position in result_buffer (counts down)
        src_offset = (
            len(data) - 8
        )  # current read position in input `data` (counts down from before the 8-byte block)

        self.logger.log_debug(
            f"mii: starting lz77 decompress. target_size=0x{decompressed_size_from_footer:x}, initial src_offset for flags={src_offset-1}"
        )

        while dest_offset > 0:
            if src_offset <= 0:  # should have at least one flag byte remaining
                raise EOFError(
                    f"mii source data exhausted unexpectedly (dest_offset={dest_offset}, src_offset={src_offset}, expected flag byte)"
                )

            block_flags = data[src_offset - 1]  # read flag byte
            src_offset -= 1

            for bit_num in range(8):  # process 8 blocks/literals per flag byte
                if dest_offset <= 0:
                    break  # finished decompression

                is_compressed_block = (block_flags & 0x80) != 0  # check msb
                block_flags = (block_flags << 1) & 0xFF  # shift for next flag bit

                if not is_compressed_block:  # literal byte
                    if src_offset <= 0:
                        raise EOFError(
                            f"mii source exhausted (expected literal byte) (dest_offset={dest_offset}, src_offset={src_offset})"
                        )
                    literal_byte = data[src_offset - 1]
                    src_offset -= 1
                    dest_offset -= 1
                    if (
                        dest_offset < 0
                    ):  # sanity check, should not happen if decompressed_size_from_footer was correct
                        raise IndexError(
                            "mii destination offset became negative while writing literal"
                        )
                    result_buffer[dest_offset] = literal_byte
                else:  # lz77 copy block (compressed)
                    if src_offset < 2:  # need 2 bytes for lz77 parameters
                        raise EOFError(
                            f"mii source exhausted (expected lz77 block params) (dest_offset={dest_offset}, src_offset={src_offset})"
                        )

                    byte1 = data[src_offset - 1]
                    byte2 = data[src_offset - 2]
                    src_offset -= 2

                    # length: 3-18. (byte1 upper 4 bits) + 3.
                    copy_length = ((byte1 & 0xF0) >> 4) + 3
                    # displacement: 1-4096. (byte1 lower 4 bits << 8 | byte2) + 1.
                    copy_displacement = (((byte1 & 0x0F) << 8) | byte2) + 1

                    if dest_offset < copy_length:
                        raise ValueError(
                            f"mii lz77 copy length ({copy_length}) exceeds remaining destination space ({dest_offset}). "
                            "possible corrupt data or incorrect decompressed_size_from_footer."
                        )

                    # perform the backward copy from previously decompressed data in result_buffer
                    try:
                        for k in range(copy_length):
                            current_write_idx = (
                                dest_offset - 1 - k
                            )  # calculate write index for this byte of the copy
                            # source for copy is relative to current write_idx in destination buffer
                            current_read_idx = current_write_idx + copy_displacement
                            if not (
                                0 <= current_read_idx < decompressed_size_from_footer
                                and 0
                                <= current_write_idx
                                < decompressed_size_from_footer
                            ):
                                raise IndexError(
                                    f"mii lz77 copy out of bounds: read_idx={current_read_idx}, write_idx={current_write_idx}, "
                                    f"disp={copy_displacement}, len={copy_length}, current_dest_offset_start_of_copy={dest_offset}, total_size={decompressed_size_from_footer}"
                                )
                            result_buffer[current_write_idx] = result_buffer[
                                current_read_idx
                            ]
                        dest_offset -= (
                            copy_length  # advance dest_offset by the full copy_length
                        )
                    except IndexError as ie:
                        raise IndexError(
                            f"mii lz77 copy error: {ie} (len={copy_length}, disp={copy_displacement}, "
                            f"dest_offset_at_error_iteration_start={dest_offset}, write_idx_attempted_base={dest_offset - 1}, read_idx_attempted_base={dest_offset - 1 + copy_displacement})"
                        )
                if (
                    dest_offset <= 0 and bit_num < 7
                ):  # check if finished after processing current bit's block
                    break

        if dest_offset != 0:
            # this means the decompressed data did not exactly fill the allocated buffer.
            self.logger.log_warn(
                f"mii decompression finished, but dest_offset is non-zero ({dest_offset}). "
                "result may be truncated or padded if original size in footer was incorrect."
            )
        return bytes(result_buffer)

    def _load_binary_segment(
        self,
        cpu_name: str,  # "ARM9" or "ARM7"
        rom_offset: int,
        rom_size: int,
        ram_address: int,
        bss_size: int,
        entry_address: int,  # used for logging and setting entry point symbol
        is_arm9_with_module_params: bool = False,
    ) -> Optional[int]:
        """
        loads a main binary (arm9 or arm7) into its specified ram address.
        handles potential decompression for arm9 binaries if nitro sdk module parameters
        are found and indicate compression. also maps the bss section.
        defines segments and sections in binary ninja for the loaded code/data and bss.

        args:
            cpu_name: identifier string ("ARM9" or "ARM7").
            rom_offset: file offset of the binary in the rom.
            rom_size: size of the binary in the rom file.
            ram_address: target memory address to load the binary.
            bss_size: size of the bss section for this binary.
            entry_address: the raw entry address for this binary (from header).
            is_arm9_with_module_params: flag to indicate if this is an arm9 binary
                                       that might use nitro sdk moduleparams for compression info.

        returns:
            the effective size of the loaded code/data portion in memory (after any
            decompression), or none if loading failed critically. returns 0 if rom_size was 0.
        """
        if (
            not self.nds_rom or not self.nds_rom.header
        ):  # should be checked by caller, but defensive
            self.logger.log_error(
                f"cannot load {cpu_name} binary, rom structure not parsed or header missing."
            )
            return None
        if rom_size == 0:
            self.logger.log_info(
                f"{cpu_name} rom_size in header is 0. skipping loading of code/data part."
            )
            # still need to handle bss if bss_size > 0, so return 0 for effective_code_data_size
            effective_code_data_size_in_memory = 0
            # proceed to bss handling outside this block
        else:  # rom_size > 0
            self.logger.log_info(
                f"loading {cpu_name} binary: rom_offset=0x{rom_offset:x}, rom_size=0x{rom_size:x}, load_addr=0x{ram_address:x}"
            )
            raw_binary_data: bytes = self.raw_data.read(rom_offset, rom_size)
            if not raw_binary_data or len(raw_binary_data) != rom_size:
                self.logger.log_error(
                    f"failed to read full {cpu_name} binary data from rom (read {len(raw_binary_data)}, expected {rom_size}). cannot load."
                )
                return None  # critical failure for this binary

            effective_code_data_size_in_memory = 0
            final_data_to_write_to_ram = (
                raw_binary_data  # default: treat as uncompressed
            )
            segment_file_offset_for_mapping = rom_offset
            segment_file_length_for_mapping = rom_size
            was_decompressed_successfully = False
            code_section_comment_suffix = "(raw)"

            if is_arm9_with_module_params:
                module_params_struct_offset = self._find_nitro_sdk_module_params(
                    raw_binary_data
                )
                sdk_derived_code_data_size_in_memory = 0
                is_compressed_by_sdk_params = False

                if module_params_struct_offset is not None:
                    try:
                        # offsets are relative to the start of raw_binary_data here
                        autoload_end_addr = struct.unpack_from(
                            "<I", raw_binary_data, module_params_struct_offset + 8
                        )[0]
                        compressed_static_end_marker = struct.unpack_from(
                            "<I", raw_binary_data, module_params_struct_offset + 20
                        )[0]

                        is_compressed_by_sdk_params = compressed_static_end_marker != 0
                        sdk_derived_code_data_size_in_memory = (
                            autoload_end_addr - ram_address
                        )

                        self.logger.log_info(
                            f"  {cpu_name} moduleparams found: compressed_marker=0x{compressed_static_end_marker:x} (is_compressed={is_compressed_by_sdk_params}), "
                            f"autoload_end_addr=0x{autoload_end_addr:x}, derived_sdk_code_data_size=0x{sdk_derived_code_data_size_in_memory:x}."
                        )

                        max_reasonable_decomp_size = (
                            rom_size * 25
                        )  # allow up to 25x compression ratio as a sanity check
                        if (
                            not (
                                0
                                <= sdk_derived_code_data_size_in_memory
                                <= max_reasonable_decomp_size
                            )
                            or sdk_derived_code_data_size_in_memory < 0
                        ):
                            self.logger.log_error(
                                f"  moduleparams: invalid sdk_derived_code_data_size (0x{sdk_derived_code_data_size_in_memory:x}). "
                                f"will treat as uncompressed or use rom_size from header."
                            )
                            is_compressed_by_sdk_params = (
                                False  # be cautious, ignore compression flag
                            )
                        elif (
                            sdk_derived_code_data_size_in_memory == 0
                            and is_compressed_by_sdk_params
                        ):
                            self.logger.log_info(
                                "  moduleparams indicate compression but derived size in memory is 0. assuming empty payload after decompression."
                            )
                    except Exception as e:
                        self.logger.log_error(
                            f"error processing _start_moduleparams for {cpu_name}: {e}. treating as uncompressed."
                        )
                        is_compressed_by_sdk_params = False
                else:  # module_params structure not found
                    self.logger.log_info(
                        f"  {cpu_name}: _start_moduleparams not found. assuming uncompressed or using rom_size from header."
                    )

                if is_compressed_by_sdk_params:
                    self.logger.log_info(
                        f"  attempting {cpu_name} decompression (expected decompressed size from sdk_params: 0x{sdk_derived_code_data_size_in_memory:x})..."
                    )
                    try:
                        decompressed_data = self._mii_uncompress_backward(
                            raw_binary_data
                        )
                        actual_decompressed_size = len(decompressed_data)
                        self.logger.log_info(
                            f"  {cpu_name} actual decompressed size: 0x{actual_decompressed_size:x}."
                        )

                        if (
                            sdk_derived_code_data_size_in_memory > 0
                            and actual_decompressed_size
                            != sdk_derived_code_data_size_in_memory
                        ):
                            self.logger.log_warn(
                                f"  actual decompressed {cpu_name} size (0x{actual_decompressed_size:x}) "
                                f"differs from moduleparams expected (0x{sdk_derived_code_data_size_in_memory:x}). using actual decompressed size for memory."
                            )
                        elif (
                            sdk_derived_code_data_size_in_memory == 0
                            and actual_decompressed_size > 0
                        ):
                            self.logger.log_warn(
                                f"  moduleparams expected 0 size after decompression, but actual was 0x{actual_decompressed_size:x}. using actual."
                            )
                        effective_code_data_size_in_memory = actual_decompressed_size
                        final_data_to_write_to_ram = decompressed_data
                        was_decompressed_successfully = True
                        code_section_comment_suffix = "(decompressed)"
                    except Exception as e:
                        self.logger.log_error(
                            f"{cpu_name} decompression failed: {e}. falling back to raw mapping using rom_size."
                        )
                        effective_code_data_size_in_memory = (
                            rom_size  # fallback to original rom_size for memory
                        )
                        final_data_to_write_to_ram = raw_binary_data
                        code_section_comment_suffix = "(raw, decompression failed)"
                else:  # not compressed according to sdk params, or params not found/invalid
                    code_section_comment_suffix = (
                        "(raw, sdk uncompressed)"
                        if module_params_struct_offset
                        else "(raw, no sdk params)"
                    )
                    # if module params were found but indicated uncompressed, use its derived size for memory if valid.
                    # otherwise, use the plain rom_size from header for memory.
                    if (
                        module_params_struct_offset
                        and sdk_derived_code_data_size_in_memory > 0
                    ):
                        effective_code_data_size_in_memory = (
                            sdk_derived_code_data_size_in_memory
                        )
                    else:  # no valid sdk size, or no params found
                        effective_code_data_size_in_memory = rom_size
                    final_data_to_write_to_ram = (
                        raw_binary_data  # data is already what it should be in memory
                    )
            else:  # not arm9 with module params (e.g., arm7) -> typically not compressed
                effective_code_data_size_in_memory = rom_size
                final_data_to_write_to_ram = raw_binary_data
                code_section_comment_suffix = "(raw)"

            # define the segment for the code/data part
            if effective_code_data_size_in_memory > 0:
                self.logger.log_info(
                    f"  adding segment for {cpu_name} code/data: mem_addr=0x{ram_address:08x}, mem_size=0x{effective_code_data_size_in_memory:x}, "
                    f"file_offset=0x{segment_file_offset_for_mapping:x} (original rom_offset), file_size=0x{segment_file_length_for_mapping:x} (original rom_size)"
                )
                self.add_auto_segment(
                    ram_address,
                    effective_code_data_size_in_memory,  # size in memory (can be different from rom_size if decompressed)
                    segment_file_offset_for_mapping,  # original file offset of this binary
                    segment_file_length_for_mapping,  # original file length of this binary (before decompression)
                    self.PERM_RX,  # readable and executable
                )
                # if data was transformed (decompressed) or if the effective memory size differs from the original file portion mapped,
                # we need to explicitly write the final data into the segment in binary ninja's view.
                if (
                    was_decompressed_successfully
                    or effective_code_data_size_in_memory
                    != segment_file_length_for_mapping
                ):
                    self.logger.log_info(
                        f"  writing {len(final_data_to_write_to_ram)} bytes of processed {cpu_name} data to memory address 0x{ram_address:08x}"
                    )
                    bytes_written = self.write(ram_address, final_data_to_write_to_ram)
                    if bytes_written != len(final_data_to_write_to_ram):
                        self.logger.log_error(
                            f"{cpu_name} data write error: expected {len(final_data_to_write_to_ram)} bytes, wrote {bytes_written} bytes. segment content may be corrupt."
                        )
                self.add_auto_section(
                    name=f".{cpu_name.lower()}_code_data",  # e.g., .arm9_code_data
                    start=ram_address,
                    length=effective_code_data_size_in_memory,
                    semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                    type="Code",  # binary ninja section type
                )
                self.set_comment_at(
                    ram_address,
                    f"{cpu_name} code/data start {code_section_comment_suffix}",
                )
            elif (
                rom_size > 0
            ):  # rom_size was > 0, but effective_code_data_size_in_memory ended up 0 (e.g., decompression yielded empty)
                self.logger.log_warn(
                    f"  {cpu_name} has rom_size 0x{rom_size:x} but effective code/data size in memory is 0. no code/data segment mapped."
                )

        # handle bss section for this binary
        if bss_size > 0:
            # bss starts immediately after the code/data portion in memory
            bss_start_address = ram_address + effective_code_data_size_in_memory
            self.logger.log_info(
                f"  mapping {cpu_name} bss: addr=0x{bss_start_address:08x}, size=0x{bss_size:x}"
            )
            # bss is not file-backed, so file_offset and file_length are 0 for add_auto_segment.
            self.add_auto_segment(
                bss_start_address, bss_size, 0, 0, self.PERM_RW
            )  # readable and writable
            self.add_auto_section(
                name=f".{cpu_name.lower()}.bss",  # e.g., .arm9.bss
                start=bss_start_address,
                length=bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,  # bss is read-write data
                type="BSS",  # binary ninja section type
            )
            self.set_comment_at(bss_start_address, f"{cpu_name} BSS start")
        else:
            self.logger.log_info(
                f"  no {cpu_name} BSS section defined (bss_size is 0 in header)."
            )

        self.logger.log_info(
            f"{cpu_name} binary processed: entry_addr_header=0x{entry_address:08x}, load_addr=0x{ram_address:08x}, "
            f"code_data_mem_size=0x{effective_code_data_size_in_memory:x}, bss_size=0x{bss_size:x}"
        )
        return effective_code_data_size_in_memory

    def _load_overlays(self, cpu_name: str, overlay_table: Optional[NDSOverlayTable]):
        """
        loads arm9 or arm7 overlays into their specified ram addresses.
        handles decompression for compressed overlays, maps segments for code/data
        and bss sections, and defines sections and static initializer symbols in binary ninja.

        args:
            cpu_name: string identifier, either "ARM9" or "ARM7".
            overlay_table: the parsed `NDSOverlayTable` for the respective cpu,
                           obtained from `self.nds_rom`.
        """
        if (
            not self.nds_rom
            or not self.nds_rom.fat_entries
            or not overlay_table
            or not overlay_table.entries
        ):
            self.logger.log_info(
                f"no {cpu_name} overlays found or prerequisites missing (fat/overlay table). skipping {cpu_name} overlay loading."
            )
            return
        # critical check for a field expected from the nds_cartridge parsing library.
        # if this attribute is missing, overlay compression status cannot be determined.
        if not hasattr(NDSOverlayEntry, "is_compressed"):
            self.logger.log_error(
                f"external library `nds_cartridge.py` NDSOverlayEntry class is missing the 'is_compressed' attribute. "
                f"cannot load {cpu_name} overlays correctly as compression status is unknown. please update the library."
            )
            return

        self.logger.log_info(
            f"loading {cpu_name} overlays (total {len(overlay_table.entries)} entries in table)..."
        )
        num_loaded_successfully = 0
        num_failed_or_skipped = 0

        for i, overlay_entry in enumerate(overlay_table.entries):
            # file_id 0xffff is a standard marker for an unused/placeholder overlay entry.
            if overlay_entry.file_id == 0xFFFF:
                self.logger.log_debug(
                    f"  skipping {cpu_name} overlay entry {i}: file_id is 0xFFFF (placeholder)."
                )
                continue
            # validate file_id against the bounds of the file allocation table.
            if overlay_entry.file_id >= len(self.nds_rom.fat_entries):
                self.logger.log_warn(
                    f"  skipping invalid {cpu_name} overlay entry {i}: file_id {overlay_entry.file_id} "
                    f"is out of FAT bounds (max index {len(self.nds_rom.fat_entries)-1}). overlay entry is corrupt."
                )
                num_failed_or_skipped += 1
                continue
            # skip if the overlay entry defines no ram or bss region (effectively empty).
            if overlay_entry.ram_size == 0 and overlay_entry.bss_size == 0:
                self.logger.log_info(
                    f"  skipping empty {cpu_name} overlay entry {i} (file_id {overlay_entry.file_id}): "
                    "ram_size and bss_size are both 0 in overlay table."
                )
                continue

            fat_entry = self.nds_rom.fat_entries[overlay_entry.file_id]
            overlay_size_in_rom_file = fat_entry.end_address - fat_entry.start_address
            overlay_data_raw_from_rom = b""
            segment_name_base = f"{cpu_name}_Overlay_{i}_File{overlay_entry.file_id}"  # unique name for logging and symbols

            self.logger.log_debug(
                f"  processing {segment_name_base}: rom_offset=0x{fat_entry.start_address:x}, rom_size=0x{overlay_size_in_rom_file:x}, "
                f"ram_addr=0x{overlay_entry.ram_address:x}, ram_size_hdr=0x{overlay_entry.ram_size:x}, bss_size_hdr=0x{overlay_entry.bss_size:x}, "
                f"is_compressed_flag={overlay_entry.is_compressed}, static_init=0x{overlay_entry.static_initializer_start_address:x}"
            )

            # read the raw overlay data from the rom file if its size is greater than zero.
            if overlay_size_in_rom_file > 0:
                overlay_data_raw_from_rom = self.raw_data.read(
                    fat_entry.start_address, overlay_size_in_rom_file
                )
                if (
                    not overlay_data_raw_from_rom
                    or len(overlay_data_raw_from_rom) != overlay_size_in_rom_file
                ):
                    self.logger.log_error(
                        f"failed to read data for {segment_name_base} from rom. expected 0x{overlay_size_in_rom_file:x} bytes. skipping this overlay."
                    )
                    num_failed_or_skipped += 1
                    continue
            elif (
                overlay_entry.ram_size > 0
            ):  # overlay expects ram content, but no corresponding data in rom (fat entry size is 0).
                self.logger.log_warn(
                    f"{segment_name_base} expects ram content (ram_size_hdr 0x{overlay_entry.ram_size:x}) but has no data in rom (rom_size 0x{overlay_size_in_rom_file:x}). "
                    "code/data part will be empty. will proceed to bss if any."
                )
                # if ram_size is > 0 but rom_size is 0, this overlay might be purely bss or an error in the rom.

            load_address = overlay_entry.ram_address
            effective_ram_size_in_memory = (
                0  # actual size of the code/data part in memory after processing
            )
            final_data_to_write_to_ram = (
                b""  # the bytes to write into the memory segment
            )
            overlay_was_decompressed_successfully = False
            code_section_comment_suffix = "(raw)"

            if overlay_entry.is_compressed:
                if (
                    not overlay_data_raw_from_rom
                ):  # cannot decompress if no raw data was read (e.g., rom_size_in_file was 0)
                    self.logger.log_error(
                        f"cannot decompress {segment_name_base}: no raw data from rom (rom_size was 0x{overlay_size_in_rom_file:x})."
                    )
                    if (
                        overlay_entry.ram_size > 0
                    ):  # if it expected content, this is a failure for the code/data part
                        num_failed_or_skipped += 1
                        continue  # skip to next overlay
                    # if ram_size is 0, it might be a pure bss overlay incorrectly marked compressed; proceed to bss handling.
                else:  # have raw data to decompress
                    self.logger.log_info(
                        f"  decompressing {segment_name_base} (rom_size: 0x{overlay_size_in_rom_file:x}, expected ram_size from header: 0x{overlay_entry.ram_size:x})..."
                    )
                    try:
                        decompressed_data = self._mii_uncompress_backward(
                            overlay_data_raw_from_rom
                        )
                        actual_decompressed_size = len(decompressed_data)
                        self.logger.log_info(
                            f"   {segment_name_base} actual decompressed size: 0x{actual_decompressed_size:x}"
                        )

                        # compare actual decompressed size with the size specified in the overlay table entry.
                        if (
                            overlay_entry.ram_size > 0
                            and actual_decompressed_size != overlay_entry.ram_size
                        ):
                            self.logger.log_warn(
                                f"   {segment_name_base}: actual decompressed size (0x{actual_decompressed_size:x}) "
                                f"differs from overlay table's ram_size (0x{overlay_entry.ram_size:x}). using actual decompressed size for memory mapping."
                            )
                        elif (
                            overlay_entry.ram_size == 0 and actual_decompressed_size > 0
                        ):
                            self.logger.log_warn(
                                f"   {segment_name_base}: overlay table's ram_size was 0, but decompressed to 0x{actual_decompressed_size:x}. using actual size."
                            )

                        effective_ram_size_in_memory = actual_decompressed_size
                        final_data_to_write_to_ram = decompressed_data
                        overlay_was_decompressed_successfully = True
                        code_section_comment_suffix = "(decompressed)"
                    except Exception as e:
                        self.logger.log_error(
                            f"failed to decompress {segment_name_base}: {e}. code/data part will be empty or mapped raw if a fallback were implemented (currently not)."
                        )
                        # if decompression fails, effective_ram_size_in_memory remains 0.
                        code_section_comment_suffix = "(raw, decompression failed)"
            else:  # not compressed according to overlay_entry.is_compressed flag
                effective_ram_size_in_memory = (
                    overlay_size_in_rom_file  # use raw size from rom for memory
                )
                final_data_to_write_to_ram = overlay_data_raw_from_rom
                code_section_comment_suffix = "(raw)"

            # add segment for the code/data part of the overlay if it has content
            if effective_ram_size_in_memory > 0:
                self.logger.log_info(
                    f"  adding segment for {segment_name_base} code/data: mem_addr=0x{load_address:08x}, mem_size=0x{effective_ram_size_in_memory:x}, "
                    f"file_offset=0x{fat_entry.start_address:x} (original rom_offset), file_size=0x{overlay_size_in_rom_file:x} (original rom_size)"
                )
                self.add_auto_segment(
                    load_address,
                    effective_ram_size_in_memory,  # size in memory (can be different from rom_size if decompressed)
                    fat_entry.start_address,  # original file offset of this overlay
                    overlay_size_in_rom_file,  # original file length of this overlay (before decompression)
                    self.PERM_RX,  # readable and executable
                )
                # if data was transformed (decompressed) or if the effective memory size differs from the original file portion mapped,
                # we need to explicitly write the final data into the segment in binary ninja's view.
                if (
                    overlay_was_decompressed_successfully
                    or effective_ram_size_in_memory != overlay_size_in_rom_file
                ):
                    self.logger.log_info(
                        f"  writing {len(final_data_to_write_to_ram)} bytes of processed {segment_name_base} data to memory address 0x{load_address:08x}"
                    )
                    bytes_written = self.write(load_address, final_data_to_write_to_ram)
                    if bytes_written != len(final_data_to_write_to_ram):
                        self.logger.log_error(
                            f"{segment_name_base} data write error: expected {len(final_data_to_write_to_ram)} bytes, wrote {bytes_written} bytes. segment content may be corrupt."
                        )

                self.add_auto_section(
                    name=f".{segment_name_base}",  # e.g., .ARM9_Overlay_0_File123
                    start=load_address,
                    length=effective_ram_size_in_memory,
                    semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                    type="OverlayCode",  # custom section type for overlays
                )
                self.set_comment_at(
                    load_address,
                    f"{segment_name_base} code/data start {code_section_comment_suffix}",
                )
            elif (
                overlay_entry.ram_size > 0
            ):  # expected ram content (ram_size_hdr > 0) but no valid data was mapped (effective_ram_size_in_memory is 0)
                self.logger.log_warn(
                    f"  {segment_name_base} expected RAM size 0x{overlay_entry.ram_size:x} in header, but no valid data was mapped for its code/data section (e.g., decompression yielded empty or rom_size was 0)."
                )

            # add bss segment for the overlay if bss_size is defined
            if overlay_entry.bss_size > 0:
                # bss starts immediately after the code/data portion in memory
                bss_start_address = load_address + effective_ram_size_in_memory
                self.logger.log_info(
                    f"  mapping {segment_name_base} BSS: addr=0x{bss_start_address:08x}, size=0x{overlay_entry.bss_size:x}"
                )
                # bss is not file-backed.
                self.add_auto_segment(
                    bss_start_address, overlay_entry.bss_size, 0, 0, self.PERM_RW
                )  # readable and writable
                self.add_auto_section(
                    name=f".{segment_name_base}.bss",  # e.g., .ARM9_Overlay_0_File123.bss
                    start=bss_start_address,
                    length=overlay_entry.bss_size,
                    semantics=SectionSemantics.ReadWriteDataSectionSemantics,  # bss is read-write data
                    type="OverlayBSS",  # custom section type for overlay bss
                )
                self.set_comment_at(bss_start_address, f"{segment_name_base} BSS start")

            # define symbol for static initializer function if present and valid
            if overlay_entry.static_initializer_start_address != 0:
                init_raw_addr = overlay_entry.static_initializer_start_address
                init_func_addr = (
                    init_raw_addr & ~1
                )  # align to 2 bytes for arm/thumb function address
                # is_thumb_init = (init_raw_addr & 1) != 0 # lsb indicates thumb, useful for disassembler hint

                # check if the initializer address falls within the loaded code/data part of this overlay
                if effective_ram_size_in_memory > 0 and (
                    load_address
                    <= init_func_addr
                    < load_address + effective_ram_size_in_memory
                ):
                    self.logger.log_info(
                        f"  defining symbol for {segment_name_base} static initializer at 0x{init_func_addr:08x}."
                    )
                    self.define_auto_symbol(
                        Symbol(
                            SymbolType.FunctionSymbol,
                            init_func_addr,
                            f"{segment_name_base}_Init",
                        )
                    )
                    self.set_comment_at(
                        init_func_addr,
                        f"{segment_name_base} static initializer (entry point for this overlay module)",
                    )
                    # overlay initializers are not primary entry points for the whole rom,
                    # so self.add_entry_point() is not typically called here.
                else:
                    self.logger.log_warn(
                        f"  {segment_name_base} static initializer address 0x{init_raw_addr:x} is outside its loaded/valid RAM region "
                        f"(mapped region: 0x{load_address:x} to 0x{load_address + effective_ram_size_in_memory -1 :x}). "
                        "skipping symbol definition for initializer."
                    )
            num_loaded_successfully += 1

        # final log summarizing overlay loading for this cpu
        log_func = (
            self.logger.log_info if num_failed_or_skipped == 0 else self.logger.log_warn
        )
        log_func(
            f"finished loading {cpu_name} overlays: {num_loaded_successfully} processed, {num_failed_or_skipped} failed or were skipped."
        )

    def _define_all_io_registers(self) -> None:
        """
        defines symbols and tags for all known nds i/o hardware registers
        as specified in the `NDS_IO_REGISTERS` list (imported from `..defs.nds`).
        this makes hardware registers easily identifiable in binary ninja's ui.
        """
        self.logger.log_info("defining nds i/o hardware registers...")
        if not NDS_IO_REGISTERS:  # check if the imported list is populated.
            self.logger.log_info(
                "NDS_IO_REGISTERS list is empty or not available. no nds-specific i/o registers will be defined."
            )
            return

        defined_count = 0
        for addr, name, tag_category, desc in NDS_IO_REGISTERS:
            self.logger.log_debug(
                f"  defining i/o register: {name} at 0x{addr:08x} (Category: {tag_category})"
            )
            self._define_hardware_register(addr, name, tag_category, desc)
            defined_count += 1
        self.logger.log_info(
            f"defined {defined_count}/{len(NDS_IO_REGISTERS)} nds i/o registers from the provided list."
        )

    def _define_rom_entry_points(self) -> None:
        """
        defines the primary entry points for arm9 and arm7 processors based on
        information from the parsed rom header. it adds these addresses as official
        entry points to binary ninja and defines `_start9` and `_start7` symbols
        at these locations. actual function creation is deferred to binary ninja's
        analysis passes.
        """
        if (
            not self.nds_rom or not self.nds_rom.header
        ):  # ensure rom structure was parsed
            self.logger.log_error(
                "cannot define rom entry points, rom structure not parsed or header missing."
            )
            return

        header = self.nds_rom.header

        # arm9 entry point
        arm9_entry_raw_from_header = header.arm9_entry_address
        # function addresses must be aligned (lsb is thumb mode indicator).
        self._primary_arm9_entry_point = arm9_entry_raw_from_header & ~1
        arm9_expected_load_addr = header.arm9_ram_address

        # validate that the entry point address falls within an executable segment
        # that was actually loaded at the expected arm9 ram address.
        segment_at_arm9_entry = self.get_segment_at(self._primary_arm9_entry_point)
        if (
            segment_at_arm9_entry
            and segment_at_arm9_entry.start == arm9_expected_load_addr
            and segment_at_arm9_entry.executable
        ):
            self.logger.log_info(
                f"defining arm9 entry point: symbol '_start9' at 0x{self._primary_arm9_entry_point:08x}."
            )
            self.add_entry_point(self._primary_arm9_entry_point)
            self.define_auto_symbol(
                Symbol(
                    SymbolType.FunctionSymbol, self._primary_arm9_entry_point, "_start9"
                )
            )
        else:
            self.logger.log_warn(
                f"arm9 entry point 0x{self._primary_arm9_entry_point:08x} (raw from header 0x{arm9_entry_raw_from_header:x}) "
                f"is not within a valid executable segment starting at the expected load address 0x{arm9_expected_load_addr:x}. "
                f"segment found: {segment_at_arm9_entry}. "
                "_start9 symbol/entry point may not be effective, or analysis might not start correctly for arm9."
            )
            self._primary_arm9_entry_point = None  # invalidate if not in a good segment to prevent its use by perform_get_entry_point.

        # arm7 entry point
        arm7_entry_raw_from_header = header.arm7_entry_address
        self._primary_arm7_entry_point = arm7_entry_raw_from_header & ~1
        arm7_expected_load_addr = header.arm7_ram_address

        segment_at_arm7_entry = self.get_segment_at(self._primary_arm7_entry_point)
        if (
            segment_at_arm7_entry
            and segment_at_arm7_entry.start == arm7_expected_load_addr
            and segment_at_arm7_entry.executable
        ):
            self.logger.log_info(
                f"defining arm7 entry point: symbol '_start7' at 0x{self._primary_arm7_entry_point:08x}."
            )
            # arm7 entry point is also added. binary ninja can handle multiple entry points.
            # analysis often focuses on the first one added unless specified otherwise by user or analysis settings.
            self.add_entry_point(self._primary_arm7_entry_point)
            self.define_auto_symbol(
                Symbol(
                    SymbolType.FunctionSymbol, self._primary_arm7_entry_point, "_start7"
                )
            )
        else:
            self.logger.log_warn(
                f"arm7 entry point 0x{self._primary_arm7_entry_point:08x} (raw from header 0x{arm7_entry_raw_from_header:x}) "
                f"is not within a valid executable segment starting at the expected load address 0x{arm7_expected_load_addr:x}. "
                f"segment found: {segment_at_arm7_entry}. "
                "_start7 symbol/entry point may not be effective."
            )
            self._primary_arm7_entry_point = None  # invalidate

        # define a symbol for debug rom information if present in the header.
        # the debug rom itself is not typically loaded as executable code by this loader.
        if header.debug_rom_offset != 0 and header.debug_size > 0:
            # use debug_ram_address from header if valid, else a common fallback.
            debug_load_addr = (
                header.debug_ram_address
                if header.debug_ram_address != 0
                else 0x02400000
            )
            self.logger.log_info(
                f"debug rom info found in header: rom_offset=0x{header.debug_rom_offset:x}, size=0x{header.debug_size:x}. "
                f"defining data symbol 'arm9_debug_load_address' at potential load address 0x{debug_load_addr:08x}."
            )
            self.define_auto_symbol(
                Symbol(
                    SymbolType.DataSymbol, debug_load_addr, "arm9_debug_load_address"
                )
            )

    # - main initialization logic for the view
    def init(self) -> bool:
        """
        initializes the NDSView. this is the main setup method called by binary ninja
        after `is_valid_for_data` returns true. it orchestrates the entire loading process:
        1.  parses the NDS ROM structure (header, fat, overlays, etc.).
        2.  initializes NDS-specific tag types for UI categorization.
        3.  maps fixed NDS hardware memory regions (RAM, VRAM, I/O, TCM, BIOS).
        4.  loads the ARM9 and ARM7 main binaries, including decompression if applicable.
        5.  loads ARM9 and ARM7 overlay files.
        6.  defines known NDS I/O hardware registers as symbols with tags.
        7.  defines the program entry points for ARM9 and ARM7 from the ROM header.

        returns:
            true if all initialization steps complete successfully and the view is ready for analysis,
            false otherwise, indicating a failure to binary ninja.
        """
        # architecture and platform should have been validated and set in __init__.
        # if they are not set, __init__ would have raised an error, preventing init from being called.
        if not self.arch or not self.platform:  # defensive check
            self.logger.log_error(
                "critical: architecture or platform is not set. cannot initialize NDSView. this indicates an issue in __init__."
            )
            return False

        try:
            self.logger.log_info(
                f"starting nds rom loading process for '{self.file.filename}'..."
            )

            # step 1: parse the nds rom structure. this is fundamental.
            if not self._parse_rom_structure():
                self.logger.log_error(
                    "failed to parse nds rom structure. aborting NDSView initialization."
                )
                return False  # cannot proceed without a valid rom structure.

            # step 2: define nds-specific tag types for categorizing elements in the ui.
            self._initialize_tag_types()

            # step 3: map fixed nds hardware memory regions.
            self._map_memory_regions()

            # ensure nds_rom and its header are valid after parsing before proceeding to load binaries.
            if not self.nds_rom or not self.nds_rom.header:
                self.logger.log_error(
                    "nds_rom object or its header is invalid after parsing. cannot load binaries."
                )
                return False
            header = self.nds_rom.header  # shorthand for easier access to header fields

            # step 4a: load arm9 main binary.
            self._load_binary_segment(
                cpu_name="ARM9",
                rom_offset=header.arm9_rom_offset,
                rom_size=header.arm9_size,
                ram_address=header.arm9_ram_address,
                bss_size=header.arm9_bss_size,
                entry_address=header.arm9_entry_address,
                is_arm9_with_module_params=True,  # arm9 binaries often use moduleparams
            )

            # step 4b: load arm7 main binary.
            self._load_binary_segment(
                cpu_name="ARM7",
                rom_offset=header.arm7_rom_offset,
                rom_size=header.arm7_size,
                ram_address=header.arm7_ram_address,
                bss_size=header.arm7_bss_size,
                entry_address=header.arm7_entry_address,
                is_arm9_with_module_params=False,  # arm7 binaries typically do not use moduleparams for compression
            )

            # step 5: load arm9 and arm7 overlays.
            self._load_overlays("ARM9", self.nds_rom.arm9_overlay_table)
            self._load_overlays("ARM7", self.nds_rom.arm7_overlay_table)

            # step 6: define known nds i/o hardware registers.
            self._define_all_io_registers()

            # step 7: define the program entry points from the rom header.
            self._define_rom_entry_points()

            self.logger.log_info(
                "nds rom loading and setup steps complete. triggering analysis by binary ninja..."
            )
            # trigger analysis to run in the background.
            # it's generally recommended to use `update_analysis()` instead of `update_analysis_and_wait()`
            # in loaders to avoid potential deadlocks or ui freezes, especially with complex files.
            self.update_analysis()
            self.logger.log_info(
                "analysis update triggered. initial analysis will run in the background."
            )

            return True  # initialization successful

        except Exception as e:
            # catch any unexpected errors during the entire initialization process.
            self.logger.log_error(
                f"an unexpected critical error occurred during nds rom initialization: {e}"
            )
            self.logger.log_error(f"traceback:\n{traceback.format_exc()}")
            return False  # indicate failure to binary ninja.

    # - required binaryview method overrides
    # these methods are part of the BinaryView plugin interface and must be implemented.

    def perform_is_executable(self) -> bool:
        """indicates that nds roms contain executable code."""
        return True

    def perform_get_entry_point(self) -> int:
        """
        returns the primary entry point address of the nds rom.
        conventionally, this loader prioritizes the arm9 entry point if it was
        successfully defined and validated. if not, it falls back to the arm7
        entry point if that was valid. if neither are available through the
        loader's specific tracking, it consults binary ninja's own list of
        entry points (populated by `add_entry_point` calls). as a final
        resort, it returns the start of the view or 0.
        """
        if self._primary_arm9_entry_point is not None:
            self.logger.log_debug(
                f"perform_get_entry_point: returning stored primary ARM9 entry point 0x{self._primary_arm9_entry_point:08x}."
            )
            return self._primary_arm9_entry_point
        elif self._primary_arm7_entry_point is not None:
            self.logger.log_debug(
                f"perform_get_entry_point: primary ARM9 entry point not set or invalid, returning stored primary ARM7 entry point 0x{self._primary_arm7_entry_point:08x}."
            )
            return self._primary_arm7_entry_point
        elif self.entry_points and len(self.entry_points) > 0:
            # this fallback uses binary ninja's list of entry points, which should reflect
            # what was added via self.add_entry_point() during _define_rom_entry_points.
            # the order in self.entry_points depends on the order add_entry_point was called.
            self.logger.log_warn(
                f"perform_get_entry_point: loader's primary arm9/arm7 entry point attributes not set. "
                f"falling back to the first entry point in binary ninja's list (total {len(self.entry_points)} entries): 0x{self.entry_points[0]:08x}"
            )
            return self.entry_points[0]

        # last resort if no entry points were defined or tracked successfully.
        default_entry = self.start if self.start is not None else 0
        self.logger.log_error(
            "perform_get_entry_point: no valid entry points found from loader logic or binary ninja's list. "
            f"returning start of view (0x{default_entry:08x}) or 0. analysis may be incorrect or start at an unexpected location."
        )
        return default_entry

    def perform_get_address_size(self) -> int:
        """returns the address size for the nds platform, which is 4 bytes (32-bit addresses)."""
        return 4


# register the NDSView class with binary ninja so it can be used to open nds rom files.
NDSView.register()
