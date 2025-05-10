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
from binaryninja.log import Logger

# imports for nds rom parsing capabilities.
# this loader relies on an external 'nds_cartridge' reader module
# to handle the low-level details of the nds rom format.
from ..readers.nds_cartridge import (
    NDSRomReader,  # main class for reading and validating nds roms.
    NDSRom,  # dataclass representing the entire parsed rom structure.
    NDSOverlayTable,  # represents arm9/arm7 overlay tables.
    NDSOverlayEntry,  # represents a single entry in an overlay table.
    # NDSCartridgeHeader and NDSFatEntry are implicitly used via NDSRom and not directly referenced here.
)

# import nds io definitions
from ..defs.nds import NDS_IO_REGISTERS

# - nds hardware definitions

# this dictionary maps descriptive names of nds hardware categories (tag type names)
# to emoji icons for better visual distinction in the binary ninja ui.
# these names should be in proper case as they are used for creating tag types.
NDS_TAG_TYPE_DEFINITIONS: Dict[str, str] = {
    "Display": "🖼️",  # for 2d engines, 3d engine display aspects
    "DMA": "➡️",  # for direct memory access controllers
    "Timers": "⏱️",  # for hardware timers
    "Keypad": "🎮",  # for keypad and extended key input
    "IPC": "↔️",  # for inter-processor communication fifos
    "Gamecard": "💾",  # for gamecard (slot-1) interface and spi
    "Interrupts": "⚡",  # for interrupt controllers (ie, if, ime)
    "Power": "🔋",  # for power management and halt control
    "Memory Control": "🐏",  # for ram, vram, tcm control registers, exmemcnt
    "Math": "➗",  # for hardware math units (divider, square root)
    "3D Engine": "🧊",  # for 3d graphics processing unit registers
    "Sound": "🔊",  # for sound controller registers and channels
    "SPI": "〰️",  # for serial peripheral interface (touchscreen, firmware, rtc)
    "RTC": "🕒",  # for real-time clock (accessed via spi)
    "Wifi": "📡",  # for wireless communication registers and ram
    "System": "⚙️",  # for general system control, bios protection, postflg
    "ARM9 Specific": "9️⃣",  # for registers or features only accessible/relevant to the arm9 processor
    "ARM7 Specific": "7️⃣",  # for registers or features only accessible/relevant to the arm7 processor
    "Hardcoded Addr": "📍",  # for special hardcoded ram addresses (e.g., irq handlers, memory control)
    "Memory Region": "🗺️",  # for mapped memory segments (ram, rom, i/o)
    "Hardware Register": "🔩",  # a generic fallback for i/o registers not fitting other categories
}

# - nitro sdk constants
# these constants relate to the _start_ModuleParams structure found in binaries compiled
# with the official nintendo nitro sdk. this structure provides metadata about the binary,
# including information about compression and memory layout.

# magic bytes used to identify the _start_ModuleParams structure.
NITRO_SDK_MODULE_PARAMS_MAGIC = (
    b"\x21\x06\xc0\xde\xde\xc0\x06\x21"  # ASCII: "!\\x06\\xc0\\xde\\xde\\xc0\\x06!"
)
# size of the _start_ModuleParams structure in bytes.
NITRO_SDK_MODULE_PARAMS_SIZE = 36
# offset of the magic bytes within the _start_ModuleParams structure itself.
NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET = 0x1C


# - ndsview class definition
class NDSView(BinaryView):
    """
    BinaryView class for loading and analyzing Nintendo DS (NDS) ROM files.
    It handles the NDS's dual-cpu architecture (ARM9 and ARM7), memory map,
    overlays (dynamically loaded code segments), and hardware registers.
    The loader relies on an external `nds_cartridge` reader module for
    low-level parsing of the ROM format.
    """

    name = "NDS"  # short name for the view type, used by binary ninja internally.
    long_name = "Nintendo DS ROM"  # descriptive name shown in the ui.

    # - segment permission flags
    # common combinations for defining memory segment permissions.
    # these are bitwise OR combinations of SegmentReadable (R), SegmentWritable (W), SegmentExecutable (X).
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
        # create a logger instance specific to this plugin for organized and identifiable logging.
        self.logger: Logger = self.create_logger(f"{self.name}")
        # store a reference to the raw data view for direct access to the rom bytes.
        self.raw_data: BinaryView = data
        # cache for created tagtypes to avoid redundant api calls and improve performance during setup.
        # keys are lowercase tag type names, values are the TagType objects.
        self._created_tag_types: Dict[str, TagType] = {}
        # store parsed rom data (header, binaries, overlays, etc.) from the NDSRomReader.
        # this will be populated by _parse_rom_file_structure().
        self.nds_rom_data: Optional[NDSRom] = None
        # store the primary entry point address (typically ARM9's) once determined.
        # this is used by perform_get_entry_point().
        self._primary_entry_point_address: Optional[int] = None

        # set architecture and platform. the nds features an arm946e-s (armv5te isa)
        # and an arm7tdmi (armv4t isa). for binary ninja, "armv7" is often used as a
        # versatile base architecture that supports the necessary instruction sets (arm and thumb)
        # for analyzing both processors' code.
        try:
            # type ignore justification: architecture names are string literals used as keys.
            self.arch: Optional[Architecture] = Architecture["armv7"]  # type: ignore
            if not self.arch:
                self.logger.log_error(
                    "critical: 'armv7' architecture definition not found in binary ninja. NDS analysis requires it."
                )
                # this is a fatal error for the loader; it cannot proceed without a base architecture.
                raise RuntimeError("'armv7' architecture definition not found.")

            # get the standalone platform associated with the chosen architecture.
            # this provides a basic execution environment context for analysis.
            self.platform: Optional[Platform] = self.arch.standalone_platform
            if not self.platform:
                self.logger.log_error(
                    f"critical: could not get standalone platform for architecture '{self.arch.name}'. NDS analysis cannot proceed."
                )
                # also a fatal error.
                raise RuntimeError(
                    f"failed to get standalone platform for {self.arch.name}."
                )
            self.logger.log_info(
                f"using platform: {self.platform.name}, architecture: {self.arch.name} for NDS analysis."
            )
        except KeyError:
            # this handles the specific case where "armv7" is not a recognized architecture key
            # in the current binary ninja environment.
            available_archs = [arch.name for arch in Architecture.list]  # type: ignore
            self.logger.log_error(
                f"critical: 'armv7' architecture key not found. available architectures: {available_archs}. NDS analysis requires 'armv7' or a compatible alternative."
            )
            raise RuntimeError(
                f"required 'armv7' architecture not found. available: {available_archs}"
            )
        except Exception as e:
            # catch any other unexpected errors during this critical setup phase.
            self.logger.log_error(
                f"critical error during NDSView architecture/platform setup: {e}\n{traceback.format_exc()}"
            )
            raise  # re-raise to ensure initialization fails clearly and binary ninja handles it.

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        checks if the provided data is likely an nds rom.
        this uses a basic heuristic: the presence of the nintendo logo magic bytes
        (0x24, 0xff, 0xae, 0x51) at offset 0xc0 in the header.
        full validation (e.g., crc checks by NDSRomReader) is deferred to the
        `init` method for performance reasons, as `is_valid_for_data` might be
        called frequently by binary ninja for many file types.

        args:
            data: the BinaryView object containing the data to validate.

        returns:
            true if the data appears to be an nds rom based on the magic bytes, false otherwise.
        """
        try:
            # minimum header size needed to check the nintendo logo magic.
            # the logo itself starts at 0xc0; we need to read 4 bytes from there.
            min_check_size = 0xC0 + 4
            if data.length < min_check_size:
                # log at debug level as this is a common scenario for non-nds files.
                log_debug(
                    f"[{cls.name}] validation: data length {data.length} is less than min check size {min_check_size}. not an nds rom."
                )
                return False

            # check the first few bytes of the nintendo logo at offset 0xc0.
            # the expected magic is 0x51AEFF24 (stored little-endian as b"\\x24\\xff\\xae\\x51").
            logo_magic_bytes = data.read(0xC0, 4)
            expected_magic = b"\x24\xff\xae\x51"
            if logo_magic_bytes == expected_magic:
                # the magic bytes match; this is a strong indicator of an nds rom.
                log_info(
                    f"[{cls.name}] validation: found nintendo logo magic bytes at 0xC0. identified as potential nds rom."
                )
                return True
            else:
                # the bytes at the magic offset do not match.
                actual_magic_hex = (
                    logo_magic_bytes.hex() if logo_magic_bytes else "N/A"
                )  # provide hex for easier debugging
                log_debug(
                    f"[{cls.name}] validation: nintendo logo magic mismatch at 0xC0 (expected {expected_magic.hex()}, got 0x{actual_magic_hex}). not an nds rom."
                )
                return False
        except Exception as e:
            # log an error if reading the bytes fails for any unexpected reason.
            log_error(
                f"[{cls.name}] validation: error during basic nds rom validation check: {e}\n{traceback.format_exc()}"
            )
            return False

    # - helper methods for initialization

    def _parse_rom_file_structure(self) -> bool:
        """
        parses the nds rom structure using the external `NDSRomReader` module.
        this involves reading the entire rom into memory (a necessary step for
        the current `NDSRomReader` implementation), performing full validation
        (e.g., header crc checks), and populating `self.nds_rom_data` with the
        parsed structures (header, arm9/arm7 binaries, fat, overlay tables).

        returns:
            true if the rom structure was successfully parsed and validated, false otherwise.
        """
        self.logger.log_info(
            "reading entire rom into memory for full parsing and validation by NDSRomReader..."
        )
        rom_length = self.raw_data.length
        if rom_length == 0:
            self.logger.log_error("rom file is empty. cannot parse NDS structure.")
            return False

        # read the entire rom data. this can be memory-intensive for large roms.
        # future improvements to NDSRomReader might allow stream-based parsing.
        rom_data_bytes: Optional[bytes] = self.raw_data.read(0, rom_length)
        if not rom_data_bytes or len(rom_data_bytes) != rom_length:
            read_len = len(rom_data_bytes) if rom_data_bytes else 0
            self.logger.log_error(
                f"failed to read full rom data ({read_len} read vs {rom_length} expected) from parent view. NDS parsing aborted."
            )
            return False

        self.logger.log_info(
            "performing full header and rom structure validation via NDSRomReader.is_valid()..."
        )
        # NDSRomReader.is_valid might perform crc checks or other deep validation.
        # it might be more efficient to pass a slice for header validation if the reader supports it.
        # for now, assuming it might need more context or the full data.
        validation_check_size = min(
            0x1000, rom_length
        )  # e.g., first 4kb for header checks
        if not NDSRomReader.is_valid(rom_data_bytes[:validation_check_size]):
            self.logger.log_error(
                "full rom validation failed via NDSRomReader.is_valid(). The ROM may be corrupted or not a standard NDS file."
            )
            # depending on strictness, one might return false here.
            # for robustness, we'll proceed to attempt parsing but log this validation failure.
            # return False # uncomment for strict validation enforcement.
        else:
            self.logger.log_info("NDSRomReader initial validation successful.")

        self.logger.log_info(
            "parsing full NDS ROM structure using NDSRomReader.read()..."
        )
        try:
            # this is where the main parsing happens via the external reader.
            self.nds_rom_data = NDSRomReader.read(rom_data_bytes)
        except Exception as e:
            self.logger.log_error(
                f"NDSRomReader.read() encountered an unhandled exception: {e}"
            )
            self.logger.log_error(traceback.format_exc())
            self.nds_rom_data = None  # ensure it's none on failure
        finally:
            # attempt to free the large rom_data_bytes buffer.
            # this relies on the assumption that NDSRomReader copies necessary data
            # or that the parsed structures no longer directly reference this buffer.
            del rom_data_bytes
            self.logger.log_debug(
                "released in-memory copy of full rom data after NDSRomReader.read() attempt."
            )

        if not self.nds_rom_data or not self.nds_rom_data.header:
            self.logger.log_error(
                "failed to parse NDS ROM structure: NDSRomReader.read() returned None, or the parsed header is missing."
            )
            return False

        self.logger.log_info(
            "successfully parsed NDS ROM file structure using NDSRomReader."
        )
        return True

    def _initialize_tag_types(self) -> None:
        """
        defines and caches all necessary tag types specific to NDS hardware and memory regions.
        it iterates through the global `NDS_TAG_TYPE_DEFINITIONS` dictionary.
        this ensures that tags can be applied with appropriate icons and names in the ui.
        """
        self.logger.log_info("initializing NDS hardware and memory tag types...")
        initialized_count = 0
        for name, icon in NDS_TAG_TYPE_DEFINITIONS.items():
            if self._get_or_create_tag_type(name, icon):
                initialized_count += 1
            else:
                # warning if a specific tag type couldn't be set up.
                self.logger.log_warn(
                    f"could not initialize NDS tag type: '{name}' with icon '{icon}'."
                )
        self.logger.log_info(
            f"{initialized_count}/{len(NDS_TAG_TYPE_DEFINITIONS)} NDS tag types are now ready."
        )

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        """
        retrieves an existing tag type by its name or creates a new one if it doesn't exist.
        results are cached in `self._created_tag_types` to avoid redundant api calls
        and improve performance during the loading process.
        tag type names are handled case-insensitively for lookup by binary ninja,
        but are created with the provided casing.

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

        # attempt to get the tag type using binary ninja's built-in lookup (case-insensitive by name).
        existing_tag_type = self.get_tag_type(name)
        if existing_tag_type:
            self.logger.log_debug(
                f"found existing tag type in BinaryView: '{name}'. caching it."
            )
            self._created_tag_types[name_lower] = existing_tag_type
            return existing_tag_type

        # if the tag type does not exist in the view, create it.
        try:
            # use the original (proper) casing for the name when creating the new tag type.
            self.logger.log_info(f"creating new tag type: '{name}' with icon '{icon}'.")
            new_tag_type = self.create_tag_type(name, icon)
            self._created_tag_types[name_lower] = (
                new_tag_type  # cache the newly created type
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
        name: str,  # the symbol name for the register
        tag_category_name: str,  # e.g., "Display", "Sound", must be a key in NDS_TAG_TYPE_DEFINITIONS
        description: str = "",  # comment for the register
    ):
        """
        helper method to define a symbol for a hardware register at a given address
        and apply a descriptive tag to it for better organization in the ui.

        args:
            address: the memory address of the hardware register.
            name: the name for the register symbol (e.g., "REG_DISPSTAT").
            tag_category_name: the category name of the tag type (e.g., "Display").
                               this must match a key in NDS_TAG_TYPE_DEFINITIONS.
            description: an optional comment to add for the register at its address.
        """
        try:
            # define the symbol for the register at its address.
            # DataSymbol is appropriate for memory-mapped registers.
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))

            # add the provided description as a comment at the register's address if not empty.
            if description:
                self.set_comment_at(address, description)

            # retrieve the icon associated with the tag category from our definitions.
            # default to a generic hardware icon if the category is not found (should not happen with valid definitions).
            tag_icon = NDS_TAG_TYPE_DEFINITIONS.get(
                tag_category_name, "🔩"
            )  # "🔩" is a generic gear/nut icon
            tag_type = self._get_or_create_tag_type(tag_category_name, tag_icon)

            # if the tag type was successfully obtained or created, add the tag to the register's address.
            if tag_type:
                # using the register name as tag data can be helpful for UI identification.
                # self.add_tag expects the tag type's name (a string) as its second argument.
                self.add_tag(address, tag_type.name, data=name)
            else:
                # this indicates an issue with tag type creation/retrieval.
                self.logger.log_warn(
                    f"could not obtain or create tag type '{tag_category_name}' for register '{name}' at 0x{address:08x}."
                )
        except Exception as e:
            # log any errors encountered during register definition, but continue loading other registers.
            self.logger.log_error(
                f"error processing hardware register '{name}' at 0x{address:08x}: {e}\n{traceback.format_exc()}"
            )

    def _map_memory_regions(self) -> None:
        """
        maps the core NDS memory regions (RAM, VRAM, I/O, BIOS, TCMs).
        RAM regions that can contain code (e.g., Main RAM, WRAM, TCMs, Overlays)
        are given minimal file backing. This is a workaround to help Binary Ninja
        persist functions defined in these RAM regions when saving a BNDB, as
        non-file-backed RAM segments might otherwise lose such user-defined data.
        The actual byte content for these minimal backings is insignificant as the
        regions are RAM and will be populated by the NDS software at runtime.
        """
        self.logger.log_info("mapping NDS memory regions...")

        # internal helper function to simplify adding memory regions as segments.
        def add_memory_segment(
            address: int,  # starting virtual address of the segment
            size: int,  # size of the segment in bytes
            permissions: SegmentFlag,  # R/W/X permissions (e.g., self.PERM_RX)
            name: str,  # descriptive name for the segment (e.g., "Main RAM")
            tag_name: str = "Memory Region",  # category for the tag, defaults to "Memory Region"
            is_ram_for_code: bool = False,  # if true, provide minimal file backing for bndb persistence
        ):
            self.logger.log_debug(
                f"  preparing to map '{name}': addr=0x{address:08x}, size=0x{size:06x} ({size // 1024}KB), perms={permissions}, ram_for_code={is_ram_for_code}"
            )
            file_offset_backing, file_length_backing = 0, 0
            if is_ram_for_code:
                # for ram regions intended to hold code (like overlays or main ram where code is loaded),
                # providing a minimal, valid file backing helps binary ninja save functions defined there.
                # the actual byte read from the file for this backing is not important, as it's ram.
                if self.raw_data.length > 0:
                    file_offset_backing = (
                        0  # use a valid small offset from the start of the raw file.
                    )
                    file_length_backing = (
                        1  # must be non-zero to indicate "file-backed" to bn.
                    )
                    # sanity check the backing range against the raw file length.
                    if file_offset_backing + file_length_backing > self.raw_data.length:
                        self.logger.log_warn(
                            f"  cannot provide file backing for RAM region '{name}' (offset {file_offset_backing}, len {file_length_backing}) as it exceeds raw file length {self.raw_data.length}. Mapping as non-backed RAM."
                        )
                        file_length_backing = (
                            0  # fallback to non-backed if raw file is too small.
                        )
                else:  # raw file itself is empty.
                    self.logger.log_warn(
                        f"  raw file length is 0, cannot provide file backing for RAM region '{name}'. Mapping as non-backed RAM."
                    )
                    file_length_backing = 0

            try:
                # add the segment to the binary view.
                self.add_auto_segment(
                    address, size, file_offset_backing, file_length_backing, permissions
                )
                # get the appropriate tag type for this memory region.
                tag_icon = NDS_TAG_TYPE_DEFINITIONS.get(
                    tag_name, "🗺️"
                )  # default map icon
                tag_type = self._get_or_create_tag_type(tag_name, tag_icon)
                if tag_type:
                    # add a tag at the start of the region for easy identification in the ui.
                    self.add_tag(
                        address, tag_type.name, data=f"{name} Start"
                    )  # use the tag type's string name.
                # add a comment at the start of the region indicating its name and size.
                self.set_comment_at(address, f"{name} ({size // 1024}KB)")
                self.logger.log_info(f"  successfully mapped '{name}'.")
            except Exception as e:
                self.logger.log_error(
                    f"failed to map memory region '{name}' at 0x{address:08x}: {e}\n{traceback.format_exc()}"
                )

        # - main memory regions (consult NDS technical documents like GBATEK for precise layout and usage)
        # main ram: 4mb, general purpose, can contain code for arm9 (including overlays).
        add_memory_segment(
            0x02000000,
            0x00400000,
            self.PERM_RWX,
            "Main RAM (4MB)",
            is_ram_for_code=True,
        )
        # shared wram: 32kb block, accessible by both arm9 and arm7, can contain code.
        add_memory_segment(
            0x03000000,
            0x00008000,
            self.PERM_RWX,
            "Shared WRAM (32KB Block)",
            is_ram_for_code=True,
        )
        # arm7 wram: 64kb, exclusive to arm7, can contain arm7 code.
        add_memory_segment(
            0x03800000,
            0x00010000,
            self.PERM_RWX,
            "ARM7 WRAM (64KB)",
            is_ram_for_code=True,
        )

        # - i/o ports (memory-mapped hardware registers)
        add_memory_segment(
            0x04000000,
            0x00001000,
            self.PERM_RW,
            "I/O Registers (Main Block, 0x4000xxx)",
            tag_name="Hardware Register",
        )
        add_memory_segment(
            0x04100000,
            0x00000020,
            self.PERM_RW,
            "I/O Registers (IPC/Card Data, 0x4100xxx)",
            tag_name="Hardware Register",
        )
        # wifi block includes i/o registers and 8kb of dedicated ram.
        add_memory_segment(
            0x04800000,
            0x00008000,
            self.PERM_RW,
            "Wireless Comm (I/O & 8KB RAM at 0x4804000)",
            tag_name="Wifi",
        )

        # - graphics memory (palette, vram, oam) - typically not for direct program code execution.
        add_memory_segment(
            0x05000000, 0x00000800, self.PERM_RW, "Standard Palette RAM (2KB)"
        )
        add_memory_segment(
            0x06000000, 0x000A4000, self.PERM_RW, "VRAM (Main Banks A-I, 656KB Total)"
        )
        add_memory_segment(
            0x06800000, 0x000A4000, self.PERM_RW, "VRAM (LCDC Mapped Alias)"
        )  # an alias for accessing vram
        add_memory_segment(
            0x07000000, 0x00000800, self.PERM_RW, "OAM - OBJ Attribute Memory (2KB)"
        )

        # - bios roms (map as readable/executable, as they contain system code)
        # arm9 bios: 4kb, mapped at 0xffff0000 from arm9's perspective.
        add_memory_segment(
            0xFFFF0000,
            0x00001000,
            self.PERM_RX,
            "ARM9 BIOS (4KB)",
            is_ram_for_code=True,
        )  # minimal backing if functions defined
        # arm7 bios: 16kb, mapped at 0x00000000 from arm7's perspective (physical 0).
        add_memory_segment(
            0x00000000,
            0x00004000,
            self.PERM_RX,
            "ARM7 BIOS (16KB at Physical 0x0)",
            is_ram_for_code=True,
        )

        # - tightly coupled memories (tcms) for arm9 (fast on-chip ram)
        # arm9 itcm (instruction tcm): 32kb, often mirrored from 0x00000000 to 0x01000000. we map the common mirror.
        self.logger.log_info(
            "ARM9 ITCM is documented at physical 0x00000000 (32KB), often mirrored to 0x01000000. Mapping the 0x01xxxxxx mirror."
        )
        add_memory_segment(
            0x01000000,
            0x00008000,
            self.PERM_RWX,
            "ARM9 ITCM (32KB Code, Mapped at 0x01xxxxxx)",
            is_ram_for_code=True,
        )
        # arm9 dtcm (data tcm): 16kb, base address is configurable by software. 0x027c0000 is a common default.
        dtcm_base = 0x027C0000  # a common default base address for dtcm.
        self.logger.log_info(
            f"mapping ARM9 DTCM at common default base 0x{dtcm_base:08x} (16KB). Actual base is configurable by software via memory control registers."
        )
        add_memory_segment(
            dtcm_base,
            0x00004000,
            self.PERM_RWX,
            "ARM9 DTCM (16KB Data, Common Default Base)",
            is_ram_for_code=True,
        )

        self.logger.log_info("finished mapping NDS memory regions.")

    def _find_module_params(self, data: bytes) -> Optional[int]:
        """
        searches for the Nitro SDK `_start_ModuleParams` magic bytes within the provided data.
        this structure, if present, contains metadata about the binary's layout,
        including information about compression and sizes, which can be more reliable
        than the main NDS header for SDK-compiled binaries.

        args:
            data: bytes object (typically an ARM9 binary's raw data) to search within.

        returns:
            the starting offset of the `_start_ModuleParams` structure within `data` if
            found and appears validly positioned, otherwise none.
        """
        try:
            magic_index = data.find(NITRO_SDK_MODULE_PARAMS_MAGIC)
            if magic_index != -1:
                # the magic bytes are at a fixed offset within the struct.
                # calculate the potential start of the struct based on this.
                struct_start_offset = magic_index - NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET
                # basic sanity check: does the calculated start offset and struct size fit within the data?
                if 0 <= struct_start_offset and (
                    struct_start_offset + NITRO_SDK_MODULE_PARAMS_SIZE <= len(data)
                ):
                    self.logger.log_info(
                        f"found _start_ModuleParams structure at offset 0x{struct_start_offset:x} within provided binary data."
                    )
                    return struct_start_offset
                else:
                    self.logger.log_warn(
                        f"found _start_ModuleParams magic at 0x{magic_index:x}, but calculated struct start offset 0x{struct_start_offset:x} is invalid for data length {len(data)}. Ignoring."
                    )
            else:
                # it's common for homebrew or non-sdk compiled binaries not to have this structure.
                self.logger.log_info(
                    "_start_ModuleParams magic not found. Assuming binary is not standard SDK build or uses a different layout mechanism."
                )
        except Exception as e:
            # catch any unexpected errors during the search.
            self.logger.log_error(
                f"error occurred while searching for _start_ModuleParams: {e}\n{traceback.format_exc()}"
            )
        return None

    def _load_arm9_binary(self) -> None:
        """
        loads the main arm9 binary. this involves:
        1. reading the raw arm9 binary data from the rom based on header offsets.
        2. searching for and parsing the `_start_ModuleParams` structure (if present)
           to determine compression status and accurate code/data sizes.
        3. if compressed (typically mii lz77 variant), decompressing the data.
        4. mapping the processed arm9 code/data into a memory segment with rx permissions.
        5. mapping the arm9 bss (uninitialized data) segment with rw permissions.
        6. creating corresponding sections for analysis.
        """
        if not self.nds_rom_data or not self.nds_rom_data.header:
            self.logger.log_error(
                "cannot load ARM9 binary, NDS ROM data/header not parsed or available."
            )
            return

        header = self.nds_rom_data.header
        if header.arm9_size == 0:
            self.logger.log_info("ARM9 size in header is 0, skipping ARM9 loading.")
            return

        self.logger.log_info(
            f"loading ARM9 binary: ROM offset=0x{header.arm9_rom_offset:x}, ROM size=0x{header.arm9_size:x}, Target RAM addr=0x{header.arm9_ram_address:x}"
        )
        arm9_data_raw: Optional[bytes] = self.raw_data.read(
            header.arm9_rom_offset, header.arm9_size
        )
        if not arm9_data_raw or len(arm9_data_raw) != header.arm9_size:
            read_len = len(arm9_data_raw) if arm9_data_raw else 0
            self.logger.log_error(
                f"failed to read full ARM9 binary data from ROM (read {read_len} bytes, expected {header.arm9_size} bytes). ARM9 loading aborted."
            )
            return

        load_address = header.arm9_ram_address
        # effective_code_data_size is the size of the .text/.data segment in memory after any transformation (e.g. decompression).
        effective_code_data_size = 0
        bss_size = header.arm9_bss_size  # from the main nds header.

        # determine compression and actual code/data size, preferring _start_ModuleParams if available and valid.
        is_compressed_via_moduleparams = False
        module_params_struct_found = False
        # sdk_derived_code_data_size is the expected size of code+data after decompression, according to _start_ModuleParams.
        sdk_derived_code_data_size = 0

        module_params_offset_in_raw_arm9 = self._find_module_params(arm9_data_raw)

        if module_params_offset_in_raw_arm9 is not None:
            module_params_struct_found = True
            try:
                # _start_moduleparams structure fields relevant for size and compression:
                #   u32 autoLoadStartOffset; (offset 0) -> not directly used here, arm9_ram_address is the base
                #   u32 autoLoadEndOffset;   (offset 4) -> size of code+data when loaded/decompressed
                #   u32 bssStartOffset;      (offset 8) -> offset to bss start (relative to arm9_ram_address)
                #   u32 bssEndOffset;        (offset 12) -> offset to bss end (relative to arm9_ram_address)
                #   ...
                #   u32 compressedEndOffset; (offset 20 / 0x14) -> non-zero if compressed
                # all offsets are relative to the arm9_ram_address.
                auto_load_end_offset_from_struct = struct.unpack_from(
                    "<I", arm9_data_raw, module_params_offset_in_raw_arm9 + 4
                )[0]
                compressed_static_end_marker = struct.unpack_from(
                    "<I", arm9_data_raw, module_params_offset_in_raw_arm9 + 0x14
                )[0]

                is_compressed_via_moduleparams = compressed_static_end_marker != 0
                # sdk_derived_code_data_size is the size from load_address to the end of the loaded/decompressed code/data section.
                sdk_derived_code_data_size = (
                    auto_load_end_offset_from_struct  # this value is the size itself.
                )

                self.logger.log_info(
                    f"  _start_ModuleParams parsed: compressed_marker=0x{compressed_static_end_marker:x} (is_compressed={is_compressed_via_moduleparams}), "
                    f"auto_load_end_offset (derived_code_data_size)=0x{sdk_derived_code_data_size:x}"
                )

                # sanity check the derived size: must be non-negative and not excessively large.
                # allow up to 20x compression ratio as a heuristic.
                if not (0 <= sdk_derived_code_data_size <= header.arm9_size * 20):
                    self.logger.log_error(
                        f"  _start_ModuleParams: derived_code_data_size (0x{sdk_derived_code_data_size:x}) seems invalid. "
                        f"Will revert to using header.arm9_size and assume uncompressed."
                    )
                    sdk_derived_code_data_size = header.arm9_size  # fallback
                    is_compressed_via_moduleparams = (
                        False  # be cautious, assume uncompressed
                    )
            except struct.error as se:  # error unpacking struct fields
                self.logger.log_error(
                    f"error unpacking _start_ModuleParams fields: {se}. Assuming uncompressed based on header.arm9_size."
                )
                module_params_struct_found = (
                    False  # treat as if not found due to parsing error
                )
                sdk_derived_code_data_size = header.arm9_size
                is_compressed_via_moduleparams = False
            except Exception as e:  # catch any other unexpected errors
                self.logger.log_error(
                    f"unexpected error processing _start_ModuleParams: {e}. Assuming uncompressed based on header.arm9_size."
                )
                module_params_struct_found = False
                sdk_derived_code_data_size = header.arm9_size
                is_compressed_via_moduleparams = False
        else:  # _start_ModuleParams magic not found
            sdk_derived_code_data_size = (
                header.arm9_size
            )  # default to raw size from header for code/data
            is_compressed_via_moduleparams = (
                False  # assume uncompressed if no moduleparams
            )
            self.logger.log_info(
                "  _start_ModuleParams not found. Assuming ARM9 is uncompressed or using header.arm9_size for .text/.data."
            )

        arm9_successfully_decompressed_and_written = False

        if is_compressed_via_moduleparams:
            self.logger.log_info(
                f"  attempting ARM9 Mii LZ77 decompression (expected decompressed size from moduleparams: 0x{sdk_derived_code_data_size:x})..."
            )
            try:
                decompressed_data = self._mii_uncompress_backward(arm9_data_raw)
                if decompressed_data:
                    actual_decompressed_size = len(decompressed_data)
                    # if moduleparams was found and gave a specific target size, compare against it.
                    if (
                        module_params_struct_found
                        and actual_decompressed_size != sdk_derived_code_data_size
                        and sdk_derived_code_data_size != 0
                    ):
                        self.logger.log_warn(
                            f"  actual decompressed ARM9 size (0x{actual_decompressed_size:x}) differs from _start_ModuleParams expected size (0x{sdk_derived_code_data_size:x}). "
                            "Using actual decompressed size for memory segment."
                        )
                    effective_code_data_size = actual_decompressed_size  # use the size of what was actually decompressed.

                    self.logger.log_info(
                        f"  adding segment for decompressed ARM9: mem_addr=0x{load_address:08x}, mem_size=0x{effective_code_data_size:x}, "
                        f"file_offset=0x{header.arm9_rom_offset:x} (original compressed file_size=0x{header.arm9_size:x})"
                    )
                    # the segment maps the original compressed data from the file, but its size in memory is the decompressed size.
                    self.add_auto_segment(
                        load_address,
                        effective_code_data_size,  # memory address and size (decompressed)
                        header.arm9_rom_offset,
                        header.arm9_size,  # file data is the original compressed block
                        self.PERM_RX,  # code is readable and executable
                    )

                    self.logger.log_info(
                        f"  writing {effective_code_data_size} bytes of decompressed ARM9 data to memory at 0x{load_address:08x}..."
                    )
                    bytes_written = self.write(load_address, decompressed_data)
                    if bytes_written != effective_code_data_size:
                        self.logger.log_error(
                            f"ARM9 write error (decompressed data): expected to write {effective_code_data_size} bytes, but wrote {bytes_written}. Segment may be corrupted."
                        )
                        # do not mark as successfully decompressed if write failed.
                    else:
                        arm9_successfully_decompressed_and_written = True
                        self.logger.log_info(
                            f"  ARM9 decompression & write successful: {header.arm9_size} compressed bytes -> {effective_code_data_size} decompressed bytes."
                        )
                else:  # mii_uncompress_backward returned empty data
                    self.logger.log_warn(
                        "ARM9 Mii decompression resulted in empty data. Effective code/data size will be 0. Falling back to raw mapping if applicable later."
                    )
                    effective_code_data_size = (
                        0  # ensure this is zero if decompression yields nothing
                    )
            except Exception as e:
                self.logger.log_error(
                    f"ARM9 Mii decompression raised an exception: {e}. Effective code/data size will be 0. Falling back to raw mapping.\n{traceback.format_exc()}"
                )
                effective_code_data_size = 0  # ensure this on error too

        # handle cases where arm9 was not compressed, or decompression failed/yielded empty data.
        if not arm9_successfully_decompressed_and_written:
            if (
                is_compressed_via_moduleparams
            ):  # implies decompression was attempted but failed or was empty
                self.logger.log_warn(
                    "  falling back to mapping raw (uncompressed) ARM9 data due to prior decompression issue."
                )
            else:  # was not considered compressed in the first place
                self.logger.log_info(
                    "  ARM9 mapping as raw/uncompressed data (no compression indicated or moduleparams absent)."
                )

            # determine the size of the code/data segment in memory.
            # default to the size specified in the main NDS header (header.arm9_size).
            effective_code_data_size = header.arm9_size
            # determine how much data to map from the file.
            file_map_length = header.arm9_size

            # if _start_ModuleParams was found and indicated uncompressed, and its derived size is valid and different,
            # it might be more accurate for the memory layout than the main header's arm9_size.
            if (
                module_params_struct_found
                and not is_compressed_via_moduleparams
                and sdk_derived_code_data_size > 0
            ):
                if sdk_derived_code_data_size != header.arm9_size:
                    self.logger.log_warn(
                        f"  _start_ModuleParams size (0x{sdk_derived_code_data_size:x}) for uncompressed ARM9 differs from main header's arm9_size (0x{header.arm9_size:x}). "
                        "Using _start_ModuleParams size for the memory segment size."
                    )
                effective_code_data_size = (
                    sdk_derived_code_data_size  # this is the intended size in memory.
                )
                # when mapping from file, map the smaller of the two to avoid reading past end of actual binary in file if moduleparams overestimates.
                file_map_length = min(sdk_derived_code_data_size, header.arm9_size)

            if effective_code_data_size > 0:
                self.logger.log_info(
                    f"  adding segment for raw ARM9: mem_addr=0x{load_address:08x}, mem_size=0x{effective_code_data_size:x}, "
                    f"file_offset=0x{header.arm9_rom_offset:x}, file_map_len=0x{file_map_length:x}"
                )
                self.add_auto_segment(
                    load_address,
                    effective_code_data_size,  # size in memory
                    header.arm9_rom_offset,
                    file_map_length,  # data from file
                    self.PERM_RX,
                )
            else:  # if effective_code_data_size ended up as 0 (e.g. header.arm9_size was 0 and no moduleparams)
                self.logger.log_error(
                    "  ARM9 effective_code_data_size is 0 for raw mapping. Cannot create code/data segment."
                )
                return  # cannot proceed without a code/data segment if bss is also 0.

        # add a section for the loaded arm9 code/data to aid analysis.
        if effective_code_data_size > 0:
            self.add_auto_section(
                name=".arm9.text_data",  # a more descriptive section name
                start=load_address,
                length=effective_code_data_size,
                semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,  # arm9 code/data is typically read-only from rom/ram
            )
            # provide a comment indicating how this segment was loaded.
            comment = "ARM9 Code/Data Segment"
            if arm9_successfully_decompressed_and_written:
                comment += " (Decompressed by Loader)"
            elif module_params_struct_found and not is_compressed_via_moduleparams:
                comment += " (SDK Raw, Uncompressed)"
            elif is_compressed_via_moduleparams:
                comment += " (Raw, Decompression Attempted but Failed/Empty)"  # implies it was expected to be compressed
            else:
                comment += " (Raw, Assumed Uncompressed)"
            self.set_comment_at(load_address, comment)
        else:  # this case should ideally be caught earlier if bss is also 0
            self.logger.log_warn(
                "ARM9 effective code/data size is zero, skipping section creation for .text_data."
            )
            if (
                bss_size == 0
            ):  # if no code/data and no bss, then arm9 is effectively empty
                self.logger.log_warn(
                    "ARM9 has no code/data and no BSS. ARM9 loading effectively skipped."
                )
                return

        # handle arm9 bss (uninitialized data segment).
        if bss_size > 0:
            bss_start_address = (
                load_address + effective_code_data_size
            )  # bss typically follows the .text/.data segment.
            self.logger.log_info(
                f"  mapping ARM9 BSS: addr=0x{bss_start_address:08x}, size=0x{bss_size:x}"
            )
            # bss is not file-backed, so file_offset and file_length are 0.
            self.add_auto_segment(
                bss_start_address, bss_size, 0, 0, self.PERM_RW
            )  # bss is readable and writable.
            self.add_auto_section(
                name=".arm9.bss",
                start=bss_start_address,
                length=bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,  # standard bss semantics
            )
            self.set_comment_at(
                bss_start_address, "ARM9 BSS Segment Start (Uninitialized Data)"
            )
        else:
            self.logger.log_info(
                "  no ARM9 BSS section defined in header (bss_size is 0)."
            )

        self.logger.log_info(
            f"ARM9 binary processing complete: Entry Address=0x{header.arm9_entry_address:08x}, Load Address=0x{load_address:08x}, "
            f"Code/Data Memory Size=0x{effective_code_data_size:x}, BSS Size=0x{bss_size:x}"
        )

    def _load_arm7_binary(self) -> None:
        """
        loads the main arm7 binary. arm7 binaries are typically not compressed in NDS ROMs.
        this method maps the arm7 code/data from the rom into a memory segment
        and also maps its bss (uninitialized data) segment. sections are created
        for both to aid analysis.
        """
        if not self.nds_rom_data or not self.nds_rom_data.header:
            self.logger.log_error(
                "cannot load ARM7 binary, NDS ROM data/header not parsed or available."
            )
            return

        header = self.nds_rom_data.header
        if header.arm7_size == 0:  # check if arm7 binary has any size.
            self.logger.log_info("ARM7 size in header is 0, skipping ARM7 loading.")
            return

        self.logger.log_info(
            f"loading ARM7 binary: ROM offset=0x{header.arm7_rom_offset:x}, ROM size=0x{header.arm7_size:x}, Target RAM addr=0x{header.arm7_ram_address:x}"
        )
        load_address = header.arm7_ram_address
        # for arm7, the size in rom is typically the size in memory (uncompressed).
        code_data_size = header.arm7_size

        if code_data_size > 0:
            # map the arm7 code/data segment directly from the rom.
            self.add_auto_segment(
                load_address,
                code_data_size,  # memory address and size
                header.arm7_rom_offset,
                code_data_size,  # file offset and length match memory size
                self.PERM_RX,  # arm7 code is readable and executable
            )
            # create a section for the arm7 code/data.
            self.add_auto_section(
                name=".arm7.text_data",  # section name indicating arm7 code/data
                start=load_address,
                length=code_data_size,
                semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,  # typically read-only code
            )
            self.set_comment_at(load_address, "ARM7 Code/Data Segment Start")
        else:  # this case should ideally be caught by the header.arm7_size == 0 check earlier.
            self.logger.log_warn(
                "ARM7 code/data size is zero, skipping segment and section creation for .text_data."
            )
            if (
                header.arm7_bss_size == 0
            ):  # if bss is also zero, then arm7 is effectively empty.
                self.logger.log_warn(
                    "ARM7 has no code/data and no BSS. ARM7 loading effectively skipped."
                )
                return

        # handle arm7 bss (uninitialized data segment).
        arm7_bss_size = header.arm7_bss_size
        if arm7_bss_size > 0:
            bss_start_address = (
                load_address + code_data_size
            )  # bss follows the .text/.data segment.
            self.logger.log_info(
                f"  mapping ARM7 BSS: addr=0x{bss_start_address:08x}, size=0x{arm7_bss_size:x}"
            )
            # bss is not file-backed.
            self.add_auto_segment(
                bss_start_address, arm7_bss_size, 0, 0, self.PERM_RW
            )  # bss is readable and writable.
            self.add_auto_section(
                name=".arm7.bss",
                start=bss_start_address,
                length=arm7_bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,  # standard bss semantics
            )
            self.set_comment_at(
                bss_start_address, "ARM7 BSS Segment Start (Uninitialized Data)"
            )
        else:
            self.logger.log_info(
                "  no ARM7 BSS section defined in header (bss_size is 0)."
            )

        self.logger.log_info(
            f"ARM7 binary processing complete: Entry Address=0x{header.arm7_entry_address:08x}, Load Address=0x{load_address:08x}, "
            f"Code/Data Size=0x{code_data_size:x}, BSS Size=0x{arm7_bss_size:x}"
        )

    def _load_overlays_for_cpu(
        self, cpu_name: str, overlay_table: Optional[NDSOverlayTable]
    ) -> None:
        """
        loads overlays for a specific cpu (arm9 or arm7). overlays are dynamically
        loaded code/data segments. this method iterates through the overlay table,
        reads the overlay data from the rom (via fat), handles decompression
        (mii lz77 variant if indicated), maps the code/data and bss segments,
        and creates corresponding sections.

        args:
            cpu_name: string identifier for the cpu ("ARM9" or "ARM7") for logging and naming.
            overlay_table: the NDSOverlayTable object containing entries for this cpu's overlays.
        """
        if (
            not self.nds_rom_data
            or not self.nds_rom_data.fat_entries
            or not overlay_table
            or not overlay_table.entries
        ):
            self.logger.log_info(
                f"no {cpu_name} overlays to load (ROM data, FAT, overlay table, or entries missing/empty)."
            )
            return
        # the `is_compressed` attribute was added to NDSOverlayEntry in a later version of the nds_cartridge reader.
        # this check ensures compatibility and provides a clear error if the reader is outdated.
        if not hasattr(NDSOverlayEntry, "is_compressed"):
            self.logger.log_error(
                f"The NDSOverlayEntry class from the `nds_cartridge.py` reader module is missing the "
                f"'is_compressed' attribute. This loader cannot reliably determine if {cpu_name} overlays "
                f"are compressed. Please update your NDS ROM reader module to a newer version."
            )
            return

        self.logger.log_info(
            f"loading {cpu_name} overlays ({len(overlay_table.entries)} entries in table)..."
        )
        num_loaded_successfully = 0
        num_failed_or_skipped = 0

        for i, overlay_entry in enumerate(overlay_table.entries):
            # file_id 0xffff (or other invalid values) is a common placeholder for an unused/empty overlay table entry.
            if overlay_entry.file_id == 0xFFFF:  # standard "empty" marker
                self.logger.log_debug(
                    f"  skipping {cpu_name} overlay index {i}: placeholder entry (File ID 0xFFFF)."
                )
                continue
            if overlay_entry.file_id >= len(self.nds_rom_data.fat_entries):
                self.logger.log_warn(
                    f"  skipping invalid {cpu_name} overlay index {i}: File ID {overlay_entry.file_id} "
                    f"is out of FAT bounds (max index {len(self.nds_rom_data.fat_entries)-1}). Possible ROM corruption."
                )
                num_failed_or_skipped += 1
                continue
            # an overlay is considered effectively empty if both its RAM (code/data) and BSS sizes are zero.
            if overlay_entry.ram_size == 0 and overlay_entry.bss_size == 0:
                self.logger.log_info(
                    f"  skipping empty {cpu_name} overlay index {i} (File ID {overlay_entry.file_id}): RAM and BSS sizes are both zero in overlay table entry."
                )
                continue  # no actual content to map for this overlay.

            fat_entry = self.nds_rom_data.fat_entries[overlay_entry.file_id]
            overlay_size_in_rom = fat_entry.end_address - fat_entry.start_address
            segment_name_base = f"{cpu_name}_Overlay{i}_FileID{overlay_entry.file_id}"  # more specific name
            self.logger.log_debug(
                f"  processing {segment_name_base}: ROM offset=0x{fat_entry.start_address:x}, ROM size=0x{overlay_size_in_rom:x}, "
                f"Target RAM addr=0x{overlay_entry.ram_address:x}, Declared RAM size=0x{overlay_entry.ram_size:x}, "
                f"BSS size=0x{overlay_entry.bss_size:x}, Compressed Flag={overlay_entry.is_compressed}"
            )

            overlay_data_from_rom: Optional[bytes] = None
            # only attempt to read from rom if the fat indicates there's data for this file id.
            if overlay_size_in_rom > 0:
                overlay_data_from_rom = self.raw_data.read(
                    fat_entry.start_address, overlay_size_in_rom
                )
                if (
                    not overlay_data_from_rom
                    or len(overlay_data_from_rom) != overlay_size_in_rom
                ):
                    read_len = (
                        len(overlay_data_from_rom) if overlay_data_from_rom else 0
                    )
                    self.logger.log_error(
                        f"failed to read {segment_name_base} data from ROM (read {read_len} bytes, expected {overlay_size_in_rom} bytes). Skipping this overlay."
                    )
                    num_failed_or_skipped += 1
                    continue
            elif (
                overlay_entry.ram_size > 0
            ):  # overlay table expects ram content, but fat says no data in rom.
                self.logger.log_warn(
                    f"{segment_name_base} expects RAM content (declared RAM size 0x{overlay_entry.ram_size:x}) "
                    f"but has no corresponding data in ROM (FAT entry size is 0x{overlay_size_in_rom:x}). "
                    f"The code/data part of this overlay will be empty."
                )
                # proceed to BSS handling, effective_ram_content_size will remain 0.

            effective_ram_content_size = (
                0  # this will be the actual size of the code/data part in memory.
            )
            load_address = overlay_entry.ram_address
            overlay_successfully_processed_ram_part = (
                False  # tracks if code/data was successfully mapped/written.
            )

            if overlay_entry.is_compressed:
                if (
                    not overlay_data_from_rom
                ):  # cannot decompress if no raw data was read (e.g., rom_size was 0).
                    self.logger.log_error(
                        f"cannot decompress {segment_name_base}: no raw data available from ROM (ROM size in FAT was {overlay_size_in_rom})."
                    )
                    if (
                        overlay_entry.ram_size > 0
                    ):  # if it expected content, this is a failure for the code/data part.
                        num_failed_or_skipped += 1
                        continue
                    # if ram_size is 0, it might be a pure bss overlay incorrectly marked compressed; proceed to bss handling.
                else:  # have raw data, attempt decompression.
                    self.logger.log_info(
                        f"  decompressing {segment_name_base} (ROM size: 0x{overlay_size_in_rom:x}, declared target RAM size: 0x{overlay_entry.ram_size:x})..."
                    )
                    try:
                        decompressed_data = self._mii_uncompress_backward(
                            overlay_data_from_rom
                        )
                        if decompressed_data:
                            effective_ram_content_size = len(decompressed_data)
                            # compare actual decompressed size with the size declared in the overlay table.
                            # overlay_entry.ram_size is the authoritative expected size after decompression.
                            if (
                                effective_ram_content_size != overlay_entry.ram_size
                                and overlay_entry.ram_size != 0
                            ):
                                self.logger.log_warn(
                                    f"  {segment_name_base}: actual decompressed size (0x{effective_ram_content_size:x}) "
                                    f"differs from overlay table's declared RAM size (0x{overlay_entry.ram_size:x}). "
                                    "Using actual decompressed size for memory segment, but this might indicate an issue."
                                )
                            elif (
                                overlay_entry.ram_size == 0
                                and effective_ram_content_size > 0
                            ):
                                self.logger.log_warn(
                                    f"  {segment_name_base}: overlay table declared RAM size 0 but decompression yielded 0x{effective_ram_content_size:x} bytes. Using actual decompressed size."
                                )

                            # map the original compressed data from file, but the segment's memory size is the decompressed size.
                            self.add_auto_segment(
                                load_address,
                                effective_ram_content_size,
                                fat_entry.start_address,
                                overlay_size_in_rom,
                                self.PERM_RX,
                            )
                            # write the decompressed data into the newly created memory segment.
                            bytes_written = self.write(load_address, decompressed_data)
                            if bytes_written == effective_ram_content_size:
                                overlay_successfully_processed_ram_part = True
                                self.logger.log_info(
                                    f"  {segment_name_base} decompression & write successful: {overlay_size_in_rom} bytes -> {effective_ram_content_size} bytes."
                                )
                            else:
                                self.logger.log_error(
                                    f"  {segment_name_base} write error (decompressed): expected to write {effective_ram_content_size} bytes, but wrote {bytes_written}. Overlay may be corrupt."
                                )
                        else:  # mii_uncompress_backward returned empty data.
                            self.logger.log_warn(
                                f"  decompression of {segment_name_base} resulted in empty data. Code/data part will be effectively empty."
                            )
                            effective_ram_content_size = 0  # ensure this is zero if decompression yields nothing.
                    except Exception as e:
                        self.logger.log_error(
                            f"failed to decompress {segment_name_base}: {e}. Code/data part will be effectively empty.\n{traceback.format_exc()}"
                        )
                        effective_ram_content_size = 0  # ensure this on error too.
            elif (
                overlay_data_from_rom
            ):  # not compressed, and there is raw data from rom.
                effective_ram_content_size = (
                    overlay_size_in_rom  # use raw size from rom.
                )
                # it's good practice to compare with overlay_entry.ram_size here too.
                if (
                    effective_ram_content_size != overlay_entry.ram_size
                    and overlay_entry.ram_size != 0
                ):
                    self.logger.log_warn(
                        f"  {segment_name_base} (uncompressed): ROM file size (0x{effective_ram_content_size:x}) "
                        f"differs from overlay table's declared RAM size (0x{overlay_entry.ram_size:x}). "
                        "Using ROM file size for mapping, but this might indicate an issue."
                    )
                elif (
                    overlay_entry.ram_size == 0 and effective_ram_content_size > 0
                ):  # table says 0, but file has data
                    self.logger.log_warn(
                        f"  {segment_name_base} (uncompressed): overlay table declared RAM size 0 but ROM file has 0x{effective_ram_content_size:x} bytes. Using ROM file size."
                    )

                # map the raw data directly.
                self.add_auto_segment(
                    load_address,
                    effective_ram_content_size,
                    fat_entry.start_address,
                    effective_ram_content_size,
                    self.PERM_RX,
                )
                overlay_successfully_processed_ram_part = (
                    True  # considered processed if mapped.
                )
                self.logger.log_info(
                    f"  {segment_name_base} mapped as raw (uncompressed) data: size 0x{effective_ram_content_size:x}."
                )

            # add a section for the code/data part of the overlay if it was successfully processed and has content.
            if (
                effective_ram_content_size > 0
                and overlay_successfully_processed_ram_part
            ):
                self.add_auto_section(
                    name=f".overlay.{segment_name_base}",  # unique section name
                    start=load_address,
                    length=effective_ram_content_size,
                    semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,  # overlays are typically code/rodata
                )
                self.set_comment_at(
                    load_address,
                    f"{segment_name_base} Code/Data Start{' (Decompressed by Loader)' if overlay_entry.is_compressed else ' (Raw from ROM)'}",
                )
            elif (
                overlay_entry.ram_size > 0
                and not overlay_successfully_processed_ram_part
            ):  # expected ram content but didn't get it mapped.
                self.logger.log_warn(
                    f"  {segment_name_base} expected RAM content (declared size 0x{overlay_entry.ram_size:x}) but no valid data was mapped for sectioning. No code/data section created."
                )

            # add bss segment for the overlay if defined.
            if overlay_entry.bss_size > 0:
                # bss follows the actual code/data content in memory.
                bss_start_address = load_address + effective_ram_content_size
                self.logger.log_info(
                    f"  mapping {segment_name_base} BSS: addr=0x{bss_start_address:08x}, size=0x{overlay_entry.bss_size:x}"
                )
                self.add_auto_segment(
                    bss_start_address, overlay_entry.bss_size, 0, 0, self.PERM_RW
                )  # bss is not file-backed.
                self.add_auto_section(
                    name=f".overlay.{segment_name_base}.bss",  # unique bss section name
                    start=bss_start_address,
                    length=overlay_entry.bss_size,
                    semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                )
                self.set_comment_at(
                    bss_start_address,
                    f"{segment_name_base} BSS Start (Uninitialized Data)",
                )

            # define a symbol for the static initializer function, if specified.
            if overlay_entry.static_initializer_start_address != 0:
                init_addr_raw = overlay_entry.static_initializer_start_address
                init_func_addr = (
                    init_addr_raw & ~1
                )  # align to 2 bytes for arm/thumb instruction sets.
                # check if the initializer address falls within the loaded code/data part of this overlay.
                if (
                    effective_ram_content_size > 0
                    and overlay_successfully_processed_ram_part
                    and (
                        load_address
                        <= init_func_addr
                        < load_address + effective_ram_content_size
                    )
                ):
                    self.logger.log_info(
                        f"  defining symbol for {segment_name_base} static initializer at 0x{init_func_addr:x} (raw entry: 0x{init_addr_raw:x})."
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
                        f"{segment_name_base} Static Initializer Entry Point",
                    )
                    # self.add_function(init_func_addr) # let analysis discover it to handle arm/thumb state correctly.
                else:
                    self.logger.log_warn(
                        f"  {segment_name_base} static initializer address 0x{init_addr_raw:x} (aligned 0x{init_func_addr:x}) "
                        f"is outside its loaded/valid RAM region (0x{load_address:x} - 0x{load_address + effective_ram_content_size -1 :x}). Skipping symbol definition."
                    )
            num_loaded_successfully += 1

        # log summary of overlay loading.
        log_summary_func = (
            self.logger.log_info if num_failed_or_skipped == 0 else self.logger.log_warn
        )
        log_summary_func(
            f"finished loading {cpu_name} overlays: {num_loaded_successfully} entries processed, {num_failed_or_skipped} failed or skipped."
        )

    def _mii_uncompress_backward(self, data: bytes) -> bytes:
        """
        decompresses data using the Mii LZ77 variant (backward decompression).
        this is a common compression format for NDS overlays and ARM9 binaries.
        the algorithm reads control flags and data from the end of the compressed
        stream and writes to the end of the destination buffer, working backwards.

        args:
            data: the compressed byte string.

        returns:
            a bytes object containing the decompressed data.

        raises:
            ValueError: if the data is malformed (e.g., too short, invalid size, unsupported type).
            EOFError: if the compressed data ends prematurely during decompression.
            IndexError: if there's an out-of-bounds access during decompression (indicates corruption).
        """
        if len(data) < 4:  # minimum for footer (which contains the decompressed size)
            raise ValueError(
                "data too short for Mii decompression footer (minimum 4 bytes required)."
            )

        # the last 4 bytes of the compressed data form a footer containing the decompressed size (little-endian u32).
        decompressed_size = struct.unpack_from("<I", data, len(data) - 4)[0]
        self.logger.log_debug(
            f"Mii Decompress: Expected decompressed size from footer: 0x{decompressed_size:x}"
        )

        if decompressed_size == 0:  # if target size is 0, the result is empty.
            self.logger.log_debug(
                "Mii Decompress: Decompressed size is 0, returning empty data."
            )
            return b""

        # for compressed data, there's typically a 4-byte compression header *before* the 4-byte decompressed_size footer.
        # so, minimum length for actual compressed data is 8 bytes.
        if len(data) < 8:
            # if data is short (4-7 bytes) but `decompressed_size` matches `len(data)-4`,
            # it might be uncompressed data with just a size footer.
            if decompressed_size == len(data) - 4:
                self.logger.log_info(
                    "Mii Decompress: Data seems uncompressed (length matches data minus footer). Returning raw data (excluding footer)."
                )
                return data[:-4]
            # otherwise, it's malformed if it's too short for a header but expects non-zero decompressed output.
            raise ValueError(
                f"data too short for Mii header (length {len(data)}) but decompressed_size is {decompressed_size}. Malformed data."
            )

        # the compression header is the 4 bytes immediately preceding the decompressed_size footer.
        header_val = struct.unpack_from("<I", data, len(data) - 8)[0]
        comp_type = (
            header_val >> 24
        ) & 0xF  # compression type is in the top 4 bits of this header word.

        # type 0x1 (or 0x10 when shifted) is the common LZ77 variant used in NDS.
        if comp_type != 0x1:
            self.logger.log_warn(
                f"Mii compression type is {comp_type}, not the expected type 1 (LZ77 variant). "
                f"Attempting to treat as uncompressed (returning raw data minus 4-byte footer as a fallback)."
            )
            # this is a fallback. if it's truly a different compression algorithm, this will produce incorrect data.
            # if decompressed_size matches len(data)-4, it's more likely to be uncompressed.
            if decompressed_size == len(data) - 4:
                return data[:-4]
            else:  # sizes don't match for uncompressed fallback, this is likely an error or an unsupported type.
                raise ValueError(
                    f"unsupported Mii compression type {comp_type} and size mismatch for uncompressed fallback strategy."
                )

        # sanity check on decompressed_size to prevent attempts to allocate excessive memory.
        # NDS typically has 4MB main RAM. Overlays are usually much smaller.
        # a very large decompressed_size (e.g., > 32MB) is highly suspicious and likely indicates corruption.
        if (
            decompressed_size > 0x2000000
        ):  # 32 MB limit, adjust if necessary for specific use cases.
            raise ValueError(
                f"invalid Mii decompressed_size: 0x{decompressed_size:x} (exceeds sanity limit of 32MB). Possible data corruption."
            )

        result_buffer = bytearray(decompressed_size)
        dest_ptr = decompressed_size  # current position in destination buffer (writing backwards from end).
        src_ptr = (
            len(data) - 8
        )  # current position in source buffer (reading backwards from before header/footer).

        while dest_ptr > 0:  # continue until destination buffer is filled.
            if (
                src_ptr <= 0
            ):  # ran out of source data before filling destination buffer.
                raise EOFError(
                    f"Mii source data exhausted prematurely (dest_ptr={dest_ptr}, src_ptr={src_ptr}). Decompressed data may be incomplete or corrupted."
                )

            block_flags = data[
                src_ptr - 1
            ]  # read the 8-bit flag block. each bit controls one operation.
            src_ptr -= 1

            for bit_idx in range(8):  # process 8 blocks/literals based on the flags.
                if dest_ptr <= 0:
                    break  # finished decompression if destination buffer is full.

                if (
                    block_flags & 0x80
                ) == 0:  # if the highest bit of block_flags is 0, it's a literal byte.
                    if src_ptr <= 0:
                        raise EOFError(
                            f"Mii source exhausted while expecting a literal byte (dest_ptr={dest_ptr}, src_ptr={src_ptr})."
                        )
                    literal_byte = data[src_ptr - 1]
                    src_ptr -= 1
                    dest_ptr -= 1  # move destination pointer back.
                    if dest_ptr < 0:
                        raise IndexError(
                            "Mii destination pointer became negative during literal byte write (should not happen)."
                        )
                    result_buffer[dest_ptr] = literal_byte
                else:  # if the highest bit is 1, it's an LZ77 copy block (length/displacement pair).
                    if src_ptr <= 1:
                        raise EOFError(
                            f"Mii source exhausted while expecting LZ77 block parameters (dest_ptr={dest_ptr}, src_ptr={src_ptr})."
                        )
                    byte1 = data[src_ptr - 1]
                    byte2 = data[src_ptr - 2]
                    src_ptr -= 2

                    # decode length and displacement from the two bytes.
                    # length: 4 bits (from byte1 high nibble) + 3 (minimum copy length is 3).
                    # displacement: 12 bits (byte1 low nibble + byte2) + 1 (displacement is 1-based).
                    copy_length = ((byte1 & 0xF0) >> 4) + 3
                    copy_disp = (((byte1 & 0x0F) << 8) | byte2) + 1

                    if (
                        dest_ptr < copy_length
                    ):  # check if there's enough space left in destination for this copy.
                        raise ValueError(
                            f"Mii LZ77 copy length ({copy_length}) exceeds remaining destination space ({dest_ptr}). "
                            f"Possible corrupt data or incorrect decompressed_size in footer."
                        )

                    # perform the copy from already decompressed part of the buffer.
                    for _ in range(copy_length):
                        current_write_idx = dest_ptr - 1
                        # source for copy is relative to current_write_idx + displacement (looking "back" in the output).
                        current_read_idx = current_write_idx + copy_disp
                        # sanity check bounds for both read and write indices.
                        if not (
                            0 <= current_read_idx < decompressed_size
                            and 0 <= current_write_idx < decompressed_size
                        ):
                            raise IndexError(
                                f"Mii LZ77 copy operation out of bounds: read_idx={current_read_idx}, write_idx={current_write_idx}, "
                                f"disp={copy_disp}, len={copy_length}, dest_rem={dest_ptr}, total_size={decompressed_size}"
                            )
                        result_buffer[current_write_idx] = result_buffer[
                            current_read_idx
                        ]
                        dest_ptr -= (
                            1  # move destination pointer back for each byte copied.
                        )

                block_flags = (
                    block_flags << 1
                ) & 0xFF  # shift to process the next flag bit.
                if dest_ptr <= 0 and bit_idx < 7:
                    break  # check if done after each bit, not just after 8 bits.

        if (
            dest_ptr != 0
        ):  # if dest_ptr is not 0, the output buffer wasn't perfectly filled.
            self.logger.log_warn(
                f"Mii decompression finished, but destination pointer is non-zero ({dest_ptr}). "
                f"This means the actual decompressed data size did not exactly match the 'decompressed_size' from the footer. "
                f"The result may be truncated or contain uninitialized padding if the original size was incorrect."
            )
        return bytes(result_buffer)

    def _define_all_io_registers(self) -> None:
        """
        defines symbols and tags for known NDS I/O registers.
        the actual list `NDS_IO_REGISTERS` is currently empty as per user request,
        so this method will log that and do nothing if the list is empty.
        """
        self.logger.log_info(
            "defining NDS hardware symbols and tags for I/O registers..."
        )
        if not NDS_IO_REGISTERS:  # check if the list has been populated.
            self.logger.log_info(
                "  NDS_IO_REGISTERS list is currently empty. No NDS-specific I/O registers will be defined at this time."
            )
            return

        defined_count = 0
        for addr, name, tag_name, desc in NDS_IO_REGISTERS:
            self.logger.log_debug(
                f"  defining I/O register: {name} at 0x{addr:08x} (Category: {tag_name})"
            )
            self._define_hardware_register(addr, name, tag_name, desc)
            defined_count += 1
        self.logger.log_info(
            f"defined {defined_count}/{len(NDS_IO_REGISTERS)} NDS I/O registers from the list."
        )

    def _define_entry_points_and_symbols(self) -> None:
        """
        defines entry points and corresponding `_start9` and `_start7` symbols
        for the ARM9 and ARM7 processors based on information from the NDS header.
        actual function creation at these addresses is deferred to Binary Ninja's
        standard analysis passes, which will correctly handle ARM/Thumb mode.
        """
        if not self.nds_rom_data or not self.nds_rom_data.header:
            self.logger.log_error(
                "cannot define NDS entry points, NDS ROM data/header not parsed or available."
            )
            return

        header = self.nds_rom_data.header
        primary_entry_defined_successfully = False

        # define arm9 entry point and symbol.
        arm9_load_addr = header.arm9_ram_address
        arm9_entry_raw = (
            header.arm9_entry_address
        )  # this address may have LSB set for Thumb mode.
        arm9_entry_aligned = (
            arm9_entry_raw & ~1
        )  # actual function address must be word-aligned.
        # is_thumb_arm9 = (arm9_entry_raw & 1) != 0 # LSB=1 indicates Thumb mode.

        segment_at_arm9_entry = self.get_segment_at(arm9_entry_aligned)
        # ensure the entry point falls within a valid, executable segment that was loaded at the expected arm9 ram address.
        if (
            segment_at_arm9_entry
            and segment_at_arm9_entry.start == arm9_load_addr
            and segment_at_arm9_entry.executable
        ):
            self.logger.log_info(
                f"defining ARM9 entry point and symbol: _start9 at 0x{arm9_entry_aligned:08x} (raw entry from header: 0x{arm9_entry_raw:x})."
            )
            self.add_entry_point(arm9_entry_aligned)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, arm9_entry_aligned, "_start9")
            )
            self._primary_entry_point_address = (
                arm9_entry_aligned  # arm9 is typically the primary processor.
            )
            primary_entry_defined_successfully = True
        else:
            self.logger.log_warn(
                f"ARM9 entry point 0x{arm9_entry_aligned:x} (raw 0x{arm9_entry_raw:x}) is not within a valid executable segment "
                f"that starts at the expected load address 0x{arm9_load_addr:x}. "
                f"Segment found: {segment_at_arm9_entry}. The _start9 symbol/entry point may not be effective or analysis may fail here."
            )

        # define arm7 entry point and symbol.
        arm7_load_addr = header.arm7_ram_address
        arm7_entry_raw = header.arm7_entry_address
        arm7_entry_aligned = arm7_entry_raw & ~1
        # is_thumb_arm7 = (arm7_entry_raw & 1) != 0

        segment_at_arm7_entry = self.get_segment_at(arm7_entry_aligned)
        if (
            segment_at_arm7_entry
            and segment_at_arm7_entry.start == arm7_load_addr
            and segment_at_arm7_entry.executable
        ):
            self.logger.log_info(
                f"defining ARM7 entry point and symbol: _start7 at 0x{arm7_entry_aligned:08x} (raw entry from header: 0x{arm7_entry_raw:x})."
            )
            self.add_entry_point(
                arm7_entry_aligned
            )  # add as an additional entry point for analysis.
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, arm7_entry_aligned, "_start7")
            )
            if (
                not primary_entry_defined_successfully
            ):  # if arm9 entry definition failed, arm7 might be considered primary.
                self._primary_entry_point_address = arm7_entry_aligned
                primary_entry_defined_successfully = True
        else:
            self.logger.log_warn(
                f"ARM7 entry point 0x{arm7_entry_aligned:x} (raw 0x{arm7_entry_raw:x}) is not within a valid executable segment "
                f"that starts at the expected load address 0x{arm7_load_addr:x}. "
                f"Segment found: {segment_at_arm7_entry}. The _start7 symbol/entry point may not be effective."
            )

        # handle debug rom info if present (usually for arm9 development/debugging).
        if header.debug_rom_offset != 0 and header.debug_size > 0:
            # debug_ram_address might be 0 in header; use a common fallback if so.
            debug_load_addr = (
                header.debug_ram_address
                if header.debug_ram_address != 0
                else 0x02400000
            )  # a common fallback address for debug monitors.
            self.logger.log_info(
                f"debug ARM9 information present in header: ROM offset=0x{header.debug_rom_offset:x}, ROM size=0x{header.debug_size:x}. "
                f"Intended RAM load address=0x{debug_load_addr:08x}. Note: This debug binary is not typically mapped by this loader by default."
            )
            # this loader doesn't map the debug rom by default. just define a symbol indicating its intended load address.
            self.define_auto_symbol(
                Symbol(
                    SymbolType.DataSymbol,
                    debug_load_addr,
                    "arm9_debug_intended_load_address",
                )
            )

        if not primary_entry_defined_successfully:
            self.logger.log_error(
                "failed to define any primary entry point for ARM9 or ARM7 based on header information and segment validation."
            )

    # - main initialization logic
    def init(self) -> bool:
        """
        initializes the NDSView. this is the main setup method called by Binary Ninja
        after `is_valid_for_data` returns true. it orchestrates parsing the NDS ROM
        structure, mapping all memory regions, loading the ARM9 and ARM7 binaries
        (including overlays), defining symbols and tags for hardware registers,
        and setting the processor entry points.

        returns:
            true if initialization was successful and the view is ready for analysis, false otherwise.
        """
        # architecture and platform should have been validated and set in __init__.
        if not self.arch or not self.platform:
            self.logger.log_error(
                "critical: architecture or platform is not set. cannot initialize NDSView."
            )
            return False  # this should ideally not be reached if __init__ completed without raising.

        try:
            self.logger.log_info(
                f"starting NDS ROM loading process for '{self.file.filename}'..."
            )

            # step 1: parse the entire nds rom file structure using the ndsromreader.
            # this is a critical step that populates self.nds_rom_data.
            if not self._parse_rom_file_structure():
                self.logger.log_error(
                    "initial NDS ROM parsing and validation failed. aborting NDSView initialization."
                )
                return False  # cannot proceed reliably if the rom structure is unknown or invalid.

            # step 2: define all necessary tag types for nds specific elements (memory, hardware categories).
            self._initialize_tag_types()

            # step 3: map the general nds memory layout (bios, ram regions, i/o, vram, etc.) into segments.
            self._map_memory_regions()

            # step 4: load the arm9 and arm7 binaries and their overlays.
            # these methods will handle decompression and map further segments for code/data/bss.
            self._load_arm9_binary()
            self._load_arm7_binary()
            if (
                self.nds_rom_data
            ):  # ensure nds_rom_data is valid after parsing (it should be if _parse_rom_file_structure returned true).
                self._load_overlays_for_cpu(
                    "ARM9", self.nds_rom_data.arm9_overlay_table
                )
                self._load_overlays_for_cpu(
                    "ARM7", self.nds_rom_data.arm7_overlay_table
                )
            else:  # should not happen if parsing succeeded.
                self.logger.log_error(
                    "nds_rom_data is unexpectedly None after successful parsing. cannot load binaries/overlays."
                )
                return False

            # step 5: define symbols and tags for all known nds i/o registers.
            self._define_all_io_registers()  # this will use the NDS_IO_REGISTERS list when populated.

            # step 6: define the rom's entry points for arm9 and arm7.
            self._define_entry_points_and_symbols()

            # note: self.update_analysis() or self.update_analysis_and_wait() is not called here.
            # binary ninja's core will handle triggering the analysis passes after the loader's init() returns true.
            self.logger.log_info(
                "NDS ROM structure loaded and initial setup complete. Binary Ninja will now perform analysis."
            )
            return True  # initialization successful

        except Exception as e:
            # catch any unexpected errors during the entire initialization process.
            self.logger.log_error(
                f"a critical failure occurred during NDSView initialization: {e}\n{traceback.format_exc()}"
            )
            return False  # indicate failure to binary ninja.

    # - required binaryview method overrides
    # these methods are part of the BinaryView plugin interface and must be implemented.

    def perform_is_executable(self) -> bool:
        """
        indicates that NDS ROMs contain executable code for its processors.
        """
        self.logger.log_debug(
            "perform_is_executable called, returning true for NDS ROM."
        )
        return True

    def perform_get_entry_point(self) -> int:
        """
        returns the primary entry point address for the NDS ROM.
        this is typically the ARM9 entry point. If that was not successfully
        defined or is invalid, it might fall back to the ARM7 entry point or,
        as a last resort, the start of the view or 0.
        this method is called by the Binary Ninja core after `init()` completes.
        """
        if self._primary_entry_point_address is not None:
            self.logger.log_debug(
                f"perform_get_entry_point: returning stored primary entry point 0x{self._primary_entry_point_address:08x}."
            )
            return self._primary_entry_point_address

        # fallback logic if _primary_entry_point_address wasn't set during init (e.g., due to issues).
        self.logger.log_warn(
            "perform_get_entry_point: _primary_entry_point_address was not set during initialization. "
            "Attempting fallback using parsed header values."
        )
        if self.nds_rom_data and self.nds_rom_data.header:
            header = self.nds_rom_data.header
            # try arm9 entry first as primary.
            arm9_entry_aligned = header.arm9_entry_address & ~1
            # check if a segment exists at the arm9 load address (where its entry point should reside).
            seg_at_arm9_load = self.get_segment_at(header.arm9_ram_address)
            if (
                seg_at_arm9_load
                and seg_at_arm9_load.start == header.arm9_ram_address
                and header.arm9_ram_address
                <= arm9_entry_aligned
                < header.arm9_ram_address + seg_at_arm9_load.length
            ):
                self.logger.log_info(
                    "perform_get_entry_point: using ARM9 entry address from header as fallback."
                )
                return arm9_entry_aligned

            # if arm9 entry is not valid or its segment isn't as expected, try arm7.
            arm7_entry_aligned = header.arm7_entry_address & ~1
            seg_at_arm7_load = self.get_segment_at(header.arm7_ram_address)
            if (
                seg_at_arm7_load
                and seg_at_arm7_load.start == header.arm7_ram_address
                and header.arm7_ram_address
                <= arm7_entry_aligned
                < header.arm7_ram_address + seg_at_arm7_load.length
            ):
                self.logger.log_info(
                    "perform_get_entry_point: using ARM7 entry address from header as fallback (ARM9 entry was not valid/in segment)."
                )
                return arm7_entry_aligned

        # if all fallbacks fail, this indicates a significant issue with the ROM or loader logic.
        self.logger.log_error(
            "perform_get_entry_point: no valid entry points found from loader's internal state or parsed header. "
            "Returning start of view (0x{self.start:08x}) or 0 as a last resort. Analysis may be incorrect."
        )
        return self.start if self.start is not None else 0  # absolute last resort.

    def perform_get_address_size(self) -> int:
        """
        returns the address size for the NDS platform, which is 4 bytes (32-bit addresses)
        for both its ARM9 and ARM7 processors.
        """
        self.logger.log_debug(
            "perform_get_address_size called, returning 4 (for 32-bit addresses)."
        )
        return 4


# register the NDSView class with Binary Ninja so it can be used to open .nds files.
NDSView.register()
