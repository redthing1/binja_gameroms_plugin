import struct
import traceback
from typing import Optional, Dict, Tuple, List
from dataclasses import dataclass

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

# io definitions for psp hardware registers.
from ..defs.psp import PSP_IO_REGISTERS

# - elf constants
# these constants define the structure and magic values for elf (executable and linkable format) files,
# specifically tailored for 32-bit little-endian mips executables as used by the playstation portable (psp).

# elf header structure format string for 32-bit little-endian.
# describes the layout of the main elf header.
# fields: e_ident[16], e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
#         e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
ELF_HEADER_FORMAT = "<16sHHIIIIIHHHHHH"  # '<' for little-endian
ELF_HEADER_SIZE = struct.calcsize(ELF_HEADER_FORMAT)

# e_ident array indices (offsets within the 16-byte e_ident field of the elf header).
EI_MAG0 = 0  # magic number byte 0: 0x7f
EI_MAG1 = 1  # magic number byte 1: 'E'
EI_MAG2 = 2  # magic number byte 2: 'L'
EI_MAG3 = 3  # magic number byte 3: 'F'
EI_CLASS = 4  # file class (e.g., 32-bit or 64-bit).
EI_DATA = 5  # data encoding (e.g., little or big endian).
EI_VERSION = 6  # elf version (should be EV_CURRENT, which is 1).

# e_ident values relevant for psp elf files.
ELFCLASS32 = 1  # indicates a 32-bit object file.
ELFDATA2LSB = 1  # indicates little-endian data encoding.

# e_type values (elf file type).
ET_EXEC = 2  # indicates an executable file. psp elfs are typically this type.

# e_machine values (architecture identifier).
EM_MIPS = 8  # indicates mips architecture. psp uses a mips-based cpu (allegrex).

# program header structure format string for 32-bit elf.
# describes the layout of entries in the program header table.
# fields: p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
P_HEADER_FORMAT = "<IIIIIIII"
P_HEADER_SIZE = struct.calcsize(P_HEADER_FORMAT)

# p_type values (program header type).
PT_LOAD = 1  # indicates a loadable segment. these are the segments mapped into memory.

# p_flags values (segment permissions).
PF_X = 1  # execute permission.
PF_W = 2  # write permission.
PF_R = 4  # read permission.

# section header structure format string for 32-bit elf.
# describes the layout of entries in the section header table.
# fields: sh_name (index into string table), sh_type, sh_flags, sh_addr, sh_offset, sh_size,
#         sh_link, sh_info, sh_addralign, sh_entsize
S_HEADER_FORMAT = "<IIIIIIIIII"
S_HEADER_SIZE = struct.calcsize(S_HEADER_FORMAT)

# sh_type values (section type).
SHT_NULL = 0  # section header table entry unused.
SHT_PROGBITS = 1  # program data (e.g., .text, .data sections).
SHT_SYMTAB = 2  # symbol table.
SHT_STRTAB = 3  # string table (often for section names or symbol names).
SHT_RELA = 4  # relocation entries with addends (used for dynamic linking).
SHT_HASH = 5  # symbol hash table.
SHT_DYNAMIC = 6  # dynamic linking information.
SHT_NOTE = 7  # notes section (e.g., abi version, build id).
SHT_NOBITS = 8  # program space with no data in the file (e.g., .bss section).
SHT_REL = 9  # relocation entries, no addends.
SHT_SHLIB = 10  # reserved, unspecified semantics.
SHT_DYNSYM = 11  # dynamic linker symbol table.

# sh_flags values (section attributes/flags).
SHF_WRITE = 0x1  # section is writable during execution.
SHF_ALLOC = 0x2  # section occupies memory during execution (i.e., it's loaded).
SHF_EXECINSTR = 0x4  # section contains executable machine instructions.


# - dataclasses for elf structures
# these dataclasses provide a structured way to store and access parsed elf header fields,
# improving code readability and maintainability.


@dataclass
class ELFHeader32:
    """Represents the parsed 32-bit ELF header fields."""

    e_ident: bytes = (
        b"\x00" * 16
    )  # identification bytes (magic, class, data, version, etc.)
    e_type: int = 0  # object file type (e.g., executable, relocatable)
    e_machine: int = 0  # specifies the required architecture (e.g., mips)
    e_version: int = 0  # object file version (usually 1 for current)
    e_entry: int = 0  # virtual address of the program entry point
    e_phoff: int = 0  # program header table's file offset
    e_shoff: int = 0  # section header table's file offset
    e_flags: int = 0  # processor-specific flags (e.g., mips abi flags)
    e_ehsize: int = 0  # elf header's size in bytes
    e_phentsize: int = 0  # size in bytes of one entry in the program header table
    e_phnum: int = 0  # number of entries in the program header table
    e_shentsize: int = 0  # size in bytes of one entry in the section header table
    e_shnum: int = 0  # number of entries in the section header table
    e_shstrndx: int = (
        0  # section header table index of the string table used for section names
    )


@dataclass
class ProgramHeader32:
    """Represents a parsed 32-bit ELF Program Header entry."""

    p_type: int = 0  # type of segment (e.g., PT_LOAD, PT_DYNAMIC)
    p_offset: int = 0  # segment's file offset from the beginning of the file
    p_vaddr: int = 0  # segment's virtual address where it should be mapped in memory
    p_paddr: int = (
        0  # segment's physical address (often ignored or same as vaddr on systems without mmu complexity)
    )
    p_filesz: int = 0  # segment's size in the file image in bytes
    p_memsz: int = 0  # segment's size in memory in bytes (can be > p_filesz for .bss)
    p_flags: int = 0  # segment-dependent flags (read, write, execute permissions)
    p_align: int = (
        0  # segment alignment requirement in memory and file (0 or 1 means no alignment)
    )


# - psp hardware definitions

# dictionary mapping psp-specific tag type names (proper case) to icons.
# these are used for categorizing hardware registers and memory regions in the ui,
# making it easier for users to identify different hardware components.
PSP_TAG_TYPE_DEFINITIONS: Dict[str, str] = {
    "Memory Region": "🗺️",  # for general memory segments like ram, vram, scratchpad
    "Memory Management": "🧠",  # for memory controller, tlb, cache control registers
    "System Control": "⚙️",  # for syscon (system controller), clockgen, overall power control
    "Interrupts": "⚡",  # for interrupt controller registers
    "Profiler": "⏱️",  # for hardware profiling units, if any are directly mapped
    "VME": "🎬",  # for virtual mobile engine (psp's multimedia co-processor) registers
    "NAND Flash": "💾",  # for nand flash controller and associated dma
    "Graphics Engine": "🖼️",  # for gpu (graphics processing unit) registers
    "KIRK Crypto": "🔒",  # for kirk cryptographic engine registers (security processor)
    "LCD Controller": "🖥️",  # for lcd display controller registers
    "GPIO": "💡",  # for general purpose i/o pin registers
    "UART": "↔️",  # for universal asynchronous receiver/transmitter (serial port) registers
    "Audio": "🔊",  # for audio codec and controller registers (sas core)
    "DMA": "➡️",  # for direct memory access controller registers
    "Timers": "⏱️",  # for hardware timer registers
    "USB": "🔌",  # for usb controller registers
    "Memory Stick": "💾",  # for memory stick pro duo controller registers
    "WLAN": "📡",  # for wireless lan controller registers
    "Power": "🔋",  # for specific power management registers (e.g., battery, charging)
    "I2C": "⛓️",  # for inter-integrated circuit (i2c) bus controller registers
    "SPI": "〰️",  # for serial peripheral interface (spi) bus controller registers
    "ATA": "💿",  # for ata (ide) interface, primarily for the umd drive
    "Hardware Register": "🔩",  # generic fallback icon for i/o registers not fitting other categories
}


# - pspview class definition
class PSPView(BinaryView):
    """
    BinaryView class for loading and analyzing PlayStation Portable (PSP)
    ELF executables. It handles ELF parsing, maps memory regions according
    to PSP's hardware layout and ELF segments, and defines known hardware registers.
    """

    name = "PSPELF"  # short name for the view type, registered with binary ninja.
    long_name = "PlayStation Portable ELF"  # descriptive name shown in the ui.

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
        # create a logger instance specific to this plugin for organized and identifiable logging.
        self.logger: Logger = self.create_logger(f"{self.name}")
        # store a reference to the raw data view for reading segment data from the elf file.
        self.raw_data: BinaryView = data
        # cache for created tagtypes to avoid redundant api calls during setup.
        self._created_tag_types: Dict[str, TagType] = {}
        # store the parsed elf header after successful parsing by _parse_elf_header().
        self.elf_header: Optional[ELFHeader32] = None
        # store the primary entry point address once determined, for use by perform_get_entry_point().
        self._primary_entry_point_address: Optional[int] = None

        # the psp uses a mips iii-based allegrex cpu, which is a 32-bit little-endian mips processor.
        # we need to find a suitable mips architecture definition available in binary ninja.
        selected_arch: Optional[Architecture] = None
        selected_platform: Optional[Platform] = None

        # prioritize 'mipsel32' as it explicitly denotes little-endian mips 32-bit.
        # if 'mipsel32' is not found or lacks a standalone platform, fallback to the more generic 'mips32'.
        arch_candidates = ["mipsel32", "mips32"]
        for arch_name_candidate in arch_candidates:
            self.logger.log_debug(
                f"__init__: attempting to get architecture '{arch_name_candidate}'..."
            )
            try:
                current_arch_attempt = Architecture[arch_name_candidate]  # type: ignore (arch names are strings)
                if current_arch_attempt:
                    self.logger.log_debug(
                        f"__init__: found architecture: {current_arch_attempt.name}. getting its standalone platform..."
                    )
                    current_platform_attempt = current_arch_attempt.standalone_platform
                    if current_platform_attempt:
                        selected_arch = current_arch_attempt
                        selected_platform = current_platform_attempt
                        self.logger.log_info(
                            f"__init__: successfully selected architecture '{selected_arch.name}' and platform '{selected_platform.name}'."
                        )
                        break  # successfully found a suitable architecture and platform.
                    else:
                        self.logger.log_warn(
                            f"__init__: architecture '{current_arch_attempt.name}' found, but no standalone platform associated. trying next candidate if any."
                        )
            except KeyError:  # architecture name not found in binary ninja's list.
                self.logger.log_warn(
                    f"__init__: architecture '{arch_name_candidate}' not found. trying next candidate if any."
                )
            except (
                Exception
            ) as e:  # catch any other unexpected error during architecture lookup.
                self.logger.log_error(
                    f"__init__: unexpected error looking up architecture '{arch_name_candidate}': {e}"
                )

        # if after trying all candidates, no suitable architecture/platform was found, this is a fatal error.
        if not selected_arch or not selected_platform:
            self.logger.log_error(
                f"critical __init__ error: failed to find a suitable MIPS architecture and platform from candidates: {arch_candidates}. "
                "PSP analysis cannot proceed. Ensure Binary Ninja has MIPS support installed."
            )
            raise RuntimeError(
                "mips architecture/platform not found or not suitable for PSP."
            )

        self.arch: Architecture = selected_arch
        self.platform: Platform = selected_platform

        self.logger.log_info(
            f"PSPView instance fully initialized with platform: {self.platform.name}, architecture: {self.arch.name}"
        )

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        checks if the provided data is likely a valid psp elf file.
        this method is called by binary ninja to determine if this view should be used
        for the given file. it performs several checks on the elf header:
        1.  ensures the data is large enough for an elf header.
        2.  verifies the elf magic number (0x7f 'e' 'l' 'f').
        3.  checks for 32-bit class (ELFCLASS32).
        4.  checks for little-endian data encoding (ELFDATA2LSB).
        5.  checks for mips architecture (EM_MIPS).

        args:
            data: the BinaryView object containing the data to be validated.
        returns:
            true if the data appears to be a psp-compatible elf, false otherwise.
        """
        # check if the data is at least as large as an elf header.
        if data.length < ELF_HEADER_SIZE:
            log_debug(
                f"[{cls.name}] validation: file size {data.length} is smaller than ELF header size {ELF_HEADER_SIZE}. Not a PSP ELF."
            )
            return False

        try:
            # read the elf header bytes from the beginning of the file.
            header_bytes = data.read(0, ELF_HEADER_SIZE)
            if (
                len(header_bytes) < ELF_HEADER_SIZE
            ):  # ensure enough bytes were actually read.
                log_debug(
                    f"[{cls.name}] validation: could not read full ELF header (read {len(header_bytes)} bytes, expected {ELF_HEADER_SIZE})."
                )
                return False

            # e_ident is the first 16 bytes of the header and contains crucial identification info.
            e_ident = header_bytes[:16]

            # 1. check elf magic number: 0x7f 'E' 'L' 'F'.
            if not (
                e_ident[EI_MAG0] == 0x7F
                and e_ident[EI_MAG1] == ord("E")
                and e_ident[EI_MAG2] == ord("L")
                and e_ident[EI_MAG3] == ord("F")
            ):
                log_debug(
                    f"[{cls.name}] validation: invalid ELF magic number (got: {e_ident[:4].hex()})."
                )
                return False

            # 2. check for 32-bit class. psp uses 32-bit mips.
            if e_ident[EI_CLASS] != ELFCLASS32:
                log_debug(
                    f"[{cls.name}] validation: incorrect ELF class ({e_ident[EI_CLASS]}, expected {ELFCLASS32} for 32-bit)."
                )
                return False

            # 3. check for little-endian data encoding. psp mips is little-endian.
            if e_ident[EI_DATA] != ELFDATA2LSB:
                log_debug(
                    f"[{cls.name}] validation: incorrect data encoding ({e_ident[EI_DATA]}, expected {ELFDATA2LSB} for little-endian)."
                )
                return False

            # 4. unpack the e_machine field (architecture) to check for mips.
            # e_machine is a 2-byte field (unsigned short) at offset 18 (0x12) in the header.
            # struct.unpack_from is used to read directly from the offset in header_bytes.
            e_machine_val = struct.unpack_from("<H", header_bytes, 18)[
                0
            ]  # '<H' for little-endian unsigned short.
            if e_machine_val != EM_MIPS:
                log_debug(
                    f"[{cls.name}] validation: incorrect machine type ({e_machine_val}, expected {EM_MIPS} for MIPS architecture)."
                )
                return False

            # if all checks pass, it's highly likely a valid psp elf.
            log_info(
                f"[{cls.name}] validation successful: file appears to be a valid MIPS32 little-endian ELF, suitable for PSP."
            )
            return True

        except (struct.error, IndexError) as unpack_err:
            # handle potential errors during unpacking header bytes or accessing e_ident indices.
            log_error(
                f"[{cls.name}] error during ELF header validation (struct unpacking or indexing issue): {unpack_err}\n{traceback.format_exc()}"
            )
            return False
        except Exception as e:
            # catch any other unexpected errors during the validation process.
            log_error(
                f"[{cls.name}] unexpected error during ELF validation: {e}\n{traceback.format_exc()}"
            )
            return False

    # - helper methods for initialization

    def _parse_elf_header(self) -> bool:
        """
        parses the elf header from the raw data provided by the parent view
        (self.raw_data) and stores the parsed fields in `self.elf_header` (an ELFHeader32 dataclass instance).

        returns:
            true on successful parsing and population of `self.elf_header`,
            false if an error occurs (e.g., file too small for header, read error,
            struct unpack error).
        """
        self.logger.log_info("parsing ELF header from raw data...")
        if self.raw_data.length < ELF_HEADER_SIZE:
            self.logger.log_error(
                f"file is too small ({self.raw_data.length} bytes) for ELF header (requires {ELF_HEADER_SIZE} bytes). Cannot parse."
            )
            return False

        header_bytes = self.raw_data.read(0, ELF_HEADER_SIZE)
        if len(header_bytes) < ELF_HEADER_SIZE:  # ensure full header was read.
            self.logger.log_error(
                f"could not read full ELF header (read {len(header_bytes)} bytes, expected {ELF_HEADER_SIZE}). Cannot parse."
            )
            return False

        try:
            # unpack the header bytes according to the defined format string ELF_HEADER_FORMAT.
            header_values_tuple = struct.unpack(ELF_HEADER_FORMAT, header_bytes)
            # store the parsed values into the ELFHeader32 dataclass instance for easy access.
            self.elf_header = ELFHeader32(*header_values_tuple)

            # log key fields for diagnostic purposes and to confirm successful parsing.
            self.logger.log_info(
                f"  ELF Entry Point Address: 0x{self.elf_header.e_entry:08x}"
            )
            self.logger.log_info(
                f"  Program Header Table: File Offset=0x{self.elf_header.e_phoff:x}, Number of Entries={self.elf_header.e_phnum}, Size of Entry={self.elf_header.e_phentsize} bytes"
            )
            self.logger.log_info(
                f"  Section Header Table: File Offset=0x{self.elf_header.e_shoff:x}, Number of Entries={self.elf_header.e_shnum}, Size of Entry={self.elf_header.e_shentsize} bytes, String Table Index={self.elf_header.e_shstrndx}"
            )
            self.logger.log_info("ELF header parsed successfully.")
            return True
        except (
            struct.error
        ) as unpack_err:  # specifically catch struct unpacking errors.
            self.logger.log_error(f"failed to unpack ELF header data: {unpack_err}")
            self.logger.log_error(
                f"  ELF header format string used: '{ELF_HEADER_FORMAT}' (expected size: {struct.calcsize(ELF_HEADER_FORMAT)} bytes)"
            )
            self.elf_header = None  # ensure self.elf_header is None on failure to prevent later use of potentially invalid data.
            return False
        except Exception as e:  # catch any other unexpected errors during parsing.
            self.logger.log_error(
                f"unexpected error occurred while parsing ELF header: {e}\n{traceback.format_exc()}"
            )
            self.elf_header = None
            return False

    def _initialize_tag_types(self) -> None:
        """
        defines and caches all necessary tag types used by this view for PSP-specific elements
        (e.g., memory regions, hardware components). it iterates through the global
        `PSP_TAG_TYPE_DEFINITIONS` dictionary. this setup allows for visually distinct
        and organized tagging in the binary ninja ui.
        """
        self.logger.log_info("initializing PSP hardware and memory tag types...")
        initialized_count = 0
        total_defined = len(PSP_TAG_TYPE_DEFINITIONS)
        for name, icon in PSP_TAG_TYPE_DEFINITIONS.items():
            if self._get_or_create_tag_type(name, icon):
                initialized_count += 1
            else:
                # log a warning if a specific tag type couldn't be set up.
                # this might indicate an issue with the name/icon or binary ninja api.
                self.logger.log_warn(
                    f"could not initialize PSP tag type: '{name}' with icon '{icon}'."
                )
        self.logger.log_info(
            f"{initialized_count}/{total_defined} PSP tag types are now ready for use."
        )

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        """
        retrieves an existing tag type by its name or creates a new one if it doesn't exist.
        results are cached in `self._created_tag_types` to avoid redundant api calls to
        binary ninja and improve performance during the loading process.
        tag type names are handled case-insensitively for lookup by binary ninja's
        `get_tag_type` method, but are created with the provided casing.

        args:
            name: the name of the tag type (e.g., "Memory Region"). use proper case for creation.
            icon: the icon (emoji or short string) for the tag type (e.g., "🗺️").

        returns:
            the TagType object if successfully found or created, or none if both attempts fail.
        """
        # use lowercase for the internal cache key for consistent lookups and to match
        # how binary ninja's `self.tag_types` might store them.
        name_lower = name.lower()
        if name_lower in self._created_tag_types:
            self.logger.log_debug(f"retrieved cached tag type: '{name}'.")
            return self._created_tag_types[name_lower]

        # attempt to get the tag type using binary ninja's built-in lookup by name.
        # this is case-insensitive.
        existing_tag_type = self.get_tag_type(name)
        if existing_tag_type:
            self.logger.log_debug(
                f"found existing tag type in BinaryView: '{name}'. Caching it."
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
            # log an error if tag type creation fails for any reason (e.g., invalid icon, api issues).
            self.logger.log_error(
                f"failed to create tag type '{name}': {e}\n{traceback.format_exc()}"
            )
            return None

    def _define_hardware_register(
        self,
        address: int,
        name: str,  # the symbol name for the register, should be uppercase (e.g., SYSCON_RAMSIZE)
        tag_category_name: str,  # e.g., "System Control", must be a key in PSP_TAG_TYPE_DEFINITIONS
        description: str = "",  # a comment for the register
    ):
        """
        helper method to define a symbol for a hardware register at a given address
        and apply a descriptive tag to it for better organization and identification
        within the binary ninja user interface.

        args:
            address: the memory-mapped i/o address of the hardware register.
            name: the conventional name for the register symbol (e.g., "SYSCON_RAMSIZE").
            tag_category_name: the category name of the tag type (e.g., "System Control").
                               this must match a key in PSP_TAG_TYPE_DEFINITIONS.
            description: an optional comment to add for the register at its address, explaining its purpose.
        """
        try:
            # define the symbol for the register at its memory-mapped address.
            # DataSymbol is appropriate for hardware registers.
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))

            # add the provided description as a comment at the register's address if a description is given.
            if description:
                self.set_comment_at(address, description)

            # retrieve the icon associated with the tag category from our definitions.
            # default to a generic hardware icon if the category is not found (should not happen with valid definitions).
            tag_icon = PSP_TAG_TYPE_DEFINITIONS.get(
                tag_category_name, "🔩"
            )  # "🔩" is a generic nut/bolt icon.
            tag_type_object = self._get_or_create_tag_type(tag_category_name, tag_icon)

            # if the tag type was successfully obtained or created, add the tag to the register's address.
            if tag_type_object:
                # using the register name as tag data can be helpful for UI identification.
                # self.add_tag expects the tag type's name (a string) as its second argument.
                self.add_tag(address, tag_type_object.name, data=name)
            else:
                # this indicates an issue with tag type creation/retrieval for this category.
                self.logger.log_warn(
                    f"could not obtain or create tag type '{tag_category_name}' for register '{name}' at 0x{address:08x}. Tag not applied."
                )
        except Exception as e:
            # log any errors encountered during register definition, but continue loading other registers.
            self.logger.log_error(
                f"error processing hardware register '{name}' at 0x{address:08x}: {e}\n{traceback.format_exc()}"
            )

    def _map_psp_hardware_memory_regions(self) -> None:
        """
        maps the core psp hardware memory regions (e.g., main ram, vram, i/o ports, scratchpad, boot rom alias).
        these regions are defined with fixed addresses and sizes based on psp hardware documentation.
        they are typically not file-backed (i.e., their content is not read from the elf file itself,
        except potentially for a boot rom if it were loaded from a separate file, which is not done here).
        these mappings establish the foundational memory layout of the psp system for analysis.
        """
        self.logger.log_info("mapping core PSP hardware memory regions...")

        # internal helper function to simplify adding memory regions as segments.
        # this promotes consistency in how segments are added and logged.
        def add_hardware_memory_region(
            address: int,  # starting virtual address of the hardware region.
            size: int,  # size of the region in bytes.
            permissions: SegmentFlag,  # r/w/x permissions for the region (e.g., self.PERM_RW).
            name: str,  # descriptive name for the region (e.g., "Main RAM").
            tag_name: str = "Memory Region",  # category for the tag, defaults to "Memory Region".
            tag_icon: str = "🗺️",  # icon for the tag, defaults to a map icon.
        ):
            self.logger.log_debug(
                f"  preparing to map hardware region '{name}': addr=0x{address:08x}, size=0x{size:x} ({size // 1024}KB), "
                f"perms={(permissions.name if hasattr(permissions, 'name') else permissions)}"  # log permission enum name if possible
            )
            try:
                # hardware regions are not backed by the elf file itself, so file_offset and file_length are 0.
                # their content is determined by the psp hardware/runtime.
                self.add_auto_segment(address, size, 0, 0, permissions)

                # get the appropriate tag type for this memory region.
                tag_type_object = self._get_or_create_tag_type(tag_name, tag_icon)
                if tag_type_object:
                    # add a tag at the start of the region for easy identification in the ui.
                    # use the tag type's string name.
                    self.add_tag(address, tag_type_object.name, data=f"{name} Start")

                # add a comment at the start of the region indicating its name and size.
                self.set_comment_at(address, f"PSP Hardware: {name} ({size // 1024}KB)")
                self.logger.log_info(f"  successfully mapped hardware region '{name}'.")
            except Exception as e:
                self.logger.log_error(
                    f"failed to map hardware memory region '{name}' at 0x{address:08x}: {e}\n{traceback.format_exc()}"
                )

        # - define standard psp memory regions based on common knowledge / sdk documentation.
        # sc (system control) cpu scratchpad ram (16kb): fast internal ram for the cpu.
        add_hardware_memory_region(
            0x00010000,
            0x4000,
            self.PERM_RWX,
            "SC CPU Scratchpad RAM",
            tag_name="Memory Management",
        )

        # vram / edram (embedded dram for graphics):
        # psp sdk often refers to 0x04000000 as the start of vram accessible by the cpu for framebuffers, textures, etc.
        # the directly cpu-accessible portion is typically 2mb. total edram might be larger for gpu internal use.
        add_hardware_memory_region(
            0x04000000,
            0x00200000,
            self.PERM_RW,
            "VRAM / Display Memory (2MB CPU Accessible)",
            tag_name="Graphics Engine",
        )

        # main ram:
        # psp-1000 models have 32mb. psp-2000/3000/go models have 64mb.
        # user applications typically have access to a partition starting at 0x08000000.
        # for general elf loading, assuming the common 32mb user partition is a safe default.
        # a more advanced loader might try to detect psp model or allow user configuration.
        main_ram_base = 0x08000000
        main_ram_size = 0x02000000  # 32mb default (user partition size for psp-1000).
        # main_ram_size = 0x04000000 # could be 64mb for later models, but user partition might still be limited.
        add_hardware_memory_region(
            main_ram_base,
            main_ram_size,
            self.PERM_RWX,
            f"Main RAM ({main_ram_size // (1024*1024)}MB User Partition)",
        )

        # i/o ports: memory-mapped hardware registers. these are large, often sparsely populated regions.
        # map the main known blocks as readable/writable segments and tag them generically as "Hardware Register".
        # specific registers within these blocks will be defined later by _define_psp_io_registers().
        add_hardware_memory_region(
            0x1C000000,
            0x01000000,
            self.PERM_RW,
            "I/O Ports Block 1 (Syscon, Media Engine, etc.)",
            tag_name="Hardware Register",
        )  # 16mb (covers 0x1Cxxxxxx)
        add_hardware_memory_region(
            0x1D000000,
            0x02000000,
            self.PERM_RW,
            "I/O Ports Block 2 (Graphics, Audio, etc.)",
            tag_name="Hardware Register",
        )  # 32mb (covers 0x1Dxxxxxx, 0x1Exxxxxx)
        add_hardware_memory_region(
            0x1F000000,
            0x00C00000,
            self.PERM_RW,
            "I/O Ports Block 3 (NAND, Kirk, etc.)",
            tag_name="Hardware Register",
        )  # ~12mb (covers up to ~0x1FBFFFFF)

        # nand dma i/o buffers (a specific small region within the broader i/o space, sometimes highlighted).
        add_hardware_memory_region(
            0x1FF00000,
            0x00000A00,
            self.PERM_RW,
            "NAND DMA I/O Buffers",
            tag_name="NAND Flash",
        )  # approx 2.5kb

        # boot rom / kernel ram (exception vectors):
        # psp's boot rom (ipl) resides at physical address 0x1fc00000.
        # mips cpus often access this region via kseg1 (uncached, unmapped) virtual addresses starting at 0xbfc00000.
        # this kseg1 alias maps physical 0x1fc00000 to virtual 0xbfc00000.
        # we map a standard 16kb area here, which covers the mips reset and exception vectors.
        boot_rom_kseg1_base = 0xBFC00000
        boot_rom_vector_area_size = (
            0x4000  # 16kb, standard mips size for initial vectors.
        )
        add_hardware_memory_region(
            boot_rom_kseg1_base,
            boot_rom_vector_area_size,
            self.PERM_RX,
            "Boot ROM Exception Vectors (KSEG1 Alias)",
        )
        # define symbols for common mips exception vectors relative to this kseg1 base.
        # these are standard entry points for the cpu on reset or exceptions.
        self.define_auto_symbol(
            Symbol(
                SymbolType.FunctionSymbol, boot_rom_kseg1_base + 0x000, "Reset_Vector"
            )
        )  # reset/power-on vector
        self.define_auto_symbol(
            Symbol(
                SymbolType.FunctionSymbol,
                boot_rom_kseg1_base + 0x180,
                "General_Exception_Vector",
            )
        )  # common handler for most exceptions when bev=1
        # other vectors like tlb refill (0x000, 0x080, 0x100 depending on config) exist but reset and general exception are key.

        self.logger.log_info("finished mapping PSP hardware memory regions.")

    def _map_elf_loadable_segments(self) -> None:
        """
        maps the loadable program segments (those with type PT_LOAD) from the ELF header.
        these segments contain the actual code and initialized data from the ELF file.
        they are read from the file based on `p_offset` and `p_filesz` and mapped
        into memory at their specified virtual addresses (`p_vaddr`) with sizes
        defined by `p_memsz`. segment permissions (read, write, execute) are
        derived from `p_flags`. this method relies on `self.elf_header` having
        been successfully parsed and populated.
        """
        if not self.elf_header:
            self.logger.log_error(
                "cannot map ELF segments, ELF header not parsed or is invalid."
            )
            return

        e_phoff = self.elf_header.e_phoff  # file offset of the program header table.
        e_phnum = (
            self.elf_header.e_phnum
        )  # number of entries in the program header table.
        e_phentsize = self.elf_header.e_phentsize  # size of each program header entry.

        program_headers_exist = e_phoff > 0 and e_phnum > 0
        self.logger.log_info(
            f"mapping ELF program segments (PT_LOAD type)... Found {e_phnum} program header entries at file offset 0x{e_phoff:x}."
        )

        if not program_headers_exist:
            self.logger.log_info(
                "no program headers found in ELF file (e_phoff or e_phnum is zero). No ELF segments to map."
            )
            return

        # validate program header table information against file size and expected entry size before looping.
        if e_phoff + e_phnum * e_phentsize > self.raw_data.length:
            self.logger.log_error(
                f"program header table definition (offset=0x{e_phoff:x}, num_entries={e_phnum}, entry_size={e_phentsize}) "
                f"exceeds total file size ({self.raw_data.length} bytes). Cannot reliably map ELF segments."
            )
            return
        if e_phentsize != P_HEADER_SIZE:
            self.logger.log_error(
                f"unexpected program header entry size specified in ELF header ({e_phentsize} bytes), "
                f"expected {P_HEADER_SIZE} bytes based on format string. Cannot reliably map ELF segments."
            )
            return

        for i in range(e_phnum):  # iterate through each program header entry.
            ph_file_offset = (
                e_phoff + i * e_phentsize
            )  # calculate file offset of current program header.
            ph_bytes = self.raw_data.read(ph_file_offset, P_HEADER_SIZE)
            if len(ph_bytes) < P_HEADER_SIZE:  # ensure full header entry was read.
                self.logger.log_error(
                    f"could not read full program header entry {i} at file offset 0x{ph_file_offset:x}. Skipping this entry."
                )
                continue

            try:
                # unpack the program header entry bytes into the ProgramHeader32 dataclass.
                ph = ProgramHeader32(*struct.unpack(P_HEADER_FORMAT, ph_bytes))
            except struct.error as unpack_err:
                self.logger.log_error(
                    f"failed to unpack program header entry {i}: {unpack_err}. Skipping this entry."
                )
                continue

            # we are primarily interested in loadable segments (type PT_LOAD).
            if ph.p_type == PT_LOAD:
                map_vaddr = (
                    ph.p_vaddr
                )  # virtual address where the segment should be mapped in memory.
                map_memsz = (
                    ph.p_memsz
                )  # size of the segment in memory (can be larger than file size for .bss).
                segment_file_offset = (
                    ph.p_offset
                )  # offset of this segment's data within the elf file.
                segment_file_data_len = (
                    ph.p_filesz
                )  # size of this segment's data in the elf file.

                # basic validation for the segment's parameters.
                if (
                    map_memsz == 0
                ):  # a loadable segment must have a non-zero memory size.
                    self.logger.log_warn(
                        f"skipping PT_LOAD segment {i} at vaddr 0x{map_vaddr:08x} due to zero memory size (p_memsz = 0)."
                    )
                    continue
                if segment_file_data_len > map_memsz:
                    self.logger.log_warn(
                        f"PT_LOAD segment {i}: file size (p_filesz=0x{segment_file_data_len:x}) is greater than memory size (p_memsz=0x{map_memsz:x}). "
                        f"Will clamp file data length to memory size for mapping, as per ELF spec (excess file data ignored)."
                    )
                    segment_file_data_len = (
                        map_memsz  # map only up to memsize from file.
                    )
                if segment_file_offset + segment_file_data_len > self.raw_data.length:
                    self.logger.log_error(
                        f"PT_LOAD segment {i} data (file_offset=0x{segment_file_offset:x}, file_data_len=0x{segment_file_data_len:x}) "
                        f"exceeds ELF file bounds (total file length={self.raw_data.length}). Skipping this segment as data is invalid."
                    )
                    continue

                # determine binary ninja segment permissions from elf p_flags.
                bn_segment_permissions = 0  # start with no permissions.
                perm_str_log = ""  # for logging.
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
                    f"FileOffset=0x{segment_file_offset:x}, FileDataLen=0x{segment_file_data_len:x}, Perms='{perm_str_log}' (ELF_Flags=0x{ph.p_flags:x})"
                )

                # add the segment to binary ninja using the virtual address.
                # data for the segment is read from segment_file_offset for segment_file_data_len bytes.
                # the segment in memory will have size map_memsz. if map_memsz > segment_file_data_len,
                # the remainder is implicitly zero-filled (bss).
                self.add_auto_segment(
                    map_vaddr,
                    map_memsz,
                    segment_file_offset,
                    segment_file_data_len,
                    bn_segment_permissions,
                )
                self.set_comment_at(
                    map_vaddr,
                    f"ELF Segment {i} (PT_LOAD): File Offset=0x{segment_file_offset:x}, File Size=0x{segment_file_data_len:x}",
                )

                # if p_memsz > p_filesz, the difference is the bss portion of this segment.
                # binary ninja's add_auto_segment handles the zero-filling of this bss part.
                # add a comment to mark the start of the bss within this segment if it exists.
                if map_memsz > segment_file_data_len:
                    bss_start_addr_in_segment = map_vaddr + segment_file_data_len
                    bss_size_in_segment = map_memsz - segment_file_data_len
                    # ensure bss part is actually within the segment's memory bounds.
                    if bss_start_addr_in_segment < map_vaddr + map_memsz:
                        self.set_comment_at(
                            bss_start_addr_in_segment,
                            f"ELF Segment {i} BSS Area Start (Size: 0x{bss_size_in_segment:x})",
                        )
            else:  # not a PT_LOAD segment.
                self.logger.log_debug(
                    f"  skipping program header entry {i}: type=0x{ph.p_type:x} (not PT_LOAD). Other types like PT_NOTE, PT_PHDR are not mapped as loadable segments."
                )
        self.logger.log_info("finished mapping ELF program (PT_LOAD) segments.")

    def _map_elf_sections(self) -> None:
        """
        parses the elf section header table and defines corresponding sections in binary ninja.
        sections provide semantic information about memory regions (e.g., ".text", ".data", ".bss"),
        which is useful for analysis and user understanding. this method relies on
        `self.elf_header` being populated and the section header string table
        (`e_shstrndx`) being correctly identified and readable from the elf file.
        """
        if not self.elf_header:
            self.logger.log_error(
                "cannot map ELF sections, ELF header not parsed or is invalid."
            )
            return

        e_shoff = self.elf_header.e_shoff  # file offset of the section header table.
        e_shnum = (
            self.elf_header.e_shnum
        )  # number of entries in the section header table.
        e_shentsize = self.elf_header.e_shentsize  # size of each section header entry.
        e_shstrndx = (
            self.elf_header.e_shstrndx
        )  # index of the section header string table within the section header table.

        self.logger.log_info("mapping ELF sections...")
        if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
            self.logger.log_warn(
                "ELF section header table information is missing or invalid (offset, num_entries, or entry_size is zero). Skipping ELF section mapping."
            )
            return
        if e_shentsize != S_HEADER_SIZE:
            self.logger.log_error(
                f"unexpected section header entry size: {e_shentsize} bytes (expected {S_HEADER_SIZE} bytes). Skipping ELF section mapping."
            )
            return
        if (
            e_shstrndx >= e_shnum
        ):  # string table index must be a valid index into the section header table.
            self.logger.log_error(
                f"invalid section header string table index in ELF header: {e_shstrndx} (must be < number of sections {e_shnum}). "
                "Section names will be unavailable; skipping ELF section mapping."
            )
            return

        # read the section header for the string table first to get section names.
        strtab_sheader_file_offset = e_shoff + e_shstrndx * e_shentsize
        if strtab_sheader_file_offset + S_HEADER_SIZE > self.raw_data.length:
            self.logger.log_error(
                "section header string table's own header offset is out of file bounds. Skipping ELF section mapping."
            )
            return
        strtab_sheader_bytes = self.raw_data.read(
            strtab_sheader_file_offset, S_HEADER_SIZE
        )
        if len(strtab_sheader_bytes) < S_HEADER_SIZE:
            self.logger.log_error(
                "could not read the full section header for the string table. Skipping ELF section mapping."
            )
            return

        try:
            # unpack the string table's own section header to find its file offset and size.
            # variable names here are local to this unpacking, shadowing class constants intentionally for clarity.
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
            self.logger.log_error(
                f"failed to unpack section header for the string table: {unpack_err}. Skipping ELF section mapping."
            )
            return

        section_names_data_buffer: bytes = b""  # initialize as empty bytes buffer.
        if (
            strtab_sh_type != SHT_STRTAB
        ):  # ensure the identified section is actually a string table.
            self.logger.log_warn(
                f"section header string table index {e_shstrndx} does not point to a SHT_STRTAB section (actual type={strtab_sh_type}). "
                "Section names will be unavailable for ELF sections."
            )
        elif (
            strtab_data_file_offset + strtab_data_size > self.raw_data.length
        ):  # ensure string table data is within file bounds.
            self.logger.log_error(
                f"section header string table data (file_offset=0x{strtab_data_file_offset:x}, size=0x{strtab_data_size:x}) "
                "is out of file bounds. Section names will be unavailable."
            )
        else:  # read the string table data.
            section_names_data_buffer = self.raw_data.read(
                strtab_data_file_offset, strtab_data_size
            )
            if len(section_names_data_buffer) < strtab_data_size:
                self.logger.log_warn(
                    "could not read full section header string table data. Section names may be incomplete."
                )

        # helper function to get a section name string from the string table data buffer.
        def get_section_name_from_strtab(name_index: int) -> str:
            if not section_names_data_buffer or name_index >= len(
                section_names_data_buffer
            ):
                return f"section_{name_index}"  # fallback name if string table is missing or index is out of bounds.
            try:
                # section names are null-terminated strings within the string table.
                null_terminator_pos = section_names_data_buffer.find(
                    b"\x00", name_index
                )
                if (
                    null_terminator_pos == -1
                ):  # if no null terminator found (e.g., last name in table or malformed).
                    null_terminator_pos = len(
                        section_names_data_buffer
                    )  # take up to the end.
                return section_names_data_buffer[name_index:null_terminator_pos].decode(
                    "utf-8", errors="replace"
                )
            except Exception as decode_err:  # catch potential utf-8 decoding errors.
                self.logger.log_warn(
                    f"error decoding section name at index {name_index} from string table: {decode_err}"
                )
                return f"section_{name_index}_decode_error"  # return a placeholder.

        # iterate through all section headers to define sections in binary ninja.
        for i in range(e_shnum):  # e_shnum is the total number of section headers.
            if i == SHT_NULL:
                continue  # section at index 0 (SHT_NULL) is unused and skipped.
            # skip the string table section itself if we've already processed its data.
            if i == e_shstrndx and section_names_data_buffer:
                self.logger.log_debug(
                    f"  skipping section {i} as it is the section header string table itself."
                )
                continue

            sh_file_offset = (
                e_shoff + i * e_shentsize
            )  # calculate file offset of current section header.
            # bounds check for the entire section header table was done earlier.
            sh_bytes = self.raw_data.read(sh_file_offset, S_HEADER_SIZE)
            if len(sh_bytes) < S_HEADER_SIZE:  # ensure full section header was read.
                self.logger.log_error(
                    f"could not read full section header {i} at file offset 0x{sh_file_offset:x}. Skipping this section."
                )
                continue

            try:
                # unpack the current section header's fields.
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
                self.logger.log_error(
                    f"failed to unpack section header {i}: {unpack_err}. Skipping this section."
                )
                continue

            # skip sections that are not allocated in memory (SHF_ALLOC flag not set),
            # unless they are of type SHT_NOBITS (like .bss), which are allocated but have no file data.
            # also skip sections with zero size, as they cannot be meaningfully added to binary ninja.
            if (not (sh_flags & SHF_ALLOC) and sh_type != SHT_NOBITS) or sh_size == 0:
                self.logger.log_debug(
                    f"  skipping section {i} (name_idx={sh_name_idx}): not allocated in memory or has zero size "
                    f"(type={sh_type}, flags=0x{sh_flags:x}, size=0x{sh_size:x})."
                )
                continue

            section_name = get_section_name_from_strtab(sh_name_idx)
            bn_section_semantics = (
                SectionSemantics.DefaultSectionSemantics
            )  # default semantics.
            bn_section_type_str = ""  # binary ninja uses this for format-specific type strings (e.g., "Code", "Data", "BSS").

            # determine binary ninja section semantics based on elf section flags and type.
            is_code_section = bool(sh_flags & SHF_EXECINSTR)
            is_writable_section = bool(sh_flags & SHF_WRITE)
            is_bss_section_type = (
                sh_type == SHT_NOBITS
            )  # .bss sections have type SHT_NOBITS.

            if is_code_section:
                bn_section_semantics = (
                    SectionSemantics.ReadOnlyCodeSectionSemantics
                )  # typical for .text sections.
                bn_section_type_str = "Code"
            elif (
                is_bss_section_type
            ):  # .bss sections are uninitialized data, readable and writable.
                bn_section_semantics = SectionSemantics.ReadWriteDataSectionSemantics
                bn_section_type_str = "BSS"
            elif sh_type == SHT_PROGBITS:  # SHT_PROGBITS sections contain program data.
                if is_writable_section:  # if writable, it's likely .data or similar.
                    bn_section_semantics = (
                        SectionSemantics.ReadWriteDataSectionSemantics
                    )
                    bn_section_type_str = "Data"
                else:  # if not writable, it's likely .rodata or similar.
                    bn_section_semantics = SectionSemantics.ReadOnlyDataSectionSemantics
                    bn_section_type_str = "ReadOnlyData"
            # other section types like SHT_SYMTAB, SHT_STRTAB (if SHF_ALLOC is set), SHT_NOTE, etc.,
            # might need specific handling or can use default semantics if they are allocated.
            # for this loader, we are primarily focused on correctly identifying common code/data/bss sections.

            self.logger.log_info(
                f"  adding ELF section '{section_name}': VAddr=0x{sh_addr:08x}, Size=0x{sh_size:x}, "
                f"ELFType={sh_type}, ELFFlags=0x{sh_flags:x}, "
                f"BN_Semantics='{bn_section_semantics.name}', BN_Type='{bn_section_type_str}'"
            )

            # provide an extra log warning if a section commonly expected to be code (e.g., ".text")
            # does not have executable semantics. this can indicate issues with the elf or linker script.
            if (
                section_name.startswith(".text")
                and bn_section_semantics
                != SectionSemantics.ReadOnlyCodeSectionSemantics
            ):
                self.logger.log_warn(
                    f"section '{section_name}' starts with '.text' but does not have ReadOnlyCodeSectionSemantics "
                    f"(actual determined semantics: {bn_section_semantics.name}). This might be unusual."
                )

            try:
                # add the section to binary ninja using add_auto_section.
                # sh_addralign and sh_entsize are passed directly from the elf section header.
                self.add_auto_section(
                    name=section_name,
                    start=sh_addr,  # virtual address of the section.
                    length=sh_size,  # size of the section in memory.
                    semantics=bn_section_semantics,
                    type=bn_section_type_str,
                    align=(
                        int(sh_addralign) if sh_addralign > 0 else 1
                    ),  # ensure alignment is at least 1.
                    entry_size=int(
                        sh_entsize
                    ),  # size of entries if this section holds a table (e.g., symbol table).
                    # sh_link and sh_info (for section links and extra info) are not directly used by add_auto_section
                    # in a simple way, but could be used if processing symbol/relocation tables here.
                )
            except Exception as sec_add_err:
                self.logger.log_error(
                    f"failed to add section '{section_name}' at vaddr 0x{sh_addr:x} to Binary Ninja: {sec_add_err}\n{traceback.format_exc()}"
                )
        self.logger.log_info("finished mapping ELF sections.")

    def _define_psp_io_registers(self) -> None:
        """
        defines symbols and tags for known psp i/o hardware registers.
        the actual list of registers (`PSP_IO_REGISTERS`) is expected to be
        imported from an external definitions file (e.g., `..defs.psp`).
        """
        self.logger.log_info("defining PSP I/O hardware registers...")
        if not PSP_IO_REGISTERS:  # check if the imported list is populated.
            self.logger.log_info(
                "  PSP_IO_REGISTERS list is empty. No PSP-specific I/O registers will be defined at this time."
            )
            return

        defined_count = 0
        for addr, name, tag_name, desc in PSP_IO_REGISTERS:
            self.logger.log_debug(
                f"  defining I/O register: {name} at 0x{addr:08x} (Category: {tag_name})"
            )
            self._define_hardware_register(addr, name, tag_name, desc)
            defined_count += 1
        self.logger.log_info(
            f"defined {defined_count}/{len(PSP_IO_REGISTERS)} PSP I/O registers from the provided list."
        )

    def _define_elf_entry_point(self) -> None:
        """
        defines the program entry point based on the `e_entry` field from the
        parsed elf header. it adds this address as an entry point to binary ninja
        and defines a `_start` symbol there. actual function creation at this
        address is deferred to binary ninja's analysis passes.
        this method relies on `self.elf_header` being successfully populated.
        """
        if not self.elf_header:
            self.logger.log_error(
                "cannot define ELF entry point, ELF header not parsed or is invalid."
            )
            return

        entry_point_addr = self.elf_header.e_entry
        self.logger.log_info(
            f"defining program entry point at 0x{entry_point_addr:08x} as specified in ELF header."
        )

        # validate the entry point address before adding it.
        # check if it falls within a mapped and executable segment.
        segment_at_entry = self.get_segment_at(entry_point_addr)
        if segment_at_entry:
            self.logger.log_debug(
                f"  entry point 0x{entry_point_addr:08x} is within segment: "
                f"Start=0x{segment_at_entry.start:08x}, Length=0x{segment_at_entry.length:x}, Executable={segment_at_entry.executable}."
            )
            if segment_at_entry.executable:
                # use the binary ninja api to officially add this as an entry point.
                self.add_entry_point(entry_point_addr)
                # store this address for perform_get_entry_point() to return.
                self._primary_entry_point_address = entry_point_addr
                # define a standard symbol for the entry point, e.g., "_start".
                # use proper case for standard symbol names if convention dictates (e.g., _start for c-style entry).
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, entry_point_addr, "_start")
                )
                # attempt to define a function at the entry point to give analysis a hint.
                try:
                    self.add_function(entry_point_addr)
                    self.logger.log_info(
                        f"  successfully added entry point and function hint for '_start' at 0x{entry_point_addr:08x}."
                    )
                except Exception as func_add_err:
                    # log a warning if function definition fails, but the entry point and symbol are still set.
                    self.logger.log_warn(
                        f"  could not define function hint at entry point 0x{entry_point_addr:08x}: {func_add_err}. "
                        "Entry point and symbol were still added; analysis will proceed."
                    )
            else:  # segment containing entry point exists but is not marked executable.
                self.logger.log_warn(
                    f"  entry point 0x{entry_point_addr:08x} is within a non-executable segment. "
                    "Defining as a data symbol '_entry_point_data' instead of function '_start'. "
                    "Analysis may not proceed as expected from this entry point."
                )
                self.define_auto_symbol(
                    Symbol(SymbolType.DataSymbol, entry_point_addr, "_entry_point_data")
                )
        else:  # no segment contains the entry point address.
            self.logger.log_error(
                f"  entry point 0x{entry_point_addr:08x} from ELF header is not within any mapped memory segment. "
                "Cannot set entry point or define symbol effectively. This usually indicates an issue with ELF segments or memory mapping."
            )

    # - main initialization logic
    def init(self) -> bool:
        """
        initializes the PSPView. this is the main setup method called by Binary Ninja
        after `is_valid_for_data` returns true. it orchestrates the entire loading process:
        1.  parses the ELF header.
        2.  initializes PSP-specific tag types for UI categorization.
        3.  maps fixed PSP hardware memory regions (RAM, VRAM, I/O, etc.).
        4.  maps loadable segments defined in the ELF program header table.
        5.  defines sections based on the ELF section header table for semantic information.
        6.  defines known PSP I/O hardware registers.
        7.  defines the program entry point from the ELF header.

        returns:
            true if all initialization steps complete successfully and the view is ready for analysis,
            false otherwise, indicating a failure to Binary Ninja.
        """
        # platform and architecture should have been validated and set in __init__.
        # if they are not set, __init__ would have raised an error, preventing init from being called.
        if not self.arch or not self.platform:
            self.logger.log_error(
                "critical: architecture or platform is not set. cannot initialize PSPView. This indicates an issue in __init__."
            )
            return (
                False  # this should not happen if __init__ completed without raising.
            )

        try:
            self.logger.log_info(
                f"starting PSP ELF loading process for '{self.file.filename}'..."
            )

            # step 1: parse the elf header. this is fundamental for understanding the file structure.
            if not self._parse_elf_header():
                self.logger.log_error(
                    "failed to parse ELF header. aborting PSPView initialization."
                )
                return False  # cannot proceed without a valid elf header.

            # step 2: define psp-specific tag types for categorizing elements in the ui.
            self._initialize_tag_types()

            # step 3: map fixed psp hardware memory regions (ram, vram, i/o blocks, boot rom alias).
            # this establishes the base memory layout of the psp system.
            self._map_psp_hardware_memory_regions()

            # step 4: map loadable segments (pt_load) from the elf program header table.
            # these are the actual code and initialized data segments from the elf file.
            self._map_elf_loadable_segments()

            # step 5: define sections based on the elf section header table.
            # this provides semantic meaning (e.g., .text, .data, .bss) to the mapped memory regions.
            self._map_elf_sections()

            # step 6: define known psp i/o hardware registers as symbols with tags.
            self._define_psp_io_registers()

            # step 7: define the program entry point from the elf header.
            self._define_elf_entry_point()

            # note: self.update_analysis_and_wait() is not called here.
            # binary ninja's core will handle triggering the analysis passes after the loader's init() returns true.
            # this is preferred to avoid potential ui thread blocking issues.
            self.logger.log_info(
                "PSP ELF loading and setup steps complete. View is ready for analysis by Binary Ninja."
            )
            return True  # initialization successful

        except Exception as e:
            # catch any unexpected errors during the entire initialization process.
            self.logger.log_error(
                f"a critical failure occurred during PSPView initialization: {e}\n{traceback.format_exc()}"
            )
            return False  # indicate failure to binary ninja.

    # - required binaryview method overrides
    # these methods are part of the BinaryView plugin interface and must be implemented.

    def perform_is_executable(self) -> bool:
        """
        indicates that psp elf files typically contain executable code.
        """
        self.logger.log_debug(
            "perform_is_executable called, returning true for PSP ELF."
        )
        return True

    def perform_get_entry_point(self) -> int:
        """
        returns the primary entry point address of the psp elf.
        this value is typically read from the elf header's `e_entry` field
        and stored in `self._primary_entry_point_address` during initialization.
        this method is called by the binary ninja core after `init()` completes successfully.
        """
        if self._primary_entry_point_address is not None:
            self.logger.log_debug(
                f"perform_get_entry_point: returning stored primary entry point 0x{self._primary_entry_point_address:08x}."
            )
            return self._primary_entry_point_address
        elif (
            self.elf_header
        ):  # fallback if _primary_entry_point_address wasn't set but header was parsed (e.g., entry point validation failed)
            self.logger.log_warn(
                "[PSP] perform_get_entry_point: _primary_entry_point_address was not set during init. "
                f"Falling back to e_entry directly from parsed ELF header (0x{self.elf_header.e_entry:08x})."
            )
            return self.elf_header.e_entry
        else:
            # this case should ideally not be reached if init succeeded.
            # it indicates an issue in the loader's internal logic or a very early failure before header parsing.
            default_entry = self.start if self.start is not None else 0
            self.logger.log_error(
                "[PSP] perform_get_entry_point called but no entry point was stored during initialization and ELF header is not available. "
                f"Returning start of view (0x{default_entry:08x}) as a last resort. Analysis may be incorrect or start at an unexpected location."
            )
            return default_entry  # absolute last resort.

    def perform_get_address_size(self) -> int:
        """
        returns the address size for the psp platform, which is 4 bytes (32-bit addresses).
        """
        self.logger.log_debug(
            "perform_get_address_size called, returning 4 (for 32-bit addresses)."
        )
        return 4


# register the PSPView class with Binary Ninja so it can be used to open PSP ELF files.
PSPView.register()
