"""
GBA ROM loader using the refactored base loader architecture.
"""

import struct
import traceback
from typing import Optional, Dict, Tuple, List, cast

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
    GBAHeader,
    GBA_TAG_TYPE_DEFINITIONS,
    GBA_IO_REGISTER_DEFINITIONS,
    GBA_NINTENDO_LOGO_OFFSET,
    GBA_NINTENDO_LOGO_SIZE,
    GBA_GAME_TITLE_OFFSET,
    GBA_GAME_TITLE_SIZE,
    GBA_GAME_CODE_OFFSET,
    GBA_GAME_CODE_SIZE,
    GBA_MAKER_CODE_OFFSET,
    GBA_MAKER_CODE_SIZE,
    GBA_FIXED_VALUE_OFFSET,
    GBA_MAIN_UNIT_CODE_OFFSET,
    GBA_DEVICE_TYPE_OFFSET,
    GBA_SOFTWARE_VERSION_OFFSET,
    GBA_HEADER_CHECKSUM_OFFSET,
    GBA_HEADER_MIN_SIZE,
)


class GBAView(BaseROMLoader):
    """
    BinaryView class for loading and analyzing Game Boy Advance (GBA) ROM files.
    """

    name = "GBA"
    long_name = "Game Boy Advance ROM"

    def __init__(self, data: BinaryView):
        super().__init__(data)
        
        # GBA-specific attributes
        self.rom_size: int = self.raw_data.length
        self.gba_header: Optional[GBAHeader] = None
        self._entry_point_address: Optional[int] = None

    def get_loader_name(self) -> str:
        """Return the name for this loader (used for logging)."""
        return self.name

    def get_tag_type_definitions(self) -> Dict[str, str]:
        """Return dictionary mapping tag type names to icons."""
        return GBA_TAG_TYPE_DEFINITIONS

    def _setup_architecture_and_platform(self) -> None:
        """Set up self.arch and self.platform for GBA ROMs."""
        try:
            self.arch: Optional[Architecture] = Architecture["armv7"]  # type: ignore
            if not self.arch:
                self.logger.log_error(
                    "critical: armv7 architecture definition not found in binary ninja. GBA analysis requires it."
                )
                raise RuntimeError("armv7 architecture definition not found.")

            self.platform: Optional[Platform] = self.arch.standalone_platform
            if not self.platform:
                self.logger.log_error(
                    f"critical: could not get standalone platform for architecture '{self.arch.name}'. GBA analysis cannot proceed."
                )
                raise RuntimeError(f"failed to get standalone platform for {self.arch.name}.")
            
            self.logger.log_info(
                f"successfully set platform: {self.platform.name}, architecture: {self.arch.name}"
            )
        except KeyError:
            self.logger.log_error(
                "critical: armv7 architecture key not found. this architecture is required for gba analysis."
            )
            raise RuntimeError("armv7 architecture key not found.")
        except Exception as e:
            self.logger.log_error(
                f"critical error during architecture or platform setup: {e}\n{traceback.format_exc()}"
            )
            raise

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        Checks if the provided data is likely a GBA ROM.
        This is done by looking for a specific fixed value (0x96) at offset 0xB2 in the header.
        """
        if data.length < GBA_HEADER_MIN_SIZE:
            log_debug(
                f"[{cls.name}] validation: data length {data.length} is less than min header size {GBA_HEADER_MIN_SIZE}. not a gba rom."
            )
            return False

        try:
            magic_byte_data = data.read(GBA_FIXED_VALUE_OFFSET, 1)
            if not magic_byte_data:
                log_debug(
                    f"[{cls.name}] validation: failed to read fixed value byte at offset 0x{GBA_FIXED_VALUE_OFFSET:x}."
                )
                return False

            magic_byte = magic_byte_data[0]
            if magic_byte == 0x96:
                log_info(
                    f"[{cls.name}] validation: found fixed value 0x96 in header at offset 0x{GBA_FIXED_VALUE_OFFSET:x}. identified as gba rom."
                )
                return True
            else:
                log_debug(
                    f"[{cls.name}] validation: fixed value at 0x{GBA_FIXED_VALUE_OFFSET:x} was 0x{magic_byte:02x}, expected 0x96. not a gba rom."
                )
                return False
        except Exception as e:
            log_error(
                f"[{cls.name}] validation: error reading fixed value byte from header: {e}\n{traceback.format_exc()}"
            )
            return False

    def _parse_rom_header(self) -> bool:
        """
        Parses key fields from the GBA ROM header and stores them in self.gba_header.
        """
        self.logger.log_info("parsing gba rom header...")
        if self.rom_size < GBA_HEADER_MIN_SIZE:
            self.logger.log_error(
                f"rom is too small ({self.rom_size} bytes) to contain a valid gba header (min {GBA_HEADER_MIN_SIZE} bytes)."
            )
            return False
        
        try:
            # Read various fields from the ROM header
            title_bytes = self.raw_data.read(GBA_GAME_TITLE_OFFSET, GBA_GAME_TITLE_SIZE)
            game_code_bytes = self.raw_data.read(GBA_GAME_CODE_OFFSET, GBA_GAME_CODE_SIZE)
            maker_code_bytes = self.raw_data.read(GBA_MAKER_CODE_OFFSET, GBA_MAKER_CODE_SIZE)
            software_version_byte = self.raw_data.read(GBA_SOFTWARE_VERSION_OFFSET, 1)

            if not all([title_bytes, game_code_bytes, maker_code_bytes, software_version_byte]):
                self.logger.log_error(
                    "failed to read one or more essential header fields from the rom. header parsing aborted."
                )
                return False

            # Decode bytes to strings
            game_title = title_bytes.decode("ascii", errors="replace").rstrip("\x00")
            game_code = game_code_bytes.decode("ascii", errors="replace").rstrip("\x00")
            maker_code = maker_code_bytes.decode("ascii", errors="replace").rstrip("\x00")
            software_version = software_version_byte[0]

            # Populate the GBA header dataclass
            self.gba_header = GBAHeader(
                game_title=game_title,
                game_code=game_code,
                maker_code=maker_code,
                software_version=software_version,
            )
            
            self.logger.log_info(
                f"parsed header: title='{self.gba_header.game_title}', "
                f"code='{self.gba_header.game_code}', "
                f"maker='{self.gba_header.maker_code}', "
                f"version={self.gba_header.software_version}"
            )
            return True
        except Exception as e:
            self.logger.log_error(
                f"an unexpected error occurred while parsing gba header fields: {e}\n{traceback.format_exc()}"
            )
            self.gba_header = None
            return False

    def _map_memory_regions(self) -> None:
        """Maps the core GBA memory regions using the shared helper method."""
        self.logger.log_info("mapping gba memory regions...")

        # BIOS system ROM (16kb): 0x00000000 - 0x00003FFF
        self._add_memory_segment_with_tag(0x00000000, 0x4000, self.PERM_RX, "BIOS System ROM")

        # WRAM - on-board (slower, 256kb): 0x02000000 - 0x0203FFFF
        self._add_memory_segment_with_tag(0x02000000, 0x40000, self.PERM_RWX, "WRAM - On-board")

        # WRAM - on-chip (faster, 32kb): 0x03000000 - 0x03007FFF
        self._add_memory_segment_with_tag(0x03000000, 0x8000, self.PERM_RWX, "WRAM - On-chip")

        # I/O registers (approx 1kb): 0x04000000 - 0x040003FF
        self._add_memory_segment_with_tag(
            0x04000000, 0x0400, self.PERM_RW, "I/O Registers", tag_name="Hardware Register"
        )

        # Palette RAM (1kb): 0x05000000 - 0x050003FF
        self._add_memory_segment_with_tag(0x05000000, 0x0400, self.PERM_RW, "Palette RAM")

        # VRAM - video RAM (96kb): 0x06000000 - 0x06017FFF
        self._add_memory_segment_with_tag(0x06000000, 0x18000, self.PERM_RW, "VRAM")

        # OAM - object attribute memory (1kb): 0x07000000 - 0x070003FF
        self._add_memory_segment_with_tag(0x07000000, 0x0400, self.PERM_RW, "OAM")

        # Game Pak ROM (up to 32mb): 0x08000000 - 0x09FFFFFF
        rom_map_size = min(self.rom_size, 0x2000000)  # cap at 32mb
        if rom_map_size > 0:
            self._add_memory_segment_with_tag(
                0x08000000, rom_map_size, self.PERM_RX, "Game Pak ROM",
                file_offset=0, file_length=rom_map_size
            )
        else:
            self.logger.log_warn("rom size is zero or negative, skipping game pak rom mapping.")

        # Game Pak SRAM (save ram, up to 64kb): 0x0E000000 - 0x0E00FFFF
        self._add_memory_segment_with_tag(0x0E000000, 0x10000, self.PERM_RW, "Game Pak SRAM")
        
        self.logger.log_info("finished mapping gba memory regions.")

    def _define_memory_sections(self) -> None:
        """Defines sections based on the mapped memory segments."""
        self.logger.log_info("defining memory sections...")
        
        rom_base_address = 0x08000000
        rom_segment = self.get_segment_at(rom_base_address)
        if rom_segment:
            self.logger.log_debug(
                f"attempting to add section '.text' for rom segment at 0x{rom_segment.start:08x}, length 0x{rom_segment.length:x}."
            )
            try:
                self.add_auto_section(
                    name=".text",
                    start=rom_segment.start,
                    length=rom_segment.length,
                    semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                )
                self.logger.log_info("successfully added '.text' section for game pak rom.")
            except Exception as e:
                self.logger.log_error(
                    f"failed to add '.text' section for rom: {e}\n{traceback.format_exc()}"
                )
        else:
            self.logger.log_warn(
                f"could not find rom segment at 0x{rom_base_address:08x} to define a code section."
            )
        
        self.logger.log_info("finished defining memory sections.")

    def _define_all_io_registers(self) -> None:
        """Defines symbols and tags for all known GBA I/O registers."""
        self.logger.log_info("defining gba i/o hardware registers...")
        
        defined_count = 0
        for addr, name, tag_category, desc in GBA_IO_REGISTER_DEFINITIONS:
            self.logger.log_debug(
                f"defining i/o register: {name} at 0x{addr:08x} (Category: {tag_category})"
            )
            self._define_hardware_register(addr, name, tag_category, desc)
            defined_count += 1
        
        self.logger.log_info(
            f"defined {defined_count}/{len(GBA_IO_REGISTER_DEFINITIONS)} i/o hardware registers."
        )

    def _define_rom_entry_point(self) -> None:
        """Defines the primary entry point for GBA ROMs."""
        entry_point_address = 0x08000000  # standard GBA entry point
        self.logger.log_info(f"defining rom entry point at 0x{entry_point_address:08x}.")

        segment_at_entry = self.get_segment_at(entry_point_address)
        if segment_at_entry and segment_at_entry.executable:
            try:
                self.add_entry_point(entry_point_address)
                self._entry_point_address = entry_point_address
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, entry_point_address, "_start")
                )
                self.add_function(entry_point_address)
                self.logger.log_info(
                    f"successfully added entry point and created function '_start' at 0x{entry_point_address:08x}."
                )
            except Exception as e:
                self.logger.log_warn(
                    f"failed to fully define function at entry point 0x{entry_point_address:08x}: {e}."
                )
        else:
            self.logger.log_error(
                f"cannot define entry point at 0x{entry_point_address:08x}. "
                "the address is not within an executable segment or the segment is missing."
            )

    def init(self) -> bool:
        """
        Initializes the GBAView using the refactored architecture.
        """
        if not self.arch or not self.platform:
            self.logger.log_error(
                "critical: architecture or platform is not set. cannot initialize GBAView."
            )
            return False

        try:
            self.logger.log_info(f"starting gba rom loading process for '{self.file.filename}'...")

            # Step 1: Parse the ROM header
            if not self._parse_rom_header():
                self.logger.log_error("failed to parse gba rom header. aborting load process.")
                return False

            # Step 2: Initialize tag types (using inherited method)
            self._initialize_tag_types()

            # Step 3: Map the GBA memory layout
            self._map_memory_regions()

            # Step 4: Define sections
            self._define_memory_sections()

            # Step 5: Define I/O registers
            self._define_all_io_registers()

            # Step 6: Define entry point
            self._define_rom_entry_point()

            self.logger.log_info("gba rom loading and setup steps complete. view is ready for analysis.")
            return True

        except Exception as e:
            self.logger.log_error(
                f"an unexpected error occurred during gba rom initialization: {e}\n{traceback.format_exc()}"
            )
            return False

    def perform_is_executable(self) -> bool:
        """Indicates that GBA ROMs contain executable code."""
        return True

    def perform_get_entry_point(self) -> int:
        """Returns the primary entry point address of the GBA ROM."""
        if self._entry_point_address is not None:
            return self._entry_point_address
        else:
            self.logger.log_error(
                "perform_get_entry_point called but no entry point was stored during initialization."
            )
            return 0x08000000  # standard GBA entry point as fallback

    def perform_get_address_size(self) -> int:
        """Returns the address size for GBA, which is 4 bytes (32-bit addresses)."""
        return 4


# Register the GBAView class with binary ninja
GBAView.register()