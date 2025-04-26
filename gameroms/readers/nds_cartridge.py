# reads and parses nintendo ds rom file structures.
# includes header, overlay tables, fat, and fnt parsing.

from dataclasses import dataclass
import struct
from typing import List, Optional, Dict

# --- dataclasses for nds rom structures ---


@dataclass
class NDSCartridgeHeader:
    """Represents the parsed NDS cartridge header (first 0x200 bytes)."""

    game_title: str = ""
    gamecode: str = ""
    makercode: str = ""
    unitcode: int = 0
    encryption_seed_select: int = 0
    devicecapacity: int = 0
    reserved1: bytes = b"\x00" * 9
    nds_region: int = 0
    rom_version: int = 0
    autostart: int = 0
    arm9_rom_offset: int = 0
    arm9_entry_address: int = 0
    arm9_ram_address: int = 0
    arm9_size: int = 0
    arm7_rom_offset: int = 0
    arm7_entry_address: int = 0
    arm7_ram_address: int = 0
    arm7_size: int = 0
    fnt_offset: int = 0
    fnt_size: int = 0
    fat_offset: int = 0
    fat_size: int = 0
    arm9_overlay_offset: int = 0
    arm9_overlay_size: int = 0
    arm7_overlay_offset: int = 0
    arm7_overlay_size: int = 0
    port_40001a4_normal: int = 0
    port_40001a4_key1: int = 0
    icon_title_offset: int = 0
    secure_area_checksum: int = 0
    secure_area_delay: int = 0
    arm9_auto_load_list_ram_address: int = 0
    arm7_auto_load_list_ram_address: int = 0
    secure_area_disable: bytes = b"\x00" * 8
    total_used_rom_size: int = 0
    rom_header_size: int = 0
    reserved_88h: int = 0
    reserved_8ch: bytes = b"\x00" * 8
    nand_end_rom_area: int = 0
    nand_start_rw_area: int = 0
    reserved_98h: bytes = b"\x00" * 0x18
    reserved_b0h: bytes = b"\x00" * 0x10
    nintendo_logo: bytes = b"\x00" * 0x9C
    nintendo_logo_checksum: int = 0
    header_checksum: int = 0
    debug_rom_offset: int = 0
    debug_size: int = 0
    debug_ram_address: int = 0
    reserved_debug: bytes = b"\x00" * 4
    reserved_170h: bytes = b"\x00" * 0x90


@dataclass
class NDSOverlayEntry:
    """Represents an entry in the ARM9 or ARM7 Overlay Table."""

    overlay_id: int = 0
    ram_address: int = 0
    ram_size: int = 0
    bss_size: int = 0
    static_initializer_start_address: int = 0
    static_initializer_end_address: int = 0
    file_id: int = 0
    reserved: int = 0


@dataclass
class NDSOverlayTable:
    """Contains a list of overlay entries."""

    entries: List[NDSOverlayEntry]


@dataclass
class NDSFatEntry:
    """Represents an entry in the File Allocation Table."""

    start_address: int = 0
    end_address: int = 0


@dataclass
class FNTDirectoryEntry:
    """Represents a directory entry in the main File Name Table."""

    sub_table_offset: int = 0
    first_file_id: int = 0
    parent_directory_id: Optional[int] = None  # Root has None


@dataclass
class FNTSubEntry:
    """Represents a file or subdirectory entry within an FNT sub-table."""

    name: str = ""
    is_directory: bool = False
    # Only valid if is_directory is True, otherwise file_id is sequential from parent's first_file_id
    directory_id: Optional[int] = None


@dataclass
class FNTFileSystem:
    """Represents the parsed File Name Table structure."""

    # Maps directory ID (0xF000 + index) to its main table entry
    main_table: Dict[int, FNTDirectoryEntry]
    # Maps directory ID to a list of its sub-entries (files/subdirs)
    sub_tables: Dict[int, List[FNTSubEntry]]


@dataclass
class NDSRom:
    """Represents the fully parsed NDS ROM data."""

    header: NDSCartridgeHeader
    arm9_overlay_table: Optional[NDSOverlayTable]  # Can be None if size is 0
    arm7_overlay_table: Optional[NDSOverlayTable]  # Can be None if size is 0
    fat_entries: List[NDSFatEntry]
    file_system: Optional[FNTFileSystem]  # Can be None if size is 0
    # We don't store the full rom_data here anymore to save memory in Binja view
    # The BinaryView will read directly from the parent view (self.raw)


# --- nds rom reader class ---


class NDSRomReader:
    """Provides static methods to read and parse NDS ROM data."""

    @staticmethod
    def read(rom_data: bytes) -> Optional[NDSRom]:
        """
        reads the complete nds rom structure from byte data.
        returns an ndsrom object or none on critical failure.
        """
        try:
            header = NDSRomReader._read_cartridge_header(rom_data)
            if not header:  # Check if header parsing failed
                return None

            arm9_ovt = NDSRomReader._read_overlay_table(
                rom_data, header.arm9_overlay_offset, header.arm9_overlay_size
            )
            arm7_ovt = NDSRomReader._read_overlay_table(
                rom_data, header.arm7_overlay_offset, header.arm7_overlay_size
            )
            fat = NDSRomReader._parse_fat(rom_data, header.fat_offset, header.fat_size)
            fnt = NDSRomReader._parse_fnt(rom_data, header.fnt_offset, header.fnt_size)

            return NDSRom(
                header=header,
                arm9_overlay_table=arm9_ovt,
                arm7_overlay_table=arm7_ovt,
                fat_entries=fat,
                file_system=fnt,
            )
        except Exception as e:
            # Use log_error if available, otherwise print
            log_func = globals().get("log_error", print)
            log_func(f"[NDSRomReader] Error during ROM parsing: {e}")
            log_func(traceback.format_exc())
            return None

    @staticmethod
    def _read_cartridge_header(rom_data: bytes) -> Optional[NDSCartridgeHeader]:
        """parses the 512-byte nds cartridge header."""
        if len(rom_data) < 0x200:
            log_func = globals().get("log_error", print)
            log_func("[NDSRomReader] ROM data too short for header.")
            return None
        header_data = rom_data[:0x200]

        try:
            # unpack fields based on ds_cartridge_header.txt
            header = NDSCartridgeHeader(
                game_title=header_data[:12]
                .decode("ascii", errors="replace")
                .rstrip("\x00"),
                gamecode=header_data[0xC:0x10].decode("ascii", errors="replace"),
                makercode=header_data[0x10:0x12].decode("ascii", errors="replace"),
                unitcode=header_data[0x12],
                encryption_seed_select=header_data[0x13],
                devicecapacity=header_data[0x14],
                reserved1=header_data[0x15:0x1D],  # Size is 8 bytes (0x1D - 0x15)
                nds_region=header_data[0x1D],
                rom_version=header_data[0x1E],
                autostart=header_data[0x1F],
                arm9_rom_offset=struct.unpack_from("<I", header_data, 0x20)[0],
                arm9_entry_address=struct.unpack_from("<I", header_data, 0x24)[0],
                arm9_ram_address=struct.unpack_from("<I", header_data, 0x28)[0],
                arm9_size=struct.unpack_from("<I", header_data, 0x2C)[0],
                arm7_rom_offset=struct.unpack_from("<I", header_data, 0x30)[0],
                arm7_entry_address=struct.unpack_from("<I", header_data, 0x34)[0],
                arm7_ram_address=struct.unpack_from("<I", header_data, 0x38)[0],
                arm7_size=struct.unpack_from("<I", header_data, 0x3C)[0],
                fnt_offset=struct.unpack_from("<I", header_data, 0x40)[0],
                fnt_size=struct.unpack_from("<I", header_data, 0x44)[0],
                fat_offset=struct.unpack_from("<I", header_data, 0x48)[0],
                fat_size=struct.unpack_from("<I", header_data, 0x4C)[0],
                arm9_overlay_offset=struct.unpack_from("<I", header_data, 0x50)[0],
                arm9_overlay_size=struct.unpack_from("<I", header_data, 0x54)[0],
                arm7_overlay_offset=struct.unpack_from("<I", header_data, 0x58)[0],
                arm7_overlay_size=struct.unpack_from("<I", header_data, 0x5C)[0],
                port_40001a4_normal=struct.unpack_from("<I", header_data, 0x60)[0],
                port_40001a4_key1=struct.unpack_from("<I", header_data, 0x64)[0],
                icon_title_offset=struct.unpack_from("<I", header_data, 0x68)[0],
                secure_area_checksum=struct.unpack_from("<H", header_data, 0x6C)[0],
                secure_area_delay=struct.unpack_from("<H", header_data, 0x6E)[0],
                arm9_auto_load_list_ram_address=struct.unpack_from(
                    "<I", header_data, 0x70
                )[0],
                arm7_auto_load_list_ram_address=struct.unpack_from(
                    "<I", header_data, 0x74
                )[0],
                secure_area_disable=header_data[0x78:0x80],
                total_used_rom_size=struct.unpack_from("<I", header_data, 0x80)[0],
                rom_header_size=struct.unpack_from("<I", header_data, 0x84)[0],
                reserved_88h=struct.unpack_from("<I", header_data, 0x88)[
                    0
                ],  # Unknown field
                reserved_8ch=header_data[0x8C:0x94],  # 8 bytes reserved
                nand_end_rom_area=struct.unpack_from("<H", header_data, 0x94)[0],
                nand_start_rw_area=struct.unpack_from("<H", header_data, 0x96)[0],
                reserved_98h=header_data[0x98:0xB0],  # 0x18 bytes reserved
                reserved_b0h=header_data[0xB0:0xC0],  # 0x10 bytes reserved
                nintendo_logo=header_data[0xC0:0x15C],
                nintendo_logo_checksum=struct.unpack_from("<H", header_data, 0x15C)[0],
                header_checksum=struct.unpack_from("<H", header_data, 0x15E)[0],
                debug_rom_offset=struct.unpack_from("<I", header_data, 0x160)[0],
                debug_size=struct.unpack_from("<I", header_data, 0x164)[0],
                debug_ram_address=struct.unpack_from("<I", header_data, 0x168)[0],
                reserved_debug=header_data[0x16C:0x170],  # 4 bytes reserved
                reserved_170h=header_data[0x170:0x200],  # 0x90 bytes reserved
            )
            return header
        except struct.error as e:
            log_func = globals().get("log_error", print)
            log_func(f"[NDSRomReader] Failed to unpack header: {e}")
            return None
        except Exception as e:
            log_func = globals().get("log_error", print)
            log_func(f"[NDSRomReader] Unexpected error reading header: {e}")
            return None

    @staticmethod
    def _read_overlay_table(
        rom_data: bytes, offset: int, size: int
    ) -> Optional[NDSOverlayTable]:
        """reads an arm9 or arm7 overlay table."""
        if offset == 0 or size == 0:
            return None  # no overlay table present
        if offset + size > len(rom_data):
            log_func = globals().get("log_error", print)
            log_func(
                f"[NDSRomReader] Overlay table offset/size out of bounds (offset=0x{offset:x}, size=0x{size:x}, rom_size=0x{len(rom_data):x})"
            )
            return None

        entries = []
        overlay_data = rom_data[offset : offset + size]
        entry_size = 32  # Each entry is 32 bytes

        if len(overlay_data) % entry_size != 0:
            log_func = globals().get("log_warn", print)
            log_func(
                f"[NDSRomReader] Overlay table size (0x{size:x}) not a multiple of entry size ({entry_size}). Table might be truncated."
            )

        try:
            for i in range(0, len(overlay_data) // entry_size * entry_size, entry_size):
                entry = NDSOverlayEntry(
                    overlay_id=struct.unpack_from("<I", overlay_data, i)[0],
                    ram_address=struct.unpack_from("<I", overlay_data, i + 4)[0],
                    ram_size=struct.unpack_from("<I", overlay_data, i + 8)[0],
                    bss_size=struct.unpack_from("<I", overlay_data, i + 12)[0],
                    static_initializer_start_address=struct.unpack_from(
                        "<I", overlay_data, i + 16
                    )[0],
                    static_initializer_end_address=struct.unpack_from(
                        "<I", overlay_data, i + 20
                    )[0],
                    file_id=struct.unpack_from("<I", overlay_data, i + 24)[0],
                    reserved=struct.unpack_from("<I", overlay_data, i + 28)[0],
                )
                entries.append(entry)
            return NDSOverlayTable(entries)
        except struct.error as e:
            log_func = globals().get("log_error", print)
            log_func(f"[NDSRomReader] Failed to unpack overlay entry: {e}")
            return None  # Return None or partial table? Returning None for now.
        except Exception as e:
            log_func = globals().get("log_error", print)
            log_func(f"[NDSRomReader] Unexpected error reading overlay table: {e}")
            return None

    @staticmethod
    def _parse_fat(
        rom_data: bytes, fat_offset: int, fat_size: int
    ) -> List[NDSFatEntry]:
        """parses the file allocation table."""
        if fat_offset == 0 or fat_size == 0:
            return []
        if fat_offset + fat_size > len(rom_data):
            log_func = globals().get("log_error", print)
            log_func(
                f"[NDSRomReader] FAT offset/size out of bounds (offset=0x{fat_offset:x}, size=0x{fat_size:x}, rom_size=0x{len(rom_data):x})"
            )
            return []

        fat_entries = []
        fat_data = rom_data[fat_offset : fat_offset + fat_size]
        entry_size = 8  # Each entry is 8 bytes

        if len(fat_data) % entry_size != 0:
            log_func = globals().get("log_warn", print)
            log_func(
                f"[NDSRomReader] FAT size (0x{fat_size:x}) not a multiple of entry size ({entry_size}). Table might be truncated."
            )

        try:
            for i in range(0, len(fat_data) // entry_size * entry_size, entry_size):
                start_address = struct.unpack_from("<I", fat_data, i)[0]
                end_address = struct.unpack_from("<I", fat_data, i + 4)[0]
                # FAT entries can be all zero for unused slots, skip them
                # Also check for invalid ranges
                if start_address != 0 or end_address != 0:
                    if end_address < start_address:
                        log_func = globals().get("log_warn", print)
                        log_func(
                            f"[NDSRomReader] Invalid FAT entry {i//entry_size}: end address (0x{end_address:x}) < start address (0x{start_address:x})"
                        )
                        # Add it anyway? Or skip? Skipping for now.
                        continue
                    fat_entries.append(NDSFatEntry(start_address, end_address))
            return fat_entries
        except struct.error as e:
            log_func = globals().get("log_error", print)
            log_func(f"[NDSRomReader] Failed to unpack FAT entry: {e}")
            return fat_entries  # Return potentially partial list
        except Exception as e:
            log_func = globals().get("log_error", print)
            log_func(f"[NDSRomReader] Unexpected error reading FAT: {e}")
            return fat_entries

    @staticmethod
    def _parse_fnt(
        rom_data: bytes, fnt_offset: int, fnt_size: int
    ) -> Optional[FNTFileSystem]:
        """parses the file name table (main table and sub-tables)."""
        if fnt_offset == 0 or fnt_size == 0:
            return None
        if fnt_offset + fnt_size > len(rom_data):
            log_func = globals().get("log_error", print)
            log_func(
                f"[NDSRomReader] FNT offset/size out of bounds (offset=0x{fnt_offset:x}, size=0x{fnt_size:x}, rom_size=0x{len(rom_data):x})"
            )
            return None

        fnt_data = rom_data[fnt_offset : fnt_offset + fnt_size]
        main_table: Dict[int, FNTDirectoryEntry] = {}
        sub_tables: Dict[int, List[FNTSubEntry]] = {}

        try:
            # First entry in FNT is the root directory's sub-table offset
            root_sub_table_offset = struct.unpack_from("<I", fnt_data, 0)[0]
            root_first_file_id = struct.unpack_from("<H", fnt_data, 4)[0]
            total_directories = struct.unpack_from("<H", fnt_data, 6)[
                0
            ]  # This seems to be the number of directories *including* root

            # Add root directory entry (ID 0xF000)
            main_table[0xF000] = FNTDirectoryEntry(
                root_sub_table_offset, root_first_file_id, None
            )

            # Read main table entries for other directories
            # The main table starts at fnt_offset, each entry is 8 bytes
            # There are 'total_directories' entries in total (including root)
            main_table_size = total_directories * 8
            if main_table_size > fnt_size:
                log_func = globals().get("log_error", print)
                log_func(
                    f"[NDSRomReader] FNT main table size ({main_table_size}) exceeds total FNT size ({fnt_size})."
                )
                return None  # Cannot proceed

            for i in range(1, total_directories):  # Start from 1 to skip root
                offset = i * 8
                sub_table_offset = struct.unpack_from("<I", fnt_data, offset)[0]
                first_file_id = struct.unpack_from("<H", fnt_data, offset + 4)[0]
                parent_directory_id = struct.unpack_from("<H", fnt_data, offset + 6)[
                    0
                ]  # Parent ID includes 0xF000 base
                dir_id = 0xF000 + i
                main_table[dir_id] = FNTDirectoryEntry(
                    sub_table_offset, first_file_id, parent_directory_id
                )

            # Parse sub-tables for each directory
            for dir_id, dir_entry in main_table.items():
                sub_tables[dir_id] = NDSRomReader._parse_fnt_sub_table(
                    fnt_data, dir_entry.sub_table_offset
                )

            return FNTFileSystem(main_table=main_table, sub_tables=sub_tables)

        except struct.error as e:
            log_func = globals().get("log_error", print)
            log_func(f"[NDSRomReader] Failed to unpack FNT entry: {e}")
            return None
        except Exception as e:
            log_func = globals().get("log_error", print)
            log_func(f"[NDSRomReader] Unexpected error reading FNT: {e}")
            return None

    @staticmethod
    def _parse_fnt_sub_table(
        fnt_data: bytes, sub_table_offset: int
    ) -> List[FNTSubEntry]:
        """parses a single fnt sub-table containing file and subdirectory entries."""
        entries = []
        offset = sub_table_offset

        while True:
            # Check bounds before reading type_length
            if offset >= len(fnt_data):
                log_func = globals().get("log_error", print)
                log_func(
                    f"[NDSRomReader] FNT sub-table offset 0x{offset:x} exceeds FNT data size 0x{len(fnt_data):x}."
                )
                break  # Stop parsing this sub-table

            type_length = fnt_data[offset]
            if type_length == 0:  # End of sub-table marker
                break
            if (
                type_length == 0xFF
            ):  # Seems to indicate end in some cases? GBATEK doesn't mention.
                log_func = globals().get("log_warn", print)
                log_func(
                    f"[NDSRomReader] Encountered 0xFF marker in FNT sub-table at offset 0x{offset:x}. Stopping parse."
                )
                break

            is_directory = (type_length & 0x80) != 0
            name_length = type_length & 0x7F

            name_start = offset + 1
            name_end = name_start + name_length

            # Check bounds for name
            if name_end > len(fnt_data):
                log_func = globals().get("log_error", print)
                log_func(
                    f"[NDSRomReader] FNT entry name length ({name_length}) exceeds FNT data bounds at offset 0x{name_start:x}."
                )
                break

            try:
                name = fnt_data[name_start:name_end].decode("ascii", errors="replace")
            except UnicodeDecodeError:
                name = f"invalid_name_at_{name_start:x}"
                log_func = globals().get("log_warn", print)
                log_func(
                    f"[NDSRomReader] Failed to decode FNT entry name at offset 0x{name_start:x}."
                )

            offset = name_end  # Move offset past the name

            if is_directory:
                # Check bounds for directory ID
                if offset + 2 > len(fnt_data):
                    log_func = globals().get("log_error", print)
                    log_func(
                        f"[NDSRomReader] FNT directory entry missing ID at offset 0x{offset:x}."
                    )
                    break
                directory_id = struct.unpack_from("<H", fnt_data, offset)[0]
                offset += 2
                entries.append(FNTSubEntry(name, True, directory_id))
            else:
                # File entry, directory_id is None
                entries.append(FNTSubEntry(name, False, None))

        return entries

    @staticmethod
    def is_valid(rom_data: bytes) -> bool:
        """
        performs basic header validation including crc checks.
        returns true if checks pass, false otherwise.
        """
        if len(rom_data) < 0x160:
            return False

        header_data = rom_data[:0x160]

        # check header crc
        header_crc = struct.unpack_from("<H", header_data, 0x15E)[0]
        calculated_header_crc = NDSRomReader._crc16(header_data[:0x15E])
        if header_crc != calculated_header_crc:
            # Use log_warn if available, otherwise print
            log_func = globals().get("log_warn", print)
            log_func(
                f"[NDSRomReader] Header CRC mismatch! Expected 0x{calculated_header_crc:04X}, got 0x{header_crc:04X}."
            )
            # return False # Optionally make CRC failure fatal

        # check nintendo logo crc (often called secure area crc in docs)
        logo_crc = struct.unpack_from("<H", header_data, 0x15C)[0]
        # standard logo crc is fixed
        if logo_crc != 0xCF56:
            log_func = globals().get("log_warn", print)
            log_func(
                f"[NDSRomReader] Nintendo Logo CRC mismatch! Expected 0xCF56, got 0x{logo_crc:04X}."
            )
            # return False # Optionally make CRC failure fatal

        # could add secure area checksum check here if needed (header[0x6c])
        # secure_checksum = struct.unpack_from("<H", header_data, 0x6C)[0]
        # ... calculate expected checksum based on secure area data ...
        # if secure_checksum != calculated_secure_checksum:
        #     log_warn("[NDSRomReader] Secure Area checksum mismatch!")
        #     # return False

        return True  # Return True even if CRCs fail, but log warnings

    @staticmethod
    def _crc16(data: bytes) -> int:
        """calculates the crc-16 used in nds headers."""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001  # Polynomial for CRC-16-CCITT
                else:
                    crc >>= 1
        return crc


# --- nds rom printer class (for debugging) ---


class NDSRomPrinter:
    """Provides static methods to print parsed NDS ROM information."""

    @staticmethod
    def print_rom_info(nds_rom: Optional[NDSRom]):
        """prints a summary of the parsed nds rom data."""
        if not nds_rom:
            print("NDS ROM data is None, cannot print info.")
            return

        print("\n" + "=" * 40)
        NDSRomPrinter._print_header(nds_rom.header)
        NDSRomPrinter._print_fat(nds_rom.fat_entries)
        NDSRomPrinter._print_file_system(
            nds_rom.file_system, nds_rom.header.fnt_offset
        )  # Pass FNT offset
        NDSRomPrinter._print_overlay_tables(
            nds_rom.arm9_overlay_table, nds_rom.arm7_overlay_table
        )

        # validation check result (re-run for clarity, though done during parsing)
        # is_valid = NDSRomReader.is_valid(nds_rom.rom_data) # Need rom_data for this
        # if is_valid:
        #     print("\nROM header validation checks passed.")
        # else:
        #     print("\nROM header validation checks failed (see warnings above).")
        print("\n" + "=" * 40)

    @staticmethod
    def _print_header(header: Optional[NDSCartridgeHeader]):
        """prints the parsed header information."""
        if not header:
            print("Header: Not available")
            return

        print("NDS ROM Header Information:")
        print("===========================")
        print(f"Game Title: {header.game_title}")
        print(f"Game Code: {header.gamecode}")
        print(f"Maker Code: {header.makercode}")
        print(f"Unit Code: {header.unitcode:02X}h")
        print(f"Encryption Seed Select: {header.encryption_seed_select:02X}h")
        print(
            f"Device Capacity: {header.devicecapacity:02X}h ({(128 * (1 << header.devicecapacity)) // 1024} KB)"
        )
        print(f"NDS Region: {header.nds_region:02X}h")
        print(f"ROM Version: {header.rom_version:02X}h")
        print(f"Autostart: {header.autostart:02X}h")

        print("\nARM9:")
        print(f"  ROM Offset: 0x{header.arm9_rom_offset:08X}")
        print(f"  Entry Address: 0x{header.arm9_entry_address:08X}")
        print(f"  RAM Address: 0x{header.arm9_ram_address:08X}")
        print(f"  Size: 0x{header.arm9_size:08X}")
        print(
            f"  BSS Size: 0x{getattr(header, 'arm9_bss_size', 0):08X}"
        )  # Assuming bss size is added

        print("\nARM7:")
        print(f"  ROM Offset: 0x{header.arm7_rom_offset:08X}")
        print(f"  Entry Address: 0x{header.arm7_entry_address:08X}")
        print(f"  RAM Address: 0x{header.arm7_ram_address:08X}")
        print(f"  Size: 0x{header.arm7_size:08X}")
        print(
            f"  BSS Size: 0x{getattr(header, 'arm7_bss_size', 0):08X}"
        )  # Assuming bss size is added

        print("\nFile Tables:")
        print(f"  FNT Offset: 0x{header.fnt_offset:08X}")
        print(f"  FNT Size: 0x{header.fnt_size:08X}")
        print(f"  FAT Offset: 0x{header.fat_offset:08X}")
        print(f"  FAT Size: 0x{header.fat_size:08X}")

        print("\nOverlay Tables:")
        print(f"  ARM9 Overlay Offset: 0x{header.arm9_overlay_offset:08X}")
        print(f"  ARM9 Overlay Size: 0x{header.arm9_overlay_size:08X}")
        print(f"  ARM7 Overlay Offset: 0x{header.arm7_overlay_offset:08X}")
        print(f"  ARM7 Overlay Size: 0x{header.arm7_overlay_size:08X}")

        print("\nPort 40001A4h Settings:")
        print(f"  Normal: 0x{header.port_40001a4_normal:08X}")
        print(f"  KEY1: 0x{header.port_40001a4_key1:08X}")

        print(f"\nIcon/Title Offset: 0x{header.icon_title_offset:08X}")
        print(f"Secure Area Checksum: 0x{header.secure_area_checksum:04X}")
        print(f"Secure Area Delay: 0x{header.secure_area_delay:04X}")

        print("\nAuto Load List RAM Addresses:")
        print(f"  ARM9: 0x{header.arm9_auto_load_list_ram_address:08X}")
        print(f"  ARM7: 0x{header.arm7_auto_load_list_ram_address:08X}")

        print(f"\nSecure Area Disable: {header.secure_area_disable.hex()}")
        print(f"Total Used ROM Size: 0x{header.total_used_rom_size:08X}")
        print(f"ROM Header Size: 0x{header.rom_header_size:08X}")

        print(f"\nNintendo Logo Checksum: 0x{header.nintendo_logo_checksum:04X}")
        print(f"Header Checksum: 0x{header.header_checksum:04X}")

        print("\nDebug Info:")
        print(f"  ROM Offset: 0x{header.debug_rom_offset:08X}")
        print(f"  Size: 0x{header.debug_size:08X}")
        print(f"  RAM Address: 0x{header.debug_ram_address:08X}")

    @staticmethod
    def _print_fat(fat_entries: List[NDSFatEntry]):
        """prints the parsed file allocation table."""
        print("\nFile Allocation Table (FAT):")
        if not fat_entries:
            print("  (Empty)")
            return
        for i, entry in enumerate(fat_entries):
            print(
                f"  File {i:04X}: Start: 0x{entry.start_address:08X}, End: 0x{entry.end_address:08X} (Size: {entry.end_address - entry.start_address})"
            )

    @staticmethod
    def _print_file_system(file_system: Optional[FNTFileSystem], fnt_offset: int):
        """prints the parsed file name table structure recursively."""
        print("\nFile Name Table (FNT):")
        if not file_system or not file_system.main_table:
            print("  (Empty or Not Parsed)")
            return
        # Start printing from the root directory (ID 0xF000)
        NDSRomPrinter._print_directory(file_system, 0xF000)

    @staticmethod
    def _print_directory(file_system: FNTFileSystem, dir_id: int, indent: str = ""):
        """helper to recursively print directory contents."""
        if dir_id not in file_system.main_table:
            print(f"{indent}Error: Directory ID {dir_id:04X} not found in main table.")
            return

        # Print directory ID (optional, can be verbose)
        # print(f"{indent}Directory ID: {dir_id:04X}")

        if dir_id not in file_system.sub_tables:
            print(f"{indent}  (Error: Sub-table not found for Dir ID {dir_id:04X})")
            return

        sub_table = file_system.sub_tables[dir_id]
        for entry in sub_table:
            if entry.is_directory:
                print(f"{indent}  [{entry.name}]")
                # Recursive call for subdirectory
                NDSRomPrinter._print_directory(
                    file_system, entry.directory_id, indent + "    "
                )
            else:
                print(f"{indent}  {entry.name}")

    @staticmethod
    def _print_overlay_tables(
        arm9_ovt: Optional[NDSOverlayTable], arm7_ovt: Optional[NDSOverlayTable]
    ):
        """prints both arm9 and arm7 overlay tables."""
        NDSRomPrinter._print_overlay_table("ARM9", arm9_ovt)
        NDSRomPrinter._print_overlay_table("ARM7", arm7_ovt)

    @staticmethod
    def _print_overlay_table(name: str, ovt: Optional[NDSOverlayTable]):
        """prints a single overlay table."""
        print(f"\n{name} Overlay Table:")
        print("=" * (len(name) + 15))
        if not ovt or not ovt.entries:
            print("  (Empty or Not Present)")
            return

        for i, entry in enumerate(ovt.entries):
            print(f"Overlay {i} (ID: {entry.overlay_id}):")  # Include Overlay ID
            print(f"  File ID: {entry.file_id}")
            print(f"  RAM Address: 0x{entry.ram_address:08X}")
            print(f"  RAM Size: 0x{entry.ram_size:08X}")
            print(f"  BSS Size: 0x{entry.bss_size:08X}")
            print(
                f"  Static Init Start: 0x{entry.static_initializer_start_address:08X}"
            )
            print(f"  Static Init End: 0x{entry.static_initializer_end_address:08X}")
            # print(f"  Reserved: 0x{entry.reserved:08X}") # Usually 0, less interesting
            print()


# --- command line execution (for testing the reader) ---


def main():
    """main function for command-line testing."""
    import sys
    import os

    if len(sys.argv) != 2:
        print(f"Usage: python {os.path.basename(__file__)} <path_to_nds_rom>")
        sys.exit(1)

    rom_file = sys.argv[1]
    if not os.path.exists(rom_file):
        print(f"Error: File not found: {rom_file}")
        sys.exit(1)

    print(f"Reading ROM: {rom_file}")
    try:
        with open(rom_file, "rb") as f:
            rom_data = f.read()
    except IOError as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    print("Parsing ROM...")
    nds_rom = NDSRomReader.read(rom_data)

    if nds_rom:
        print("Parsing successful. Printing ROM info...")
        NDSRomPrinter.print_rom_info(nds_rom)
    else:
        print("Failed to parse ROM.")
        sys.exit(1)


if __name__ == "__main__":
    # Add dummy log functions if running standalone for testing
    if "log_info" not in globals():

        def log_info(msg):
            print(f"INFO: {msg}")

        def log_warn(msg):
            print(f"WARN: {msg}")

        def log_error(msg):
            print(f"ERROR: {msg}")

        globals()["log_info"] = log_info
        globals()["log_warn"] = log_warn
        globals()["log_error"] = log_error
    main()
