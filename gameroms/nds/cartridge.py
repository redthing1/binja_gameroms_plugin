# reads and parses nintendo ds rom file structures.
# includes header, overlay tables, fat, and fnt parsing.

import struct
import traceback  # import traceback for error logging
from dataclasses import dataclass, field  # import field for default_factory
from typing import List, Optional, Dict, TYPE_CHECKING, Tuple  # added tuple

# CRC and validation constants
CRC16_CCITT_POLY = 0x1021  # CRC-16-CCITT polynomial
NINTENDO_LOGO_CRC = 0xCF56  # Standard Nintendo logo CRC

# use binaryninja logging if available, otherwise fallback to print
try:
    from binaryninja import log_error, log_warn, log_info

    # import binaryview only for type hinting if needed, avoid circular dependency
    if TYPE_CHECKING:
        from binaryninja import BinaryView
except ImportError:
    # define dummy log functions if binaryninja is not available (e.g., running standalone)
    def log_info(msg: str):
        print(f"info: {msg}")

    def log_warn(msg: str):
        print(f"warn: {msg}")

    def log_error(msg: str):
        print(f"error: {msg}")

    # define dummy binaryview for type hinting
    if TYPE_CHECKING:

        class BinaryView:
            pass


# --- nitro sdk constants (copied from ndsrom.py for helper function) ---
NITRO_SDK_MODULE_PARAMS_MAGIC = b"\x21\x06\xc0\xde\xde\xc0\x06\x21"
NITRO_SDK_MODULE_PARAMS_SIZE = 36  # size of the moduleparams struct
NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET = 0x1C  # offset of magic within the struct

# --- dataclasses for nds rom structures ---


@dataclass
class NDSCartridgeHeader:
    """represents the parsed nds cartridge header (first 0x200 bytes)."""

    # 0x000 - 0x01F: Basic Info
    game_title: str = ""
    gamecode: str = ""
    makercode: str = ""
    unitcode: int = 0
    encryption_seed_select: int = 0
    devicecapacity: int = 0
    reserved1: bytes = field(
        default_factory=lambda: b"\x00" * 7
    )  # corrected size (0x15-0x1b)
    reserved1c: int = 0  # byte 0x1c
    nds_region: int = 0
    rom_version: int = 0
    autostart: int = 0
    # 0x020 - 0x03F: ARM9 Info
    arm9_rom_offset: int = 0
    arm9_entry_address: int = 0
    arm9_ram_address: int = 0
    arm9_size: int = 0
    # 0x030 - 0x03F: ARM7 Info
    arm7_rom_offset: int = 0
    arm7_entry_address: int = 0
    arm7_ram_address: int = 0
    arm7_size: int = 0
    # 0x040 - 0x05F: File Table Info
    fnt_offset: int = 0
    fnt_size: int = 0
    fat_offset: int = 0
    fat_size: int = 0
    arm9_overlay_offset: int = 0
    arm9_overlay_size: int = 0
    arm7_overlay_offset: int = 0
    arm7_overlay_size: int = 0
    # 0x060 - 0x07F: Misc Settings & Secure Area
    port_40001a4_normal: int = 0
    port_40001a4_key1: int = 0
    icon_title_offset: int = 0
    secure_area_checksum: int = 0
    secure_area_delay: int = 0
    arm9_auto_load_list_ram_address: int = 0
    arm7_auto_load_list_ram_address: int = 0
    secure_area_disable: bytes = field(default_factory=lambda: b"\x00" * 8)
    # 0x080 - 0x0BF: Size Info & Reserved
    total_used_rom_size: int = 0
    rom_header_size: int = 0
    reserved_88h: int = 0
    reserved_8ch: bytes = field(default_factory=lambda: b"\x00" * 8)
    nand_end_rom_area: int = 0
    nand_start_rw_area: int = 0
    reserved_98h: bytes = field(default_factory=lambda: b"\x00" * 0x18)
    reserved_b0h: bytes = field(default_factory=lambda: b"\x00" * 0x10)
    # 0x0C0 - 0x15F: Logo & Checksums
    nintendo_logo: bytes = field(default_factory=lambda: b"\x00" * 0x9C)
    nintendo_logo_checksum: int = 0
    header_checksum: int = 0
    # 0x160 - 0x1FF: Debug & Reserved
    debug_rom_offset: int = 0
    debug_size: int = 0
    debug_ram_address: int = 0
    reserved_debug: bytes = field(default_factory=lambda: b"\x00" * 4)
    reserved_170h: bytes = field(default_factory=lambda: b"\x00" * 0x90)
    # non-standard fields populated by reader
    arm9_bss_size: int = 0
    arm7_bss_size: int = 0


@dataclass
class NDSOverlayEntry:
    """represents an entry in the arm9 or arm7 overlay table."""

    overlay_id: int = 0
    ram_address: int = 0
    ram_size: int = 0
    bss_size: int = 0
    static_initializer_start_address: int = 0
    static_initializer_end_address: int = 0
    file_id: int = 0
    flags: int = 0  # contains compression flag in bit 0 and auth code flag in bit 1
    is_compressed: bool = False  # derived flag for convenience
    has_auth_code: bool = False  # derived flag for convenience


@dataclass
class NDSOverlayTable:
    """contains a list of overlay entries."""

    entries: List[NDSOverlayEntry] = field(default_factory=list)


@dataclass
class NDSFatEntry:
    """represents an entry in the file allocation table."""

    start_address: int = 0
    end_address: int = 0


@dataclass
class FNTDirectoryEntry:
    """represents a directory entry in the main file name table."""

    sub_table_offset: int = 0
    first_file_id: int = 0
    parent_directory_id: Optional[int] = None  # root has none


@dataclass
class FNTSubEntry:
    """represents a file or subdirectory entry within an fnt sub-table."""

    name: str = ""
    is_directory: bool = False
    # only valid if is_directory is true, otherwise file_id is sequential from parent's first_file_id
    directory_id: Optional[int] = None


@dataclass
class FNTFileSystem:
    """represents the parsed file name table structure."""

    # maps directory id (0xf000 + index) to its main table entry
    main_table: Dict[int, FNTDirectoryEntry] = field(default_factory=dict)
    # maps directory id to a list of its sub-entries (files/subdirs)
    sub_tables: Dict[int, List[FNTSubEntry]] = field(default_factory=dict)


@dataclass
class NDSRom:
    """represents the fully parsed nds rom data."""

    header: Optional[NDSCartridgeHeader] = None  # allow none initially
    arm9_overlay_table: Optional[NDSOverlayTable] = None  # can be none if size is 0
    arm7_overlay_table: Optional[NDSOverlayTable] = None  # can be none if size is 0
    fat_entries: List[NDSFatEntry] = field(default_factory=list)
    file_system: Optional[FNTFileSystem] = None  # can be none if size is 0
    # we don't store the full rom_data here anymore to save memory in binja view
    # the binaryview will read directly from the parent view (self.raw)


# --- nds rom reader class ---


class NDSRomReader:
    """provides static methods to read and parse nds rom data."""

    @staticmethod
    def read(rom_data: bytes) -> Optional[NDSRom]:
        """
        reads the complete nds rom structure from byte data.
        returns an ndsrom object or none on critical failure.
        assumes rom_data contains the entire rom.
        """
        try:
            header = NDSRomReader._read_cartridge_header(rom_data)
            if not header:
                log_error("[NDSRomReader] failed to read cartridge header.")
                return None

            # parse tables using offsets from header
            arm9_ovt = NDSRomReader._read_overlay_table(
                rom_data, header.arm9_overlay_offset, header.arm9_overlay_size
            )
            arm7_ovt = NDSRomReader._read_overlay_table(
                rom_data, header.arm7_overlay_offset, header.arm7_overlay_size
            )
            fat = NDSRomReader._parse_fat(rom_data, header.fat_offset, header.fat_size)
            fnt = NDSRomReader._parse_fnt(rom_data, header.fnt_offset, header.fnt_size)

            # try to parse arm9 bss size from moduleparams (best effort)
            NDSRomReader._try_parse_arm9_bss_size(rom_data, header)

            return NDSRom(
                header=header,
                arm9_overlay_table=arm9_ovt,
                arm7_overlay_table=arm7_ovt,
                fat_entries=fat,
                file_system=fnt,
            )
        except Exception as e:
            log_error(f"[NDSRomReader] error during rom parsing: {e}")
            log_error(traceback.format_exc())
            return None

    @staticmethod
    def read_header_and_tables(
        header_bytes: bytes, raw_bv: "BinaryView"
    ) -> Optional[NDSRom]:
        """
        reads header from header_bytes, then reads tables directly from raw_bv.
        alternative constructor for potentially lower memory usage in binja.
        note: currently unused by ndsrom.py, kept for potential future use.
        """
        try:
            header = NDSRomReader._read_cartridge_header(header_bytes)
            if not header:
                log_error("[NDSRomReader] failed to read cartridge header (lazy).")
                return None

            # read tables directly from the binaryview
            arm9_ovt_data = raw_bv.read(
                header.arm9_overlay_offset, header.arm9_overlay_size
            )
            arm7_ovt_data = raw_bv.read(
                header.arm7_overlay_offset, header.arm7_overlay_size
            )
            fat_data = raw_bv.read(header.fat_offset, header.fat_size)
            fnt_data = raw_bv.read(header.fnt_offset, header.fnt_size)

            # parse table data
            arm9_ovt = (
                NDSRomReader._parse_overlay_table_data(arm9_ovt_data)
                if arm9_ovt_data
                else None
            )
            arm7_ovt = (
                NDSRomReader._parse_overlay_table_data(arm7_ovt_data)
                if arm7_ovt_data
                else None
            )
            fat = NDSRomReader._parse_fat_data(fat_data) if fat_data else []
            fnt = NDSRomReader._parse_fnt_data(fnt_data) if fnt_data else None

            # bss size parsing would need arm9 data read here too
            NDSRomReader._try_parse_arm9_bss_size_lazy(raw_bv, header)

            return NDSRom(
                header=header,
                arm9_overlay_table=arm9_ovt,
                arm7_overlay_table=arm7_ovt,
                fat_entries=fat,
                file_system=fnt,
            )
        except Exception as e:
            log_error(
                f"[NDSRomReader] error during header/table parsing from raw view: {e}"
            )
            log_error(traceback.format_exc())
            return None

    @staticmethod
    def _read_cartridge_header(rom_data: bytes) -> Optional[NDSCartridgeHeader]:
        """parses the 512-byte nds cartridge header."""
        header_size = 0x200
        if len(rom_data) < header_size:
            log_error(
                f"[NDSRomReader] rom data too short for header (need {header_size}, got {len(rom_data)})."
            )
            return None
        header_data = rom_data[:header_size]

        try:
            # unpack fields based on ds_cartridge_header.txt offsets
            header = NDSCartridgeHeader(
                game_title=header_data[0x00:0x0C]
                .decode("shift_jis", errors="replace")
                .rstrip("\x00"),
                gamecode=header_data[0x0C:0x10].decode("ascii", errors="replace"),
                makercode=header_data[0x10:0x12].decode("ascii", errors="replace"),
                unitcode=header_data[0x12],
                encryption_seed_select=header_data[0x13],
                devicecapacity=header_data[0x14],
                reserved1=header_data[0x15:0x1C],  # 7 bytes
                reserved1c=header_data[0x1C],
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
                reserved_88h=struct.unpack_from("<I", header_data, 0x88)[0],
                reserved_8ch=header_data[0x8C:0x94],
                nand_end_rom_area=struct.unpack_from("<H", header_data, 0x94)[0],
                nand_start_rw_area=struct.unpack_from("<H", header_data, 0x96)[0],
                reserved_98h=header_data[0x98:0xB0],
                reserved_b0h=header_data[0xB0:0xC0],
                nintendo_logo=header_data[0xC0:0x15C],
                nintendo_logo_checksum=struct.unpack_from("<H", header_data, 0x15C)[0],
                header_checksum=struct.unpack_from("<H", header_data, 0x15E)[0],
                debug_rom_offset=struct.unpack_from("<I", header_data, 0x160)[0],
                debug_size=struct.unpack_from("<I", header_data, 0x164)[0],
                debug_ram_address=struct.unpack_from("<I", header_data, 0x168)[0],
                reserved_debug=header_data[0x16C:0x170],
                reserved_170h=header_data[0x170:0x200],
            )
            return header
        except struct.error as e:
            log_error(f"[NDSRomReader] failed to unpack header: {e}")
            return None
        except Exception as e:
            log_error(f"[NDSRomReader] unexpected error reading header: {e}")
            log_error(traceback.format_exc())  # include traceback for unexpected errors
            return None

    @staticmethod
    def _read_overlay_table(
        rom_data: bytes, offset: int, size: int
    ) -> Optional[NDSOverlayTable]:
        """reads an arm9 or arm7 overlay table from the full rom_data."""
        if offset == 0 or size == 0:
            # log_info("[NDSRomReader] overlay table has zero offset or size, skipping.")
            return None  # no overlay table present is not an error
        if offset + size > len(rom_data):
            log_error(
                f"[NDSRomReader] overlay table offset/size out of bounds (offset=0x{offset:x}, size=0x{size:x}, rom_size=0x{len(rom_data):x})"
            )
            return None

        overlay_data = rom_data[offset : offset + size]
        return NDSRomReader._parse_overlay_table_data(overlay_data)

    @staticmethod
    def _parse_overlay_table_data(overlay_data: bytes) -> Optional[NDSOverlayTable]:
        """parses overlay entries from the given byte data."""
        entries = []
        entry_size = 32  # each entry is 32 bytes

        if len(overlay_data) % entry_size != 0:
            log_warn(
                f"[NDSRomReader] overlay table size (0x{len(overlay_data):x}) not a multiple of entry size ({entry_size}). table might be truncated."
            )

        num_entries = len(overlay_data) // entry_size
        try:
            for i in range(num_entries):
                offset = i * entry_size
                # read the last dword containing flags
                flags_dword = struct.unpack_from("<I", overlay_data, offset + 28)[0]
                # bit 0 indicates compression
                is_compressed_flag = (flags_dword & 1) != 0
                # bit 1 indicates authentication code presence (dsi)
                has_auth_code_flag = (flags_dword & 2) != 0

                entry = NDSOverlayEntry(
                    overlay_id=struct.unpack_from("<I", overlay_data, offset)[0],
                    ram_address=struct.unpack_from("<I", overlay_data, offset + 4)[0],
                    ram_size=struct.unpack_from("<I", overlay_data, offset + 8)[0],
                    bss_size=struct.unpack_from("<I", overlay_data, offset + 12)[0],
                    static_initializer_start_address=struct.unpack_from(
                        "<I", overlay_data, offset + 16
                    )[0],
                    static_initializer_end_address=struct.unpack_from(
                        "<I", overlay_data, offset + 20
                    )[0],
                    file_id=struct.unpack_from("<I", overlay_data, offset + 24)[0],
                    flags=flags_dword,  # store the raw flags field
                    is_compressed=is_compressed_flag,  # store the derived boolean flag
                    has_auth_code=has_auth_code_flag,  # store the derived boolean flag
                )
                entries.append(entry)
            return NDSOverlayTable(entries=entries)
        except struct.error as e:
            log_error(
                f"[NDSRomReader] failed to unpack overlay entry at index {i}: {e}"
            )
            return None  # return none if any entry fails
        except Exception as e:
            log_error(f"[NDSRomReader] unexpected error reading overlay table: {e}")
            log_error(traceback.format_exc())
            return None

    @staticmethod
    def _parse_fat(
        rom_data: bytes, fat_offset: int, fat_size: int
    ) -> List[NDSFatEntry]:
        """parses the file allocation table from the full rom_data."""
        if fat_offset == 0 or fat_size == 0:
            # log_info("[NDSRomReader] fat has zero offset or size, skipping.")
            return []
        if fat_offset + fat_size > len(rom_data):
            log_error(
                f"[NDSRomReader] fat offset/size out of bounds (offset=0x{fat_offset:x}, size=0x{fat_size:x}, rom_size=0x{len(rom_data):x})"
            )
            return []

        fat_data = rom_data[fat_offset : fat_offset + fat_size]
        return NDSRomReader._parse_fat_data(fat_data)

    @staticmethod
    def _parse_fat_data(fat_data: bytes) -> List[NDSFatEntry]:
        """parses fat entries from the given byte data."""
        fat_entries = []
        entry_size = 8  # each entry is 8 bytes

        if len(fat_data) % entry_size != 0:
            log_warn(
                f"[NDSRomReader] fat size (0x{len(fat_data):x}) not a multiple of entry size ({entry_size}). table might be truncated."
            )

        num_entries = len(fat_data) // entry_size
        try:
            for i in range(num_entries):
                offset = i * entry_size
                start_address = struct.unpack_from("<I", fat_data, offset)[0]
                end_address = struct.unpack_from("<I", fat_data, offset + 4)[0]
                # fat entries can be all zero for unused slots, skip them silently
                if start_address == 0 and end_address == 0:
                    fat_entries.append(
                        NDSFatEntry(0, 0)
                    )  # append placeholder for correct indexing
                    continue
                # check for invalid ranges
                if end_address < start_address:
                    log_warn(
                        f"[NDSRomReader] invalid fat entry {i}: end address (0x{end_address:x}) < start address (0x{start_address:x})"
                    )
                    # append invalid entry anyway? or placeholder? appending placeholder
                    fat_entries.append(NDSFatEntry(0, 0))
                    continue
                fat_entries.append(NDSFatEntry(start_address, end_address))
            return fat_entries
        except struct.error as e:
            log_error(f"[NDSRomReader] failed to unpack fat entry at index {i}: {e}")
            return fat_entries  # return potentially partial list
        except Exception as e:
            log_error(f"[NDSRomReader] unexpected error reading fat: {e}")
            log_error(traceback.format_exc())
            return fat_entries  # return potentially partial list

    @staticmethod
    def _parse_fnt(
        rom_data: bytes, fnt_offset: int, fnt_size: int
    ) -> Optional[FNTFileSystem]:
        """parses the file name table (main table and sub-tables) from the full rom_data."""
        if fnt_offset == 0 or fnt_size == 0:
            # log_info("[NDSRomReader] fnt has zero offset or size, skipping.")
            return None
        if fnt_offset + fnt_size > len(rom_data):
            log_error(
                f"[NDSRomReader] fnt offset/size out of bounds (offset=0x{fnt_offset:x}, size=0x{fnt_size:x}, rom_size=0x{len(rom_data):x})"
            )
            return None

        fnt_data = rom_data[fnt_offset : fnt_offset + fnt_size]
        return NDSRomReader._parse_fnt_data(fnt_data)

    @staticmethod
    def _parse_fnt_data(fnt_data: bytes) -> Optional[FNTFileSystem]:
        """parses the file name table structure from the given byte data."""
        main_table: Dict[int, FNTDirectoryEntry] = {}
        sub_tables: Dict[int, List[FNTSubEntry]] = {}

        try:
            # first entry in fnt is the root directory's sub-table offset
            root_sub_table_offset = struct.unpack_from("<I", fnt_data, 0)[0]
            root_first_file_id = struct.unpack_from("<H", fnt_data, 4)[0]
            total_directories = struct.unpack_from("<H", fnt_data, 6)[0]

            if total_directories == 0:
                log_warn("[NDSRomReader] fnt reports zero directories.")
                return FNTFileSystem()  # return empty filesystem

            # add root directory entry (id 0xf000)
            main_table[0xF000] = FNTDirectoryEntry(
                root_sub_table_offset, root_first_file_id, None
            )

            # read main table entries for other directories
            main_table_size = total_directories * 8
            if main_table_size > len(fnt_data):
                log_error(
                    f"[NDSRomReader] fnt main table size ({main_table_size}) exceeds total fnt data size ({len(fnt_data)})."
                )
                return None  # cannot proceed

            for i in range(1, total_directories):  # start from 1 to skip root
                offset = i * 8
                sub_table_offset = struct.unpack_from("<I", fnt_data, offset)[0]
                first_file_id = struct.unpack_from("<H", fnt_data, offset + 4)[0]
                parent_directory_id = struct.unpack_from("<H", fnt_data, offset + 6)[0]
                dir_id = 0xF000 + i
                main_table[dir_id] = FNTDirectoryEntry(
                    sub_table_offset, first_file_id, parent_directory_id
                )

            # parse sub-tables for each directory
            for dir_id, dir_entry in main_table.items():
                # check if sub-table offset is valid before parsing
                if dir_entry.sub_table_offset >= len(fnt_data):
                    log_error(
                        f"[NDSRomReader] invalid sub-table offset 0x{dir_entry.sub_table_offset:x} for dir id {dir_id:04x}"
                    )
                    sub_tables[dir_id] = []  # assign empty list if offset invalid
                    continue
                sub_tables[dir_id] = NDSRomReader._parse_fnt_sub_table(
                    fnt_data, dir_entry.sub_table_offset
                )

            return FNTFileSystem(main_table=main_table, sub_tables=sub_tables)

        except struct.error as e:
            log_error(f"[NDSRomReader] failed to unpack fnt entry: {e}")
            return None
        except Exception as e:
            log_error(f"[NDSRomReader] unexpected error reading fnt: {e}")
            log_error(traceback.format_exc())
            return None

    @staticmethod
    def _parse_fnt_sub_table(
        fnt_data: bytes, sub_table_offset: int
    ) -> List[FNTSubEntry]:
        """parses a single fnt sub-table containing file and subdirectory entries."""
        entries = []
        offset = sub_table_offset

        while True:
            # check bounds before reading type_length
            if offset >= len(fnt_data):
                log_error(
                    f"[NDSRomReader] fnt sub-table offset 0x{offset:x} exceeds fnt data size 0x{len(fnt_data):x} while reading entry."
                )
                break  # stop parsing this sub-table

            type_length = fnt_data[offset]
            if type_length == 0:  # end of sub-table marker
                break
            if type_length == 0xFF:  # end marker seen in some files
                # log_warn(f"[NDSRomReader] encountered 0xff marker in fnt sub-table at offset 0x{offset:x}. stopping parse.")
                break

            is_directory = (type_length & 0x80) != 0
            name_length = type_length & 0x7F

            name_start = offset + 1
            name_end = name_start + name_length

            # check bounds for name
            if name_end > len(fnt_data):
                log_error(
                    f"[NDSRomReader] fnt entry name length ({name_length}) exceeds fnt data bounds at offset 0x{name_start:x}."
                )
                break

            try:
                # use shift_jis for filenames as well
                name = fnt_data[name_start:name_end].decode(
                    "shift_jis", errors="replace"
                )
            except UnicodeDecodeError:
                # attempt fallback with utf-8 or latin-1? or just mark as invalid
                name = f"invalid_name_bytes_{fnt_data[name_start:name_end].hex()}"
                log_warn(
                    f"[NDSRomReader] failed to decode fnt entry name at offset 0x{name_start:x} using shift_jis."
                )

            offset = name_end  # move offset past the name

            if is_directory:
                # check bounds for directory id
                if offset + 2 > len(fnt_data):
                    log_error(
                        f"[NDSRomReader] fnt directory entry '{name}' missing id at offset 0x{offset:x}."
                    )
                    break
                directory_id = struct.unpack_from("<H", fnt_data, offset)[0]
                offset += 2
                entries.append(FNTSubEntry(name, True, directory_id))
            else:
                # file entry, directory_id is none
                entries.append(FNTSubEntry(name, False, None))

        return entries

    @staticmethod
    def is_valid(rom_data: bytes) -> bool:
        """
        performs basic header validation including crc checks.
        returns true if checks pass, false otherwise.
        """
        if len(rom_data) < 0x160:  # need up to header checksum
            log_error("[NDSRomReader] rom data too short for validation checks.")
            return False

        header_data = rom_data[:0x160]
        valid = True  # assume valid initially

        # check header crc
        try:
            header_crc = struct.unpack_from("<H", header_data, 0x15E)[0]
            calculated_header_crc = NDSRomReader._crc16(header_data[:0x15E])
            if header_crc != calculated_header_crc:
                log_warn(
                    f"[NDSRomReader] header crc mismatch! expected 0x{calculated_header_crc:04x}, got 0x{header_crc:04x}."
                )
                valid = False  # optionally make crc failure fatal by returning here
        except struct.error:
            log_error("[NDSRomReader] failed to unpack header crc.")
            return False  # cannot validate

        # check nintendo logo crc
        try:
            logo_crc_expected = NINTENDO_LOGO_CRC
            logo_crc_actual = struct.unpack_from("<H", header_data, 0x15C)[0]
            if logo_crc_actual != logo_crc_expected:
                log_warn(
                    f"[NDSRomReader] nintendo logo crc mismatch! expected 0x{logo_crc_expected:04x}, got 0x{logo_crc_actual:04x}."
                )
                valid = False  # optionally make crc failure fatal
        except struct.error:
            log_error("[NDSRomReader] failed to unpack logo crc.")
            return False  # cannot validate

        # could add secure area checksum check here if needed (header[0x6c])
        # try:
        #     secure_checksum = struct.unpack_from("<H", header_data, 0x6c)[0]
        #     # ... calculate expected checksum based on secure area data ...
        #     # calculated_secure_checksum = NDSRomReader._crc16(rom_data[0x????:0x????]) # needs secure area range
        #     # if secure_checksum != calculated_secure_checksum:
        #     #     log_warn("[NDSRomReader] secure area checksum mismatch!")
        #     #     valid = False
        # except struct.error:
        #      log_error("[NDSRomReader] failed to unpack secure area checksum.")
        #      valid = False

        return valid

    @staticmethod
    def _crc16(data: bytes) -> int:
        """calculates the crc-16/ccitt-false used in nds headers."""
        crc = 0xFFFF
        poly = CRC16_CCITT_POLY
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ poly) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc

    @staticmethod
    def _find_module_params_in_data(data: bytes) -> Optional[int]:
        """helper to find moduleparams within a given data block."""
        # copied from ndsview._find_module_params for use within ndsromreader
        try:
            magic_index = data.find(NITRO_SDK_MODULE_PARAMS_MAGIC)
            if magic_index != -1:
                struct_start_offset = magic_index - NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET
                if (
                    struct_start_offset >= 0
                    and struct_start_offset + NITRO_SDK_MODULE_PARAMS_SIZE <= len(data)
                ):
                    return struct_start_offset
        except Exception:
            pass  # ignore errors during search
        return None

    @staticmethod
    def _try_parse_arm9_bss_size(rom_data: bytes, header: NDSCartridgeHeader):
        """attempts to find moduleparams and parse arm9 bss size."""
        if not header or header.arm9_size == 0:
            return  # cannot parse without header or arm9 data

        arm9_offset = header.arm9_rom_offset
        arm9_end = arm9_offset + header.arm9_size
        if arm9_end > len(rom_data):
            log_warn(
                "[NDSRomReader] arm9 offset/size exceeds rom data length, cannot parse bss."
            )
            return

        arm9_data = rom_data[arm9_offset:arm9_end]
        module_params_offset = NDSRomReader._find_module_params_in_data(arm9_data)

        if module_params_offset is not None:
            try:
                # unpack bss start and end addresses (relative to start of arm9_data)
                bss_start_addr = struct.unpack_from(
                    "<I", arm9_data, module_params_offset + 12
                )[0]
                bss_end_addr = struct.unpack_from(
                    "<I", arm9_data, module_params_offset + 16
                )[0]

                if bss_end_addr >= bss_start_addr:
                    header.arm9_bss_size = bss_end_addr - bss_start_addr
                    log_info(
                        f"[NDSRomReader] parsed arm9 bss size 0x{header.arm9_bss_size:x} from moduleparams."
                    )
                else:
                    log_warn(
                        f"[NDSRomReader] invalid bss start/end from moduleparams (start=0x{bss_start_addr:x}, end=0x{bss_end_addr:x})."
                    )
            except Exception as bss_e:
                log_warn(
                    f"[NDSRomReader] failed to parse bss size from found moduleparams: {bss_e}."
                )
        # else:
        # log_info("[NDSRomReader] moduleparams not found, cannot determine arm9 bss size.")

    @staticmethod
    def _try_parse_arm9_bss_size_lazy(raw_bv: "BinaryView", header: NDSCartridgeHeader):
        """attempts to find moduleparams and parse arm9 bss size using lazy reads."""
        if not header or header.arm9_size == 0:
            return

        arm9_data = raw_bv.read(header.arm9_rom_offset, header.arm9_size)
        if not arm9_data:
            log_warn(
                "[NDSRomReader] failed to read arm9 data (lazy), cannot parse bss."
            )
            return

        module_params_offset = NDSRomReader._find_module_params_in_data(arm9_data)
        if module_params_offset is not None:
            try:
                bss_start_addr = struct.unpack_from(
                    "<I", arm9_data, module_params_offset + 12
                )[0]
                bss_end_addr = struct.unpack_from(
                    "<I", arm9_data, module_params_offset + 16
                )[0]
                if bss_end_addr >= bss_start_addr:
                    header.arm9_bss_size = bss_end_addr - bss_start_addr
                    log_info(
                        f"[NDSRomReader] parsed arm9 bss size 0x{header.arm9_bss_size:x} from moduleparams (lazy)."
                    )
                else:
                    log_warn(
                        f"[NDSRomReader] invalid bss start/end from moduleparams (lazy) (start=0x{bss_start_addr:x}, end=0x{bss_end_addr:x})."
                    )
            except Exception as bss_e:
                log_warn(
                    f"[NDSRomReader] failed to parse bss size from found moduleparams (lazy): {bss_e}."
                )


# --- nds rom printer class (for debugging) ---


class NDSRomPrinter:
    """provides static methods to print parsed nds rom information."""

    @staticmethod
    def print_rom_info(nds_rom: Optional[NDSRom]):
        """prints a summary of the parsed nds rom data."""
        if not nds_rom:
            print("nds rom data is none, cannot print info.")
            return

        print("\n" + "=" * 40)
        NDSRomPrinter._print_header(nds_rom.header)
        NDSRomPrinter._print_fat(nds_rom.fat_entries)
        NDSRomPrinter._print_file_system(nds_rom.file_system)
        NDSRomPrinter._print_overlay_tables(
            nds_rom.arm9_overlay_table, nds_rom.arm7_overlay_table
        )
        print("\n" + "=" * 40)

    @staticmethod
    def _print_header(header: Optional[NDSCartridgeHeader]):
        """prints the parsed header information."""
        if not header:
            print("header: not available")
            return

        print("nds rom header information:")
        print("===========================")
        print(f"game title: {header.game_title}")
        print(f"game code: {header.gamecode}")
        print(f"maker code: {header.makercode}")
        print(f"unit code: {header.unitcode:02x}h")
        print(f"encryption seed select: {header.encryption_seed_select:02x}h")
        print(
            f"device capacity: {header.devicecapacity:02x}h ({(128 * (1 << header.devicecapacity)) // 1024} kb)"
        )
        print(f"nds region: {header.nds_region:02x}h")
        print(f"rom version: {header.rom_version:02x}h")
        print(f"autostart: {header.autostart:02x}h")

        print("\narm9:")
        print(f"  rom offset: 0x{header.arm9_rom_offset:08x}")
        print(f"  entry address: 0x{header.arm9_entry_address:08x}")
        print(f"  ram address: 0x{header.arm9_ram_address:08x}")
        print(f"  size: 0x{header.arm9_size:08x}")
        print(f"  bss size: 0x{header.arm9_bss_size:08x}")  # directly use parsed field

        print("\narm7:")
        print(f"  rom offset: 0x{header.arm7_rom_offset:08x}")
        print(f"  entry address: 0x{header.arm7_entry_address:08x}")
        print(f"  ram address: 0x{header.arm7_ram_address:08x}")
        print(f"  size: 0x{header.arm7_size:08x}")
        print(f"  bss size: 0x{header.arm7_bss_size:08x}")  # directly use parsed field

        print("\nfile tables:")
        print(f"  fnt offset: 0x{header.fnt_offset:08x}")
        print(f"  fnt size: 0x{header.fnt_size:08x}")
        print(f"  fat offset: 0x{header.fat_offset:08x}")
        print(f"  fat size: 0x{header.fat_size:08x}")

        print("\noverlay tables:")
        print(f"  arm9 overlay offset: 0x{header.arm9_overlay_offset:08x}")
        print(f"  arm9 overlay size: 0x{header.arm9_overlay_size:08x}")
        print(f"  arm7 overlay offset: 0x{header.arm7_overlay_offset:08x}")
        print(f"  arm7 overlay size: 0x{header.arm7_overlay_size:08x}")

        print("\nport 40001a4h settings:")
        print(f"  normal: 0x{header.port_40001a4_normal:08x}")
        print(f"  key1: 0x{header.port_40001a4_key1:08x}")

        print(f"\nicon/title offset: 0x{header.icon_title_offset:08x}")
        print(f"secure area checksum: 0x{header.secure_area_checksum:04x}")
        print(f"secure area delay: 0x{header.secure_area_delay:04x}")

        print("\nauto load list ram addresses:")
        print(f"  arm9: 0x{header.arm9_auto_load_list_ram_address:08x}")
        print(f"  arm7: 0x{header.arm7_auto_load_list_ram_address:08x}")

        print(f"\nsecure area disable: {header.secure_area_disable.hex()}")
        print(f"total used rom size: 0x{header.total_used_rom_size:08x}")
        print(f"rom header size: 0x{header.rom_header_size:08x}")

        print(f"\nnintendo logo checksum: 0x{header.nintendo_logo_checksum:04x}")
        print(f"header checksum: 0x{header.header_checksum:04x}")

        print("\ndebug info:")
        print(f"  rom offset: 0x{header.debug_rom_offset:08x}")
        print(f"  size: 0x{header.debug_size:08x}")
        print(f"  ram address: 0x{header.debug_ram_address:08x}")

    @staticmethod
    def _print_fat(fat_entries: List[NDSFatEntry]):
        """prints the parsed file allocation table."""
        print("\nfile allocation table (fat):")
        if not fat_entries:
            print("  (empty)")
            return
        for i, entry in enumerate(fat_entries):
            # only print non-empty entries for brevity in testing
            if entry.start_address != 0 or entry.end_address != 0:
                print(
                    f"  file {i:04x}: start: 0x{entry.start_address:08x}, end: 0x{entry.end_address:08x} (size: {entry.end_address - entry.start_address})"
                )

    @staticmethod
    def _print_file_system(file_system: Optional[FNTFileSystem]):
        """prints the parsed file name table structure recursively."""
        print("\nfile name table (fnt):")
        if not file_system or not file_system.main_table:
            print("  (empty or not parsed)")
            return
        # start printing from the root directory (id 0xf000)
        NDSRomPrinter._print_directory(file_system, 0xF000)

    @staticmethod
    def _print_directory(file_system: FNTFileSystem, dir_id: int, indent: str = ""):
        """helper to recursively print directory contents."""
        if dir_id not in file_system.main_table:
            print(f"{indent}error: directory id {dir_id:04x} not found in main table.")
            return

        # print directory id (optional, can be verbose)
        # print(f"{indent}directory id: {dir_id:04x}")

        if dir_id not in file_system.sub_tables:
            print(f"{indent}  (error: sub-table not found for dir id {dir_id:04x})")
            return

        sub_table = file_system.sub_tables[dir_id]
        for entry in sub_table:
            if entry.is_directory:
                print(f"{indent}  [{entry.name}]")
                # recursive call for subdirectory
                if entry.directory_id is not None:
                    NDSRomPrinter._print_directory(
                        file_system, entry.directory_id, indent + "    "
                    )
                else:
                    print(f"{indent}    (error: subdirectory entry has no id)")
            else:
                print(f"{indent}  {entry.name}")

    @staticmethod
    def _print_overlay_tables(
        arm9_ovt: Optional[NDSOverlayTable], arm7_ovt: Optional[NDSOverlayTable]
    ):
        """prints both arm9 and arm7 overlay tables."""
        NDSRomPrinter._print_overlay_table("arm9", arm9_ovt)
        NDSRomPrinter._print_overlay_table("arm7", arm7_ovt)

    @staticmethod
    def _print_overlay_table(name: str, ovt: Optional[NDSOverlayTable]):
        """prints a single overlay table."""
        print(f"\n{name} overlay table:")
        print("=" * (len(name) + 15))
        if not ovt or not ovt.entries:
            print("  (empty or not present)")
            return

        for i, entry in enumerate(ovt.entries):
            print(f"overlay {i} (id: {entry.overlay_id}):")  # include overlay id
            print(f"  file id: {entry.file_id}")
            print(f"  ram address: 0x{entry.ram_address:08x}")
            print(f"  ram size: 0x{entry.ram_size:08x}")
            print(f"  bss size: 0x{entry.bss_size:08x}")
            print(f"  compressed: {entry.is_compressed}")  # print compression flag
            print(f"  has auth code: {entry.has_auth_code}")  # print auth code flag
            print(
                f"  static init start: 0x{entry.static_initializer_start_address:08x}"
            )
            print(f"  static init end: 0x{entry.static_initializer_end_address:08x}")
            # print(f"  flags: 0x{entry.flags:08x}") # print raw flags if needed
            print()


# --- command line execution (for testing the reader) ---


def main():
    """main function for command-line testing."""
    import sys
    import os

    if len(sys.argv) != 2:
        print(f"usage: python {os.path.basename(__file__)} <path_to_nds_rom>")
        sys.exit(1)

    rom_file = sys.argv[1]
    if not os.path.exists(rom_file):
        print(f"error: file not found: {rom_file}")
        sys.exit(1)

    print(f"reading rom: {rom_file}")
    try:
        with open(rom_file, "rb") as f:
            rom_data = f.read()
    except IOError as e:
        print(f"error reading file: {e}")
        sys.exit(1)

    print("parsing rom...")
    nds_rom = NDSRomReader.read(rom_data)

    if nds_rom:
        print("parsing successful. printing rom info...")
        NDSRomPrinter.print_rom_info(nds_rom)
    else:
        print("failed to parse rom.")
        sys.exit(1)


if __name__ == "__main__":
    # no need for dummy log functions here if imported at top level
    main()
