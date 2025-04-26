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
)
from binaryninja.log import Logger

# --- gba header constants ---
# offsets within the gba header
GBA_NINTENDO_LOGO_OFFSET = 0x04
GBA_NINTENDO_LOGO_SIZE = 0x9C  # 156 bytes
GBA_GAME_TITLE_OFFSET = 0xA0
GBA_GAME_TITLE_SIZE = 12
GBA_GAME_CODE_OFFSET = 0xAC
GBA_GAME_CODE_SIZE = 4
GBA_MAKER_CODE_OFFSET = 0xB0
GBA_MAKER_CODE_SIZE = 2
GBA_FIXED_VALUE_OFFSET = 0xB2  # Should be 0x96
GBA_MAIN_UNIT_CODE_OFFSET = 0xB3
GBA_DEVICE_TYPE_OFFSET = 0xB4
GBA_SOFTWARE_VERSION_OFFSET = 0xBC
GBA_HEADER_CHECKSUM_OFFSET = 0xBD
GBA_HEADER_MIN_SIZE = 0xC0  # Minimum size to check logo magic


# --- dataclass for gba header ---
@dataclass
class GBAHeader:
    """Represents parsed information from the GBA ROM header."""

    game_title: str = ""
    game_code: str = ""
    maker_code: str = ""
    software_version: int = 0
    # Add other fields if needed later


# --- gba hardware definitions ---

# dictionary mapping tag type names (proper case) to icons
GBA_TAG_TYPES: Dict[str, str] = {
    "Memory Region": "🗺️",
    "Display": "🖼️",
    "Sound": "🔊",
    "DMA": "➡️",
    "Timers": "⏱️",
    "Serial IO": "↔️",
    "Keypad": "🎮",
    "Interrupts": "⚡",
    "System Control": "⚙️",
    "Hardware Register": "🔩",  # Generic fallback
}

# list of known i/o registers: (address, name, tag_type_name, description)
# names and descriptions use proper case for symbols/comments. tag_type_name matches GBA_TAG_TYPES keys.
GBA_IO_REGISTERS: List[Tuple[int, str, str, str]] = [
    # Display Registers (0x4000000 - 0x400005F)
    (0x4000000, "REG_DISPCNT", "Display", "LCD Control"),
    (0x4000004, "REG_DISPSTAT", "Display", "General LCD Status"),
    (0x4000006, "REG_VCOUNT", "Display", "Vertical Counter"),
    (0x4000008, "REG_BG0CNT", "Display", "BG0 Control"),
    (0x400000A, "REG_BG1CNT", "Display", "BG1 Control"),
    (0x400000C, "REG_BG2CNT", "Display", "BG2 Control"),
    (0x400000E, "REG_BG3CNT", "Display", "BG3 Control"),
    (0x4000010, "REG_BG0HOFS", "Display", "BG0 X-Offset"),
    (0x4000012, "REG_BG0VOFS", "Display", "BG0 Y-Offset"),
    (0x4000014, "REG_BG1HOFS", "Display", "BG1 X-Offset"),
    (0x4000016, "REG_BG1VOFS", "Display", "BG1 Y-Offset"),
    (0x4000018, "REG_BG2HOFS", "Display", "BG2 X-Offset"),
    (0x400001A, "REG_BG2VOFS", "Display", "BG2 Y-Offset"),
    (0x400001C, "REG_BG3HOFS", "Display", "BG3 X-Offset"),
    (0x400001E, "REG_BG3VOFS", "Display", "BG3 Y-Offset"),
    (0x4000020, "REG_BG2PA", "Display", "BG2 Rotation/Scaling Parameter A (dx)"),
    (0x4000022, "REG_BG2PB", "Display", "BG2 Rotation/Scaling Parameter B (dmx)"),
    (0x4000024, "REG_BG2PC", "Display", "BG2 Rotation/Scaling Parameter C (dy)"),
    (0x4000026, "REG_BG2PD", "Display", "BG2 Rotation/Scaling Parameter D (dmy)"),
    (
        0x4000028,
        "REG_BG2X",
        "Display",
        "BG2 Reference Point X-Coordinate (Upper 28 bits)",
    ),
    (
        0x400002C,
        "REG_BG2Y",
        "Display",
        "BG2 Reference Point Y-Coordinate (Upper 28 bits)",
    ),
    (0x4000030, "REG_BG3PA", "Display", "BG3 Rotation/Scaling Parameter A (dx)"),
    (0x4000032, "REG_BG3PB", "Display", "BG3 Rotation/Scaling Parameter B (dmx)"),
    (0x4000034, "REG_BG3PC", "Display", "BG3 Rotation/Scaling Parameter C (dy)"),
    (0x4000036, "REG_BG3PD", "Display", "BG3 Rotation/Scaling Parameter D (dmy)"),
    (
        0x4000038,
        "REG_BG3X",
        "Display",
        "BG3 Reference Point X-Coordinate (Upper 28 bits)",
    ),
    (
        0x400003C,
        "REG_BG3Y",
        "Display",
        "BG3 Reference Point Y-Coordinate (Upper 28 bits)",
    ),
    (0x4000040, "REG_WIN0H", "Display", "Window 0 Horizontal Dimensions"),
    (0x4000042, "REG_WIN1H", "Display", "Window 1 Horizontal Dimensions"),
    (0x4000044, "REG_WIN0V", "Display", "Window 0 Vertical Dimensions"),
    (0x4000046, "REG_WIN1V", "Display", "Window 1 Vertical Dimensions"),
    (0x4000048, "REG_WININ", "Display", "Inside of Window 0 and 1"),
    (0x400004A, "REG_WINOUT", "Display", "Inside of OBJ Window & Outside of Windows"),
    (0x400004C, "REG_MOSAIC", "Display", "Mosaic Size"),
    (0x4000050, "REG_BLDCNT", "Display", "Color Special Effects Selection"),
    (0x4000052, "REG_BLDALPHA", "Display", "Alpha Blending Coefficients"),
    (0x4000054, "REG_BLDY", "Display", "Brightness (Fade-In/Out) Coefficient"),
    # Sound Registers (0x4000060 - 0x40000A7)
    (0x4000060, "REG_SOUND1CNT_L", "Sound", "Channel 1 Sweep register (NR10)"),
    (
        0x4000062,
        "REG_SOUND1CNT_H",
        "Sound",
        "Channel 1 Duty/Length/Envelope (NR11, NR12)",
    ),
    (0x4000064, "REG_SOUND1CNT_X", "Sound", "Channel 1 Frequency/Control (NR13, NR14)"),
    (
        0x4000068,
        "REG_SOUND2CNT_L",
        "Sound",
        "Channel 2 Duty/Length/Envelope (NR21, NR22)",
    ),
    (0x400006C, "REG_SOUND2CNT_H", "Sound", "Channel 2 Frequency/Control (NR23, NR24)"),
    (0x4000070, "REG_SOUND3CNT_L", "Sound", "Channel 3 Stop/Wave RAM select (NR30)"),
    (0x4000072, "REG_SOUND3CNT_H", "Sound", "Channel 3 Length/Volume (NR31, NR32)"),
    (0x4000074, "REG_SOUND3CNT_X", "Sound", "Channel 3 Frequency/Control (NR33, NR34)"),
    (0x4000078, "REG_SOUND4CNT_L", "Sound", "Channel 4 Length/Envelope (NR41, NR42)"),
    (0x400007C, "REG_SOUND4CNT_H", "Sound", "Channel 4 Frequency/Control (NR43, NR44)"),
    (0x4000080, "REG_SOUNDCNT_L", "Sound", "Control Stereo/Volume/Enable (NR50, NR51)"),
    (0x4000082, "REG_SOUNDCNT_H", "Sound", "Control Mixing/DMA Control"),
    (0x4000084, "REG_SOUNDCNT_X", "Sound", "Control Sound on/off (NR52)"),
    (0x4000088, "REG_SOUNDBIAS", "Sound", "Sound PWM Control"),
    (
        0x4000090,
        "REG_WAVE_RAM",
        "Sound",
        "Channel 3 Wave Pattern RAM (16 bytes, mirrored)",
    ),  # Symbol at start
    (0x40000A0, "REG_FIFO_A", "Sound", "Channel A FIFO, Data 0-3"),
    (0x40000A4, "REG_FIFO_B", "Sound", "Channel B FIFO, Data 0-3"),
    # DMA Registers (0x40000B0 - 0x40000DF)
    (0x40000B0, "REG_DMA0SAD", "DMA", "DMA 0 Source Address"),
    (0x40000B4, "REG_DMA0DAD", "DMA", "DMA 0 Destination Address"),
    (0x40000B8, "REG_DMA0CNT_L", "DMA", "DMA 0 Word Count"),
    (0x40000BA, "REG_DMA0CNT_H", "DMA", "DMA 0 Control"),
    (0x40000BC, "REG_DMA1SAD", "DMA", "DMA 1 Source Address"),
    (0x40000C0, "REG_DMA1DAD", "DMA", "DMA 1 Destination Address"),
    (0x40000C4, "REG_DMA1CNT_L", "DMA", "DMA 1 Word Count"),
    (0x40000C6, "REG_DMA1CNT_H", "DMA", "DMA 1 Control"),
    (0x40000C8, "REG_DMA2SAD", "DMA", "DMA 2 Source Address"),
    (0x40000CC, "REG_DMA2DAD", "DMA", "DMA 2 Destination Address"),
    (0x40000D0, "REG_DMA2CNT_L", "DMA", "DMA 2 Word Count"),
    (0x40000D2, "REG_DMA2CNT_H", "DMA", "DMA 2 Control"),
    (0x40000D4, "REG_DMA3SAD", "DMA", "DMA 3 Source Address"),
    (0x40000D8, "REG_DMA3DAD", "DMA", "DMA 3 Destination Address"),
    (0x40000DC, "REG_DMA3CNT_L", "DMA", "DMA 3 Word Count"),
    (0x40000DE, "REG_DMA3CNT_H", "DMA", "DMA 3 Control"),
    # Timer Registers (0x4000100 - 0x400010F)
    (0x4000100, "REG_TM0CNT_L", "Timers", "Timer 0 Counter/Reload"),
    (0x4000102, "REG_TM0CNT_H", "Timers", "Timer 0 Control"),
    (0x4000104, "REG_TM1CNT_L", "Timers", "Timer 1 Counter/Reload"),
    (0x4000106, "REG_TM1CNT_H", "Timers", "Timer 1 Control"),
    (0x4000108, "REG_TM2CNT_L", "Timers", "Timer 2 Counter/Reload"),
    (0x400010A, "REG_TM2CNT_H", "Timers", "Timer 2 Control"),
    (0x400010C, "REG_TM3CNT_L", "Timers", "Timer 3 Counter/Reload"),
    (0x400010E, "REG_TM3CNT_H", "Timers", "Timer 3 Control"),
    # Serial Communication Registers (0x4000120 - 0x400015B)
    (0x4000120, "REG_SIODATA32", "Serial IO", "SIO Data (Normal-32bit Mode)"),
    (0x4000120, "REG_SIOMULTI0", "Serial IO", "SIO Data 0 (Multiplayer Parent)"),
    (0x4000122, "REG_SIOMULTI1", "Serial IO", "SIO Data 1 (Multiplayer Child 1)"),
    (0x4000124, "REG_SIOMULTI2", "Serial IO", "SIO Data 2 (Multiplayer Child 2)"),
    (0x4000126, "REG_SIOMULTI3", "Serial IO", "SIO Data 3 (Multiplayer Child 3)"),
    (0x4000128, "REG_SIOCNT", "Serial IO", "SIO Control Register"),
    (0x400012A, "REG_SIOMLT_SEND", "Serial IO", "SIO Data Send (Multiplayer Local)"),
    (0x400012A, "REG_SIODATA8", "Serial IO", "SIO Data (Normal-8bit and UART Mode)"),
    (0x4000134, "REG_RCNT", "Serial IO", "SIO Mode Select / General Purpose Data"),
    (0x4000140, "REG_JOYCNT", "Serial IO", "SIO JOY Bus Control"),
    (0x4000150, "REG_JOY_RECV", "Serial IO", "SIO JOY Bus Receive Data"),
    (0x4000154, "REG_JOY_TRANS", "Serial IO", "SIO JOY Bus Transmit Data"),
    (0x4000158, "REG_JOYSTAT", "Serial IO", "SIO JOY Bus Receive Status"),
    # Keypad Input (0x4000130 - 0x4000133)
    (0x4000130, "REG_KEYINPUT", "Keypad", "Key Status"),
    (0x4000132, "REG_KEYCNT", "Keypad", "Key Interrupt Control"),
    # Interrupt, Waitstate, Power Control (0x4000200 - 0x4000301, 0x4000800)
    (0x4000200, "REG_IE", "Interrupts", "Interrupt Enable Register"),
    (0x4000202, "REG_IF", "Interrupts", "Interrupt Flag / Acknowledge"),
    (0x4000204, "REG_WAITCNT", "System Control", "Game Pak Waitstate Control"),
    (0x4000208, "REG_IME", "Interrupts", "Interrupt Master Enable Register"),
    (0x4000300, "REG_POSTFLG", "System Control", "Post Boot Flag (Undocumented)"),
    (0x4000301, "REG_HALTCNT", "System Control", "Power Down Control (Undocumented)"),
    (
        0x4000800,
        "REG_INTERNAL_MEM_CNT",
        "System Control",
        "Internal Memory Control (Undocumented)",
    ),
]


# --- gbaview class definition ---


class GBAView(BinaryView):
    """
    BinaryView class for loading and analyzing Game Boy Advance (GBA) ROM files.
    """

    name = "GBA"
    long_name = "Game Boy Advance ROM"

    # --- segment permission flags ---
    # combine basic permissions for common scenarios
    RWX_FLAGS: SegmentFlag = (
        SegmentFlag.SegmentReadable
        | SegmentFlag.SegmentWritable
        | SegmentFlag.SegmentExecutable
    )
    RW_FLAGS: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    RX_FLAGS: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
    R_FLAGS: SegmentFlag = SegmentFlag.SegmentReadable

    def __init__(self, data: BinaryView):
        """
        initializes the GBAView instance. minimal setup here.
        args:
            data: the BinaryView object containing the raw gba rom data.
        """
        # --- initialize the base binaryview *first* ---
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)

        # --- initialize instance variables *after* successful base init ---
        self.raw: BinaryView = data  # keep a reference to the raw data view
        self.log: Logger = self.create_logger("GBA")  # use "GBA" logger name.
        self._created_tag_types: Dict[str, TagType] = {}  # cache for created TagTypes.
        self.rom_size = self.raw.length  # get rom size from the raw view
        self.gba_header: Optional[GBAHeader] = None  # store parsed header info

        # set architecture and platform (gba uses armv4t, covered by armv7 profile)
        try:
            self.arch: Architecture = Architecture["armv7"]  # type: ignore
            self.platform: Platform = self.arch.standalone_platform  # type: ignore
            if not self.platform:
                log_error(
                    "[GBA] critical: could not get standalone platform for armv7."
                )
                raise RuntimeError("failed to get armv7 platform.")
            log_info(
                f"[GBA] using platform: {self.platform.name}, architecture: {self.arch.name}"
            )
        except KeyError:
            log_error("[GBA] critical: armv7 architecture not found.")
            raise RuntimeError("armv7 architecture not found.")
        except Exception as e:
            log_error(f"[GBA] critical error setting platform/arch: {e}")
            raise

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        checks if the data is likely a gba rom using the nintendo logo magic byte.
        args:
            data: the BinaryView object containing the data.
        returns:
            true if the data is likely a gba rom, false otherwise.
        """
        # check header size
        if data.length < GBA_HEADER_MIN_SIZE:
            return False

        # check nintendo logo fixed value byte at 0xb2
        try:
            magic_byte = data.read(GBA_FIXED_VALUE_OFFSET, 1)
            if magic_byte == b"\x96":
                log_info("[GBA] validation: found fixed value 0x96 in header.")
                return True
            else:
                # log_warn("[GBA] validation: fixed value 0x96 mismatch.") # Can be noisy
                return False
        except Exception as e:
            # Use a generic logger name here as self.log isn't available in classmethod
            log_error(f"[GBA Validation] error reading fixed value byte: {e}")
            return False

        # could add header checksum validation here if needed
        # header_checksum = data.read(GBA_HEADER_CHECKSUM_OFFSET, 1)[0]
        # calculated = 0
        # for i in range(GBA_GAME_TITLE_OFFSET, GBA_HEADER_CHECKSUM_OFFSET):
        #     calculated = calculated - data.read(i, 1)[0]
        # calculated = (calculated - 0x19) & 0xFF
        # if header_checksum != calculated:
        #     log_warn("[GBA] Header checksum mismatch.")
        #     # return False # Decide if strict check is needed

    # --- helper methods ---

    def _parse_header(self) -> bool:
        """parses key fields from the gba header."""
        self.log.log_info("parsing gba header...")
        if self.raw.length < GBA_HEADER_MIN_SIZE:
            self.log.log_error("rom too small for gba header.")
            return False
        try:
            title_bytes = self.raw.read(GBA_GAME_TITLE_OFFSET, GBA_GAME_TITLE_SIZE)
            game_code_bytes = self.raw.read(GBA_GAME_CODE_OFFSET, GBA_GAME_CODE_SIZE)
            maker_code_bytes = self.raw.read(GBA_MAKER_CODE_OFFSET, GBA_MAKER_CODE_SIZE)
            sw_version_byte = self.raw.read(GBA_SOFTWARE_VERSION_OFFSET, 1)

            self.gba_header = GBAHeader(
                game_title=title_bytes.decode("ascii", errors="replace").rstrip("\x00"),
                game_code=game_code_bytes.decode("ascii", errors="replace"),
                maker_code=maker_code_bytes.decode("ascii", errors="replace"),
                software_version=sw_version_byte[0] if sw_version_byte else 0,
            )
            self.log.log_info(
                f"game title: '{self.gba_header.game_title}', code: {self.gba_header.game_code}, maker: {self.gba_header.maker_code}"
            )
            return True
        except Exception as e:
            self.log.log_error(f"failed to parse gba header fields: {e}")
            self.gba_header = None
            return False

    def _define_tag_types(self):
        """
        defines and caches all necessary tag types used by this view.
        iterates through the global GBA_TAG_TYPES dictionary.
        """
        self.log.log_info("defining gba hardware tag types...")
        for name, icon in GBA_TAG_TYPES.items():
            self._get_or_create_tag_type(name, icon)

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        """
        gets or creates a tag type, caching the result. avoids redundant api calls.
        args:
            name: the name of the tag type (e.g., "Memory Region"). use proper case.
            icon: the icon (emoji) for the tag type (e.g., "🗺️").
        returns:
            the TagType object or none if creation failed.
        """
        # use lowercase for internal caching/lookup key
        name_lower = name.lower()
        # check cache first.
        if name_lower in self._created_tag_types:
            return self._created_tag_types[name_lower]

        # check if tag type already exists in the view.
        if name_lower in self.tag_types:
            tag_type = self.tag_types[name_lower]
            if isinstance(tag_type, list):
                tag_type = tag_type[0] if tag_type else None
            if tag_type:
                self.log.log_info(f"found existing TagType '{name_lower}'.")
                self._created_tag_types[name_lower] = tag_type
                return tag_type
            else:
                self.log.log_error(
                    f"TagType '{name_lower}' exists but api returned empty list/none."
                )
                pass  # proceed to creation block.

        # if not found or api returned none unexpectedly, create it.
        try:
            # use the original (proper) casing for the name when creating.
            self.log.log_info(f"creating new TagType '{name}' with icon '{icon}'.")
            tag_type = self.create_tag_type(name, icon)
            self._created_tag_types[name_lower] = tag_type  # cache using lowercase key.
            return tag_type
        except Exception as e:
            self.log.log_error(f"failed to create TagType '{name}': {e}")
            return None

    def _define_reg_with_tag(
        self,
        address: int,
        name: str,  # use proper case for symbol name
        tag_type_name: str,  # use proper case for tag type name
        tag_type_icon: str,
        description: str = "",  # use proper case for description
    ):
        """
        helper to define a hardware register symbol and apply a descriptive tag.
        args:
            address: the memory address of the register.
            name: the name of the register (symbol name, e.g., "REG_DISPCNT").
            tag_type_name: the name of the tag type to apply (e.g., "Display").
            tag_type_icon: the icon for the tag type (used if creating the type).
            description: an optional comment for the register.
        """
        try:
            # define the symbol at the specified address.
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))

            # add the comment if provided.
            if description:
                self.set_comment_at(address, description)

            # get or create the tag type using the helper. pass proper case name.
            tag_type = self._get_or_create_tag_type(tag_type_name, tag_type_icon)

            # add the tag to the address if the tag type was successfully obtained/created.
            if tag_type:
                # use the register name as the tag data for easy identification in ui.
                self.add_tag(address, tag_type, data=name)
        except Exception as e:
            # log if defining symbol or adding tag fails, but don't stop the loading process.
            self.log.log_error(
                f"failed processing register '{name}' at 0x{address:x}: {e}"
            )

    def _map_memory_regions(self):
        """maps the core gba memory regions (bios, wram, vram, io, rom, sram)."""
        self.log.log_info("mapping gba memory regions...")

        # helper function to add segment and associated tag/comment.
        def add_memory_region(
            addr,
            size,
            perms,
            name,
            tag_name="Memory Region",
            tag_icon="🗺️",
            file_offset=0,
            file_len=0,
        ):
            self.log.log_info(f"  mapping {name}: addr=0x{addr:08x}, size=0x{size:x}")
            # add the segment. use file offset/len only for rom.
            self.add_auto_segment(addr, size, file_offset, file_len, perms)
            # get the tag type (use proper case name).
            tag_type = self._get_or_create_tag_type(tag_name, tag_icon)
            if tag_type:
                # add tag at the start of the region.
                self.add_tag(addr, tag_type, data=f"{name} Start")
            # add comment at the start of the region (proper case allowed here).
            self.set_comment_at(addr, f"{name} ({size // 1024}KB)")

        # bios rom (16kb) - typically not present in rom file, map as zero-filled
        add_memory_region(0x00000000, 0x4000, self.RX_FLAGS, "BIOS System ROM")

        # wram - on-board (slow, 256kb)
        add_memory_region(0x02000000, 0x40000, self.RWX_FLAGS, "WRAM - On-board")

        # wram - on-chip (fast, 32kb)
        add_memory_region(0x03000000, 0x8000, self.RWX_FLAGS, "WRAM - On-chip")

        # i/o registers (1kb)
        add_memory_region(
            0x04000000,
            0x0400,
            self.RW_FLAGS,
            "I/O Registers",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )

        # palette ram (1kb)
        add_memory_region(0x05000000, 0x0400, self.RW_FLAGS, "Palette RAM")

        # vram (96kb)
        add_memory_region(0x06000000, 0x18000, self.RW_FLAGS, "VRAM")

        # oam - obj attributes (1kb)
        add_memory_region(0x07000000, 0x0400, self.RW_FLAGS, "OAM")

        # game pak rom (up to 32mb, mapped directly from file)
        # map the first 16mb waitstate 0 region. larger roms might need more segments for waitstates 1/2
        rom_map_size = min(
            self.rom_size, 0x2000000
        )  # Map up to 32MB if ROM is that large
        if rom_map_size > 0:
            add_memory_region(
                0x08000000,
                rom_map_size,
                self.RX_FLAGS,
                "Game Pak ROM",
                file_offset=0,
                file_len=rom_map_size,
            )
            # TODO: Add segments for waitstate 1 (0x0A000000) and 2 (0x0C000000) if needed, mirroring the first segment's data.
        else:
            self.log.log_warn("rom size appears to be 0, not mapping game pak rom.")

        # game pak sram (up to 64kb)
        # size is variable, map max potential size. actual size depends on cart.
        add_memory_region(0x0E000000, 0x10000, self.RW_FLAGS, "Game Pak SRAM")

    def _define_sections(self):
        """defines sections based on mapped segments to aid analysis."""
        self.log.log_info("defining sections...")
        # define a code section for the main rom segment to address analysis warnings
        rom_segment = self.get_segment_at(0x08000000)
        if rom_segment:
            self.log.log_info(
                f"  adding section '.text' for rom segment at 0x{rom_segment.start:08x}"
            )
            try:
                self.add_auto_section(
                    name=".text",  # common name for code
                    start=rom_segment.start,
                    length=rom_segment.length,
                    semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                    type="Code",
                )
            except Exception as e:
                self.log.log_error(f"failed to add rom code section: {e}")
        else:
            self.log.log_warn(
                "could not find rom segment at 0x08000000 to define code section."
            )
        # could potentially define sections for wram, vram etc. if needed

    def _define_io_registers(self):
        """defines symbols and tags for known gba i/o registers."""
        self.log.log_info("defining gba i/o registers...")
        for addr, name, tag_name, desc in GBA_IO_REGISTERS:
            # get the icon for the tag type, providing a default if needed
            icon = GBA_TAG_TYPES.get(tag_name, "🔩")  # default to generic hardware icon
            self._define_reg_with_tag(addr, name, tag_name, icon, desc)

    def _define_entry_point(self):
        """defines the fixed gba entry point."""
        entry_point_addr = 0x8000000  # Standard GBA entry point
        self.log.log_info(f"defining entry point at 0x{entry_point_addr:08x}")
        segment_at_entry = self.get_segment_at(entry_point_addr)
        if segment_at_entry and segment_at_entry.executable:
            self.add_entry_point(entry_point_addr)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, entry_point_addr, "_start")
            )
            try:
                self.add_function(entry_point_addr)  # Define function for analysis
            except Exception as e:
                self.log.log_warn(
                    f"failed to add function at entry point 0x{entry_point_addr:x}: {e}"
                )
        else:
            self.log.log_error(
                f"entry point 0x{entry_point_addr:x} not in executable segment. cannot define function."
            )

    # --- main initialization logic ---

    def init(self) -> bool:
        """
        initializes the GBAView by mapping memory regions, defining sections,
        symbols, tags, and the entry point.
        returns:
            true on successful initialization, false otherwise.
        """
        # platform/arch should be valid here if __init__ succeeded.

        try:
            self.log.log_info("starting gba rom loading process...")

            # --- main loading steps ---
            if not self._parse_header():
                return False  # Parse header first
            self._define_tag_types()
            self._map_memory_regions()
            self._define_sections()  # Define sections after segments are mapped
            self._define_io_registers()
            self._define_entry_point()

            # --- final analysis update ---
            self.log.log_info("gba rom loading complete. updating analysis...")
            # it's often better to let the user trigger the initial analysis,
            # but for loaders, triggering it can be helpful to resolve symbols etc.
            self.update_analysis_and_wait()
            self.log.log_info("analysis update finished.")

            return True  # initialization successful

        except Exception as e:
            # catch any unexpected errors during initialization
            log_error(f"[GBA] failed to initialize gbaview: {e}")
            log_error(traceback.format_exc())
            return False  # indicate failure

    # --- required binaryview methods ---

    def perform_is_executable(self) -> bool:
        """gba roms contain executable code"""
        return True

    def perform_get_entry_point(self) -> int:
        """returns the fixed gba entry point address"""
        # this is called by the core *after* init() completes.
        if len(self.entry_points) > 0:
            return self.entry_points[0]
        else:
            # fallback if add_entry_point failed in init
            log_warn(
                "[GBA] perform_get_entry_point called but no entry points defined. returning fixed address 0x08000000."
            )
            return 0x08000000

    def perform_get_address_size(self) -> int:
        """gba uses 32-bit addresses"""
        return 4


GBAView.register()
