import struct
import traceback
from typing import Optional, Dict, Tuple, List, cast
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

# - gba header constants
# these constants define offsets and sizes for various fields within the gba rom header.
# this information is crucial for correctly parsing the metadata embedded in every gba rom.

# offset for the nintendo logo within the gba header.
GBA_NINTENDO_LOGO_OFFSET = 0x04
# size of the nintendo logo data in bytes.
GBA_NINTENDO_LOGO_SIZE = 0x9C  # 156 bytes
# offset for the 12-character game title.
GBA_GAME_TITLE_OFFSET = 0xA0
# size of the game title string in bytes.
GBA_GAME_TITLE_SIZE = 12
# offset for the 4-character game code (often used as a unique identifier).
GBA_GAME_CODE_OFFSET = 0xAC
# size of the game code string in bytes.
GBA_GAME_CODE_SIZE = 4
# offset for the 2-character maker code (identifies the game developer/publisher).
GBA_MAKER_CODE_OFFSET = 0xB0
# size of the maker code string in bytes.
GBA_MAKER_CODE_SIZE = 2
# offset for a fixed value (must be 0x96) used for basic rom validation.
GBA_FIXED_VALUE_OFFSET = 0xB2
# offset for the main unit code (hardware revision information).
GBA_MAIN_UNIT_CODE_OFFSET = 0xB3
# offset for the device type (e.g., cartridge type).
GBA_DEVICE_TYPE_OFFSET = 0xB4
# offset for the software version number of the game.
GBA_SOFTWARE_VERSION_OFFSET = 0xBC
# offset for the header checksum, used to verify header integrity.
GBA_HEADER_CHECKSUM_OFFSET = 0xBD
# minimum size of the header required for basic validation (e.g., to check the fixed value).
GBA_HEADER_MIN_SIZE = 0xC0


# - dataclass for gba header
@dataclass
class GBAHeader:
    """
    Represents parsed information from the GBA ROM header.
    This structure holds key metadata extracted from the ROM,
    such as game title, various codes, and software version,
    which can be useful for identifying the game and its properties.
    """

    game_title: str = ""
    game_code: str = ""
    maker_code: str = ""
    software_version: int = 0
    # other fields can be added here if more detailed header parsing is needed in the future.


# - gba hardware definitions

# this dictionary maps descriptive names of gba hardware categories (tag type names)
# to emoji icons for better visual distinction in the binary ninja ui.
# these names should be in proper case as they are used for creating tag types.
GBA_TAG_TYPE_DEFINITIONS: Dict[str, str] = {
    "Memory Region": "🗺️",  # for segments like ram, rom, etc.
    "Display": "🖼️",  # for display controller registers (lcd, backgrounds, sprites)
    "Sound": "🔊",  # for sound controller registers (apu channels)
    "DMA": "➡️",  # for direct memory access controller registers
    "Timers": "⏱️",  # for hardware timer registers
    "Serial IO": "↔️",  # for serial input/output registers (link cable)
    "Keypad": "🎮",  # for keypad input registers
    "Interrupts": "⚡",  # for interrupt controller registers (ie, if, ime)
    "System Control": "⚙️",  # for system control registers (waitstate, power)
    "Hardware Register": "🔩",  # a generic fallback for registers not fitting other categories
}

# this list defines known gba i/o registers. each entry is a tuple containing:
# (address, name_string, tag_type_name_string, description_string)
# - address: the memory-mapped i/o address of the register.
# - name_string: the conventional name of the register (e.g., "REG_DISPCNT").
# - tag_type_name_string: the category this register belongs to, must match a key in GBA_TAG_TYPE_DEFINITIONS.
# - description_string: a brief explanation of the register's purpose.
# names and descriptions use proper case for symbols and comments.
GBA_IO_REGISTER_DEFINITIONS: List[Tuple[int, str, str, str]] = [
    # display registers (0x4000000 - 0x400005F)
    (
        0x4000000,
        "REG_DISPCNT",
        "Display",
        "LCD Control (Video Mode, BG/OBJ Enable, Window Enable)",
    ),
    (
        0x4000004,
        "REG_DISPSTAT",
        "Display",
        "General LCD Status (VBlank, HBlank, VCounter Match)",
    ),
    (0x4000006, "REG_VCOUNT", "Display", "Vertical Counter (Current Scanline)"),
    (0x4000008, "REG_BG0CNT", "Display", "Background 0 Control"),
    (0x400000A, "REG_BG1CNT", "Display", "Background 1 Control"),
    (0x400000C, "REG_BG2CNT", "Display", "Background 2 Control"),
    (0x400000E, "REG_BG3CNT", "Display", "Background 3 Control"),
    (0x4000010, "REG_BG0HOFS", "Display", "Background 0 X-Offset (Scrolling)"),
    (0x4000012, "REG_BG0VOFS", "Display", "Background 0 Y-Offset (Scrolling)"),
    (0x4000014, "REG_BG1HOFS", "Display", "Background 1 X-Offset (Scrolling)"),
    (0x4000016, "REG_BG1VOFS", "Display", "Background 1 Y-Offset (Scrolling)"),
    (0x4000018, "REG_BG2HOFS", "Display", "Background 2 X-Offset (Scrolling)"),
    (0x400001A, "REG_BG2VOFS", "Display", "Background 2 Y-Offset (Scrolling)"),
    (0x400001C, "REG_BG3HOFS", "Display", "Background 3 X-Offset (Scrolling)"),
    (0x400001E, "REG_BG3VOFS", "Display", "Background 3 Y-Offset (Scrolling)"),
    (0x4000020, "REG_BG2PA", "Display", "BG2 Rotation/Scaling Parameter A (dx)"),
    (0x4000022, "REG_BG2PB", "Display", "BG2 Rotation/Scaling Parameter B (dmx)"),
    (0x4000024, "REG_BG2PC", "Display", "BG2 Rotation/Scaling Parameter C (dy)"),
    (0x4000026, "REG_BG2PD", "Display", "BG2 Rotation/Scaling Parameter D (dmy)"),
    (
        0x4000028,
        "REG_BG2X",
        "Display",
        "BG2 Reference Point X-Coordinate (28-bit integer part)",
    ),
    (
        0x400002C,
        "REG_BG2Y",
        "Display",
        "BG2 Reference Point Y-Coordinate (28-bit integer part)",
    ),
    (0x4000030, "REG_BG3PA", "Display", "BG3 Rotation/Scaling Parameter A (dx)"),
    (0x4000032, "REG_BG3PB", "Display", "BG3 Rotation/Scaling Parameter B (dmx)"),
    (0x4000034, "REG_BG3PC", "Display", "BG3 Rotation/Scaling Parameter C (dy)"),
    (0x4000036, "REG_BG3PD", "Display", "BG3 Rotation/Scaling Parameter D (dmy)"),
    (
        0x4000038,
        "REG_BG3X",
        "Display",
        "BG3 Reference Point X-Coordinate (28-bit integer part)",
    ),
    (
        0x400003C,
        "REG_BG3Y",
        "Display",
        "BG3 Reference Point Y-Coordinate (28-bit integer part)",
    ),
    (0x4000040, "REG_WIN0H", "Display", "Window 0 Horizontal Dimensions (X2, X1)"),
    (0x4000042, "REG_WIN1H", "Display", "Window 1 Horizontal Dimensions (X2, X1)"),
    (0x4000044, "REG_WIN0V", "Display", "Window 0 Vertical Dimensions (Y2, Y1)"),
    (0x4000046, "REG_WIN1V", "Display", "Window 1 Vertical Dimensions (Y2, Y1)"),
    (0x4000048, "REG_WININ", "Display", "Inside of Window 0 and 1 Layer Control"),
    (
        0x400004A,
        "REG_WINOUT",
        "Display",
        "Inside of OBJ Window & Outside of Windows Layer Control",
    ),
    (0x400004C, "REG_MOSAIC", "Display", "Mosaic Size (BG H/V, OBJ H/V)"),
    (
        0x4000050,
        "REG_BLDCNT",
        "Display",
        "Color Special Effects Selection (Blending Mode, Target Pixels)",
    ),
    (
        0x4000052,
        "REG_BLDALPHA",
        "Display",
        "Alpha Blending Coefficients (EVA for BGTarget1, EVB for BGTarget2)",
    ),
    (0x4000054, "REG_BLDY", "Display", "Brightness (Fade-In/Out) Coefficient (EVY)"),
    # sound registers (0x4000060 - 0x40000A7)
    (0x4000060, "REG_SOUND1CNT_L", "Sound", "Channel 1 Sweep control (NR10)"),
    (
        0x4000062,
        "REG_SOUND1CNT_H",
        "Sound",
        "Channel 1 Duty Cycle, Length, Envelope control (NR11, NR12)",
    ),
    (
        0x4000064,
        "REG_SOUND1CNT_X",
        "Sound",
        "Channel 1 Frequency, Control (NR13, NR14)",
    ),
    (
        0x4000068,
        "REG_SOUND2CNT_L",
        "Sound",
        "Channel 2 Duty Cycle, Length, Envelope control (NR21, NR22)",
    ),  # Corrected, was SOUND2CNT_H
    (
        0x400006C,
        "REG_SOUND2CNT_H",
        "Sound",
        "Channel 2 Frequency, Control (NR23, NR24)",
    ),
    (
        0x4000070,
        "REG_SOUND3CNT_L",
        "Sound",
        "Channel 3 Stop, Wave RAM select, Dimension (NR30)",
    ),
    (
        0x4000072,
        "REG_SOUND3CNT_H",
        "Sound",
        "Channel 3 Length, Volume control (NR31, NR32)",
    ),
    (
        0x4000074,
        "REG_SOUND3CNT_X",
        "Sound",
        "Channel 3 Frequency, Control (NR33, NR34)",
    ),
    (
        0x4000078,
        "REG_SOUND4CNT_L",
        "Sound",
        "Channel 4 Length, Envelope control (NR41, NR42)",
    ),
    (
        0x400007C,
        "REG_SOUND4CNT_H",
        "Sound",
        "Channel 4 Frequency, Polynomial Counter, Control (NR43, NR44)",
    ),
    (
        0x4000080,
        "REG_SOUNDCNT_L",
        "Sound",
        "Master Sound Control (Stereo Panning, Volume) (NR50, NR51)",
    ),
    (
        0x4000082,
        "REG_SOUNDCNT_H",
        "Sound",
        "Sound Channel Output Ratios, DMA Sound Control",
    ),
    (
        0x4000084,
        "REG_SOUNDCNT_X",
        "Sound",
        "Master Sound Enable, Channel Status (NR52)",
    ),
    (
        0x4000088,
        "REG_SOUNDBIAS",
        "Sound",
        "Sound PWM Bias Control, Amplitude Resolution",
    ),
    # symbol is defined at the start of this 16-byte mirrored region for wave ram
    (
        0x4000090,
        "REG_WAVE_RAM",
        "Sound",
        "Channel 3 Wave Pattern RAM (32x4-bit samples)",
    ),
    (0x40000A0, "REG_FIFO_A", "Sound", "Channel A (Direct Sound) FIFO Data Register"),
    (0x40000A4, "REG_FIFO_B", "Sound", "Channel B (Direct Sound) FIFO Data Register"),
    # dma registers (0x40000B0 - 0x40000DF)
    (
        0x40000B0,
        "REG_DMA0SAD",
        "DMA",
        "DMA 0 Source Address (Internal/External Memory)",
    ),
    (
        0x40000B4,
        "REG_DMA0DAD",
        "DMA",
        "DMA 0 Destination Address (Internal/External Memory)",
    ),
    (
        0x40000B8,
        "REG_DMA0CNT_L",
        "DMA",
        "DMA 0 Word Count (Number of 16/32-bit transfers)",
    ),
    (
        0x40000BA,
        "REG_DMA0CNT_H",
        "DMA",
        "DMA 0 Control (Enable, Timing, Transfer Type)",
    ),
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
    # timer registers (0x4000100 - 0x400010F)
    (0x4000100, "REG_TM0CNT_L", "Timers", "Timer 0 Counter/Reload Value"),
    (0x4000102, "REG_TM0CNT_H", "Timers", "Timer 0 Control (Enable, Mode, Prescaler)"),
    (0x4000104, "REG_TM1CNT_L", "Timers", "Timer 1 Counter/Reload Value"),
    (0x4000106, "REG_TM1CNT_H", "Timers", "Timer 1 Control"),
    (0x4000108, "REG_TM2CNT_L", "Timers", "Timer 2 Counter/Reload Value"),
    (0x400010A, "REG_TM2CNT_H", "Timers", "Timer 2 Control"),
    (0x400010C, "REG_TM3CNT_L", "Timers", "Timer 3 Counter/Reload Value"),
    (0x400010E, "REG_TM3CNT_H", "Timers", "Timer 3 Control"),
    # serial communication registers (0x4000120 - 0x400015B)
    (
        0x4000120,
        "REG_SIODATA32",
        "Serial IO",
        "SIO Data (Normal 32-bit Mode) / Multiplayer Data 0 (Parent)",
    ),
    # REG_SIOMULTI0 is an alias for REG_SIODATA32 when in multiplayer mode
    (0x4000122, "REG_SIOMULTI1", "Serial IO", "SIO Multiplayer Data 1 (Child 1)"),
    (0x4000124, "REG_SIOMULTI2", "Serial IO", "SIO Multiplayer Data 2 (Child 2)"),
    (0x4000126, "REG_SIOMULTI3", "Serial IO", "SIO Multiplayer Data 3 (Child 3)"),
    (
        0x4000128,
        "REG_SIOCNT",
        "Serial IO",
        "SIO Control Register (Mode, Speed, Interrupts)",
    ),
    (
        0x400012A,
        "REG_SIODATA8",
        "Serial IO",
        "SIO Data (Normal 8-bit/UART Mode) / Multiplayer Send Data",
    ),
    # REG_SIOMLT_SEND is an alias for REG_SIODATA8 when in multiplayer mode
    (
        0x4000134,
        "REG_RCNT",
        "Serial IO",
        "General Purpose I/O Mode Select / Data (R/CNT)",
    ),
    (0x4000140, "REG_JOYCNT", "Serial IO", "SIO JOY Bus Control"),
    (0x4000150, "REG_JOY_RECV", "Serial IO", "SIO JOY Bus Receive Data"),
    (0x4000154, "REG_JOY_TRANS", "Serial IO", "SIO JOY Bus Transmit Data"),
    (0x4000158, "REG_JOYSTAT", "Serial IO", "SIO JOY Bus Receive Status"),
    # keypad input (0x4000130 - 0x4000133)
    (
        0x4000130,
        "REG_KEYINPUT",
        "Keypad",
        "Key Input Status (Read-only, lists currently pressed keys)",
    ),
    (
        0x4000132,
        "REG_KEYCNT",
        "Keypad",
        "Key Interrupt Control (Enable keypad interrupt, condition)",
    ),
    # interrupt, waitstate, power control (0x4000200 - 0x4000301, 0x4000800)
    (
        0x4000200,
        "REG_IE",
        "Interrupts",
        "Interrupt Enable Register (Mask for enabling specific interrupts)",
    ),
    (
        0x4000202,
        "REG_IF",
        "Interrupts",
        "Interrupt Flag / Acknowledge Register (Identifies pending interrupts)",
    ),
    (
        0x4000204,
        "REG_WAITCNT",
        "System Control",
        "Game Pak Waitstate Control (Memory access timing)",
    ),
    (
        0x4000208,
        "REG_IME",
        "Interrupts",
        "Interrupt Master Enable Register (Global interrupt enable/disable)",
    ),
    (
        0x4000300,
        "REG_POSTFLG",
        "System Control",
        "Post Boot Flag (Undocumented, related to boot status)",
    ),
    (
        0x4000301,
        "REG_HALTCNT",
        "System Control",
        "Power Down Control (Undocumented, initiates low-power modes)",
    ),
    (
        0x4000800,
        "REG_INTERNAL_MEM_CNT",
        "System Control",
        "Internal Memory Control (Undocumented, possibly WRAM control/prefetch)",
    ),
]


# - gbaview class definition
class GBAView(BinaryView):
    """
    BinaryView class for loading and analyzing Game Boy Advance (GBA) ROM files.
    It sets up the GBA memory map, defines hardware registers, and identifies
    the entry point, preparing the ROM for further analysis in Binary Ninja.
    """

    name = "GBA"  # short name for the view type, used by binary ninja
    long_name = "Game Boy Advance ROM"  # descriptive name shown in the ui

    # - segment permission flags
    # these flag combinations are commonly used for defining memory segments.
    # SegmentReadable (R), SegmentWritable (W), SegmentExecutable (X)
    PERM_RWX: SegmentFlag = (
        SegmentFlag.SegmentReadable
        | SegmentFlag.SegmentWritable
        | SegmentFlag.SegmentExecutable
    )
    PERM_RW: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    PERM_RX: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
    PERM_R: SegmentFlag = SegmentFlag.SegmentReadable

    def __init__(self, data: BinaryView):
        """
        initializes the GBAView instance.
        this involves setting up the parent view (raw data), a dedicated logger,
        and configuring the architecture and platform specific to GBA.

        args:
            data: the BinaryView object containing the raw GBA ROM data.
                  this is typically the 'Raw' view of the file.
        """
        # initialize the base binaryview first, linking to the parent (raw) data.
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)

        # store a reference to the raw data view for direct access if needed.
        self.raw_data: BinaryView = data
        # create a logger instance specific to this plugin for organized logging.
        # BN.GBA helps distinguish logs from this plugin.
        self.logger: Logger = self.create_logger(f"BN.{self.name}")
        # cache for created tagtypes to avoid redundant api calls and improve performance.
        # keys are lowercase tag type names, values are the TagType objects.
        self._created_tag_types: Dict[str, TagType] = {}
        # get rom size from the raw view's length.
        self.rom_size: int = self.raw_data.length
        # placeholder for parsed header information, populated by _parse_rom_header.
        self.gba_header: Optional[GBAHeader] = None
        # store the defined entry point address for perform_get_entry_point.
        self._entry_point_address: Optional[int] = None

        # set architecture and platform. gba uses an armv4t processor,
        # which is generally compatible with the armv7 profile in binary ninja.
        try:
            # type ignore justification: architecture names are string literals used as keys.
            self.arch: Optional[Architecture] = Architecture["armv7"]  # type: ignore
            if not self.arch:
                self.logger.log_error(
                    "critical: armv7 architecture definition not found in binary ninja. GBA analysis requires it."
                )
                # this is a fatal error for the loader.
                raise RuntimeError("armv7 architecture definition not found.")

            # get the standalone platform associated with the armv7 architecture.
            self.platform: Optional[Platform] = self.arch.standalone_platform
            if not self.platform:
                self.logger.log_error(
                    f"critical: could not get standalone platform for architecture '{self.arch.name}'. GBA analysis cannot proceed."
                )
                # this is also a fatal error.
                raise RuntimeError(
                    f"failed to get standalone platform for {self.arch.name}."
                )
            self.logger.log_info(
                f"successfully set platform: {self.platform.name}, architecture: {self.arch.name}"
            )
        except KeyError:
            # this handles the specific case where "armv7" is not a recognized architecture key.
            self.logger.log_error(
                "critical: armv7 architecture key not found. this architecture is required for gba analysis."
            )
            raise RuntimeError("armv7 architecture key not found.")
        except Exception as e:
            # catch any other unexpected errors during this critical setup phase.
            self.logger.log_error(
                f"critical error during architecture or platform setup: {e}\n{traceback.format_exc()}"
            )
            raise  # re-raise to ensure initialization fails clearly and binary ninja handles it.

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        checks if the provided data is likely a gba rom.
        this is primarily done by looking for a specific fixed value (0x96)
        at a known offset (0xb2) in the header. this is a quick and common
        heuristic for GBA ROM identification.

        args:
            data: the BinaryView object containing the data to validate.

        returns:
            true if the data is likely a gba rom, false otherwise.
        """
        # ensure the data is large enough to contain the minimum header fields for validation.
        if data.length < GBA_HEADER_MIN_SIZE:
            # log at debug level as this is a common scenario for non-gba files.
            log_debug(
                f"[{cls.name}] validation: data length {data.length} is less than min header size {GBA_HEADER_MIN_SIZE}. not a gba rom."
            )
            return False

        # attempt to read the fixed value byte at offset 0xb2.
        # this byte should be 0x96 in a valid gba header.
        try:
            magic_byte_data = data.read(GBA_FIXED_VALUE_OFFSET, 1)
            if not magic_byte_data:
                # failed to read the byte, could be an issue with the data view or offset.
                log_debug(
                    f"[{cls.name}] validation: failed to read fixed value byte at offset 0x{GBA_FIXED_VALUE_OFFSET:x}."
                )
                return False

            magic_byte = magic_byte_data[0]  # get the byte value
            if magic_byte == 0x96:
                # the magic byte matches, this is likely a gba rom.
                log_info(
                    f"[{cls.name}] validation: found fixed value 0x96 in header at offset 0x{GBA_FIXED_VALUE_OFFSET:x}. identified as gba rom."
                )
                return True
            else:
                # the byte at the magic offset does not match.
                log_debug(
                    f"[{cls.name}] validation: fixed value at 0x{GBA_FIXED_VALUE_OFFSET:x} was 0x{magic_byte:02x}, expected 0x96. not a gba rom."
                )
                return False
        except Exception as e:
            # log an error if reading the byte fails for any unexpected reason.
            log_error(
                f"[{cls.name}] validation: error reading fixed value byte from header: {e}\n{traceback.format_exc()}"
            )
            return False

    # - helper methods for initialization

    def _parse_rom_header(self) -> bool:
        """
        parses key fields from the gba rom header using the defined constants
        and stores them in the `self.gba_header` dataclass instance.
        this includes the game title, game code, maker code, and software version.

        returns:
            true if header parsing was successful and all required fields were read, false otherwise.
        """
        self.logger.log_info("parsing gba rom header...")
        if self.rom_size < GBA_HEADER_MIN_SIZE:
            self.logger.log_error(
                f"rom is too small ({self.rom_size} bytes) to contain a valid gba header (min {GBA_HEADER_MIN_SIZE} bytes)."
            )
            return False
        try:
            # read various fields from the rom header.
            title_bytes = self.raw_data.read(GBA_GAME_TITLE_OFFSET, GBA_GAME_TITLE_SIZE)
            game_code_bytes = self.raw_data.read(
                GBA_GAME_CODE_OFFSET, GBA_GAME_CODE_SIZE
            )
            maker_code_bytes = self.raw_data.read(
                GBA_MAKER_CODE_OFFSET, GBA_MAKER_CODE_SIZE
            )
            software_version_byte = self.raw_data.read(GBA_SOFTWARE_VERSION_OFFSET, 1)

            # ensure all reads were successful (returned data).
            if not all(
                [title_bytes, game_code_bytes, maker_code_bytes, software_version_byte]
            ):
                self.logger.log_error(
                    "failed to read one or more essential header fields from the rom. header parsing aborted."
                )
                return False

            # decode bytes to strings, replacing errors and stripping null terminators.
            # ascii is standard for these fields, 'replace' handles non-ascii gracefully.
            game_title = title_bytes.decode("ascii", errors="replace").rstrip("\x00")
            game_code = game_code_bytes.decode("ascii", errors="replace").rstrip("\x00")
            maker_code = maker_code_bytes.decode("ascii", errors="replace").rstrip(
                "\x00"
            )
            software_version = software_version_byte[0]  # it's a single byte

            # populate the gba_header dataclass.
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
            # catch any other exceptions during parsing (e.g., decoding errors not caught by 'replace').
            self.logger.log_error(
                f"an unexpected error occurred while parsing gba header fields: {e}\n{traceback.format_exc()}"
            )
            self.gba_header = None  # ensure header is None on failure
            return False

    def _initialize_tag_types(self) -> None:
        """
        defines and caches all necessary tag types used by this view.
        it iterates through the global GBA_TAG_TYPE_DEFINITIONS dictionary.
        this ensures that tags for hardware registers and memory regions
        can be applied with appropriate icons and names in the ui.
        """
        self.logger.log_info("initializing gba hardware tag types...")
        initialized_count = 0
        for name, icon in GBA_TAG_TYPE_DEFINITIONS.items():
            if self._get_or_create_tag_type(name, icon):
                initialized_count += 1
            else:
                # warning if a specific tag type couldn't be set up.
                self.logger.log_warn(
                    f"could not initialize tag type: '{name}' with icon '{icon}'."
                )
        self.logger.log_info(
            f"{initialized_count}/{len(GBA_TAG_TYPE_DEFINITIONS)} tag types are now ready."
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

        # attempt to get the tag type using binary ninja's built-in lookup (case-insensitive).
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
        tag_category_name: str,  # e.g., "Display", "Sound", must be a key in GBA_TAG_TYPE_DEFINITIONS
        description: str = "",  # comment for the register
    ):
        """
        helper method to define a symbol for a hardware register at a given address
        and apply a descriptive tag to it for better organization in the ui.

        args:
            address: the memory address of the hardware register.
            name: the name for the register symbol (e.g., "REG_DISPCNT").
            tag_category_name: the category name of the tag type (e.g., "Display").
                               this must match a key in GBA_TAG_TYPE_DEFINITIONS.
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
            tag_icon = GBA_TAG_TYPE_DEFINITIONS.get(
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
        maps the core gba memory regions such as bios, wram, vram, i/o, rom, and sram.
        each region is defined as a segment with appropriate permissions (read, write, execute)
        and tagged for easier identification in the binary ninja interface.
        """
        self.logger.log_info("mapping gba memory regions...")

        # internal helper function to simplify adding memory regions as segments.
        # this promotes consistency in how segments are added and logged.
        def add_memory_segment(
            address: int,  # starting virtual address of the segment
            size: int,  # size of the segment in bytes
            permissions: SegmentFlag,  # R/W/X permissions (e.g., self.PERM_RX)
            name: str,  # descriptive name for the segment (e.g., "BIOS System ROM")
            tag_name: str = "Memory Region",  # category for the tag, defaults to "Memory Region"
            file_offset: int = 0,  # offset in the raw file data, if applicable (for rom)
            file_length: int = 0,  # length of data from file to map, if applicable (for rom)
        ):
            # log at debug level for individual segment mapping details.
            self.logger.log_debug(
                f"  preparing to map '{name}': address=0x{address:08x}, size=0x{size:06x} ({size // 1024} kb), permissions={permissions}"
            )
            try:
                # add the segment to the binary view.
                # file_offset and file_length are typically zero for ram/io regions not directly backed by the rom file.
                self.add_auto_segment(
                    address, size, file_offset, file_length, permissions
                )

                # get the appropriate tag type for this memory region.
                tag_icon = GBA_TAG_TYPE_DEFINITIONS.get(
                    tag_name, "🗺️"
                )  # default map icon
                tag_type = self._get_or_create_tag_type(tag_name, tag_icon)
                if tag_type:
                    # add a tag at the start of the region for easy identification in the ui.
                    # use the tag type's string name.
                    self.add_tag(address, tag_type.name, data=f"{name} Start")

                # add a comment at the start of the region indicating its name and size.
                self.set_comment_at(address, f"{name} ({size // 1024}KB)")
                # log successful mapping at info level.
                self.logger.log_info(f"  successfully mapped '{name}'.")
            except Exception as e:
                self.logger.log_error(
                    f"failed to map memory region '{name}' at 0x{address:08x}: {e}\n{traceback.format_exc()}"
                )

        # - define standard gba memory regions
        # bios system rom (16kb): 0x00000000 - 0x00003FFF
        # typically not present in rom files, so mapped as zero-filled and readable/executable.
        add_memory_segment(0x00000000, 0x4000, self.PERM_RX, "BIOS System ROM")

        # wram - on-board (slower, 256kb): 0x02000000 - 0x0203FFFF
        add_memory_segment(0x02000000, 0x40000, self.PERM_RWX, "WRAM - On-board")

        # wram - on-chip (faster, 32kb): 0x03000000 - 0x03007FFF
        add_memory_segment(0x03000000, 0x8000, self.PERM_RWX, "WRAM - On-chip")

        # i/o registers (approx 1kb, mapped up to 0x400): 0x04000000 - 0x040003FF
        # these are memory-mapped hardware control registers.
        add_memory_segment(
            0x04000000,
            0x0400,  # covers the main i/o block, specific registers are defined later.
            self.PERM_RW,  # i/o registers are typically readable and writable.
            "I/O Registers",
            tag_name="Hardware Register",  # use a specific tag category for i/o.
        )

        # palette ram (1kb): 0x05000000 - 0x050003FF
        # stores color palettes for backgrounds and sprites.
        add_memory_segment(0x05000000, 0x0400, self.PERM_RW, "Palette RAM")

        # vram - video ram (96kb): 0x06000000 - 0x06017FFF
        # stores tile data, sprite data, and framebuffers.
        add_memory_segment(0x06000000, 0x18000, self.PERM_RW, "VRAM")

        # oam - object attribute memory (1kb): 0x07000000 - 0x070003FF
        # stores attributes for sprites (objects).
        add_memory_segment(0x07000000, 0x0400, self.PERM_RW, "OAM")

        # game pak rom (up to 32mb): 0x08000000 - 0x09FFFFFF (Wait State 0)
        # also mirrored at 0x0A000000 (WS1) and 0x0C000000 (WS2).
        # this segment is mapped directly from the input rom file.
        rom_map_size = min(
            self.rom_size, 0x2000000
        )  # cap at 32mb for safety, though practically often smaller.
        if rom_map_size > 0:
            add_memory_segment(
                0x08000000,  # primary mapping for rom (waitstate 0)
                rom_map_size,
                self.PERM_RX,  # rom is typically readable and executable.
                "Game Pak ROM",
                file_offset=0,  # map from the beginning of the file.
                file_length=rom_map_size,  # map the actual size of the rom data.
            )
            # todo: consider adding mirrored segments for waitstate 1 (0x0Axxxxxx)
            # and waitstate 2 (0x0Cxxxxxx) if the rom is large enough.
            # this can be complex due to how binary ninja handles overlapping file mappings
            # in segments and might require careful handling of segment data sources.
            # for now, mapping the primary 0x08xxxxxx region is usually sufficient.
        else:
            self.logger.log_warn(
                "rom size is zero or negative, skipping game pak rom mapping."
            )

        # game pak sram (save ram, up to 64kb): 0x0E000000 - 0x0E00FFFF
        # the actual size varies by cartridge; we map a common maximum potential size.
        # this memory is typically battery-backed for saving game progress.
        add_memory_segment(0x0E000000, 0x10000, self.PERM_RW, "Game Pak SRAM")
        self.logger.log_info("finished mapping gba memory regions.")

    def _define_memory_sections(self) -> None:
        """
        defines sections based on the mapped memory segments.
        this helps binary ninja's analysis by providing semantic meaning to
        different memory areas, particularly for identifying code regions.
        sections are different from segments; segments define how file data maps to memory,
        while sections provide semantic information about those memory regions.
        """
        self.logger.log_info("defining memory sections...")
        # define a code section for the main rom segment to aid analysis.
        # the rom is typically mapped starting at 0x08000000.
        rom_base_address = 0x08000000
        rom_segment = self.get_segment_at(rom_base_address)
        if rom_segment:
            self.logger.log_debug(
                f"  attempting to add section '.text' for rom segment at 0x{rom_segment.start:08x}, length 0x{rom_segment.length:x}."
            )
            try:
                # ReadOnlyCodeSectionSemantics is appropriate for rom code.
                self.add_auto_section(
                    name=".text",  # a common convention for executable code sections.
                    start=rom_segment.start,
                    length=rom_segment.length,
                    semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                )
                self.logger.log_info(
                    "  successfully added '.text' section for game pak rom."
                )
            except Exception as e:
                self.logger.log_error(
                    f"failed to add '.text' section for rom: {e}\n{traceback.format_exc()}"
                )
        else:
            self.logger.log_warn(
                f"could not find rom segment at 0x{rom_base_address:08x} to define a code section. "
                "analysis of rom code may be incomplete or misidentified."
            )
        # other sections for wram, vram, etc., could be defined here if beneficial
        # for specific analysis tasks or plugin interactions (e.g., .data, .bss for wram).
        self.logger.log_info("finished defining memory sections.")

    def _define_all_io_registers(self) -> None:
        """
        defines symbols and tags for all known gba i/o registers
        as specified in the GBA_IO_REGISTER_DEFINITIONS list.
        this makes hardware registers easily identifiable in binary ninja.
        """
        self.logger.log_info("defining gba i/o hardware registers...")
        defined_count = 0
        for addr, name, tag_category, desc in GBA_IO_REGISTER_DEFINITIONS:
            self.logger.log_debug(
                f"  defining i/o register: {name} at 0x{addr:08x} (Category: {tag_category})"
            )
            self._define_hardware_register(addr, name, tag_category, desc)
            defined_count += 1
        self.logger.log_info(
            f"defined {defined_count}/{len(GBA_IO_REGISTER_DEFINITIONS)} i/o hardware registers."
        )

    def _define_rom_entry_point(self) -> None:
        """
        defines the primary entry point for gba roms.
        the standard entry point is at the beginning of the rom mapping, which is 0x08000000.
        this function adds this address as an entry point and attempts to define a function there.
        """
        entry_point_address = 0x08000000  # standard gba entry point in rom
        self.logger.log_info(
            f"defining rom entry point at 0x{entry_point_address:08x}."
        )

        # verify that the entry point address falls within an executable segment.
        # this is a sanity check before adding an entry point.
        segment_at_entry = self.get_segment_at(entry_point_address)
        if segment_at_entry and segment_at_entry.executable:
            try:
                # add the address as an official entry point to the binary view.
                self.add_entry_point(entry_point_address)
                # store this for perform_get_entry_point to return later.
                self._entry_point_address = entry_point_address

                # define a symbol for the entry point, commonly named '_start' or 'entry'.
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, entry_point_address, "_start")
                )
                # attempt to create a function at the entry point.
                # this helps kickstart disassembly and analysis from this known location.
                self.add_function(entry_point_address)
                self.logger.log_info(
                    f"successfully added entry point and created function '_start' at 0x{entry_point_address:08x}."
                )
            except Exception as e:
                self.logger.log_warn(
                    f"failed to fully define function at entry point 0x{entry_point_address:08x}: {e}. "
                    "entry point address itself was added, but function creation or symbol definition might have failed."
                )
        else:
            self.logger.log_error(
                f"cannot define entry point at 0x{entry_point_address:08x}. "
                "the address is not within an executable segment or the segment is missing. "
                "this may indicate an issue with memory mapping."
            )

    # - main initialization logic for the view
    def init(self) -> bool:
        """
        initializes the GBAView. this is the main setup method called by binary ninja
        after `is_valid_for_data` returns true. it orchestrates parsing the header,
        mapping memory, defining symbols and tags for hardware, and setting the entry point.

        returns:
            true if initialization was successful and the view is ready for analysis, false otherwise.
        """
        # architecture and platform should have been validated and set in __init__.
        # if they are not set, __init__ would have raised an error, preventing init from being called.
        # however, a defensive check can be included for robustness.
        if not self.arch or not self.platform:
            self.logger.log_error(
                "critical: architecture or platform is not set. cannot initialize GBAView."
            )
            return False  # should not happen if __init__ completed.

        try:
            self.logger.log_info(
                f"starting gba rom loading process for '{self.file.filename}'..."
            )

            # step 1: parse the rom header to extract metadata.
            # this is crucial for identifying the game and potentially for other loader logic.
            if not self._parse_rom_header():
                self.logger.log_error(
                    "failed to parse gba rom header. aborting load process."
                )
                return False  # cannot proceed reliably without header info if it's used later.

            # step 2: define all necessary tag types for gba specific elements (memory, hardware).
            self._initialize_tag_types()

            # step 3: map the gba memory layout (bios, ram, rom, io, etc.) into segments.
            self._map_memory_regions()

            # step 4: define sections based on the mapped segments (e.g., .text for rom code).
            self._define_memory_sections()

            # step 5: define symbols and tags for all known gba i/o registers.
            self._define_all_io_registers()

            # step 6: define the rom's entry point.
            self._define_rom_entry_point()

            # note: self.update_analysis_and_wait() is not called here.
            # the binary ninja core will handle triggering analysis after the loader's init() returns true.
            self.logger.log_info(
                "gba rom loading and setup steps complete. view is ready for analysis."
            )
            return True  # initialization successful

        except Exception as e:
            # catch any unexpected errors during the initialization process.
            self.logger.log_error(
                f"an unexpected error occurred during gba rom initialization: {e}\n{traceback.format_exc()}"
            )
            return False  # indicate failure to binary ninja.

    # - required binaryview method overrides
    # these methods are part of the BinaryView plugin interface and must be implemented.

    def perform_is_executable(self) -> bool:
        """
        indicates that gba roms contain executable code.
        """
        self.logger.log_debug("perform_is_executable called, returning true.")
        return True

    def perform_get_entry_point(self) -> int:
        """
        returns the primary entry point address of the gba rom.
        this is called by the binary ninja core after init() completes successfully.
        """
        if self._entry_point_address is not None:
            self.logger.log_debug(
                f"perform_get_entry_point called, returning stored entry point 0x{self._entry_point_address:08x}."
            )
            return self._entry_point_address
        else:
            # this case should ideally not be reached if init() succeeded and defined an entry point.
            # it indicates an issue in the loader's internal logic.
            self.logger.log_error(
                "perform_get_entry_point called but no entry point was stored during initialization. "
                "this indicates an issue in the loader's init process. returning default GBA entry 0x08000000 as a fallback."
            )
            return 0x08000000  # standard gba entry point, but signals a problem.

    def perform_get_address_size(self) -> int:
        """
        returns the address size for gba, which is 4 bytes (32-bit addresses).
        """
        self.logger.log_debug("perform_get_address_size called, returning 4 (32-bit).")
        return 4  # gba uses 32-bit addressing


# register the GBAView class with binary ninja so it can be used to open gba roms.
GBAView.register()
