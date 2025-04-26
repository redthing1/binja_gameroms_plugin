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
)
from binaryninja.log import Logger

from ..readers.nds_cartridge import (
    NDSRomReader,
    NDSRom,
    NDSCartridgeHeader,
    NDSOverlayTable,
    NDSFatEntry,
)

# --- nds hardware definitions ---

# dictionary mapping tag type names (proper case) to icons
NDS_TAG_TYPES: Dict[str, str] = {
    "Display": "🖼️",
    "DMA": "➡️",
    "Timers": "⏱️",
    "Keypad": "🎮",
    "IPC": "↔️",
    "Gamecard": "💾",
    "Interrupts": "⚡",
    "Power": "🔋",
    "Memory Control": "🐏",
    "Math": "➗",
    "3D Engine": "🧊",
    "Sound": "🔊",
    "SPI": "〰️",
    "RTC": "🕒",
    "Wifi": "📡",
    "System": "⚙️",
    "ARM9 Specific": "9️⃣",
    "ARM7 Specific": "7️⃣",
    "Hardcoded Addr": "📍",
    "Memory Region": "🗺️",
    "Hardware Register": "🔩",  # Generic fallback
}

# list of known i/o registers: (address, name, tag_type_name, description)
# names and descriptions use proper case for symbols/comments. tag_type_name matches NDS_TAG_TYPES keys.
NDS_IO_REGISTERS: List[Tuple[int, str, str, str]] = [
    # --- arm9 and arm7 common i/o registers ---
    (0x4000004, "REG_DISPSTAT", "Display", "Display Status (Shared)"),
    (0x4000006, "REG_VCOUNT", "Display", "Vertical Counter (Shared)"),
    # DMA (Common Part)
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
    # DMA Fill (ARM9 only?) - Tagging anyway
    (0x40000E0, "REG_DMA0FILL", "DMA", "DMA 0 Fill Data"),
    (0x40000E4, "REG_DMA1FILL", "DMA", "DMA 1 Fill Data"),
    (0x40000E8, "REG_DMA2FILL", "DMA", "DMA 2 Fill Data"),
    (0x40000EC, "REG_DMA3FILL", "DMA", "DMA 3 Fill Data"),
    # Timers (Common)
    (0x4000100, "REG_TM0CNT_L", "Timers", "Timer 0 Data/Reload"),
    (0x4000102, "REG_TM0CNT_H", "Timers", "Timer 0 Control"),
    (0x4000104, "REG_TM1CNT_L", "Timers", "Timer 1 Data/Reload"),
    (0x4000106, "REG_TM1CNT_H", "Timers", "Timer 1 Control"),
    (0x4000108, "REG_TM2CNT_L", "Timers", "Timer 2 Data/Reload"),
    (0x400010A, "REG_TM2CNT_H", "Timers", "Timer 2 Control"),
    (0x400010C, "REG_TM3CNT_L", "Timers", "Timer 3 Data/Reload"),
    (0x400010E, "REG_TM3CNT_H", "Timers", "Timer 3 Control"),
    # Keypad (Common)
    (0x4000130, "REG_KEYINPUT", "Keypad", "Key Status"),
    (0x4000132, "REG_KEYCNT", "Keypad", "Key Interrupt Control"),
    # IPC (Common)
    (0x4000180, "REG_IPCSYNC", "IPC", "IPC Synchronize Register"),
    (0x4000184, "REG_IPCFIFOCNT", "IPC", "IPC FIFO Control Register"),
    (0x4000188, "REG_IPCFIFOSEND", "IPC", "IPC Send FIFO (Write)"),
    (
        0x4100000,
        "REG_IPCFIFORECV",
        "IPC",
        "IPC Receive FIFO (Read)",
    ),  # Note different base
    # Gamecard (Common)
    (0x40001A0, "REG_AUXSPICNT", "Gamecard", "Card SPI Control / ROM Control"),
    (0x40001A2, "REG_AUXSPIDATA", "Gamecard", "Card SPI Data/Strobe"),
    (0x40001A4, "REG_ROMCTRL", "Gamecard", "Card Bus Timing/Control"),
    (0x40001A8, "REG_CARDCMD", "Gamecard", "Card Command (8 bytes)"),
    (
        0x4100010,
        "REG_CARDDATA",
        "Gamecard",
        "Card Data Read FIFO",
    ),  # Note different base
    (0x40001B0, "REG_CARD_SECKEY1_L", "Gamecard", "Seed 0/Key1 Low"),
    (0x40001B4, "REG_CARD_SECKEY2_L", "Gamecard", "Seed 1/Key2 Low (if used)"),
    (0x40001B8, "REG_CARD_SECKEY1_H", "Gamecard", "Seed 0/Key1 High (7 bits)"),
    (0x40001BA, "REG_CARD_SECKEY2_H", "Gamecard", "Seed 1/Key2 High (7 bits)"),
    # Interrupts (Common Part)
    (0x4000208, "REG_IME", "Interrupts", "Interrupt Master Enable (0/1)"),
    (0x4000210, "REG_IE", "Interrupts", "Interrupt Enable Bits"),
    (0x4000214, "REG_IF", "Interrupts", "Interrupt Request Flags (Write 1 to clear)"),
    # System (Common Part)
    (0x4000300, "REG_POSTFLG", "System", "Boot Flag? Undocumented"),
    (
        0x4000301,
        "REG_HALTCNT",
        "Power",
        "Power Down Control (NDS bits differ from GBA)",
    ),
    # --- arm9 specific i/o registers ---
    (0x4000000, "REG_DISPCNT_A", "Display", "Display Control (Engine A)"),
    (0x4000008, "REG_BG0CNT_A", "Display", "BG0 Control (Engine A)"),
    (0x400000A, "REG_BG1CNT_A", "Display", "BG1 Control (Engine A)"),
    (0x400000C, "REG_BG2CNT_A", "Display", "BG2 Control (Engine A)"),
    (0x400000E, "REG_BG3CNT_A", "Display", "BG3 Control (Engine A)"),
    (0x4000010, "REG_BG0HOFS_A", "Display", "BG0 X-Offset (Engine A)"),
    (0x4000012, "REG_BG0VOFS_A", "Display", "BG0 Y-Offset (Engine A)"),
    (0x4000014, "REG_BG1HOFS_A", "Display", "BG1 X-Offset (Engine A)"),
    (0x4000016, "REG_BG1VOFS_A", "Display", "BG1 Y-Offset (Engine A)"),
    (0x4000018, "REG_BG2HOFS_A", "Display", "BG2 X-Offset (Engine A)"),
    (0x400001A, "REG_BG2VOFS_A", "Display", "BG2 Y-Offset (Engine A)"),
    (0x400001C, "REG_BG3HOFS_A", "Display", "BG3 X-Offset (Engine A)"),
    (0x400001E, "REG_BG3VOFS_A", "Display", "BG3 Y-Offset (Engine A)"),
    (0x4000020, "REG_BG2PA_A", "Display", "BG2 Rot/Scale Param A (dx) (Engine A)"),
    (0x4000022, "REG_BG2PB_A", "Display", "BG2 Rot/Scale Param B (dmx) (Engine A)"),
    (0x4000024, "REG_BG2PC_A", "Display", "BG2 Rot/Scale Param C (dy) (Engine A)"),
    (0x4000026, "REG_BG2PD_A", "Display", "BG2 Rot/Scale Param D (dmy) (Engine A)"),
    (0x4000028, "REG_BG2X_A", "Display", "BG2 Reference Point X (Engine A)"),
    (0x400002C, "REG_BG2Y_A", "Display", "BG2 Reference Point Y (Engine A)"),
    (0x4000030, "REG_BG3PA_A", "Display", "BG3 Rot/Scale Param A (dx) (Engine A)"),
    (0x4000032, "REG_BG3PB_A", "Display", "BG3 Rot/Scale Param B (dmx) (Engine A)"),
    (0x4000034, "REG_BG3PC_A", "Display", "BG3 Rot/Scale Param C (dy) (Engine A)"),
    (0x4000036, "REG_BG3PD_A", "Display", "BG3 Rot/Scale Param D (dmy) (Engine A)"),
    (0x4000038, "REG_BG3X_A", "Display", "BG3 Reference Point X (Engine A)"),
    (0x400003C, "REG_BG3Y_A", "Display", "BG3 Reference Point Y (Engine A)"),
    (0x4000040, "REG_WIN0H_A", "Display", "Window 0 Horizontal Dimensions (Engine A)"),
    (0x4000042, "REG_WIN1H_A", "Display", "Window 1 Horizontal Dimensions (Engine A)"),
    (0x4000044, "REG_WIN0V_A", "Display", "Window 0 Vertical Dimensions (Engine A)"),
    (0x4000046, "REG_WIN1V_A", "Display", "Window 1 Vertical Dimensions (Engine A)"),
    (0x4000048, "REG_WININ_A", "Display", "Inside Window 0/1 Control (Engine A)"),
    (
        0x400004A,
        "REG_WINOUT_A",
        "Display",
        "Inside OBJ/Outside Window Control (Engine A)",
    ),
    (0x400004C, "REG_MOSAIC_A", "Display", "Mosaic Size (Engine A)"),
    (0x4000050, "REG_BLDCNT_A", "Display", "Color Special Effects Control (Engine A)"),
    (0x4000052, "REG_BLDALPHA_A", "Display", "Alpha Blending Coefficients (Engine A)"),
    (0x4000054, "REG_BLDY_A", "Display", "Brightness Coefficient (Engine A)"),
    (0x4000060, "REG_DISP3DCNT", "3D Engine", "3D Display Control"),
    (0x4000064, "REG_DISPCAPCNT", "Display", "Display Capture Control"),
    (0x4000068, "REG_DISP_MMEM_FIFO", "Display", "Main Memory Display FIFO"),
    (0x400006C, "REG_MASTER_BRIGHT_A", "Display", "Master Brightness (Engine A)"),
    (
        0x4000204,
        "REG_EXMEMCNT",
        "Memory Control",
        "External Memory Control (GBA Slot, etc.)",
    ),
    (0x4000240, "REG_VRAMCNT_A", "Memory Control", "VRAM-A Bank Control"),
    (0x4000241, "REG_VRAMCNT_B", "Memory Control", "VRAM-B Bank Control"),
    (0x4000242, "REG_VRAMCNT_C", "Memory Control", "VRAM-C Bank Control"),
    (0x4000243, "REG_VRAMCNT_D", "Memory Control", "VRAM-D Bank Control"),
    (0x4000244, "REG_VRAMCNT_E", "Memory Control", "VRAM-E Bank Control"),
    (0x4000245, "REG_VRAMCNT_F", "Memory Control", "VRAM-F Bank Control"),
    (0x4000246, "REG_VRAMCNT_G", "Memory Control", "VRAM-G Bank Control"),
    (0x4000247, "REG_WRAMCNT", "Memory Control", "WRAM Bank Control"),
    (0x4000248, "REG_VRAMCNT_H", "Memory Control", "VRAM-H Bank Control"),
    (0x4000249, "REG_VRAMCNT_I", "Memory Control", "VRAM-I Bank Control"),
    (0x4000280, "REG_DIVCNT", "Math", "Division Control"),
    (0x4000290, "REG_DIV_NUMER", "Math", "Division Numerator (64-bit)"),
    (0x4000298, "REG_DIV_DENOM", "Math", "Division Denominator (64-bit)"),
    (0x40002A0, "REG_DIV_RESULT", "Math", "Division Quotient Result (64-bit)"),
    (0x40002A8, "REG_DIVREM_RESULT", "Math", "Division Remainder Result (64-bit)"),
    (0x40002B0, "REG_SQRTCNT", "Math", "Square Root Control"),
    (0x40002B4, "REG_SQRT_RESULT", "Math", "Square Root Result (32-bit)"),
    (0x40002B8, "REG_SQRT_PARAM", "Math", "Square Root Parameter (64-bit)"),
    (0x4000304, "REG_POWCNT1", "Power", "Graphics/System Power Control 1"),
    # 3D Engine Registers (0x4000320 - 0x40006A3) - Define start/end tags
    (0x4000320, "NDS9_3D_REGS_START", "3D Engine", "NDS 3D Registers Start"),
    (
        0x40006A3,
        "NDS9_3D_REGS_END",
        "3D Engine",
        "NDS 3D Registers End",
    ),  # GBATEK doesn't specify end, using last known
    # Engine B Registers
    (0x4001000, "REG_DISPCNT_B", "Display", "Display Control (Engine B)"),
    (0x4001008, "REG_BG0CNT_B", "Display", "BG0 Control (Engine B)"),
    (0x400100A, "REG_BG1CNT_B", "Display", "BG1 Control (Engine B)"),
    (0x400100C, "REG_BG2CNT_B", "Display", "BG2 Control (Engine B)"),
    (0x400100E, "REG_BG3CNT_B", "Display", "BG3 Control (Engine B)"),
    (0x4001010, "REG_BG0HOFS_B", "Display", "BG0 X-Offset (Engine B)"),
    (0x4001012, "REG_BG0VOFS_B", "Display", "BG0 Y-Offset (Engine B)"),
    (0x4001014, "REG_BG1HOFS_B", "Display", "BG1 X-Offset (Engine B)"),
    (0x4001016, "REG_BG1VOFS_B", "Display", "BG1 Y-Offset (Engine B)"),
    (0x4001018, "REG_BG2HOFS_B", "Display", "BG2 X-Offset (Engine B)"),
    (0x400101A, "REG_BG2VOFS_B", "Display", "BG2 Y-Offset (Engine B)"),
    (0x400101C, "REG_BG3HOFS_B", "Display", "BG3 X-Offset (Engine B)"),
    (0x400101E, "REG_BG3VOFS_B", "Display", "BG3 Y-Offset (Engine B)"),
    (0x4001020, "REG_BG2PA_B", "Display", "BG2 Rot/Scale Param A (dx) (Engine B)"),
    (0x4001022, "REG_BG2PB_B", "Display", "BG2 Rot/Scale Param B (dmx) (Engine B)"),
    (0x4001024, "REG_BG2PC_B", "Display", "BG2 Rot/Scale Param C (dy) (Engine B)"),
    (0x4001026, "REG_BG2PD_B", "Display", "BG2 Rot/Scale Param D (dmy) (Engine B)"),
    (0x4001028, "REG_BG2X_B", "Display", "BG2 Reference Point X (Engine B)"),
    (0x400102C, "REG_BG2Y_B", "Display", "BG2 Reference Point Y (Engine B)"),
    (0x4001030, "REG_BG3PA_B", "Display", "BG3 Rot/Scale Param A (dx) (Engine B)"),
    (0x4001032, "REG_BG3PB_B", "Display", "BG3 Rot/Scale Param B (dmx) (Engine B)"),
    (0x4001034, "REG_BG3PC_B", "Display", "BG3 Rot/Scale Param C (dy) (Engine B)"),
    (0x4001036, "REG_BG3PD_B", "Display", "BG3 Rot/Scale Param D (dmy) (Engine B)"),
    (0x4001038, "REG_BG3X_B", "Display", "BG3 Reference Point X (Engine B)"),
    (0x400103C, "REG_BG3Y_B", "Display", "BG3 Reference Point Y (Engine B)"),
    (0x4001040, "REG_WIN0H_B", "Display", "Window 0 Horizontal Dimensions (Engine B)"),
    (0x4001042, "REG_WIN1H_B", "Display", "Window 1 Horizontal Dimensions (Engine B)"),
    (0x4001044, "REG_WIN0V_B", "Display", "Window 0 Vertical Dimensions (Engine B)"),
    (0x4001046, "REG_WIN1V_B", "Display", "Window 1 Vertical Dimensions (Engine B)"),
    (0x4001048, "REG_WININ_B", "Display", "Inside Window 0/1 Control (Engine B)"),
    (
        0x400104A,
        "REG_WINOUT_B",
        "Display",
        "Inside OBJ/Outside Window Control (Engine B)",
    ),
    (0x400104C, "REG_MOSAIC_B", "Display", "Mosaic Size (Engine B)"),
    (0x4001050, "REG_BLDCNT_B", "Display", "Color Special Effects Control (Engine B)"),
    (0x4001052, "REG_BLDALPHA_B", "Display", "Alpha Blending Coefficients (Engine B)"),
    (0x4001054, "REG_BLDY_B", "Display", "Brightness Coefficient (Engine B)"),
    (0x400106C, "REG_MASTER_BRIGHT_B", "Display", "Master Brightness (Engine B)"),
    # --- arm7 specific i/o registers ---
    (0x4000136, "REG_EXTKEYIN", "Keypad", "Extended Key Input (Lid, etc.)"),
    (0x4000138, "REG_RTCDATA", "RTC", "RTC Data Register (via SPI)"),
    (0x40001C0, "REG_SPICNT", "SPI", "SPI Control (Firmware, Touchscreen, Powerman)"),
    (0x40001C2, "REG_SPIDATA", "SPI", "SPI Data"),
    (
        0x4000204,
        "REG_EXMEMSTAT",
        "Memory Control",
        "External Memory Status (Read Only)",
    ),
    (0x4000240, "REG_VRAMSTAT", "Memory Control", "VRAM C,D Bank Status"),
    (0x4000241, "REG_WRAMSTAT", "Memory Control", "WRAM Bank Status"),
    (0x4000304, "REG_POWCNT2", "Power", "Sound/Wifi Power Control 2"),
    (0x4000308, "REG_BIOSPROT", "System", "BIOS Write Protection"),
    # Sound Registers (0x4000400 - 0x400051C) - Define start/end tags
    (0x4000400, "NDS7_SOUND_REGS_START", "Sound", "NDS Sound Registers Start"),
    (
        0x400051F,
        "NDS7_SOUND_REGS_END",
        "Sound",
        "NDS Sound Registers End",
    ),  # End is inclusive? Using +1
    (0x4000500, "REG_SOUNDCNT", "Sound", "Sound Control Register"),
    (0x4000504, "REG_SOUNDBIAS", "Sound", "Sound Bias Register"),
    (0x4000508, "REG_SNDCAP0CNT", "Sound", "Sound Capture 0 Control"),
    (0x4000509, "REG_SNDCAP1CNT", "Sound", "Sound Capture 1 Control"),
    (0x4000510, "REG_SNDCAP0DAD", "Sound", "Sound Capture 0 Destination Address"),
    (0x4000514, "REG_SNDCAP0LEN", "Sound", "Sound Capture 0 Length"),
    (0x4000518, "REG_SNDCAP1DAD", "Sound", "Sound Capture 1 Destination Address"),
    (0x400051C, "REG_SNDCAP1LEN", "Sound", "Sound Capture 1 Length"),
    # Wifi Registers (0x480xxxx) - Define start/end tags
    (0x4800000, "NDS7_WIFI_REGS_START", "Wifi", "NDS Wifi Registers Start"),
    (
        0x480FFFF,
        "NDS7_WIFI_REGS_END",
        "Wifi",
        "NDS Wifi Registers End",
    ),  # End is inclusive? Using +1
    # --- hardcoded ram addresses ---
    (
        0x0380FFF8,
        "NDS7_IRQ_CHECKBITS",
        "Hardcoded Addr",
        "ARM7 IRQ 'IF' Check Bits Mirror?",
    ),
    (
        0x0380FFFC,
        "NDS7_IRQ_HANDLER_PTR",
        "Hardcoded Addr",
        "ARM7 Pointer to IRQ Handler",
    ),
    (0x027FFFFE, "MAIN_MEM_CNT", "Hardcoded Addr", "Main Memory Control?"),
    # Add DTCM addresses if DTCM base is known/fixed
    # (0xDTCM_BASE + 0x3FF8, "NDS9_IRQ_CHECKBITS", "Hardcoded Addr", "ARM9 IRQ Check Bits"),
    # (0xDTCM_BASE + 0x3FFC, "NDS9_IRQ_HANDLER_PTR", "Hardcoded Addr", "ARM9 IRQ Handler"),
]


# --- ndsview class definition ---


class NDSView(BinaryView):
    """
    BinaryView class for loading and analyzing Nintendo DS ROM files.
    """

    name = "NDS"
    long_name = "Nintendo DS ROM"

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
        initializes the NDSView instance. minimal setup here.
        args:
            data: the BinaryView object containing the raw nds rom data.
        """
        # --- initialize the base binaryview *first* ---
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)

        # --- initialize instance variables *after* successful base init ---
        self.raw: BinaryView = data  # keep a reference to the raw data view
        self.log: Logger = self.create_logger("NDS")  # use "NDS" logger name.
        self._created_tag_types: Dict[str, TagType] = {}  # cache for created TagTypes.
        self.nds_rom: Optional[NDSRom] = None  # store parsed rom data

        # set architecture and platform (nds uses armv7 with thumb extensions)
        try:
            self.arch: Architecture = Architecture["armv7"]  # type: ignore
            self.platform: Platform = self.arch.standalone_platform  # type: ignore
            if not self.platform:
                log_error(
                    "[NDS] critical: could not get standalone platform for armv7."
                )
                raise RuntimeError("failed to get armv7 platform.")
            log_info(
                f"[NDS] using platform: {self.platform.name}, architecture: {self.arch.name}"
            )
        except KeyError:
            log_error("[NDS] critical: armv7 architecture not found.")
            raise RuntimeError("armv7 architecture not found.")
        except Exception as e:
            log_error(f"[NDS] critical error setting platform/arch: {e}")
            raise

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        checks if the data is likely an nds rom using a basic heuristic.
        the full validation (crc checks) is deferred to the init method.
        args:
            data: the BinaryView object containing the data.
        returns:
            true if the data is likely an nds rom, false otherwise.
        """
        try:
            # check for minimum header size needed for the logo magic
            if data.length < 0xC4:
                return False

            # check the first few bytes of the nintendo logo at 0xc0
            logo_magic = data.read(0xC0, 4)
            if logo_magic == b"\x24\xff\xae\x51":
                log_info("[NDS] validation: found nintendo logo magic bytes.")
                return True  # assume valid for now, full check in init()
            else:
                # log_warn("[NDS] validation: nintendo logo magic bytes mismatch.") # can be noisy
                return False
        except Exception as e:
            log_error(
                f"[NDS] error during basic validation check: {e}\n{traceback.format_exc()}"
            )
            return False

    # --- helper methods ---

    def _parse_rom_header(self) -> bool:
        """
        parses the nds rom header using ndsromreader.
        performs full validation and stores the result in self.nds_rom.
        returns true on success, false on failure.
        """
        self.log.log_info("reading entire rom into memory for header parsing...")
        rom_length = self.raw.length
        rom_data_bytes: bytes = self.raw.read(0, rom_length)
        if not rom_data_bytes or len(rom_data_bytes) != rom_length:
            self.log.log_error(
                f"failed to read full rom data ({len(rom_data_bytes)} read vs {rom_length} expected) from parent view."
            )
            return False

        # --- perform full validation here ---
        self.log.log_info("performing full header validation...")
        # use a larger chunk for validation if needed by is_valid
        validation_size = min(0x1000, rom_length)  # e.g., first 4kb
        if not NDSRomReader.is_valid(rom_data_bytes[:validation_size]):
            self.log.log_error(
                "full header validation failed via ndsromreader.is_valid."
            )
            self.log.log_warn(
                "continuing load despite header validation failure."
            )  # or return false for strictness
        else:
            self.log.log_info("full header validation successful.")
        # ------------------------------------

        self.log.log_info("parsing nds rom structure using ndsromreader...")
        self.nds_rom = NDSRomReader.read(rom_data_bytes)
        del rom_data_bytes  # free memory after parsing

        if not self.nds_rom or not self.nds_rom.header:
            self.log.log_error(
                "failed to parse nds rom header and structures (NDSRomReader.read returned None or header missing)."
            )
            return False
        return True

    def _define_tag_types(self):
        """
        defines and caches all necessary tag types used by this view.
        iterates through the global NDS_TAG_TYPES dictionary.
        """
        self.log.log_info("defining nds hardware tag types...")
        for name, icon in NDS_TAG_TYPES.items():
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
            name: the name of the register (symbol name, e.g., "REG_DISPSTAT").
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
        """maps the core nds memory regions (ram, vram, io, etc.)."""
        self.log.log_info("mapping nds memory regions...")

        # helper function to add segment and associated tag/comment.
        def add_memory_region(
            addr, size, perms, name, tag_name="Memory Region", tag_icon="🗺️"
        ):
            self.log.log_info(f"  mapping {name}: addr=0x{addr:08x}, size=0x{size:x}")
            # add the segment with zero offset/length from the file (it's ram or io).
            self.add_auto_segment(addr, size, 0, 0, perms)
            # get the tag type (use proper case name).
            tag_type = self._get_or_create_tag_type(tag_name, tag_icon)
            if tag_type:
                # add tag at the start of the region.
                self.add_tag(addr, tag_type, data=f"{name} Start")
            # add comment at the start of the region (proper case allowed here).
            self.set_comment_at(addr, f"{name} ({size // 1024}KB)")

        # main ram
        add_memory_region(0x02000000, 0x00400000, self.RWX_FLAGS, "Main RAM")
        # shared wram
        add_memory_region(0x03000000, 0x00008000, self.RWX_FLAGS, "Shared WRAM")
        add_memory_region(0x037F8000, 0x00008000, self.RWX_FLAGS, "Shared WRAM Mirror")
        # arm7 wram
        add_memory_region(0x03800000, 0x00010000, self.RWX_FLAGS, "ARM7 WRAM")
        # i/o registers
        add_memory_region(
            0x04000000,
            0x00001000,
            self.RW_FLAGS,
            "I/O Registers (Main Block)",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )
        add_memory_region(
            0x040001A0,
            0x000000C0,
            self.RW_FLAGS,
            "I/O Registers (Cart/IPC/SPI)",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )
        add_memory_region(
            0x04000200,
            0x00000100,
            self.RW_FLAGS,
            "I/O Registers (Mem/IRQ/Math)",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )
        add_memory_region(
            0x04000300,
            0x00000100,
            self.RW_FLAGS,
            "I/O Registers (Power/GFX)",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )
        add_memory_region(
            0x04000400,
            0x00000200,
            self.RW_FLAGS,
            "I/O Registers (Sound)",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )
        add_memory_region(
            0x04001000,
            0x00000100,
            self.RW_FLAGS,
            "I/O Registers (Engine B)",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )
        add_memory_region(
            0x04100000,
            0x00000020,
            self.RW_FLAGS,
            "IPC FIFO / Card Data",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )
        # palette ram
        add_memory_region(0x05000000, 0x00001000, self.RW_FLAGS, "Palette RAM")
        # vram
        add_memory_region(0x06000000, 0x000A4000, self.RW_FLAGS, "VRAM")
        add_memory_region(0x06800000, 0x000A4000, self.RW_FLAGS, "VRAM LCDC Mirror")
        # oam
        add_memory_region(0x07000000, 0x00001000, self.RW_FLAGS, "OAM")
        # arm9 bios
        add_memory_region(0xFFFF0000, 0x00004000, self.RX_FLAGS, "ARM9 BIOS")
        # arm7 bios is typically at 0x00000000, but that's handled by arm7 loading

    def _load_arm9(self):
        """loads the main arm9 binary, handling decompression and adding sections."""
        if not self.nds_rom or not self.nds_rom.header:
            self.log.log_error("cannot load arm9, rom header not parsed.")
            return

        header = self.nds_rom.header
        if header.arm9_size == 0:
            self.log.log_info("arm9 size is 0, skipping.")
            return

        self.log.log_info("loading arm9 binary...")
        arm9_data_raw: bytes = self.raw.read(header.arm9_rom_offset, header.arm9_size)
        if not arm9_data_raw:
            self.log.log_error(
                f"failed to read arm9 data from rom offset 0x{header.arm9_rom_offset:x}"
            )
            return

        final_arm9_data = arm9_data_raw
        final_size = header.arm9_size
        decompressed = False

        # try decompression
        try:
            decompressed_data = self._mii_uncompress_backward(arm9_data_raw)
            if len(decompressed_data) != len(arm9_data_raw):
                final_arm9_data = decompressed_data
                final_size = len(decompressed_data)
                decompressed = True
                self.log.log_info(
                    f"decompressed arm9: {header.arm9_size} bytes -> {final_size} bytes"
                )
            else:
                self.log.log_info(
                    "arm9 appears uncompressed or decompression yielded same data."
                )
        except Exception as e:
            self.log.log_warn(f"arm9 decompression failed: {e}. using raw data.")

        # add segment and load data
        load_address = header.arm9_ram_address
        if decompressed:
            # if decompressed, size changed, so add segment then write
            self.add_auto_segment(
                load_address, final_size, 0, final_size, self.RX_FLAGS
            )
            bytes_written = self.write(load_address, final_arm9_data)
            if bytes_written != final_size:
                self.log.log_error(
                    f"arm9 write error (decompressed): expected {final_size}, wrote {bytes_written}"
                )
                return  # fail if write fails
        else:
            # if not decompressed, map directly from file
            self.add_auto_segment(
                load_address,
                final_size,
                header.arm9_rom_offset,
                final_size,
                self.RX_FLAGS,
            )

        # add section for analysis
        self.add_auto_section(
            name=".arm9",  # simple name for the main binary
            start=load_address,
            length=final_size,
            semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            type="Code",
        )

        self.set_comment_at(
            load_address,
            f"ARM9 Binary Start{' (Decompressed)' if decompressed else ''}",
        )
        self.log.log_info(
            f"arm9 loaded: entry=0x{header.arm9_entry_address:08x}, load=0x{load_address:08x}, "
            f"size=0x{final_size:x}, offset=0x{header.arm9_rom_offset:08x} {'(decompressed)' if decompressed else '(raw mapped)'}"
        )

        # handle arm9 bss
        arm9_bss_size = getattr(header, "arm9_bss_size", 0)  # Get BSS size if available
        if arm9_bss_size > 0:
            bss_start = load_address + final_size
            self.log.log_info(
                f"  mapping arm9 bss: addr=0x{bss_start:08x}, size=0x{arm9_bss_size:x}"
            )
            self.add_auto_segment(bss_start, arm9_bss_size, 0, 0, self.RW_FLAGS)
            self.add_auto_section(
                name=".arm9.bss",
                start=bss_start,
                length=arm9_bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="BSS",
            )
            self.set_comment_at(bss_start, "ARM9 BSS Start")

    def _load_arm7(self):
        """loads the main arm7 binary and adds section."""
        if not self.nds_rom or not self.nds_rom.header:
            self.log.log_error("cannot load arm7, rom header not parsed.")
            return

        header = self.nds_rom.header
        if header.arm7_size == 0:
            self.log.log_info("arm7 size is 0, skipping loading.")
            return

        self.log.log_info("loading arm7 binary...")
        # arm7 is usually not compressed, map directly from file
        load_address = header.arm7_ram_address
        final_size = header.arm7_size
        self.add_auto_segment(
            load_address, final_size, header.arm7_rom_offset, final_size, self.RX_FLAGS
        )

        # add section for analysis
        self.add_auto_section(
            name=".arm7",  # simple name for the main binary
            start=load_address,
            length=final_size,
            semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            type="Code",
        )

        self.set_comment_at(load_address, "ARM7 Binary Start")
        self.log.log_info(
            f"arm7 loaded: entry=0x{header.arm7_entry_address:08x}, load=0x{load_address:08x}, "
            f"size=0x{final_size:x}, offset=0x{header.arm7_rom_offset:08x} (raw mapped)"
        )

        # handle arm7 bss
        arm7_bss_size = getattr(header, "arm7_bss_size", 0)  # Get BSS size if available
        if arm7_bss_size > 0:
            bss_start = load_address + final_size
            self.log.log_info(
                f"  mapping arm7 bss: addr=0x{bss_start:08x}, size=0x{arm7_bss_size:x}"
            )
            self.add_auto_segment(bss_start, arm7_bss_size, 0, 0, self.RW_FLAGS)
            self.add_auto_section(
                name=".arm7.bss",
                start=bss_start,
                length=arm7_bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="BSS",
            )
            self.set_comment_at(bss_start, "ARM7 BSS Start")

    def _load_overlays(self, cpu_name: str, overlay_table: Optional[NDSOverlayTable]):
        """
        loads arm9 or arm7 overlays, handling decompression and adding segments/sections.
        args:
            cpu_name: "ARM9" or "ARM7" for logging/naming.
            overlay_table: the parsed NDSOverlayTable object.
        """
        if not self.nds_rom or not overlay_table or not overlay_table.entries:
            self.log.log_info(f"no {cpu_name} overlays found or overlay table missing.")
            return

        self.log.log_info(f"loading {cpu_name} overlays...")
        num_loaded = 0
        num_failed = 0
        for i, entry in enumerate(overlay_table.entries):
            if entry.file_id == 0xFFFF or entry.file_id >= len(
                self.nds_rom.fat_entries
            ):
                # skip invalid file ids
                continue
            if entry.ram_size == 0 and entry.bss_size == 0:
                # skip empty overlays
                continue

            fat_entry = self.nds_rom.fat_entries[entry.file_id]
            if fat_entry.start_address >= fat_entry.end_address:
                self.log.log_warn(
                    f"skipping invalid {cpu_name} overlay {i} (file id {entry.file_id}): fat entry invalid."
                )
                num_failed += 1
                continue

            overlay_size_in_rom = fat_entry.end_address - fat_entry.start_address
            if overlay_size_in_rom <= 0:
                self.log.log_warn(
                    f"skipping invalid {cpu_name} overlay {i} (file id {entry.file_id}): non-positive size in rom."
                )
                num_failed += 1
                continue

            overlay_data_raw: bytes = self.raw.read(
                fat_entry.start_address, overlay_size_in_rom
            )
            if not overlay_data_raw:
                self.log.log_error(
                    f"failed to read {cpu_name} overlay {i} (file id {entry.file_id}) data from rom offset 0x{fat_entry.start_address:x}"
                )
                num_failed += 1
                continue

            loaded_data = b""
            segment_ram_size = 0
            decompressed = False
            if entry.ram_size > 0:
                try:
                    decompressed_data = self._mii_uncompress_backward(overlay_data_raw)
                    if len(decompressed_data) != entry.ram_size:
                        self.log.log_warn(
                            f"{cpu_name} overlay {i} (file id {entry.file_id}): decompressed size {len(decompressed_data):x} != expected ram size {entry.ram_size:x}. using decompressed size."
                        )
                        segment_ram_size = len(decompressed_data)
                    else:
                        segment_ram_size = entry.ram_size
                    loaded_data = decompressed_data
                    decompressed = True
                except Exception as e:
                    self.log.log_error(
                        f"failed to decompress {cpu_name} overlay {i} (file id {entry.file_id}): {e}. skipping."
                    )
                    num_failed += 1
                    continue
            else:  # ram_size is 0, only BSS
                segment_ram_size = 0
                loaded_data = b""

            segment_name_base = f"{cpu_name}_Overlay_{i}_File{entry.file_id}"
            load_address = entry.ram_address

            # add code/data segment (if size > 0) then write decompressed data
            if segment_ram_size > 0:
                self.add_auto_segment(
                    load_address, segment_ram_size, 0, segment_ram_size, self.RX_FLAGS
                )
                bytes_written = self.write(load_address, loaded_data[:segment_ram_size])
                if bytes_written != segment_ram_size:
                    self.log.log_error(
                        f"overlay {segment_name_base} write error: expected {segment_ram_size}, wrote {bytes_written}"
                    )
                    num_failed += 1
                    continue  # fail if write fails
                # add section for the loaded code/data part
                self.add_auto_section(
                    name=f".{segment_name_base}",
                    start=load_address,
                    length=segment_ram_size,
                    semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,  # Assume code
                    type="OverlayCode",
                )

            # add bss segment (if size > 0)
            if entry.bss_size > 0:
                bss_start_address = load_address + segment_ram_size
                self.add_auto_segment(
                    bss_start_address, entry.bss_size, 0, 0, self.RW_FLAGS
                )
                # add section for bss
                self.add_auto_section(
                    name=f".{segment_name_base}.bss",
                    start=bss_start_address,
                    length=entry.bss_size,
                    semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                    type="OverlayBSS",
                )
                self.set_comment_at(bss_start_address, f"{segment_name_base} BSS Start")

            self.set_comment_at(
                load_address,
                f"{segment_name_base} Start{' (Decompressed)' if decompressed else ''}",
            )

            # define static initializer function
            if entry.static_initializer_start_address != 0:
                init_start = entry.static_initializer_start_address
                func_addr = init_start & ~1  # ensure word alignment
                self.add_function(func_addr)
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, func_addr, f"{segment_name_base}_Init"))  # type: ignore
                self.set_comment_at(
                    func_addr, f"{segment_name_base} Static Initializer"
                )
                # TODO: Set thumb mode if init_start & 1 was true

            num_loaded += 1

        log_func = self.log.log_info if num_failed == 0 else self.log.log_warn
        log_func(
            f"loaded {num_loaded} / {len(overlay_table.entries)} {cpu_name} overlays ({num_failed} failures)."
        )

    def _mii_uncompress_backward(self, data: bytes) -> bytes:
        """
        decompresses data using mii lz77 variant (backward).
        raises ValueError or EOFError on failure.
        """
        if len(data) < 4:
            raise ValueError("data too short for mii decompression footer")
        footer = data[-4:]
        header_val = struct.unpack_from("<I", footer, 0)[0]
        comp_type = (header_val >> 24) & 0xF
        if comp_type == 1:  # Type 1 LZ77
            decompressed_size = header_val & 0xFFFFFF
        else:  # Other types (like Huffman) not supported here, assume size is full value
            # For simplicity, assume uncompressed if not type 1
            # A more robust implementation would check other types
            # raise ValueError(f"unsupported mii compression type: {comp_type}")
            decompressed_size = header_val  # Treat as uncompressed size? Or error?

        if decompressed_size == 0 and len(data) > 4:
            raise ValueError("decompressed size is zero but data is present.")
        if decompressed_size == 0:
            return b""  # Empty data is valid

        if decompressed_size < 0 or decompressed_size > 0x10000000:  # Sanity check size
            raise ValueError(f"invalid decompressed size: 0x{decompressed_size:x}")

        # Only handle type 1 LZ77 for now
        if comp_type != 1:
            self.log.log_warn(
                f"mii compression type {comp_type} encountered, treating as uncompressed."
            )
            return data[:-4]  # Return original data minus footer

        result = bytearray(decompressed_size)
        dst_offs = decompressed_size
        src_offs = len(data) - 4  # Start before footer

        while dst_offs > 0:
            if src_offs <= 0:
                raise EOFError(f"mii source data exhausted (dst_offs={dst_offs})")
            block_header = data[src_offs - 1]
            src_offs -= 1
            for i in range(8):
                if dst_offs <= 0:
                    break  # Finished decompression

                if (block_header & 0x80) == 0:  # Literal byte
                    if src_offs <= 0:
                        raise EOFError("mii source exhausted (literal)")
                    literal_byte = data[src_offs - 1]
                    src_offs -= 1
                    dst_offs -= 1
                    result[dst_offs] = literal_byte
                else:  # LZ77 copy block
                    if src_offs <= 1:
                        raise EOFError("mii source exhausted (lz77 block)")
                    byte1 = data[src_offs - 1]
                    byte2 = data[src_offs - 2]
                    src_offs -= 2
                    length = ((byte1 & 0xF0) >> 4) + 3
                    disp = (((byte1 & 0x0F) << 8) | byte2) + 1

                    if dst_offs < length:
                        raise ValueError(
                            f"mii lz77 copy length ({length}) exceeds dest space ({dst_offs})"
                        )

                    copy_src_base = dst_offs + disp
                    # Check bounds rigorously
                    if copy_src_base < 0 or copy_src_base + length > decompressed_size:
                        raise ValueError(
                            f"mii lz77 copy source offset {copy_src_base} or length {length} out of bounds (disp={disp}, dst_offs={dst_offs}, size={decompressed_size})"
                        )

                    # Copy bytes carefully, handling potential overlaps
                    for j in range(length):
                        result[dst_offs - 1] = result[
                            copy_src_base + j - 1
                        ]  # Read from potentially already written part
                        dst_offs -= 1
                        if dst_offs <= 0 and j < length - 1:
                            raise EOFError(
                                "mii destination filled unexpectedly during lz77 copy"
                            )

                block_header = (block_header << 1) & 0xFF  # Move to next bit

        if dst_offs != 0:
            # This might happen if the decompressed size in the footer was wrong
            self.log.log_warn(
                f"mii decompression: dst_offs non-zero ({dst_offs}) after loop. possible size mismatch."
            )

        return bytes(result)

    def _define_io_registers(self):
        """defines symbols and tags for known nds i/o registers."""
        self.log.log_info("defining nds hardware symbols and tags...")
        for addr, name, tag_name, desc in NDS_IO_REGISTERS:
            icon = NDS_TAG_TYPES.get(tag_name, "🔩")  # default icon
            self._define_reg_with_tag(addr, name, tag_name, icon, desc)

    def _define_entry_points(self):
        """defines entry points and start symbols for arm9 and arm7."""
        if not self.nds_rom or not self.nds_rom.header:
            self.log.log_error("cannot define entry points, rom header not parsed.")
            return

        header = self.nds_rom.header

        # arm9 entry point
        if header.arm9_size > 0:
            entry_point = header.arm9_entry_address
            self.log.log_info(f"defining arm9 entry point: 0x{entry_point:08x}")
            segment_at_entry = self.get_segment_at(entry_point)
            if segment_at_entry and segment_at_entry.executable:
                self.add_entry_point(entry_point)
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, entry_point, "_start9"))  # type: ignore
                try:
                    self.add_function(entry_point)
                except Exception as e:
                    self.log.log_warn(
                        f"failed to add function at arm9 entry 0x{entry_point:x}: {e}"
                    )
            else:
                self.log.log_warn(
                    f"arm9 entry point 0x{entry_point:x} not in executable segment."
                )

        # arm7 entry point
        if header.arm7_size > 0:
            entry_point = header.arm7_entry_address
            self.log.log_info(f"defining arm7 entry point: 0x{entry_point:08x}")
            segment_at_entry = self.get_segment_at(entry_point)
            if segment_at_entry and segment_at_entry.executable:
                self.add_entry_point(entry_point)
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, entry_point, "_start7"))  # type: ignore
                try:
                    self.add_function(entry_point)
                except Exception as e:
                    self.log.log_warn(
                        f"failed to add function at arm7 entry 0x{entry_point:x}: {e}"
                    )
            else:
                self.log.log_warn(
                    f"arm7 entry point 0x{entry_point:x} not in executable segment."
                )

        # debug arm9 entry point (if applicable) - typically no defined entry in header
        if header.debug_rom_offset != 0 and header.debug_size > 0:
            debug_load_addr = (
                header.debug_ram_address
                if header.debug_ram_address != 0
                else 0x02400000
            )
            self.log.log_info(
                f"debug arm9 loaded at 0x{debug_load_addr:08x}, no standard entry point defined."
            )
            # maybe add a symbol at the load address?
            self.define_auto_symbol(
                Symbol(
                    SymbolType.DataSymbol, debug_load_addr, "arm9_debug_load_address"
                )
            )

    # --- main initialization logic ---

    def init(self) -> bool:
        """
        initializes the NDSView by parsing the header, mapping memory regions,
        loading binaries, defining sections, symbols, and tags.
        returns:
            true on successful initialization, false otherwise.
        """
        # platform/arch should be valid here if __init__ succeeded.

        try:
            self.log.log_info("starting nds rom loading process...")

            # --- main loading steps ---
            if not self._parse_rom_header():
                return False
            self._define_tag_types()
            self._map_memory_regions()
            self._load_arm9()
            self._load_arm7()
            self._load_overlays(
                "ARM9", self.nds_rom.arm9_overlay_table if self.nds_rom else None
            )
            self._load_overlays(
                "ARM7", self.nds_rom.arm7_overlay_table if self.nds_rom else None
            )
            # load debug info if present (optional step)
            # if self.nds_rom and self.nds_rom.header.debug_rom_offset != 0 and self.nds_rom.header.debug_size > 0:
            #    self._init_debug_arm9() # Assuming this helper exists or is added
            self._define_io_registers()
            self._define_entry_points()

            # --- final analysis update ---
            self.log.log_info("nds rom loading complete. updating analysis...")
            self.update_analysis_and_wait()
            self.log.log_info("analysis update finished.")

            return True  # initialization successful

        except Exception as e:
            # catch any unexpected errors during initialization
            log_error(f"[NDS] failed to initialize ndsview: {e}")
            log_error(traceback.format_exc())
            return False  # indicate failure

    # --- required binaryview methods ---

    def perform_is_executable(self) -> bool:
        """nds roms contain executable code"""
        return True

    def perform_get_entry_point(self) -> int:
        """returns the primary (arm9) entry point address"""
        # this is called by the core *after* init() completes.
        if len(self.entry_points) > 0:
            # prefer the first entry point added (usually arm9)
            return self.entry_points[0]
        elif self.nds_rom and self.nds_rom.header:
            # fallback to header value if no entry points were added somehow
            return self.nds_rom.header.arm9_entry_address
        else:
            # ultimate fallback
            log_warn(
                "[NDS] perform_get_entry_point called but no entry points defined and header not parsed. returning start address."
            )
            return self.start

    def perform_get_address_size(self) -> int:
        """nds uses 32-bit addresses"""
        return 4


NDSView.register()
