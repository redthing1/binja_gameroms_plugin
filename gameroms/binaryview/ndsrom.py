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
    NDSOverlayEntry,
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
    "Memory Control": "🐏",  # for ram, vram, tcm control registers
    "Math": "➗",  # for hardware math units (div, sqrt)
    "3D Engine": "🧊",
    "Sound": "🔊",
    "SPI": "〰️",  # for serial peripheral interface
    "RTC": "🕒",  # real-time clock
    "Wifi": "📡",
    "System": "⚙️",  # for general system control, bios protection etc.
    "ARM9 Specific": "9️⃣",  # registers only accessible/relevant to arm9
    "ARM7 Specific": "7️⃣",  # registers only accessible/relevant to arm7
    "Hardcoded Addr": "📍",  # special hardcoded ram addresses (e.g. irq handlers)
    "Memory Region": "🗺️",  # for mapped memory segments
    "Hardware Register": "🔩",  # generic fallback for i/o registers
}

# list of known i/o registers: (address, name, tag_type_name, description from tech docs)
# names and descriptions use proper case for symbols/comments. tag_type_name matches nds_tag_types keys.
NDS_IO_REGISTERS: List[Tuple[int, str, str, str]] = [
    # --- arm9 and arm7 common i/o registers (accessible by both cpus, though some may be specific in function) ---
    # --- display status / vertical count (shared between 2d engine a and b) ---
    (
        0x4000004,
        "REG_DISPSTAT",
        "Display",
        "General LCD Status (R/W)",
    ),  # shared by 2d engine a & b
    (
        0x4000006,
        "REG_VCOUNT",
        "Display",
        "Vertical Counter (Read only)",
    ),  # shared by 2d engine a & b
    # --- dma channels 0-3 (shared base address, individual control/functionality per cpu) ---
    (0x40000B0, "REG_DMA0SAD", "DMA", "DMA 0 Source Address (R/W)"),
    (0x40000B4, "REG_DMA0DAD", "DMA", "DMA 0 Destination Address (R/W)"),
    (0x40000B8, "REG_DMA0CNT_L", "DMA", "DMA 0 Word Count (R/W)"),
    (0x40000BA, "REG_DMA0CNT_H", "DMA", "DMA 0 Control (R/W)"),
    (0x40000BC, "REG_DMA1SAD", "DMA", "DMA 1 Source Address (R/W)"),
    (0x40000C0, "REG_DMA1DAD", "DMA", "DMA 1 Destination Address (R/W)"),
    (0x40000C4, "REG_DMA1CNT_L", "DMA", "DMA 1 Word Count (R/W)"),
    (0x40000C6, "REG_DMA1CNT_H", "DMA", "DMA 1 Control (R/W)"),
    (0x40000C8, "REG_DMA2SAD", "DMA", "DMA 2 Source Address (R/W)"),
    (0x40000CC, "REG_DMA2DAD", "DMA", "DMA 2 Destination Address (R/W)"),
    (0x40000D0, "REG_DMA2CNT_L", "DMA", "DMA 2 Word Count (R/W)"),
    (0x40000D2, "REG_DMA2CNT_H", "DMA", "DMA 2 Control (R/W)"),
    (0x40000D4, "REG_DMA3SAD", "DMA", "DMA 3 Source Address (R/W)"),
    (0x40000D8, "REG_DMA3DAD", "DMA", "DMA 3 Destination Address (R/W)"),
    (0x40000DC, "REG_DMA3CNT_L", "DMA", "DMA 3 Word Count (R/W)"),
    (0x40000DE, "REG_DMA3CNT_H", "DMA", "DMA 3 Control (R/W)"),
    # --- dma fill registers (arm9 i/o map lists these, arm7 does not; primarily arm9) ---
    (0x40000E0, "REG_DMA0FILL", "DMA", "DMA 0 Fill Data (W) (ARM9)"),
    (0x40000E4, "REG_DMA1FILL", "DMA", "DMA 1 Fill Data (W) (ARM9)"),
    (0x40000E8, "REG_DMA2FILL", "DMA", "DMA 2 Fill Data (W) (ARM9)"),
    (0x40000EC, "REG_DMA3FILL", "DMA", "DMA 3 Fill Data (W) (ARM9)"),
    # --- timers 0-3 (shared base address) ---
    (0x4000100, "REG_TM0CNT_L", "Timers", "Timer 0 Data/Reload (R/W)"),
    (0x4000102, "REG_TM0CNT_H", "Timers", "Timer 0 Control (R/W)"),
    (0x4000104, "REG_TM1CNT_L", "Timers", "Timer 1 Data/Reload (R/W)"),
    (0x4000106, "REG_TM1CNT_H", "Timers", "Timer 1 Control (R/W)"),
    (0x4000108, "REG_TM2CNT_L", "Timers", "Timer 2 Data/Reload (R/W)"),
    (0x400010A, "REG_TM2CNT_H", "Timers", "Timer 2 Control (R/W)"),
    (0x400010C, "REG_TM3CNT_L", "Timers", "Timer 3 Data/Reload (R/W)"),
    (0x400010E, "REG_TM3CNT_H", "Timers", "Timer 3 Control (R/W)"),
    # --- keypad input (shared) ---
    (0x4000130, "REG_KEYINPUT", "Keypad", "Key Status (Read only)"),
    (0x4000132, "REG_KEYCNT", "Keypad", "Key Interrupt Control (R/W)"),
    # --- inter-processor communication (ipc) fifo (shared) ---
    (0x4000180, "REG_IPCSYNC", "IPC", "IPC Synchronize Register (R/W)"),
    (0x4000184, "REG_IPCFIFOCNT", "IPC", "IPC FIFO Control Register (R/W)"),
    (0x4000188, "REG_IPCFIFOSEND", "IPC", "IPC Send FIFO (Write only)"),
    (
        0x4100000,
        "REG_IPCFIFORECV",
        "IPC",
        "IPC Receive FIFO (Read only)",
    ),  # note different base for arm9/arm7 receive
    # --- gamecard (slot-1) interface (shared) ---
    (
        0x40001A0,
        "REG_AUXSPICNT",
        "Gamecard",
        "Gamecard ROM and SPI Control (R/W)",
    ),  # also called romctrl1 by some sources
    (0x40001A2, "REG_AUXSPIDATA", "Gamecard", "Gamecard SPI Bus Data/Strobe (R/W)"),
    (
        0x40001A4,
        "REG_ROMCTRL",
        "Gamecard",
        "Gamecard Bus Timing/Control (R/W)",
    ),  # also called romctrl2
    (0x40001A8, "REG_CARDCMD", "Gamecard", "Gamecard Bus Command Out (8 bytes) (W)"),
    (
        0x4100010,
        "REG_CARDDATA",
        "Gamecard",
        "Gamecard Bus Data In (4 bytes) (Read only)",
    ),  # note different base for data in
    # --- gamecard encryption seeds (shared, though primarily used by arm9 for setup) ---
    (
        0x40001B0,
        "REG_CARD_SECKEY1_L",
        "Gamecard",
        "Gamecard Encryption Seed 0 Lower 32bit (R/W)",
    ),
    (
        0x40001B4,
        "REG_CARD_SECKEY2_L",
        "Gamecard",
        "Gamecard Encryption Seed 1 Lower 32bit (R/W)",
    ),
    (
        0x40001B8,
        "REG_CARD_SECKEY1_H",
        "Gamecard",
        "Gamecard Encryption Seed 0 Upper 7bit (R/W)",
    ),
    (
        0x40001BA,
        "REG_CARD_SECKEY2_H",
        "Gamecard",
        "Gamecard Encryption Seed 1 Upper 7bit (R/W)",
    ),
    # --- interrupt master enable / enable / flags (shared) ---
    (0x4000208, "REG_IME", "Interrupts", "Interrupt Master Enable (0/1) (R/W)"),
    (0x4000210, "REG_IE", "Interrupts", "Interrupt Enable Bits (R/W)"),
    (
        0x4000214,
        "REG_IF",
        "Interrupts",
        "Interrupt Request Flags (R/W, write 1 to clear)",
    ),
    # --- system control (shared, some undocumented or behavior differs) ---
    (0x4000300, "REG_POSTFLG", "System", "POST Boot Flag (R/W, Undocumented)"),
    (
        0x4000301,
        "REG_HALTCNT",
        "Power",
        "Power Down Control / Halt Control (W) (NDS bits differ from GBA)",
    ),
    # --- arm9 specific i/o registers ---
    # --- arm9 2d engine a ---
    (0x4000000, "REG_DISPCNT_A", "Display", "2D Engine A - LCD Control (R/W) (ARM9)"),
    # 0x4000008 - 0x4000055 : 2D Engine A BG/Window/Mosaic/Blend registers (similar to GBA)
    (0x4000008, "REG_BG0CNT_A", "Display", "2D Engine A - BG0 Control (R/W) (ARM9)"),
    (0x400000A, "REG_BG1CNT_A", "Display", "2D Engine A - BG1 Control (R/W) (ARM9)"),
    (0x400000C, "REG_BG2CNT_A", "Display", "2D Engine A - BG2 Control (R/W) (ARM9)"),
    (0x400000E, "REG_BG3CNT_A", "Display", "2D Engine A - BG3 Control (R/W) (ARM9)"),
    (0x4000010, "REG_BG0HOFS_A", "Display", "2D Engine A - BG0 X-Offset (W) (ARM9)"),
    (0x4000012, "REG_BG0VOFS_A", "Display", "2D Engine A - BG0 Y-Offset (W) (ARM9)"),
    (0x4000014, "REG_BG1HOFS_A", "Display", "2D Engine A - BG1 X-Offset (W) (ARM9)"),
    (0x4000016, "REG_BG1VOFS_A", "Display", "2D Engine A - BG1 Y-Offset (W) (ARM9)"),
    (0x4000018, "REG_BG2HOFS_A", "Display", "2D Engine A - BG2 X-Offset (W) (ARM9)"),
    (0x400001A, "REG_BG2VOFS_A", "Display", "2D Engine A - BG2 Y-Offset (W) (ARM9)"),
    (0x400001C, "REG_BG3HOFS_A", "Display", "2D Engine A - BG3 X-Offset (W) (ARM9)"),
    (0x400001E, "REG_BG3VOFS_A", "Display", "2D Engine A - BG3 Y-Offset (W) (ARM9)"),
    (
        0x4000020,
        "REG_BG2PA_A",
        "Display",
        "2D Engine A - BG2 Rotation/Scaling Parameter A (dx) (W) (ARM9)",
    ),
    (
        0x4000022,
        "REG_BG2PB_A",
        "Display",
        "2D Engine A - BG2 Rotation/Scaling Parameter B (dmx) (W) (ARM9)",
    ),
    (
        0x4000024,
        "REG_BG2PC_A",
        "Display",
        "2D Engine A - BG2 Rotation/Scaling Parameter C (dy) (W) (ARM9)",
    ),
    (
        0x4000026,
        "REG_BG2PD_A",
        "Display",
        "2D Engine A - BG2 Rotation/Scaling Parameter D (dmy) (W) (ARM9)",
    ),
    (
        0x4000028,
        "REG_BG2X_A",
        "Display",
        "2D Engine A - BG2 Reference Point X (Internal) (W) (ARM9)",
    ),
    (
        0x400002C,
        "REG_BG2Y_A",
        "Display",
        "2D Engine A - BG2 Reference Point Y (Internal) (W) (ARM9)",
    ),
    (
        0x4000030,
        "REG_BG3PA_A",
        "Display",
        "2D Engine A - BG3 Rotation/Scaling Parameter A (dx) (W) (ARM9)",
    ),
    (
        0x4000032,
        "REG_BG3PB_A",
        "Display",
        "2D Engine A - BG3 Rotation/Scaling Parameter B (dmx) (W) (ARM9)",
    ),
    (
        0x4000034,
        "REG_BG3PC_A",
        "Display",
        "2D Engine A - BG3 Rotation/Scaling Parameter C (dy) (W) (ARM9)",
    ),
    (
        0x4000036,
        "REG_BG3PD_A",
        "Display",
        "2D Engine A - BG3 Rotation/Scaling Parameter D (dmy) (W) (ARM9)",
    ),
    (
        0x4000038,
        "REG_BG3X_A",
        "Display",
        "2D Engine A - BG3 Reference Point X (Internal) (W) (ARM9)",
    ),
    (
        0x400003C,
        "REG_BG3Y_A",
        "Display",
        "2D Engine A - BG3 Reference Point Y (Internal) (W) (ARM9)",
    ),
    (
        0x4000040,
        "REG_WIN0H_A",
        "Display",
        "2D Engine A - Window 0 Horizontal Dimensions (W) (ARM9)",
    ),
    (
        0x4000042,
        "REG_WIN1H_A",
        "Display",
        "2D Engine A - Window 1 Horizontal Dimensions (W) (ARM9)",
    ),
    (
        0x4000044,
        "REG_WIN0V_A",
        "Display",
        "2D Engine A - Window 0 Vertical Dimensions (W) (ARM9)",
    ),
    (
        0x4000046,
        "REG_WIN1V_A",
        "Display",
        "2D Engine A - Window 1 Vertical Dimensions (W) (ARM9)",
    ),
    (
        0x4000048,
        "REG_WININ_A",
        "Display",
        "2D Engine A - Inside Window 0/1 Control (R/W) (ARM9)",
    ),
    (
        0x400004A,
        "REG_WINOUT_A",
        "Display",
        "2D Engine A - Inside OBJ/Outside Window Control (R/W) (ARM9)",
    ),
    (0x400004C, "REG_MOSAIC_A", "Display", "2D Engine A - Mosaic Size (W) (ARM9)"),
    (
        0x4000050,
        "REG_BLDCNT_A",
        "Display",
        "2D Engine A - Color Special Effects Control (R/W) (ARM9)",
    ),
    (
        0x4000052,
        "REG_BLDALPHA_A",
        "Display",
        "2D Engine A - Alpha Blending Coefficients (R/W) (ARM9)",
    ),
    (
        0x4000054,
        "REG_BLDY_A",
        "Display",
        "2D Engine A - Brightness Coefficient (W) (ARM9)",
    ),
    # --- arm9 3d display / capture / master bright ---
    (
        0x4000060,
        "REG_DISP3DCNT",
        "3D Engine",
        "3D Display Control Register (R/W) (ARM9)",
    ),
    (
        0x4000064,
        "REG_DISPCAPCNT",
        "Display",
        "Display Capture Control Register (R/W) (ARM9)",
    ),
    (
        0x4000068,
        "REG_DISP_MMEM_FIFO",
        "Display",
        "Main Memory Display FIFO (R?/W) (ARM9)",
    ),  # for transferring data to VRAM for display
    (
        0x400006C,
        "REG_MASTER_BRIGHT_A",
        "Display",
        "2D Engine A - Master Brightness Up/Down (W) (ARM9)",
    ),
    # --- arm9 memory control (exmemcnt, vram/wram cnt) ---
    (
        0x4000204,
        "REG_EXMEMCNT",
        "Memory Control",
        "External Memory Control (GBA Slot, etc.) (R/W) (ARM9)",
    ),
    (
        0x4000240,
        "REG_VRAMCNT_A",
        "Memory Control",
        "VRAM-A (128K) Bank Control (W) (ARM9)",
    ),
    (
        0x4000241,
        "REG_VRAMCNT_B",
        "Memory Control",
        "VRAM-B (128K) Bank Control (W) (ARM9)",
    ),
    (
        0x4000242,
        "REG_VRAMCNT_C",
        "Memory Control",
        "VRAM-C (128K) Bank Control (W) (ARM9)",
    ),
    (
        0x4000243,
        "REG_VRAMCNT_D",
        "Memory Control",
        "VRAM-D (128K) Bank Control (W) (ARM9)",
    ),
    (
        0x4000244,
        "REG_VRAMCNT_E",
        "Memory Control",
        "VRAM-E (64K) Bank Control (W) (ARM9)",
    ),
    (
        0x4000245,
        "REG_VRAMCNT_F",
        "Memory Control",
        "VRAM-F (16K) Bank Control (W) (ARM9)",
    ),
    (
        0x4000246,
        "REG_VRAMCNT_G",
        "Memory Control",
        "VRAM-G (16K) Bank Control (W) (ARM9)",
    ),
    (
        0x4000247,
        "REG_WRAMCNT",
        "Memory Control",
        "WRAM Bank Control (for Shared WRAM) (W) (ARM9)",
    ),
    (
        0x4000248,
        "REG_VRAMCNT_H",
        "Memory Control",
        "VRAM-H (32K) Bank Control (W) (ARM9)",
    ),
    (
        0x4000249,
        "REG_VRAMCNT_I",
        "Memory Control",
        "VRAM-I (16K) Bank Control (W) (ARM9)",
    ),
    # --- arm9 math hardware (division, square root) ---
    (0x4000280, "REG_DIVCNT", "Math", "Division Control (R/W) (ARM9)"),
    (0x4000290, "REG_DIV_NUMER", "Math", "Division Numerator (64-bit) (R/W) (ARM9)"),
    (0x4000298, "REG_DIV_DENOM", "Math", "Division Denominator (64-bit) (R/W) (ARM9)"),
    (
        0x40002A0,
        "REG_DIV_RESULT",
        "Math",
        "Division Quotient Result (64-bit) (Read only) (ARM9)",
    ),
    (
        0x40002A8,
        "REG_DIVREM_RESULT",
        "Math",
        "Division Remainder Result (64-bit) (Read only) (ARM9)",
    ),
    (0x40002B0, "REG_SQRTCNT", "Math", "Square Root Control (R/W) (ARM9)"),
    (
        0x40002B4,
        "REG_SQRT_RESULT",
        "Math",
        "Square Root Result (32-bit) (Read only) (ARM9)",
    ),
    (
        0x40002B8,
        "REG_SQRT_PARAM",
        "Math",
        "Square Root Parameter Input (64-bit) (R/W) (ARM9)",
    ),
    (
        0x4000304,
        "REG_POWCNT1",
        "Power",
        "Graphics Power Control Register (R/W) (ARM9)",
    ),  # also system power
    # --- arm9 3d engine registers (block defined, specific registers are numerous) ---
    (
        0x4000320,
        "NDS9_3D_REGS_START",
        "3D Engine",
        "NDS ARM9 3D Registers Start (ARM9)",
    ),
    (0x40006A3, "NDS9_3D_REGS_END", "3D Engine", "NDS ARM9 3D Registers End (ARM9)"),
    # --- arm9 2d engine b ---
    (0x4001000, "REG_DISPCNT_B", "Display", "2D Engine B - LCD Control (R/W) (ARM9)"),
    # 0x4001008 - 0x4001055 : 2D Engine B BG/Window/Mosaic/Blend registers
    (0x4001008, "REG_BG0CNT_B", "Display", "2D Engine B - BG0 Control (R/W) (ARM9)"),
    (0x400100A, "REG_BG1CNT_B", "Display", "2D Engine B - BG1 Control (R/W) (ARM9)"),
    (0x400100C, "REG_BG2CNT_B", "Display", "2D Engine B - BG2 Control (R/W) (ARM9)"),
    (0x400100E, "REG_BG3CNT_B", "Display", "2D Engine B - BG3 Control (R/W) (ARM9)"),
    (0x4001010, "REG_BG0HOFS_B", "Display", "2D Engine B - BG0 X-Offset (W) (ARM9)"),
    (0x4001012, "REG_BG0VOFS_B", "Display", "2D Engine B - BG0 Y-Offset (W) (ARM9)"),
    # ... (other BG H/V OFS, PA-PD, X/Y for Engine B) ...
    (
        0x4001040,
        "REG_WIN0H_B",
        "Display",
        "2D Engine B - Window 0 Horizontal Dimensions (W) (ARM9)",
    ),
    # ... (other WIN H/V, WININ/OUT, MOSAIC, BLD for Engine B) ...
    (
        0x4001050,
        "REG_BLDCNT_B",
        "Display",
        "2D Engine B - Color Special Effects Control (R/W) (ARM9)",
    ),
    (
        0x4001052,
        "REG_BLDALPHA_B",
        "Display",
        "2D Engine B - Alpha Blending Coefficients (R/W) (ARM9)",
    ),
    (
        0x4001054,
        "REG_BLDY_B",
        "Display",
        "2D Engine B - Brightness Coefficient (W) (ARM9)",
    ),
    (
        0x400106C,
        "REG_MASTER_BRIGHT_B",
        "Display",
        "2D Engine B - Master Brightness Up/Down (W) (ARM9)",
    ),
    # --- arm7 specific i/o registers ---
    # (note: some shared registers like dma, timers, keypad, ipc, gamecard, ime/ie/if are listed above)
    (
        0x4000136,
        "REG_EXTKEYIN",
        "Keypad",
        "Extended Key Input (Lid, Touchscreen presence) (Read only) (ARM7)",
    ),
    (
        0x4000138,
        "REG_RTCDATA",
        "RTC",
        "RTC Realtime Clock SPI Bus Data (R/W) (ARM7)",
    ),  # accessed via spi
    (
        0x40001C0,
        "REG_SPICNT",
        "SPI",
        "SPI Bus Control (Firmware, Touchscreen, Powerman) (R/W) (ARM7)",
    ),
    (0x40001C2, "REG_SPIDATA", "SPI", "SPI Bus Data (R/W) (ARM7)"),
    (
        0x4000204,
        "REG_EXMEMSTAT",
        "Memory Control",
        "External Memory Status (Read Only) (ARM7)",
    ),  # distinct from arm9's exmemcnt
    # 0x4000206h WIFIWAITCNT (ARM7) - not in current list, could be added
    (
        0x4000240,
        "REG_VRAMSTAT",
        "Memory Control",
        "VRAM-C,D Bank Status (Read only) (ARM7)",
    ),
    (
        0x4000241,
        "REG_WRAMSTAT",
        "Memory Control",
        "WRAM Bank Status (for Shared WRAM) (Read only) (ARM7)",
    ),
    (
        0x4000304,
        "REG_POWCNT2",
        "Power",
        "Sound/Wifi Power Control Register (R/W) (ARM7)",
    ),
    (0x4000308, "REG_BIOSPROT", "System", "BIOS Write Protection Address (W) (ARM7)"),
    # --- arm7 sound registers (block defined) ---
    (
        0x4000400,
        "NDS7_SOUND_REGS_START",
        "Sound",
        "NDS ARM7 Sound Registers Start (ARM7)",
    ),
    # individual sound channel registers 0x4000400 - 0x40004EF (16 channels * 0x10 bytes)
    (
        0x4000500,
        "REG_SOUNDCNT",
        "Sound",
        "Sound Control Register (Master Enable, Mixing) (R/W) (ARM7)",
    ),
    (0x4000504, "REG_SOUNDBIAS", "Sound", "Sound Bias Register (R/W) (ARM7)"),
    (0x4000508, "REG_SNDCAP0CNT", "Sound", "Sound Capture 0 Control (R/W) (ARM7)"),
    (0x4000509, "REG_SNDCAP1CNT", "Sound", "Sound Capture 1 Control (R/W) (ARM7)"),
    (
        0x4000510,
        "REG_SNDCAP0DAD",
        "Sound",
        "Sound Capture 0 Destination Address (R/W) (ARM7)",
    ),
    (0x4000514, "REG_SNDCAP0LEN", "Sound", "Sound Capture 0 Length (W) (ARM7)"),
    (
        0x4000518,
        "REG_SNDCAP1DAD",
        "Sound",
        "Sound Capture 1 Destination Address (R/W) (ARM7)",
    ),
    (0x400051C, "REG_SNDCAP1LEN", "Sound", "Sound Capture 1 Length (W) (ARM7)"),
    (
        0x400051F,
        "NDS7_SOUND_REGS_END",
        "Sound",
        "NDS ARM7 Sound Registers End (ARM7)",
    ),  # approx end
    # --- arm7 wlan registers (block defined) ---
    (
        0x4800000,
        "NDS7_WIFI_REGS_START",
        "Wifi",
        "NDS ARM7 Wifi Registers Start (Ports and RAM) (ARM7)",
    ),
    # includes 8kb wifi ram at 0x4804000
    (
        0x4807FFF,
        "NDS7_WIFI_REGS_END",
        "Wifi",
        "NDS ARM7 Wifi Registers End (WS0) (ARM7)",
    ),  # end of 32k ws0 region
    # 0x4808000h  ..  Wifi WS1 Region (32K) (mirror of above, other waitstates) - not explicitly mapped as a separate symbol block
    # --- hardcoded ram addresses (mostly for exception/irq handlers) ---
    # arm9 dtcm addresses for irq handler are usually relative to dtcm base, which is variable.
    # current loader maps dtcm at 0x027c0000. so, dtcm+3ff8 would be 0x027c3ff8.
    (
        0x027C3FF8,
        "NDS9_IRQ_CHECKBITS_DTCM",
        "Hardcoded Addr",
        "ARM9 IRQ 'IF' Check Bits (in DTCM, assuming DTCM@0x027C0000)",
    ),
    (
        0x027C3FFC,
        "NDS9_IRQ_HANDLER_PTR_DTCM",
        "Hardcoded Addr",
        "ARM9 Pointer to IRQ Handler (in DTCM, assuming DTCM@0x027C0000)",
    ),
    (
        0x0380FFF8,
        "NDS7_IRQ_CHECKBITS",
        "Hardcoded Addr",
        "ARM7 IRQ 'IF' Check Bits (in ARM7 WRAM)",
    ),
    (
        0x0380FFFC,
        "NDS7_IRQ_HANDLER_PTR",
        "Hardcoded Addr",
        "ARM7 Pointer to IRQ Handler (in ARM7 WRAM)",
    ),
    (
        0x027FFFFE,
        "MAIN_MEM_CNT",
        "Hardcoded Addr",
        "Main Memory Control (R/W)",
    ),  # affects arm9 memory mapping
]

# --- nitro sdk constants ---
NITRO_SDK_MODULE_PARAMS_MAGIC = b"\x21\x06\xc0\xde\xde\xc0\x06\x21"
NITRO_SDK_MODULE_PARAMS_SIZE = 36  # size of the moduleparams struct
NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET = 0x1C  # offset of magic within the struct

# --- ndsview class definition ---


class NDSView(BinaryView):
    """
    binaryview class for loading and analyzing nintendo ds rom files.
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
        initializes the ndsview instance. minimal setup here.
        args:
            data: the binaryview object containing the raw nds rom data.
        """
        # --- initialize the base binaryview *first* ---
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)

        # --- initialize instance variables *after* successful base init ---
        self.raw: BinaryView = data  # keep a reference to the raw data view
        self.log: Logger = self.create_logger("NDS")  # use "nds" logger name.
        self._created_tag_types: Dict[str, TagType] = {}  # cache for created tagtypes.
        self.nds_rom: Optional[NDSRom] = None  # store parsed rom data

        # set architecture and platform (nds uses armv7 with thumb extensions)
        try:
            # arm9 is armv5te, arm7 is armv4t.
            # use "armv7" as the closest available architecture in binary ninja
            # that supports both arm and thumb instructions needed for arm9 analysis.
            self.arch: Architecture = Architecture["armv7"]  # type: ignore
            self.platform: Platform = self.arch.standalone_platform  # type: ignore
            if not self.platform:
                log_error(
                    "[NDS] critical: could not get standalone platform for armv7."
                )
                raise RuntimeError("failed to get armv7 platform.")
            self.log.log_info(
                f"using platform: {self.platform.name}, architecture: {self.arch.name}"
            )
        except KeyError:
            available_archs = [arch.name for arch in Architecture]  # type: ignore
            log_error(
                f"[NDS] critical: armv7 architecture not found. available: {available_archs}"
            )
            raise RuntimeError(
                f"required 'armv7' architecture not found in this binary ninja installation. available: {available_archs}"
            )
        except Exception as e:
            log_error(f"[NDS] critical error setting platform/arch: {e}")
            raise

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        checks if the data is likely an nds rom using a basic heuristic.
        the full validation (crc checks) is deferred to the init method.
        args:
            data: the binaryview object containing the data.
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

        self.log.log_info("performing full header validation...")
        validation_size = min(0x1000, rom_length)
        if not NDSRomReader.is_valid(rom_data_bytes[:validation_size]):
            self.log.log_error(
                "full header validation failed via ndsromreader.is_valid."
            )
            # if strict validation is needed, uncomment the next line:
            # return False
        else:
            self.log.log_info("full header validation successful.")

        self.log.log_info("parsing nds rom structure using ndsromreader...")
        try:
            self.nds_rom = NDSRomReader.read(rom_data_bytes)
        except Exception as e:
            self.log.log_error(f"ndsromreader.read failed: {e}")
            self.log.log_error(traceback.format_exc())
            self.nds_rom = None  # ensure it's none on failure

        del rom_data_bytes  # free memory after parsing

        if not self.nds_rom or not self.nds_rom.header:
            self.log.log_error(
                "failed to parse nds rom header and structures (ndsromreader.read returned none or header missing)."
            )
            return False
        return True

    def _define_tag_types(self):
        """
        defines and caches all necessary tag types used by this view.
        iterates through the global nds_tag_types dictionary.
        """
        self.log.log_info("defining nds hardware tag types...")
        for name, icon in NDS_TAG_TYPES.items():
            self._get_or_create_tag_type(name, icon)

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        """
        gets or creates a tag type, caching the result. avoids redundant api calls.
        args:
            name: the name of the tag type (e.g., "memory region"). use proper case.
            icon: the icon (emoji) for the tag type (e.g., "🗺️").
        returns:
            the tagtype object or none if creation failed.
        """
        name_lower = name.lower()
        if name_lower in self._created_tag_types:
            return self._created_tag_types[name_lower]

        if name_lower in self.tag_types:
            tag_type = self.tag_types[name_lower]
            if isinstance(tag_type, list):  # api can return list for some reason
                tag_type = tag_type[0] if tag_type else None
            if tag_type:
                self.log.log_info(f"found existing tagtype '{name_lower}'.")
                self._created_tag_types[name_lower] = tag_type
                return tag_type
            else:
                self.log.log_error(
                    f"tagtype '{name_lower}' exists but api returned empty list/none."
                )
                # proceed to creation block.

        try:
            self.log.log_info(f"creating new tagtype '{name}' with icon '{icon}'.")
            tag_type = self.create_tag_type(name, icon)
            self._created_tag_types[name_lower] = tag_type
            return tag_type
        except Exception as e:
            self.log.log_error(f"failed to create tagtype '{name}': {e}")
            return None

    def _define_reg_with_tag(
        self,
        address: int,
        name: str,
        tag_type_name: str,
        tag_type_icon: str,
        description: str = "",
    ):
        """
        helper to define a hardware register symbol and apply a descriptive tag.
        """
        try:
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))
            if description:
                self.set_comment_at(address, description)
            tag_type = self._get_or_create_tag_type(tag_type_name, tag_type_icon)
            if tag_type:
                self.add_tag(address, tag_type, data=name)
        except Exception as e:
            self.log.log_error(
                f"failed processing register '{name}' at 0x{address:x}: {e}"
            )

    def _map_memory_regions(self):
        """maps the core nds memory regions (ram, vram, io, etc.).
        ram regions that can contain code are given minimal file backing for bndb function persistence.
        """
        self.log.log_info("mapping nds memory regions...")

        def add_memory_region(
            addr,
            size,
            perms,
            name,
            tag_name="Memory Region",
            tag_icon="🗺️",
            is_ram_for_code=False,
        ):
            # helper to add a memory segment and associated metadata.
            # addr: start address of the region.
            # size: size of the region in bytes.
            # perms: segment permissions (e.g., self.rx_flags).
            # name: descriptive name for the region (e.g., "main ram").
            # tag_name: name of the tag type to apply (e.g., "memory region").
            # tag_icon: icon for the tag type.
            # is_ram_for_code: boolean, if true, provides minimal file backing for bndb function persistence.

            self.log.log_info(
                f"  mapping {name}: addr=0x{addr:08x}, size=0x{size:x}, perms={perms}"
            )

            file_offset_for_backing = 0  # default for non-backed or i/o
            file_length_for_backing = 0  # default for non-backed or i/o

            if is_ram_for_code:
                # provide minimal file backing for ram regions that might contain executable code.
                # this helps bn save functions defined in these regions to the bndb.
                # the actual byte read is insignificant as the region is ram or overwritten.
                file_offset_for_backing = (
                    0  # use a valid small offset from the start of the raw file
                )
                file_length_for_backing = (
                    1  # must be non-zero to indicate "file-backed"
                )

                # sanity check against raw file length
                if self.raw.length == 0:
                    self.log.log_warn(
                        f"raw file length is 0, cannot provide file backing for ram region {name}. mapping as non-backed."
                    )
                    file_length_for_backing = 0  # fallback to non-backed
                elif (
                    file_offset_for_backing + file_length_for_backing > self.raw.length
                ):
                    self.log.log_warn(
                        f"minimal file backing for ram region {name} (offset {file_offset_for_backing}, len {file_length_for_backing}) exceeds raw file length {self.raw.length}. mapping as non-backed."
                    )
                    file_length_for_backing = 0  # fallback to non-backed

            self.add_auto_segment(
                addr, size, file_offset_for_backing, file_length_for_backing, perms
            )

            tag_type = self._get_or_create_tag_type(tag_name, tag_icon)
            if tag_type:
                self.add_tag(addr, tag_type, data=f"{name} Start")
            self.set_comment_at(addr, f"{name} ({size // 1024}kb)")

        # --- main memory regions (based on ds_technical_docs.txt) ---
        # main ram: 4mb (standard), code can be loaded here (arm9, overlays)
        add_memory_region(
            0x02000000, 0x00400000, self.RWX_FLAGS, "Main RAM", is_ram_for_code=True
        )

        # shared wram: 32kb usable by arm9/arm7. can contain code.
        # tech doc: "32k mappable to nds7 or nds9" from a total of 96kb wram.
        # common mapping for arm9 is 0x03000000. arm7 often uses 0x037f8000 mirror.
        add_memory_region(
            0x03000000,
            0x00008000,
            self.RWX_FLAGS,
            "Shared WRAM (32KB Block)",
            is_ram_for_code=True,
        )
        # self.add_auto_segment(0x037F8000, 0x00008000, 0,0, self.RWX_FLAGS) # this is an alias/mirror, map only one primary shared wram
        # self.set_comment_at(0x037F8000, "Shared WRAM (ARM7 Mirror)")

        # arm7 wram: 64kb, exclusive to arm7. can contain arm7 code.
        add_memory_region(
            0x03800000,
            0x00010000,
            self.RWX_FLAGS,
            "ARM7 WRAM (64KB)",
            is_ram_for_code=True,
        )

        # --- i/o ports (not typically for general code execution, so no special backing) ---
        # main i/o block for arm9/arm7 shared registers, and arm9 specific (engine a, math, etc.)
        add_memory_region(
            0x04000000,
            0x00001000,
            self.RW_FLAGS,
            "I/O Registers (Main Block, 0x4000xxx)",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )
        # i/o for ipc receive fifo, gamecard data in (arm9/arm7)
        add_memory_region(
            0x04100000,
            0x00000020,
            self.RW_FLAGS,
            "I/O Registers (IPC/Card Data, 0x4100xxx)",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )
        # wifi i/o and ram block (arm7)
        add_memory_region(
            0x04800000,
            0x00008000,
            self.RW_FLAGS,
            "Wireless Comm (I/O & 8KB RAM@0x4804000)",
            tag_name="Wifi",
            tag_icon="📡",
        )  # covers ws0 32k region

        # --- graphics memory (palette, vram, oam - not typically for direct program code execution) ---
        add_memory_region(
            0x05000000, 0x00000800, self.RW_FLAGS, "Standard Palette RAM (2KB)"
        )  # corrected size
        add_memory_region(
            0x06000000, 0x000A4000, self.RW_FLAGS, "VRAM (Main Banks, 656KB Total)"
        )  # covers all vram banks a-i
        add_memory_region(
            0x06800000, 0x000A4000, self.RW_FLAGS, "VRAM (LCDC Mapped Alias)"
        )  # lcdc access to vram
        add_memory_region(
            0x07000000, 0x00000800, self.RW_FLAGS, "OAM - OBJ Attribute Memory (2KB)"
        )  # corrected size

        # --- bios roms ---
        # arm9 bios: 4kb used, mapped at 0xffff0000.
        # tech doc says "32kb (only 3k used)" for arm9 bios, but also "4k nds9" in breakdown. using 4k.
        add_memory_region(
            0xFFFF0000,
            0x00001000,
            self.RX_FLAGS,
            "ARM9 BIOS (4KB)",
            is_ram_for_code=True,
        )  # minimal backing if functions defined
        # arm7 bios: 16kb, mapped at 0x00000000 (from arm7's perspective).
        add_memory_region(
            0x00000000,
            0x00004000,
            self.RX_FLAGS,
            "ARM7 BIOS (16KB at Physical 0x0)",
            is_ram_for_code=True,
        )  # minimal backing

        # --- tightly coupled memories (tcm) for arm9 ---
        # arm9 itcm: 32kb code tcm. tech doc: "00000000h instruction tcm (32kb) ... mirror-able to 1000000h".
        # common convention is to use the 0x01000000 mirror.
        self.log.log_info(
            "nds9 itcm is documented at 0x00000000 (32kb), mirrored to 0x01000000. mapping the 0x01000000 mirror."
        )
        add_memory_region(
            0x01000000,
            0x00008000,
            self.RWX_FLAGS,
            "ARM9 ITCM (32KB Code, Mapped at 0x01xxxxxx)",
            is_ram_for_code=True,
        )

        # arm9 dtcm: 16kb data tcm. base is movable. common default is 0x027c0000.
        # tech doc: "0xxxx000h data tcm (16kb) (moveable)".
        dtcm_common_base = 0x027C0000  # a common default, actual base can vary
        self.log.log_info(
            f"mapping arm9 dtcm at common default 0x{dtcm_common_base:x} (16kb). actual base is configurable."
        )
        add_memory_region(
            dtcm_common_base,
            0x00004000,
            self.RWX_FLAGS,
            "ARM9 DTCM (16KB Data, Common Default)",
            is_ram_for_code=True,
        )

        # --- gba slot memory (not typically used by nds mode games, but part of memory map) ---
        # self.log.log_info("gba slot rom/ram regions are part of the nds memory map but not mapped by default by this loader.")
        # add_memory_region(0x08000000, 0x02000000, self.R_FLAGS, "GBA Slot ROM (Max 32MB)", is_ram_for_code=False) # typically read-only
        # add_memory_region(0x0A000000, 0x00010000, self.RW_FLAGS, "GBA Slot RAM (Max 64KB)", is_ram_for_code=True)

    def _find_module_params(self, data: bytes) -> Optional[int]:
        """searches for the nitro sdk _start_moduleparams magic bytes."""
        try:
            magic_index = data.find(NITRO_SDK_MODULE_PARAMS_MAGIC)
            if magic_index != -1:
                struct_start_offset = magic_index - NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET
                if (
                    struct_start_offset >= 0
                    and struct_start_offset + NITRO_SDK_MODULE_PARAMS_SIZE <= len(data)
                ):
                    self.log.log_info(
                        f"found _start_moduleparams structure at offset 0x{struct_start_offset:x} within arm9 data."
                    )
                    return struct_start_offset
                else:
                    self.log.log_warn(
                        f"found moduleparams magic at 0x{magic_index:x}, but calculated struct offset 0x{struct_start_offset:x} is invalid."
                    )
            else:
                self.log.log_info(
                    "_start_moduleparams magic not found. assuming non-sdk build or different structure."
                )
        except Exception as e:
            self.log.log_error(f"error searching for moduleparams: {e}")
        return None

    def _load_arm9(self):
        """loads the main arm9 binary, handling decompression and bss."""
        if not self.nds_rom or not self.nds_rom.header:
            self.log.log_error("cannot load arm9, rom header not parsed.")
            return

        header = self.nds_rom.header
        if header.arm9_size == 0:
            self.log.log_info("arm9 size is 0, skipping.")
            return

        self.log.log_info("loading arm9 binary...")
        arm9_data_raw: bytes = self.raw.read(header.arm9_rom_offset, header.arm9_size)
        if not arm9_data_raw or len(arm9_data_raw) != header.arm9_size:
            self.log.log_error(
                f"failed to read full arm9 data from rom offset 0x{header.arm9_rom_offset:x} (read {len(arm9_data_raw)}, expected {header.arm9_size})"
            )
            return

        load_address = header.arm9_ram_address
        # effective_code_data_size is the size of the code/data segment in memory after any transformation
        effective_code_data_size = 0
        bss_size = header.arm9_bss_size

        is_compressed_according_to_moduleparams = False
        module_params_found = False
        sdk_derived_code_data_size = (
            0  # expected decompressed size if moduleparams are used
        )

        module_params_offset_in_raw = self._find_module_params(arm9_data_raw)

        if module_params_offset_in_raw is not None:
            module_params_found = True
            try:
                auto_load_start = struct.unpack_from(
                    "<I", arm9_data_raw, module_params_offset_in_raw + 8
                )[0]
                compressed_static_end = struct.unpack_from(
                    "<I", arm9_data_raw, module_params_offset_in_raw + 20
                )[0]
                is_compressed_according_to_moduleparams = compressed_static_end != 0
                sdk_derived_code_data_size = auto_load_start - load_address

                self.log.log_info(
                    f"  moduleparams: compressed={is_compressed_according_to_moduleparams}, autoload_end=0x{auto_load_start:x}, sdk_code_data_size=0x{sdk_derived_code_data_size:x}"
                )
                if not (
                    0 <= sdk_derived_code_data_size <= header.arm9_size * 20
                ):  # sanity check (allow reasonable compression ratio)
                    self.log.log_error(
                        f"  moduleparams: invalid sdk_code_data_size (0x{sdk_derived_code_data_size:x}). will use header.arm9_size."
                    )
                    sdk_derived_code_data_size = header.arm9_size
                    is_compressed_according_to_moduleparams = False  # be cautious
            except Exception as e:
                self.log.log_error(
                    f"error processing _start_moduleparams: {e}. using header.arm9_size."
                )
                module_params_found = False
                sdk_derived_code_data_size = header.arm9_size
                is_compressed_according_to_moduleparams = False
        else:  # moduleparams not found
            sdk_derived_code_data_size = (
                header.arm9_size
            )  # default to raw size from header
            is_compressed_according_to_moduleparams = False  # assume uncompressed
            self.log.log_info(
                "  _start_moduleparams not found. assuming arm9 is uncompressed or using header size."
            )

        arm9_was_actually_decompressed_and_valid = False

        if is_compressed_according_to_moduleparams:
            self.log.log_info(
                f"  attempting arm9 decompression (expected decompressed size: 0x{sdk_derived_code_data_size:x})..."
            )
            try:
                decompressed_data = self._mii_uncompress_backward(arm9_data_raw)
                if decompressed_data:  # check if decompression yielded any data
                    actual_decompressed_size = len(decompressed_data)
                    if (
                        module_params_found
                        and actual_decompressed_size != sdk_derived_code_data_size
                    ):
                        self.log.log_warn(
                            f"  actual decompressed arm9 size (0x{actual_decompressed_size:x}) != moduleparams expected (0x{sdk_derived_code_data_size:x}). using actual."
                        )

                    effective_code_data_size = actual_decompressed_size

                    # segment definition points to original compressed data in the file,
                    # but its memory size is the decompressed size.
                    self.log.log_info(
                        f"  adding segment for decompressed arm9: mem_addr=0x{load_address:08x}, mem_size=0x{effective_code_data_size:x}, file_offset=0x{header.arm9_rom_offset:x}, file_size=0x{header.arm9_size:x}"
                    )
                    self.add_auto_segment(
                        load_address,
                        effective_code_data_size,  # memory address and size (decompressed)
                        header.arm9_rom_offset,
                        header.arm9_size,  # file offset and size (original compressed)
                        self.RX_FLAGS,
                    )

                    self.log.log_info(
                        f"  writing {effective_code_data_size} bytes of decompressed arm9 data to 0x{load_address:08x}"
                    )
                    bytes_written = self.write(load_address, decompressed_data)
                    if bytes_written != effective_code_data_size:
                        self.log.log_error(
                            f"arm9 write error (decompressed): expected {effective_code_data_size}, wrote {bytes_written}. segment may be corrupt."
                        )
                        # proceed with caution, segment might be partially written or incorrect
                    else:
                        arm9_was_actually_decompressed_and_valid = (
                            True  # successfully decompressed and written
                        )
                else:
                    self.log.log_warn(
                        "arm9 decompression resulted in empty data. falling back to raw mapping."
                    )
            except Exception as e:
                self.log.log_error(
                    f"arm9 decompression raised an exception: {e}. falling back to raw mapping."
                )

        # if not compressed, or if decompression was attempted but failed or yielded empty data
        if not arm9_was_actually_decompressed_and_valid:
            if (
                is_compressed_according_to_moduleparams
            ):  # implies decompression failed or was empty
                self.log.log_warn(
                    "  falling back to mapping raw arm9 data due to decompression issue."
                )
            else:  # was not considered compressed in the first place
                self.log.log_info("  arm9 mapping as raw/uncompressed data.")

            effective_code_data_size = header.arm9_size  # default to size in rom header
            file_map_length = header.arm9_size

            if (
                module_params_found
                and not is_compressed_according_to_moduleparams
                and sdk_derived_code_data_size > 0
            ):
                if sdk_derived_code_data_size != header.arm9_size:
                    self.log.log_warn(
                        f"  moduleparams size 0x{sdk_derived_code_data_size:x} for uncompressed ARM9 differs from header size 0x{header.arm9_size:x}. Using moduleparams size for segment memory."
                    )
                effective_code_data_size = sdk_derived_code_data_size  # memory size
                file_map_length = min(
                    sdk_derived_code_data_size, header.arm9_size
                )  # but map from file based on smaller of the two

            if effective_code_data_size > 0:
                self.log.log_info(
                    f"  adding segment for raw arm9: mem_addr=0x{load_address:08x}, mem_size=0x{effective_code_data_size:x}, file_offset=0x{header.arm9_rom_offset:x}, file_size=0x{file_map_length:x}"
                )
                self.add_auto_segment(
                    load_address,
                    effective_code_data_size,
                    header.arm9_rom_offset,
                    file_map_length,
                    self.RX_FLAGS,
                )
            else:
                self.log.log_error(
                    "  arm9 effective_code_data_size is 0 for raw mapping. cannot create segment."
                )
                return

        # add section for analysis
        if effective_code_data_size > 0:
            self.add_auto_section(
                name=".arm9_code_data",
                start=load_address,
                length=effective_code_data_size,
                semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                type="Code",
            )
            comment = "arm9 code/data start"
            if arm9_was_actually_decompressed_and_valid:
                comment += " (decompressed)"
            elif module_params_found and not is_compressed_according_to_moduleparams:
                comment += " (sdk raw)"
            elif is_compressed_according_to_moduleparams:
                comment += " (raw, decompression failed/empty)"  # if it was supposed to be compressed but ended up raw
            else:
                comment += " (raw)"
            self.set_comment_at(load_address, comment)
        else:
            self.log.log_warn(
                "arm9 effective code/data size is zero, skipping section creation."
            )
            return

        # handle arm9 bss
        if bss_size > 0:
            bss_start_address = load_address + effective_code_data_size
            self.log.log_info(
                f"  mapping arm9 bss: addr=0x{bss_start_address:08x}, size=0x{bss_size:x}"
            )
            self.add_auto_segment(
                bss_start_address, bss_size, 0, 0, self.RW_FLAGS
            )  # bss is not file-backed
            self.add_auto_section(
                name=".arm9.bss",
                start=bss_start_address,
                length=bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="BSS",
            )
            self.set_comment_at(bss_start_address, "arm9 bss start")
        else:
            self.log.log_info("  no arm9 bss section defined.")

        self.log.log_info(
            f"arm9 loaded: entry=0x{header.arm9_entry_address:08x}, load=0x{load_address:08x}, "
            f"code_data_size=0x{effective_code_data_size:x}, bss_size=0x{bss_size:x}, rom_offset=0x{header.arm9_rom_offset:08x}"
        )

    def _load_arm7(self):
        """loads the main arm7 binary and adds section. arm7 is typically not compressed."""
        if not self.nds_rom or not self.nds_rom.header:
            self.log.log_error("cannot load arm7, rom header not parsed.")
            return

        header = self.nds_rom.header
        if header.arm7_size == 0:
            self.log.log_info("arm7 size is 0, skipping loading.")
            return

        self.log.log_info("loading arm7 binary...")
        load_address = header.arm7_ram_address
        final_size = header.arm7_size  # size in rom and size in memory are the same
        self.add_auto_segment(
            load_address,
            final_size,
            header.arm7_rom_offset,  # file offset
            final_size,  # file length
            self.RX_FLAGS,
        )

        self.add_auto_section(
            name=".arm7",
            start=load_address,
            length=final_size,
            semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            type="Code",
        )
        self.set_comment_at(load_address, "arm7 binary start")

        arm7_bss_size = header.arm7_bss_size
        if arm7_bss_size > 0:
            bss_start = load_address + final_size
            self.log.log_info(
                f"  mapping arm7 bss: addr=0x{bss_start:08x}, size=0x{arm7_bss_size:x}"
            )
            self.add_auto_segment(
                bss_start, arm7_bss_size, 0, 0, self.RW_FLAGS  # bss is not file-backed
            )
            self.add_auto_section(
                name=".arm7.bss",
                start=bss_start,
                length=arm7_bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="BSS",
            )
            self.set_comment_at(bss_start, "arm7 bss start")

        self.log.log_info(
            f"arm7 loaded: entry=0x{header.arm7_entry_address:08x}, load=0x{load_address:08x}, "
            f"size=0x{final_size:x}, bss_size=0x{arm7_bss_size:x}, rom_offset=0x{header.arm7_rom_offset:08x} (raw mapped)"
        )

    def _load_overlays(self, cpu_name: str, overlay_table: Optional[NDSOverlayTable]):
        """
        loads arm9 or arm7 overlays, handling decompression and adding segments/sections.
        """
        if (
            not self.nds_rom
            or not self.nds_rom.fat_entries
            or not overlay_table
            or not overlay_table.entries
        ):
            self.log.log_info(
                f"no {cpu_name} overlays found, fat missing, or overlay table missing."
            )
            return
        if not hasattr(NDSOverlayEntry, "is_compressed"):
            self.log.log_error(
                f"nds_cartridge.py NDSOverlayEntry is missing 'is_compressed' attribute. cannot load {cpu_name} overlays correctly."
            )
            return

        self.log.log_info(f"loading {cpu_name} overlays...")
        num_loaded = 0
        num_failed = 0
        for i, entry in enumerate(overlay_table.entries):
            if entry.file_id == 0xFFFF:
                continue  # skip placeholder
            if entry.file_id >= len(self.nds_rom.fat_entries):
                self.log.log_warn(
                    f"skipping invalid {cpu_name} overlay {i}: file id {entry.file_id} out of fat bounds."
                )
                num_failed += 1
                continue
            if (
                entry.ram_size == 0 and entry.bss_size == 0
            ):  # entirely empty overlay entry
                self.log.log_info(
                    f"skipping empty {cpu_name} overlay {i} (file id {entry.file_id})."
                )
                continue

            fat_entry = self.nds_rom.fat_entries[entry.file_id]
            overlay_size_in_rom = fat_entry.end_address - fat_entry.start_address

            overlay_data_raw = b""
            if overlay_size_in_rom > 0:  # only read if fat entry indicates data
                overlay_data_raw = self.raw.read(
                    fat_entry.start_address, overlay_size_in_rom
                )
                if not overlay_data_raw or len(overlay_data_raw) != overlay_size_in_rom:
                    self.log.log_error(
                        f"failed to read {cpu_name} overlay {i} (file id {entry.file_id}) data from rom."
                    )
                    num_failed += 1
                    continue
            elif (
                entry.ram_size > 0
            ):  # overlay expects ram content, but no corresponding data in rom (e.g. fully compressed to nothing, or error in rom)
                self.log.log_warn(
                    f"{cpu_name} overlay {i} (file_id {entry.file_id}) expects RAM content (size 0x{entry.ram_size:x}) but has no data in ROM (size 0x{overlay_size_in_rom:x}). Skipping code/data part."
                )
                # will proceed to bss if any, segment_ram_size_in_memory will be 0

            segment_ram_size_in_memory = 0  # actual size of code/data part in memory
            load_address = entry.ram_address
            segment_name_base = f"{cpu_name}_Overlay_{i}_File{entry.file_id}"
            overlay_was_decompressed_and_valid = False

            if entry.is_compressed:
                if not overlay_data_raw:  # cannot decompress if no raw data was read
                    self.log.log_error(
                        f"cannot decompress {segment_name_base}: no raw data from rom (size_in_rom was {overlay_size_in_rom})."
                    )
                    # if ram_size > 0, this is an issue. if ram_size is 0, it might be a pure bss overlay marked compressed.
                    if (
                        entry.ram_size > 0
                    ):  # if it expected content, this is a failure for the code part
                        num_failed += 1
                        continue
                    # if ram_size is 0, proceed to bss handling
                else:  # have raw data to decompress
                    self.log.log_info(
                        f"  decompressing {segment_name_base} (rom size: 0x{overlay_size_in_rom:x}, expected ram size: 0x{entry.ram_size:x})..."
                    )
                    try:
                        decompressed_data = self._mii_uncompress_backward(
                            overlay_data_raw
                        )
                        if decompressed_data:  # check if decompression yielded any data
                            segment_ram_size_in_memory = len(decompressed_data)
                            if (
                                segment_ram_size_in_memory != entry.ram_size
                                and entry.ram_size != 0
                            ):  # entry.ram_size is the target decompressed size
                                self.log.log_warn(
                                    f"  {segment_name_base}: actual decompressed size (0x{segment_ram_size_in_memory:x}) != table RAM size (0x{entry.ram_size:x}). using actual."
                                )

                            # segment definition points to original compressed data, memory size is decompressed size
                            self.log.log_info(
                                f"  adding segment for decompressed overlay {segment_name_base}: mem_addr=0x{load_address:08x}, mem_size=0x{segment_ram_size_in_memory:x}, file_offset=0x{fat_entry.start_address:x}, file_size=0x{overlay_size_in_rom:x}"
                            )
                            self.add_auto_segment(
                                load_address,
                                segment_ram_size_in_memory,  # memory address and size (decompressed)
                                fat_entry.start_address,
                                overlay_size_in_rom,  # file offset and size (original compressed)
                                self.RX_FLAGS,
                            )
                            bytes_written = self.write(load_address, decompressed_data)
                            if bytes_written != segment_ram_size_in_memory:
                                self.log.log_error(
                                    f"overlay {segment_name_base} write error (decompressed): expected {segment_ram_size_in_memory}, wrote {bytes_written}"
                                )
                                # segment might be corrupted, do not mark as valid decompressed
                            else:
                                overlay_was_decompressed_and_valid = True
                                self.log.log_info(
                                    f"  decompression & write successful: {overlay_size_in_rom} bytes -> {segment_ram_size_in_memory} bytes"
                                )
                        else:  # decompression resulted in empty data
                            self.log.log_warn(
                                f"  decompression of {segment_name_base} resulted in empty data. overlay code/data part will be empty."
                            )
                            segment_ram_size_in_memory = 0  # ensure it's zero
                    except Exception as e:
                        self.log.log_error(
                            f"failed to decompress {segment_name_base}: {e}. overlay code/data part will be empty."
                        )
                        segment_ram_size_in_memory = 0  # ensure it's zero

            # if not compressed, or if decompression was attempted but failed/was empty
            if (
                not overlay_was_decompressed_and_valid and not entry.is_compressed
            ):  # only map raw if it was never meant to be compressed
                segment_ram_size_in_memory = (
                    overlay_size_in_rom  # use raw size from rom
                )
                if (
                    segment_ram_size_in_memory > 0
                ):  # only map if there's actual data in rom
                    self.log.log_info(
                        f"  adding segment for raw overlay {segment_name_base}: mem_addr=0x{load_address:08x}, size=0x{segment_ram_size_in_memory:x}, file_offset=0x{fat_entry.start_address:x}"
                    )
                    self.add_auto_segment(
                        load_address,
                        segment_ram_size_in_memory,
                        fat_entry.start_address,
                        segment_ram_size_in_memory,
                        self.RX_FLAGS,
                    )
                # if segment_ram_size_in_memory is 0 here, it means overlay_size_in_rom was 0.
                # if entry.ram_size was > 0, it was logged as a warning earlier.

            # add section for the code/data part
            if segment_ram_size_in_memory > 0:
                self.add_auto_section(
                    f".{segment_name_base}",
                    load_address,
                    segment_ram_size_in_memory,
                    SectionSemantics.ReadOnlyCodeSectionSemantics,
                    "OverlayCode",
                )
                self.set_comment_at(
                    load_address,
                    f"{segment_name_base} start{' (decompressed)' if overlay_was_decompressed_and_valid else ' (raw)'}",
                )
            elif (
                entry.ram_size > 0
            ):  # expected ram content but segment_ram_size_in_memory is 0 (e.g. decompression yielded empty or raw was empty)
                self.log.log_warn(
                    f"  {segment_name_base} expected RAM size 0x{entry.ram_size:x} but no valid data was mapped for sectioning."
                )

            # add bss segment
            if entry.bss_size > 0:
                bss_start_address = (
                    load_address + segment_ram_size_in_memory
                )  # bss follows actual code/data
                self.log.log_info(
                    f"  mapping {segment_name_base} bss: addr=0x{bss_start_address:08x}, size=0x{entry.bss_size:x}"
                )
                self.add_auto_segment(
                    bss_start_address, entry.bss_size, 0, 0, self.RW_FLAGS
                )  # bss not file backed
                self.add_auto_section(
                    f".{segment_name_base}.bss",
                    bss_start_address,
                    entry.bss_size,
                    SectionSemantics.ReadWriteDataSectionSemantics,
                    "OverlayBSS",
                )
                self.set_comment_at(bss_start_address, f"{segment_name_base} bss start")

            # define static initializer function symbol (analysis will create the function)
            if entry.static_initializer_start_address != 0:
                init_start = entry.static_initializer_start_address
                func_addr = init_start & ~1
                is_thumb = (init_start & 1) != 0
                # check if initializer is within the loaded code/data part of this overlay
                if segment_ram_size_in_memory > 0 and (
                    load_address
                    <= func_addr
                    < load_address + segment_ram_size_in_memory
                ):
                    self.log.log_info(
                        f"  defining symbol for {segment_name_base} static initializer at 0x{func_addr:x} {'(thumb implied)' if is_thumb else ''}"
                    )
                    self.define_auto_symbol(
                        Symbol(
                            SymbolType.FunctionSymbol,
                            func_addr,
                            f"{segment_name_base}_Init",
                        )
                    )
                    self.set_comment_at(
                        func_addr,
                        f"{segment_name_base} static initializer (entry point)",
                    )
                    # self.add_entry_point(func_addr) # consider if overlay initializers are true "entry points" for analysis
                else:
                    self.log.log_warn(
                        f"  {segment_name_base} static initializer 0x{init_start:x} is outside its loaded/valid RAM region (start 0x{load_address:x}, size 0x{segment_ram_size_in_memory:x}). skipping symbol definition."
                    )
            num_loaded += 1

        log_func = self.log.log_info if num_failed == 0 else self.log.log_warn
        log_func(
            f"loaded {num_loaded} / {len(overlay_table.entries)} {cpu_name} overlays ({num_failed} failures)."
        )

    def _mii_uncompress_backward(self, data: bytes) -> bytes:
        """
        decompresses data using mii lz77 variant (backward).
        raises valueerror or eoferror on failure.
        """
        if len(data) < 4:  # minimum for footer
            raise ValueError("data too short for mii decompression footer")

        footer = data[-4:]
        decompressed_size = struct.unpack_from("<I", footer, 0)[0]

        if decompressed_size == 0 and len(data) == 4:
            return b""  # just a footer indicating zero size
        if (
            decompressed_size == 0 and len(data) > 4
        ):  # non-empty data but zero size in footer
            self.log.log_warn(
                "mii footer indicates zero decompressed size but data is present."
            )
            # this case is ambiguous. for now, let's assume it might be an error or uncompressed.

        # check for header if data is long enough
        if (
            len(data) < 8
        ):  # need at least footer (4 bytes) and header (4 bytes) for type 1
            # if only footer, and size is non-zero, it might be uncompressed data with a size footer
            if decompressed_size == len(data) - 4:
                self.log.log_info(
                    "mii data seems uncompressed (size matches data minus footer)."
                )
                return data[:-4]
            # if decompressed_size is 0 here, means it's an empty payload from just footer
            if decompressed_size == 0:
                return b""
            raise ValueError(
                f"data too short for mii header (len {len(data)}) but decompressed_size is {decompressed_size}"
            )

        header_val = struct.unpack_from("<I", data, len(data) - 8)[0]
        comp_type = (header_val >> 24) & 0xF  # usually 0x1 for lz77 variant

        if (
            decompressed_size == 0
        ):  # if truly zero from footer, and we have header+footer
            if (
                comp_type == 0x1 and header_val == 0x10000000
            ):  # common for empty compressed block
                return b""
            # if decompressed_size is 0 but header is not the empty block marker, it's ambiguous
            self.log.log_warn(
                f"mii decompressed_size is 0, but header is 0x{header_val:x}. Assuming empty based on size."
            )
            return b""

        if (
            decompressed_size > 0x10000000
        ):  # sanity check size (256mb), nds max ram is 4mb. overlays are smaller.
            raise ValueError(
                f"invalid mii decompressed size: 0x{decompressed_size:x} (too large)"
            )

        if comp_type != 0x1:  # common nds lz77 type is 0x1_
            self.log.log_warn(
                f"mii compression type {comp_type} encountered, not type 1 (lz77). treating as uncompressed (returning raw data minus footer)."
            )
            return data[:-4]  # fallback, might be incorrect

        result = bytearray(decompressed_size)
        dst_offs = decompressed_size
        src_offs = len(data) - 8  # start reading before the 8-byte header/footer block

        while dst_offs > 0:
            if src_offs <= 0:
                raise EOFError(
                    f"mii source data exhausted unexpectedly (dst_offs={dst_offs}, src_offs={src_offs})"
                )

            block_header = data[src_offs - 1]
            src_offs -= 1

            for _ in range(8):  # process 8 blocks/literals
                if dst_offs <= 0:
                    break  # finished decompression mid-header

                if (block_header & 0x80) == 0:  # literal byte
                    if src_offs <= 0:
                        raise EOFError(
                            f"mii source exhausted (literal byte) (dst_offs={dst_offs}, src_offs={src_offs})"
                        )
                    literal_byte = data[src_offs - 1]
                    src_offs -= 1
                    dst_offs -= 1
                    if (
                        dst_offs < 0
                    ):  # should not happen if decompressed_size was correct
                        raise IndexError(
                            "mii destination offset became negative (literal)"
                        )
                    result[dst_offs] = literal_byte
                else:  # lz77 copy block
                    if src_offs <= 1:  # need 2 bytes for lz77 params
                        raise EOFError(
                            f"mii source exhausted (lz77 block header) (dst_offs={dst_offs}, src_offs={src_offs})"
                        )
                    byte1 = data[src_offs - 1]
                    byte2 = data[src_offs - 2]
                    src_offs -= 2

                    length = ((byte1 & 0xF0) >> 4) + 3
                    disp = (((byte1 & 0x0F) << 8) | byte2) + 1

                    if dst_offs < length:  # not enough space left to write
                        raise ValueError(
                            f"mii lz77 copy length ({length}) exceeds remaining destination space ({dst_offs}). possible corrupt data or incorrect decompressed_size."
                        )

                    try:
                        for _ in range(length):
                            current_write_idx = dst_offs - 1
                            current_read_idx = current_write_idx + disp
                            if not (
                                0 <= current_read_idx < decompressed_size
                                and 0 <= current_write_idx < decompressed_size
                            ):
                                raise IndexError(
                                    f"mii lz77 copy out of bounds: read_idx={current_read_idx}, write_idx={current_write_idx}, disp={disp}, len={length}, dst_rem={dst_offs}"
                                )
                            result[current_write_idx] = result[current_read_idx]
                            dst_offs -= 1
                    except IndexError as ie:
                        raise IndexError(
                            f"mii lz77 copy error: {ie} (length={length}, disp={disp}, current_dst_offs_before_iter_copy={dst_offs+length}, read_idx_attempt={current_read_idx}, write_idx_attempt={current_write_idx})"
                        )

                block_header = (block_header << 1) & 0xFF
                if dst_offs <= 0 and _ < 7:  # check after each bit processed
                    break

        if dst_offs != 0:
            self.log.log_warn(
                f"mii decompression finished, but dst_offs is non-zero ({dst_offs}). result may be truncated or padded if original size was incorrect."
            )
        return bytes(result)

    def _define_io_registers(self):
        """defines symbols and tags for known nds i/o registers."""
        self.log.log_info("defining nds hardware symbols and tags...")
        for addr, name, tag_name, desc in NDS_IO_REGISTERS:
            icon = NDS_TAG_TYPES.get(tag_name, "🔩")
            self._define_reg_with_tag(addr, name, tag_name, icon, desc)

    def _define_entry_points(self):
        """defines entry points and start symbols for arm9 and arm7.
        functions themselves will be created by analysis.
        """
        if not self.nds_rom or not self.nds_rom.header:
            self.log.log_error("cannot define entry points, rom header not parsed.")
            return

        header = self.nds_rom.header

        # arm9 entry point
        arm9_load_addr = header.arm9_ram_address
        entry_point_arm9 = header.arm9_entry_address
        func_addr_aligned_arm9 = (
            entry_point_arm9 & ~1
        )  # address for function must be word aligned
        is_thumb_arm9 = (entry_point_arm9 & 1) != 0  # lsb indicates thumb mode

        segment_at_arm9_entry = self.get_segment_at(func_addr_aligned_arm9)
        # check if the entry point is within a valid, executable segment that was loaded at the expected arm9 ram address
        if (
            segment_at_arm9_entry
            and segment_at_arm9_entry.start == arm9_load_addr
            and segment_at_arm9_entry.executable
        ):
            self.log.log_info(
                f"defining arm9 entry point symbol: _start9 at 0x{func_addr_aligned_arm9:08x}{', thumb implied' if is_thumb_arm9 else ''}"
            )
            self.add_entry_point(func_addr_aligned_arm9)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, func_addr_aligned_arm9, "_start9")
            )
            # self.add_function(func_addr_aligned_arm9) # removed: let analysis create it
        else:
            self.log.log_warn(
                f"arm9 entry point 0x{func_addr_aligned_arm9:x} not in a valid executable segment starting at expected load address 0x{arm9_load_addr:x}. "
                f"segment found: {segment_at_arm9_entry}. _start9 symbol/entry point may not be effective."
            )

        # arm7 entry point
        arm7_load_addr = header.arm7_ram_address
        entry_point_arm7 = header.arm7_entry_address
        func_addr_aligned_arm7 = entry_point_arm7 & ~1
        is_thumb_arm7 = (entry_point_arm7 & 1) != 0

        segment_at_arm7_entry = self.get_segment_at(func_addr_aligned_arm7)
        if (
            segment_at_arm7_entry
            and segment_at_arm7_entry.start == arm7_load_addr
            and segment_at_arm7_entry.executable
        ):
            self.log.log_info(
                f"defining arm7 entry point symbol: _start7 at 0x{func_addr_aligned_arm7:08x}{', thumb implied' if is_thumb_arm7 else ''}"
            )
            self.add_entry_point(func_addr_aligned_arm7)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, func_addr_aligned_arm7, "_start7")
            )
            # self.add_function(func_addr_aligned_arm7) # removed: let analysis create it
        else:
            self.log.log_warn(
                f"arm7 entry point 0x{func_addr_aligned_arm7:x} not in a valid executable segment starting at expected load address 0x{arm7_load_addr:x}. "
                f"segment found: {segment_at_arm7_entry}. _start7 symbol/entry point may not be effective."
            )

        if header.debug_rom_offset != 0 and header.debug_size > 0:
            debug_load_addr = (
                header.debug_ram_address
                if header.debug_ram_address != 0
                else 0x02400000
            )  # common fallback
            self.log.log_info(
                f"debug arm9 seems present: rom_offset=0x{header.debug_rom_offset:x}, size=0x{header.debug_size:x}, load_addr=0x{debug_load_addr:08x}."
            )
            self.define_auto_symbol(
                Symbol(
                    SymbolType.DataSymbol, debug_load_addr, "arm9_debug_load_address"
                )
            )

    # --- main initialization logic ---

    def init(self) -> bool:
        """
        initializes the ndsview by parsing the header, mapping memory regions,
        loading binaries, defining sections, symbols, and tags.
        returns:
            true on successful initialization, false otherwise.
        """
        try:
            self.log.log_info("starting nds rom loading process...")

            if not self._parse_rom_header():
                self.log.log_error("initial rom header parsing failed. aborting init.")
                return False  # ensure init fails if header parsing fails

            self._define_tag_types()
            self._map_memory_regions()

            self._load_arm9()
            self._load_arm7()
            if self.nds_rom:  # check again as it might be none if parsing failed badly
                self._load_overlays("ARM9", self.nds_rom.arm9_overlay_table)
                self._load_overlays("ARM7", self.nds_rom.arm7_overlay_table)

            self._define_io_registers()
            self._define_entry_points()  # call after segments are loaded, defines symbols and entry points

            self.log.log_info(
                "nds rom loading complete. triggering analysis (background)..."
            )
            self.update_analysis()  # changed from update_analysis_and_wait() to avoid ui thread wait error
            self.log.log_info(
                "analysis update triggered. initial analysis will run in background."
            )

            return True

        except Exception as e:
            log_error(f"[NDS] critical failure during ndsview initialization: {e}")
            log_error(traceback.format_exc())
            return False

    # --- required binaryview methods ---

    def perform_is_executable(self) -> bool:
        """nds roms contain executable code"""
        return True

    def perform_get_entry_point(self) -> int:
        """returns the primary (arm9) entry point address, or arm7 if arm9 is absent."""
        # this is called by the core *after* init() completes.
        # self.entry_points should exist if BinaryView.__init__ completed successfully.
        if hasattr(self, "entry_points") and len(self.entry_points) > 0:
            return self.entry_points[0]

        # fallback if self.entry_points wasn't populated or accessible (e.g. if init failed early)
        self.log.log_warn(
            "[NDS] perform_get_entry_point: self.entry_points not available or empty. attempting fallback to header values."
        )
        if self.nds_rom and self.nds_rom.header:
            # check arm9 entry first
            arm9_entry_aligned = self.nds_rom.header.arm9_entry_address & ~1
            segment_at_arm9_entry = self.get_segment_at(arm9_entry_aligned)
            # check if a segment exists at the arm9 load address (where the entry point should be)
            if (
                segment_at_arm9_entry
                and segment_at_arm9_entry.start == self.nds_rom.header.arm9_ram_address
            ):
                self.log.log_info(
                    "[NDS] perform_get_entry_point: using arm9_entry_address from header as fallback."
                )
                return arm9_entry_aligned

            # then check arm7 entry
            arm7_entry_aligned = self.nds_rom.header.arm7_entry_address & ~1
            segment_at_arm7_entry = self.get_segment_at(arm7_entry_aligned)
            if (
                segment_at_arm7_entry
                and segment_at_arm7_entry.start == self.nds_rom.header.arm7_ram_address
            ):
                self.log.log_info(
                    "[NDS] perform_get_entry_point: using arm7_entry_address as fallback (arm9 entry not valid/in segment)."
                )
                return arm7_entry_aligned

        self.log.log_error(
            "[NDS] perform_get_entry_point: no valid entry points found from loader or header. returning start of view or 0."
        )
        return self.start if self.start is not None else 0

    def perform_get_address_size(self) -> int:
        """nds uses 32-bit addresses"""
        return 4


NDSView.register()
