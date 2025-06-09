"""
GBA hardware definitions including memory layout, I/O registers, and hardware constants.
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass

# GBA ROM Header Constants
GBA_NINTENDO_LOGO_OFFSET = 0x04
GBA_NINTENDO_LOGO_SIZE = 0x9C  # 156 bytes
GBA_GAME_TITLE_OFFSET = 0xA0
GBA_GAME_TITLE_SIZE = 12
GBA_GAME_CODE_OFFSET = 0xAC
GBA_GAME_CODE_SIZE = 4
GBA_MAKER_CODE_OFFSET = 0xB0
GBA_MAKER_CODE_SIZE = 2
GBA_FIXED_VALUE_OFFSET = 0xB2
GBA_MAIN_UNIT_CODE_OFFSET = 0xB3
GBA_DEVICE_TYPE_OFFSET = 0xB4
GBA_SOFTWARE_VERSION_OFFSET = 0xBC
GBA_HEADER_CHECKSUM_OFFSET = 0xBD
GBA_HEADER_MIN_SIZE = 0xC0


@dataclass
class GBAHeader:
    """
    Represents parsed information from the GBA ROM header.
    This structure holds key metadata extracted from the ROM,
    such as game title, various codes, and software version.
    """
    game_title: str = ""
    game_code: str = ""
    maker_code: str = ""
    software_version: int = 0


# GBA Hardware Tag Type Definitions
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

# GBA I/O Register Definitions
# Format: (address, name, tag_type_name, description)
GBA_IO_REGISTER_DEFINITIONS: List[Tuple[int, str, str, str]] = [
    # Display registers (0x4000000 - 0x400005F)
    (0x4000000, "REG_DISPCNT", "Display", "LCD Control (Video Mode, BG/OBJ Enable, Window Enable)"),
    (0x4000004, "REG_DISPSTAT", "Display", "General LCD Status (VBlank, HBlank, VCounter Match)"),
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
    (0x4000028, "REG_BG2X", "Display", "BG2 Reference Point X-Coordinate (28-bit integer part)"),
    (0x400002C, "REG_BG2Y", "Display", "BG2 Reference Point Y-Coordinate (28-bit integer part)"),
    (0x4000030, "REG_BG3PA", "Display", "BG3 Rotation/Scaling Parameter A (dx)"),
    (0x4000032, "REG_BG3PB", "Display", "BG3 Rotation/Scaling Parameter B (dmx)"),
    (0x4000034, "REG_BG3PC", "Display", "BG3 Rotation/Scaling Parameter C (dy)"),
    (0x4000036, "REG_BG3PD", "Display", "BG3 Rotation/Scaling Parameter D (dmy)"),
    (0x4000038, "REG_BG3X", "Display", "BG3 Reference Point X-Coordinate (28-bit integer part)"),
    (0x400003C, "REG_BG3Y", "Display", "BG3 Reference Point Y-Coordinate (28-bit integer part)"),
    (0x4000040, "REG_WIN0H", "Display", "Window 0 Horizontal Dimensions (X2, X1)"),
    (0x4000042, "REG_WIN1H", "Display", "Window 1 Horizontal Dimensions (X2, X1)"),
    (0x4000044, "REG_WIN0V", "Display", "Window 0 Vertical Dimensions (Y2, Y1)"),
    (0x4000046, "REG_WIN1V", "Display", "Window 1 Vertical Dimensions (Y2, Y1)"),
    (0x4000048, "REG_WININ", "Display", "Inside of Window 0 and 1 Layer Control"),
    (0x400004A, "REG_WINOUT", "Display", "Inside of OBJ Window & Outside of Windows Layer Control"),
    (0x400004C, "REG_MOSAIC", "Display", "Mosaic Size (BG H/V, OBJ H/V)"),
    (0x4000050, "REG_BLDCNT", "Display", "Color Special Effects Selection (Blending Mode, Target Pixels)"),
    (0x4000052, "REG_BLDALPHA", "Display", "Alpha Blending Coefficients (EVA for BGTarget1, EVB for BGTarget2)"),
    (0x4000054, "REG_BLDY", "Display", "Brightness (Fade-In/Out) Coefficient (EVY)"),
    
    # Sound registers (0x4000060 - 0x40000A7)
    (0x4000060, "REG_SOUND1CNT_L", "Sound", "Channel 1 Sweep control (NR10)"),
    (0x4000062, "REG_SOUND1CNT_H", "Sound", "Channel 1 Duty Cycle, Length, Envelope control (NR11, NR12)"),
    (0x4000064, "REG_SOUND1CNT_X", "Sound", "Channel 1 Frequency, Control (NR13, NR14)"),
    (0x4000068, "REG_SOUND2CNT_L", "Sound", "Channel 2 Duty Cycle, Length, Envelope control (NR21, NR22)"),
    (0x400006C, "REG_SOUND2CNT_H", "Sound", "Channel 2 Frequency, Control (NR23, NR24)"),
    (0x4000070, "REG_SOUND3CNT_L", "Sound", "Channel 3 Stop, Wave RAM select, Dimension (NR30)"),
    (0x4000072, "REG_SOUND3CNT_H", "Sound", "Channel 3 Length, Volume control (NR31, NR32)"),
    (0x4000074, "REG_SOUND3CNT_X", "Sound", "Channel 3 Frequency, Control (NR33, NR34)"),
    (0x4000078, "REG_SOUND4CNT_L", "Sound", "Channel 4 Length, Envelope control (NR41, NR42)"),
    (0x400007C, "REG_SOUND4CNT_H", "Sound", "Channel 4 Frequency, Polynomial Counter, Control (NR43, NR44)"),
    (0x4000080, "REG_SOUNDCNT_L", "Sound", "Master Sound Control (Stereo Panning, Volume) (NR50, NR51)"),
    (0x4000082, "REG_SOUNDCNT_H", "Sound", "Sound Channel Output Ratios, DMA Sound Control"),
    (0x4000084, "REG_SOUNDCNT_X", "Sound", "Master Sound Enable, Channel Status (NR52)"),
    (0x4000088, "REG_SOUNDBIAS", "Sound", "Sound PWM Bias Control, Amplitude Resolution"),
    (0x4000090, "REG_WAVE_RAM", "Sound", "Channel 3 Wave Pattern RAM (32x4-bit samples)"),
    (0x40000A0, "REG_FIFO_A", "Sound", "Channel A (Direct Sound) FIFO Data Register"),
    (0x40000A4, "REG_FIFO_B", "Sound", "Channel B (Direct Sound) FIFO Data Register"),
    
    # DMA registers (0x40000B0 - 0x40000DF)
    (0x40000B0, "REG_DMA0SAD", "DMA", "DMA 0 Source Address (Internal/External Memory)"),
    (0x40000B4, "REG_DMA0DAD", "DMA", "DMA 0 Destination Address (Internal/External Memory)"),
    (0x40000B8, "REG_DMA0CNT_L", "DMA", "DMA 0 Word Count (Number of 16/32-bit transfers)"),
    (0x40000BA, "REG_DMA0CNT_H", "DMA", "DMA 0 Control (Enable, Timing, Transfer Type)"),
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
    
    # Timer registers (0x4000100 - 0x400010F)
    (0x4000100, "REG_TM0CNT_L", "Timers", "Timer 0 Counter/Reload Value"),
    (0x4000102, "REG_TM0CNT_H", "Timers", "Timer 0 Control (Enable, Mode, Prescaler)"),
    (0x4000104, "REG_TM1CNT_L", "Timers", "Timer 1 Counter/Reload Value"),
    (0x4000106, "REG_TM1CNT_H", "Timers", "Timer 1 Control"),
    (0x4000108, "REG_TM2CNT_L", "Timers", "Timer 2 Counter/Reload Value"),
    (0x400010A, "REG_TM2CNT_H", "Timers", "Timer 2 Control"),
    (0x400010C, "REG_TM3CNT_L", "Timers", "Timer 3 Counter/Reload Value"),
    (0x400010E, "REG_TM3CNT_H", "Timers", "Timer 3 Control"),
    
    # Serial communication registers (0x4000120 - 0x400015B)
    (0x4000120, "REG_SIODATA32", "Serial IO", "SIO Data (Normal 32-bit Mode) / Multiplayer Data 0 (Parent)"),
    (0x4000122, "REG_SIOMULTI1", "Serial IO", "SIO Multiplayer Data 1 (Child 1)"),
    (0x4000124, "REG_SIOMULTI2", "Serial IO", "SIO Multiplayer Data 2 (Child 2)"),
    (0x4000126, "REG_SIOMULTI3", "Serial IO", "SIO Multiplayer Data 3 (Child 3)"),
    (0x4000128, "REG_SIOCNT", "Serial IO", "SIO Control Register (Mode, Speed, Interrupts)"),
    (0x400012A, "REG_SIODATA8", "Serial IO", "SIO Data (Normal 8-bit/UART Mode) / Multiplayer Send Data"),
    (0x4000134, "REG_RCNT", "Serial IO", "General Purpose I/O Mode Select / Data (R/CNT)"),
    (0x4000140, "REG_JOYCNT", "Serial IO", "SIO JOY Bus Control"),
    (0x4000150, "REG_JOY_RECV", "Serial IO", "SIO JOY Bus Receive Data"),
    (0x4000154, "REG_JOY_TRANS", "Serial IO", "SIO JOY Bus Transmit Data"),
    (0x4000158, "REG_JOYSTAT", "Serial IO", "SIO JOY Bus Receive Status"),
    
    # Keypad input (0x4000130 - 0x4000133)
    (0x4000130, "REG_KEYINPUT", "Keypad", "Key Input Status (Read-only, lists currently pressed keys)"),
    (0x4000132, "REG_KEYCNT", "Keypad", "Key Interrupt Control (Enable keypad interrupt, condition)"),
    
    # Interrupt, waitstate, power control (0x4000200 - 0x4000301, 0x4000800)
    (0x4000200, "REG_IE", "Interrupts", "Interrupt Enable Register (Mask for enabling specific interrupts)"),
    (0x4000202, "REG_IF", "Interrupts", "Interrupt Flag / Acknowledge Register (Identifies pending interrupts)"),
    (0x4000204, "REG_WAITCNT", "System Control", "Game Pak Waitstate Control (Memory access timing)"),
    (0x4000208, "REG_IME", "Interrupts", "Interrupt Master Enable Register (Global interrupt enable/disable)"),
    (0x4000300, "REG_POSTFLG", "System Control", "Post Boot Flag (Undocumented, related to boot status)"),
    (0x4000301, "REG_HALTCNT", "System Control", "Power Down Control (Undocumented, initiates low-power modes)"),
    (0x4000800, "REG_INTERNAL_MEM_CNT", "System Control", "Internal Memory Control (Undocumented, possibly WRAM control/prefetch)"),
]