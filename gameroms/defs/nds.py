from typing import List, Tuple

# list of known i/o registers: (address, name, tag_type_name, description from tech docs)
# names and descriptions use proper case for symbols/comments. tag_type_name matches NDS_TAG_TYPE_DEFINITIONS keys.
# this list will be populated separately.
# list of known nintendo ds i/o registers
# format: (address, name, tag_type_name, description from tech docs)
# names and descriptions use proper case for symbols/comments, adhering to binary ninja conventions.
# tag_type_name corresponds to keys in the NDS_TAG_TYPE_DEFINITIONS dictionary.
# fmt: off
NDS_IO_REGISTERS = [
    # - arm9 i/o map
    # these registers are primarily accessed or exclusively available to the arm9 processor.

    # - arm9 display engine a (main screen: 0x04000000 - 0x0400006f)
    # controls for the main 2d graphics engine (engine a).
    (0x04000000, "DISPCNT_A", "Display", "2D Engine A - LCD Control (ARM9)"),
    # general lcd status, shared between engine a and b, but listed here under arm9 context.
    (0x04000004, "DISPSTAT", "Display", "General LCD Status (Shared A+B)"),
    # vertical counter, shared, indicates current scanline.
    (0x04000006, "VCOUNT", "Display", "Vertical Counter (Shared A+B, Read-only)"),

    # - 2d engine a: background, affine, window, and effects (0x04000008 - 0x04000057)
    # this block (0x50 bytes) covers detailed controls for backgrounds, affine transformations,
    # windowing, mosaic, and blending effects for engine a.
    # background controls (bg0-bg3)
    (0x04000008, "BG0CNT_A", "Display", "2D Engine A - BG0 Control (ARM9)"),
    (0x0400000A, "BG1CNT_A", "Display", "2D Engine A - BG1 Control (ARM9)"),
    (0x0400000C, "BG2CNT_A", "Display", "2D Engine A - BG2 Control (ARM9)"),
    (0x0400000E, "BG3CNT_A", "Display", "2D Engine A - BG3 Control (ARM9)"),
    (0x04000010, "BG0HOFS_A", "Display", "2D Engine A - BG0 X-Offset (ARM9)"),
    (0x04000012, "BG0VOFS_A", "Display", "2D Engine A - BG0 Y-Offset (ARM9)"),
    (0x04000014, "BG1HOFS_A", "Display", "2D Engine A - BG1 X-Offset (ARM9)"),
    (0x04000016, "BG1VOFS_A", "Display", "2D Engine A - BG1 Y-Offset (ARM9)"),
    (0x04000018, "BG2HOFS_A", "Display", "2D Engine A - BG2 X-Offset (ARM9)"),
    (0x0400001A, "BG2VOFS_A", "Display", "2D Engine A - BG2 Y-Offset (ARM9)"),
    (0x0400001C, "BG3HOFS_A", "Display", "2D Engine A - BG3 X-Offset (ARM9)"),
    (0x0400001E, "BG3VOFS_A", "Display", "2D Engine A - BG3 Y-Offset (ARM9)"),
    # background 2 affine transformation parameters
    (0x04000020, "BG2PA_A", "Display", "2D Engine A - BG2 Rotation/Scaling Parameter A (dx) (ARM9)"),
    (0x04000022, "BG2PB_A", "Display", "2D Engine A - BG2 Rotation/Scaling Parameter B (dmx) (ARM9)"),
    (0x04000024, "BG2PC_A", "Display", "2D Engine A - BG2 Rotation/Scaling Parameter C (dy) (ARM9)"),
    (0x04000026, "BG2PD_A", "Display", "2D Engine A - BG2 Rotation/Scaling Parameter D (dmy) (ARM9)"),
    (0x04000028, "BG2X_L_A", "Display", "2D Engine A - BG2 Reference Point X-Coordinate, Low (Internal) (ARM9)"),
    (0x0400002A, "BG2X_H_A", "Display", "2D Engine A - BG2 Reference Point X-Coordinate, High (Internal) (ARM9)"),
    (0x0400002C, "BG2Y_L_A", "Display", "2D Engine A - BG2 Reference Point Y-Coordinate, Low (Internal) (ARM9)"),
    (0x0400002E, "BG2Y_H_A", "Display", "2D Engine A - BG2 Reference Point Y-Coordinate, High (Internal) (ARM9)"),
    # background 3 affine transformation parameters
    (0x04000030, "BG3PA_A", "Display", "2D Engine A - BG3 Rotation/Scaling Parameter A (dx) (ARM9)"),
    (0x04000032, "BG3PB_A", "Display", "2D Engine A - BG3 Rotation/Scaling Parameter B (dmx) (ARM9)"),
    (0x04000034, "BG3PC_A", "Display", "2D Engine A - BG3 Rotation/Scaling Parameter C (dy) (ARM9)"),
    (0x04000036, "BG3PD_A", "Display", "2D Engine A - BG3 Rotation/Scaling Parameter D (dmy) (ARM9)"),
    (0x04000038, "BG3X_L_A", "Display", "2D Engine A - BG3 Reference Point X-Coordinate, Low (Internal) (ARM9)"),
    (0x0400003A, "BG3X_H_A", "Display", "2D Engine A - BG3 Reference Point X-Coordinate, High (Internal) (ARM9)"),
    (0x0400003C, "BG3Y_L_A", "Display", "2D Engine A - BG3 Reference Point Y-Coordinate, Low (Internal) (ARM9)"),
    (0x0400003E, "BG3Y_H_A", "Display", "2D Engine A - BG3 Reference Point Y-Coordinate, High (Internal) (ARM9)"),
    # windowing controls
    (0x04000040, "WIN0H_A", "Display", "2D Engine A - Window 0 Horizontal Dimensions (ARM9)"),
    (0x04000042, "WIN1H_A", "Display", "2D Engine A - Window 1 Horizontal Dimensions (ARM9)"),
    (0x04000044, "WIN0V_A", "Display", "2D Engine A - Window 0 Vertical Dimensions (ARM9)"),
    (0x04000046, "WIN1V_A", "Display", "2D Engine A - Window 1 Vertical Dimensions (ARM9)"),
    (0x04000048, "WININ_A", "Display", "2D Engine A - Inside Window Control (ARM9)"),
    (0x0400004A, "WINOUT_A", "Display", "2D Engine A - Outside Window and OBJ Window Control (ARM9)"),
    # mosaic and blending controls
    (0x0400004C, "MOSAIC_A", "Display", "2D Engine A - Mosaic Size (ARM9)"),
    (0x04000050, "BLDCNT_A", "Display", "2D Engine A - Blend Control (ARM9)"),
    (0x04000052, "BLDALPHA_A", "Display", "2D Engine A - Blend Alpha Coefficients (ARM9)"),
    (0x04000054, "BLDY_A", "Display", "2D Engine A - Blend Brightness (Fade) Coefficient (ARM9)"),

    # - 3d display, capture, and main memory fifo (0x04000060 - 0x0400006f)
    (0x04000060, "DISP3DCNT", "3D Engine", "3D Display Control Register (ARM9)"), # Also Display
    (0x04000064, "DISPCAPCNT", "Display", "Display Capture Control Register (ARM9)"),
    (0x04000068, "DISP_MMEM_FIFO", "Display", "Main Memory Display FIFO (ARM9)"),
    (0x0400006C, "MASTER_BRIGHT_A", "Display", "2D Engine A - Master Brightness (ARM9)"),
]
# fmt: on

# - dma channels (0x040000b0 - 0x040000de)
# these are shared between arm9 and arm7, but typically configured by arm9.
# dma channel registers are repeated for channels 0 through 3.
_dma_base = 0x040000B0
for _i in range(4):
    # dma source address (32-bit)
    NDS_IO_REGISTERS.append(
        (
            _dma_base + _i * 0xC + 0x0,
            f"DMA{_i}SAD",
            "DMA",
            f"DMA Channel {_i} Source Address (Shared)",
        )
    )
    # dma destination address (32-bit)
    NDS_IO_REGISTERS.append(
        (
            _dma_base + _i * 0xC + 0x4,
            f"DMA{_i}DAD",
            "DMA",
            f"DMA Channel {_i} Destination Address (Shared)",
        )
    )
    # dma word count (16-bit) and control (16-bit)
    NDS_IO_REGISTERS.append(
        (
            _dma_base + _i * 0xC + 0x8,
            f"DMA{_i}CNT",
            "DMA",
            f"DMA Channel {_i} Control & Word Count (Shared)",
        )
    )

# - dma fill registers (0x040000e0 - 0x040000ef)
# arm9 specific registers for dma fill operations.
_dma_fill_base = 0x040000E0
for _i in range(4):
    # dma fill data (32-bit)
    NDS_IO_REGISTERS.append(
        (
            _dma_fill_base + _i * 0x4,
            f"DMA{_i}FILL",
            "DMA",
            f"DMA Channel {_i} Fill Data (ARM9 Specific)",
        )
    )

# - timers (0x04000100 - 0x0400010f)
# four 16-bit timers, shared between arm9 and arm7.
_timer_base = 0x04000100
for _i in range(4):
    # timer data/reload value (16-bit)
    NDS_IO_REGISTERS.append(
        (
            _timer_base + _i * 0x4 + 0x0,
            f"TM{_i}D",
            "Timers",
            f"Timer {_i} Data/Reload Value (Shared)",
        )
    )
    # timer control (16-bit)
    NDS_IO_REGISTERS.append(
        (
            _timer_base + _i * 0x4 + 0x2,
            f"TM{_i}CNT",
            "Timers",
            f"Timer {_i} Control (Shared)",
        )
    )

# fmt: off
NDS_IO_REGISTERS.extend([
    # - keypad input (0x04000130 - 0x04000133)
    # shared keypad registers.
    (0x04000130, "KEYINPUT", "Keypad", "Key Input Status (Shared, Read-only)"),
    (0x04000132, "KEYCNT", "Keypad", "Key Interrupt Control (Shared)"),

    # - ipc and gamecard interface (0x04000180 - 0x040001bb)
    # inter-processor communication and gamecard (slot-1) registers, shared.
    (0x04000180, "IPCSYNC", "IPC", "IPC Synchronize Register (Shared)"),
    (0x04000184, "IPCFIFOCNT", "IPC", "IPC FIFO Control Register (Shared)"),
    (0x04000188, "IPCFIFOSEND", "IPC", "IPC Send FIFO (Shared, Write-only by active CPU)"),
    (0x040001A0, "AUXSPICNT", "Gamecard", "Gamecard ROM and SPI Bus Control (Shared)"), # Also SPI
    (0x040001A2, "AUXSPIDATA", "Gamecard", "Gamecard SPI Bus Data/Strobe (Shared)"),    # Also SPI
    (0x040001A4, "ROMCTRL", "Gamecard", "Gamecard Bus Timing/Control (Shared)"), # AKA CARDCTRL
    (0x040001A8, "CARDCMD", "Gamecard", "Gamecard Bus Command Output (Shared, 8 bytes)"),
    (0x040001B0, "CARD_SEED0_LO", "Gamecard", "Gamecard Encryption Seed 0 Lower 32bit (Shared)"),
    (0x040001B4, "CARD_SEED1_LO", "Gamecard", "Gamecard Encryption Seed 1 Lower 32bit (Shared)"),
    (0x040001B8, "CARD_SEED0_HI", "Gamecard", "Gamecard Encryption Seed 0 Upper 7bit (Shared)"),
    (0x040001BA, "CARD_SEED1_HI", "Gamecard", "Gamecard Encryption Seed 1 Upper 7bit (Shared)"),

    # - arm9 memory and interrupt control (0x04000204 - 0x04000249)
    (0x04000204, "EXMEMCNT", "Memory Control", "External Memory Control (ARM9 Specific R/W, partially shared status)"),
    (0x04000208, "IME_A9", "Interrupts", "Interrupt Master Enable (ARM9 Specific)"),
    (0x04000210, "IE_A9", "Interrupts", "Interrupt Enable Register (ARM9 Specific)"),
    (0x04000214, "IF_A9", "Interrupts", "Interrupt Request Flags (ARM9 Specific, R/W to clear)"),
    (0x04000240, "VRAMCNT_A", "Memory Control", "VRAM Bank A (128KB) Control (ARM9 Specific Write)"),
    (0x04000241, "VRAMCNT_B", "Memory Control", "VRAM Bank B (128KB) Control (ARM9 Specific Write)"),
    (0x04000242, "VRAMCNT_C", "Memory Control", "VRAM Bank C (128KB) Control (ARM9 Specific Write)"),
    (0x04000243, "VRAMCNT_D", "Memory Control", "VRAM Bank D (128KB) Control (ARM9 Specific Write)"),
    (0x04000244, "VRAMCNT_E", "Memory Control", "VRAM Bank E (64KB) Control (ARM9 Specific Write)"),
    (0x04000245, "VRAMCNT_F", "Memory Control", "VRAM Bank F (16KB) Control (ARM9 Specific Write)"),
    (0x04000246, "VRAMCNT_G", "Memory Control", "VRAM Bank G (16KB) Control (ARM9 Specific Write)"),
    (0x04000247, "WRAMCNT", "Memory Control", "Shared WRAM Bank Control (ARM9 Specific Write)"),
    (0x04000248, "VRAMCNT_H", "Memory Control", "VRAM Bank H (32KB) Control (ARM9 Specific Write)"),
    (0x04000249, "VRAMCNT_I", "Memory Control", "VRAM Bank I (16KB) Control (ARM9 Specific Write)"),

    # - arm9 math hardware (0x04000280 - 0x040002bb)
    # hardware division and square root units.
    (0x04000280, "DIVCNT", "Math", "Division Control (ARM9 Specific)"),
    (0x04000290, "DIV_NUMER", "Math", "Division Numerator (64-bit) (ARM9 Specific R/W)"),
    (0x04000298, "DIV_DENOM", "Math", "Division Denominator (64-bit) (ARM9 Specific R/W)"),
    (0x040002A0, "DIV_RESULT", "Math", "Division Quotient Result (64-bit) (ARM9 Specific Read)"),
    (0x040002A8, "DIVREM_RESULT", "Math", "Division Remainder Result (64-bit) (ARM9 Specific Read)"),
    (0x040002B0, "SQRTCNT", "Math", "Square Root Control (ARM9 Specific)"),
    (0x040002B4, "SQRT_RESULT", "Math", "Square Root Result (32-bit) (ARM9 Specific Read)"),
    (0x040002B8, "SQRT_PARAM", "Math", "Square Root Parameter Input (64-bit) (ARM9 Specific R/W)"),

    # - arm9 system control (0x04000300 - 0x04000307)
    (0x04000300, "POSTFLG_A9", "System", "POST Boot Flag (ARM9, Undocumented features)"),
    (0x04000304, "POWCNT1", "Power", "Main Power Control Register (ARM9 Specific)"),

    # - arm9 3d graphics engine (0x04000320 - 0x040006a3)
    # this is a large block of registers for the 3d engine.
    # only a few key registers are listed here as per the overview document.
    (0x04000400, "GXFIFO", "3D Engine", "Geometry Command FIFO (ARM9)"),
    (0x04000600, "GXSTAT", "3D Engine", "Geometry Engine Status (ARM9)"),

    # - arm9 display engine b (sub screen: 0x04001000 - 0x0400106f)
    # controls for the sub 2d graphics engine (engine b).
    (0x04001000, "DISPCNT_B", "Display", "2D Engine B - LCD Control (ARM9)"),
    # detailed registers for engine b (bg, affine, window, effects) follow a similar pattern to engine a.
    (0x04001008, "BG0CNT_B", "Display", "2D Engine B - BG0 Control (ARM9)"),
    (0x0400100A, "BG1CNT_B", "Display", "2D Engine B - BG1 Control (ARM9)"),
    (0x0400100C, "BG2CNT_B", "Display", "2D Engine B - BG2 Control (ARM9)"),
    (0x0400100E, "BG3CNT_B", "Display", "2D Engine B - BG3 Control (ARM9)"),
    (0x04001010, "BG0HOFS_B", "Display", "2D Engine B - BG0 X-Offset (ARM9)"),
    (0x04001012, "BG0VOFS_B", "Display", "2D Engine B - BG0 Y-Offset (ARM9)"),
    (0x04001014, "BG1HOFS_B", "Display", "2D Engine B - BG1 X-Offset (ARM9)"),
    (0x04001016, "BG1VOFS_B", "Display", "2D Engine B - BG1 Y-Offset (ARM9)"),
    (0x04001018, "BG2HOFS_B", "Display", "2D Engine B - BG2 X-Offset (ARM9)"),
    (0x0400101A, "BG2VOFS_B", "Display", "2D Engine B - BG2 Y-Offset (ARM9)"),
    (0x0400101C, "BG3HOFS_B", "Display", "2D Engine B - BG3 X-Offset (ARM9)"),
    (0x0400101E, "BG3VOFS_B", "Display", "2D Engine B - BG3 Y-Offset (ARM9)"),
    (0x04001020, "BG2PA_B", "Display", "2D Engine B - BG2 Rotation/Scaling Parameter A (dx) (ARM9)"),
    (0x04001022, "BG2PB_B", "Display", "2D Engine B - BG2 Rotation/Scaling Parameter B (dmx) (ARM9)"),
    (0x04001024, "BG2PC_B", "Display", "2D Engine B - BG2 Rotation/Scaling Parameter C (dy) (ARM9)"),
    (0x04001026, "BG2PD_B", "Display", "2D Engine B - BG2 Rotation/Scaling Parameter D (dmy) (ARM9)"),
    (0x04001028, "BG2X_L_B", "Display", "2D Engine B - BG2 Reference Point X-Coordinate, Low (Internal) (ARM9)"),
    (0x0400102A, "BG2X_H_B", "Display", "2D Engine B - BG2 Reference Point X-Coordinate, High (Internal) (ARM9)"),
    (0x0400102C, "BG2Y_L_B", "Display", "2D Engine B - BG2 Reference Point Y-Coordinate, Low (Internal) (ARM9)"),
    (0x0400102E, "BG2Y_H_B", "Display", "2D Engine B - BG2 Reference Point Y-Coordinate, High (Internal) (ARM9)"),
    (0x04001030, "BG3PA_B", "Display", "2D Engine B - BG3 Rotation/Scaling Parameter A (dx) (ARM9)"),
    (0x04001032, "BG3PB_B", "Display", "2D Engine B - BG3 Rotation/Scaling Parameter B (dmx) (ARM9)"),
    (0x04001034, "BG3PC_B", "Display", "2D Engine B - BG3 Rotation/Scaling Parameter C (dy) (ARM9)"),
    (0x04001036, "BG3PD_B", "Display", "2D Engine B - BG3 Rotation/Scaling Parameter D (dmy) (ARM9)"),
    (0x04001038, "BG3X_L_B", "Display", "2D Engine B - BG3 Reference Point X-Coordinate, Low (Internal) (ARM9)"),
    (0x0400103A, "BG3X_H_B", "Display", "2D Engine B - BG3 Reference Point X-Coordinate, High (Internal) (ARM9)"),
    (0x0400103C, "BG3Y_L_B", "Display", "2D Engine B - BG3 Reference Point Y-Coordinate, Low (Internal) (ARM9)"),
    (0x0400103E, "BG3Y_H_B", "Display", "2D Engine B - BG3 Reference Point Y-Coordinate, High (Internal) (ARM9)"),
    (0x04001040, "WIN0H_B", "Display", "2D Engine B - Window 0 Horizontal Dimensions (ARM9)"),
    (0x04001042, "WIN1H_B", "Display", "2D Engine B - Window 1 Horizontal Dimensions (ARM9)"),
    (0x04001044, "WIN0V_B", "Display", "2D Engine B - Window 0 Vertical Dimensions (ARM9)"),
    (0x04001046, "WIN1V_B", "Display", "2D Engine B - Window 1 Vertical Dimensions (ARM9)"),
    (0x04001048, "WININ_B", "Display", "2D Engine B - Inside Window Control (ARM9)"),
    (0x0400104A, "WINOUT_B", "Display", "2D Engine B - Outside Window and OBJ Window Control (ARM9)"),
    (0x0400104C, "MOSAIC_B", "Display", "2D Engine B - Mosaic Size (ARM9)"),
    (0x04001050, "BLDCNT_B", "Display", "2D Engine B - Blend Control (ARM9)"),
    (0x04001052, "BLDALPHA_B", "Display", "2D Engine B - Blend Alpha Coefficients (ARM9)"),
    (0x04001054, "BLDY_B", "Display", "2D Engine B - Blend Brightness (Fade) Coefficient (ARM9)"),
    (0x0400106C, "MASTER_BRIGHT_B", "Display", "2D Engine B - Master Brightness (ARM9)"),

    # - arm9 ipc receive and gamecard data in (0x04100000 - 0x04100013, shared region)
    (0x04100000, "IPCFIFORECV", "IPC", "IPC Receive FIFO (Shared, Read-only by active CPU)"),
    (0x04100010, "CARDDATA_RD", "Gamecard", "Gamecard Bus 4-byte Data In (Shared, Read-only)"),

    # - arm7 i/o map
    # these registers are primarily accessed or exclusively available to the arm7 processor,
    # or have different behavior/meaning on arm7 compared to arm9 for shared addresses.

    # shared registers like dispstat, vcount, dma, timers, keyinput, keycnt, ipc, gamecard control
    # are already listed above. their addresses are the same for arm7.

    # - arm7 debug and extended keypad (0x04000120 - 0x04000139)
    (0x04000120, "SIODATA32_A7", "ARM7 Specific", "Debug SIO Data 32 (ARM7)"),
    (0x04000128, "SIOCNT_A7", "ARM7 Specific", "Debug SIO Control (ARM7)"),
    (0x04000134, "RCNT_A7", "ARM7 Specific", "Debug SIO Mode/General Purpose (RCNT) (ARM7)"),
    (0x04000136, "EXTKEYIN", "Keypad", "Extended Key Input (Touchscreen, etc.) (ARM7 Read-only)"),
    (0x04000138, "RTCCNT_A7", "RTC", "Real-Time Clock I/O (via SPI) (ARM7)"),

    # - arm7 spi interface (0x040001c0 - 0x040001c3)
    # for firmware, touchscreen, and power management.
    (0x040001C0, "SPICNT_A7", "SPI", "SPI Bus Control (Firmware, Touch, Powerman) (ARM7 Specific)"),
    (0x040001C2, "SPIDATA_A7", "SPI", "SPI Bus Data (ARM7 Specific)"),

    # - arm7 memory, irq, and system control (0x04000204 - 0x0400030b)
    (0x04000204, "EXMEMSTAT_A7", "Memory Control", "External Memory Status (ARM7 Read, reflects NDS9 EXMEMCNT bits 7-15)"),
    (0x04000206, "WIFIWAITCNT_A7", "Wifi", "Wifi Wait State Control (ARM7 Specific)"),
    (0x04000208, "IME_A7", "Interrupts", "Interrupt Master Enable (ARM7 Specific)"),
    (0x04000210, "IE_A7", "Interrupts", "Interrupt Enable Register (ARM7 Specific)"),
    (0x04000214, "IF_A7", "Interrupts", "Interrupt Request Flags (ARM7 Specific, R/W to clear)"),
    # note: ie2 and if2 (0x4000218, 0x400021c) are dsi only.
    (0x04000240, "VRAMSTAT_A7", "Memory Control", "VRAM C,D Bank Status (ARM7 Read-only)"),
    (0x04000241, "WRAMSTAT_A7", "Memory Control", "Shared WRAM Bank Status (ARM7 Read-only)"),
    (0x04000300, "POSTFLG_A7", "System", "POST Boot Flag (ARM7)"),
    (0x04000301, "HALTCNT_A7", "Power", "Halt Control / Power Down (ARM7 Specific)"),
    (0x04000304, "POWCNT2_A7", "Power", "Sound/Wifi Power Control (ARM7 Specific)"),
    (0x04000308, "BIOSPROT_A7", "System", "BIOS Read Protection Address (ARM7 Specific)"),
])
# fmt: on

# - arm7 sound registers (0x04000400 - 0x0400051f)
# 16 sound channels, plus global sound controls and capture units.
_sound_base = 0x04000400
for _i in range(16):  # sound channels 0-15
    _ch_base = _sound_base + _i * 0x10
    # sound channel x control (16-bit + 16-bit unused)
    NDS_IO_REGISTERS.append(
        (
            _ch_base + 0x0,
            f"SOUND{_i}CNT",
            "Sound",
            f"Sound Channel {_i} Control (ARM7 Specific)",
        )
    )
    # sound channel x source address (32-bit)
    NDS_IO_REGISTERS.append(
        (
            _ch_base + 0x4,
            f"SOUND{_i}SAD",
            "Sound",
            f"Sound Channel {_i} Data Source Address (ARM7 Specific Write)",
        )
    )
    # sound channel x timer/reload (16-bit)
    NDS_IO_REGISTERS.append(
        (
            _ch_base + 0x8,
            f"SOUND{_i}TMR",
            "Sound",
            f"Sound Channel {_i} Timer/Reload Value (ARM7 Specific Write)",
        )
    )
    # sound channel x loopstart point (16-bit)
    NDS_IO_REGISTERS.append(
        (
            _ch_base + 0xA,
            f"SOUND{_i}PNT",
            "Sound",
            f"Sound Channel {_i} Loop Start Point (ARM7 Specific Write)",
        )
    )
    # sound channel x length in 32-bit words (20-bit relevant)
    NDS_IO_REGISTERS.append(
        (
            _ch_base + 0xC,
            f"SOUND{_i}LEN",
            "Sound",
            f"Sound Channel {_i} Length in DWords (ARM7 Specific Write)",
        )
    )

# fmt: off
NDS_IO_REGISTERS.extend([
    (0x04000500, "SOUNDCNT", "Sound", "Global Sound Control (ARM7 Specific)"),
    (0x04000504, "SOUNDBIAS", "Sound", "Sound Bias Setting (ARM7 Specific)"),
    (0x04000508, "SNDCAP0CNT", "Sound", "Sound Capture 0 Control (ARM7 Specific)"),
    (0x04000509, "SNDCAP1CNT", "Sound", "Sound Capture 1 Control (ARM7 Specific)"),
    (0x04000510, "SNDCAP0DAD", "Sound", "Sound Capture 0 Destination Address (ARM7 Specific R/W)"),
    (0x04000514, "SNDCAP0LEN", "Sound", "Sound Capture 0 Length (ARM7 Specific Write)"),
    (0x04000518, "SNDCAP1DAD", "Sound", "Sound Capture 1 Destination Address (ARM7 Specific R/W)"),
    (0x0400051C, "SNDCAP1LEN", "Sound", "Sound Capture 1 Length (ARM7 Specific Write)"),
])
# fmt: on

# note: dsi-specific and debug-emulator specific registers from the document have been omitted
# as the focus is on general nds hardware registers.
# note: the granularity of 2d engine bg/window/affine registers is based on common gba layouts,
# as the nds technical document often states "same registers as gba, some changed bits" for these blocks.
# registers shared by both cpus are generally listed once under the arm9 section if primarily configured there,
# or with a "(shared)" remark. arm7-specific views or functionalities for shared addresses are noted.
