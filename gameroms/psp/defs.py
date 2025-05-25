from typing import List, Tuple

# list of known i/o registers: (address, name, tag_type_name, description)
# names and descriptions use proper case for symbols/comments. tag_type_name matches PSP_TAG_TYPES keys.
PSP_IO_REGISTERS: List[Tuple[int, str, str, str]] = [
    # Memory Management (0x1C00xxxx)
    (
        0x1C000000,
        "MEMPROT0",
        "Memory Management",
        "Memory Protection 08000000-081FFFFF",
    ),
    (
        0x1C000004,
        "MEMPROT1",
        "Memory Management",
        "Memory Protection 08200000-083FFFFF",
    ),
    (
        0x1C000008,
        "MEMPROT2",
        "Memory Management",
        "Memory Protection 08400000-085FFFFF",
    ),
    (
        0x1C00000C,
        "MEMPROT3",
        "Memory Management",
        "Memory Protection 08600000-087FFFFF",
    ),
    (
        0x1C000010,
        "MEMPROT4",
        "Memory Management",
        "Memory Protection 08800000-089FFFFF?",
    ),
    (
        0x1C000014,
        "MEMPROT5",
        "Memory Management",
        "Memory Protection 08A00000-08BFFFFF?",
    ),
    (
        0x1C000018,
        "MEMPROT6",
        "Memory Management",
        "Memory Protection 08C00000-08DFFFFF?",
    ),
    (
        0x1C00001C,
        "MEMPROT7",
        "Memory Management",
        "Memory Protection 08E00000-08FFFFFF?",
    ),
    (
        0x1C000020,
        "MEMPROT8",
        "Memory Management",
        "Memory Protection 09000000-091FFFFF?",
    ),
    (
        0x1C000024,
        "MEMPROT9",
        "Memory Management",
        "Memory Protection 09200000-093FFFFF?",
    ),
    (
        0x1C000028,
        "MEMPROT10",
        "Memory Management",
        "Memory Protection 09400000-095FFFFF?",
    ),
    (
        0x1C00002C,
        "MEMPROT11",
        "Memory Management",
        "Memory Protection 09600000-097FFFFF?",
    ),
    (
        0x1C000030,
        "MEMMAN_PROFCTRL",
        "Memory Management",
        "Profiler control?",
    ),  # Note: Docs list 1C000030 under MemMan but name it PROF_CTRL?
    (0x1C000044, "MEMMAN_UNK_44", "Memory Management", "Unknown MemMan Reg 0x44"),
    # System Controller (0x1C10xxxx)
    (0x1C100000, "SYSCON_NMIEN", "System Control", "NMI enable mask"),
    (0x1C100004, "SYSCON_NMIFLAG", "System Control", "NMI flags"),
    (0x1C10000C, "SYSCON_NMI12_CTRL", "System Control", "NMI12 control register?"),
    (0x1C100010, "SYSCON_NMI8_CTRL", "System Control", "NMI8 control register?"),
    (0x1C100014, "SYSCON_NMI9_CTRL", "System Control", "NMI9 control register?"),
    (0x1C100018, "SYSCON_NMI7_CTRL", "System Control", "NMI7 control register?"),
    (0x1C10001C, "SYSCON_NMI6_CTRL", "System Control", "NMI6 control register?"),
    (0x1C100020, "SYSCON_NMI5_CTRL", "System Control", "NMI5 control register?"),
    (0x1C100024, "SYSCON_NMI4_CTRL", "System Control", "NMI4 control register?"),
    (0x1C100028, "SYSCON_NMI3_CTRL", "System Control", "NMI3 control register?"),
    (0x1C10002C, "SYSCON_NMI2_CTRL", "System Control", "NMI2 control register?"),
    (0x1C100030, "SYSCON_NMI1_CTRL", "System Control", "NMI1 control register?"),
    (0x1C100034, "SYSCON_NMI0_CTRL", "System Control", "NMI0 control register?"),
    (0x1C100040, "SYSCON_RAMSIZE", "System Control", "RAM size / HW Version"),
    (0x1C100044, "SYSCON_RPCINT", "System Control", "SC/ME RPC interrupt"),
    (0x1C100048, "SYSCON_CPUSEMA", "System Control", "SC/ME semaphore"),
    (0x1C10004C, "SYSCON_RESETEN", "System Control", "Reset enable"),
    (0x1C100050, "SYSCON_BUSCLKEN", "System Control", "Bus clock enable"),
    (0x1C100078, "SYSCON_IOEN", "System Control", "I/O enable"),
    (0x1C10007C, "SYSCON_GPIOEN", "System Control", "GPIO enable/direction?"),
    (
        0x1C100080,
        "SYSCON_MEMMAN_EXC_CTRL",
        "System Control",
        "MemMan exception control?",
    ),
    (0x1C100088, "SYSCON_NMI13_CTRL", "System Control", "NMI13 control register?"),
    (0x1C1000A0, "SYSCON_NMI10_CTRL", "System Control", "NMI10 control register?"),
    (0x1C1000A4, "SYSCON_NMI11_CTRL", "System Control", "NMI11 control register?"),
    (0x1C1000E0, "SYSCON_NMI14_CTRL", "System Control", "NMI14 control register?"),
    (0x1C1000E4, "SYSCON_NMI15_CTRL", "System Control", "NMI15 control register?"),
    # Interrupt Manager (0x1C30xxxx)
    (0x1C300000, "INTMAN_UNK_00", "Interrupts", "Unknown IntMan Reg 0x00"),
    (0x1C300004, "INTMAN_INTFLG0", "Interrupts", "Interrupt Flag 0-31"),
    (0x1C300008, "INTMAN_INTMSK0", "Interrupts", "Interrupt Mask 0-31"),
    (0x1C300010, "INTMAN_UNK_10", "Interrupts", "Unknown IntMan Reg 0x10"),
    (0x1C300014, "INTMAN_INTFLG1", "Interrupts", "Interrupt Flag 32-63"),
    (0x1C300018, "INTMAN_INTMSK1", "Interrupts", "Interrupt Mask 32-63"),
    (0x1C300020, "INTMAN_UNK_20", "Interrupts", "Unknown IntMan Reg 0x20"),
    (0x1C300024, "INTMAN_INTFLG2", "Interrupts", "Interrupt Flag 38-39, 46-47?"),
    (0x1C300028, "INTMAN_INTMSK2", "Interrupts", "Interrupt Mask 38-39, 46-47?"),
    # Profiler (0x1C40xxxx)
    (0x1C400000, "PROF_PROFEN", "Profiler", "Profiler enable"),
    (0x1C400004, "PROF_CNTSYSCLK", "Profiler", "System clock cycles"),
    (0x1C400008, "PROF_CNTCPUCLK", "Profiler", "CPU clock cycles"),
    (0x1C40000C, "PROF_CNTSTALL", "Profiler", "Total stalled cycles"),
    (0x1C400010, "PROF_CNTSTALLINT", "Profiler", "Internal stalled cycles"),
    (0x1C400014, "PROF_CNTSTALLMEM", "Profiler", "Memory stalled cycles"),
    (0x1C400018, "PROF_CNTSTALLCOP", "Profiler", "Coprocessor stalled cycles"),
    (0x1C40001C, "PROF_CNTSTALLVFPU", "Profiler", "VFPU stalled cycles"),
    (0x1C400020, "PROF_CNTSLEEP", "Profiler", "Sleep cycles"),
    (0x1C400024, "PROF_CNTBUSACCESS", "Profiler", "Bus access cycles"),
    (0x1C400028, "PROF_CNTUCACHELD", "Profiler", "Uncached load count"),
    (0x1C40002C, "PROF_CNTUCACHEST", "Profiler", "Uncached store count"),
    (0x1C400030, "PROF_CNTCACHELD", "Profiler", "Cached load count"),
    (0x1C400034, "PROF_CNTCACHEST", "Profiler", "Cached store count"),
    (0x1C400038, "PROF_CNTICACHEMISS", "Profiler", "I-cache miss count"),
    (0x1C40003C, "PROF_CNTDCACHEMISS", "Profiler", "D-cache miss count"),
    (0x1C400040, "PROF_CNTDCACHEWB", "Profiler", "D-cache writeback count"),
    (0x1C400044, "PROF_CNTCOP0INSN", "Profiler", "Coprocessor 0 instruction count"),
    (0x1C400048, "PROF_CNTFPUINSN", "Profiler", "FPU instruction count"),
    (0x1C40004C, "PROF_CNTVFPUINSN", "Profiler", "VFPU instruction count"),
    (0x1C400050, "PROF_CNTLOCALBUS", "Profiler", "Local bus access cycles"),
    # VME Control (0x1CC0xxxx)
    (0x1CC00010, "VME_VMERESET", "VME", "VME reset"),
    (0x1CC00030, "VME_UNK_30", "VME", "Unknown VME Reg 0x30"),
    (0x1CC00040, "VME_UNK_40", "VME", "Unknown VME Reg 0x40"),
    (0x1CC00070, "VME_UNK_70", "VME", "Unknown VME Reg 0x70"),
    # NAND Flash (0x1D10xxxx, 0x1FF0xxxx)
    (0x1D101000, "NAND_NANDCTRL", "NAND Flash", "NAND control"),
    (0x1D101004, "NAND_NANDSTATUS", "NAND Flash", "NAND status"),
    (0x1D101008, "NAND_NANDCMD", "NAND Flash", "NAND command"),
    (0x1D10100C, "NAND_NANDADDR", "NAND Flash", "NAND address"),
    (0x1D101014, "NAND_NANDRESET", "NAND Flash", "NAND reset?"),
    (0x1D101020, "NAND_NANDDMAADDR", "NAND Flash", "NAND DMA address"),
    (0x1D101024, "NAND_NANDDMACTRL", "NAND Flash", "NAND DMA control"),
    (0x1D101028, "NAND_NANDDMASTATUS", "NAND Flash", "NAND DMA status"),
    (0x1D101038, "NAND_NANDDMAINTR", "NAND Flash", "NAND DMA intr?"),
    (0x1D101200, "NAND_NANDRESUME", "NAND Flash", "NAND resume?"),
    (0x1D101300, "NAND_NANDSERIAL", "NAND Flash", "NAND serial data"),
    (0x1FF00000, "NAND_NANDDMABUF", "NAND Flash", "NAND DMA data buffer (512 bytes)"),
    (0x1FF00800, "NAND_NANDDMAECC", "NAND Flash", "NAND DMA data ECC"),
    (0x1FF00900, "NAND_NANDDMASPARE", "NAND Flash", "NAND DMA spare buffer (16 bytes)"),
    # Graphics Engine (0x07Fxxxxx, 0x1D4xxxxx, 0x1D5xxxxx)
    (0x07F00000, "GE_GECTRLFIFO", "Graphics Engine", "GE control FIFO?"),  # In VRAM
    (0x07F80000, "GE_GEEDRAM_START", "Graphics Engine", "GE EDRAM Start?"),  # In VRAM
    (0x1D400000, "GE_GERESET", "Graphics Engine", "GE reset"),
    (0x1D400008, "GE_GEEDRAMSIZE", "Graphics Engine", "GE EDRAM size"),
    (0x1D400100, "GE_GEEXEC", "Graphics Engine", "Execute GE display list"),
    (0x1D400108, "GE_GEDLISTADDR", "Graphics Engine", "GE display list address"),
    (0x1D500010, "GE_GEEDRAMRESET", "Graphics Engine", "GE EDRAM reset"),
    # KIRK Crypto (0x1DE0xxxx)
    (0x1DE00000, "KIRK_KIRKSIG", "KIRK Crypto", "KIRK signature"),
    (0x1DE00004, "KIRK_KIRKVER", "KIRK Crypto", "KIRK version"),
    (0x1DE00008, "KIRK_KIRKERR", "KIRK Crypto", "KIRK error"),
    (0x1DE0000C, "KIRK_KIRKPHASE", "KIRK Crypto", "KIRK processing phase"),
    (0x1DE00010, "KIRK_KIRKCMD", "KIRK Crypto", "KIRK command"),
    (0x1DE00014, "KIRK_KIRKRESULT", "KIRK Crypto", "KIRK result"),
    (0x1DE00018, "KIRK_UNK_18", "KIRK Crypto", "Unknown KIRK Reg 0x18"),
    (0x1DE0001C, "KIRK_KIRKSTATUS", "KIRK Crypto", "KIRK status"),
    (0x1DE00020, "KIRK_UNK_20", "KIRK Crypto", "Unknown KIRK Reg 0x20"),
    (0x1DE00024, "KIRK_UNK_24", "KIRK Crypto", "Unknown KIRK Reg 0x24"),
    (0x1DE00028, "KIRK_KIRKPRVSTS", "KIRK Crypto", "Previous Status"),
    (0x1DE0002C, "KIRK_KIRKSRC", "KIRK Crypto", "KIRK source buffer address"),
    (0x1DE00030, "KIRK_KIRKDST", "KIRK Crypto", "KIRK destination buffer address"),
    (0x1DE0004C, "KIRK_UNK_4C", "KIRK Crypto", "Unknown KIRK Reg 0x4C"),
    (0x1DE00050, "KIRK_UNK_50", "KIRK Crypto", "Unknown KIRK Reg 0x50"),
    # LCD Controller (0x1E14xxxx)
    (0x1E140000, "LCDC_LCDCEN", "LCD Controller", "LCDC enable?"),
    (0x1E140004, "LCDC_LCDCSYNCDIFF", "LCD Controller", "LCDC sync difference"),
    (0x1E140008, "LCDC_UNK_08", "LCD Controller", "Unknown LCDC Reg 0x08"),
    (0x1E140010, "LCDC_LCDCXBP", "LCD Controller", "LCDC X back porch"),
    (0x1E140014, "LCDC_LCDCXSYNC", "LCD Controller", "LCDC X sync width"),
    (0x1E140018, "LCDC_LCDCXFP", "LCD Controller", "LCDC X front porch"),
    (0x1E14001C, "LCDC_LCDCXRES", "LCD Controller", "LCDC X Resolution"),
    (0x1E140020, "LCDC_LCDCYBP", "LCD Controller", "LCDC Y back porch"),
    (0x1E140024, "LCDC_LCDCYSYNC", "LCD Controller", "LCDC Y sync width"),
    (0x1E140028, "LCDC_LCDCYFP", "LCD Controller", "LCDC Y front porch"),
    (0x1E14002C, "LCDC_LCDCYRES", "LCD Controller", "LCDC Y Resolution"),
    (0x1E140030, "LCDC_LCDCXPOS", "LCD Controller", "LCDC X raster position"),
    (0x1E140034, "LCDC_LCDCYPOS", "LCD Controller", "LCDC Y raster position"),
    (0x1E140040, "LCDC_LCDCYSHIFT", "LCD Controller", "LCDC Y shift"),
    (0x1E140044, "LCDC_LCDCXSHIFT", "LCD Controller", "LCDC X shift"),
    (0x1E140048, "LCDC_LCDCSCLXRES", "LCD Controller", "LCDC scaled X resolution"),
    (0x1E14004C, "LCDC_LCDCSCLYRES", "LCD Controller", "LCDC scaled Y resolution"),
    (0x1E140050, "LCDC_UNK_50", "LCD Controller", "Unknown LCDC Reg 0x50"),
    (0x1E140070, "LCDC_UNK_70", "LCD Controller", "Unknown LCDC Reg 0x70"),
    # GPIO (0x1E24xxxx)
    (0x1E240000, "GPIO_UNK_00", "GPIO", "Unknown GPIO Reg 0x00"),
    (0x1E240004, "GPIO_GPIOREAD", "GPIO", "GPIO Read"),
    (0x1E240008, "GPIO_GPIOSET", "GPIO", "GPIO Set"),
    (0x1E24000C, "GPIO_GPIOCLEAR", "GPIO", "GPIO Clear"),
    # UARTs (0x1E4xxxxx, 0x1E5xxxxx) - Defined via loop below
]

# add uart registers dynamically
for i in range(8):  # UART 1 to 8
    if i < 4:  # UART 1-4 base 0x1E4x0000
        base = 0x1E400000 + i * 0x40000
        uart_num = i + 1
    else:  # UART 5-8 base 0x1E5x0000
        base = 0x1E500000 + (i - 4) * 0x40000
        uart_num = i + 1
    PSP_IO_REGISTERS.extend(
        [
            (base + 0x00, f"UART{uart_num}_FIFO", "UART", f"UART {uart_num} FIFO"),
            (base + 0x18, f"UART{uart_num}_STATUS", "UART", f"UART {uart_num} Status"),
            (
                base + 0x24,
                f"UART{uart_num}_BAUD1",
                "UART",
                f"UART {uart_num} Baudrate Divisor 1",
            ),
            (
                base + 0x28,
                f"UART{uart_num}_BAUD2",
                "UART",
                f"UART {uart_num} Baudrate Divisor 2",
            ),
            (base + 0x2C, f"UART{uart_num}_CTRL", "UART", f"UART {uart_num} Control"),
        ]
    )
