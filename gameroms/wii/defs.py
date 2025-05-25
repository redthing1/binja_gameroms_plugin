# PATH: gameroms/wii/defs.py
from typing import Dict, List, Tuple, Optional
import re


# Helper to parse description from template, removing links and cleaning up
def _parse_desc(text: str) -> str:
    if text is None:
        return ""
    # Remove MediaWiki links like [[Hardware/IPC|IPC]] -> IPC or [[IPC]] -> IPC
    text = re.sub(r"\[\[(?:[^|]+\|)?([^]]+)\]\]", r"\1", text)
    # Remove {{check}} template
    text = re.sub(r"\{\{check\}\}", "(needs verification)", text)
    # Remove other templates like {{reglist|...}} or {{rld|...}} if they accidentally get in description part
    text = re.sub(r"\{\{[^}]+\}\}", "", text)
    # Replace multiple spaces with one, strip leading/trailing whitespace
    text = " ".join(text.split())
    return text.strip()


# Wii Tag Type Definitions
WII_TAG_TYPE_DEFINITIONS: Dict[str, str] = {
    "Memory Region": "🗺️",
    "Hardware Register": "🔩",
    "Hollywood Register": "🎬",  # Main MMIO block for Hollywood
    "System Control": "🛠️",
    "Interrupts": "⚡",
    "MEM1": "💾",  # Main RAM
    "MEM2": "🗳️",  # Auxiliary RAM
    "IPC": "↔️",  # Inter-Processor Communication
    "Timer": "⏱️",
    "Video Interface": "📺",  # VI
    "GPIO": "💡",
    "PLL/Clock": "🕰️",
    "OTP": "🔑",  # One-Time Programmable Memory
    "Debug": "🐞",
    "Global Variable": "🌍",
    "Exception Vector": "❗",
    "Bus Control": "🚌",  # AHB, etc.
    "USB": "🔌",
    "I2C": "⛓️",
    "NAND/Flash": "💾",  # Also for NAND controller if separate from Hollywood MMIO
    "Audio Interface": "🔊",  # AI/DSP related
    "Drive Interface": "💿",  # DI
    "EXI": "↔️",  # EXternal Interface
    "Processor Interface": "↔️",  # PI
    "Memory Interface": "🧠",  # MI, MEM_PROT
}

# Wii I/O Registers (Hollywood, PPC-accessible view: 0xCD000000 base for many)
# Derived from wii_hollywood_regs.txt.
# Assuming 0x0d80xxxx addresses in the doc map to 0xCD00xxxx for PPC virtual space.
# (i.e., listed address - 0x0D800000 + 0xCD000000)
# For registers like MEM_PROT at 0x0d8b420a, it becomes 0xCD0B420A.
WII_IO_REGISTERS: List[Tuple[int, str, str, str]] = [
    # IPC Registers (0xCD000000 - 0xCD00000F)
    (0xCD000000, "HW_IPC_PPCMSG", "IPC", _parse_desc("IPC Message from PPC to ARM")),
    (0xCD000004, "HW_IPC_PPCCTRL", "IPC", _parse_desc("IPC Control from PPC to ARM")),
    (0xCD000008, "HW_IPC_ARMMSG", "IPC", _parse_desc("IPC Message from ARM to PPC")),
    (0xCD00000C, "HW_IPC_ARMCTRL", "IPC", _parse_desc("IPC Control from ARM to PPC")),
    # Timer (0xCD000010 - 0xCD000017)
    (0xCD000010, "HW_TIMER", "Timer", _parse_desc("Starlet Timer value")),
    (0xCD000014, "HW_ALARM", "Timer", _parse_desc("Starlet Timer alarm value")),
    # Video Interface (0xCD000018 - 0xCD000027, plus others)
    (
        0xCD000018,
        "HW_VI1CFG",
        "Video Interface",
        _parse_desc("VI-configuration related, unused?"),
    ),
    (0xCD00001C, "HW_VIDIM", "Video Interface", _parse_desc("Dims the video output")),
    (
        0xCD000024,
        "HW_VISOLID",
        "Video Interface",
        _parse_desc("Sets the video output to a solid color"),
    ),
    # Interrupts (0xCD000030 - 0xCD00005F, partial)
    (
        0xCD000030,
        "HW_PPCIRQFLAG",
        "Interrupts",
        _parse_desc("Hollywood IRQ controller PPC IRQ Flags"),
    ),
    (
        0xCD000034,
        "HW_PPCIRQMASK",
        "Interrupts",
        _parse_desc("Hollywood IRQ controller PPC IRQ Mask"),
    ),
    (
        0xCD000038,
        "HW_ARMIRQFLAG",
        "Interrupts",
        _parse_desc("Hollywood IRQ controller ARM IRQ Flags"),
    ),
    (
        0xCD00003C,
        "HW_ARMIRQMASK",
        "Interrupts",
        _parse_desc("Hollywood IRQ controller ARM IRQ Mask"),
    ),
    (
        0xCD000040,
        "HW_ARMFIQMASK",
        "Interrupts",
        _parse_desc("Hollywood IRQ controller ARM FIQ Mask"),
    ),
    (
        0xCD000044,
        "HW_IOPINTPPC",
        "Interrupts",
        _parse_desc("Interrupt from IO PADS to PPC"),
    ),
    (
        0xCD000048,
        "HW_WDGINTSTS",
        "Timer",
        _parse_desc("Watchdog Interrupt Status"),
    ),  # Also Timer
    (
        0xCD00004C,
        "HW_WDGCFG",
        "Timer",
        _parse_desc("Watchdog Configuration"),
    ),  # Also Timer
    (
        0xCD000050,
        "HW_DMAADRINTSTS",
        "Interrupts",
        _parse_desc("DMA Address Error Interrupt Status"),
    ),
    (
        0xCD000054,
        "HW_CPUADRINTSTS",
        "Interrupts",
        _parse_desc("CPU Address Error Interrupt Status"),
    ),
    (
        0xCD000058,
        "HW_DBGINTSTS",
        "Debug",
        _parse_desc("Debug Interrupt Status"),
    ),  # Also Debug
    (
        0xCD00005C,
        "HW_DBGINTEN",
        "Debug",
        _parse_desc("Debug Interrupt Enable"),
    ),  # Also Debug
    # System/Bus Control & Protection (0xCD000060 - 0xCD000077)
    (
        0xCD000060,
        "HW_SRNPROT",
        "System Control",
        _parse_desc(
            "SRAM Protection/Mirroring (HW_MEMMIRR), Bus control; includes the SRAM bank swap"
        ),
    ),
    (
        0xCD000064,
        "HW_AHBPROT",
        "System Control",
        _parse_desc(
            "Access control for the PPC to access devices on the AHB (HW_BUSPROT)"
        ),
    ),
    (0xCD000068, "HW_I2CIOPINTEN", "I2C", _parse_desc("I2C IOP Interrupt Enable")),
    (0xCD00006C, "HW_I2CIOPINTSTS", "I2C", _parse_desc("I2C IOP Interrupt Status")),
    (
        0xCD000070,
        "HW_AIPPROT",
        "EXI",
        _parse_desc(
            "EXI PPC enable / control / other; Flipper interface compatibility"
        ),
    ),
    (
        0xCD000074,
        "HW_AIPIOCTRL",
        "EXI",
        _parse_desc("AIP IO Control; Flipper interface compatibility/bus control"),
    ),
    # More VI (0xCD000078 - 0xCD00007F)
    (0xCD000078, "HW_VIINTEN", "Video Interface", _parse_desc("VI Interrupt Enable")),
    (0xCD00007C, "HW_VIINTSTS", "Video Interface", _parse_desc("VI Interrupt Status")),
    # USB Debug (0xCD000080 - 0xCD00008F)
    (
        0xCD000080,
        "HW_USBDBG0",
        "USB",
        _parse_desc("USB-related, unused? Debug Register 0"),
    ),
    (
        0xCD000084,
        "HW_USBDBG1",
        "USB",
        _parse_desc("USB-related, unused? Debug Register 1"),
    ),
    (0xCD000088, "HW_USBFRCRST", "USB", _parse_desc("USB Force Reset")),
    (0xCD00008C, "HW_USBIOTEST", "USB", _parse_desc("USB IO Test")),
    # ELA / MemTest (0xCD000090 - 0xCD00009F)
    (
        0xCD000090,
        "HW_ELA_REG_ADDR",
        "Debug",
        _parse_desc("Unknown (embedded logic-analyzer?!) Address"),
    ),
    (
        0xCD000094,
        "HW_ELA_REG_DATA",
        "Debug",
        _parse_desc("Unknown (embedded logic-analyzer?!) Data"),
    ),
    (0xCD000098, "HW_MEMTSTN", "Debug", _parse_desc("Memory Test N")),
    (0xCD00009C, "HW_MEMTSTP", "Debug", _parse_desc("Memory Test P")),
    # GPIO (0xCD0000C0 - 0xCD0000FF)
    (0xCD0000C0, "HW_GPIOB_OUT", "GPIO", _parse_desc("Hollywood GPIOs Port B Output")),
    (
        0xCD0000C4,
        "HW_GPIOB_DIR",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Direction"),
    ),
    (0xCD0000C8, "HW_GPIOB_IN", "GPIO", _parse_desc("Hollywood GPIOs Port B Input")),
    (
        0xCD0000CC,
        "HW_GPIOB_INTLVL",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Interrupt Level"),
    ),
    (
        0xCD0000D0,
        "HW_GPIOB_INTFLAG",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Interrupt Flag"),
    ),
    (
        0xCD0000D4,
        "HW_GPIOB_INTMASK",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Interrupt Mask"),
    ),
    (
        0xCD0000D8,
        "HW_GPIOB_STRAPS",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Straps"),
    ),
    (
        0xCD0000DC,
        "HW_GPIO_ENABLE",
        "GPIO",
        _parse_desc("Hollywood GPIOs Enable (Legacy Main GPIOs)"),
    ),  # Grouped as "HW_GPIO_..."
    (
        0xCD0000E0,
        "HW_GPIO_OUT",
        "GPIO",
        _parse_desc("Hollywood GPIOs Output (Legacy Main GPIOs)"),
    ),
    (
        0xCD0000E4,
        "HW_GPIO_DIR",
        "GPIO",
        _parse_desc("Hollywood GPIOs Direction (Legacy Main GPIOs)"),
    ),
    (
        0xCD0000E8,
        "HW_GPIO_IN",
        "GPIO",
        _parse_desc("Hollywood GPIOs Input (Legacy Main GPIOs)"),
    ),
    (
        0xCD0000EC,
        "HW_GPIO_INTLVL",
        "GPIO",
        _parse_desc("Hollywood GPIOs Interrupt Level (Legacy Main GPIOs)"),
    ),
    (
        0xCD0000F0,
        "HW_GPIO_INTFLAG",
        "GPIO",
        _parse_desc("Hollywood GPIOs Interrupt Flag (Legacy Main GPIOs)"),
    ),
    (
        0xCD0000F4,
        "HW_GPIO_INTMASK",
        "GPIO",
        _parse_desc("Hollywood GPIOs Interrupt Mask (Legacy Main GPIOs)"),
    ),
    (
        0xCD0000F8,
        "HW_GPIO_STRAPS",
        "GPIO",
        _parse_desc("Hollywood GPIOs Straps (Legacy Main GPIOs)"),
    ),
    (0xCD0000FC, "HW_GPIO_OWNER", "GPIO", _parse_desc("Hollywood GPIOs Owner")),
    # AHB Arbiter (0xCD000100 - 0xCD00014F)
    (
        0xCD000100,
        "HW_ARB_CFG_M0",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 0"),
    ),
    (
        0xCD000104,
        "HW_ARB_CFG_M1",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 1"),
    ),
    (
        0xCD000108,
        "HW_ARB_CFG_M2",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 2"),
    ),
    (
        0xCD00010C,
        "HW_ARB_CFG_M3",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 3"),
    ),
    (
        0xCD000110,
        "HW_ARB_CFG_M4",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 4"),
    ),
    (
        0xCD000114,
        "HW_ARB_CFG_M5",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 5"),
    ),
    (
        0xCD000118,
        "HW_ARB_CFG_M6",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 6"),
    ),
    (
        0xCD00011C,
        "HW_ARB_CFG_M7",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 7"),
    ),
    (
        0xCD000120,
        "HW_ARB_CFG_M8",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 8"),
    ),
    (
        0xCD000124,
        "HW_ARB_CFG_M9",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 9"),
    ),
    (
        0xCD000130,
        "HW_ARB_CFG_MC",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master C"),
    ),  # Docs show M0-M9 then MC-MF
    (
        0xCD000134,
        "HW_ARB_CFG_MD",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master D"),
    ),
    (
        0xCD000138,
        "HW_ARB_CFG_ME",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master E"),
    ),
    (
        0xCD00013C,
        "HW_ARB_CFG_MF",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master F"),
    ),
    (
        0xCD000140,
        "HW_ARB_CFG_CPU",
        "Bus Control",
        _parse_desc("AHB Arbiter Config CPU"),
    ),
    (
        0xCD000144,
        "HW_ARB_CFG_DMA",
        "Bus Control",
        _parse_desc("AHB Arbiter Config DMA"),
    ),
    (
        0xCD000148,
        "HW_ARB_PCNTCFG",
        "Bus Control",
        _parse_desc("AHB Arbiter Perf Counter Config"),
    ),
    (
        0xCD00014C,
        "HW_ARB_PCNTSTS",
        "Bus Control",
        _parse_desc("AHB Arbiter Perf Counter Status"),
    ),
    # I2C Slave (0xCD000150 - 0xCD00016F)
    (0xCD000150, "HW_I2CSCTRL_0", "I2C", _parse_desc("I2C Slave Control (instance 0)")),
    (0xCD000154, "HW_I2CSSTS_0", "I2C", _parse_desc("I2C Slave Status (instance 0)")),
    (
        0xCD000158,
        "HW_I2CSRDEN_0",
        "I2C",
        _parse_desc("I2C Slave Read Enable (instance 0)"),
    ),
    (0xCD000160, "HW_I2CSTRAP", "I2C", _parse_desc("I2C Strap Configuration")),
    (
        0xCD000164,
        "HW_I2CSCTRL_1",
        "I2C",
        _parse_desc("I2C Slave Control (instance 1)"),
    ),  # Renamed from HW_I2CSCTRL to avoid conflict
    (
        0xCD000168,
        "HW_I2CSVISETYUV",
        "Video Interface",
        _parse_desc("I2C Slave VI Set YUV (via I2C to VI)"),
    ),
    (
        0xCD00016C,
        "HW_I2CSVISETFILT",
        "Video Interface",
        _parse_desc("I2C Slave VI Set Filter (via I2C to VI)"),
    ),
    # Spares and System (0xCD000170 - 0xCD00019B)
    (0xCD000170, "HW_SPARE2", "System Control", _parse_desc("Spare Register 2")),
    (0xCD000174, "HW_SPARE3", "System Control", _parse_desc("Spare Register 3")),
    (
        0xCD000180,
        "HW_COMPAT",
        "System Control",
        _parse_desc("Compatibility reg (DI stuff, boot code)"),
    ),
    (
        0xCD000184,
        "HW_RESET_AHB",
        "System Control",
        _parse_desc("(ACRRSTAHB) AHB Reset Control"),
    ),
    (0xCD000188, "HW_SPARE0", "System Control", _parse_desc("Spare Register 0")),
    (
        0xCD00018C,
        "HW_BOOT0",
        "System Control",
        _parse_desc("(ACR_SPARE1) Controls boot0 mapping"),
    ),
    (
        0xCD000190,
        "HW_CLOCKS",
        "PLL/Clock",
        _parse_desc("(ACRSYSCTRL) Clock Control (System Speed)"),
    ),
    (
        0xCD000194,
        "HW_RESETS",
        "System Control",
        _parse_desc("(ACRRSTCTRL) System Resets / Power Control"),
    ),
    (
        0xCD000198,
        "HW_IFPOWER",
        "System Control",
        _parse_desc("(ACRCLKGATE) Interface Power Gating Control"),
    ),
    # PLLs (0xCD00019C - 0xCD0001DB)
    (
        0xCD00019C,
        "HW_PLLDR",
        "PLL/Clock",
        _parse_desc("PLL Drive / Clock configuration"),
    ),
    (
        0xCD0001A0,
        "HW_PLLSYSEXT1",
        "PLL/Clock",
        _parse_desc("System PLL External Control 1"),
    ),
    (
        0xCD0001A4,
        "HW_PLLSYSEXT2",
        "PLL/Clock",
        _parse_desc("System PLL External Control 2"),
    ),
    (
        0xCD0001A8,
        "HW_PLLAIEXT1",
        "PLL/Clock",
        _parse_desc("Audio PLL External Control 1"),
    ),
    (
        0xCD0001AC,
        "HW_PLLAIEXT2",
        "PLL/Clock",
        _parse_desc("Audio PLL External Control 2"),
    ),
    (0xCD0001B0, "HW_PLLSYS", "PLL/Clock", _parse_desc("System PLL Control")),
    (
        0xCD0001B4,
        "HW_PLLSYSEXT",
        "PLL/Clock",
        _parse_desc("System PLL External Control (Main)"),
    ),
    (0xCD0001B8, "HW_PLLDSK", "PLL/Clock", _parse_desc("Disk (DI) PLL Control")),
    (0xCD0001BC, "HW_PLLDDR", "PLL/Clock", _parse_desc("DDR (MEM2) PLL Control")),
    (
        0xCD0001C0,
        "HW_PLLDDREXT",
        "PLL/Clock",
        _parse_desc("DDR (MEM2) PLL External Control"),
    ),
    (0xCD0001C4, "HW_PLLVI", "PLL/Clock", _parse_desc("Video Interface PLL Control")),
    (
        0xCD0001C8,
        "HW_PLLVIEXT",
        "PLL/Clock",
        _parse_desc("Video Interface PLL External Control"),
    ),
    (0xCD0001CC, "HW_PLLAI", "PLL/Clock", _parse_desc("Audio Interface PLL Control")),
    (
        0xCD0001D0,
        "HW_PLLAIEXT",
        "PLL/Clock",
        _parse_desc("Audio Interface PLL External Control"),
    ),
    (0xCD0001D4, "HW_PLLUSB", "PLL/Clock", _parse_desc("USB PLL Control")),
    (0xCD0001D8, "HW_PLLUSBEXT", "PLL/Clock", _parse_desc("USB PLL External Control")),
    # IO Control / OTP (0xCD0001DC - 0xCD0001F3)
    (
        0xCD0001DC,
        "HW_IOPWRCTRL",
        "System Control",
        _parse_desc("IOP Power Control (subsystems)"),
    ),
    (
        0xCD0001E0,
        "HW_IOSTRCTRL0",
        "System Control",
        _parse_desc("IO Strength Control 0"),
    ),
    (
        0xCD0001E4,
        "HW_IOSTRCTRL1",
        "System Control",
        _parse_desc("IO Strength Control 1"),
    ),
    (0xCD0001E8, "HW_CLKSTRCTRL", "PLL/Clock", _parse_desc("Clock Strength Control")),
    (0xCD0001EC, "HW_OTPCMD", "OTP", _parse_desc("(ACREFUSEADDR) OTP Command/Address")),
    (0xCD0001F0, "HW_OTPDATA", "OTP", _parse_desc("(ACREFUSEDATA) OTP Data")),
    # Debug, SI, Version (0xCD0001F4 - 0xCD00021B)
    (0xCD0001F4, "HW_DBGCLK", "Debug", _parse_desc("Debug Clock Control")),
    (
        0xCD0001F8,
        "HW_OBSCLKOCTRL",
        "Debug",
        _parse_desc("Observe Clock Output Control"),
    ),
    (0xCD0001FC, "HW_OBSCLKICTRL", "Debug", _parse_desc("Observe Clock Input Control")),
    (0xCD000200, "HW_DBGPORT", "Debug", _parse_desc("Debug Port")),
    (
        0xCD000204,
        "HW_SICLKDIV",
        "System Control",
        _parse_desc("SI Clock Divider (SI-related, unused?)"),
    ),  # "SI" usually Serial Interface
    (
        0xCD000208,
        "HW_SICTRL",
        "System Control",
        _parse_desc("SI Control (SI-related, unused?)"),
    ),
    (
        0xCD00020C,
        "HW_SIDATA",
        "System Control",
        _parse_desc("SI Data (SI-related, unused?)"),
    ),
    (
        0xCD000210,
        "HW_SIINT",
        "System Control",
        _parse_desc("SI Interrupt (SI-related, unused?)"),
    ),
    (
        0xCD000214,
        "HW_VERSION",
        "System Control",
        _parse_desc("(ACRCHIPREVID) Hollywood Version Register"),
    ),
    (0xCD000218, "HW_DBGBUSRD", "Debug", _parse_desc("Debug Bus Read Data")),
    # MEM2 Protection Registers (at 0xCD0Bxxxx base for PPC)
    (
        0xCD0B420A,
        "MEM_PROT",
        "Memory Interface",
        _parse_desc("MEM2 protection enable (16-bit)"),
    ),
    (
        0xCD0B420C,
        "MEM_PROT_START",
        "Memory Interface",
        _parse_desc("MEM2 protection low address (upper 16 bits of physical address)"),
    ),
    (
        0xCD0B420E,
        "MEM_PROT_END",
        "Memory Interface",
        _parse_desc("MEM2 protection high address (upper 16 bits of physical address)"),
    ),
    (
        0xCD0B4228,
        "MEM_FLUSHREQ",
        "Memory Interface",
        _parse_desc("AHB flush request (16-bit)"),
    ),
    (
        0xCD0B422A,
        "MEM_FLUSHACK",
        "Memory Interface",
        _parse_desc("AHB flush ack (16-bit)"),
    ),
]

# Wii Global Symbols / OS Data Area (MEM1: 0x8xxxxxxx)
# From wii_memmap_info.txt "Broadway / IOS Global Memory Locations"
WII_GLOBAL_SYMBOLS: List[Tuple[int, str, str, str, Optional[str]]] = [
    # Address, Name, TagType, Description, DataType (string for parse_type_string or None)
    (
        0x80000000,
        "GameID",
        "Global Variable",
        _parse_desc("Game Code 'RSPE' (Wii Sports)"),
        "char[4]",
    ),
    (0x80000004, "MakerCode", "Global Variable", _parse_desc("Maker code"), "char[2]"),
    (
        0x80000006,
        "DiscNumber",
        "Global Variable",
        _parse_desc("Disc Number (multidisc games)"),
        "uint8_t",
    ),
    (
        0x80000007,
        "DiscVersion",
        "Global Variable",
        _parse_desc("Disc Version"),
        "uint8_t",
    ),
    (
        0x80000008,
        "DiscStreamingFlag",
        "Global Variable",
        _parse_desc("Disc Streaming flag"),
        "uint8_t",
    ),
    (
        0x80000009,
        "DiscStreamingBufferSize",
        "Global Variable",
        _parse_desc("Disc Streaming buffer size"),
        "uint8_t",
    ),
    (
        0x80000018,
        "DiscLayoutMagicWii",
        "Global Variable",
        _parse_desc("Disc layout magic (Wii) 0x5D1C9EA3"),
        "uint32_t",
    ),
    (
        0x8000001C,
        "DiscLayoutMagicGC",
        "Global Variable",
        _parse_desc("Disc layout magic (GC) 0xC2339F3D"),
        "uint32_t",
    ),
    (
        0x80000020,
        "NintendoBootCodeMagic",
        "Global Variable",
        _parse_desc("Nintendo Standard Boot Code. 0x0D15EA5E"),
        "uint32_t",
    ),
    (
        0x80000024,
        "ApploaderVersion",
        "Global Variable",
        _parse_desc("Version (set by apploader) 0x00000001"),
        "uint32_t",
    ),
    (
        0x80000028,
        "MEM1SizePhysicalHeader",
        "Global Variable",
        _parse_desc("Memory Size (Physical) 24MB (Header) 0x01800000"),
        "uint32_t",
    ),
    (
        0x8000002C,
        "ProductionBoardModel",
        "Global Variable",
        _parse_desc("Production Board Model 0x00000023"),
        "uint32_t",
    ),
    (
        0x80000030,
        "ArenaLoHeader",
        "Global Variable",
        _parse_desc("Arena Low (Header Value) 0x00000000"),
        "uint32_t",
    ),  # This is likely a pointer so void*
    (
        0x80000034,
        "ArenaHiHeader",
        "Global Variable",
        _parse_desc("Arena High (Header Value, e.g. 0x817FEC60)"),
        "uint32_t",
    ),  # This is likely a pointer so void*
    (
        0x80000038,
        "FSTLocationHeader",
        "Global Variable",
        _parse_desc("Start of FST (Header Value, varies)"),
        "void*",
    ),
    (
        0x8000003C,
        "FSTMaxSizeHeader",
        "Global Variable",
        _parse_desc("Maximum FST Size (Header Value, varies)"),
        "uint32_t",
    ),
    (
        0x80000040,
        "pDBStruct",
        "Debug",
        _parse_desc("Pointer to the beginning of the DB global struct"),
        "void*",
    ),
    (
        0x80000044,
        "DBExceptionMask",
        "Debug",
        _parse_desc("DB marked exception mask"),
        "uint32_t",
    ),
    (
        0x80000048,
        "DBExceptionDestination",
        "Debug",
        _parse_desc("DB exception destination (e.g. 0x81340000)"),
        "void*",
    ),
    (0x8000004C, "DBReturnAddress", "Debug", _parse_desc("DB return address"), "void*"),
    (
        0x80000060,
        "OSDebuggerHook",
        "Debug",
        _parse_desc("Hook to be jumped to by debugged exceptions (OSDBIntegrator)"),
        "void*",
    ),  # Function pointer
    (
        0x800000C0,
        "pOSContextCurrentReal",
        "Global Variable",
        _parse_desc("Pointer to Current OSContext instance (real mode)"),
        "void*",
    ),  # OSContext*
    (
        0x800000C4,
        "UserInterruptMask",
        "Interrupts",
        _parse_desc("User interrupt mask (e.g. 0xffffff00)"),
        "uint32_t",
    ),
    (
        0x800000C8,
        "OSInterruptMask",
        "Interrupts",
        _parse_desc("Revolution OS interrupt mask (usually 0)"),
        "uint32_t",
    ),
    (
        0x800000CC,
        "CurrentVideoMode",
        "Video Interface",
        _parse_desc("Value indicating current video mode (0=NTSC,1=PAL,2=MPAL)"),
        "uint32_t",
    ),
    (
        0x800000D4,
        "pOSContextCurrentTranslated",
        "Global Variable",
        _parse_desc("Pointer to Current OSContext instance (translated mode)"),
        "void*",
    ),  # OSContext*
    (
        0x800000D8,
        "pOSContextFPRSave",
        "Global Variable",
        _parse_desc("Pointer to OSContext to save FPRs to (NULL if unused)"),
        "void*",
    ),  # OSContext*
    (
        0x800000DC,
        "pOSThreadEarliest",
        "Global Variable",
        _parse_desc("Pointer to the earliest created OSThread"),
        "void*",
    ),  # OSThread*
    (
        0x800000E0,
        "pOSThreadLatest",
        "Global Variable",
        _parse_desc("Pointer to the most recently created OSThread"),
        "void*",
    ),  # OSThread*
    (
        0x800000E4,
        "pOSThreadCurrent",
        "Global Variable",
        _parse_desc("Pointer to the current OSThread"),
        "void*",
    ),  # OSThread*
    (
        0x800000EC,
        "DevDebuggerMonitorAddr",
        "Debug",
        _parse_desc("Dev Debugger Monitor Address (If present, e.g. 0x81800000)"),
        "void*",
    ),
    (
        0x800000F0,
        "SimulatedMemorySize",
        "Global Variable",
        _parse_desc("Simulated Memory Size (e.g. 0x01800000)"),
        "uint32_t",
    ),
    (
        0x800000F4,
        "pBI2Data",
        "Global Variable",
        _parse_desc("Pointer to data from partition's bi2.bin or emulated bi2.bin"),
        "void*",
    ),
    (
        0x800000F8,
        "ConsoleBusSpeed",
        "System Control",
        _parse_desc("Console Bus Speed (e.g. 0x0E7BE2C0 for 243MHz)"),
        "uint32_t",
    ),
    (
        0x800000FC,
        "ConsoleCPUSpeed",
        "System Control",
        _parse_desc("Console CPU Speed (e.g. 0x2B73A840 for 729MHz)"),
        "uint32_t",
    ),
    # Exception Handlers Area (PPC vectors are typically at fixed offsets from 0x0 in their segment)
    (
        0x80000100,
        "SystemResetExceptionHandler",
        "Exception Vector",
        _parse_desc("System Reset Exception Handler"),
        "void()",
    ),
    (
        0x80000200,
        "MachineCheckExceptionHandler",
        "Exception Vector",
        _parse_desc("Machine Check Exception Handler"),
        "void()",
    ),
    (
        0x80000300,
        "DSIExceptionHandler",
        "Exception Vector",
        _parse_desc("Data Storage Interrupt (DSI) Exception Handler"),
        "void()",
    ),
    (
        0x80000400,
        "ISIExceptionHandler",
        "Exception Vector",
        _parse_desc("Instruction Storage Interrupt (ISI) Exception Handler"),
        "void()",
    ),
    (
        0x80000500,
        "ExternalInterruptHandler",
        "Exception Vector",
        _parse_desc("External Interrupt Handler"),
        "void()",
    ),
    (
        0x80000600,
        "AlignmentExceptionHandler",
        "Exception Vector",
        _parse_desc("Alignment Exception Handler"),
        "void()",
    ),
    (
        0x80000700,
        "ProgramExceptionHandler",
        "Exception Vector",
        _parse_desc("Program Exception Handler (syscall, trap)"),
        "void()",
    ),
    (
        0x80000800,
        "FloatingPointUnavailableHandler",
        "Exception Vector",
        _parse_desc("Floating Point Unavailable Exception Handler"),
        "void()",
    ),
    (
        0x80000900,
        "DecrementerExceptionHandler",
        "Exception Vector",
        _parse_desc("Decrementer Exception Handler"),
        "void()",
    ),
    (
        0x80000C00,
        "SystemCallExceptionHandler",
        "Exception Vector",
        _parse_desc("System Call Exception Handler (PPC SC instruction)"),
        "void()",
    ),
    (
        0x80000D00,
        "TraceExceptionHandler",
        "Exception Vector",
        _parse_desc("Trace Exception Handler (debug)"),
        "void()",
    ),
    (
        0x80000F00,
        "FloatingPointAssistHandler",
        "Exception Vector",
        _parse_desc("Floating Point Assist Exception Handler"),
        "void()",
    ),  # For software FP emulation
    (
        0x80001300,
        "InstructionAddressBreakpointHandler",
        "Exception Vector",
        _parse_desc(
            "IABR Exception Handler (PPC60x specific, may differ for Broadway)"
        ),
        "void()",
    ),
    (
        0x80001400,
        "SystemManagementInterruptHandler",
        "Exception Vector",
        _parse_desc("SMI Handler"),
        "void()",
    ),
    (
        0x80001700,
        "ThermalManagementInterruptHandler",
        "Exception Vector",
        _parse_desc("Thermal Management Interrupt Handler"),
        "void()",
    ),
    (
        0x80001800,
        "OSHomebrewAreaStart",
        "Global Variable",
        _parse_desc("Unused exception handler area, often used by homebrew"),
        None,
    ),  # This is a region marker
    (
        0x80003000,
        "OSExceptionVectorAreaStart",
        "Global Variable",
        _parse_desc("OS managed exception vector area start"),
        None,
    ),  # Region marker
    (
        0x80003040,
        "pOSInterruptTable",
        "Interrupts",
        _parse_desc("Pointer to __OSInterrupt table"),
        "void*",
    ),  # OSInterruptHandler*
    (
        0x800030C0,
        "EXIProbeStartTime0",
        "EXI",
        _parse_desc("EXI Probe start time, channel 0"),
        "uint32_t",
    ),
    (
        0x800030C4,
        "EXIProbeStartTime1",
        "EXI",
        _parse_desc("EXI Probe start time, channel 1"),
        "uint32_t",
    ),
    (
        0x800030C8,
        "pRELLoadedFirst",
        "Global Variable",
        _parse_desc("Pointer to the first loaded REL file"),
        "void*",
    ),  # RELHeader*
    (
        0x800030CC,
        "pRELLoadedLast",
        "Global Variable",
        _parse_desc("Pointer to the last loaded REL file"),
        "void*",
    ),  # RELHeader*
    (
        0x800030D0,
        "pRELModuleNameTable",
        "Global Variable",
        _parse_desc("Pointer to a REL module name table (or 0)"),
        "char**",
    ),
    (
        0x800030D8,
        "OSTime",
        "Global Variable",
        _parse_desc("System time (64-bit, units of 1/40.5MHz since 2000-01-01)"),
        "uint64_t",
    ),
    (
        0x800030E4,
        "OSPADButtonStatePort4Apploader",
        "Global Variable",
        _parse_desc("Apploader GCN port 4 button state for NR disc support"),
        "uint16_t",
    ),
    (
        0x800030E6,
        "DVDDeviceCodeAddress",
        "Drive Interface",
        _parse_desc("DVD Device Code Address"),
        "uint16_t",
    ),
    (
        0x800030E8,
        "OSDebugInfoPtr",
        "Debug",
        _parse_desc("Pointer to Debug-related info"),
        "void*",
    ),
    (
        0x800030F0,
        "DOLExecuteParameters",
        "Global Variable",
        _parse_desc("DOL Execute Parameters (usually 0)"),
        "uint32_t",
    ),
    (
        0x80003100,
        "OSPhysicalMEM1Size",
        "Global Variable",
        _parse_desc("Physical MEM1 size (set by IOS)"),
        "uint32_t",
    ),
    (
        0x80003104,
        "OSSimulatedMEM1Size",
        "Global Variable",
        _parse_desc("Simulated MEM1 size (set by OS)"),
        "uint32_t",
    ),
    (
        0x8000310C,
        "OSMEM1ArenaStart",
        "Global Variable",
        _parse_desc("MEM1 Arena Start (start of usable memory by game, set by IOS)"),
        "void*",
    ),
    (
        0x80003110,
        "OSMEM1ArenaEnd",
        "Global Variable",
        _parse_desc("MEM1 Arena End (end of usable memory by game, set by IOS)"),
        "void*",
    ),
    (
        0x80003118,
        "OSPhysicalMEM2Size",
        "Global Variable",
        _parse_desc("Physical MEM2 size (set by IOS, e.g. 0x04000000)"),
        "uint32_t",
    ),
    (
        0x8000311C,
        "OSSimulatedMEM2Size",
        "Global Variable",
        _parse_desc("Simulated MEM2 size (set by IOS)"),
        "uint32_t",
    ),
    (
        0x80003120,
        "OSMEM2PPCAddressableEnd",
        "Global Variable",
        _parse_desc("End of MEM2 addressable to PPC (e.g. 0x93400000, set by IOS)"),
        "void*",
    ),
    (
        0x80003124,
        "OSMEM2UsableStart",
        "Global Variable",
        _parse_desc("Usable MEM2 Start (by game, set by IOS, e.g. 0x90000800)"),
        "void*",
    ),
    (
        0x80003128,
        "OSMEM2UsableEnd",
        "Global Variable",
        _parse_desc("Usable MEM2 End (by game, set by IOS, e.g. 0x933E0000)"),
        "void*",
    ),
    (
        0x80003130,
        "OS_IPCBufferStart",
        "IOS Communication",
        _parse_desc("IOS IPC Buffer Start (e.g. 0x933E0000)"),
        "void*",
    ),
    (
        0x80003134,
        "OS_IPCBufferEnd",
        "IOS Communication",
        _parse_desc("IOS IPC Buffer End (e.g. 0x93400000)"),
        "void*",
    ),
    (
        0x80003138,
        "OSHollywoodVersion",
        "Global Variable",
        _parse_desc("Hollywood Version (from HW_VERSION, e.g. 0x00000011)"),
        "uint32_t",
    ),
    (
        0x80003140,
        "OSIOSVersion",
        "Global Variable",
        _parse_desc("IOS version (e.g. 0x00090204 = IOS9 v2.4)"),
        "uint32_t",
    ),
    (
        0x80003144,
        "OSIOSBuildDate",
        "Global Variable",
        _parse_desc("IOS Build Date (e.g. 0x00062507 = June 25, 2007)"),
        "uint32_t",
    ),
    (
        0x80003148,
        "OSIOSReservedHeapStart",
        "IOS Communication",
        _parse_desc("IOS Reserved Heap Start (e.g. 0x93600000)"),
        "void*",
    ),
    (
        0x8000314C,
        "OSIOSReservedHeapEnd",
        "IOS Communication",
        _parse_desc("IOS Reserved Heap End (e.g. 0x93620000)"),
        "void*",
    ),
    (
        0x80003158,
        "OSGDDRVendorCode",
        "Global Variable",
        _parse_desc("GDDR Vendor Code (e.g. 0x0000FF16)"),
        "uint32_t",
    ),
    (
        0x8000315C,
        "OSBootIndicator",
        "Global Variable",
        _parse_desc("Set by IOS/NAND Boot Program (e.g. 0x80 for NAND boot)"),
        "uint8_t",
    ),
    (
        0x8000315D,
        "OSEnableLegacyDI",
        "Drive Interface",
        _parse_desc("Enable legacy DI mode? (0x80 for true)"),
        "uint8_t",
    ),
    (
        0x8000315E,
        "OSDevkitBootProgramVersion",
        "Global Variable",
        _parse_desc("Devkit boot program version (e.g. 0x0113 for v1.13)"),
        "uint16_t",
    ),
    (
        0x80003160,
        "OSInitSemaphore",
        "Global Variable",
        _parse_desc("Init semaphore for main() (OSSem*)"),
        "uint32_t",
    ),
    (
        0x80003164,
        "OSGCModeFlag",
        "Global Variable",
        _parse_desc("GC (MIOS) mode flag, set to 1 by boot2 for MIOS shutdown"),
        "uint32_t",
    ),
    (
        0x80003180,
        "OSWC24GameID",
        "Global Variable",
        _parse_desc("Game ID for WC24 mode (must match 0x80000000)"),
        "char[4]",
    ),
    (
        0x80003184,
        "OSApplicationType",
        "Global Variable",
        _parse_desc("Application type. 0x80 disc, 0x81 channel."),
        "uint8_t",
    ),
    (
        0x80003186,
        "OSApplicationType2",
        "Global Variable",
        _parse_desc("Secondary application type (channel load context)"),
        "uint8_t",
    ),
    (
        0x80003188,
        "OSMinimumIOSVersion",
        "Global Variable",
        _parse_desc("Minimum IOS version required (major/title version)"),
        "uint32_t",
    ),
    (
        0x8000318C,
        "OSTitleLaunchCode",
        "Global Variable",
        _parse_desc("Title Booted from NAND (Launch Code)"),
        "uint32_t",
    ),
    (
        0x80003190,
        "OSTitleReturnCode",
        "Global Variable",
        _parse_desc("Title Booted from NAND (Return Code)"),
        "uint32_t",
    ),
    (
        0x80003194,
        "OSDataPartitionType",
        "Drive Interface",
        _parse_desc("Data partition type from disc (usually 0)"),
        "uint32_t",
    ),
    (
        0x80003198,
        "OSDataPartitionOffset",
        "Drive Interface",
        _parse_desc("Data partition offset from disc (LBA words)"),
        "uint32_t",
    ),
    (
        0x8000319C,
        "OSDiscLayerFlag",
        "Drive Interface",
        _parse_desc("Set by apploader (0x80 single-layer, 0x81 dual-layer)"),
        "uint8_t",
    ),
    (
        0x80003400,
        "OSBS1BootCodeAreaStart",
        "Global Variable",
        _parse_desc("Area for BS1 boot code (start)"),
        None,
    ),  # Region marker
    (
        0x80003F00,
        "OSAppExecutableAreaStart",
        "Global Variable",
        _parse_desc("Standard application executable area start"),
        None,
    ),  # Region marker
    (
        0x81330000,
        "OSLoaderExecutableAreaStart",
        "Global Variable",
        _parse_desc("Loader executable area start / App Executable Area End"),
        None,
    ),  # Region marker
]
