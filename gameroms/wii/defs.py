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
    "IOS Communication": "📨",  # For PPC-IOS shared memory buffers/params
}

# Wii I/O Registers (Hollywood, PPC-accessible view: 0xCD000000 base for many)
# Derived from wii_hollywood_regs.txt.
# PPC_Addr = Doc_Addr - 0x0D800000 + 0xCD000000
# Format: (address, name, tag_category, description, size_bits)
WII_IO_REGISTERS: List[Tuple[int, str, str, str, int]] = [
    # IPC (0xCD000000 - 0xCD00000F) - Group Desc from doc: "IPC"
    (
        0xCD000000,
        "HW_IPC_PPCMSG",
        "IPC",
        _parse_desc("IPC Message from PPC to ARM"),
        32,
    ),
    (
        0xCD000004,
        "HW_IPC_PPCCTRL",
        "IPC",
        _parse_desc("IPC Control from PPC to ARM"),
        32,
    ),
    (
        0xCD000008,
        "HW_IPC_ARMMSG",
        "IPC",
        _parse_desc("IPC Message from ARM to PPC"),
        32,
    ),
    (
        0xCD00000C,
        "HW_IPC_ARMCTRL",
        "IPC",
        _parse_desc("IPC Control from ARM to PPC"),
        32,
    ),
    # Timer (0xCD000010 - 0xCD000017) - Group Desc from doc: "Starlet Timer"
    (0xCD000010, "HW_TIMER", "Timer", _parse_desc("Starlet Timer value"), 32),
    (0xCD000014, "HW_ALARM", "Timer", _parse_desc("Starlet Timer alarm value"), 32),
    # Video Interface (various)
    (
        0xCD000018,
        "HW_VI1CFG",
        "Video Interface",
        _parse_desc("VI-configuration related, unused?"),
        32,
    ),
    (
        0xCD00001C,
        "HW_VIDIM",
        "Video Interface",
        _parse_desc("Dims the video output"),
        32,
    ),
    (
        0xCD000024,
        "HW_VISOLID",
        "Video Interface",
        _parse_desc("Sets the video output to a solid color"),
        32,
    ),
    # Interrupts (0xCD000030 - 0xCD00005F, partial) - Group Desc from doc: "Hollywood IRQ controller"
    (
        0xCD000030,
        "HW_PPCIRQFLAG",
        "Interrupts",
        _parse_desc("Hollywood IRQ controller PPC IRQ Flags"),
        32,
    ),
    (
        0xCD000034,
        "HW_PPCIRQMASK",
        "Interrupts",
        _parse_desc("Hollywood IRQ controller PPC IRQ Mask"),
        32,
    ),
    (
        0xCD000038,
        "HW_ARMIRQFLAG",
        "Interrupts",
        _parse_desc("Hollywood IRQ controller ARM IRQ Flags"),
        32,
    ),
    (
        0xCD00003C,
        "HW_ARMIRQMASK",
        "Interrupts",
        _parse_desc("Hollywood IRQ controller ARM IRQ Mask"),
        32,
    ),
    (
        0xCD000040,
        "HW_ARMFIQMASK",
        "Interrupts",
        _parse_desc("Hollywood IRQ controller ARM FIQ Mask"),
        32,
    ),
    (
        0xCD000044,
        "HW_IOPINTPPC",
        "Interrupts",
        _parse_desc("Interrupt from IO PADS to PPC"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD000048,
        "HW_WDGINTSTS",
        "Timer",
        _parse_desc("Watchdog Interrupt Status"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD00004C,
        "HW_WDGCFG",
        "Timer",
        _parse_desc("Watchdog Configuration"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD000050,
        "HW_DMAADRINTSTS",
        "Interrupts",
        _parse_desc("DMA Address Error Interrupt Status"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD000054,
        "HW_CPUADRINTSTS",
        "Interrupts",
        _parse_desc("CPU Address Error Interrupt Status"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD000058,
        "HW_DBGINTSTS",
        "Debug",
        _parse_desc("Debug Interrupt Status"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD00005C,
        "HW_DBGINTEN",
        "Debug",
        _parse_desc("Debug Interrupt Enable"),
        32,
    ),  # Doc has no specific desc, prior was good
    # System/Bus Control & Protection (0xCD000060 - 0xCD000077)
    (
        0xCD000060,
        "HW_SRNPROT",
        "System Control",
        _parse_desc("Probably bus control; includes the SRAM bank swap"),
        32,
    ),
    (
        0xCD000064,
        "HW_AHBPROT",
        "Bus Control",
        _parse_desc(
            "Access control for the PPC to access devices on the AHB (HW_BUSPROT)"
        ),
        32,
    ),
    (
        0xCD000068,
        "HW_I2CIOPINTEN",
        "I2C",
        _parse_desc("I2C IOP Interrupt Enable"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD00006C,
        "HW_I2CIOPINTSTS",
        "I2C",
        _parse_desc("I2C IOP Interrupt Status"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD000070,
        "HW_AIPPROT",
        "EXI",
        _parse_desc(
            "EXI PPC enable / control / other; probably related to Flipper interface compatibility"
        ),
        32,
    ),
    (
        0xCD000074,
        "HW_AIPIOCTRL",
        "EXI",
        _parse_desc("Probably related to Flipper interface compatibility/bus control"),
        32,
    ),
    # More VI (0xCD000078 - 0xCD00007F)
    (
        0xCD000078,
        "HW_VIINTEN",
        "Video Interface",
        _parse_desc("VI Interrupt Enable"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD00007C,
        "HW_VIINTSTS",
        "Video Interface",
        _parse_desc("VI Interrupt Status"),
        32,
    ),  # Doc has no specific desc, prior was good
    # USB Debug (0xCD000080 - 0xCD00008F) - Group Desc from doc: "USB-related, unused?"
    (
        0xCD000080,
        "HW_USBDBG0",
        "USB",
        _parse_desc("USB-related, unused? Debug Register 0"),
        32,
    ),
    (
        0xCD000084,
        "HW_USBDBG1",
        "USB",
        _parse_desc("USB-related, unused? Debug Register 1"),
        32,
    ),
    (
        0xCD000088,
        "HW_USBFRCRST",
        "USB",
        _parse_desc("USB Force Reset"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD00008C,
        "HW_USBIOTEST",
        "USB",
        _parse_desc("USB IO Test"),
        32,
    ),  # Doc has no specific desc, prior was good
    # ELA / MemTest (0xCD000090 - 0xCD00009F) - Group Desc from doc: "Unknown (embedded logic-analyzer?!)"
    (
        0xCD000090,
        "HW_ELA_REG_ADDR",
        "Debug",
        _parse_desc("Unknown (embedded logic-analyzer?!) Address"),
        32,
    ),
    (
        0xCD000094,
        "HW_ELA_REG_DATA",
        "Debug",
        _parse_desc("Unknown (embedded logic-analyzer?!) Data"),
        32,
    ),
    (
        0xCD000098,
        "HW_MEMTSTN",
        "Debug",
        _parse_desc("Memory Test N"),
        32,
    ),  # Doc has no specific desc, prior was good
    (
        0xCD00009C,
        "HW_MEMTSTP",
        "Debug",
        _parse_desc("Memory Test P"),
        32,
    ),  # Doc has no specific desc, prior was good
    # GPIO (0xCD0000C0 - 0xCD0000FF) - Group Desc from doc: "Hollywood GPIOs"
    (
        0xCD0000C0,
        "HW_GPIOB_OUT",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Output"),
        32,
    ),
    (
        0xCD0000C4,
        "HW_GPIOB_DIR",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Direction"),
        32,
    ),
    (
        0xCD0000C8,
        "HW_GPIOB_IN",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Input"),
        32,
    ),
    (
        0xCD0000CC,
        "HW_GPIOB_INTLVL",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Interrupt Level"),
        32,
    ),
    (
        0xCD0000D0,
        "HW_GPIOB_INTFLAG",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Interrupt Flag"),
        32,
    ),
    (
        0xCD0000D4,
        "HW_GPIOB_INTMASK",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Interrupt Mask"),
        32,
    ),
    (
        0xCD0000D8,
        "HW_GPIOB_STRAPS",
        "GPIO",
        _parse_desc("Hollywood GPIOs Port B Straps"),
        32,
    ),
    (
        0xCD0000DC,
        "HW_GPIO_ENABLE",
        "GPIO",
        _parse_desc("Hollywood GPIOs Enable (Legacy Main GPIOs)"),
        32,
    ),
    (
        0xCD0000E0,
        "HW_GPIO_OUT",
        "GPIO",
        _parse_desc("Hollywood GPIOs Output (Legacy Main GPIOs)"),
        32,
    ),
    (
        0xCD0000E4,
        "HW_GPIO_DIR",
        "GPIO",
        _parse_desc("Hollywood GPIOs Direction (Legacy Main GPIOs)"),
        32,
    ),
    (
        0xCD0000E8,
        "HW_GPIO_IN",
        "GPIO",
        _parse_desc("Hollywood GPIOs Input (Legacy Main GPIOs)"),
        32,
    ),
    (
        0xCD0000EC,
        "HW_GPIO_INTLVL",
        "GPIO",
        _parse_desc("Hollywood GPIOs Interrupt Level (Legacy Main GPIOs)"),
        32,
    ),
    (
        0xCD0000F0,
        "HW_GPIO_INTFLAG",
        "GPIO",
        _parse_desc("Hollywood GPIOs Interrupt Flag (Legacy Main GPIOs)"),
        32,
    ),
    (
        0xCD0000F4,
        "HW_GPIO_INTMASK",
        "GPIO",
        _parse_desc("Hollywood GPIOs Interrupt Mask (Legacy Main GPIOs)"),
        32,
    ),
    (
        0xCD0000F8,
        "HW_GPIO_STRAPS",
        "GPIO",
        _parse_desc("Hollywood GPIOs Straps (Legacy Main GPIOs)"),
        32,
    ),
    (0xCD0000FC, "HW_GPIO_OWNER", "GPIO", _parse_desc("Hollywood GPIOs Owner"), 32),
    # AHB Arbiter (0xCD000100 - 0xCD00014F) - Group Desc from doc: "AHB-related registers?"
    (
        0xCD000100,
        "HW_ARB_CFG_M0",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 0"),
        32,
    ),
    (
        0xCD000104,
        "HW_ARB_CFG_M1",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 1"),
        32,
    ),
    (
        0xCD000108,
        "HW_ARB_CFG_M2",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 2"),
        32,
    ),
    (
        0xCD00010C,
        "HW_ARB_CFG_M3",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 3"),
        32,
    ),
    (
        0xCD000110,
        "HW_ARB_CFG_M4",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 4"),
        32,
    ),
    (
        0xCD000114,
        "HW_ARB_CFG_M5",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 5"),
        32,
    ),
    (
        0xCD000118,
        "HW_ARB_CFG_M6",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 6"),
        32,
    ),
    (
        0xCD00011C,
        "HW_ARB_CFG_M7",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 7"),
        32,
    ),
    (
        0xCD000120,
        "HW_ARB_CFG_M8",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 8"),
        32,
    ),
    (
        0xCD000124,
        "HW_ARB_CFG_M9",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master 9"),
        32,
    ),
    (
        0xCD000130,
        "HW_ARB_CFG_MC",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master C"),
        32,
    ),
    (
        0xCD000134,
        "HW_ARB_CFG_MD",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master D"),
        32,
    ),
    (
        0xCD000138,
        "HW_ARB_CFG_ME",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master E"),
        32,
    ),
    (
        0xCD00013C,
        "HW_ARB_CFG_MF",
        "Bus Control",
        _parse_desc("AHB Arbiter Config Master F"),
        32,
    ),
    (
        0xCD000140,
        "HW_ARB_CFG_CPU",
        "Bus Control",
        _parse_desc("AHB Arbiter Config CPU"),
        32,
    ),
    (
        0xCD000144,
        "HW_ARB_CFG_DMA",
        "Bus Control",
        _parse_desc("AHB Arbiter Config DMA"),
        32,
    ),
    (
        0xCD000148,
        "HW_ARB_PCNTCFG",
        "Bus Control",
        _parse_desc("AHB Arbiter Perf Counter Config"),
        32,
    ),
    (
        0xCD00014C,
        "HW_ARB_PCNTSTS",
        "Bus Control",
        _parse_desc("AHB Arbiter Perf Counter Status"),
        32,
    ),
    # I2C Slave (0xCD000150 - 0xCD00016F)
    (
        0xCD000150,
        "HW_I2CSCTRL_0",
        "I2C",
        _parse_desc("I2C Slave Control (instance 0)"),
        32,
    ),  # Doc name HW_I2CSCTRL
    (
        0xCD000154,
        "HW_I2CSSTS_0",
        "I2C",
        _parse_desc("I2C Slave Status (instance 0)"),
        32,
    ),  # Doc name HW_I2CSSTS
    (
        0xCD000158,
        "HW_I2CSRDEN_0",
        "I2C",
        _parse_desc("I2C Slave Read Enable (instance 0)"),
        32,
    ),  # Doc name HW_I2CSRDEN
    (0xCD000160, "HW_I2CSTRAP", "I2C", _parse_desc("I2C Strap Configuration"), 32),
    (
        0xCD000164,
        "HW_I2CSCTRL_1",
        "I2C",
        _parse_desc("I2C Slave Control (instance 1)"),
        32,
    ),  # Doc name HW_I2CSCTRL
    (
        0xCD000168,
        "HW_I2CSVISETYUV",
        "Video Interface",
        _parse_desc("I2C Slave VI Set YUV (via I2C to VI)"),
        32,
    ),
    (
        0xCD00016C,
        "HW_I2CSVISETFILT",
        "Video Interface",
        _parse_desc("I2C Slave VI Set Filter (via I2C to VI)"),
        32,
    ),
    # Spares and System (0xCD000170 - 0xCD00019B)
    (0xCD000170, "HW_SPARE2", "System Control", _parse_desc("Spare Register 2"), 32),
    (0xCD000174, "HW_SPARE3", "System Control", _parse_desc("Spare Register 3"), 32),
    (
        0xCD000180,
        "HW_COMPAT",
        "System Control",
        _parse_desc("Some DI stuff and boot code and (needs verification)"),
        32,
    ),
    (
        0xCD000184,
        "HW_RESET_AHB",
        "System Control",
        _parse_desc("(ACRRSTAHB) AHB Reset Control"),
        32,
    ),
    (0xCD000188, "HW_SPARE0", "System Control", _parse_desc("Spare Register 0"), 32),
    (
        0xCD00018C,
        "HW_BOOT0",
        "System Control",
        _parse_desc("(ACR_SPARE1) Controls boot0 mapping? (needs verification)"),
        32,
    ),
    (
        0xCD000190,
        "HW_CLOCKS",
        "PLL/Clock",
        _parse_desc("(ACRSYSCTRL) clock stuff?"),
        32,
    ),
    (
        0xCD000194,
        "HW_RESETS",
        "System Control",
        _parse_desc("(ACRRSTCTRL) System resets / power (needs verification)"),
        32,
    ),
    (
        0xCD000198,
        "HW_IFPOWER",
        "System Control",
        _parse_desc("(ACRCLKGATE) set to 0xFFFFFF when Wii wakes up (interfaces)"),
        32,
    ),
    # PLLs (0xCD00019C - 0xCD0001DB) - Group Desc from doc: "PLL/Clock configuration (?)"
    (
        0xCD00019C,
        "HW_PLLDR",
        "PLL/Clock",
        _parse_desc("PLL Drive / Clock configuration"),
        32,
    ),
    (
        0xCD0001A0,
        "HW_PLLSYSEXT1",
        "PLL/Clock",
        _parse_desc("System PLL External Control 1"),
        32,
    ),
    (
        0xCD0001A4,
        "HW_PLLSYSEXT2",
        "PLL/Clock",
        _parse_desc("System PLL External Control 2"),
        32,
    ),
    (
        0xCD0001A8,
        "HW_PLLAIEXT1",
        "PLL/Clock",
        _parse_desc("Audio PLL External Control 1"),
        32,
    ),
    (
        0xCD0001AC,
        "HW_PLLAIEXT2",
        "PLL/Clock",
        _parse_desc("Audio PLL External Control 2"),
        32,
    ),  # Doc: HW_PLLATEXT2, using AI for consistency
    (0xCD0001B0, "HW_PLLSYS", "PLL/Clock", _parse_desc("System PLL Control"), 32),
    (
        0xCD0001B4,
        "HW_PLLSYSEXT",
        "PLL/Clock",
        _parse_desc("System PLL External Control (Main)"),
        32,
    ),
    (0xCD0001B8, "HW_PLLDSK", "PLL/Clock", _parse_desc("Disk (DI) PLL Control"), 32),
    (0xCD0001BC, "HW_PLLDDR", "PLL/Clock", _parse_desc("DDR (MEM2) PLL Control"), 32),
    (
        0xCD0001C0,
        "HW_PLLDDREXT",
        "PLL/Clock",
        _parse_desc("DDR (MEM2) PLL External Control"),
        32,
    ),
    (
        0xCD0001C4,
        "HW_PLLVI",
        "PLL/Clock",
        _parse_desc("Video Interface PLL Control"),
        32,
    ),
    (
        0xCD0001C8,
        "HW_PLLVIEXT",
        "PLL/Clock",
        _parse_desc("Video Interface PLL External Control"),
        32,
    ),
    (
        0xCD0001CC,
        "HW_PLLAI",
        "PLL/Clock",
        _parse_desc("Audio Interface PLL Control"),
        32,
    ),
    (
        0xCD0001D0,
        "HW_PLLAIEXT",
        "PLL/Clock",
        _parse_desc("Audio Interface PLL External Control"),
        32,
    ),
    (0xCD0001D4, "HW_PLLUSB", "PLL/Clock", _parse_desc("USB PLL Control"), 32),
    (
        0xCD0001D8,
        "HW_PLLUSBEXT",
        "PLL/Clock",
        _parse_desc("USB PLL External Control"),
        32,
    ),
    # IO Control / OTP (0xCD0001DC - 0xCD0001F3)
    (
        0xCD0001DC,
        "HW_IOPWRCTRL",
        "System Control",
        _parse_desc("set to 0xFFFFFFF when Wii wakes up (subsystems)"),
        32,
    ),
    (
        0xCD0001E0,
        "HW_IOSTRCTRL0",
        "System Control",
        _parse_desc("IO Strength Control 0"),
        32,
    ),  # Group desc "More clock registers?"
    (
        0xCD0001E4,
        "HW_IOSTRCTRL1",
        "System Control",
        _parse_desc("IO Strength Control 1"),
        32,
    ),
    (
        0xCD0001E8,
        "HW_CLKSTRCTRL",
        "PLL/Clock",
        _parse_desc("Clock Strength Control"),
        32,
    ),
    (0xCD0001EC, "HW_OTPCMD", "OTP", _parse_desc("(ACREFUSEADDR) OTP"), 32),
    (0xCD0001F0, "HW_OTPDATA", "OTP", _parse_desc("(ACREFUSEDATA) OTP Data"), 32),
    # Debug, SI, Version (0xCD0001F4 - 0xCD00021B)
    (
        0xCD0001F4,
        "HW_DBGCLK",
        "Debug",
        _parse_desc("Debug Clock Control"),
        32,
    ),  # Group desc "Debug registers"
    (
        0xCD0001F8,
        "HW_OBSCLKOCTRL",
        "Debug",
        _parse_desc("Observe Clock Output Control"),
        32,
    ),
    (
        0xCD0001FC,
        "HW_OBSCLKICTRL",
        "Debug",
        _parse_desc("Observe Clock Input Control"),
        32,
    ),
    (0xCD000200, "HW_DBGPORT", "Debug", _parse_desc("Debug Port"), 32),
    (
        0xCD000204,
        "HW_SICLKDIV",
        "System Control",
        _parse_desc("SI-related, unused?"),
        32,
    ),  # Group desc "SI-related, unused?"
    (
        0xCD000208,
        "HW_SICTRL",
        "System Control",
        _parse_desc("SI Control (SI-related, unused?)"),
        32,
    ),
    (
        0xCD00020C,
        "HW_SIDATA",
        "System Control",
        _parse_desc("SI Data (SI-related, unused?)"),
        32,
    ),
    (
        0xCD000210,
        "HW_SIINT",
        "System Control",
        _parse_desc("SI Interrupt (SI-related, unused?)"),
        32,
    ),
    (
        0xCD000214,
        "HW_VERSION",
        "System Control",
        _parse_desc("(ACRCHIPREVID) Hollywood version"),
        32,
    ),
    (0xCD000218, "HW_DBGBUSRD", "Debug", _parse_desc("Debug Bus Read Data"), 32),
    # MEM2 Protection Registers (at 0xCD0Bxxxx base for PPC)
    (
        0xCD0B420A,
        "MEM_PROT",
        "Memory Interface",
        _parse_desc("MEM2 protection enable"),
        16,
    ),
    (
        0xCD0B420C,
        "MEM_PROT_START",
        "Memory Interface",
        _parse_desc("MEM2 protection low address (upper 16 bits)"),
        16,
    ),
    (
        0xCD0B420E,
        "MEM_PROT_END",
        "Memory Interface",
        _parse_desc("MEM2 protection high address (upper 16 bits)"),
        16,
    ),
    (
        0xCD0B4228,
        "MEM_FLUSHREQ",
        "Memory Interface",
        _parse_desc("AHB flush request"),
        16,
    ),
    (0xCD0B422A, "MEM_FLUSHACK", "Memory Interface", _parse_desc("AHB flush ack"), 16),
]

# Wii Global Symbols / OS Data Area (MEM1: 0x8xxxxxxx)
# From wii_memmap_info.txt "Broadway / IOS Global Memory Locations"
# Format: (Address, Name, TagType, Description, DataType (string for parse_type_string or None))
WII_GLOBAL_SYMBOLS: List[Tuple[int, str, str, str, Optional[str]]] = [
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
        _parse_desc("Disc layout magic (Wii)"),
        "uint32_t",
    ),
    (
        0x8000001C,
        "DiscLayoutMagicGC",
        "Global Variable",
        _parse_desc("Disc layout magic (GC)"),
        "uint32_t",
    ),
    (
        0x80000020,
        "NintendoBootCodeMagic",
        "Global Variable",
        _parse_desc("Nintendo Standard Boot Code."),
        "uint32_t",
    ),
    (
        0x80000024,
        "ApploaderVersion",
        "Global Variable",
        _parse_desc("Version (set by apploader)"),
        "uint32_t",
    ),
    (
        0x80000028,
        "MEM1SizePhysicalHeader",
        "Global Variable",
        _parse_desc("Memory Size (Physical) 24MB"),
        "uint32_t",
    ),
    (
        0x8000002C,
        "ProductionBoardModel",
        "Global Variable",
        _parse_desc("Production Board Model"),
        "uint32_t",
    ),
    (
        0x80000030,
        "ArenaLoHeader",
        "Global Variable",
        _parse_desc("Arena Low"),
        "uint32_t",
    ),
    (
        0x80000034,
        "ArenaHiHeader",
        "Global Variable",
        _parse_desc("Arena High"),
        "uint32_t",
    ),
    (
        0x80000038,
        "FSTLocationHeader",
        "Global Variable",
        _parse_desc("Start of FST (varies in all games)"),
        "void*",
    ),
    (
        0x8000003C,
        "FSTMaxSizeHeader",
        "Global Variable",
        _parse_desc("Maximum FST Size (varies in all games)"),
        "uint32_t",
    ),
    (
        0x80000040,
        "pDBStruct",
        "Debug",
        _parse_desc("Beginning of the DB global struct"),
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
        _parse_desc("DB exception destination"),
        "void*",
    ),
    (0x8000004C, "DBReturnAddress", "Debug", _parse_desc("DB return address"), "void*"),
    (
        0x80000060,
        "OSDebuggerHook",
        "Debug",
        _parse_desc(
            "Hook to be jumped to by debugged exceptions, but is disabled in production software. If nothing is written to it, SDK titles will write the 0x20 bytes of instructions here."
        ),
        "void*",
    ),  # Size in doc is 0x24
    (
        0x800000C0,
        "pOSContextCurrentReal",
        "Global Variable",
        _parse_desc("Current OSContext instance (real mode)"),
        "void*",
    ),
    (
        0x800000C4,
        "UserInterruptMask",
        "Interrupts",
        _parse_desc("User interrupt mask"),
        "uint32_t",
    ),
    (
        0x800000C8,
        "OSInterruptMask",
        "Interrupts",
        _parse_desc("Revolution OS interrupt mask"),
        "uint32_t",
    ),
    (
        0x800000CC,
        "CurrentVideoMode",
        "Video Interface",
        _parse_desc(
            "Value indicating the current video mode. 0 = NTSC, 1 = PAL, 2 = MPAL"
        ),
        "uint32_t",
    ),
    (
        0x800000D4,
        "pOSContextCurrentTranslated",
        "Global Variable",
        _parse_desc("Current OSContext instance (translated mode)"),
        "void*",
    ),
    (
        0x800000D8,
        "pOSContextFPRSave",
        "Global Variable",
        _parse_desc(
            "OSContext to save FPRs to (NULL if floating point mode hasn't been used since the last interrupt)"
        ),
        "void*",
    ),
    (
        0x800000DC,
        "pOSThreadEarliest",
        "Global Variable",
        _parse_desc("Pointer to the earliest created OSThread"),
        "void*",
    ),
    (
        0x800000E0,
        "pOSThreadLatest",
        "Global Variable",
        _parse_desc("Pointer to the most recently created OSThread"),
        "void*",
    ),
    (
        0x800000E4,
        "pOSThreadCurrent",
        "Global Variable",
        _parse_desc("Pointer to the current OSThread"),
        "void*",
    ),
    (
        0x800000EC,
        "DevDebuggerMonitorAddr",
        "Debug",
        _parse_desc("Dev Debugger Monitor Address (If present)"),
        "void*",
    ),
    (
        0x800000F0,
        "SimulatedMemorySize",
        "Global Variable",
        _parse_desc("Simulated Memory Size"),
        "uint32_t",
    ),
    (
        0x800000F4,
        "pBI2Data",
        "Global Variable",
        _parse_desc(
            "Pointer to data read from partition's bi2.bin, set by apploader, or the emulated bi2.bin created by the NAND Boot Program"
        ),
        "void*",
    ),
    (
        0x800000F8,
        "ConsoleBusSpeed",
        "System Control",
        _parse_desc("Console Bus Speed"),
        "uint32_t",
    ),
    (
        0x800000FC,
        "ConsoleCPUSpeed",
        "System Control",
        _parse_desc("Console CPU Speed"),
        "uint32_t",
    ),
    # Exception Handlers Area (PPC vectors are typically at fixed offsets from 0x0 in their segment)
    # The doc groups 0x80000100 to 0x800017FF (size 0x1700) as "Exception handlers (0x100 bytes reserved for each handler)"
    # Individual handlers are standard PPC exception vector offsets.
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
    # (0x80000A00 is Performance Monitor interrupt, not listed explicitly but fits pattern)
    # (0x80000B00 is IBAT Miss, not listed explicitly)
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
    # (0x80000E00 is FP Assist (emulation using 7xx/G3 extension), not listed)
    (
        0x80000F00,
        "FloatingPointAssistHandler",
        "Exception Vector",
        _parse_desc("Floating Point Assist Exception Handler (software FP emulation)"),
        "void()",
    ),  # Listed in prior defs, not explicitly in table but fits pattern
    # (0x80001000 - 0x800012FF are other specific exceptions, not in table)
    (
        0x80001300,
        "InstructionAddressBreakpointHandler",
        "Exception Vector",
        _parse_desc("IABR Exception Handler"),
        "void()",
    ),  # Listed in prior defs
    (
        0x80001400,
        "SystemManagementInterruptHandler",
        "Exception Vector",
        _parse_desc("SMI Handler"),
        "void()",
    ),  # Listed in prior defs
    # (0x80001500 is DBAT Miss, not listed)
    # (0x80001600 is reserved, not listed)
    (
        0x80001700,
        "ThermalManagementInterruptHandler",
        "Exception Vector",
        _parse_desc("Thermal Management Interrupt Handler"),
        "void()",
    ),  # Listed in prior defs
    (
        0x80001800,
        "OSHomebrewAreaStart",
        "Global Variable",
        _parse_desc(
            "Unused exception handler area, the SDK does not use or clear it. It is often used by homebrew to store persistent code here like Gecko OS's code handler, Bluebomb or The Homebrew Channel's reload stub, which libogc jumps to upon homebrew exit."
        ),
        None,
    ),
    (
        0x80003000,
        "OSExceptionVectorAreaStart",
        "Global Variable",
        _parse_desc("Exception vector area"),
        None,
    ),  # Doc size 0x3c
    (
        0x80003040,
        "pOSInterruptTable",
        "Interrupts",
        _parse_desc("__OSInterrupt table."),
        "void*",
    ),
    (
        0x800030C0,
        "EXIProbeTimes",
        "EXI",
        _parse_desc("EXI Probe start times, for both channels 0 and 1."),
        "uint32_t[2]",
    ),  # Doc size 8 bytes
    (
        0x800030C8,
        "pRELLoadedFirst",
        "Global Variable",
        _parse_desc(
            "Related to Nintendo's dynamic linking system (REL). Pointer to the first loaded REL file."
        ),
        "void*",
    ),
    (
        0x800030CC,
        "pRELLoadedLast",
        "Global Variable",
        _parse_desc(
            "Related to Nintendo's dynamic linking system (REL). Pointer to the last loaded REL file."
        ),
        "void*",
    ),
    (
        0x800030D0,
        "pRELModuleNameTable",
        "Global Variable",
        _parse_desc(
            "Pointer to a REL module name table, or 0. Added to the name offset in each REL file."
        ),
        "char**",
    ),
    (
        0x800030D8,
        "OSTime",
        "Global Variable",
        _parse_desc(
            "System time, measured as time since January 1st 2000 in units of 1/40500000th of a second."
        ),
        "uint64_t",
    ),
    (
        0x800030E4,
        "OSPADButtonStatePort4Apploader",
        "Global Variable",
        _parse_desc(
            "__OSPADButton. Apploader puts button state of GCN port 4 at game start here for Gamecube NR disc support"
        ),
        "uint16_t",
    ),
    (
        0x800030E6,
        "DVDDeviceCodeAddress",
        "Drive Interface",
        _parse_desc("DVD Device Code Address"),
        "uint16_t",
    ),
    (0x800030E8, "OSDebugInfoPtr", "Debug", _parse_desc("Debug-related info"), "void*"),
    (
        0x800030F0,
        "DOLExecuteParameters",
        "Global Variable",
        _parse_desc("DOL Execute Parameters"),
        "uint32_t",
    ),
    (
        0x80003100,
        "OSPhysicalMEM1Size",
        "Global Variable",
        _parse_desc("Physical MEM1 size"),
        "uint32_t",
    ),
    (
        0x80003104,
        "OSSimulatedMEM1Size",
        "Global Variable",
        _parse_desc("Simulated MEM1 size"),
        "uint32_t",
    ),
    (
        0x8000310C,
        "OSMEM1ArenaStart",
        "Global Variable",
        _parse_desc("MEM1 Arena Start (start of usable memory by the game)"),
        "void*",
    ),
    (
        0x80003110,
        "OSMEM1ArenaEnd",
        "Global Variable",
        _parse_desc("MEM1 Arena End (end of usable memory by the game)"),
        "void*",
    ),
    (
        0x80003118,
        "OSPhysicalMEM2Size",
        "Global Variable",
        _parse_desc("Physical MEM2 size. (0x3118-0x314C are set by IOS upon reload.)"),
        "uint32_t",
    ),
    (
        0x8000311C,
        "OSSimulatedMEM2Size",
        "Global Variable",
        _parse_desc("Simulated MEM2 size."),
        "uint32_t",
    ),
    (
        0x80003120,
        "OSMEM2PPCAddressableEnd",
        "Global Variable",
        _parse_desc("End of MEM2 addressable to PPC."),
        "void*",
    ),
    (
        0x80003124,
        "OSMEM2UsableStart",
        "Global Variable",
        _parse_desc("Usable MEM2 Start (start of usable memory by the game)"),
        "void*",
    ),
    (
        0x80003128,
        "OSMEM2UsableEnd",
        "Global Variable",
        _parse_desc("Usable MEM2 End (end of usable memory by the game)"),
        "void*",
    ),
    (
        0x80003130,
        "OS_IPCBufferStart",
        "IOS Communication",
        _parse_desc("IOS IPC Buffer Start"),
        "void*",
    ),
    (
        0x80003134,
        "OS_IPCBufferEnd",
        "IOS Communication",
        _parse_desc("IOS IPC Buffer End"),
        "void*",
    ),
    (
        0x80003138,
        "OSHollywoodVersion",
        "Global Variable",
        _parse_desc("Hollywood Version"),
        "uint32_t",
    ),
    (
        0x80003140,
        "OSIOSVersion",
        "Global Variable",
        _parse_desc("IOS version (e.g. 090204 = IOS9, v2.4)"),
        "uint32_t",
    ),  # Example format is part of desc
    (
        0x80003144,
        "OSIOSBuildDate",
        "Global Variable",
        _parse_desc("IOS Build Date (e.g. 62507 = 06/25/07 = June 25, 2007)"),
        "uint32_t",
    ),  # Example format is part of desc
    (
        0x80003148,
        "OSIOSReservedHeapStart",
        "IOS Communication",
        _parse_desc("IOS Reserved Heap Start"),
        "void*",
    ),
    (
        0x8000314C,
        "OSIOSReservedHeapEnd",
        "IOS Communication",
        _parse_desc("IOS Reserved Heap End"),
        "void*",
    ),
    (
        0x80003158,
        "OSGDDRVendorCode",
        "Global Variable",
        _parse_desc("GDDR Vendor Code"),
        "uint32_t",
    ),
    (
        0x8000315C,
        "OSBootIndicator",
        "Global Variable",
        _parse_desc(
            "During the boot process, u32 0x315c is first set to 0xdeadbeef by IOS in the boot_ppc syscall. The value is set to 0x80 by the NAND Boot Program to indicate that it was loaded by the boot program (and probably 0x81 by apploaders)"
        ),
        "uint8_t",
    ),  # Doc has uint32_t but desc implies uint8_t usage
    (
        0x8000315D,
        "OSEnableLegacyDI",
        "Drive Interface",
        _parse_desc(
            '"Enable legacy DI" mode? 0x81 = false, anything else means true (though typically set to 0x80). Required to be set when loading Gamecube apploader.'
        ),
        "uint8_t",
    ),
    (
        0x8000315E,
        "OSDevkitBootProgramVersion",
        "Global Variable",
        _parse_desc(
            '"Devkit boot program version", written to by the system menu. The value carries over to disc games. 0x0113 appears to mean v1.13.'
        ),
        "uint16_t",
    ),
    (
        0x80003160,
        "OSInitSemaphore",
        "Global Variable",
        _parse_desc("Init semaphore (1-2 main() waits for this to clear)"),
        "uint32_t",
    ),
    (
        0x80003164,
        "OSGCModeFlag",
        "Global Variable",
        _parse_desc(
            "GC (MIOS) mode flag, set to 1 by boot2 when MIOS triggers a shutdown; the System Menu reads this and turns off the console if it is set to 1 and state.dat is set appropriately."
        ),
        "uint32_t",
    ),
    (
        0x80003180,
        "OSWC24GameID",
        "Global Variable",
        _parse_desc(
            "Game ID 'RSPE' Wii Sports ID. If these 4 bytes don't match the ID at 80000000, WC24 mode in games is disabled."
        ),
        "char[4]",
    ),
    (
        0x80003184,
        "OSApplicationType",
        "Global Variable",
        _parse_desc("Application type. 0x80 for disc games, 0x81 for channels."),
        "uint8_t",
    ),
    (
        0x80003186,
        "OSApplicationType2",
        "Global Variable",
        _parse_desc(
            "Application type 2. Appears to be set to the when a game loads a channel (e.g. Mario Kart Wii loading the region select menu will result in this being 0x80 from the disc and the main application type being 0x81, or the Wii Fit channel transitioning to the Wii Fit disc will result in this being 0x81 and the main type being 0x80)."
        ),
        "uint8_t",
    ),
    (
        0x80003188,
        "OSMinimumIOSVersion",
        "Global Variable",
        _parse_desc(
            "Minimum IOS version (2 bytes for the major version, 2 bytes for the title version)"
        ),
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
        _parse_desc(
            "While reading a disc, the system menu reads the first partition table (0x20 bytes from 0x00040020) and stores a pointer to the data partition entry. When launching the disc game, it copies the partition type to 0x3194. The partition type for data partitions is 0, so typically this location always has 0."
        ),
        "uint32_t",
    ),
    (
        0x80003198,
        "OSDataPartitionOffset",
        "Drive Interface",
        _parse_desc(
            "While reading a disc, the system menu reads the first partition table (0x20 bytes from 0x00040020) and stores a pointer to the data partition entry. When launching the disc game, it copies the partition offset to 0x3198."
        ),
        "uint32_t",
    ),
    (
        0x8000319C,
        "OSDiscLayerFlag",
        "Drive Interface",
        _parse_desc(
            "Set by the apploader to 0x80 for single-layer discs and 0x81 for dual-layer discs (determined by whether 0x7ed40000 is the value at offset 0x30 in the partition's bi2.bin; it seems that that value is 0 for single-layer discs). Early titles' apploaders do not set it at all, leaving the value as 0. This controls the out-of-bounds Error #001 read for titles that do make such a read: they try to read at 0x7ed40000 for dual-layer discs and 0x460a0000 for single-layer discs."
        ),
        "uint8_t",
    ),
    (
        0x80003400,
        "OSBS1BootCodeAreaStart",
        "Global Variable",
        _parse_desc('"BS1" boot code'),
        None,
    ),  # Region marker
    (
        0x80003F00,
        "OSAppExecutableAreaStart",
        "Global Variable",
        _parse_desc("Standard application executable area"),
        None,
    ),  # Region marker
    (
        0x81330000,
        "OSLoaderExecutableAreaStart",
        "Global Variable",
        _parse_desc("Loader executable area, also used by a NAND Boot Program"),
        None,
    ),  # Region marker
]
