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


# Wii Tag Type Definitions (expanded for GameCube)
WII_TAG_TYPE_DEFINITIONS: Dict[str, str] = {
    "Memory Region": "🗺️",
    "Hardware Register": "🔩", # Generic hardware register
    "Broadway Register": "⚙️", # Broadway CPU specific registers
    "Hollywood Register": "🎬",  # Main MMIO block for Hollywood
    "System Control": "🛠️",
    "Interrupts": "⚡",
    "MEM1": "💾",  # Main RAM
    "MEM2": "🗳️",  # Auxiliary RAM
    "IPC": "↔️",  # Inter-Processor Communication
    "Timer": "⏱️",
    "Video Interface": "📺",  # VI (Shared GameCube/Wii)
    "GPIO": "💡",
    "PLL/Clock": "🕰️",
    "OTP": "🔑",  # One-Time Programmable Memory
    "Debug": "🐞",
    "Global Variable": "🌍",
    "Exception Vector": "❗",
    "Bus Control": "🚌",  # AHB, etc.
    "USB": "🔌",
    "I2C": "⛓️",
    "NAND/Flash": "💾",
    "Audio Interface": "🔊",  # AI (Shared GameCube/Wii)
    "Drive Interface": "💿",  # DI (Shared GameCube/Wii)
    "EXI": "↔️",  # EXternal Interface (Shared GameCube/Wii)
    "Processor Interface": "↔️",  # PI (Shared GameCube/Wii)
    "Memory Interface": "🐏",  # MI (Shared GameCube/Wii)
    "IOS Communication": "📨",
    # GameCube Specific Tags
    "Command Processor Register": "🕹️", # CP
    "Pixel Engine Register": "🎨",      # PE
    "DSP Register": "🎶",               # DSP Interface Registers
    "Serial Interface Register": "💬",  # SI
    "Graphics FIFO": "📥",
}

# Wii I/O Registers (Hollywood, PPC-accessible view: 0xCD000000 base for many)
# Format: (address, name, tag_category, description, size_bits)
WII_IO_REGISTERS: List[Tuple[int, str, str, str, int]] = [
    # IPC (0xCD000000 - 0xCD00000F)
    (0xCD000000, "HW_IPC_PPCMSG", "IPC", _parse_desc("IPC Message from PPC to ARM."), 32),
    (0xCD000004, "HW_IPC_PPCCTRL", "IPC", _parse_desc("IPC Control from PPC to ARM."), 32),
    (0xCD000008, "HW_IPC_ARMMSG", "IPC", _parse_desc("IPC Message from ARM to PPC."), 32),
    (0xCD00000C, "HW_IPC_ARMCTRL", "IPC", _parse_desc("IPC Control from ARM to PPC."), 32),
    # Timer (0xCD000010 - 0xCD000017)
    (0xCD000010, "HW_TIMER", "Timer", _parse_desc("Starlet Timer value."), 32),
    (0xCD000014, "HW_ALARM", "Timer", _parse_desc("Starlet Timer alarm value."), 32),
    # Video Interface (various)
    (0xCD000018, "HW_VI1CFG", "Video Interface", _parse_desc("VI-configuration related, potentially unused. Related to VISEL bit 1."), 32),
    (0xCD00001C, "HW_VIDIM", "Video Interface", _parse_desc("Dims the video output."), 32),
    (0xCD000024, "HW_VISOLID", "Video Interface", _parse_desc("Sets the video output to a solid color."), 32),
    # Interrupts (0xCD000030 - 0xCD00005F, partial)
    (0xCD000030, "HW_PPCIRQFLAG", "Interrupts", _parse_desc("Hollywood IRQ controller PPC IRQ Flags."), 32),
    (0xCD000034, "HW_PPCIRQMASK", "Interrupts", _parse_desc("Hollywood IRQ controller PPC IRQ Mask."), 32),
    (0xCD000038, "HW_ARMIRQFLAG", "Interrupts", _parse_desc("Hollywood IRQ controller ARM IRQ Flags."), 32),
    (0xCD00003C, "HW_ARMIRQMASK", "Interrupts", _parse_desc("Hollywood IRQ controller ARM IRQ Mask."), 32),
    (0xCD000040, "HW_ARMFIQMASK", "Interrupts", _parse_desc("Hollywood IRQ controller ARM FIQ Mask."), 32),
    (0xCD000044, "HW_IOPINTPPC", "Interrupts", _parse_desc("Interrupt from IO PADS to PPC."), 32),
    (0xCD000048, "HW_WDGINTSTS", "Timer", _parse_desc("Watchdog Interrupt Status."), 32),
    (0xCD00004C, "HW_WDGCFG", "Timer", _parse_desc("Watchdog Configuration."), 32),
    (0xCD000050, "HW_DMAADRINTSTS", "Interrupts", _parse_desc("DMA Address Error Interrupt Status."), 32),
    (0xCD000054, "HW_CPUADRINTSTS", "Interrupts", _parse_desc("CPU Address Error Interrupt Status."), 32),
    (0xCD000058, "HW_DBGINTSTS", "Debug", _parse_desc("Debug Interrupt Status."), 32),
    (0xCD00005C, "HW_DBGINTEN", "Debug", _parse_desc("Debug Interrupt Enable."), 32),
    # System/Bus Control & Protection (0xCD000060 - 0xCD000077)
    (0xCD000060, "HW_SRNPROT", "System Control", _parse_desc("Bus control for SRAM visibility and mirroring; includes SRAM bank swap."), 32),
    (0xCD000064, "HW_AHBPROT", "Bus Control", _parse_desc("Access control for PPC and IOP to devices on the AHB. Also known as HW_BUSPROT."), 32),
    (0xCD000068, "HW_I2CIOPINTEN", "I2C", _parse_desc("I2C IOP Interrupt Enable."), 32),
    (0xCD00006C, "HW_I2CIOPINTSTS", "I2C", _parse_desc("I2C IOP Interrupt Status."), 32),
    (0xCD000070, "HW_AIPPROT", "EXI", _parse_desc("EXI bus enable and control; Flipper interface compatibility."), 32),
    (0xCD000074, "HW_AIPIOCTRL", "EXI", _parse_desc("AIP IO Control; Flipper interface compatibility and bus control."), 32),
    # More VI (0xCD000078 - 0xCD00007F)
    (0xCD000078, "HW_VIINTEN", "Video Interface", _parse_desc("VI Interrupt Enable."), 32),
    (0xCD00007C, "HW_VIINTSTS", "Video Interface", _parse_desc("VI Interrupt Status."), 32),
    # USB Debug (0xCD000080 - 0xCD00008F)
    (0xCD000080, "HW_USBDBG0", "USB", _parse_desc("USB-related debug register 0, potentially unused."), 32),
    (0xCD000084, "HW_USBDBG1", "USB", _parse_desc("USB-related debug register 1, potentially unused."), 32),
    (0xCD000088, "HW_USBFRCRST", "USB", _parse_desc("USB Force Reset."), 32),
    (0xCD00008C, "HW_USBIOTEST", "USB", _parse_desc("USB IO Test."), 32),
    # ELA / MemTest (0xCD000090 - 0xCD00009F)
    (0xCD000090, "HW_ELA_REG_ADDR", "Debug", _parse_desc("Address register for Embedded Logic Analyzer (ELA)."), 32),
    (0xCD000094, "HW_ELA_REG_DATA", "Debug", _parse_desc("Data register for Embedded Logic Analyzer (ELA)."), 32),
    (0xCD000098, "HW_MEMTSTN", "Debug", _parse_desc("Memory Test N."), 32),
    (0xCD00009C, "HW_MEMTSTP", "Debug", _parse_desc("Memory Test P."), 32),
    # GPIO (0xCD0000C0 - 0xCD0000FF)
    (0xCD0000C0, "HW_GPIOB_OUT", "GPIO", _parse_desc("Hollywood GPIOs Port B Output."), 32),
    (0xCD0000C4, "HW_GPIOB_DIR", "GPIO", _parse_desc("Hollywood GPIOs Port B Direction."), 32),
    (0xCD0000C8, "HW_GPIOB_IN", "GPIO", _parse_desc("Hollywood GPIOs Port B Input."), 32),
    (0xCD0000CC, "HW_GPIOB_INTLVL", "GPIO", _parse_desc("Hollywood GPIOs Port B Interrupt Level."), 32),
    (0xCD0000D0, "HW_GPIOB_INTFLAG", "GPIO", _parse_desc("Hollywood GPIOs Port B Interrupt Flag."), 32),
    (0xCD0000D4, "HW_GPIOB_INTMASK", "GPIO", _parse_desc("Hollywood GPIOs Port B Interrupt Mask."), 32),
    (0xCD0000D8, "HW_GPIOB_STRAPS", "GPIO", _parse_desc("Hollywood GPIOs Port B Straps."), 32),
    (0xCD0000DC, "HW_GPIO_ENABLE", "GPIO", _parse_desc("Hollywood GPIOs Enable (Legacy Main GPIOs)."), 32),
    (0xCD0000E0, "HW_GPIO_OUT", "GPIO", _parse_desc("Hollywood GPIOs Output (Legacy Main GPIOs)."), 32),
    (0xCD0000E4, "HW_GPIO_DIR", "GPIO", _parse_desc("Hollywood GPIOs Direction (Legacy Main GPIOs)."), 32),
    (0xCD0000E8, "HW_GPIO_IN", "GPIO", _parse_desc("Hollywood GPIOs Input (Legacy Main GPIOs)."), 32),
    (0xCD0000EC, "HW_GPIO_INTLVL", "GPIO", _parse_desc("Hollywood GPIOs Interrupt Level (Legacy Main GPIOs)."), 32),
    (0xCD0000F0, "HW_GPIO_INTFLAG", "GPIO", _parse_desc("Hollywood GPIOs Interrupt Flag (Legacy Main GPIOs)."), 32),
    (0xCD0000F4, "HW_GPIO_INTMASK", "GPIO", _parse_desc("Hollywood GPIOs Interrupt Mask (Legacy Main GPIOs)."), 32),
    (0xCD0000F8, "HW_GPIO_STRAPS", "GPIO", _parse_desc("Hollywood GPIOs Straps (Legacy Main GPIOs)."), 32),
    (0xCD0000FC, "HW_GPIO_OWNER", "GPIO", _parse_desc("Hollywood GPIOs Owner."), 32),
    # AHB Arbiter (0xCD000100 - 0xCD00014F)
    (0xCD000100, "HW_ARB_CFG_M0", "Bus Control", _parse_desc("AHB Arbiter Config Master 0."), 32),
    (0xCD000104, "HW_ARB_CFG_M1", "Bus Control", _parse_desc("AHB Arbiter Config Master 1."), 32),
    (0xCD000108, "HW_ARB_CFG_M2", "Bus Control", _parse_desc("AHB Arbiter Config Master 2."), 32),
    (0xCD00010C, "HW_ARB_CFG_M3", "Bus Control", _parse_desc("AHB Arbiter Config Master 3."), 32),
    (0xCD000110, "HW_ARB_CFG_M4", "Bus Control", _parse_desc("AHB Arbiter Config Master 4."), 32),
    (0xCD000114, "HW_ARB_CFG_M5", "Bus Control", _parse_desc("AHB Arbiter Config Master 5."), 32),
    (0xCD000118, "HW_ARB_CFG_M6", "Bus Control", _parse_desc("AHB Arbiter Config Master 6."), 32),
    (0xCD00011C, "HW_ARB_CFG_M7", "Bus Control", _parse_desc("AHB Arbiter Config Master 7."), 32),
    (0xCD000120, "HW_ARB_CFG_M8", "Bus Control", _parse_desc("AHB Arbiter Config Master 8."), 32),
    (0xCD000124, "HW_ARB_CFG_M9", "Bus Control", _parse_desc("AHB Arbiter Config Master 9."), 32),
    (0xCD000130, "HW_ARB_CFG_MC", "Bus Control", _parse_desc("AHB Arbiter Config Master C."), 32),
    (0xCD000134, "HW_ARB_CFG_MD", "Bus Control", _parse_desc("AHB Arbiter Config Master D."), 32),
    (0xCD000138, "HW_ARB_CFG_ME", "Bus Control", _parse_desc("AHB Arbiter Config Master E."), 32),
    (0xCD00013C, "HW_ARB_CFG_MF", "Bus Control", _parse_desc("AHB Arbiter Config Master F."), 32),
    (0xCD000140, "HW_ARB_CFG_CPU", "Bus Control", _parse_desc("AHB Arbiter Config CPU."), 32),
    (0xCD000144, "HW_ARB_CFG_DMA", "Bus Control", _parse_desc("AHB Arbiter Config DMA."), 32),
    (0xCD000148, "HW_ARB_PCNTCFG", "Bus Control", _parse_desc("AHB Arbiter Perf Counter Config."), 32),
    (0xCD00014C, "HW_ARB_PCNTSTS", "Bus Control", _parse_desc("AHB Arbiter Perf Counter Status."), 32),
    # I2C Slave (0xCD000150 - 0xCD00016F)
    (0xCD000150, "HW_I2CSCTRL_0", "I2C", _parse_desc("I2C Slave Control (instance 0)."), 32),
    (0xCD000154, "HW_I2CSSTS_0", "I2C", _parse_desc("I2C Slave Status (instance 0)."), 32),
    (0xCD000158, "HW_I2CSRDEN_0", "I2C", _parse_desc("I2C Slave Read Enable (instance 0)."), 32),
    (0xCD000160, "HW_I2CSTRAP", "I2C", _parse_desc("I2C Strap Configuration."), 32),
    (0xCD000164, "HW_I2CSCTRL_1", "I2C", _parse_desc("I2C Slave Control (instance 1)."), 32),
    (0xCD000168, "HW_I2CSVISETYUV", "Video Interface", _parse_desc("I2C Slave VI Set YUV (via I2C to VI)."), 32),
    (0xCD00016C, "HW_I2CSVISETFILT", "Video Interface", _parse_desc("I2C Slave VI Set Filter (via I2C to VI)."), 32),
    # Spares and System (0xCD000170 - 0xCD00019B)
    (0xCD000170, "HW_SPARE2", "System Control", _parse_desc("Spare Register 2."), 32),
    (0xCD000174, "HW_SPARE3", "System Control", _parse_desc("Spare Register 3."), 32),
    (0xCD000180, "HW_COMPAT", "System Control", _parse_desc("Compatibility register for DI functions and PPC boot options. (needs verification)"), 32),
    (0xCD000184, "HW_RESET_AHB", "System Control", _parse_desc("(ACRRSTAHB) AHB Reset Control."), 32),
    (0xCD000188, "HW_SPARE0", "System Control", _parse_desc("Spare Register 0."), 32),
    (0xCD00018C, "HW_BOOT0", "System Control", _parse_desc("(ACR_SPARE1) Controls boot0 memory mapping and DSK PLL source. (needs verification)"), 32),
    (0xCD000190, "HW_CLOCKS", "PLL/Clock", _parse_desc("(ACRSYSCTRL) System clock control, including CPU speed mode."), 32),
    (0xCD000194, "HW_RESETS", "System Control", _parse_desc("(ACRRSTCTRL) System reset and power control for various components. (needs verification)"), 32),
    (0xCD000198, "HW_IFPOWER", "System Control", _parse_desc("(ACRCLKGATE) Interface power gating control."), 32),
    # PLLs (0xCD00019C - 0xCD0001DB)
    (0xCD00019C, "HW_PLLDR", "PLL/Clock", _parse_desc("PLL Drive / Clock configuration."), 32),
    (0xCD0001A0, "HW_PLLSYSEXT1", "PLL/Clock", _parse_desc("System PLL External Control 1."), 32),
    (0xCD0001A4, "HW_PLLSYSEXT2", "PLL/Clock", _parse_desc("System PLL External Control 2."), 32),
    (0xCD0001A8, "HW_PLLAIEXT1", "PLL/Clock", _parse_desc("Audio PLL External Control 1."), 32),
    (0xCD0001AC, "HW_PLLAIEXT2", "PLL/Clock", _parse_desc("Audio PLL External Control 2."), 32),
    (0xCD0001B0, "HW_PLLSYS", "PLL/Clock", _parse_desc("System PLL Control."), 32),
    (0xCD0001B4, "HW_PLLSYSEXT", "PLL/Clock", _parse_desc("System PLL External Control (Main)."), 32),
    (0xCD0001B8, "HW_PLLDSK", "PLL/Clock", _parse_desc("Disk (DI) PLL Control."), 32),
    (0xCD0001BC, "HW_PLLDDR", "PLL/Clock", _parse_desc("DDR (MEM2) PLL Control."), 32),
    (0xCD0001C0, "HW_PLLDDREXT", "PLL/Clock", _parse_desc("DDR (MEM2) PLL External Control."), 32),
    (0xCD0001C4, "HW_PLLVI", "PLL/Clock", _parse_desc("Video Interface PLL Control."), 32),
    (0xCD0001C8, "HW_PLLVIEXT", "PLL/Clock", _parse_desc("Video Interface PLL External Control."), 32),
    (0xCD0001CC, "HW_PLLAI", "PLL/Clock", _parse_desc("Audio Interface PLL Control."), 32),
    (0xCD0001D0, "HW_PLLAIEXT", "PLL/Clock", _parse_desc("Audio Interface PLL External Control."), 32),
    (0xCD0001D4, "HW_PLLUSB", "PLL/Clock", _parse_desc("USB PLL Control."), 32),
    (0xCD0001D8, "HW_PLLUSBEXT", "PLL/Clock", _parse_desc("USB PLL External Control."), 32),
    # IO Control / OTP (0xCD0001DC - 0xCD0001F3)
    (0xCD0001DC, "HW_IOPWRCTRL", "System Control", _parse_desc("IOP subsystem power control."), 32),
    (0xCD0001E0, "HW_IOSTRCTRL0", "System Control", _parse_desc("IO Strength Control 0."), 32),
    (0xCD0001E4, "HW_IOSTRCTRL1", "System Control", _parse_desc("IO Strength Control 1."), 32),
    (0xCD0001E8, "HW_CLKSTRCTRL", "PLL/Clock", _parse_desc("Clock Strength Control."), 32),
    (0xCD0001EC, "HW_OTPCMD", "OTP", _parse_desc("(ACREFUSEADDR) OTP command and address register."), 32),
    (0xCD0001F0, "HW_OTPDATA", "OTP", _parse_desc("(ACREFUSEDATA) OTP data register."), 32),
    # Debug, SI, Version (0xCD0001F4 - 0xCD00021B)
    (0xCD0001F4, "HW_DBGCLK", "Debug", _parse_desc("Debug Clock Control."), 32),
    (0xCD0001F8, "HW_OBSCLKOCTRL", "Debug", _parse_desc("Observe Clock Output Control."), 32),
    (0xCD0001FC, "HW_OBSCLKICTRL", "Debug", _parse_desc("Observe Clock Input Control."), 32),
    (0xCD000200, "HW_DBGPORT", "Debug", _parse_desc("Debug Port."), 32),
    (0xCD000204, "HW_SICLKDIV", "System Control", _parse_desc("Serial Interface (SI) clock divider, potentially unused."), 32),
    (0xCD000208, "HW_SICTRL", "System Control", _parse_desc("Serial Interface (SI) control, potentially unused."), 32),
    (0xCD00020C, "HW_SIDATA", "System Control", _parse_desc("Serial Interface (SI) data, potentially unused."), 32),
    (0xCD000210, "HW_SIINT", "System Control", _parse_desc("Serial Interface (SI) interrupt, potentially unused."), 32),
    (0xCD000214, "HW_VERSION", "System Control", _parse_desc("(ACRCHIPREVID) Hollywood chip version and revision register."), 32),
    (0xCD000218, "HW_DBGBUSRD", "Debug", _parse_desc("Debug Bus Read Data."), 32),
    # MEM2 Protection Registers (at 0xCD0Bxxxx base for PPC)
    (0xCD0B420A, "MEM_PROT", "Memory Interface", _parse_desc("MEM2 protection enable."), 16),
    (0xCD0B420C, "MEM_PROT_START", "Memory Interface", _parse_desc("MEM2 protection low address (upper 16 bits of physical address)."), 16),
    (0xCD0B420E, "MEM_PROT_END", "Memory Interface", _parse_desc("MEM2 protection high address (upper 16 bits of physical address)."), 16),
    (0xCD0B4228, "MEM_FLUSHREQ", "Memory Interface", _parse_desc("AHB flush request."), 16),
    (0xCD0B422A, "MEM_FLUSHACK", "Memory Interface", _parse_desc("AHB flush ack."), 16),
]

# Wii Global Symbols / OS Data Area (MEM1: 0x8xxxxxxx)
# Format: (Address, Name, TagType, Description, DataType (string for parse_type_string or None))
WII_GLOBAL_SYMBOLS: List[Tuple[int, str, str, str, Optional[str]]] = [
    (0x80000000, "GameID", "Global Variable", _parse_desc("Game Code."), "char[4]"),
    (0x80000004, "MakerCode", "Global Variable", _parse_desc("Maker code."), "char[2]"),
    (0x80000006, "DiscNumber", "Global Variable", _parse_desc("Disc Number for multidisc games."), "uint8_t"),
    (0x80000007, "DiscVersion", "Global Variable", _parse_desc("Disc Version."), "uint8_t"),
    (0x80000008, "DiscStreamingFlag", "Global Variable", _parse_desc("Disc Streaming flag."), "uint8_t"),
    (0x80000009, "DiscStreamingBufferSize", "Global Variable", _parse_desc("Disc Streaming buffer size."), "uint8_t"),
    (0x80000018, "DiscLayoutMagicWii", "Global Variable", _parse_desc("Disc layout magic for Wii."), "uint32_t"),
    (0x8000001C, "DiscLayoutMagicGC", "Global Variable", _parse_desc("Disc layout magic for GameCube."), "uint32_t"),
    (0x80000020, "NintendoBootCodeMagic", "Global Variable", _parse_desc("Nintendo Standard Boot Code."), "uint32_t"),
    (0x80000024, "ApploaderVersion", "Global Variable", _parse_desc("Version set by apploader."), "uint32_t"),
    (0x80000028, "MEM1SizePhysicalHeader", "Global Variable", _parse_desc("Physical Memory Size (24MB) from header."), "uint32_t"),
    (0x8000002C, "ProductionBoardModel", "Global Variable", _parse_desc("Production Board Model identifier."), "uint32_t"),
    (0x80000030, "ArenaLoHeader", "Global Variable", _parse_desc("Arena Low address from header."), "uint32_t"),
    (0x80000034, "ArenaHiHeader", "Global Variable", _parse_desc("Arena High address from header."), "uint32_t"),
    (0x80000038, "FSTLocationHeader", "Global Variable", _parse_desc("Start of FST from header (varies)."), "void*"),
    (0x8000003C, "FSTMaxSizeHeader", "Global Variable", _parse_desc("Maximum FST Size from header (varies)."), "uint32_t"),
    (0x80000040, "pDBStruct", "Debug", _parse_desc("Pointer to the beginning of the DB global struct."), "void*"),
    (0x80000044, "DBExceptionMask", "Debug", _parse_desc("DB marked exception mask."), "uint32_t"),
    (0x80000048, "DBExceptionDestination", "Debug", _parse_desc("DB exception destination address."), "void*"),
    (0x8000004C, "DBReturnAddress", "Debug", _parse_desc("DB return address."), "void*"),
    (0x80000060, "OSDebuggerHook", "Debug", _parse_desc("Hook for debugged exceptions (OSDBIntegrator), disabled in production. SDK titles may write instructions here."), "void*"),
    (0x800000C0, "pOSContextCurrentReal", "Global Variable", _parse_desc("Pointer to Current OSContext instance (real mode)."), "void*"), # OSContext*
    (0x800000C4, "UserInterruptMask", "Interrupts", _parse_desc("User interrupt mask."), "uint32_t"),
    (0x800000C8, "OSInterruptMask", "Interrupts", _parse_desc("Revolution OS interrupt mask."), "uint32_t"),
    (0x800000CC, "CurrentVideoMode", "Video Interface", _parse_desc("Value indicating current video mode (0=NTSC, 1=PAL, 2=MPAL)."), "uint32_t"),
    (0x800000D4, "pOSContextCurrentTranslated", "Global Variable", _parse_desc("Pointer to Current OSContext instance (translated mode)."), "void*"), # OSContext*
    (0x800000D8, "pOSContextFPRSave", "Global Variable", _parse_desc("Pointer to OSContext to save FPRs to (NULL if unused)."), "void*"), # OSContext*
    (0x800000DC, "pOSThreadEarliest", "Global Variable", _parse_desc("Pointer to the earliest created OSThread."), "void*"), # OSThread*
    (0x800000E0, "pOSThreadLatest", "Global Variable", _parse_desc("Pointer to the most recently created OSThread."), "void*"), # OSThread*
    (0x800000E4, "pOSThreadCurrent", "Global Variable", _parse_desc("Pointer to the current OSThread."), "void*"), # OSThread*
    (0x800000EC, "DevDebuggerMonitorAddr", "Debug", _parse_desc("Dev Debugger Monitor Address (if present)."), "void*"),
    (0x800000F0, "SimulatedMemorySize", "Global Variable", _parse_desc("Simulated Memory Size."), "uint32_t"),
    (0x800000F4, "pBI2Data", "Global Variable", _parse_desc("Pointer to data from partition's bi2.bin or emulated bi2.bin."), "void*"),
    (0x800000F8, "ConsoleBusSpeed", "System Control", _parse_desc("Console Bus Speed."), "uint32_t"),
    (0x800000FC, "ConsoleCPUSpeed", "System Control", _parse_desc("Console CPU Speed."), "uint32_t"),
    (0x80000100, "SystemResetExceptionHandler", "Exception Vector", _parse_desc("System Reset Exception Handler."), "void()"),
    (0x80000200, "MachineCheckExceptionHandler", "Exception Vector", _parse_desc("Machine Check Exception Handler."), "void()"),
    (0x80000300, "DSIExceptionHandler", "Exception Vector", _parse_desc("Data Storage Interrupt (DSI) Exception Handler."), "void()"),
    (0x80000400, "ISIExceptionHandler", "Exception Vector", _parse_desc("Instruction Storage Interrupt (ISI) Exception Handler."), "void()"),
    (0x80000500, "ExternalInterruptHandler", "Exception Vector", _parse_desc("External Interrupt Handler."), "void()"),
    (0x80000600, "AlignmentExceptionHandler", "Exception Vector", _parse_desc("Alignment Exception Handler."), "void()"),
    (0x80000700, "ProgramExceptionHandler", "Exception Vector", _parse_desc("Program Exception Handler (for syscall, trap)."), "void()"),
    (0x80000800, "FloatingPointUnavailableHandler", "Exception Vector", _parse_desc("Floating Point Unavailable Exception Handler."), "void()"),
    (0x80000900, "DecrementerExceptionHandler", "Exception Vector", _parse_desc("Decrementer Exception Handler."), "void()"),
    (0x80000C00, "SystemCallExceptionHandler", "Exception Vector", _parse_desc("System Call Exception Handler (for PPC SC instruction)."), "void()"),
    (0x80000D00, "TraceExceptionHandler", "Exception Vector", _parse_desc("Trace Exception Handler (for debug)."), "void()"),
    (0x80000F00, "FloatingPointAssistHandler", "Exception Vector", _parse_desc("Floating Point Assist Exception Handler (for software FP emulation)."), "void()"),
    (0x80001300, "InstructionAddressBreakpointHandler", "Exception Vector", _parse_desc("Instruction Address Breakpoint (IABR) Exception Handler."), "void()"),
    (0x80001400, "SystemManagementInterruptHandler", "Exception Vector", _parse_desc("System Management Interrupt (SMI) Handler."), "void()"),
    (0x80001700, "ThermalManagementInterruptHandler", "Exception Vector", _parse_desc("Thermal Management Interrupt Handler."), "void()"),
    (0x80001800, "OSHomebrewAreaStart", "Global Variable", _parse_desc("Unused exception handler area, often utilized by homebrew for persistent code."), None),
    (0x80003000, "OSExceptionVectorAreaStart", "Global Variable", _parse_desc("Start of OS managed exception vector area."), None),
    (0x80003040, "pOSInterruptTable", "Interrupts", _parse_desc("Pointer to __OSInterrupt table."), "void*"), # OSInterruptHandler*
    (0x800030C0, "EXIProbeTimes", "EXI", _parse_desc("EXI Probe start times for channels 0 and 1."), "uint32_t[2]"),
    (0x800030C8, "pRELLoadedFirst", "Global Variable", _parse_desc("Pointer to the first loaded REL (dynamically linked library) file."), "void*"), # RELHeader*
    (0x800030CC, "pRELLoadedLast", "Global Variable", _parse_desc("Pointer to the last loaded REL file."), "void*"), # RELHeader*
    (0x800030D0, "pRELModuleNameTable", "Global Variable", _parse_desc("Pointer to a REL module name table, or 0 if none."), "char**"),
    (0x800030D8, "OSTime", "Global Variable", _parse_desc("System time as 64-bit value (units of 1/40.5MHz since 2000-01-01)."), "uint64_t"),
    (0x800030E4, "OSPADButtonStatePort4Apploader", "Global Variable", _parse_desc("GameCube controller port 4 button state, set by apploader for NR disc support."), "uint16_t"),
    (0x800030E6, "DVDDeviceCodeAddress", "Drive Interface", _parse_desc("DVD Device Code Address."), "uint16_t"),
    (0x800030E8, "OSDebugInfoPtr", "Debug", _parse_desc("Pointer to Debug-related information structure."), "void*"),
    (0x800030F0, "DOLExecuteParameters", "Global Variable", _parse_desc("Parameters for DOL execution."), "uint32_t"),
    (0x80003100, "OSPhysicalMEM1Size", "Global Variable", _parse_desc("Physical MEM1 size, set by IOS."), "uint32_t"),
    (0x80003104, "OSSimulatedMEM1Size", "Global Variable", _parse_desc("Simulated MEM1 size, set by OS."), "uint32_t"),
    (0x8000310C, "OSMEM1ArenaStart", "Global Variable", _parse_desc("Start of MEM1 Arena (usable memory for game), set by IOS."), "void*"),
    (0x80003110, "OSMEM1ArenaEnd", "Global Variable", _parse_desc("End of MEM1 Arena (usable memory for game), set by IOS."), "void*"),
    (0x80003118, "OSPhysicalMEM2Size", "Global Variable", _parse_desc("Physical MEM2 size, set by IOS."), "uint32_t"),
    (0x8000311C, "OSSimulatedMEM2Size", "Global Variable", _parse_desc("Simulated MEM2 size, set by IOS."), "uint32_t"),
    (0x80003120, "OSMEM2PPCAddressableEnd", "Global Variable", _parse_desc("End of MEM2 addressable by PPC, set by IOS."), "void*"),
    (0x80003124, "OSMEM2UsableStart", "Global Variable", _parse_desc("Start of usable MEM2 for game, set by IOS."), "void*"),
    (0x80003128, "OSMEM2UsableEnd", "Global Variable", _parse_desc("End of usable MEM2 for game, set by IOS."), "void*"),
    (0x80003130, "OS_IPCBufferStart", "IOS Communication", _parse_desc("Start of IOS Inter-Process Communication (IPC) buffer."), "void*"),
    (0x80003134, "OS_IPCBufferEnd", "IOS Communication", _parse_desc("End of IOS IPC buffer."), "void*"),
    (0x80003138, "OSHollywoodVersion", "Global Variable", _parse_desc("Hollywood chip version (from HW_VERSION)."), "uint32_t"),
    (0x80003140, "OSIOSVersion", "Global Variable", _parse_desc("IOS version."), "uint32_t"),
    (0x80003144, "OSIOSBuildDate", "Global Variable", _parse_desc("IOS Build Date."), "uint32_t"),
    (0x80003148, "OSIOSReservedHeapStart", "IOS Communication", _parse_desc("Start of IOS Reserved Heap."), "void*"),
    (0x8000314C, "OSIOSReservedHeapEnd", "IOS Communication", _parse_desc("End of IOS Reserved Heap."), "void*"),
    (0x80003158, "OSGDDRVendorCode", "Global Variable", _parse_desc("GDDR Vendor Code."), "uint32_t"),
    (0x8000315C, "OSBootIndicator", "Global Variable", _parse_desc("Indicator set by IOS/NAND Boot Program during boot process, reflects boot source."), "uint8_t"),
    (0x8000315D, "OSEnableLegacyDI", "Drive Interface", _parse_desc("Controls legacy Drive Interface mode. True for GC apploader."), "uint8_t"),
    (0x8000315E, "OSDevkitBootProgramVersion", "Global Variable", _parse_desc("Devkit boot program version, written by System Menu."), "uint16_t"),
    (0x80003160, "OSInitSemaphore", "Global Variable", _parse_desc("Initialization semaphore for main() function."), "uint32_t"), # OSSem*
    (0x80003164, "OSGCModeFlag", "Global Variable", _parse_desc("GameCube (MIOS) mode flag. Set by boot2 on MIOS shutdown, read by System Menu."), "uint32_t"),
    (0x80003180, "OSWC24GameID", "Global Variable", _parse_desc("Game ID for WC24 mode. Must match GameID at 0x80000000 for WC24 to be enabled."), "char[4]"),
    (0x80003184, "OSApplicationType", "Global Variable", _parse_desc("Application type (0x80 for disc, 0x81 for channel)."), "uint8_t"),
    (0x80003186, "OSApplicationType2", "Global Variable", _parse_desc("Secondary application type, indicating context for mixed disc/channel operations."), "uint8_t"),
    (0x80003188, "OSMinimumIOSVersion", "Global Variable", _parse_desc("Minimum IOS version required (major/title version)."), "uint32_t"),
    (0x8000318C, "OSTitleLaunchCode", "Global Variable", _parse_desc("Launch Code for title booted from NAND."), "uint32_t"),
    (0x80003190, "OSTitleReturnCode", "Global Variable", _parse_desc("Return Code for title booted from NAND."), "uint32_t"),
    (0x80003194, "OSDataPartitionType", "Drive Interface", _parse_desc("Data partition type from disc, copied by System Menu."), "uint32_t"),
    (0x80003198, "OSDataPartitionOffset", "Drive Interface", _parse_desc("Data partition offset from disc, copied by System Menu."), "uint32_t"),
    (0x8000319C, "OSDiscLayerFlag", "Drive Interface", _parse_desc("Indicates disc layer type (single/dual), set by apploader. Affects out-of-bounds read behavior."), "uint8_t"),
    (0x80003400, "OSBS1BootCodeAreaStart", "Global Variable", _parse_desc("Start of \"BS1\" boot code area."), None),
    (0x80003F00, "OSAppExecutableAreaStart", "Global Variable", _parse_desc("Start of standard application executable area."), None),
    (0x81330000, "OSLoaderExecutableAreaStart", "Global Variable", _parse_desc("Start of loader executable area. Also used by NAND Boot Program."), None),
]


# GameCube MMIO Block (0xCC00xxxx)
# Derived from gamecube_mmio_block.html (YAGCD)
# Format: (address, name, tag_category, description, size_bits)
GAMECUBE_IO_REGISTERS: List[Tuple[int, str, str, str, int]] = [
    # - CP - Command Processor (0xCC000000, size 0x80, common access 2 bytes)
    (0xCC000000, "CP_SR", "Command Processor Register", "Status Register. Bits: 4=BP interrupt, 3=GP idle for commands, 2=GP idle for reading, 1=GX FIFO underflow, 0=GX FIFO overflow.", 16),
    (0xCC000002, "CP_CR", "Command Processor Register", "Control Register. Bits: 5=BP enable, 4=GP link enable, 3=FIFO underflow IRQ enable, 2=FIFO overflow IRQ enable/CP IRQ, 1=CP IRQ enable, 0=GP FIFO read enable.", 16),
    (0xCC000004, "CP_CLR", "Command Processor Register", "Clear Register. Write 1 to clear: bit 1=FIFO underflow, bit 0=FIFO overflow.", 16),
    (0xCC00000E, "CP_TOKEN", "Command Processor Register", "Token register.", 16),
    (0xCC000010, "CP_BBOX_LEFT", "Command Processor Register", "Bounding box - left.", 16),
    (0xCC000012, "CP_BBOX_RIGHT", "Command Processor Register", "Bounding box - right.", 16),
    (0xCC000014, "CP_BBOX_TOP", "Command Processor Register", "Bounding box - top.", 16),
    (0xCC000016, "CP_BBOX_BOTTOM", "Command Processor Register", "Bounding box - bottom.", 16),
    (0xCC000020, "CP_FIFO_BASE_LO", "Command Processor Register", "CP FIFO base address low part.", 16),
    (0xCC000022, "CP_FIFO_BASE_HI", "Command Processor Register", "CP FIFO base address high part.", 16),
    (0xCC000024, "CP_FIFO_END_LO", "Command Processor Register", "CP FIFO end address low part.", 16),
    (0xCC000026, "CP_FIFO_END_HI", "Command Processor Register", "CP FIFO end address high part.", 16),
    (0xCC000028, "CP_FIFO_HIWATER_LO", "Command Processor Register", "CP FIFO high watermark low part.", 16),
    (0xCC00002A, "CP_FIFO_HIWATER_HI", "Command Processor Register", "CP FIFO high watermark high part.", 16),
    (0xCC00002C, "CP_FIFO_LOWATER_LO", "Command Processor Register", "CP FIFO low watermark low part.", 16),
    (0xCC00002E, "CP_FIFO_LOWATER_HI", "Command Processor Register", "CP FIFO low watermark high part.", 16),
    (0xCC000030, "CP_FIFO_RW_DIST_LO", "Command Processor Register", "CP FIFO read/write distance low part.", 16),
    (0xCC000032, "CP_FIFO_RW_DIST_HI", "Command Processor Register", "CP FIFO read/write distance high part.", 16),
    (0xCC000034, "CP_FIFO_WPTR_LO", "Command Processor Register", "CP FIFO write pointer low part.", 16),
    (0xCC000036, "CP_FIFO_WPTR_HI", "Command Processor Register", "CP FIFO write pointer high part.", 16),
    (0xCC000038, "CP_FIFO_RPTR_LO", "Command Processor Register", "CP FIFO read pointer low part.", 16),
    (0xCC00003A, "CP_FIFO_RPTR_HI", "Command Processor Register", "CP FIFO read pointer high part.", 16),
    (0xCC00003C, "CP_FIFO_BP_LO", "Command Processor Register", "CP FIFO breakpoint address low part.", 16),
    (0xCC00003E, "CP_FIFO_BP_HI", "Command Processor Register", "CP FIFO breakpoint address high part.", 16),

    # - PE - Pixel Engine (0xCC001000, size 0x100, common access 2 bytes)
    (0xCC001000, "PE_ZCONFIG", "Pixel Engine Register", "Z configuration. Bits: 4=Z update enable, 1-3=Z function, 0=Z-comparator enable.", 16),
    (0xCC001002, "PE_ALPHACONFIG", "Pixel Engine Register", "Alpha configuration. Controls blending, alpha/color update, dithering.", 16),
    (0xCC001004, "PE_DESTALPHA", "Pixel Engine Register", "Destination alpha. Bits: 8=enable, 0-7=alpha value.", 16),
    (0xCC001006, "PE_ALPHAMODE", "Pixel Engine Register", "Alpha Mode. Bits: 8-15=mode, 0-7=threshold.", 16),
    (0xCC001008, "PE_ALPHAREAD", "Pixel Engine Register", "Alpha Read mode.", 16),
    (0xCC00100A, "PE_ISR", "Pixel Engine Register", "Interrupt Status Register. Bits: 3=PE Finish, 2=PE Token, 1=PE Finish enable, 0=PE Token enable.", 16),
    (0xCC00100E, "PE_TOKEN_VALUE", "Pixel Engine Register", "PE Token value asserted from last PE Token Interrupt.", 16),

    # - VI - Video Interface (0xCC002000, size 0x100, common access 4 bytes for some, 2 for others)
    (0xCC002000, "VI_VTR", "Video Interface", "Vertical Timing Register. Controls active video lines (ACV) and equalization pulse (EQU).", 16), # Doc says 2 bytes
    (0xCC002002, "VI_DCR", "Video Interface", "Display Configuration Register. Controls video format, display latch, interlace, reset, enable.", 16), # Doc says 2 bytes
    (0xCC002004, "VI_HTR0", "Video Interface", "Horizontal Timing 0. Controls HCS, HCE, HLW.", 32), # Doc says 4 bytes
    (0xCC002008, "VI_HTR1", "Video Interface", "Horizontal Timing 1. Controls HBS, HBE, HSY.", 32), # Doc says 4 bytes
    (0xCC00200C, "VI_VTO", "Video Interface", "Odd Field Vertical Timing Register. Controls PSB, PRB for odd fields.", 32), # Doc says 4 bytes
    (0xCC002010, "VI_VTE", "Video Interface", "Even Field Vertical Timing Register. Controls PSB, PRB for even fields.", 32), # Doc says 4 bytes
    (0xCC002014, "VI_BBEI", "Video Interface", "Odd Field Burst Blanking Interval Register.", 32), # Doc says 4 bytes
    (0xCC002018, "VI_BBOI", "Video Interface", "Even Field Burst Blanking Interval Register.", 32), # Doc says 4 bytes
    (0xCC00201C, "VI_TFBL", "Video Interface", "Top Field Base Register (L). Specifies display origin for top/left field.", 32), # Doc says 4 bytes
    (0xCC002020, "VI_TFBR", "Video Interface", "Top Field Base Register (R). Specifies display origin for top/right field in 3D mode.", 32), # Doc says 4 bytes
    (0xCC002024, "VI_BFBL", "Video Interface", "Bottom Field Base Register (L). Specifies display origin for bottom/left field.", 32), # Doc says 4 bytes
    (0xCC002028, "VI_BFBR", "Video Interface", "Bottom Field Base Register (R). Specifies display origin for bottom/right field in 3D mode.", 32), # Doc says 4 bytes
    (0xCC00202C, "VI_DPV", "Video Interface", "Current Vertical Position of Raster beam (VCT).", 16), # Doc says 2 bytes
    (0xCC00202E, "VI_DPH", "Video Interface", "Current Horizontal Position of Raster beam (HCT).", 16), # Doc says 2 bytes
    (0xCC002030, "VI_DI0", "Video Interface", "Display Interrupt 0. Configures VCT, HCT for interrupt, enable and status.", 32), # Doc says 4 bytes
    (0xCC002034, "VI_DI1", "Video Interface", "Display Interrupt 1.", 32), # Doc says 4 bytes
    (0xCC002038, "VI_DI2", "Video Interface", "Display Interrupt 2.", 32), # Doc says 4 bytes
    (0xCC00203C, "VI_DI3", "Video Interface", "Display Interrupt 3.", 32), # Doc says 4 bytes
    (0xCC002040, "VI_DL0", "Video Interface", "Display Latch Register 0. Latches VCT, HCT on gt0 signal.", 32), # Doc says 4 bytes
    (0xCC002044, "VI_DL1", "Video Interface", "Display Latch Register 1. Latches VCT, HCT on gt1 signal.", 32), # Doc says 4 bytes
    (0xCC002048, "VI_HSW", "Video Interface", "Horizontal Scaling Width Register (SRCWIDTH).", 16), # Doc says 2 bytes
    (0xCC00204A, "VI_HSR", "Video Interface", "Horizontal Scaling Register. Enable (HS_EN) and step size (STP).", 16), # Doc says 2 bytes
    (0xCC00204C, "VI_FCT0", "Video Interface", "Filter Coefficient Table 0 (Taps 0-2). For anti-aliasing.", 32), # Doc says 4 bytes
    (0xCC002050, "VI_FCT1", "Video Interface", "Filter Coefficient Table 1 (Taps 3-5).", 32), # Doc says 4 bytes
    (0xCC002054, "VI_FCT2", "Video Interface", "Filter Coefficient Table 2 (Taps 6-8).", 32), # Doc says 4 bytes
    (0xCC002058, "VI_FCT3", "Video Interface", "Filter Coefficient Table 3 (Taps 9-12).", 32), # Doc says 4 bytes
    (0xCC00205C, "VI_FCT4", "Video Interface", "Filter Coefficient Table 4 (Taps 13-16).", 32), # Doc says 4 bytes
    (0xCC002060, "VI_FCT5", "Video Interface", "Filter Coefficient Table 5 (Taps 17-20).", 32), # Doc says 4 bytes
    (0xCC002064, "VI_FCT6", "Video Interface", "Filter Coefficient Table 6 (Taps 21-23, T24 hardwired 0).", 32), # Doc says 4 bytes
    (0xCC002068, "VI_UNK_AA_68", "Video Interface", "Unknown anti-aliasing related register.", 32), # Doc says 4 bytes, value 0x00FF0000
    (0xCC00206C, "VI_CLKSEL", "Video Interface", "VI Clock Select Register. Selects 27MHz or 54MHz video clock.", 16), # Doc says 2 bytes
    (0xCC00206E, "VI_DTVSTAT", "Video Interface", "VI DTV Status Register (VISEL). Reads status of I/O pins.", 16), # Doc says 2 bytes
    (0xCC002070, "VI_UNK_70", "Video Interface", "Unknown VI register.", 16), # Doc says 2 bytes, value 0x0280
    (0xCC002072, "VI_BORDER_HBE", "Video Interface", "Border Horizontal Blank End. For debug mode border.", 16), # Doc says 2 bytes
    (0xCC002074, "VI_BORDER_HBS", "Video Interface", "Border Horizontal Blank Start. For debug mode border.", 16), # Doc says 2 bytes
    (0xCC002076, "VI_UNK_76", "Video Interface", "Unknown VI register.", 16), # Doc says 2 bytes, value 0x00FF
    (0xCC002078, "VI_UNK_78", "Video Interface", "Unknown VI register.", 32), # Doc says 4 bytes, value 0x00FF00FF
    (0xCC00207C, "VI_UNK_7C", "Video Interface", "Unknown VI register.", 32), # Doc says 4 bytes, value 0x00FF00FF

    # - PI - Processor Interface (0xCC003000, size 0x100, common access 4 bytes)
    (0xCC003000, "PI_INTSR", "Processor Interface", "Interrupt Cause Register. Shows sources of interrupts (RSWST, HSP, DEBUG, CP, PE_FINISH, etc.). Read to clear.", 32),
    (0xCC003004, "PI_INTMR", "Processor Interface", "Interrupt Mask Register. Enables/disables interrupts corresponding to INTSR bits.", 32),
    (0xCC00300C, "PI_FIFO_BASE", "Processor Interface", "CPU FIFO Base Start address.", 32),
    (0xCC003010, "PI_FIFO_END", "Processor Interface", "CPU FIFO Base End address.", 32),
    (0xCC003014, "PI_FIFO_WPTR", "Processor Interface", "CPU FIFO current Write Pointer.", 32),
    # PI_0x3018, PI_0x301C, PI_0x3020 are unknown
    (0xCC003024, "PI_RESET", "Processor Interface", "Reset Register. Writing here can cause a system reset.", 32),
    (0xCC00302C, "PI_CONSOLE_TYPE", "Processor Interface", "Console Type Register. Bits 28-31 indicate console type (e.g., 2 for HW2).", 32),

    # - MI - Memory Interface (0xCC004000, size 0x80, common access 4 bytes for regions, 2 for control)
    (0xCC004000, "MI_PROT_RGN1", "Memory Interface", "Protected Region 1 (Page Address Lo/Hi).", 32),
    (0xCC004004, "MI_PROT_RGN2", "Memory Interface", "Protected Region 2 (Page Address Lo/Hi).", 32),
    (0xCC004008, "MI_PROT_RGN3", "Memory Interface", "Protected Region 3 (Page Address Lo/Hi).", 32),
    (0xCC00400C, "MI_PROT_RGN4", "Memory Interface", "Protected Region 4 (Page Address Lo/Hi).", 32),
    (0xCC004010, "MI_PROT_TYPE", "Memory Interface", "Protection Type for 4 regions (2 bits per channel: 0=denied, 1=RO, 2=WO, 3=RW).", 16),
    (0xCC00401C, "MI_INTMASK", "Memory Interface", "MI Interrupt Mask. Bit 4=mask all, Bits 0-3=mask MEM0-3.", 16),
    (0xCC00401E, "MI_INTSR", "Memory Interface", "MI Interrupt Cause. Bit 4=any MI irq, Bits 0-3=MEM0-3 irq. Write 1 to clear.", 16),
    (0xCC004020, "MI_PROT_STATUS", "Memory Interface", "Protection status bits.", 16), # Unknown details from doc
    (0xCC004022, "MI_FAIL_ADDR_LO", "Memory Interface", "Address (low part) which failed protection rules.", 16),
    (0xCC004024, "MI_FAIL_ADDR_HI", "Memory Interface", "Address (high part) which failed protection rules.", 16),
    # MI_TIMER registers 0xCC004032 - 0xCC004058 are repetitive, grouping them.
    (0xCC004032, "MI_TIMER0_HI", "Timer", "Memory Interface Timer 0 High.", 16),
    (0xCC004034, "MI_TIMER0_LO", "Timer", "Memory Interface Timer 0 Low.", 16),
    (0xCC004036, "MI_TIMER1_HI", "Timer", "Memory Interface Timer 1 High.", 16),
    (0xCC004038, "MI_TIMER1_LO", "Timer", "Memory Interface Timer 1 Low.", 16),
    # ... up to MI_TIMER9 (0xCC004056/0xCC004058)
    (0xCC004056, "MI_TIMER9_HI", "Timer", "Memory Interface Timer 9 High.", 16),
    (0xCC004058, "MI_TIMER9_LO", "Timer", "Memory Interface Timer 9 Low.", 16),
    (0xCC00405A, "MI_UNK_5A", "Memory Interface", "Unknown MI register.", 16),

    # - DSP - Digital Signal Processor Interface (0xCC005000, size 0x200, common access 16-bit words)
    (0xCC005000, "DSP_MAILBOX_IN_HI", "DSP Register", "DSP Mailbox High (CPU to DSP).", 16),
    (0xCC005002, "DSP_MAILBOX_IN_LO", "DSP Register", "DSP Mailbox Low (CPU to DSP).", 16),
    (0xCC005004, "DSP_MAILBOX_OUT_HI", "DSP Register", "CPU Mailbox High (DSP to CPU).", 16),
    (0xCC005006, "DSP_MAILBOX_OUT_LO", "DSP Register", "CPU Mailbox Low (DSP to CPU).", 16),
    (0xCC00500A, "DSP_CSR", "DSP Register", "Control Status Register. Controls DSP reset, halt, interrupts (DSP, ARAM, AI).", 16),
    (0xCC005012, "DSP_AR_SIZE", "DSP Register", "ARAM Size configuration.", 16),
    (0xCC005016, "DSP_AR_MODE", "DSP Register", "ARAM Mode configuration.", 16),
    (0xCC00501A, "DSP_AR_REFRESH", "DSP Register", "ARAM Refresh rate configuration.", 16),
    (0xCC005020, "DSP_AR_DMA_MMADDR_H", "DSP Register", "ARAM DMA Main Memory Address High.", 16),
    (0xCC005022, "DSP_AR_DMA_MMADDR_L", "DSP Register", "ARAM DMA Main Memory Address Low.", 16),
    (0xCC005024, "DSP_AR_DMA_ARADDR_H", "DSP Register", "ARAM DMA ARAM Address High.", 16),
    (0xCC005026, "DSP_AR_DMA_ARADDR_L", "DSP Register", "ARAM DMA ARAM Address Low.", 16),
    (0xCC005028, "DSP_AR_DMA_CNT_H", "DSP Register", "ARAM DMA Count High (includes transfer type bit).", 16),
    (0xCC00502A, "DSP_AR_DMA_CNT_L", "DSP Register", "ARAM DMA Count Low.", 16),
    (0xCC005030, "AI_DMA_STARTADDR_H", "Audio Interface", "Audio Streaming DMA Start Address High.", 16), # Part of DSP block but named AI
    (0xCC005032, "AI_DMA_STARTADDR_L", "Audio Interface", "Audio Streaming DMA Start Address Low.", 16),
    (0xCC005036, "AI_DMA_CTL_LEN", "Audio Interface", "Audio Streaming DMA Control/Length. Bit 15=play/stop.", 16),
    (0xCC00503A, "AI_DMA_BYTES_LEFT", "Audio Interface", "Audio Streaming DMA Bytes Left.", 16),

    # - DI - DVD Interface (0xCC006000, size 0x40, common access 4 bytes)
    (0xCC006000, "DI_SR", "Drive Interface", "DI Status Register. Interrupt status/mask for Break, Transfer Complete, Device Error. DI Break control.", 32),
    (0xCC006004, "DI_CVR", "Drive Interface", "DI Cover Register. Cover interrupt status/mask, cover state.", 32),
    (0xCC006008, "DI_CMDBUF0", "Drive Interface", "DI Command Buffer 0 (Command, Subcommand1, Subcommand2).", 32),
    (0xCC00600C, "DI_CMDBUF1", "Drive Interface", "DI Command Buffer 1 (e.g., offset).", 32),
    (0xCC006010, "DI_CMDBUF2", "Drive Interface", "DI Command Buffer 2 (e.g., length).", 32),
    (0xCC006014, "DI_MAR", "Drive Interface", "DMA Memory Address Register.", 32),
    (0xCC006018, "DI_LENGTH", "Drive Interface", "DI DMA Transfer Length Register.", 32),
    (0xCC00601C, "DI_CR", "Drive Interface", "DI Control Register. Access mode (RW), DMA/Immediate mode, Transfer Start.", 32),
    (0xCC006020, "DI_IMMBUF", "Drive Interface", "DI Immediate Data Buffer (e.g., error code, register access data).", 32),
    (0xCC006024, "DI_CFG", "Drive Interface", "DI Configuration Register. Latches DIDD bus during reset.", 32),

    # - SI - Serial Interface (0xCC006400, size 0x100, common access 4 bytes)
    (0xCC006400, "SI_C0_OUTBUF", "Serial Interface Register", "SI Channel 0 Output Buffer (JoyChannel 1 Command).", 32),
    (0xCC006404, "SI_C0_INBUF_HI", "Serial Interface Register", "SI Channel 0 Input Buffer High (JoyChannel 1 Buttons 1). Includes error status.", 32),
    (0xCC006408, "SI_C0_INBUF_LO", "Serial Interface Register", "SI Channel 0 Input Buffer Low (JoyChannel 1 Buttons 2).", 32),
    (0xCC00640C, "SI_C1_OUTBUF", "Serial Interface Register", "SI Channel 1 Output Buffer (JoyChannel 2 Command).", 32),
    (0xCC006410, "SI_C1_INBUF_HI", "Serial Interface Register", "SI Channel 1 Input Buffer High (JoyChannel 2 Buttons 1).", 32),
    (0xCC006414, "SI_C1_INBUF_LO", "Serial Interface Register", "SI Channel 1 Input Buffer Low (JoyChannel 2 Buttons 2).", 32),
    (0xCC006418, "SI_C2_OUTBUF", "Serial Interface Register", "SI Channel 2 Output Buffer (JoyChannel 3 Command).", 32),
    (0xCC00641C, "SI_C2_INBUF_HI", "Serial Interface Register", "SI Channel 2 Input Buffer High (JoyChannel 3 Buttons 1).", 32),
    (0xCC006420, "SI_C2_INBUF_LO", "Serial Interface Register", "SI Channel 2 Input Buffer Low (JoyChannel 3 Buttons 2).", 32),
    (0xCC006424, "SI_C3_OUTBUF", "Serial Interface Register", "SI Channel 3 Output Buffer (JoyChannel 4 Command).", 32),
    (0xCC006428, "SI_C3_INBUF_HI", "Serial Interface Register", "SI Channel 3 Input Buffer High (JoyChannel 4 Buttons 1).", 32),
    (0xCC00642C, "SI_C3_INBUF_LO", "Serial Interface Register", "SI Channel 3 Input Buffer Low (JoyChannel 4 Buttons 2).", 32),
    (0xCC006430, "SI_POLL", "Serial Interface Register", "SI Poll Register. Controls polling interval, port enables, VBlank copy.", 32),
    (0xCC006434, "SI_COMCSR", "Serial Interface Register", "SI Communication Control Status Register. Manages non-polling transfers.", 32),
    (0xCC006438, "SI_SR", "Serial Interface Register", "SI Status Register. Error status (No Response, Collision, Over/Under Run) for channels.", 32),
    (0xCC00643C, "SI_EXILK", "Serial Interface Register", "SI EXI Clock Lock. Prevents CPU from setting EXI clock to 32MHz.", 32),
    # SI_IO_BUFFER at 0xCC006480 is a 0x80 byte buffer, not a single register.
    (0xCC006480, "SI_IO_BUFFER", "Serial Interface Register", "SI I/O Buffer (128 bytes). Access by word.", 0x80 * 8), # Size is 0x80 bytes = 1024 bits

    # - EXI - External Interface (0xCC006800, size 0x40, common access 4 bytes)
    (0xCC006800, "EXI0_CSR", "EXI", "EXI Channel 0 Control/Status Register.", 32),
    (0xCC006804, "EXI0_MAR", "EXI", "EXI Channel 0 DMA Memory Address.", 32),
    (0xCC006808, "EXI0_LENGTH", "EXI", "EXI Channel 0 DMA Transfer Length.", 32),
    (0xCC00680C, "EXI0_CR", "EXI", "EXI Channel 0 DMA Control Register (TLEN, RW, DMA, TSTART).", 32),
    (0xCC006810, "EXI0_DATA", "EXI", "EXI Channel 0 Immediate Data.", 32),
    (0xCC006814, "EXI1_CSR", "EXI", "EXI Channel 1 Control/Status Register.", 32),
    (0xCC006818, "EXI1_MAR", "EXI", "EXI Channel 1 DMA Memory Address.", 32),
    (0xCC00681C, "EXI1_LENGTH", "EXI", "EXI Channel 1 DMA Transfer Length.", 32),
    (0xCC006820, "EXI1_CR", "EXI", "EXI Channel 1 DMA Control Register.", 32),
    (0xCC006824, "EXI1_DATA", "EXI", "EXI Channel 1 Immediate Data.", 32),
    (0xCC006828, "EXI2_CSR", "EXI", "EXI Channel 2 Control/Status Register.", 32),
    (0xCC00682C, "EXI2_MAR", "EXI", "EXI Channel 2 DMA Memory Address.", 32),
    (0xCC006830, "EXI2_LENGTH", "EXI", "EXI Channel 2 DMA Transfer Length.", 32),
    (0xCC006834, "EXI2_CR", "EXI", "EXI Channel 2 DMA Control Register.", 32),
    (0xCC006838, "EXI2_DATA", "EXI", "EXI Channel 2 Immediate Data.", 32),

    # - AI - Audio Streaming Interface (0xCC006C00, size 0x20, common access 4 bytes)
    (0xCC006C00, "AI_AICR", "Audio Interface", "Audio Interface Control Register. Controls sample rate, counter reset, interrupt status/mask, play status.", 32),
    (0xCC006C04, "AI_AIVR", "Audio Interface", "Audio Interface Volume Register. Left and Right channel volume.", 32),
    (0xCC006C08, "AI_AISCNT", "Audio Interface", "Audio Interface Sample Counter. Counts stereo samples output.", 32),
    (0xCC006C0C, "AI_AIIT", "Audio Interface", "Audio Interface Interrupt Timing. Sample count for interrupt.", 32),

    # - GX FIFO - Graphics FIFO (0xCC008000)
    (0xCC008000, "GX_FIFO", "Graphics FIFO", "Graphics Processor Command FIFO. Write graphics commands and data here.", 32), # Size is effectively "as needed", defined as 4 for a single word write.
]