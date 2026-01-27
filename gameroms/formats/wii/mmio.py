from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from ...core.view_base import MmioRegister


@dataclass(frozen=True)
class GlobalSymbol:
    addr: int
    name: str
    type_str: str | None
    description: str
    is_function: bool = False


WII_MMIO_REGISTERS: list[MmioRegister] = [
    MmioRegister(0xCD000000, "HW_IPC_PPCMSG", 4, "IPC Message from PPC to ARM."),
    MmioRegister(0xCD000004, "HW_IPC_PPCCTRL", 4, "IPC Control from PPC to ARM."),
    MmioRegister(0xCD000008, "HW_IPC_ARMMSG", 4, "IPC Message from ARM to PPC."),
    MmioRegister(0xCD00000C, "HW_IPC_ARMCTRL", 4, "IPC Control from ARM to PPC."),
    MmioRegister(0xCD000010, "HW_TIMER", 4, "Starlet Timer value."),
    MmioRegister(0xCD000014, "HW_ALARM", 4, "Starlet Timer alarm value."),
    MmioRegister(
        0xCD000018,
        "HW_VI1CFG",
        4,
        "VI-configuration related, potentially unused. Related to VISEL bit 1.",
    ),
    MmioRegister(0xCD00001C, "HW_VIDIM", 4, "Dims the video output."),
    MmioRegister(
        0xCD000024, "HW_VISOLID", 4, "Sets the video output to a solid color."
    ),
    MmioRegister(
        0xCD000030, "HW_PPCIRQFLAG", 4, "Hollywood IRQ controller PPC IRQ Flags."
    ),
    MmioRegister(
        0xCD000034, "HW_PPCIRQMASK", 4, "Hollywood IRQ controller PPC IRQ Mask."
    ),
    MmioRegister(
        0xCD000038, "HW_ARMIRQFLAG", 4, "Hollywood IRQ controller ARM IRQ Flags."
    ),
    MmioRegister(
        0xCD00003C, "HW_ARMIRQMASK", 4, "Hollywood IRQ controller ARM IRQ Mask."
    ),
    MmioRegister(
        0xCD000040, "HW_ARMFIQMASK", 4, "Hollywood IRQ controller ARM FIQ Mask."
    ),
    MmioRegister(0xCD000044, "HW_IOPINTPPC", 4, "Interrupt from IO PADS to PPC."),
    MmioRegister(0xCD000048, "HW_WDGINTSTS", 4, "Watchdog Interrupt Status."),
    MmioRegister(0xCD00004C, "HW_WDGCFG", 4, "Watchdog Configuration."),
    MmioRegister(
        0xCD000050, "HW_DMAADRINTSTS", 4, "DMA Address Error Interrupt Status."
    ),
    MmioRegister(
        0xCD000054, "HW_CPUADRINTSTS", 4, "CPU Address Error Interrupt Status."
    ),
    MmioRegister(0xCD000058, "HW_DBGINTSTS", 4, "Debug Interrupt Status."),
    MmioRegister(0xCD00005C, "HW_DBGINTEN", 4, "Debug Interrupt Enable."),
    MmioRegister(
        0xCD000060,
        "HW_SRNPROT",
        4,
        "Bus control for SRAM visibility and mirroring; includes SRAM bank swap.",
    ),
    MmioRegister(
        0xCD000064,
        "HW_AHBPROT",
        4,
        "Access control for PPC and IOP to devices on the AHB. Also known as HW_BUSPROT.",
    ),
    MmioRegister(0xCD000068, "HW_I2CIOPINTEN", 4, "I2C IOP Interrupt Enable."),
    MmioRegister(0xCD00006C, "HW_I2CIOPINTSTS", 4, "I2C IOP Interrupt Status."),
    MmioRegister(
        0xCD000070,
        "HW_AIPPROT",
        4,
        "EXI bus enable and control; Flipper interface compatibility.",
    ),
    MmioRegister(
        0xCD000074,
        "HW_AIPIOCTRL",
        4,
        "AIP IO Control; Flipper interface compatibility and bus control.",
    ),
    MmioRegister(0xCD000078, "HW_VIINTEN", 4, "VI Interrupt Enable."),
    MmioRegister(0xCD00007C, "HW_VIINTSTS", 4, "VI Interrupt Status."),
    MmioRegister(
        0xCD000080, "HW_USBDBG0", 4, "USB-related debug register 0, potentially unused."
    ),
    MmioRegister(
        0xCD000084, "HW_USBDBG1", 4, "USB-related debug register 1, potentially unused."
    ),
    MmioRegister(0xCD000088, "HW_USBFRCRST", 4, "USB Force Reset."),
    MmioRegister(0xCD00008C, "HW_USBIOTEST", 4, "USB IO Test."),
    MmioRegister(
        0xCD000090,
        "HW_ELA_REG_ADDR",
        4,
        "Address register for Embedded Logic Analyzer (ELA).",
    ),
    MmioRegister(
        0xCD000094,
        "HW_ELA_REG_DATA",
        4,
        "Data register for Embedded Logic Analyzer (ELA).",
    ),
    MmioRegister(0xCD000098, "HW_MEMTSTN", 4, "Memory Test N."),
    MmioRegister(0xCD00009C, "HW_MEMTSTP", 4, "Memory Test P."),
    MmioRegister(0xCD0000C0, "HW_GPIOB_OUT", 4, "Hollywood GPIOs Port B Output."),
    MmioRegister(0xCD0000C4, "HW_GPIOB_DIR", 4, "Hollywood GPIOs Port B Direction."),
    MmioRegister(0xCD0000C8, "HW_GPIOB_IN", 4, "Hollywood GPIOs Port B Input."),
    MmioRegister(
        0xCD0000CC, "HW_GPIOB_INTLVL", 4, "Hollywood GPIOs Port B Interrupt Level."
    ),
    MmioRegister(
        0xCD0000D0, "HW_GPIOB_INTFLAG", 4, "Hollywood GPIOs Port B Interrupt Flag."
    ),
    MmioRegister(
        0xCD0000D4, "HW_GPIOB_INTMASK", 4, "Hollywood GPIOs Port B Interrupt Mask."
    ),
    MmioRegister(0xCD0000D8, "HW_GPIOB_STRAPS", 4, "Hollywood GPIOs Port B Straps."),
    MmioRegister(
        0xCD0000DC, "HW_GPIO_ENABLE", 4, "Hollywood GPIOs Enable (Legacy Main GPIOs)."
    ),
    MmioRegister(
        0xCD0000E0, "HW_GPIO_OUT", 4, "Hollywood GPIOs Output (Legacy Main GPIOs)."
    ),
    MmioRegister(
        0xCD0000E4, "HW_GPIO_DIR", 4, "Hollywood GPIOs Direction (Legacy Main GPIOs)."
    ),
    MmioRegister(
        0xCD0000E8, "HW_GPIO_IN", 4, "Hollywood GPIOs Input (Legacy Main GPIOs)."
    ),
    MmioRegister(
        0xCD0000EC,
        "HW_GPIO_INTLVL",
        4,
        "Hollywood GPIOs Interrupt Level (Legacy Main GPIOs).",
    ),
    MmioRegister(
        0xCD0000F0,
        "HW_GPIO_INTFLAG",
        4,
        "Hollywood GPIOs Interrupt Flag (Legacy Main GPIOs).",
    ),
    MmioRegister(
        0xCD0000F4,
        "HW_GPIO_INTMASK",
        4,
        "Hollywood GPIOs Interrupt Mask (Legacy Main GPIOs).",
    ),
    MmioRegister(
        0xCD0000F8, "HW_GPIO_STRAPS", 4, "Hollywood GPIOs Straps (Legacy Main GPIOs)."
    ),
    MmioRegister(0xCD0000FC, "HW_GPIO_OWNER", 4, "Hollywood GPIOs Owner."),
    MmioRegister(0xCD000100, "HW_ARB_CFG_M0", 4, "AHB Arbiter Config Master 0."),
    MmioRegister(0xCD000104, "HW_ARB_CFG_M1", 4, "AHB Arbiter Config Master 1."),
    MmioRegister(0xCD000108, "HW_ARB_CFG_M2", 4, "AHB Arbiter Config Master 2."),
    MmioRegister(0xCD00010C, "HW_ARB_CFG_M3", 4, "AHB Arbiter Config Master 3."),
    MmioRegister(0xCD000110, "HW_ARB_CFG_M4", 4, "AHB Arbiter Config Master 4."),
    MmioRegister(0xCD000114, "HW_ARB_CFG_M5", 4, "AHB Arbiter Config Master 5."),
    MmioRegister(0xCD000118, "HW_ARB_CFG_M6", 4, "AHB Arbiter Config Master 6."),
    MmioRegister(0xCD00011C, "HW_ARB_CFG_M7", 4, "AHB Arbiter Config Master 7."),
    MmioRegister(0xCD000120, "HW_ARB_CFG_M8", 4, "AHB Arbiter Config Master 8."),
    MmioRegister(0xCD000124, "HW_ARB_CFG_M9", 4, "AHB Arbiter Config Master 9."),
    MmioRegister(0xCD000130, "HW_ARB_CFG_MC", 4, "AHB Arbiter Config Master C."),
    MmioRegister(0xCD000134, "HW_ARB_CFG_MD", 4, "AHB Arbiter Config Master D."),
    MmioRegister(0xCD000138, "HW_ARB_CFG_ME", 4, "AHB Arbiter Config Master E."),
    MmioRegister(0xCD00013C, "HW_ARB_CFG_MF", 4, "AHB Arbiter Config Master F."),
    MmioRegister(0xCD000140, "HW_ARB_CFG_CPU", 4, "AHB Arbiter Config CPU."),
    MmioRegister(0xCD000144, "HW_ARB_CFG_DMA", 4, "AHB Arbiter Config DMA."),
    MmioRegister(0xCD000148, "HW_ARB_PCNTCFG", 4, "AHB Arbiter Perf Counter Config."),
    MmioRegister(0xCD00014C, "HW_ARB_PCNTSTS", 4, "AHB Arbiter Perf Counter Status."),
    MmioRegister(0xCD000150, "HW_I2CSCTRL_0", 4, "I2C Slave Control (instance 0)."),
    MmioRegister(0xCD000154, "HW_I2CSSTS_0", 4, "I2C Slave Status (instance 0)."),
    MmioRegister(0xCD000158, "HW_I2CSRDEN_0", 4, "I2C Slave Read Enable (instance 0)."),
    MmioRegister(0xCD000160, "HW_I2CSTRAP", 4, "I2C Strap Configuration."),
    MmioRegister(0xCD000164, "HW_I2CSCTRL_1", 4, "I2C Slave Control (instance 1)."),
    MmioRegister(
        0xCD000168, "HW_I2CSVISETYUV", 4, "I2C Slave VI Set YUV (via I2C to VI)."
    ),
    MmioRegister(
        0xCD00016C, "HW_I2CSVISETFILT", 4, "I2C Slave VI Set Filter (via I2C to VI)."
    ),
    MmioRegister(0xCD000170, "HW_SPARE2", 4, "Spare Register 2."),
    MmioRegister(0xCD000174, "HW_SPARE3", 4, "Spare Register 3."),
    MmioRegister(
        0xCD000180,
        "HW_COMPAT",
        4,
        "Compatibility register for DI functions and PPC boot options. (needs verification)",
    ),
    MmioRegister(0xCD000184, "HW_RESET_AHB", 4, "(ACRRSTAHB) AHB Reset Control."),
    MmioRegister(0xCD000188, "HW_SPARE0", 4, "Spare Register 0."),
    MmioRegister(
        0xCD00018C,
        "HW_BOOT0",
        4,
        "(ACR_SPARE1) Controls boot0 memory mapping and DSK PLL source. (needs verification)",
    ),
    MmioRegister(
        0xCD000190,
        "HW_CLOCKS",
        4,
        "(ACRSYSCTRL) System clock control, including CPU speed mode.",
    ),
    MmioRegister(
        0xCD000194,
        "HW_RESETS",
        4,
        "(ACRRSTCTRL) System reset and power control for various components. (needs verification)",
    ),
    MmioRegister(
        0xCD000198, "HW_IFPOWER", 4, "(ACRCLKGATE) Interface power gating control."
    ),
    MmioRegister(0xCD00019C, "HW_PLLDR", 4, "PLL Drive / Clock configuration."),
    MmioRegister(0xCD0001A0, "HW_PLLSYSEXT1", 4, "System PLL External Control 1."),
    MmioRegister(0xCD0001A4, "HW_PLLSYSEXT2", 4, "System PLL External Control 2."),
    MmioRegister(0xCD0001A8, "HW_PLLAIEXT1", 4, "Audio PLL External Control 1."),
    MmioRegister(0xCD0001AC, "HW_PLLAIEXT2", 4, "Audio PLL External Control 2."),
    MmioRegister(0xCD0001B0, "HW_PLLSYS", 4, "System PLL Control."),
    MmioRegister(0xCD0001B4, "HW_PLLSYSEXT", 4, "System PLL External Control (Main)."),
    MmioRegister(0xCD0001B8, "HW_PLLDSK", 4, "Disk (DI) PLL Control."),
    MmioRegister(0xCD0001BC, "HW_PLLDDR", 4, "DDR (MEM2) PLL Control."),
    MmioRegister(0xCD0001C0, "HW_PLLDDREXT", 4, "DDR (MEM2) PLL External Control."),
    MmioRegister(0xCD0001C4, "HW_PLLVI", 4, "Video Interface PLL Control."),
    MmioRegister(0xCD0001C8, "HW_PLLVIEXT", 4, "Video Interface PLL External Control."),
    MmioRegister(0xCD0001CC, "HW_PLLAI", 4, "Audio Interface PLL Control."),
    MmioRegister(0xCD0001D0, "HW_PLLAIEXT", 4, "Audio Interface PLL External Control."),
    MmioRegister(0xCD0001D4, "HW_PLLUSB", 4, "USB PLL Control."),
    MmioRegister(0xCD0001D8, "HW_PLLUSBEXT", 4, "USB PLL External Control."),
    MmioRegister(0xCD0001DC, "HW_IOPWRCTRL", 4, "IOP subsystem power control."),
    MmioRegister(0xCD0001E0, "HW_IOSTRCTRL0", 4, "IO Strength Control 0."),
    MmioRegister(0xCD0001E4, "HW_IOSTRCTRL1", 4, "IO Strength Control 1."),
    MmioRegister(0xCD0001E8, "HW_CLKSTRCTRL", 4, "Clock Strength Control."),
    MmioRegister(
        0xCD0001EC, "HW_OTPCMD", 4, "(ACREFUSEADDR) OTP command and address register."
    ),
    MmioRegister(0xCD0001F0, "HW_OTPDATA", 4, "(ACREFUSEDATA) OTP data register."),
    MmioRegister(0xCD0001F4, "HW_DBGCLK", 4, "Debug Clock Control."),
    MmioRegister(0xCD0001F8, "HW_OBSCLKOCTRL", 4, "Observe Clock Output Control."),
    MmioRegister(0xCD0001FC, "HW_OBSCLKICTRL", 4, "Observe Clock Input Control."),
    MmioRegister(0xCD000200, "HW_DBGPORT", 4, "Debug Port."),
    MmioRegister(
        0xCD000204,
        "HW_SICLKDIV",
        4,
        "Serial Interface (SI) clock divider, potentially unused.",
    ),
    MmioRegister(
        0xCD000208, "HW_SICTRL", 4, "Serial Interface (SI) control, potentially unused."
    ),
    MmioRegister(
        0xCD00020C, "HW_SIDATA", 4, "Serial Interface (SI) data, potentially unused."
    ),
    MmioRegister(
        0xCD000210,
        "HW_SIINT",
        4,
        "Serial Interface (SI) interrupt, potentially unused.",
    ),
    MmioRegister(
        0xCD000214,
        "HW_VERSION",
        4,
        "(ACRCHIPREVID) Hollywood chip version and revision register.",
    ),
    MmioRegister(0xCD000218, "HW_DBGBUSRD", 4, "Debug Bus Read Data."),
    MmioRegister(0xCD0B420A, "MEM_PROT", 2, "MEM2 protection enable."),
    MmioRegister(
        0xCD0B420C,
        "MEM_PROT_START",
        2,
        "MEM2 protection low address (upper 16 bits of physical address).",
    ),
    MmioRegister(
        0xCD0B420E,
        "MEM_PROT_END",
        2,
        "MEM2 protection high address (upper 16 bits of physical address).",
    ),
    MmioRegister(0xCD0B4228, "MEM_FLUSHREQ", 2, "AHB flush request."),
    MmioRegister(0xCD0B422A, "MEM_FLUSHACK", 2, "AHB flush ack."),
    MmioRegister(
        0xCC000000,
        "CP_SR",
        2,
        "Status Register. Bits: 4=BP interrupt, 3=GP idle for commands, 2=GP idle for reading, 1=GX FIFO underflow, 0=GX FIFO overflow.",
    ),
    MmioRegister(
        0xCC000002,
        "CP_CR",
        2,
        "Control Register. Bits: 5=BP enable, 4=GP link enable, 3=FIFO underflow IRQ enable, 2=FIFO overflow IRQ enable/CP IRQ, 1=CP IRQ enable, 0=GP FIFO read enable.",
    ),
    MmioRegister(
        0xCC000004,
        "CP_CLR",
        2,
        "Clear Register. Write 1 to clear: bit 1=FIFO underflow, bit 0=FIFO overflow.",
    ),
    MmioRegister(0xCC00000E, "CP_TOKEN", 2, "Token register."),
    MmioRegister(0xCC000010, "CP_BBOX_LEFT", 2, "Bounding box - left."),
    MmioRegister(0xCC000012, "CP_BBOX_RIGHT", 2, "Bounding box - right."),
    MmioRegister(0xCC000014, "CP_BBOX_TOP", 2, "Bounding box - top."),
    MmioRegister(0xCC000016, "CP_BBOX_BOTTOM", 2, "Bounding box - bottom."),
    MmioRegister(0xCC000020, "CP_FIFO_BASE_LO", 2, "CP FIFO base address low part."),
    MmioRegister(0xCC000022, "CP_FIFO_BASE_HI", 2, "CP FIFO base address high part."),
    MmioRegister(0xCC000024, "CP_FIFO_END_LO", 2, "CP FIFO end address low part."),
    MmioRegister(0xCC000026, "CP_FIFO_END_HI", 2, "CP FIFO end address high part."),
    MmioRegister(
        0xCC000028, "CP_FIFO_HIWATER_LO", 2, "CP FIFO high watermark low part."
    ),
    MmioRegister(
        0xCC00002A, "CP_FIFO_HIWATER_HI", 2, "CP FIFO high watermark high part."
    ),
    MmioRegister(
        0xCC00002C, "CP_FIFO_LOWATER_LO", 2, "CP FIFO low watermark low part."
    ),
    MmioRegister(
        0xCC00002E, "CP_FIFO_LOWATER_HI", 2, "CP FIFO low watermark high part."
    ),
    MmioRegister(
        0xCC000030, "CP_FIFO_RW_DIST_LO", 2, "CP FIFO read/write distance low part."
    ),
    MmioRegister(
        0xCC000032, "CP_FIFO_RW_DIST_HI", 2, "CP FIFO read/write distance high part."
    ),
    MmioRegister(0xCC000034, "CP_FIFO_WPTR_LO", 2, "CP FIFO write pointer low part."),
    MmioRegister(0xCC000036, "CP_FIFO_WPTR_HI", 2, "CP FIFO write pointer high part."),
    MmioRegister(0xCC000038, "CP_FIFO_RPTR_LO", 2, "CP FIFO read pointer low part."),
    MmioRegister(0xCC00003A, "CP_FIFO_RPTR_HI", 2, "CP FIFO read pointer high part."),
    MmioRegister(
        0xCC00003C, "CP_FIFO_BP_LO", 2, "CP FIFO breakpoint address low part."
    ),
    MmioRegister(
        0xCC00003E, "CP_FIFO_BP_HI", 2, "CP FIFO breakpoint address high part."
    ),
    MmioRegister(
        0xCC001000,
        "PE_ZCONFIG",
        2,
        "Z configuration. Bits: 4=Z update enable, 1-3=Z function, 0=Z-comparator enable.",
    ),
    MmioRegister(
        0xCC001002,
        "PE_ALPHACONFIG",
        2,
        "Alpha configuration. Controls blending, alpha/color update, dithering.",
    ),
    MmioRegister(
        0xCC001004,
        "PE_DESTALPHA",
        2,
        "Destination alpha. Bits: 8=enable, 0-7=alpha value.",
    ),
    MmioRegister(
        0xCC001006, "PE_ALPHAMODE", 2, "Alpha Mode. Bits: 8-15=mode, 0-7=threshold."
    ),
    MmioRegister(0xCC001008, "PE_ALPHAREAD", 2, "Alpha Read mode."),
    MmioRegister(
        0xCC00100A,
        "PE_ISR",
        2,
        "Interrupt Status Register. Bits: 3=PE Finish, 2=PE Token, 1=PE Finish enable, 0=PE Token enable.",
    ),
    MmioRegister(
        0xCC00100E,
        "PE_TOKEN_VALUE",
        2,
        "PE Token value asserted from last PE Token Interrupt.",
    ),
    MmioRegister(
        0xCC002000,
        "VI_VTR",
        2,
        "Vertical Timing Register. Controls active video lines (ACV) and equalization pulse (EQU).",
    ),
    MmioRegister(
        0xCC002002,
        "VI_DCR",
        2,
        "Display Configuration Register. Controls video format, display latch, interlace, reset, enable.",
    ),
    MmioRegister(
        0xCC002004, "VI_HTR0", 4, "Horizontal Timing 0. Controls HCS, HCE, HLW."
    ),
    MmioRegister(
        0xCC002008, "VI_HTR1", 4, "Horizontal Timing 1. Controls HBS, HBE, HSY."
    ),
    MmioRegister(
        0xCC00200C,
        "VI_VTO",
        4,
        "Odd Field Vertical Timing Register. Controls PSB, PRB for odd fields.",
    ),
    MmioRegister(
        0xCC002010,
        "VI_VTE",
        4,
        "Even Field Vertical Timing Register. Controls PSB, PRB for even fields.",
    ),
    MmioRegister(
        0xCC002014, "VI_BBEI", 4, "Odd Field Burst Blanking Interval Register."
    ),
    MmioRegister(
        0xCC002018, "VI_BBOI", 4, "Even Field Burst Blanking Interval Register."
    ),
    MmioRegister(
        0xCC00201C,
        "VI_TFBL",
        4,
        "Top Field Base Register (L). Specifies display origin for top/left field.",
    ),
    MmioRegister(
        0xCC002020,
        "VI_TFBR",
        4,
        "Top Field Base Register (R). Specifies display origin for top/right field in 3D mode.",
    ),
    MmioRegister(
        0xCC002024,
        "VI_BFBL",
        4,
        "Bottom Field Base Register (L). Specifies display origin for bottom/left field.",
    ),
    MmioRegister(
        0xCC002028,
        "VI_BFBR",
        4,
        "Bottom Field Base Register (R). Specifies display origin for bottom/right field in 3D mode.",
    ),
    MmioRegister(
        0xCC00202C, "VI_DPV", 2, "Current Vertical Position of Raster beam (VCT)."
    ),
    MmioRegister(
        0xCC00202E, "VI_DPH", 2, "Current Horizontal Position of Raster beam (HCT)."
    ),
    MmioRegister(
        0xCC002030,
        "VI_DI0",
        4,
        "Display Interrupt 0. Configures VCT, HCT for interrupt, enable and status.",
    ),
    MmioRegister(0xCC002034, "VI_DI1", 4, "Display Interrupt 1."),
    MmioRegister(0xCC002038, "VI_DI2", 4, "Display Interrupt 2."),
    MmioRegister(0xCC00203C, "VI_DI3", 4, "Display Interrupt 3."),
    MmioRegister(
        0xCC002040,
        "VI_DL0",
        4,
        "Display Latch Register 0. Latches VCT, HCT on gt0 signal.",
    ),
    MmioRegister(
        0xCC002044,
        "VI_DL1",
        4,
        "Display Latch Register 1. Latches VCT, HCT on gt1 signal.",
    ),
    MmioRegister(
        0xCC002048, "VI_HSW", 2, "Horizontal Scaling Width Register (SRCWIDTH)."
    ),
    MmioRegister(
        0xCC00204A,
        "VI_HSR",
        2,
        "Horizontal Scaling Register. Enable (HS_EN) and step size (STP).",
    ),
    MmioRegister(
        0xCC00204C,
        "VI_FCT0",
        4,
        "Filter Coefficient Table 0 (Taps 0-2). For anti-aliasing.",
    ),
    MmioRegister(0xCC002050, "VI_FCT1", 4, "Filter Coefficient Table 1 (Taps 3-5)."),
    MmioRegister(0xCC002054, "VI_FCT2", 4, "Filter Coefficient Table 2 (Taps 6-8)."),
    MmioRegister(0xCC002058, "VI_FCT3", 4, "Filter Coefficient Table 3 (Taps 9-12)."),
    MmioRegister(0xCC00205C, "VI_FCT4", 4, "Filter Coefficient Table 4 (Taps 13-16)."),
    MmioRegister(0xCC002060, "VI_FCT5", 4, "Filter Coefficient Table 5 (Taps 17-20)."),
    MmioRegister(
        0xCC002064,
        "VI_FCT6",
        4,
        "Filter Coefficient Table 6 (Taps 21-23, T24 hardwired 0).",
    ),
    MmioRegister(
        0xCC002068, "VI_UNK_AA_68", 4, "Unknown anti-aliasing related register."
    ),
    MmioRegister(
        0xCC00206C,
        "VI_CLKSEL",
        2,
        "VI Clock Select Register. Selects 27MHz or 54MHz video clock.",
    ),
    MmioRegister(
        0xCC00206E,
        "VI_DTVSTAT",
        2,
        "VI DTV Status Register (VISEL). Reads status of I/O pins.",
    ),
    MmioRegister(0xCC002070, "VI_UNK_70", 2, "Unknown VI register."),
    MmioRegister(
        0xCC002072,
        "VI_BORDER_HBE",
        2,
        "Border Horizontal Blank End. For debug mode border.",
    ),
    MmioRegister(
        0xCC002074,
        "VI_BORDER_HBS",
        2,
        "Border Horizontal Blank Start. For debug mode border.",
    ),
    MmioRegister(0xCC002076, "VI_UNK_76", 2, "Unknown VI register."),
    MmioRegister(0xCC002078, "VI_UNK_78", 4, "Unknown VI register."),
    MmioRegister(0xCC00207C, "VI_UNK_7C", 4, "Unknown VI register."),
    MmioRegister(
        0xCC003000,
        "PI_INTSR",
        4,
        "Interrupt Cause Register. Shows sources of interrupts (RSWST, HSP, DEBUG, CP, PE_FINISH, etc.). Read to clear.",
    ),
    MmioRegister(
        0xCC003004,
        "PI_INTMR",
        4,
        "Interrupt Mask Register. Enables/disables interrupts corresponding to INTSR bits.",
    ),
    MmioRegister(0xCC00300C, "PI_FIFO_BASE", 4, "CPU FIFO Base Start address."),
    MmioRegister(0xCC003010, "PI_FIFO_END", 4, "CPU FIFO Base End address."),
    MmioRegister(0xCC003014, "PI_FIFO_WPTR", 4, "CPU FIFO current Write Pointer."),
    MmioRegister(
        0xCC003024,
        "PI_RESET",
        4,
        "Reset Register. Writing here can cause a system reset.",
    ),
    MmioRegister(
        0xCC00302C,
        "PI_CONSOLE_TYPE",
        4,
        "Console Type Register. Bits 28-31 indicate console type (e.g., 2 for HW2).",
    ),
    MmioRegister(
        0xCC004000, "MI_PROT_RGN1", 4, "Protected Region 1 (Page Address Lo/Hi)."
    ),
    MmioRegister(
        0xCC004004, "MI_PROT_RGN2", 4, "Protected Region 2 (Page Address Lo/Hi)."
    ),
    MmioRegister(
        0xCC004008, "MI_PROT_RGN3", 4, "Protected Region 3 (Page Address Lo/Hi)."
    ),
    MmioRegister(
        0xCC00400C, "MI_PROT_RGN4", 4, "Protected Region 4 (Page Address Lo/Hi)."
    ),
    MmioRegister(
        0xCC004010,
        "MI_PROT_TYPE",
        2,
        "Protection Type for 4 regions (2 bits per channel: 0=denied, 1=RO, 2=WO, 3=RW).",
    ),
    MmioRegister(
        0xCC00401C,
        "MI_INTMASK",
        2,
        "MI Interrupt Mask. Bit 4=mask all, Bits 0-3=mask MEM0-3.",
    ),
    MmioRegister(
        0xCC00401E,
        "MI_INTSR",
        2,
        "MI Interrupt Cause. Bit 4=any MI irq, Bits 0-3=MEM0-3 irq. Write 1 to clear.",
    ),
    MmioRegister(0xCC004020, "MI_PROT_STATUS", 2, "Protection status bits."),
    MmioRegister(
        0xCC004022,
        "MI_FAIL_ADDR_LO",
        2,
        "Address (low part) which failed protection rules.",
    ),
    MmioRegister(
        0xCC004024,
        "MI_FAIL_ADDR_HI",
        2,
        "Address (high part) which failed protection rules.",
    ),
    MmioRegister(0xCC004032, "MI_TIMER0_HI", 2, "Memory Interface Timer 0 High."),
    MmioRegister(0xCC004034, "MI_TIMER0_LO", 2, "Memory Interface Timer 0 Low."),
    MmioRegister(0xCC004036, "MI_TIMER1_HI", 2, "Memory Interface Timer 1 High."),
    MmioRegister(0xCC004038, "MI_TIMER1_LO", 2, "Memory Interface Timer 1 Low."),
    MmioRegister(0xCC004056, "MI_TIMER9_HI", 2, "Memory Interface Timer 9 High."),
    MmioRegister(0xCC004058, "MI_TIMER9_LO", 2, "Memory Interface Timer 9 Low."),
    MmioRegister(0xCC00405A, "MI_UNK_5A", 2, "Unknown MI register."),
    MmioRegister(0xCC005000, "DSP_MAILBOX_IN_HI", 2, "DSP Mailbox High (CPU to DSP)."),
    MmioRegister(0xCC005002, "DSP_MAILBOX_IN_LO", 2, "DSP Mailbox Low (CPU to DSP)."),
    MmioRegister(0xCC005004, "DSP_MAILBOX_OUT_HI", 2, "CPU Mailbox High (DSP to CPU)."),
    MmioRegister(0xCC005006, "DSP_MAILBOX_OUT_LO", 2, "CPU Mailbox Low (DSP to CPU)."),
    MmioRegister(
        0xCC00500A,
        "DSP_CSR",
        2,
        "Control Status Register. Controls DSP reset, halt, interrupts (DSP, ARAM, AI).",
    ),
    MmioRegister(0xCC005012, "DSP_AR_SIZE", 2, "ARAM Size configuration."),
    MmioRegister(0xCC005016, "DSP_AR_MODE", 2, "ARAM Mode configuration."),
    MmioRegister(0xCC00501A, "DSP_AR_REFRESH", 2, "ARAM Refresh rate configuration."),
    MmioRegister(
        0xCC005020, "DSP_AR_DMA_MMADDR_H", 2, "ARAM DMA Main Memory Address High."
    ),
    MmioRegister(
        0xCC005022, "DSP_AR_DMA_MMADDR_L", 2, "ARAM DMA Main Memory Address Low."
    ),
    MmioRegister(0xCC005024, "DSP_AR_DMA_ARADDR_H", 2, "ARAM DMA ARAM Address High."),
    MmioRegister(0xCC005026, "DSP_AR_DMA_ARADDR_L", 2, "ARAM DMA ARAM Address Low."),
    MmioRegister(
        0xCC005028,
        "DSP_AR_DMA_CNT_H",
        2,
        "ARAM DMA Count High (includes transfer type bit).",
    ),
    MmioRegister(0xCC00502A, "DSP_AR_DMA_CNT_L", 2, "ARAM DMA Count Low."),
    MmioRegister(
        0xCC005030, "AI_DMA_STARTADDR_H", 2, "Audio Streaming DMA Start Address High."
    ),
    MmioRegister(
        0xCC005032, "AI_DMA_STARTADDR_L", 2, "Audio Streaming DMA Start Address Low."
    ),
    MmioRegister(
        0xCC005036,
        "AI_DMA_CTL_LEN",
        2,
        "Audio Streaming DMA Control/Length. Bit 15=play/stop.",
    ),
    MmioRegister(0xCC00503A, "AI_DMA_BYTES_LEFT", 2, "Audio Streaming DMA Bytes Left."),
    MmioRegister(
        0xCC006000,
        "DI_SR",
        4,
        "DI Status Register. Interrupt status/mask for Break, Transfer Complete, Device Error. DI Break control.",
    ),
    MmioRegister(
        0xCC006004,
        "DI_CVR",
        4,
        "DI Cover Register. Cover interrupt status/mask, cover state.",
    ),
    MmioRegister(
        0xCC006008,
        "DI_CMDBUF0",
        4,
        "DI Command Buffer 0 (Command, Subcommand1, Subcommand2).",
    ),
    MmioRegister(0xCC00600C, "DI_CMDBUF1", 4, "DI Command Buffer 1 (e.g., offset)."),
    MmioRegister(0xCC006010, "DI_CMDBUF2", 4, "DI Command Buffer 2 (e.g., length)."),
    MmioRegister(0xCC006014, "DI_MAR", 4, "DMA Memory Address Register."),
    MmioRegister(0xCC006018, "DI_LENGTH", 4, "DI DMA Transfer Length Register."),
    MmioRegister(
        0xCC00601C,
        "DI_CR",
        4,
        "DI Control Register. Access mode (RW), DMA/Immediate mode, Transfer Start.",
    ),
    MmioRegister(
        0xCC006020,
        "DI_IMMBUF",
        4,
        "DI Immediate Data Buffer (e.g., error code, register access data).",
    ),
    MmioRegister(
        0xCC006024,
        "DI_CFG",
        4,
        "DI Configuration Register. Latches DIDD bus during reset.",
    ),
    MmioRegister(
        0xCC006400,
        "SI_C0_OUTBUF",
        4,
        "SI Channel 0 Output Buffer (JoyChannel 1 Command).",
    ),
    MmioRegister(
        0xCC006404,
        "SI_C0_INBUF_HI",
        4,
        "SI Channel 0 Input Buffer High (JoyChannel 1 Buttons 1). Includes error status.",
    ),
    MmioRegister(
        0xCC006408,
        "SI_C0_INBUF_LO",
        4,
        "SI Channel 0 Input Buffer Low (JoyChannel 1 Buttons 2).",
    ),
    MmioRegister(
        0xCC00640C,
        "SI_C1_OUTBUF",
        4,
        "SI Channel 1 Output Buffer (JoyChannel 2 Command).",
    ),
    MmioRegister(
        0xCC006410,
        "SI_C1_INBUF_HI",
        4,
        "SI Channel 1 Input Buffer High (JoyChannel 2 Buttons 1).",
    ),
    MmioRegister(
        0xCC006414,
        "SI_C1_INBUF_LO",
        4,
        "SI Channel 1 Input Buffer Low (JoyChannel 2 Buttons 2).",
    ),
    MmioRegister(
        0xCC006418,
        "SI_C2_OUTBUF",
        4,
        "SI Channel 2 Output Buffer (JoyChannel 3 Command).",
    ),
    MmioRegister(
        0xCC00641C,
        "SI_C2_INBUF_HI",
        4,
        "SI Channel 2 Input Buffer High (JoyChannel 3 Buttons 1).",
    ),
    MmioRegister(
        0xCC006420,
        "SI_C2_INBUF_LO",
        4,
        "SI Channel 2 Input Buffer Low (JoyChannel 3 Buttons 2).",
    ),
    MmioRegister(
        0xCC006424,
        "SI_C3_OUTBUF",
        4,
        "SI Channel 3 Output Buffer (JoyChannel 4 Command).",
    ),
    MmioRegister(
        0xCC006428,
        "SI_C3_INBUF_HI",
        4,
        "SI Channel 3 Input Buffer High (JoyChannel 4 Buttons 1).",
    ),
    MmioRegister(
        0xCC00642C,
        "SI_C3_INBUF_LO",
        4,
        "SI Channel 3 Input Buffer Low (JoyChannel 4 Buttons 2).",
    ),
    MmioRegister(
        0xCC006430,
        "SI_POLL",
        4,
        "SI Poll Register. Controls polling interval, port enables, VBlank copy.",
    ),
    MmioRegister(
        0xCC006434,
        "SI_COMCSR",
        4,
        "SI Communication Control Status Register. Manages non-polling transfers.",
    ),
    MmioRegister(
        0xCC006438,
        "SI_SR",
        4,
        "SI Status Register. Error status (No Response, Collision, Over/Under Run) for channels.",
    ),
    MmioRegister(
        0xCC00643C,
        "SI_EXILK",
        4,
        "SI EXI Clock Lock. Prevents CPU from setting EXI clock to 32MHz.",
    ),
    MmioRegister(
        0xCC006480, "SI_IO_BUFFER", 128, "SI I/O Buffer (128 bytes). Access by word."
    ),
    MmioRegister(0xCC006800, "EXI0_CSR", 4, "EXI Channel 0 Control/Status Register."),
    MmioRegister(0xCC006804, "EXI0_MAR", 4, "EXI Channel 0 DMA Memory Address."),
    MmioRegister(0xCC006808, "EXI0_LENGTH", 4, "EXI Channel 0 DMA Transfer Length."),
    MmioRegister(
        0xCC00680C,
        "EXI0_CR",
        4,
        "EXI Channel 0 DMA Control Register (TLEN, RW, DMA, TSTART).",
    ),
    MmioRegister(0xCC006810, "EXI0_DATA", 4, "EXI Channel 0 Immediate Data."),
    MmioRegister(0xCC006814, "EXI1_CSR", 4, "EXI Channel 1 Control/Status Register."),
    MmioRegister(0xCC006818, "EXI1_MAR", 4, "EXI Channel 1 DMA Memory Address."),
    MmioRegister(0xCC00681C, "EXI1_LENGTH", 4, "EXI Channel 1 DMA Transfer Length."),
    MmioRegister(0xCC006820, "EXI1_CR", 4, "EXI Channel 1 DMA Control Register."),
    MmioRegister(0xCC006824, "EXI1_DATA", 4, "EXI Channel 1 Immediate Data."),
    MmioRegister(0xCC006828, "EXI2_CSR", 4, "EXI Channel 2 Control/Status Register."),
    MmioRegister(0xCC00682C, "EXI2_MAR", 4, "EXI Channel 2 DMA Memory Address."),
    MmioRegister(0xCC006830, "EXI2_LENGTH", 4, "EXI Channel 2 DMA Transfer Length."),
    MmioRegister(0xCC006834, "EXI2_CR", 4, "EXI Channel 2 DMA Control Register."),
    MmioRegister(0xCC006838, "EXI2_DATA", 4, "EXI Channel 2 Immediate Data."),
    MmioRegister(
        0xCC006C00,
        "AI_AICR",
        4,
        "Audio Interface Control Register. Controls sample rate, counter reset, interrupt status/mask, play status.",
    ),
    MmioRegister(
        0xCC006C04,
        "AI_AIVR",
        4,
        "Audio Interface Volume Register. Left and Right channel volume.",
    ),
    MmioRegister(
        0xCC006C08,
        "AI_AISCNT",
        4,
        "Audio Interface Sample Counter. Counts stereo samples output.",
    ),
    MmioRegister(
        0xCC006C0C,
        "AI_AIIT",
        4,
        "Audio Interface Interrupt Timing. Sample count for interrupt.",
    ),
    MmioRegister(
        0xCC008000,
        "GX_FIFO",
        4,
        "Graphics Processor Command FIFO. Write graphics commands and data here.",
    ),
]


WII_GLOBAL_SYMBOLS: list[GlobalSymbol] = [
    GlobalSymbol(0x80000000, "GameID", "char[4]", "Game Code.", False),
    GlobalSymbol(0x80000004, "MakerCode", "char[2]", "Maker code.", False),
    GlobalSymbol(
        0x80000006, "DiscNumber", "uint8_t", "Disc Number for multidisc games.", False
    ),
    GlobalSymbol(0x80000007, "DiscVersion", "uint8_t", "Disc Version.", False),
    GlobalSymbol(
        0x80000008, "DiscStreamingFlag", "uint8_t", "Disc Streaming flag.", False
    ),
    GlobalSymbol(
        0x80000009,
        "DiscStreamingBufferSize",
        "uint8_t",
        "Disc Streaming buffer size.",
        False,
    ),
    GlobalSymbol(
        0x80000018,
        "DiscLayoutMagicWii",
        "uint32_t",
        "Disc layout magic for Wii.",
        False,
    ),
    GlobalSymbol(
        0x8000001C,
        "DiscLayoutMagicGC",
        "uint32_t",
        "Disc layout magic for GameCube.",
        False,
    ),
    GlobalSymbol(
        0x80000020,
        "NintendoBootCodeMagic",
        "uint32_t",
        "Nintendo Standard Boot Code.",
        False,
    ),
    GlobalSymbol(
        0x80000024, "ApploaderVersion", "uint32_t", "Version set by apploader.", False
    ),
    GlobalSymbol(
        0x80000028,
        "MEM1SizePhysicalHeader",
        "uint32_t",
        "Physical Memory Size (24MB) from header.",
        False,
    ),
    GlobalSymbol(
        0x8000002C,
        "ProductionBoardModel",
        "uint32_t",
        "Production Board Model identifier.",
        False,
    ),
    GlobalSymbol(
        0x80000030, "ArenaLoHeader", "uint32_t", "Arena Low address from header.", False
    ),
    GlobalSymbol(
        0x80000034,
        "ArenaHiHeader",
        "uint32_t",
        "Arena High address from header.",
        False,
    ),
    GlobalSymbol(
        0x80000038,
        "FSTLocationHeader",
        "void*",
        "Start of FST from header (varies).",
        False,
    ),
    GlobalSymbol(
        0x8000003C,
        "FSTMaxSizeHeader",
        "uint32_t",
        "Maximum FST Size from header (varies).",
        False,
    ),
    GlobalSymbol(
        0x80000040,
        "pDBStruct",
        "void*",
        "Pointer to the beginning of the DB global struct.",
        False,
    ),
    GlobalSymbol(
        0x80000044, "DBExceptionMask", "uint32_t", "DB marked exception mask.", False
    ),
    GlobalSymbol(
        0x80000048,
        "DBExceptionDestination",
        "void*",
        "DB exception destination address.",
        False,
    ),
    GlobalSymbol(0x8000004C, "DBReturnAddress", "void*", "DB return address.", False),
    GlobalSymbol(
        0x80000060,
        "OSDebuggerHook",
        "void*",
        "Hook for debugged exceptions (OSDBIntegrator), disabled in production. SDK titles may write instructions here.",
        False,
    ),
    GlobalSymbol(
        0x800000C0,
        "pOSContextCurrentReal",
        "void*",
        "Pointer to Current OSContext instance (real mode).",
        False,
    ),
    GlobalSymbol(
        0x800000C4, "UserInterruptMask", "uint32_t", "User interrupt mask.", False
    ),
    GlobalSymbol(
        0x800000C8,
        "OSInterruptMask",
        "uint32_t",
        "Revolution OS interrupt mask.",
        False,
    ),
    GlobalSymbol(
        0x800000CC,
        "CurrentVideoMode",
        "uint32_t",
        "Value indicating current video mode (0=NTSC, 1=PAL, 2=MPAL).",
        False,
    ),
    GlobalSymbol(
        0x800000D4,
        "pOSContextCurrentTranslated",
        "void*",
        "Pointer to Current OSContext instance (translated mode).",
        False,
    ),
    GlobalSymbol(
        0x800000D8,
        "pOSContextFPRSave",
        "void*",
        "Pointer to OSContext to save FPRs to (NULL if unused).",
        False,
    ),
    GlobalSymbol(
        0x800000DC,
        "pOSThreadEarliest",
        "void*",
        "Pointer to the earliest created OSThread.",
        False,
    ),
    GlobalSymbol(
        0x800000E0,
        "pOSThreadLatest",
        "void*",
        "Pointer to the most recently created OSThread.",
        False,
    ),
    GlobalSymbol(
        0x800000E4,
        "pOSThreadCurrent",
        "void*",
        "Pointer to the current OSThread.",
        False,
    ),
    GlobalSymbol(
        0x800000EC,
        "DevDebuggerMonitorAddr",
        "void*",
        "Dev Debugger Monitor Address (if present).",
        False,
    ),
    GlobalSymbol(
        0x800000F0, "SimulatedMemorySize", "uint32_t", "Simulated Memory Size.", False
    ),
    GlobalSymbol(
        0x800000F4,
        "pBI2Data",
        "void*",
        "Pointer to data from partition's bi2.bin or emulated bi2.bin.",
        False,
    ),
    GlobalSymbol(
        0x800000F8, "ConsoleBusSpeed", "uint32_t", "Console Bus Speed.", False
    ),
    GlobalSymbol(
        0x800000FC, "ConsoleCPUSpeed", "uint32_t", "Console CPU Speed.", False
    ),
    GlobalSymbol(
        0x80000100,
        "SystemResetExceptionHandler",
        "void()",
        "System Reset Exception Handler.",
        True,
    ),
    GlobalSymbol(
        0x80000200,
        "MachineCheckExceptionHandler",
        "void()",
        "Machine Check Exception Handler.",
        True,
    ),
    GlobalSymbol(
        0x80000300,
        "DSIExceptionHandler",
        "void()",
        "Data Storage Interrupt (DSI) Exception Handler.",
        True,
    ),
    GlobalSymbol(
        0x80000400,
        "ISIExceptionHandler",
        "void()",
        "Instruction Storage Interrupt (ISI) Exception Handler.",
        True,
    ),
    GlobalSymbol(
        0x80000500,
        "ExternalInterruptHandler",
        "void()",
        "External Interrupt Handler.",
        True,
    ),
    GlobalSymbol(
        0x80000600,
        "AlignmentExceptionHandler",
        "void()",
        "Alignment Exception Handler.",
        True,
    ),
    GlobalSymbol(
        0x80000700,
        "ProgramExceptionHandler",
        "void()",
        "Program Exception Handler (for syscall, trap).",
        True,
    ),
    GlobalSymbol(
        0x80000800,
        "FloatingPointUnavailableHandler",
        "void()",
        "Floating Point Unavailable Exception Handler.",
        True,
    ),
    GlobalSymbol(
        0x80000900,
        "DecrementerExceptionHandler",
        "void()",
        "Decrementer Exception Handler.",
        True,
    ),
    GlobalSymbol(
        0x80000C00,
        "SystemCallExceptionHandler",
        "void()",
        "System Call Exception Handler (for PPC SC instruction).",
        True,
    ),
    GlobalSymbol(
        0x80000D00,
        "TraceExceptionHandler",
        "void()",
        "Trace Exception Handler (for debug).",
        True,
    ),
    GlobalSymbol(
        0x80000F00,
        "FloatingPointAssistHandler",
        "void()",
        "Floating Point Assist Exception Handler (for software FP emulation).",
        True,
    ),
    GlobalSymbol(
        0x80001300,
        "InstructionAddressBreakpointHandler",
        "void()",
        "Instruction Address Breakpoint (IABR) Exception Handler.",
        True,
    ),
    GlobalSymbol(
        0x80001400,
        "SystemManagementInterruptHandler",
        "void()",
        "System Management Interrupt (SMI) Handler.",
        True,
    ),
    GlobalSymbol(
        0x80001700,
        "ThermalManagementInterruptHandler",
        "void()",
        "Thermal Management Interrupt Handler.",
        True,
    ),
    GlobalSymbol(
        0x80001800,
        "OSHomebrewAreaStart",
        None,
        "Unused exception handler area, often utilized by homebrew for persistent code.",
        False,
    ),
    GlobalSymbol(
        0x80003000,
        "OSExceptionVectorAreaStart",
        None,
        "Start of OS managed exception vector area.",
        False,
    ),
    GlobalSymbol(
        0x80003040,
        "pOSInterruptTable",
        "void*",
        "Pointer to __OSInterrupt table.",
        False,
    ),
    GlobalSymbol(
        0x800030C0,
        "EXIProbeTimes",
        "uint32_t[2]",
        "EXI Probe start times for channels 0 and 1.",
        False,
    ),
    GlobalSymbol(
        0x800030C8,
        "pRELLoadedFirst",
        "void*",
        "Pointer to the first loaded REL (dynamically linked library) file.",
        False,
    ),
    GlobalSymbol(
        0x800030CC,
        "pRELLoadedLast",
        "void*",
        "Pointer to the last loaded REL file.",
        False,
    ),
    GlobalSymbol(
        0x800030D0,
        "pRELModuleNameTable",
        "char**",
        "Pointer to a REL module name table, or 0 if none.",
        False,
    ),
    GlobalSymbol(
        0x800030D8,
        "OSTime",
        "uint64_t",
        "System time as 64-bit value (units of 1/40.5MHz since 2000-01-01).",
        False,
    ),
    GlobalSymbol(
        0x800030E4,
        "OSPADButtonStatePort4Apploader",
        "uint16_t",
        "GameCube controller port 4 button state, set by apploader for NR disc support.",
        False,
    ),
    GlobalSymbol(
        0x800030E6,
        "DVDDeviceCodeAddress",
        "uint16_t",
        "DVD Device Code Address.",
        False,
    ),
    GlobalSymbol(
        0x800030E8,
        "OSDebugInfoPtr",
        "void*",
        "Pointer to Debug-related information structure.",
        False,
    ),
    GlobalSymbol(
        0x800030F0,
        "DOLExecuteParameters",
        "uint32_t",
        "Parameters for DOL execution.",
        False,
    ),
    GlobalSymbol(
        0x80003100,
        "OSPhysicalMEM1Size",
        "uint32_t",
        "Physical MEM1 size, set by IOS.",
        False,
    ),
    GlobalSymbol(
        0x80003104,
        "OSSimulatedMEM1Size",
        "uint32_t",
        "Simulated MEM1 size, set by OS.",
        False,
    ),
    GlobalSymbol(
        0x8000310C,
        "OSMEM1ArenaStart",
        "void*",
        "Start of MEM1 Arena (usable memory for game), set by IOS.",
        False,
    ),
    GlobalSymbol(
        0x80003110,
        "OSMEM1ArenaEnd",
        "void*",
        "End of MEM1 Arena (usable memory for game), set by IOS.",
        False,
    ),
    GlobalSymbol(
        0x80003118,
        "OSPhysicalMEM2Size",
        "uint32_t",
        "Physical MEM2 size, set by IOS.",
        False,
    ),
    GlobalSymbol(
        0x8000311C,
        "OSSimulatedMEM2Size",
        "uint32_t",
        "Simulated MEM2 size, set by IOS.",
        False,
    ),
    GlobalSymbol(
        0x80003120,
        "OSMEM2PPCAddressableEnd",
        "void*",
        "End of MEM2 addressable by PPC, set by IOS.",
        False,
    ),
    GlobalSymbol(
        0x80003124,
        "OSMEM2UsableStart",
        "void*",
        "Start of usable MEM2 for game, set by IOS.",
        False,
    ),
    GlobalSymbol(
        0x80003128,
        "OSMEM2UsableEnd",
        "void*",
        "End of usable MEM2 for game, set by IOS.",
        False,
    ),
    GlobalSymbol(
        0x80003130,
        "OS_IPCBufferStart",
        "void*",
        "Start of IOS Inter-Process Communication (IPC) buffer.",
        False,
    ),
    GlobalSymbol(
        0x80003134, "OS_IPCBufferEnd", "void*", "End of IOS IPC buffer.", False
    ),
    GlobalSymbol(
        0x80003138,
        "OSHollywoodVersion",
        "uint32_t",
        "Hollywood chip version (from HW_VERSION).",
        False,
    ),
    GlobalSymbol(0x80003140, "OSIOSVersion", "uint32_t", "IOS version.", False),
    GlobalSymbol(0x80003144, "OSIOSBuildDate", "uint32_t", "IOS Build Date.", False),
    GlobalSymbol(
        0x80003148,
        "OSIOSReservedHeapStart",
        "void*",
        "Start of IOS Reserved Heap.",
        False,
    ),
    GlobalSymbol(
        0x8000314C, "OSIOSReservedHeapEnd", "void*", "End of IOS Reserved Heap.", False
    ),
    GlobalSymbol(
        0x80003158, "OSGDDRVendorCode", "uint32_t", "GDDR Vendor Code.", False
    ),
    GlobalSymbol(
        0x8000315C,
        "OSBootIndicator",
        "uint8_t",
        "Indicator set by IOS/NAND Boot Program during boot process, reflects boot source.",
        False,
    ),
    GlobalSymbol(
        0x8000315D,
        "OSEnableLegacyDI",
        "uint8_t",
        "Controls legacy Drive Interface mode. True for GC apploader.",
        False,
    ),
    GlobalSymbol(
        0x8000315E,
        "OSDevkitBootProgramVersion",
        "uint16_t",
        "Devkit boot program version, written by System Menu.",
        False,
    ),
    GlobalSymbol(
        0x80003160,
        "OSInitSemaphore",
        "uint32_t",
        "Initialization semaphore for main() function.",
        False,
    ),
    GlobalSymbol(
        0x80003164,
        "OSGCModeFlag",
        "uint32_t",
        "GameCube (MIOS) mode flag. Set by boot2 on MIOS shutdown, read by System Menu.",
        False,
    ),
    GlobalSymbol(
        0x80003180,
        "OSWC24GameID",
        "char[4]",
        "Game ID for WC24 mode. Must match GameID at 0x80000000 for WC24 to be enabled.",
        False,
    ),
    GlobalSymbol(
        0x80003184,
        "OSApplicationType",
        "uint8_t",
        "Application type (0x80 for disc, 0x81 for channel).",
        False,
    ),
    GlobalSymbol(
        0x80003186,
        "OSApplicationType2",
        "uint8_t",
        "Secondary application type, indicating context for mixed disc/channel operations.",
        False,
    ),
    GlobalSymbol(
        0x80003188,
        "OSMinimumIOSVersion",
        "uint32_t",
        "Minimum IOS version required (major/title version).",
        False,
    ),
    GlobalSymbol(
        0x8000318C,
        "OSTitleLaunchCode",
        "uint32_t",
        "Launch Code for title booted from NAND.",
        False,
    ),
    GlobalSymbol(
        0x80003190,
        "OSTitleReturnCode",
        "uint32_t",
        "Return Code for title booted from NAND.",
        False,
    ),
    GlobalSymbol(
        0x80003194,
        "OSDataPartitionType",
        "uint32_t",
        "Data partition type from disc, copied by System Menu.",
        False,
    ),
    GlobalSymbol(
        0x80003198,
        "OSDataPartitionOffset",
        "uint32_t",
        "Data partition offset from disc, copied by System Menu.",
        False,
    ),
    GlobalSymbol(
        0x8000319C,
        "OSDiscLayerFlag",
        "uint8_t",
        "Indicates disc layer type (single/dual), set by apploader. Affects out-of-bounds read behavior.",
        False,
    ),
    GlobalSymbol(
        0x80003400,
        "OSBS1BootCodeAreaStart",
        None,
        'Start of "BS1" boot code area.',
        False,
    ),
    GlobalSymbol(
        0x80003F00,
        "OSAppExecutableAreaStart",
        None,
        "Start of standard application executable area.",
        False,
    ),
    GlobalSymbol(
        0x81330000,
        "OSLoaderExecutableAreaStart",
        None,
        "Start of loader executable area. Also used by NAND Boot Program.",
        False,
    ),
]
