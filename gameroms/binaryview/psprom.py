import struct
import traceback
from typing import Optional, Dict, Tuple, List
from dataclasses import dataclass

# import necessary binary ninja types
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

# --- elf constants ---
# elf header structure format (32-bit little-endian)
# e_ident[16], e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
# e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
ELF_HEADER_FORMAT = "<16sHHIIIIIHHHHHH"  # 16s + 2H + 5I + 6H = 14 fields
ELF_HEADER_SIZE = struct.calcsize(ELF_HEADER_FORMAT)
# e_ident indices
EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3 = 0, 1, 2, 3  # magic number bytes (\x7felf)
EI_CLASS = 4  # file class (32/64 bit)
EI_DATA = 5  # data encoding (little/big endian)
EI_VERSION = 6  # elf version
# e_ident values
ELFCLASS32 = 1  # 32-bit objects
ELFDATA2LSB = 1  # little-endian
# e_type values
ET_EXEC = 2  # executable file type
# e_machine values
EM_MIPS = 8  # mips architecture

# program header structure format (32-bit)
# p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
P_HEADER_FORMAT = "<IIIIIIII"
P_HEADER_SIZE = struct.calcsize(P_HEADER_FORMAT)
# p_type values
PT_LOAD = 1  # loadable segment type
# p_flags values
PF_X = 1  # execute permission
PF_W = 2  # write permission
PF_R = 4  # read permission

# section header structure format (32-bit)
# sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize
S_HEADER_FORMAT = "<IIIIIIIIII"
S_HEADER_SIZE = struct.calcsize(S_HEADER_FORMAT)
# sh_type values
SHT_NULL = 0  # Section header table entry unused
SHT_PROGBITS = 1  # Program data
SHT_SYMTAB = 2  # Symbol table
SHT_STRTAB = 3  # String table
SHT_RELA = 4  # Relocation entries with addends
SHT_HASH = 5  # Symbol hash table
SHT_DYNAMIC = 6  # Dynamic linking information
SHT_NOTE = 7  # Notes
SHT_NOBITS = 8  # Program space with no data (bss)
SHT_REL = 9  # Relocation entries, no addends
SHT_SHLIB = 10  # Reserved
SHT_DYNSYM = 11  # Dynamic linker symbol table
# sh_flags values
SHF_WRITE = 0x1  # Writable
SHF_ALLOC = 0x2  # Occupies memory during execution
SHF_EXECINSTR = 0x4  # Executable


# --- dataclasses for elf structures ---
@dataclass
class ELFHeader32:
    """Represents the parsed 32-bit ELF header."""

    e_ident: bytes = b"\x00" * 16
    e_type: int = 0
    e_machine: int = 0
    e_version: int = 0
    e_entry: int = 0
    e_phoff: int = 0
    e_shoff: int = 0
    e_flags: int = 0
    e_ehsize: int = 0
    e_phentsize: int = 0
    e_phnum: int = 0
    e_shentsize: int = 0
    e_shnum: int = 0
    e_shstrndx: int = 0


@dataclass
class ProgramHeader32:
    """Represents a parsed 32-bit Program Header entry."""

    p_type: int = 0
    p_offset: int = 0
    p_vaddr: int = 0
    p_paddr: int = 0
    p_filesz: int = 0
    p_memsz: int = 0
    p_flags: int = 0
    p_align: int = 0


# --- psp hardware definitions ---

# dictionary mapping tag type names (proper case) to icons
# used by _get_or_create_tag_type and _define_reg_with_tag
PSP_TAG_TYPES: Dict[str, str] = {
    "Memory Region": "🗺️",
    "Memory Management": "🧠",
    "System Control": "⚙️",
    "Interrupts": "⚡",
    "Profiler": "⏱️",
    "VME": "🎬",  # Virtual Mobile Engine
    "NAND Flash": "💾",
    "Graphics Engine": "🖼️",
    "KIRK Crypto": "🔒",
    "LCD Controller": "🖥️",
    "GPIO": "💡",
    "UART": "↔️",
    "Audio": "🔊",
    "DMA": "➡️",
    "Timers": "⏱️",
    "USB": "🔌",
    "Memory Stick": "💾",
    "WLAN": "📡",
    "Power": "🔋",
    "I2C": "⛓️",
    "SPI": "〰️",
    "ATA": "💿",
    "Hardware Register": "🔩",  # Generic fallback
}

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

# --- pspview class definition ---


class PSPView(BinaryView):
    """
    BinaryView class for loading and analyzing PSP ELF executables.
    """

    name = "PSPELF"  # Changed name slightly to avoid potential conflicts if "PSP" is used elsewhere
    long_name = "PlayStation Portable ELF"

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
        initializes the PSPView instance. minimal setup here.
        args:
            data: the BinaryView object containing the raw psp elf data.
        """
        # --- setup platform and architecture first ---
        # lookup needs to happen before calling the base class init,
        # but we store them in local variables first.
        # psp uses a mips iii-based allegrex cpu (32-bit little-endian).
        local_arch = None
        local_platform = None
        try:
            # prioritize 'mipsel32' since psp is little-endian and it's listed in user's arch list.
            log_info("[PSP] attempting to get architecture 'mipsel32'...")
            local_arch = Architecture["mipsel32"]
            log_info(
                f"[PSP] found architecture: {local_arch.name}. getting standalone platform..."
            )
            local_platform = local_arch.standalone_platform
            if local_platform is None:
                log_warn(
                    f"[PSP] architecture '{local_arch.name}' found, but no standalone platform associated. trying 'mips32'..."
                )
                # fall through to try 'mips32' if 'mipsel32' platform is missing
                local_arch = None  # reset arch so we try mips32 next

        except KeyError:
            log_warn("[PSP] architecture 'mipsel32' not found. trying 'mips32'...")
            # fall through to try 'mips32'

        # if 'mipsel32' wasn't found or had no platform, try 'mips32' as a fallback.
        if local_arch is None:
            try:
                log_info("[PSP] attempting to get architecture 'mips32'...")
                local_arch = Architecture["mips32"]
                log_info(
                    f"[PSP] found architecture: {local_arch.name}. getting standalone platform..."
                )
                local_platform = local_arch.standalone_platform
                if local_platform is None:
                    log_error(
                        f"[PSP] critical: architecture '{local_arch.name}' found, but no standalone platform associated."
                    )
                    # cannot proceed without a platform. raise exception to prevent partial initialization.
                    raise RuntimeError("failed to find a valid mips platform.")

            except KeyError:
                log_error(
                    "[PSP] critical: neither 'mipsel32' nor 'mips32' architecture found in this binary ninja version."
                )
                # cannot proceed without a mips architecture. raise exception.
                raise RuntimeError("mips architecture not found.")

        # if we reach here, we should have a valid arch and platform
        log_info(
            f"[PSP] using platform: {local_platform.name}, architecture: {local_arch.name}"
        )

        # --- initialize the base binaryview ---
        # this *must* be called and succeed before setting any instance attributes.
        try:
            BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        except Exception as base_init_err:
            log_error(
                f"[PSP] critical error during BinaryView base initialization: {base_init_err}"
            )
            # if base init fails, the object is likely unusable. re-raise.
            raise

        # --- initialize instance variables *after* successful base init ---
        self.platform = local_platform
        self.arch = local_arch
        self.raw: BinaryView = (
            data  # keep a reference to the raw data view for reading segment data.
        )
        self.log: Logger = self.create_logger("PSP")  # use "PSP" logger name.
        self._created_tag_types: Dict[str, TagType] = {}  # cache for created TagTypes.
        self.elf_header: Optional[ELFHeader32] = None  # store parsed elf header

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        checks if the provided data is likely a valid psp elf file.
        this is called by binary ninja to determine if this view should be used.
        args:
            data: the BinaryView object containing the data.
        returns:
            true if the data is likely a psp elf, false otherwise.
        """
        # check minimum size for an elf header.
        if data.length < ELF_HEADER_SIZE:
            log_warn(
                f"[PSP] validation failed: file size {data.length} is smaller than elf header size {ELF_HEADER_SIZE}."
            )
            return False

        try:
            # read the elf header bytes.
            header_bytes = data.read(0, ELF_HEADER_SIZE)
            if len(header_bytes) < ELF_HEADER_SIZE:
                log_warn("[PSP] validation failed: could not read full elf header.")
                return False

            # unpack the identification bytes (e_ident).
            ident = struct.unpack_from(
                "<16B", header_bytes, 0
            )  # read e_ident as 16 bytes.

            # check elf magic number: 0x7f 'e' 'l' 'f'.
            if not (
                ident[EI_MAG0] == 0x7F
                and ident[EI_MAG1] == ord("E")
                and ident[EI_MAG2] == ord("L")
                and ident[EI_MAG3] == ord("F")
            ):
                log_warn("[PSP] validation failed: invalid elf magic number.")
                return False

            # check for 32-bit class.
            if ident[EI_CLASS] != ELFCLASS32:
                log_warn(
                    f"[PSP] validation failed: incorrect elf class ({ident[EI_CLASS]}, expected {ELFCLASS32})."
                )
                return False

            # check for little-endian data encoding.
            if ident[EI_DATA] != ELFDATA2LSB:
                log_warn(
                    f"[PSP] validation failed: incorrect data encoding ({ident[EI_DATA]}, expected {ELFDATA2LSB})."
                )
                return False

            # unpack the rest of the header to check machine type using the *corrected* format.
            _, _, e_machine, _, _, _, _, _, _, _, _, _, _, _ = struct.unpack(
                ELF_HEADER_FORMAT, header_bytes
            )

            # check for mips architecture.
            if e_machine != EM_MIPS:
                log_warn(
                    f"[PSP] validation failed: incorrect machine type ({e_machine}, expected {EM_MIPS})."
                )
                return False

            # if all checks pass, it's likely a valid psp elf.
            log_info(
                "[PSP] validation successful: file appears to be a valid mips32 little-endian elf."
            )
            return True

        except (struct.error, IndexError) as unpack_err:
            # handle potential errors during unpacking or reading header bytes.
            log_error(
                f"[PSP] error during elf header validation (unpacking/indexing): {unpack_err}\n{traceback.format_exc()}"
            )
            return False
        except Exception as e:
            # catch any other unexpected errors during validation.
            log_error(
                f"[PSP] unexpected error during validation: {e}\n{traceback.format_exc()}"
            )
            return False

    # --- helper methods ---

    def _parse_elf_header(self) -> bool:
        """
        parses the elf header from the raw data and stores it in self.elf_header.
        returns true on success, false on failure.
        """
        self.log.log_info("parsing elf header...")
        if self.raw.length < ELF_HEADER_SIZE:
            self.log.log_error("file is too small for elf header.")
            return False

        header_bytes = self.raw.read(0, ELF_HEADER_SIZE)
        if len(header_bytes) < ELF_HEADER_SIZE:
            self.log.log_error("could not read full elf header.")
            return False

        try:
            header_values = struct.unpack(ELF_HEADER_FORMAT, header_bytes)
            self.elf_header = ELFHeader32(
                *header_values
            )  # unpack values into dataclass fields
            # log key fields after successful parsing
            self.log.log_info(f"elf entry point: 0x{self.elf_header.e_entry:08x}")
            self.log.log_info(
                f"program header offset: 0x{self.elf_header.e_phoff:x}, count: {self.elf_header.e_phnum}, entry size: {self.elf_header.e_phentsize}"
            )
            self.log.log_info(
                f"section header offset: 0x{self.elf_header.e_shoff:x}, count: {self.elf_header.e_shnum}, entry size: {self.elf_header.e_shentsize}, strtab index: {self.elf_header.e_shstrndx}"
            )
            return True
        except struct.error as unpack_err:
            self.log.log_error(f"failed to unpack elf header: {unpack_err}")
            self.log.log_error(
                f"elf header format string used: '{ELF_HEADER_FORMAT}' ({struct.calcsize(ELF_HEADER_FORMAT)} bytes)"
            )
            self.elf_header = None  # ensure it's None on failure
            return False
        except Exception as e:
            self.log.log_error(f"unexpected error parsing elf header: {e}")
            self.elf_header = None
            return False

    def _define_tag_types(self):
        """
        defines and caches all necessary tag types used by this view.
        iterates through the global PSP_TAG_TYPES dictionary.
        """
        self.log.log_info("defining psp hardware tag types...")
        for name, icon in PSP_TAG_TYPES.items():
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
            name: the name of the register (symbol name, e.g., "SYSCON_RAMSIZE").
            tag_type_name: the name of the tag type to apply (e.g., "System Control").
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
        """maps the core psp hardware memory regions (ram, vram, io, etc.)."""
        self.log.log_info("mapping core psp hardware memory regions...")

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

        # sc cpu scratchpad (16kb) - fast internal ram.
        add_memory_region(0x00010000, 0x4000, self.RWX_FLAGS, "SC CPU Scratchpad")

        # vram / edram (8mb) - video ram. usually rw.
        add_memory_region(0x04000000, 0x800000, self.RW_FLAGS, "VRAM / EDRAM")

        # main ram (assume 32mb for psp-1000 default).
        # TODO: potentially read SYSCON_RAMSIZE (0x1C100040) to determine size dynamically?
        main_ram_base = 0x08000000
        main_ram_size = 0x02000000  # 32mb default
        add_memory_region(
            main_ram_base,
            main_ram_size,
            self.RWX_FLAGS,
            f"Main RAM ({main_ram_size // (1024*1024)}MB)",
        )

        # i/o ports - map the main known blocks as rw segments. tag as hardware registers.
        add_memory_region(
            0x1C000000,
            0x01000000,
            self.RW_FLAGS,
            "I/O Ports Block 1",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )  # 16mb (covers 1cxxxxxx)
        add_memory_region(
            0x1D000000,
            0x02000000,
            self.RW_FLAGS,
            "I/O Ports Block 2",
            tag_name="Hardware Register",
            tag_icon="🔩",
        )  # 32mb (covers 1dxxxxxx, 1exxxxxx)
        add_memory_region(
            0x1FF00000,
            0x00000A00,
            self.RW_FLAGS,
            "NAND DMA IO Buffers",
            tag_name="NAND Flash",
            tag_icon="💾",
        )  # ~2.5kb

        # shared ram (2mb) - contains exception vectors.
        add_memory_region(0x1FC00000, 0x200000, self.RWX_FLAGS, "Shared RAM")

        # boot rom (16kb standard mips size) - mapped via kseg1 uncached alias.
        boot_rom_base = 0xBFC00000  # kseg1 virtual address for physical 0x1fc00000
        boot_rom_size = 0x4000  # 16kb
        # map as zero-filled rx segment at the virtual address.
        add_memory_region(
            boot_rom_base, boot_rom_size, self.RX_FLAGS, "Boot ROM (Virtual Alias)"
        )
        # define common mips boot vectors (relative to boot_rom_base). use proper case for symbol names.
        self.define_auto_symbol(
            Symbol(SymbolType.DataSymbol, boot_rom_base + 0x000, "Reset_Vector")
        )
        self.define_auto_symbol(
            Symbol(
                SymbolType.DataSymbol,
                boot_rom_base + 0x100,
                "TLB_Refill_Vector_BEV0",
            )
        )  # utlb miss
        self.define_auto_symbol(
            Symbol(
                SymbolType.DataSymbol,
                boot_rom_base + 0x180,
                "Cache_Error_Vector_BEV0",
            )
        )  # cache error / xtlb miss
        self.define_auto_symbol(
            Symbol(
                SymbolType.DataSymbol,
                boot_rom_base + 0x200,
                "General_Exception_Vector_BEV0",
            )
        )

    def _map_elf_segments(self):
        """
        maps the loadable program segments from the elf header using virtual addresses.
        relies on self.elf_header being populated.
        """
        if not self.elf_header:
            self.log.log_error("cannot map elf segments, elf header not parsed.")
            return

        e_phoff = self.elf_header.e_phoff
        e_phnum = self.elf_header.e_phnum
        e_phentsize = self.elf_header.e_phentsize

        program_headers_exist = e_phoff > 0 and e_phnum > 0
        self.log.log_info(f"mapping elf program segments (if any)...")

        if not program_headers_exist:
            self.log.log_info("no program headers found in elf file to map.")
            return

        # validate header info again before looping
        if e_phoff + e_phnum * e_phentsize > self.raw.length:
            self.log.log_error(
                f"program headers exceed file size. cannot map segments."
            )
            return
        if e_phentsize != P_HEADER_SIZE:
            self.log.log_error(
                f"unexpected program header entry size. cannot map segments."
            )
            return

        for i in range(e_phnum):
            ph_offset_in_file = e_phoff + i * e_phentsize
            ph_bytes = self.raw.read(ph_offset_in_file, P_HEADER_SIZE)
            if len(ph_bytes) < P_HEADER_SIZE:
                self.log.log_error(
                    f"could not read full program header {i} at offset 0x{ph_offset_in_file:x}."
                )
                continue

            try:
                ph = ProgramHeader32(*struct.unpack(P_HEADER_FORMAT, ph_bytes))
            except struct.error as unpack_err:
                self.log.log_error(f"failed to unpack program header {i}: {unpack_err}")
                continue

            if ph.p_type == PT_LOAD:
                # --- use virtual address (p_vaddr) for mapping ---
                map_addr = ph.p_vaddr
                map_size = ph.p_memsz
                file_offset = ph.p_offset
                file_len = ph.p_filesz

                # validate segment parameters.
                if map_size == 0:
                    self.log.log_warn(
                        f"skipping pt_load segment {i} at 0x{map_addr:08x} with zero memory size."
                    )
                    continue
                if file_len > map_size:
                    self.log.log_warn(
                        f"pt_load segment {i} file size (0x{file_len:x}) > memory size (0x{map_size:x}). clamping file length."
                    )
                    file_len = map_size
                if file_offset + file_len > self.raw.length:
                    self.log.log_error(
                        f"pt_load segment {i} data (offset=0x{file_offset:x}, len=0x{file_len:x}) exceeds file bounds (len={self.raw.length}). skipping segment."
                    )
                    continue

                # determine segment permissions from elf flags
                segment_flags_value = 0  # use integer for accumulation
                perm_str = ""
                if ph.p_flags & PF_R:
                    segment_flags_value |= SegmentFlag.SegmentReadable
                    perm_str += "r"
                else:
                    perm_str += "-"
                if ph.p_flags & PF_W:
                    segment_flags_value |= SegmentFlag.SegmentWritable
                    perm_str += "w"
                else:
                    perm_str += "-"
                if ph.p_flags & PF_X:
                    segment_flags_value |= SegmentFlag.SegmentExecutable
                    perm_str += "x"
                else:
                    perm_str += "-"

                self.log.log_info(
                    f"  mapping segment {i}: vaddr=0x{map_addr:08x}, memsize=0x{map_size:x}, "  # Log vaddr
                    f"fileoffset=0x{file_offset:x}, filesize=0x{file_len:x}, flags={perm_str}"
                )

                # add the segment using the virtual address
                self.add_auto_segment(
                    map_addr, map_size, file_offset, file_len, segment_flags_value
                )
                self.set_comment_at(map_addr, f"ELF Segment {i} (LOAD)")

                # add comment for bss section if it exists.
                if map_size > file_len:
                    bss_start = map_addr + file_len
                    bss_size = map_size - file_len
                    if bss_start < map_addr + map_size:
                        self.set_comment_at(
                            bss_start,
                            f"ELF Segment {i} BSS Start (Size: 0x{bss_size:x})",
                        )
            else:
                self.log.log_info(
                    f"  skipping segment {i}: type=0x{ph.p_type:x} (not pt_load)"
                )

    def _map_elf_sections(self):
        """
        parses the elf section header table and defines sections in binary ninja.
        relies on self.elf_header being populated.
        """
        if not self.elf_header:
            self.log.log_error("cannot map elf sections, elf header not parsed.")
            return

        # extract necessary info from stored header
        e_shoff = self.elf_header.e_shoff
        e_shnum = self.elf_header.e_shnum
        e_shentsize = self.elf_header.e_shentsize
        e_shstrndx = self.elf_header.e_shstrndx

        self.log.log_info("mapping elf sections...")
        if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
            self.log.log_warn(
                "elf section header table information missing or invalid. skipping section mapping."
            )
            return

        if e_shentsize != S_HEADER_SIZE:
            self.log.log_error(
                f"unexpected section header entry size: {e_shentsize} (expected {S_HEADER_SIZE}). skipping section mapping."
            )
            return

        if e_shstrndx >= e_shnum:
            self.log.log_error(
                f"invalid section header string table index: {e_shstrndx} (>= number of sections {e_shnum}). skipping section mapping."
            )
            return

        # read the section header for the string table first
        strtab_hdr_offset = e_shoff + e_shstrndx * e_shentsize
        if strtab_hdr_offset + S_HEADER_SIZE > self.raw.length:
            self.log.log_error(
                f"section header string table header offset out of bounds. skipping section mapping."
            )
            return
        strtab_hdr_bytes = self.raw.read(strtab_hdr_offset, S_HEADER_SIZE)
        if len(strtab_hdr_bytes) < S_HEADER_SIZE:
            self.log.log_error(
                f"could not read section header string table header. skipping section mapping."
            )
            return

        try:
            (
                sh_name_idx,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            ) = struct.unpack(S_HEADER_FORMAT, strtab_hdr_bytes)
        except struct.error as unpack_err:
            self.log.log_error(
                f"failed to unpack section header string table header: {unpack_err}. skipping section mapping."
            )
            return

        section_names_data = b""  # initialize empty
        if sh_type != SHT_STRTAB:
            self.log.log_warn(
                f"section header string table index {e_shstrndx} does not point to a SHT_STRTAB section (type={sh_type}). section names will be unavailable."
            )
        elif sh_offset + sh_size > self.raw.length:
            self.log.log_error(
                f"section header string table data (offset=0x{sh_offset:x}, size=0x{sh_size:x}) out of bounds. section names will be unavailable."
            )
        else:
            section_names_data = self.raw.read(sh_offset, sh_size)
            if len(section_names_data) < sh_size:
                self.log.log_warn(
                    f"could not read full section header string table data. section names may be incomplete."
                )

        # function to get name from string table data
        def get_section_name(index: int) -> str:
            if not section_names_data or index >= len(section_names_data):
                return f"section_{index}"  # fallback name
            try:
                # find the null terminator
                null_pos = section_names_data.find(b"\x00", index)
                if null_pos == -1:
                    null_pos = len(
                        section_names_data
                    )  # handle case where name is at the end without null
                return section_names_data[index:null_pos].decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                return f"section_{index}_decode_error"

        # iterate through all section headers
        for i in range(e_shnum):
            # skip null section header
            if i == 0:
                continue
            # skip the string table section itself if we already processed it
            if i == e_shstrndx and section_names_data:
                continue

            sh_offset_in_file = e_shoff + i * e_shentsize
            # bounds check already done for the whole table
            sh_bytes = self.raw.read(sh_offset_in_file, S_HEADER_SIZE)
            if len(sh_bytes) < S_HEADER_SIZE:
                self.log.log_error(
                    f"could not read full section header {i} at offset 0x{sh_offset_in_file:x}."
                )
                continue

            try:
                (
                    sh_name_idx,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    sh_info,
                    sh_addralign,
                    sh_entsize,
                ) = struct.unpack(S_HEADER_FORMAT, sh_bytes)
            except struct.error as unpack_err:
                self.log.log_error(f"failed to unpack section header {i}: {unpack_err}")
                continue

            # skip sections that are not allocated in memory (unless they are NOBITS/BSS)
            # also skip sections with zero size, as they cannot be added
            if (not (sh_flags & SHF_ALLOC) and sh_type != SHT_NOBITS) or sh_size == 0:
                continue

            section_name = get_section_name(sh_name_idx)
            section_semantics = SectionSemantics.DefaultSectionSemantics
            section_type_str = ""  # binja uses this for format-specific types

            # determine semantics based on flags and type
            is_code = bool(sh_flags & SHF_EXECINSTR)
            is_write = bool(sh_flags & SHF_WRITE)
            is_alloc = bool(sh_flags & SHF_ALLOC)
            is_bss = sh_type == SHT_NOBITS
            is_data = (
                is_alloc and not is_code
            )  # Simplification: allocated and not code is data

            if is_code:
                # explicitly set ReadOnlyCode for executable sections
                section_semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
                section_type_str = "Code"
            elif is_bss:
                # bss is read-write data
                section_semantics = SectionSemantics.ReadWriteDataSectionSemantics
                section_type_str = "BSS"
            elif is_data:
                if is_write:
                    # writable data
                    section_semantics = SectionSemantics.ReadWriteDataSectionSemantics
                    section_type_str = "Data"
                else:
                    # read-only data
                    section_semantics = SectionSemantics.ReadOnlyDataSectionSemantics
                    section_type_str = "ReadOnlyData"  # e.g., .rodata
            # could add checks for SHT_NOTE, SHT_SYMTAB etc. if needed

            # log the determined semantics
            self.log.log_info(
                f"  adding section '{section_name}': addr=0x{sh_addr:08x}, size=0x{sh_size:x}, type={sh_type}, flags=0x{sh_flags:x}, semantics={section_semantics.name}"
            )
            # add extra log if a common code section name doesn't have expected semantics
            if (
                section_name.startswith(".text")
                and section_semantics != SectionSemantics.ReadOnlyCodeSectionSemantics
            ):
                self.log.log_warn(
                    f"section '{section_name}' does not have ReadOnlyCodeSectionSemantics despite its name."
                )

            # add the section using add_auto_section
            # note: align, entry_size, linked_section, info_section, info_data are directly from header
            try:
                self.add_auto_section(
                    name=section_name,
                    start=sh_addr,
                    length=sh_size,
                    semantics=section_semantics,
                    type=section_type_str,
                    align=(
                        int(sh_addralign) if sh_addralign > 0 else 1
                    ),  # ensure align is at least 1
                    entry_size=int(sh_entsize),  # ensure integer
                    linked_section=str(sh_link),  # ensure string
                    info_section=str(sh_info),  # ensure string
                    # info_data seems less common, maybe skip or use sh_info if appropriate?
                )
            except Exception as sec_err:
                # log specific error if adding section fails
                self.log.log_error(
                    f"failed to add section '{section_name}' at 0x{sh_addr:x}: {sec_err}"
                )

    def _define_io_registers(self):
        """defines symbols and tags for known psp i/o registers."""
        self.log.log_info("defining psp i/o registers...")
        for addr, name, tag_name, desc in PSP_IO_REGISTERS:
            # get the icon for the tag type, providing a default if needed
            icon = PSP_TAG_TYPES.get(tag_name, "🔩")  # default to generic hardware icon
            self._define_reg_with_tag(addr, name, tag_name, icon, desc)

    def _define_entry_point(self):
        """
        defines the entry point symbol and function based on the parsed elf header.
        relies on self.elf_header being populated.
        """
        if not self.elf_header:
            self.log.log_error("cannot define entry point, elf header not parsed.")
            return

        entry_point = self.elf_header.e_entry
        self.log.log_info(f"adding entry point at 0x{entry_point:08x}")

        # validate entry point address before adding.
        # check if it falls within a mapped segment (elf segment or hardware region).
        segment_at_entry = self.get_segment_at(entry_point)
        if segment_at_entry:
            self.log.log_info(
                f"entry point 0x{entry_point:08x} is within segment starting at 0x{segment_at_entry.start:08x}."
            )
            # check if the segment is executable.
            if segment_at_entry.executable:
                # use the api to add the entry point.
                self.add_entry_point(entry_point)
                # use proper case for standard symbol name
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, entry_point, "_start")
                )
                # attempt to define a function at the entry point for analysis.
                try:
                    self.add_function(entry_point)
                except Exception as func_err:
                    # log warning if function definition fails.
                    self.log.log_warn(
                        f"could not define function at entry point 0x{entry_point:08x}: {func_err}"
                    )
            else:
                self.log.log_warn(
                    f"entry point 0x{entry_point:08x} is in a non-executable segment. defining data symbol instead."
                )
                self.define_auto_symbol(
                    Symbol(SymbolType.DataSymbol, entry_point, "_entry_point_data")
                )
        else:
            self.log.log_error(
                f"entry point 0x{entry_point:08x} is not within any mapped segment. cannot set entry point or define symbol."
            )

    # --- main initialization logic ---

    def init(self) -> bool:
        """
        initializes the PSPView by parsing the elf header, mapping memory segments
        (hardware regions and elf segments), defining sections, and defining core symbols/tags.
        this is called by binary ninja after __init__ completes.
        returns:
            true on successful initialization, false otherwise.
        """
        # platform/arch should be valid here if __init__ succeeded.

        try:
            self.log.log_info("starting psp elf loading process...")

            # --- main loading steps ---
            if not self._parse_elf_header():
                return False
            self._define_tag_types()
            self._map_memory_regions()
            self._map_elf_segments()
            self._map_elf_sections()
            self._define_io_registers()
            self._define_entry_point()

            # --- final analysis update ---
            self.log.log_info("psp elf loading complete. updating analysis...")
            # it's often better to let the user trigger the initial analysis,
            # but for loaders, triggering it can be helpful to resolve symbols etc.
            self.update_analysis_and_wait()
            self.log.log_info("analysis update finished.")

            return True  # initialization successful

        except Exception as e:
            # catch any unexpected errors during initialization
            log_error(f"[PSP] failed to initialize pspview: {e}")
            log_error(traceback.format_exc())
            return False  # indicate failure

    # --- required binaryview methods ---

    def perform_is_executable(self) -> bool:
        """psp elfs are typically executable"""
        return True

    def perform_get_entry_point(self) -> int:
        """returns the entry point address read from the elf header"""
        # this is called by the core *after* init() completes.
        # the core knows the entry point because we called self.add_entry_point()
        # return the first entry point added, or fallback to header value / start.
        if len(self.entry_points) > 0:
            return self.entry_points[0]
        elif self.elf_header:
            return self.elf_header.e_entry
        else:
            # this case should ideally not happen if init succeeded
            log_warn(
                "[PSP] perform_get_entry_point called but no entry points defined and header not parsed. returning start address."
            )
            return self.start

    def perform_get_address_size(self) -> int:
        """psp uses 32-bit addresses"""
        return 4  # mips32


PSPView.register()
