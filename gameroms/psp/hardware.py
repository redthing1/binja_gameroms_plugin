"""
PSP hardware definitions including memory layout, I/O registers, and hardware constants.
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass

# Import the I/O register definitions from the existing defs module
from .defs import PSP_IO_REGISTERS

# ELF Constants for PSP
ELF_HEADER_FORMAT = "<16sHHIIIIIHHHHHH"  # '<' for little-endian
ELF_HEADER_SIZE = 52  # struct.calcsize(ELF_HEADER_FORMAT)

# ELF identification array indices
EI_MAG0 = 0  # magic number byte 0: 0x7f
EI_MAG1 = 1  # magic number byte 1: 'E'
EI_MAG2 = 2  # magic number byte 2: 'L'
EI_MAG3 = 3  # magic number byte 3: 'F'
EI_CLASS = 4  # file class (e.g., 32-bit or 64-bit)
EI_DATA = 5  # data encoding (e.g., little or big endian)
EI_VERSION = 6  # elf version (should be EV_CURRENT, which is 1)

# ELF identification values relevant for PSP ELF files
ELFCLASS32 = 1  # indicates a 32-bit object file
ELFDATA2LSB = 1  # indicates little-endian data encoding

# ELF file types
ET_EXEC = 2  # indicates an executable file

# ELF machine types
EM_MIPS = 8  # indicates mips architecture

# Program header structure format and constants
P_HEADER_FORMAT = "<IIIIIIII"
P_HEADER_SIZE = 32  # struct.calcsize(P_HEADER_FORMAT)

# Program header types
PT_LOAD = 1  # indicates a loadable segment

# Program header flags
PF_X = 1  # execute permission
PF_W = 2  # write permission
PF_R = 4  # read permission

# Section header structure format and constants
S_HEADER_FORMAT = "<IIIIIIIIII"
S_HEADER_SIZE = 40  # struct.calcsize(S_HEADER_FORMAT)

# Section header types
SHT_NULL = 0  # section header table entry unused
SHT_PROGBITS = 1  # program data
SHT_SYMTAB = 2  # symbol table
SHT_STRTAB = 3  # string table
SHT_RELA = 4  # relocation entries with addends
SHT_HASH = 5  # symbol hash table
SHT_DYNAMIC = 6  # dynamic linking information
SHT_NOTE = 7  # notes section
SHT_NOBITS = 8  # program space with no data in the file (e.g., .bss section)
SHT_REL = 9  # relocation entries, no addends
SHT_SHLIB = 10  # reserved, unspecified semantics
SHT_DYNSYM = 11  # dynamic linker symbol table

# Section header flags
SHF_WRITE = 0x1  # section is writable during execution
SHF_ALLOC = 0x2  # section occupies memory during execution
SHF_EXECINSTR = 0x4  # section contains executable machine instructions


@dataclass
class ELFHeader32:
    """Represents parsed 32-bit ELF header fields."""
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
    """Represents a parsed 32-bit ELF Program Header entry."""
    p_type: int = 0
    p_offset: int = 0
    p_vaddr: int = 0
    p_paddr: int = 0
    p_filesz: int = 0
    p_memsz: int = 0
    p_flags: int = 0
    p_align: int = 0


# PSP Hardware Tag Type Definitions
PSP_TAG_TYPE_DEFINITIONS: Dict[str, str] = {
    "Memory Region": "🗺️",  # for general memory segments like ram, vram, scratchpad
    "Memory Management": "🧠",  # for memory controller, tlb, cache control registers
    "System Control": "⚙️",  # for syscon (system controller), clockgen, overall power control
    "Interrupts": "⚡",  # for interrupt controller registers
    "Profiler": "⏱️",  # for hardware profiling units, if any are directly mapped
    "VME": "🎬",  # for virtual mobile engine (psp's multimedia co-processor) registers
    "NAND Flash": "💾",  # for nand flash controller and associated dma
    "Graphics Engine": "🖼️",  # for gpu (graphics processing unit) registers
    "KIRK Crypto": "🔒",  # for kirk cryptographic engine registers (security processor)
    "LCD Controller": "🖥️",  # for lcd display controller registers
    "GPIO": "💡",  # for general purpose i/o pin registers
    "UART": "↔️",  # for universal asynchronous receiver/transmitter (serial port) registers
    "Audio": "🔊",  # for audio codec and controller registers (sas core)
    "DMA": "➡️",  # for direct memory access controller registers
    "Timers": "⏱️",  # for hardware timer registers
    "USB": "🔌",  # for usb controller registers
    "Memory Stick": "💾",  # for memory stick pro duo controller registers
    "WLAN": "📡",  # for wireless lan controller registers
    "Power": "🔋",  # for specific power management registers (e.g., battery, charging)
    "I2C": "⛓️",  # for inter-integrated circuit (i2c) bus controller registers
    "SPI": "〰️",  # for serial peripheral interface (spi) bus controller registers
    "ATA": "💿",  # for ata (ide) interface, primarily for the umd drive
    "Hardware Register": "🔩",  # generic fallback icon for i/o registers not fitting other categories
}

# Re-export the I/O register definitions from defs.py
__all__ = ['PSP_TAG_TYPE_DEFINITIONS', 'PSP_IO_REGISTERS', 'ELFHeader32', 'ProgramHeader32',
           'ELF_HEADER_FORMAT', 'ELF_HEADER_SIZE', 'EI_MAG0', 'EI_MAG1', 'EI_MAG2', 'EI_MAG3', 
           'EI_CLASS', 'EI_DATA', 'EI_VERSION', 'ELFCLASS32', 'ELFDATA2LSB', 'ET_EXEC', 'EM_MIPS', 
           'P_HEADER_FORMAT', 'P_HEADER_SIZE', 'PT_LOAD', 'PF_X', 'PF_W', 'PF_R', 
           'S_HEADER_FORMAT', 'S_HEADER_SIZE', 'SHT_NULL', 'SHT_PROGBITS', 'SHT_SYMTAB', 
           'SHT_STRTAB', 'SHT_RELA', 'SHT_HASH', 'SHT_DYNAMIC', 'SHT_NOTE', 'SHT_NOBITS', 
           'SHT_REL', 'SHT_SHLIB', 'SHT_DYNSYM', 'SHF_WRITE', 'SHF_ALLOC', 'SHF_EXECINSTR']