"""
NDS hardware definitions including memory layout, I/O registers, and hardware constants.
"""

from typing import Dict, List, Tuple

# Import the I/O register definitions from the existing defs module
from .defs import NDS_IO_REGISTERS

# NDS Hardware Tag Type Definitions
NDS_TAG_TYPE_DEFINITIONS: Dict[str, str] = {
    "Display": "🖼️",  # lcd, 2d/3d engines' display aspects
    "DMA": "➡️",  # direct memory access controllers
    "Timers": "⏱️",  # hardware timers
    "Keypad": "🎮",  # button inputs
    "IPC": "↔️",  # inter-processor communication fifos
    "Gamecard": "💾",  # nds game card slot interface
    "Interrupts": "⚡",  # interrupt controller registers
    "Power": "🔋",  # power management registers
    "Memory Control": "🐏",  # main ram, wram, vram, tcm control
    "Math": "➗",  # hardware math units (divider, square root)
    "3D Engine": "🧊",  # 3d graphics rendering engine registers
    "Sound": "🔊",  # sound controller registers
    "SPI": "〰️",  # serial peripheral interface (touchscreen, firmware, power man.)
    "RTC": "🕒",  # real-time clock
    "Wifi": "📡",  # wireless communication module
    "System": "⚙️",  # general system control, bios protection, etc.
    "ARM9 Specific": "9️⃣",  # registers only accessible/relevant to arm9
    "ARM7 Specific": "7️⃣",  # registers only accessible/relevant to arm7
    "Hardcoded Addr": "📍",  # special hardcoded ram addresses (e.g., irq handlers in ram)
    "Memory Region": "🗺️",  # for mapped memory segments (ram, rom, io blocks)
    "Hardware Register": "🔩",  # generic fallback for i/o registers
}

# Nitro SDK Constants
NITRO_SDK_MODULE_PARAMS_MAGIC = b"\x21\x06\xc0\xde\xde\xc0\x06\x21"
NITRO_SDK_MODULE_PARAMS_SIZE = 36
NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET = 0x1C

# Re-export the I/O register definitions from defs.py
__all__ = ['NDS_TAG_TYPE_DEFINITIONS', 'NDS_IO_REGISTERS', 'NITRO_SDK_MODULE_PARAMS_MAGIC', 
           'NITRO_SDK_MODULE_PARAMS_SIZE', 'NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET']