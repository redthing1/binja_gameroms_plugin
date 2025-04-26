# adapted from: https://github.com/SiD3W4y/binja-toolkit/blob/master/gbarom.py
# writeup: https://sideway.re/Reverse-Engineering-alttp-GBA-ep1/

from binaryninja import *
from binaryninja.log import Logger
from binaryninja.binaryview import TagType, Tag  # Import Tag types
from typing import Optional, Dict  # For type hints
import struct
import traceback
import os
import re


class GBAView(BinaryView):
    name = "GBA"
    long_name = "GameBoy Advance"

    # segment permission flags
    RWX_FLAGS: SegmentFlag = (
        SegmentFlag.SegmentReadable
        | SegmentFlag.SegmentWritable
        | SegmentFlag.SegmentExecutable
    )
    RW_FLAGS: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    RX_FLAGS: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable

    def __init__(self, data: BinaryView):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        # Correct way to get size of the parent view (the raw file data)
        self.rom_size = self.parent_view.length
        self.platform = Architecture[
            "armv7"
        ].standalone_platform  # armv7 profile includes armv4t
        self._created_tag_types: Dict[str, TagType] = {}  # cache created tag types

    @classmethod
    def is_valid_for_data(self, data: BinaryView) -> bool:
        # check header size
        if data.length < 0xC0:
            return False

        # check nintendo logo magic byte
        magic_byte = data.read(0xB2, 1)
        if not magic_byte or magic_byte != b"\x96":
            # log_info("[GBA] Nintendo logo magic byte mismatch.") # Can be noisy
            return False

        # could add header checksum validation here if needed
        # header_checksum = data.read(0xBD, 1)[0]
        # calculated = 0
        # for i in range(0xA0, 0xBD):
        #     calculated = calculated - data.read(i, 1)[0]
        # calculated = (calculated - 0x19) & 0xFF
        # if header_checksum != calculated:
        #     log_warn("[GBA] Header checksum mismatch.")
        #     # return False # Decide if strict check is needed

        return True

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        """gets or creates a tag type, caching the result."""
        if name in self._created_tag_types:
            return self._created_tag_types[name]
        if name in self.tag_types:
            tag_type = self.tag_types[name]
            if isinstance(tag_type, list):  # handle api inconsistency
                tag_type = tag_type[0] if tag_type else None
            if tag_type:
                self._created_tag_types[name] = tag_type
                return tag_type
            else:  # should not happen if name exists
                self.log.log_error(
                    f"tag type '{name}' returned empty list unexpectedly."
                )
        # if not found, create it
        try:
            tag_type = self.create_tag_type(name, icon)
            self._created_tag_types[name] = tag_type
            return tag_type
        except Exception as e:
            self.log.log_error(f"failed to create tag type '{name}': {e}")
            return None

    def _define_reg_with_tag(
        self,
        address: int,
        name: str,
        tag_type_name: str,
        tag_type_icon: str,
        description: str = "",
    ):
        """helper to define a register symbol and apply a tag."""
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))  # type: ignore
        if description:
            self.set_comment_at(address, description)

        tag_type = self._get_or_create_tag_type(tag_type_name, tag_type_icon)
        if tag_type:
            try:
                # Use the register name as the tag data for easy identification
                self.add_tag(address, tag_type, data=name)
            except Exception as e:
                self.log.log_error(
                    f"failed to add tag '{tag_type_name}' at 0x{address:x} for {name}: {e}"
                )

    def init(self) -> bool:
        self.log = self.create_logger("GBA")
        try:
            # --- define tag types ---
            tag_types = {
                "Display": "🖼️",
                "Sound": "🔊",
                "DMA": "➡️",
                "Timers": "⏱️",
                "Serial IO": "↔️",
                "Keypad": "🎮",
                "Interrupts": "⚡",
                "System Control": "⚙️",
                "Memory Region": "🗺️",
                "Hardware Register": "🔩",  # Generic fallback
            }
            for name, icon in tag_types.items():
                self._get_or_create_tag_type(name, icon)  # Pre-create types

            # --- add gba segments based on gba_technical_data.md ---
            # bios rom (16kb)
            self.add_auto_segment(0x00000000, 0x4000, 0, 0, self.RX_FLAGS)
            self.set_comment_at(0x00000000, "BIOS System ROM (16KB)")

            # wram - on-board (slow, 256kb)
            self.add_auto_segment(0x02000000, 0x40000, 0, 0, self.RWX_FLAGS)
            self.set_comment_at(0x02000000, "WRAM - On-board Work RAM (256KB, Slow)")

            # wram - on-chip (fast, 32kb)
            self.add_auto_segment(0x03000000, 0x8000, 0, 0, self.RWX_FLAGS)
            self.set_comment_at(0x03000000, "WRAM - On-chip Work RAM (32KB, Fast)")

            # i/o registers (1kb)
            self.add_auto_segment(0x04000000, 0x0400, 0, 0, self.RW_FLAGS)
            self.set_comment_at(0x04000000, "I/O Registers")

            # palette ram (1kb)
            self.add_auto_segment(0x05000000, 0x0400, 0, 0, self.RW_FLAGS)
            self.set_comment_at(0x05000000, "BG/OBJ Palette RAM (1KB)")

            # vram (96kb)
            self.add_auto_segment(
                0x06000000, 0x18000, 0, 0, self.RW_FLAGS
            )  # Changed flags to RW
            self.set_comment_at(0x06000000, "VRAM - Video RAM (96KB)")

            # oam - obj attributes (1kb)
            self.add_auto_segment(0x07000000, 0x0400, 0, 0, self.RW_FLAGS)
            self.set_comment_at(0x07000000, "OAM - OBJ Attributes (1KB)")

            # game pak rom (up to 32mb, mapped directly from file)
            # map the first 16mb waitstate 0 region. larger roms might need more segments for waitstates 1/2
            rom_map_size = min(
                self.rom_size, 0x2000000
            )  # Map up to 32MB if ROM is that large
            self.add_auto_segment(
                0x08000000, rom_map_size, 0, rom_map_size, self.RX_FLAGS
            )
            self.set_comment_at(
                0x08000000, f"Game Pak ROM / Flash (Mapped Size: 0x{rom_map_size:X})"
            )
            # TODO: Add segments for waitstate 1 (0x0A000000) and 2 (0x0C000000) if needed, mirroring the first segment's data.

            # game pak sram (up to 64kb)
            # size is variable, map max potential size. actual size depends on cart.
            self.add_auto_segment(0x0E000000, 0x10000, 0, 0, self.RW_FLAGS)
            self.set_comment_at(0x0E000000, "Game Pak SRAM (Max 64KB)")

            # --- define io registers with tags ---
            self._define_reg_with_tag(
                0x4000000, "REG_DISPCNT", "Display", tag_types["Display"], "LCD Control"
            )
            self._define_reg_with_tag(
                0x4000004,
                "REG_DISPSTAT",
                "Display",
                tag_types["Display"],
                "General LCD Status",
            )
            self._define_reg_with_tag(
                0x4000006,
                "REG_VCOUNT",
                "Display",
                tag_types["Display"],
                "Vertical Counter",
            )
            self._define_reg_with_tag(
                0x4000008, "REG_BG0CNT", "Display", tag_types["Display"], "BG0 Control"
            )
            self._define_reg_with_tag(
                0x400000A, "REG_BG1CNT", "Display", tag_types["Display"], "BG1 Control"
            )
            self._define_reg_with_tag(
                0x400000C, "REG_BG2CNT", "Display", tag_types["Display"], "BG2 Control"
            )
            self._define_reg_with_tag(
                0x400000E, "REG_BG3CNT", "Display", tag_types["Display"], "BG3 Control"
            )
            self._define_reg_with_tag(
                0x4000010,
                "REG_BG0HOFS",
                "Display",
                tag_types["Display"],
                "BG0 X-Offset",
            )
            self._define_reg_with_tag(
                0x4000012,
                "REG_BG0VOFS",
                "Display",
                tag_types["Display"],
                "BG0 Y-Offset",
            )
            self._define_reg_with_tag(
                0x4000014,
                "REG_BG1HOFS",
                "Display",
                tag_types["Display"],
                "BG1 X-Offset",
            )
            self._define_reg_with_tag(
                0x4000016,
                "REG_BG1VOFS",
                "Display",
                tag_types["Display"],
                "BG1 Y-Offset",
            )
            self._define_reg_with_tag(
                0x4000018,
                "REG_BG2HOFS",
                "Display",
                tag_types["Display"],
                "BG2 X-Offset",
            )
            self._define_reg_with_tag(
                0x400001A,
                "REG_BG2VOFS",
                "Display",
                tag_types["Display"],
                "BG2 Y-Offset",
            )
            self._define_reg_with_tag(
                0x400001C,
                "REG_BG3HOFS",
                "Display",
                tag_types["Display"],
                "BG3 X-Offset",
            )
            self._define_reg_with_tag(
                0x400001E,
                "REG_BG3VOFS",
                "Display",
                tag_types["Display"],
                "BG3 Y-Offset",
            )
            self._define_reg_with_tag(
                0x4000020,
                "REG_BG2PA",
                "Display",
                tag_types["Display"],
                "BG2 Rot/Scale A (dx)",
            )
            self._define_reg_with_tag(
                0x4000022,
                "REG_BG2PB",
                "Display",
                tag_types["Display"],
                "BG2 Rot/Scale B (dmx)",
            )
            self._define_reg_with_tag(
                0x4000024,
                "REG_BG2PC",
                "Display",
                tag_types["Display"],
                "BG2 Rot/Scale C (dy)",
            )
            self._define_reg_with_tag(
                0x4000026,
                "REG_BG2PD",
                "Display",
                tag_types["Display"],
                "BG2 Rot/Scale D (dmy)",
            )
            self._define_reg_with_tag(
                0x4000028,
                "REG_BG2X",
                "Display",
                tag_types["Display"],
                "BG2 Ref Point X",
            )
            self._define_reg_with_tag(
                0x400002C,
                "REG_BG2Y",
                "Display",
                tag_types["Display"],
                "BG2 Ref Point Y",
            )
            self._define_reg_with_tag(
                0x4000030,
                "REG_BG3PA",
                "Display",
                tag_types["Display"],
                "BG3 Rot/Scale A (dx)",
            )
            self._define_reg_with_tag(
                0x4000032,
                "REG_BG3PB",
                "Display",
                tag_types["Display"],
                "BG3 Rot/Scale B (dmx)",
            )
            self._define_reg_with_tag(
                0x4000034,
                "REG_BG3PC",
                "Display",
                tag_types["Display"],
                "BG3 Rot/Scale C (dy)",
            )
            self._define_reg_with_tag(
                0x4000036,
                "REG_BG3PD",
                "Display",
                tag_types["Display"],
                "BG3 Rot/Scale D (dmy)",
            )
            self._define_reg_with_tag(
                0x4000038,
                "REG_BG3X",
                "Display",
                tag_types["Display"],
                "BG3 Ref Point X",
            )
            self._define_reg_with_tag(
                0x400003C,
                "REG_BG3Y",
                "Display",
                tag_types["Display"],
                "BG3 Ref Point Y",
            )
            self._define_reg_with_tag(
                0x4000040,
                "REG_WIN0H",
                "Display",
                tag_types["Display"],
                "Window 0 Horizontal",
            )
            self._define_reg_with_tag(
                0x4000042,
                "REG_WIN1H",
                "Display",
                tag_types["Display"],
                "Window 1 Horizontal",
            )
            self._define_reg_with_tag(
                0x4000044,
                "REG_WIN0V",
                "Display",
                tag_types["Display"],
                "Window 0 Vertical",
            )
            self._define_reg_with_tag(
                0x4000046,
                "REG_WIN1V",
                "Display",
                tag_types["Display"],
                "Window 1 Vertical",
            )
            self._define_reg_with_tag(
                0x4000048,
                "REG_WININ",
                "Display",
                tag_types["Display"],
                "Window 0/1 In Control",
            )
            self._define_reg_with_tag(
                0x400004A,
                "REG_WINOUT",
                "Display",
                tag_types["Display"],
                "OBJ/Outside Window Control",
            )
            self._define_reg_with_tag(
                0x400004C, "REG_MOSAIC", "Display", tag_types["Display"], "Mosaic Size"
            )
            self._define_reg_with_tag(
                0x4000050,
                "REG_BLDCNT",
                "Display",
                tag_types["Display"],
                "Color Special Effects",
            )
            self._define_reg_with_tag(
                0x4000052,
                "REG_BLDALPHA",
                "Display",
                tag_types["Display"],
                "Alpha Blending Coefs",
            )
            self._define_reg_with_tag(
                0x4000054,
                "REG_BLDY",
                "Display",
                tag_types["Display"],
                "Brightness Coef",
            )
            self._define_reg_with_tag(
                0x4000060,
                "REG_SOUND1CNT_L",
                "Sound",
                tag_types["Sound"],
                "Channel 1 Sweep (NR10)",
            )
            self._define_reg_with_tag(
                0x4000062,
                "REG_SOUND1CNT_H",
                "Sound",
                tag_types["Sound"],
                "Channel 1 Duty/Len/Env (NR11, NR12)",
            )
            self._define_reg_with_tag(
                0x4000064,
                "REG_SOUND1CNT_X",
                "Sound",
                tag_types["Sound"],
                "Channel 1 Freq/Ctrl (NR13, NR14)",
            )
            self._define_reg_with_tag(
                0x4000068,
                "REG_SOUND2CNT_L",
                "Sound",
                tag_types["Sound"],
                "Channel 2 Duty/Len/Env (NR21, NR22)",
            )
            self._define_reg_with_tag(
                0x400006C,
                "REG_SOUND2CNT_H",
                "Sound",
                tag_types["Sound"],
                "Channel 2 Freq/Ctrl (NR23, NR24)",
            )
            self._define_reg_with_tag(
                0x4000070,
                "REG_SOUND3CNT_L",
                "Sound",
                tag_types["Sound"],
                "Channel 3 Stop/Wave Sel (NR30)",
            )
            self._define_reg_with_tag(
                0x4000072,
                "REG_SOUND3CNT_H",
                "Sound",
                tag_types["Sound"],
                "Channel 3 Length/Volume (NR31, NR32)",
            )
            self._define_reg_with_tag(
                0x4000074,
                "REG_SOUND3CNT_X",
                "Sound",
                tag_types["Sound"],
                "Channel 3 Freq/Ctrl (NR33, NR34)",
            )
            self._define_reg_with_tag(
                0x4000078,
                "REG_SOUND4CNT_L",
                "Sound",
                tag_types["Sound"],
                "Channel 4 Length/Env (NR41, NR42)",
            )
            self._define_reg_with_tag(
                0x400007C,
                "REG_SOUND4CNT_H",
                "Sound",
                tag_types["Sound"],
                "Channel 4 Freq/Ctrl (NR43, NR44)",
            )
            self._define_reg_with_tag(
                0x4000080,
                "REG_SOUNDCNT_L",
                "Sound",
                tag_types["Sound"],
                "Control Stereo/Vol/Enable (NR50, NR51)",
            )
            self._define_reg_with_tag(
                0x4000082,
                "REG_SOUNDCNT_H",
                "Sound",
                tag_types["Sound"],
                "Control Mixing/DMA Ctrl",
            )
            self._define_reg_with_tag(
                0x4000084,
                "REG_SOUNDCNT_X",
                "Sound",
                tag_types["Sound"],
                "Control Sound On/Off (NR52)",
            )
            self._define_reg_with_tag(
                0x4000088,
                "REG_SOUNDBIAS",
                "Sound",
                tag_types["Sound"],
                "Sound PWM Control",
            )
            self._define_reg_with_tag(
                0x4000090,
                "REG_WAVE_RAM",
                "Sound",
                tag_types["Sound"],
                "Channel 3 Wave Pattern RAM (16 bytes, mirrored)",
            )  # Size is actually 0x10, define symbol at start
            self._define_reg_with_tag(
                0x40000A0, "REG_FIFO_A", "Sound", tag_types["Sound"], "Channel A FIFO"
            )
            self._define_reg_with_tag(
                0x40000A4, "REG_FIFO_B", "Sound", tag_types["Sound"], "Channel B FIFO"
            )
            # DMA Registers
            for i in range(4):
                dma_base = 0x40000B0 + i * 0xC
                self._define_reg_with_tag(
                    dma_base + 0x0,
                    f"REG_DMA{i}SAD",
                    "DMA",
                    tag_types["DMA"],
                    f"DMA {i} Source Address",
                )
                self._define_reg_with_tag(
                    dma_base + 0x4,
                    f"REG_DMA{i}DAD",
                    "DMA",
                    tag_types["DMA"],
                    f"DMA {i} Destination Address",
                )
                self._define_reg_with_tag(
                    dma_base + 0x8,
                    f"REG_DMA{i}CNT_L",
                    "DMA",
                    tag_types["DMA"],
                    f"DMA {i} Word Count",
                )
                self._define_reg_with_tag(
                    dma_base + 0xA,
                    f"REG_DMA{i}CNT_H",
                    "DMA",
                    tag_types["DMA"],
                    f"DMA {i} Control",
                )
            # Timer Registers
            for i in range(4):
                tmr_base = 0x4000100 + i * 0x4
                self._define_reg_with_tag(
                    tmr_base + 0x0,
                    f"REG_TM{i}CNT_L",
                    "Timers",
                    tag_types["Timers"],
                    f"Timer {i} Counter/Reload",
                )
                self._define_reg_with_tag(
                    tmr_base + 0x2,
                    f"REG_TM{i}CNT_H",
                    "Timers",
                    tag_types["Timers"],
                    f"Timer {i} Control",
                )
            # Serial IO Regs (Mixed Modes)
            self._define_reg_with_tag(
                0x4000120,
                "REG_SIODATA32",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO Data (Normal-32bit)",
            )
            self._define_reg_with_tag(
                0x4000120,
                "REG_SIOMULTI0",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO Data 0 (Multiplayer Parent)",
            )
            self._define_reg_with_tag(
                0x4000122,
                "REG_SIOMULTI1",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO Data 1 (Multiplayer Child 1)",
            )
            self._define_reg_with_tag(
                0x4000124,
                "REG_SIOMULTI2",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO Data 2 (Multiplayer Child 2)",
            )
            self._define_reg_with_tag(
                0x4000126,
                "REG_SIOMULTI3",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO Data 3 (Multiplayer Child 3)",
            )
            self._define_reg_with_tag(
                0x4000128,
                "REG_SIOCNT",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO Control",
            )
            self._define_reg_with_tag(
                0x400012A,
                "REG_SIOMLT_SEND",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO Data Send (Multiplayer Local)",
            )
            self._define_reg_with_tag(
                0x400012A,
                "REG_SIODATA8",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO Data (Normal-8bit/UART)",
            )
            # Keypad Regs
            self._define_reg_with_tag(
                0x4000130, "REG_KEYINPUT", "Keypad", tag_types["Keypad"], "Key Status"
            )
            self._define_reg_with_tag(
                0x4000132,
                "REG_KEYCNT",
                "Keypad",
                tag_types["Keypad"],
                "Key Interrupt Control",
            )
            # Serial IO Regs (Continued) / General Purpose IO
            self._define_reg_with_tag(
                0x4000134,
                "REG_RCNT",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO Mode Select / General Purpose Data",
            )
            self._define_reg_with_tag(
                0x4000140,
                "REG_JOYCNT",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO JOY Bus Control",
            )
            self._define_reg_with_tag(
                0x4000150,
                "REG_JOY_RECV",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO JOY Bus Receive Data",
            )
            self._define_reg_with_tag(
                0x4000154,
                "REG_JOY_TRANS",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO JOY Bus Transmit Data",
            )
            self._define_reg_with_tag(
                0x4000158,
                "REG_JOYSTAT",
                "Serial IO",
                tag_types["Serial IO"],
                "SIO JOY Bus Receive Status",
            )
            # Interrupt, Waitstate, Power Regs
            self._define_reg_with_tag(
                0x4000200,
                "REG_IE",
                "Interrupts",
                tag_types["Interrupts"],
                "Interrupt Enable",
            )
            self._define_reg_with_tag(
                0x4000202,
                "REG_IF",
                "Interrupts",
                tag_types["Interrupts"],
                "Interrupt Flag / Acknowledge",
            )
            self._define_reg_with_tag(
                0x4000204,
                "REG_WAITCNT",
                "System Control",
                tag_types["System Control"],
                "Game Pak Waitstate Control",
            )
            self._define_reg_with_tag(
                0x4000208,
                "REG_IME",
                "Interrupts",
                tag_types["Interrupts"],
                "Interrupt Master Enable",
            )
            self._define_reg_with_tag(
                0x4000300,
                "REG_POSTFLG",
                "System Control",
                tag_types["System Control"],
                "Post Boot Flag",
            )
            self._define_reg_with_tag(
                0x4000301,
                "REG_HALTCNT",
                "System Control",
                tag_types["System Control"],
                "Power Down Control",
            )
            self._define_reg_with_tag(
                0x4000800,
                "REG_INTERNAL_MEM_CNT",
                "System Control",
                tag_types["System Control"],
                "Internal Memory Control (Undocumented)",
            )

            # --- entry point ---
            entry_point_addr = 0x8000000  # Standard GBA entry point
            self.add_entry_point(entry_point_addr)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, entry_point_addr, "_start")
            )
            self.add_function(entry_point_addr)  # Define function for analysis

            self.log.log_info("gba rom loaded successfully")

            # --- force analysis update ---
            self.log.log_info("updating analysis...")
            self.update_analysis_and_wait()
            # ---------------------------

            return True
        except:
            log_error(traceback.format_exc())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        # GBA entry point is fixed
        return 0x8000000

    def perform_get_address_size(self):
        return 4  # GBA's ARM7TDMI is 32-bit


GBAView.register()
