# adapted from https://gist.github.com/wheremyfoodat/79208c9e14a7242e6189b07d0a226ecf

from binaryninja import *

import struct
import traceback
import logging

log = logging.getLogger("NDS")

def crc16(data):
    crc = 0xFFFF
    for ch in data:
        crc ^= ch
        for bit in range(0, 8):
            if (crc & 1) == 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


class NDSView(BinaryView):
    name = "NDS"
    long_name = "Nintendo DS"

    def __init__(self, parent):
        BinaryView.__init__(self, file_metadata=parent.file, parent_view=parent)
        self.raw = parent

    @staticmethod
    def is_valid_for_data(data):
        hdr = data.read(0, 0x160)
        if len(hdr) < 0x160:
            return False
        if struct.unpack("<H", hdr[0x15E:0x160])[0] != crc16(hdr[0:0x15E]):
            print("CRC check failed, are you sure your header/ROM is valid?")
            return False
        if struct.unpack("<H", hdr[0x15C:0x15E])[0] != crc16(hdr[0xC0:0x15C]):
            print("CRC check failed, are you sure your header/ROM is valid?")
            return False
        return True

    def init_common(self):
        self.arch = Architecture["armv7"]
        self.platform = Architecture["armv7"].standalone_platform  # type: ignore
        self.hdr = self.raw.read(0, 0x160)

    def init_arm9(self):
        try:
            self.init_common()
            self.arm9_offset = struct.unpack("<L", self.hdr[0x20:0x24])[0]
            self.arm9_entry_addr = struct.unpack("<L", self.hdr[0x24:0x28])[0]
            self.arm9_load_addr = struct.unpack("<L", self.hdr[0x28:0x2C])[0]
            self.arm9_size = struct.unpack("<L", self.hdr[0x2C:0x30])[0]

            # create a segment to map the arm9 rom to the correct load address
            self.add_auto_segment(
                self.arm9_load_addr,
                self.arm9_size,
                self.arm9_offset,
                self.arm9_size,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
            )
            self.add_entry_point(self.arm9_entry_addr)
            self.add_function(self.arm9_entry_addr)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, self.arm9_entry_addr, "_start9")
            )
            log.info(
                f"ARM9 entry=0x{self.arm9_entry_addr:08x}, load=0x{self.arm9_load_addr:08x}, size=0x{self.arm9_size:08x}, offset=0x{self.arm9_offset:08x}"
            )
            return True
        except:
            log.error(traceback.format_exc())
            return False

    def init_arm7(self):
        try:
            self.init_common()
            self.arm7_offset = struct.unpack("<L", self.hdr[0x30:0x34])[0]
            self.arm7_entry_addr = struct.unpack("<L", self.hdr[0x34:0x38])[0]
            self.arm7_load_addr = struct.unpack("<L", self.hdr[0x38:0x3C])[0]
            self.arm7_size = struct.unpack("<L", self.hdr[0x3C:0x40])[0]

            # create a segment to map the arm7 rom to the correct load address
            self.add_auto_segment(
                self.arm7_load_addr,
                self.arm7_size,
                self.arm7_offset,
                self.arm7_size,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
            )
            self.add_entry_point(self.arm7_entry_addr)  # type: ignore
            self.add_function(self.arm7_entry_addr)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, self.arm7_entry_addr, "_start7")
            )
            log.info(
                f"ARM7 entry=0x{self.arm7_entry_addr:08x}, load=0x{self.arm7_load_addr:08x}, size=0x{self.arm7_size:08x}, offset=0x{self.arm7_offset:08x}"
            )
            return True
        except:
            log.error(traceback.format_exc())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.arm9_entry_addr

    def perform_get_address_size(self):
        return 4

    def init(self):
        return self.init_arm9() and self.init_arm7()
