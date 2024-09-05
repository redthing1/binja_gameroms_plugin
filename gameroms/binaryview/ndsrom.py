from binaryninja import *
from ..readers.nds_cartridge import NDSRomReader, NDSRom


class NDSView(BinaryView):
    name = "NDS"
    long_name = "Nintendo DS"

    def __init__(self, parent):
        BinaryView.__init__(self, file_metadata=parent.file, parent_view=parent)
        self.log = self.create_logger("NDS")
        self.raw = parent
        self.nds_rom = None

    @staticmethod
    def is_valid_for_data(data):
        try:
            rom_data = data.read(0, len(data))
            return NDSRomReader.is_valid(rom_data)
        except:
            return False

    def init(self):
        try:
            rom_data = self.raw.read(0, len(self.raw))
            self.nds_rom = NDSRomReader.read(rom_data)
            self.arch = Architecture["armv7"]
            self.platform = Architecture["armv7"].standalone_platform

            self._init_arm9()
            self._init_arm7()

            return True
        except:
            self.log.log_error(traceback.format_exc())
            return False

    def _init_arm9(self):
        header = self.nds_rom.header
        self._add_segment_and_entry(
            header.arm9_rom_offset,
            header.arm9_ram_address,
            header.arm9_size,
            header.arm9_entry_address,
            "_start9",
        )
        self.log.log_info(
            f"ARM9 entry=0x{header.arm9_entry_address:08x}, load=0x{header.arm9_ram_address:08x}, "
            f"size=0x{header.arm9_size:08x}, offset=0x{header.arm9_rom_offset:08x}"
        )

    def _init_arm7(self):
        header = self.nds_rom.header
        self._add_segment_and_entry(
            header.arm7_rom_offset,
            header.arm7_ram_address,
            header.arm7_size,
            header.arm7_entry_address,
            "_start7",
        )
        self.log.log_info(
            f"ARM7 entry=0x{header.arm7_entry_address:08x}, load=0x{header.arm7_ram_address:08x}, "
            f"size=0x{header.arm7_size:08x}, offset=0x{header.arm7_rom_offset:08x}"
        )

    def _add_segment_and_entry(
        self, rom_offset, load_address, size, entry_address, symbol_name
    ):
        self.add_auto_segment(
            load_address,
            size,
            rom_offset,
            size,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
        )
        self.add_entry_point(entry_address)
        self.add_function(entry_address)
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, entry_address, symbol_name)
        )

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.nds_rom.header.arm9_entry_address

    def perform_get_address_size(self):
        return 4


NDSView.register()
