import io
import zlib

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

            self._init_arm9(try_decompress=True)
            self._init_arm7()
            # self._load_arm9_overlays()

            return True
        except:
            self.log.log_error(traceback.format_exc())
            return False

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

    def _load_arm9_overlays(self):
        for i, overlay in enumerate(self.nds_rom.arm9_overlay_table.entries):
            fat_entry = self.nds_rom.fat_entries[overlay.file_id]
            overlay_data = self.nds_rom.rom_data[
                fat_entry.start_address : fat_entry.end_address
            ]

            decompressed_data = self._decompress_overlay(overlay_data)

            if len(decompressed_data) != overlay.ram_size:
                self.log.log_warning(
                    f"Overlay {i} size mismatch: expected {overlay.ram_size}, got {len(decompressed_data)}"
                )

            segment_name = f"overlay_{i}"
            self.add_auto_segment(
                overlay.ram_address,
                len(decompressed_data),
                0,  # We're using the decompressed data directly, so file offset is 0
                len(decompressed_data),
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
            )

            # Write the decompressed data to the segment
            self.write(overlay.ram_address, decompressed_data)

            # Add a comment to mark the overlay
            self.set_comment_at(overlay.ram_address, f"ARM9 Overlay {i}")

            self.log.log_info(
                f"Loaded ARM9 Overlay {i} at 0x{overlay.ram_address:08x}, size: 0x{len(decompressed_data):x}"
            )

            # If the overlay has a static initializer, add a function
            if overlay.static_initializer_start_address != 0:
                self.add_function(overlay.static_initializer_start_address)
                self.set_comment_at(
                    overlay.static_initializer_start_address,
                    f"ARM9 Overlay {i} Static Initializer",
                )

        self.log.log_info(
            f"Loaded {len(self.nds_rom.arm9_overlay_table.entries)} ARM9 overlays"
        )

    def _decompress_overlay(self, data):
        return self._mii_uncompress_backward(data)

    def _mii_uncompress_backward(self, data):
        leng = struct.unpack_from("<I", data, len(data) - 4)[0] + len(data)
        result = bytearray(leng)
        result[: len(data)] = data

        offs = len(data) - (struct.unpack_from("<I", data, len(data) - 8)[0] >> 24)
        dst_offs = leng

        while True:
            header = result[offs - 1]
            offs -= 1

            for i in range(8):
                if (header & 0x80) == 0:
                    offs -= 1
                    dst_offs -= 1
                    result[dst_offs] = result[offs]
                else:
                    a = result[offs - 1]
                    b = result[offs - 2]
                    offs -= 2

                    disp = (((a & 0xF) << 8) | b) + 2
                    length = (a >> 4) + 2

                    for _ in range(length + 1):
                        dst_offs -= 1
                        result[dst_offs] = result[dst_offs + disp]

                if offs <= (
                    len(data)
                    - (struct.unpack_from("<I", data, len(data) - 8)[0] & 0xFFFFFF)
                ):
                    return bytes(result)

                header = (header << 1) & 0xFF

    def _init_arm9(self, try_decompress=False):
        header = self.nds_rom.header
        arm9_data = self.nds_rom.rom_data[
            header.arm9_rom_offset : header.arm9_rom_offset + header.arm9_size
        ]

        if try_decompress:
            try:
                arm9_data = self._decompress_arm9(arm9_data)
            except Exception as e:
                self.log.log_error(f"Failed to decompress ARM9 binary: {str(e)}")
                self.log.log_info("Falling back to compressed ARM9 binary")

        self._add_segment_and_entry(
            header.arm9_rom_offset,
            header.arm9_ram_address,
            len(arm9_data),
            header.arm9_entry_address,
            "_start9",
        )
        # Write the ARM9 data to the segment
        self.write(header.arm9_ram_address, arm9_data)
        self.log.log_info(
            f"ARM9 entry=0x{header.arm9_entry_address:08x}, load=0x{header.arm9_ram_address:08x}, "
            f"size=0x{len(arm9_data):x}, offset=0x{header.arm9_rom_offset:08x}"
        )

    def _decompress_arm9(self, arm9_data):
        # Assuming the ModuleParams offset is at the end of the ARM9 binary
        module_params_offset = len(arm9_data) - 36  # 36 is the size of ModuleParams

        if struct.unpack_from("<I", arm9_data, module_params_offset + 0x14)[0] == 0:
            self.log.log_info("ARM9 binary does not appear to be compressed")
            return arm9_data  # Not compressed

        decompressed_data = self._mii_uncompress_backward(arm9_data)

        # Set CompressedStaticEnd to 0
        struct.pack_into("<I", decompressed_data, module_params_offset + 0x14, 0)

        self.log.log_info(
            f"Decompressed ARM9 binary from {len(arm9_data)} to {len(decompressed_data)}"
        )

        return decompressed_data


NDSView.register()
