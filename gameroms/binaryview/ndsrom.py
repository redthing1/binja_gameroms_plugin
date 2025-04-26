import io
import struct
import traceback

# import necessary types from binaryninja for type hinting
from typing import Optional, List, Dict, Tuple, Generator, Mapping, Callable, Union

# import common types from top-level
from binaryninja import (
    BinaryView,
    BinaryReader,
    BinaryWriter,
    SegmentFlag,
    SymbolType,
    Symbol,
    DataVariable,
    StringReference,
    ReferenceSource,
    TagType,
    Tag,
    Type,
    Platform,
    Architecture,
    FileMetadata,
    log_info,
    log_error,
    log_warn,
)

# import specific types from submodules if needed
# from binaryninja.binaryview import Relocation, RelocationInfo # Removed this line
from binaryninja.log import Logger  # explicit logger import
from uuid import UUID
from os import PathLike  # for type hinting file paths

# assuming nds_cartridge.py is in a sibling 'readers' directory
# adjust the import path if your structure is different
try:
    # relative import for plugin structure
    from ..readers.nds_cartridge import (
        NDSRomReader,
        NDSRom,
        NDSOverlayTable,
    )  # make types explicit
except ImportError:
    # fallback if running the script directly or structure differs
    from nds_cartridge import NDSRomReader, NDSRom, NDSOverlayTable


class NDSView(BinaryView):
    name = "NDS"
    long_name = "Nintendo DS"

    # segment permission flags
    RWX_FLAGS: SegmentFlag = (
        SegmentFlag.SegmentReadable
        | SegmentFlag.SegmentWritable
        | SegmentFlag.SegmentExecutable
    )
    RW_FLAGS: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    RX_FLAGS: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable

    def __init__(self, parent: BinaryView):
        """initializes the ndsview instance."""
        BinaryView.__init__(self, file_metadata=parent.file, parent_view=parent)
        self.log: Logger = self.create_logger("NDS")
        self.raw: BinaryView = parent  # the raw parent binaryview (data source)
        self.nds_rom: Optional[NDSRom] = None  # stores parsed rom data
        self._created_tag_types: Dict[str, TagType] = {}  # cache created tag types

    @staticmethod
    def is_valid_for_data(data: BinaryView) -> bool:
        """
        checks if the data is likely an nds rom using a basic heuristic.
        the full validation (crc checks) is deferred to the init method.
        """
        try:
            # read enough data for a basic check (e.g., nintendo logo)
            header_start: bytes = data.read(
                0, 0xC4
            )  # read up to the start of the logo + a few bytes
            if len(header_start) < 0xC4:
                return False

            # check the first few bytes of the nintendo logo at 0xc0
            if header_start[0xC0:0xC4] == b"\x24\xff\xae\x51":
                return True  # assume valid for now, full check in init()
            else:
                return False
        except Exception as e:
            log_error(
                f"[NDS] Error during basic validation check: {e}\n{traceback.format_exc()}"
            )
            return False

    def init(self) -> bool:
        """
        initializes the nds view.
        performs full validation, parses the rom header, maps memory segments,
        loads arm9/arm7 binaries and overlays, and defines hardware symbols.
        returns true on success, false on failure.
        """
        try:
            self.log.log_info("reading entire rom into memory for header parsing...")
            # read the entire rom content into memory because ndsromreader expects bytes
            rom_length = self.raw.length
            rom_data_bytes: bytes = self.raw.read(0, rom_length)
            if not rom_data_bytes or len(rom_data_bytes) != rom_length:
                self.log.log_error(
                    f"failed to read full rom data ({len(rom_data_bytes)} read vs {rom_length} expected) from parent view."
                )
                return False

            # --- perform full validation here ---
            self.log.log_info("performing full header validation...")
            if not NDSRomReader.is_valid(rom_data_bytes[:0x160]):
                self.log.log_error(
                    "full header validation failed via ndsromreader.is_valid."
                )
                self.log.log_warn("continuing load despite header validation failure.")
            else:
                self.log.log_info("full header validation successful.")
            # ------------------------------------

            self.log.log_info("parsing nds rom structure using ndsromreader...")
            self.nds_rom = NDSRomReader.read(rom_data_bytes)
            del rom_data_bytes  # free memory

            if not self.nds_rom:
                self.log.log_error(
                    "failed to parse nds rom header and structures (NDSRomReader.read returned None)."
                )
                return False

            # set architecture and platform
            self.arch: Architecture = Architecture["armv7"]  # type: ignore
            self.platform: Platform = Architecture["armv7"].standalone_platform  # type: ignore

            self.log.log_info("mapping nds memory segments...")
            self._map_memory_segments()

            self.log.log_info("loading arm9 binary...")
            self._init_arm9(try_decompress=True)

            self.log.log_info("loading arm7 binary...")
            self._init_arm7()

            self.log.log_info("loading arm9 overlays...")
            self._load_overlays("ARM9", self.nds_rom.arm9_overlay_table)

            self.log.log_info("loading arm7 overlays...")
            self._load_overlays("ARM7", self.nds_rom.arm7_overlay_table)

            # load debug info if present
            if (
                self.nds_rom.header.debug_rom_offset != 0
                and self.nds_rom.header.debug_size > 0
            ):
                self.log.log_info("loading debug arm9 binary...")
                self._init_debug_arm9()

            self.log.log_info("defining nds hardware symbols and tags...")
            self._define_symbols_and_tags()  # renamed method

            # --- force analysis update ---
            self.log.log_info("updating analysis...")
            self.update_analysis_and_wait()
            # ---------------------------

            self.log.log_info("nds rom loading complete.")
            return True
        except Exception as e:  # catch specific exceptions if possible
            self.log.log_error(f"failed to initialize ndsview: {e}")
            self.log.log_error(traceback.format_exc())
            return False

    # --- helper methods ---

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        """gets or creates a tag type, caching the result."""
        if name in self._created_tag_types:
            return self._created_tag_types[name]
        if name in self.tag_types:
            tag_type = self.tag_types[name]
            # Handle case where tag_types might return a list (shouldn't happen for unique names)
            if isinstance(tag_type, list):
                if tag_type:
                    self._created_tag_types[name] = tag_type[0]
                    return tag_type[0]
                else:
                    # Should not happen, but handle gracefully
                    self.log.log_error(
                        f"tag type '{name}' returned empty list unexpectedly."
                    )
                    return None
            else:
                self._created_tag_types[name] = tag_type
                return tag_type
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
        # define the symbol
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))  # type: ignore
        if description:
            self.set_comment_at(address, description)

        # get or create the tag type
        tag_type = self._get_or_create_tag_type(tag_type_name, tag_type_icon)

        # add the tag if the type exists
        if tag_type:
            try:
                self.add_tag(address, tag_type, data="")  # data can be empty or name
            except Exception as e:
                # log if adding tag fails, but don't stop loading
                self.log.log_error(
                    f"failed to add tag '{tag_type_name}' at 0x{address:x} for {name}: {e}"
                )

    # --- memory mapping ---

    def _map_memory_segments(self):
        """maps the core nds memory regions."""
        # add comments for clarity
        self.add_auto_segment(0x02000000, 0x00400000, 0, 0, self.RWX_FLAGS)
        self.set_comment_at(0x02000000, "Main RAM (4MB)")
        self.add_auto_segment(0x03000000, 0x00008000, 0, 0, self.RWX_FLAGS)
        self.set_comment_at(0x03000000, "Shared WRAM (32KB)")
        self.add_auto_segment(0x037F8000, 0x00008000, 0, 0, self.RWX_FLAGS)
        self.set_comment_at(0x037F8000, "Shared WRAM Mirror")
        self.add_auto_segment(0x03800000, 0x00010000, 0, 0, self.RWX_FLAGS)
        self.set_comment_at(0x03800000, "ARM7 WRAM (64KB)")
        self.add_auto_segment(0x04000000, 0x00001000, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x04000000, "I/O Registers (Main Block)")
        self.add_auto_segment(0x040001A0, 0x000000C0, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x040001A0, "I/O Registers (Cart/IPC/SPI)")
        self.add_auto_segment(0x04000200, 0x00000100, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x04000200, "I/O Registers (Mem/IRQ/Math)")
        self.add_auto_segment(0x04000300, 0x00000100, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x04000300, "I/O Registers (Power/GFX)")
        self.add_auto_segment(0x04000400, 0x00000200, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x04000400, "I/O Registers (Sound)")
        self.add_auto_segment(0x04001000, 0x00000100, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x04001000, "I/O Registers (Engine B)")
        self.add_auto_segment(0x04100000, 0x00000020, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x04100000, "IPC FIFO / Card Data")
        self.add_auto_segment(0x05000000, 0x00001000, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x05000000, "Palette RAM (4KB)")
        self.add_auto_segment(0x06000000, 0x000A4000, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x06000000, "VRAM (656KB)")
        self.add_auto_segment(0x06800000, 0x000A4000, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x06800000, "VRAM LCDC Mirror")
        self.add_auto_segment(0x07000000, 0x00001000, 0, 0, self.RW_FLAGS)
        self.set_comment_at(0x07000000, "OAM (4KB)")
        self.add_auto_segment(0xFFFF0000, 0x00004000, 0, 0, self.RX_FLAGS)
        self.set_comment_at(0xFFFF0000, "ARM9 BIOS (16KB)")

    # --- binary loading ---

    def _init_arm9(self, try_decompress=True):
        """loads the main arm9 binary, optionally decompressing it."""
        if not self.nds_rom:
            return

        header = self.nds_rom.header
        if header.arm9_size == 0:
            self.log.log_info("arm9 size is 0, skipping.")
            return

        # read the raw arm9 data directly from the parent view
        arm9_data_raw: bytes = self.raw.read(header.arm9_rom_offset, header.arm9_size)
        if not arm9_data_raw:
            self.log.log_error(
                f"failed to read arm9 data from rom offset 0x{header.arm9_rom_offset:x}"
            )
            return

        final_arm9_data = arm9_data_raw
        final_size = header.arm9_size
        decompressed = False

        if try_decompress:
            try:
                decompressed_data = self._mii_uncompress_backward(arm9_data_raw)
                # use decompressed data if it's different (check size)
                if len(decompressed_data) != len(arm9_data_raw):
                    final_arm9_data = decompressed_data
                    final_size = len(decompressed_data)
                    decompressed = True
                    self.log.log_info(
                        f"decompressed arm9: {header.arm9_size} bytes -> {final_size} bytes"
                    )
                else:
                    self.log.log_info(
                        "arm9 appears uncompressed or decompression yielded same data."
                    )
            except Exception as e:
                self.log.log_warn(f"arm9 decompression failed: {e}. using raw data.")

        # add segment and load data
        if decompressed:
            # if decompressed, size changed, so add segment then write
            self.add_auto_segment(
                header.arm9_ram_address, final_size, 0, final_size, self.RX_FLAGS
            )
            bytes_written = self.write(header.arm9_ram_address, final_arm9_data)
            if bytes_written != final_size:
                self.log.log_error(
                    f"arm9 write error (decompressed): expected {final_size}, wrote {bytes_written}"
                )
        else:
            # if not decompressed, map directly from file
            self.add_auto_segment(
                header.arm9_ram_address,
                final_size,
                header.arm9_rom_offset,
                final_size,
                self.RX_FLAGS,
            )

        # define entry point and function
        self.add_entry_point(header.arm9_entry_address)
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, header.arm9_entry_address, "_start9")
        )  # type: ignore
        self.add_function(header.arm9_entry_address)
        self.set_comment_at(header.arm9_ram_address, "ARM9 Binary Start")

        self.log.log_info(
            f"arm9 loaded: entry=0x{header.arm9_entry_address:08x}, load=0x{header.arm9_ram_address:08x}, "
            f"size=0x{final_size:x}, offset=0x{header.arm9_rom_offset:08x} {'(decompressed)' if decompressed else '(raw mapped)'}"
        )
        # TODO: handle arm9 bss

    def _init_arm7(self):
        """loads the main arm7 binary. arm7 is typically not compressed."""
        if not self.nds_rom:
            return

        header = self.nds_rom.header
        if header.arm7_size == 0:
            self.log.log_info("arm7 size is 0, skipping loading.")
            return

        # arm7 is usually not compressed, map directly from file
        final_size = header.arm7_size
        self.add_auto_segment(
            header.arm7_ram_address,
            final_size,
            header.arm7_rom_offset,
            final_size,
            self.RX_FLAGS,
        )

        # define entry point and function
        self.add_entry_point(header.arm7_entry_address)
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, header.arm7_entry_address, "_start7")
        )  # type: ignore
        self.add_function(header.arm7_entry_address)
        self.set_comment_at(header.arm7_ram_address, "ARM7 Binary Start")

        self.log.log_info(
            f"arm7 loaded: entry=0x{header.arm7_entry_address:08x}, load=0x{header.arm7_ram_address:08x}, "
            f"size=0x{final_size:x}, offset=0x{header.arm7_rom_offset:08x} (raw mapped)"
        )
        # TODO: handle arm7 bss

    def _init_debug_arm9(self):
        """loads the debug arm9 binary if present."""
        if not self.nds_rom:
            return

        header = self.nds_rom.header
        # debug arm9 is typically not compressed, map directly
        load_address = header.debug_ram_address
        if load_address == 0:
            load_address = 0x02400000
            self.log.log_warn(
                f"debug ram address is 0 in header, using default 0x{load_address:08x}"
            )

        loaded_size = header.debug_size
        self.add_auto_segment(
            load_address,
            loaded_size,
            header.debug_rom_offset,
            loaded_size,
            self.RX_FLAGS,
        )
        self.set_comment_at(load_address, "ARM9 Debug Binary Start")

        self.log.log_info(
            f"debug arm9 loaded: load=0x{load_address:08x}, size=0x{loaded_size:x}, offset=0x{header.debug_rom_offset:08x} (raw mapped)"
        )

    def _load_overlays(self, cpu_name: str, overlay_table: Optional[NDSOverlayTable]):
        """loads arm9 or arm7 overlays. overlays require decompression and writing."""
        if not self.nds_rom:
            return
        if not overlay_table or not overlay_table.entries:
            return

        num_loaded = 0
        num_failed = 0
        for i, entry in enumerate(overlay_table.entries):
            if entry.file_id == 0xFFFF or entry.file_id >= len(
                self.nds_rom.fat_entries
            ):
                continue
            if entry.ram_size == 0 and entry.bss_size == 0:
                continue

            fat_entry = self.nds_rom.fat_entries[entry.file_id]
            if fat_entry.start_address >= fat_entry.end_address:
                self.log.log_warn(
                    f"skipping invalid {cpu_name} overlay {i} (file id {entry.file_id}): fat entry invalid."
                )
                num_failed += 1
                continue

            overlay_size_in_rom = fat_entry.end_address - fat_entry.start_address
            if overlay_size_in_rom <= 0:
                self.log.log_warn(
                    f"skipping invalid {cpu_name} overlay {i} (file id {entry.file_id}): non-positive size in rom."
                )
                num_failed += 1
                continue

            overlay_data_raw: bytes = self.raw.read(
                fat_entry.start_address, overlay_size_in_rom
            )
            if not overlay_data_raw:
                self.log.log_error(
                    f"failed to read {cpu_name} overlay {i} (file id {entry.file_id}) data from rom offset 0x{fat_entry.start_address:x}"
                )
                num_failed += 1
                continue

            loaded_data = b""
            segment_ram_size = 0
            decompressed = False
            if entry.ram_size > 0:
                try:
                    decompressed_data = self._mii_uncompress_backward(overlay_data_raw)
                    if len(decompressed_data) != entry.ram_size:
                        self.log.log_warn(
                            f"{cpu_name} overlay {i} (file id {entry.file_id}): decompressed size {len(decompressed_data):x} != expected ram size {entry.ram_size:x}. using decompressed size."
                        )
                        segment_ram_size = len(decompressed_data)
                    else:
                        segment_ram_size = entry.ram_size
                    loaded_data = decompressed_data
                    decompressed = True
                except Exception as e:
                    self.log.log_error(
                        f"failed to decompress {cpu_name} overlay {i} (file id {entry.file_id}): {e}. skipping."
                    )
                    num_failed += 1
                    continue
            else:  # ram_size is 0, only BSS
                segment_ram_size = 0
                loaded_data = b""

            segment_name = f"{cpu_name}_Overlay_{i}_File{entry.file_id}"
            # add code/data segment (if size > 0) then write decompressed data
            if segment_ram_size > 0:
                self.add_auto_segment(
                    entry.ram_address,
                    segment_ram_size,
                    0,
                    segment_ram_size,
                    self.RX_FLAGS,
                )
                bytes_written = self.write(
                    entry.ram_address, loaded_data[:segment_ram_size]
                )
                if bytes_written != segment_ram_size:
                    self.log.log_error(
                        f"overlay {segment_name} write error: expected {segment_ram_size}, wrote {bytes_written}"
                    )
                    num_failed += 1
                    continue  # fail if write fails

            # add bss segment (if size > 0)
            if entry.bss_size > 0:
                bss_start_address = entry.ram_address + segment_ram_size
                self.add_auto_segment(
                    bss_start_address, entry.bss_size, 0, 0, self.RW_FLAGS
                )

            self.set_comment_at(
                entry.ram_address,
                f"{cpu_name} overlay {i} (file id: {entry.file_id}){' (decompressed)' if decompressed else ''}",
            )

            # define static initializer function
            if entry.static_initializer_start_address != 0:
                init_start = entry.static_initializer_start_address
                func_addr = init_start & ~1  # ensure word alignment
                self.add_function(func_addr)
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, func_addr, f"{segment_name}_Init")
                )  # type: ignore
                self.set_comment_at(
                    func_addr, f"{cpu_name} overlay {i} static initializer"
                )
                # TODO: Set thumb mode if init_start & 1 was true

            num_loaded += 1

        log_func = self.log.log_info if num_failed == 0 else self.log.log_warn
        log_func(
            f"loaded {num_loaded} / {len(overlay_table.entries)} {cpu_name} overlays ({num_failed} failures)."
        )

    def _mii_uncompress_backward(self, data: bytes) -> bytes:
        """decompresses data using mii lz77 variant (backward)."""
        if len(data) < 4:
            raise ValueError("data too short for mii decompression footer")
        footer = data[-4:]
        header_val = struct.unpack_from("<I", footer, 0)[0]
        comp_type = (header_val >> 24) & 0xF
        if comp_type == 1:
            decompressed_size = header_val & 0xFFFFFF
        else:
            decompressed_size = header_val
        if decompressed_size == 0:
            return (
                b""
                if len(data) == 4
                else ValueError("decompressed size is zero but data is present.")
            )
        if decompressed_size < 0 or decompressed_size > 0x10000000:
            raise ValueError(f"invalid decompressed size: 0x{decompressed_size:x}")

        result = bytearray(decompressed_size)
        dst_offs = decompressed_size
        src_offs = len(data) - 4

        while dst_offs > 0:
            if src_offs <= 0:
                raise EOFError(f"mii source data exhausted (dst_offs={dst_offs})")
            block_header = data[src_offs - 1]
            src_offs -= 1
            for i in range(8):
                if dst_offs <= 0:
                    break
                if (block_header & 0x80) == 0:
                    if src_offs <= 0:
                        raise EOFError("mii source exhausted (literal)")
                    literal_byte = data[src_offs - 1]
                    src_offs -= 1
                    dst_offs -= 1
                    result[dst_offs] = literal_byte
                else:
                    if src_offs <= 1:
                        raise EOFError("mii source exhausted (lz77 block)")
                    byte1 = data[src_offs - 1]
                    byte2 = data[src_offs - 2]
                    src_offs -= 2
                    length = ((byte1 & 0xF0) >> 4) + 3
                    disp = (((byte1 & 0x0F) << 8) | byte2) + 1
                    if dst_offs < length:
                        raise ValueError(
                            f"mii lz77 copy length ({length}) exceeds dest space ({dst_offs})"
                        )
                    copy_src_base = dst_offs + disp
                    if copy_src_base < 0 or copy_src_base > decompressed_size:
                        raise ValueError(f"mii lz77 invalid displacement ({disp})")
                    for j in range(length):
                        current_copy_src = copy_src_base + j
                        if current_copy_src >= decompressed_size:
                            raise ValueError(
                                f"mii lz77 copy source offset {current_copy_src} out of bounds"
                            )
                        result[dst_offs - 1] = result[current_copy_src]
                        dst_offs -= 1
                        if dst_offs <= 0 and j < length - 1:
                            raise EOFError(
                                "mii destination filled unexpectedly during lz77 copy"
                            )
                block_header = (block_header << 1) & 0xFF
        if dst_offs != 0:
            self.log.log_warn(
                f"mii decompression: dst_offs non-zero ({dst_offs}) after loop."
            )
        return bytes(result)

    # --- symbol and tag definitions ---

    def _define_symbols_and_tags(self):
        """defines symbols and tags for known nds hardware registers and memory locations."""

        # define tag types first (will be cached in self._created_tag_types)
        tag_types = {
            "Display": "🖼️",
            "DMA": "➡️",
            "Timers": "⏱️",
            "Keypad": "🎮",
            "IPC": "↔️",
            "Gamecard": "💾",
            "Interrupts": "⚡",
            "Power": "🔋",
            "Memory Control": "🧠",
            "Math": "➗",
            "3D Engine": "🧊",
            "Sound": "🔊",
            "SPI": "〰️",
            "RTC": "🕒",
            "Wifi": "📡",
            "System": "⚙️",
            "ARM9 Specific": "9️⃣",
            "ARM7 Specific": "7️⃣",
            "Hardcoded Addr": "📍",
        }
        for name, icon in tag_types.items():
            self._get_or_create_tag_type(name, icon)

        # --- arm9 and arm7 common i/o registers ---
        self._define_reg_with_tag(
            0x4000004,
            "REG_DISPSTAT",
            "Display",
            tag_types["Display"],
            "display status (shared)",
        )
        self._define_reg_with_tag(
            0x4000006,
            "REG_VCOUNT",
            "Display",
            tag_types["Display"],
            "vertical counter (shared)",
        )
        for i in range(4):  # DMA
            dma_base = 0x40000B0 + i * 0xC
            self._define_reg_with_tag(
                dma_base + 0x0,
                f"REG_DMA{i}SAD",
                "DMA",
                tag_types["DMA"],
                f"dma {i} source address",
            )
            self._define_reg_with_tag(
                dma_base + 0x4,
                f"REG_DMA{i}DAD",
                "DMA",
                tag_types["DMA"],
                f"dma {i} destination address",
            )
            self._define_reg_with_tag(
                dma_base + 0x8,
                f"REG_DMA{i}CNT_L",
                "DMA",
                tag_types["DMA"],
                f"dma {i} word count",
            )
            self._define_reg_with_tag(
                dma_base + 0xA,
                f"REG_DMA{i}CNT_H",
                "DMA",
                tag_types["DMA"],
                f"dma {i} control",
            )
        for i in range(4):  # Timers
            tmr_base = 0x4000100 + i * 0x4
            self._define_reg_with_tag(
                tmr_base + 0x0,
                f"REG_TM{i}CNT_L",
                "Timers",
                tag_types["Timers"],
                f"timer {i} data/reload",
            )
            self._define_reg_with_tag(
                tmr_base + 0x2,
                f"REG_TM{i}CNT_H",
                "Timers",
                tag_types["Timers"],
                f"timer {i} control",
            )
        self._define_reg_with_tag(
            0x4000130, "REG_KEYINPUT", "Keypad", tag_types["Keypad"], "key status"
        )
        self._define_reg_with_tag(
            0x4000132,
            "REG_KEYCNT",
            "Keypad",
            tag_types["Keypad"],
            "key interrupt control",
        )
        self._define_reg_with_tag(
            0x4000180, "REG_IPCSYNC", "IPC", tag_types["IPC"], "ipc synchronize"
        )
        self._define_reg_with_tag(
            0x4000184, "REG_IPCFIFOCNT", "IPC", tag_types["IPC"], "ipc fifo control"
        )
        self._define_reg_with_tag(
            0x4000188,
            "REG_IPCFIFOSEND",
            "IPC",
            tag_types["IPC"],
            "ipc send fifo (write)",
        )
        self._define_reg_with_tag(
            0x4100000,
            "REG_IPCFIFORECV",
            "IPC",
            tag_types["IPC"],
            "ipc receive fifo (read)",
        )
        self._define_reg_with_tag(
            0x40001A0,
            "REG_AUXSPICNT",
            "Gamecard",
            tag_types["Gamecard"],
            "card spi control / rom control",
        )
        self._define_reg_with_tag(
            0x40001A2,
            "REG_AUXSPIDATA",
            "Gamecard",
            tag_types["Gamecard"],
            "card spi data",
        )
        self._define_reg_with_tag(
            0x40001A4,
            "REG_ROMCTRL",
            "Gamecard",
            tag_types["Gamecard"],
            "card bus timing/control (formerly romctrl)",
        )
        self._define_reg_with_tag(
            0x40001A8,
            "REG_CARDCMD",
            "Gamecard",
            tag_types["Gamecard"],
            "card command (8 bytes)",
        )
        self._define_reg_with_tag(
            0x4100010,
            "REG_CARDDATA",
            "Gamecard",
            tag_types["Gamecard"],
            "card data read fifo",
        )
        self._define_reg_with_tag(
            0x40001B0,
            "REG_CARD_SECKEY1_L",
            "Gamecard",
            tag_types["Gamecard"],
            "seed 0/key1 low",
        )
        self._define_reg_with_tag(
            0x40001B4,
            "REG_CARD_SECKEY2_L",
            "Gamecard",
            tag_types["Gamecard"],
            "seed 1/key2 low (if used)",
        )
        self._define_reg_with_tag(
            0x40001B8,
            "REG_CARD_SECKEY1_H",
            "Gamecard",
            tag_types["Gamecard"],
            "seed 0/key1 high (7 bits)",
        )
        self._define_reg_with_tag(
            0x40001BA,
            "REG_CARD_SECKEY2_H",
            "Gamecard",
            tag_types["Gamecard"],
            "seed 1/key2 high (7 bits)",
        )
        self._define_reg_with_tag(
            0x4000208,
            "REG_IME",
            "Interrupts",
            tag_types["Interrupts"],
            "interrupt master enable (0/1)",
        )
        self._define_reg_with_tag(
            0x4000210,
            "REG_IE",
            "Interrupts",
            tag_types["Interrupts"],
            "interrupt enable bits",
        )
        self._define_reg_with_tag(
            0x4000214,
            "REG_IF",
            "Interrupts",
            tag_types["Interrupts"],
            "interrupt request flags (write 1 to clear)",
        )
        self._define_reg_with_tag(
            0x4000300,
            "REG_POSTFLG",
            "System",
            tag_types["System"],
            "boot flag? undocumented",
        )
        self._define_reg_with_tag(
            0x4000301,
            "REG_HALTCNT",
            "Power",
            tag_types["Power"],
            "power down control (nds bits differ from gba)",
        )

        # --- arm9 specific i/o registers ---
        tag_name_a9 = "ARM9 Specific"
        tag_icon_a9 = tag_types[tag_name_a9]
        self._define_reg_with_tag(
            0x4000000,
            "REG_DISPCNT_A",
            "Display",
            tag_types["Display"],
            "display control (engine a)",
        )  # Also tag with A9?
        # ... (Define and tag all other Engine A registers similarly) ...
        self._define_reg_with_tag(
            0x400006C,
            "REG_MASTER_BRIGHT_A",
            "Display",
            tag_types["Display"],
            "master brightness (engine a)",
        )
        self._define_reg_with_tag(
            0x4000204,
            "REG_EXMEMCNT",
            "Memory Control",
            tag_types["Memory Control"],
            "external memory control (gba slot, etc.)",
        )
        # ... (Define and tag VRAM/WRAM control regs) ...
        self._define_reg_with_tag(
            0x4000249,
            "REG_VRAMCNT_I",
            "Memory Control",
            tag_types["Memory Control"],
            "vram bank i control",
        )
        # ... (Define and tag Math regs) ...
        self._define_reg_with_tag(
            0x40002BC,
            "REG_SQRT_PARAM_H",
            "Math",
            tag_types["Math"],
            "square root param (high 32)",
        )
        self._define_reg_with_tag(
            0x4000304,
            "REG_POWCNT1",
            "Power",
            tag_types["Power"],
            "graphics/system power control 1",
        )
        # Tag 3D Engine Region
        tag_type_3d = self._get_or_create_tag_type("3D Engine", tag_types["3D Engine"])
        if tag_type_3d:
            self.add_tag(0x4000320, tag_type_3d, "NDS 3D Registers Start")
            self.add_tag(0x40006A3, tag_type_3d, "NDS 3D Registers End")
        # ... (Define and tag Engine B regs) ...
        self._define_reg_with_tag(
            0x400106C,
            "REG_MASTER_BRIGHT_B",
            "Display",
            tag_types["Display"],
            "master brightness (engine b)",
        )

        # --- arm7 specific i/o registers ---
        tag_name_a7 = "ARM7 Specific"
        tag_icon_a7 = tag_types[tag_name_a7]
        self._define_reg_with_tag(
            0x4000120,
            "REG_SIODATA32",
            "System",
            tag_types["System"],
            "sio data 32bit (normal/multiplayer)",
        )
        self._define_reg_with_tag(
            0x4000128,
            "REG_SIOCNT",
            "System",
            tag_types["System"],
            "sio control (normal/multiplayer)",
        )
        self._define_reg_with_tag(
            0x4000134,
            "REG_RCNT",
            "System",
            tag_types["System"],
            "sio mode select / general purpose io",
        )
        self._define_reg_with_tag(
            0x4000138,
            "REG_RTCDATA",
            "RTC",
            tag_types["RTC"],
            "rtc data register (via spi)",
        )
        self._define_reg_with_tag(
            0x40001C0, "REG_SPICNT", "SPI", tag_types["SPI"], "spi control"
        )
        self._define_reg_with_tag(
            0x40001C2, "REG_SPIDATA", "SPI", tag_types["SPI"], "spi data"
        )
        self._define_reg_with_tag(
            0x4000204,
            "REG_EXMEMSTAT",
            "Memory Control",
            tag_types["Memory Control"],
            "external memory status (read only)",
        )
        self._define_reg_with_tag(
            0x4000240,
            "REG_VRAMSTAT",
            "Memory Control",
            tag_types["Memory Control"],
            "vram c,d bank status",
        )
        self._define_reg_with_tag(
            0x4000241,
            "REG_WRAMSTAT",
            "Memory Control",
            tag_types["Memory Control"],
            "wram bank status",
        )
        self._define_reg_with_tag(
            0x4000304,
            "REG_POWCNT2",
            "Power",
            tag_types["Power"],
            "sound/wifi power control 2",
        )
        self._define_reg_with_tag(
            0x4000308,
            "REG_BIOSPROT",
            "System",
            tag_types["System"],
            "bios write protection",
        )
        # ... (Define and tag Sound regs) ...
        self._define_reg_with_tag(
            0x400051C, "REG_SNDCAP1LEN", "Sound", tag_types["Sound"], "capture 1 length"
        )
        # Tag Wifi Region
        tag_type_wifi = self._get_or_create_tag_type("Wifi", tag_types["Wifi"])
        if tag_type_wifi:
            self.add_tag(0x4800000, tag_type_wifi, "NDS Wifi Region Start")
            self.add_tag(0x480FFFF, tag_type_wifi, "NDS Wifi Region End")

        # --- hardcoded ram addresses ---
        tag_name_hc = "Hardcoded Addr"
        tag_icon_hc = tag_types[tag_name_hc]
        self._define_reg_with_tag(
            0x0380FFF8,
            "NDS7_IRQ_CHECKBITS",
            tag_name_hc,
            tag_icon_hc,
            "arm7 irq 'if' check bits mirror?",
        )
        self._define_reg_with_tag(
            0x0380FFFC,
            "NDS7_IRQ_HANDLER_PTR",
            tag_name_hc,
            tag_icon_hc,
            "arm7 pointer to irq handler",
        )
        self._define_reg_with_tag(
            0x027FFFFE, "MAIN_MEM_CNT", tag_name_hc, tag_icon_hc, "main memory control?"
        )

    # --- overridden methods ---
    def perform_is_executable(self) -> bool:
        return True

    def perform_get_entry_point(self) -> int:
        return self.nds_rom.header.arm9_entry_address if self.nds_rom else 0

    def perform_get_address_size(self) -> int:
        return 4


# register the view type with binary ninja
NDSView.register()
