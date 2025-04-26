import io
import struct
import traceback

# import necessary types from binaryninja for type hinting
from typing import Optional, List, Tuple, Generator, Mapping, Callable, Union

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
    Endianness,
    FunctionGraphType,
    DisassemblySettings,
    LinearViewCursor,
    LinearDisassemblyLine,
    InstructionTextToken,
    Function,
    BasicBlock,
    Section,
    Segment,
    CoreSymbol,
    QualifiedName,
    RegisterValueType,
    PossibleValueSet,
    StringType,
    ModificationStatus,
    AddressRange,
    TypeParserResult,
    TypeContainer,
    TypeLibrary,
    Workflow,
    Project,
    ProjectFile,
    SaveSettings,
    Component,
    ExternalLibrary,
    ExternalLocation,
    DebugInfo,
    UndoEntry,
    Settings,
    NameSpace,
    TypeFieldReference,
    TypeReferenceSource,
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
                # log_info("[NDS] Data too short for basic validation.") # Can be noisy
                return False

            # --- Basic Heuristic Check ---
            # Check the first few bytes of the Nintendo logo at 0xC0
            # Expected bytes: 24 ff ae 51
            if header_start[0xC0:0xC4] == b"\x24\xff\xae\x51":
                # log_info("[NDS] Nintendo Logo prefix matches. Tentatively valid.")
                return True  # Assume valid for now, full check in init()
            else:
                # log_warn(f"[NDS] Nintendo Logo prefix mismatch. Expected 24ffae51, got {header_start[0xC0:0xC4].hex()}.")
                return False
            # --- End Basic Heuristic Check ---

        except Exception as e:
            # log potential errors during validation
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
            self.log.log_info("reading entire rom into memory...")
            # --- workaround for unmodified ndsromreader ---
            # read the entire rom content into memory because ndsromreader expects bytes,
            # not a binaryview object. this might be memory intensive for large roms.
            rom_length = self.raw.length
            rom_data_bytes: bytes = self.raw.read(0, rom_length)
            if not rom_data_bytes or len(rom_data_bytes) != rom_length:
                self.log.log_error(
                    f"failed to read full rom data ({len(rom_data_bytes)} read vs {rom_length} expected) from parent view."
                )
                return False
            # ---------------------------------------------

            # --- Perform Full Validation Here ---
            self.log.log_info("performing full header validation...")
            if not NDSRomReader.is_valid(rom_data_bytes[:0x160]):
                # The print statements inside NDSRomReader.is_valid will indicate the failure reason
                self.log.log_error(
                    "full header validation failed via ndsromreader.is_valid."
                )
                # Optionally, decide if you want to continue loading anyway for potentially corrupt/hacked ROMs
                # return False # Strict: Fail loading if CRC is bad
                self.log.log_warn(
                    "continuing load despite header validation failure."
                )  # Lenient: Log warning and continue
            else:
                self.log.log_info("full header validation successful.")
            # ------------------------------------

            self.log.log_info("parsing nds rom structure using ndsromreader...")
            # pass the bytes object to the unmodified reader
            self.nds_rom = NDSRomReader.read(rom_data_bytes)

            if not self.nds_rom:
                self.log.log_error(
                    "failed to parse nds rom header and structures (NDSRomReader.read returned None)."
                )
                return False

            # set architecture and platform
            # nds uses armv5te (arm946e-s) and armv4t (arm7tdmi)
            # binja maps armv4t/armv5te to armv7 architecture profile in many cases
            # we'll stick with armv7 for broad compatibility but be aware of the nuances
            self.arch: Architecture = Architecture["armv7"]  # type: ignore
            # use standalone platform, as nds has its own os/firmware environment
            self.platform: Platform = Architecture["armv7"].standalone_platform  # type: ignore

            self.log.log_info("mapping nds memory segments...")
            self._map_memory_segments()

            self.log.log_info("loading arm9 binary...")
            # enable decompression by default now
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

            self.log.log_info("defining nds hardware symbols...")
            self._define_symbols()

            self.log.log_info("nds rom loading complete.")
            # returning true signals successful initialization to binary ninja
            return True
        except Exception as e:  # catch specific exceptions if possible
            self.log.log_error(f"failed to initialize ndsview: {e}")
            self.log.log_error(traceback.format_exc())
            # returning false signals failure
            return False

    # --- helper methods ---

    def _define_reg(self, address: int, name: str, description: str = ""):
        """helper to define a data symbol for a hardware register."""
        # use define_auto_symbol for loader-defined symbols
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))  # type: ignore
        if description:
            # add comments for better understanding in the ui
            self.set_comment_at(address, description)

    # --- memory mapping ---

    def _map_memory_segments(self):
        """maps the core nds memory regions."""

        # main memory (4mb)
        self.add_auto_segment(0x02000000, 0x00400000, 0, 0, self.RWX_FLAGS)

        # shared wram (32kb max) - mapped to arm9/arm7 depending on reg_wramcnt
        # map the full potential region, actual access depends on runtime config
        self.add_auto_segment(0x03000000, 0x00008000, 0, 0, self.RWX_FLAGS)
        # also map the common mirror used (especially by arm7)
        self.add_auto_segment(0x037F8000, 0x00008000, 0, 0, self.RWX_FLAGS)

        # arm7 wram (64kb) - typically accessed via 0x03800000 mirror
        self.add_auto_segment(0x03800000, 0x00010000, 0, 0, self.RWX_FLAGS)

        # i/o registers (mapped read/write, no execute)
        # covers both arm9 and arm7 i/o ranges, specific registers defined later
        self.add_auto_segment(0x04000000, 0x00001000, 0, 0, self.RW_FLAGS)
        self.add_auto_segment(0x040001A0, 0x000000C0, 0, 0, self.RW_FLAGS)
        self.add_auto_segment(0x04000200, 0x00000100, 0, 0, self.RW_FLAGS)
        self.add_auto_segment(0x04000300, 0x00000100, 0, 0, self.RW_FLAGS)
        self.add_auto_segment(0x04000400, 0x00000200, 0, 0, self.RW_FLAGS)
        self.add_auto_segment(0x04001000, 0x00000100, 0, 0, self.RW_FLAGS)
        # ipc fifos (separate range)
        self.add_auto_segment(0x04100000, 0x00000020, 0, 0, self.RW_FLAGS)

        # palette ram (4kb total: 2k bg/obj a, 2k bg/obj b)
        self.add_auto_segment(0x05000000, 0x00001000, 0, 0, self.RW_FLAGS)

        # vram (656kb total, mapping simplified here)
        # actual mapping depends on vramcnt registers (a-i)
        # map the entire potential range for simplicity
        self.add_auto_segment(0x06000000, 0x000A4000, 0, 0, self.RW_FLAGS)
        # specific common mappings (can be refined based on vramcnt analysis)
        self.add_auto_segment(0x06800000, 0x000A4000, 0, 0, self.RW_FLAGS)

        # oam (object attribute memory) (4kb total: 2k eng a, 2k eng b)
        self.add_auto_segment(0x07000000, 0x00001000, 0, 0, self.RW_FLAGS)

        # bios regions (read/execute)
        self.add_auto_segment(0xFFFF0000, 0x00004000, 0, 0, self.RX_FLAGS)
        # arm7 bios is at 0x00000000, usually overlaid by ram, but define for completeness if needed
        # self.add_auto_segment(0x00000000, 0x00004000, 0, 0, self.RX_FLAGS)

        # note: gba slot rom/ram (0x08000000, 0x0a000000) are not typically mapped by default
        # unless analyzing a specific gba mode interaction or expansion pak.

        # note: tcm (0x00000000 instruction, 0x0xxxx000 data) is complex to map statically
        # as the data tcm is movable. skipping static mapping for now.

    # --- binary loading ---

    def _init_arm9(self, try_decompress=True):
        """loads the main arm9 binary, optionally decompressing it."""
        if not self.nds_rom:
            return  # should not happen if init succeeded

        header = self.nds_rom.header
        # read the raw arm9 data from the rom view (self.raw is the binaryview)
        # header.arm9_size is the size in rom, which might be compressed
        arm9_data_raw: bytes = self.raw.read(header.arm9_rom_offset, header.arm9_size)
        if not arm9_data_raw:
            self.log.log_error(
                f"failed to read arm9 data from rom offset 0x{header.arm9_rom_offset:x}"
            )
            return

        arm9_data_loaded = arm9_data_raw
        decompressed = False
        if (
            try_decompress and header.arm9_size > 0
        ):  # don't try to decompress empty data
            try:
                # attempt decompression
                decompressed_data = self._mii_uncompress_backward(arm9_data_raw)
                # basic validation: check if decompressed size is plausible
                # a simple check is if it's significantly larger than original.
                if len(decompressed_data) > len(arm9_data_raw):
                    # more specific check: nds binaries often store compressed size info
                    # in a nitrobinaryfooter or similar structure near the end.
                    # this is heuristic without parsing the full footer.
                    arm9_data_loaded = decompressed_data
                    decompressed = True
                    self.log.log_info(
                        f"decompressed arm9: {len(arm9_data_raw)} bytes -> {len(decompressed_data)} bytes"
                    )
                else:
                    # if decompressed size isn't larger, assume it wasn't compressed
                    self.log.log_info(
                        "arm9 appears uncompressed (decompressed size not larger)."
                    )

            except ValueError as e:
                # valueerror often indicates bad footer/size info in _mii_uncompress_backward
                self.log.log_warn(
                    f"arm9 decompression failed (invalid data/footer?): {e}. using raw data."
                )
            except EOFError as e:
                # eoferror indicates data exhaustion during decompression
                self.log.log_warn(
                    f"arm9 decompression failed (data exhausted?): {e}. using raw data."
                )
            except Exception as e:
                self.log.log_warn(
                    f"arm9 decompression failed (generic error): {e}. using raw data."
                )
                # continue with original data if decompression fails

        # add segment for arm9 code/data
        # use file offset 0 because we are providing the data directly via self.write
        # the size of the segment should be the size of the *loaded* data (decompressed or raw)
        loaded_size = len(arm9_data_loaded)
        # add_auto_segment takes 6 args: start, length, data_offset, data_length, flags
        self.add_auto_segment(
            header.arm9_ram_address,
            loaded_size,
            0,  # file offset 0 for data provided via write()
            loaded_size,
            self.RX_FLAGS,  # mark as read-execute initially
        )
        # write the (potentially decompressed) data to the segment
        self.write(header.arm9_ram_address, arm9_data_loaded)

        # define entry point
        self.add_entry_point(header.arm9_entry_address)
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, header.arm9_entry_address, "_start9")
        )  # type: ignore
        # add function for analysis start
        self.add_function(header.arm9_entry_address)

        self.log.log_info(
            f"arm9 loaded: entry=0x{header.arm9_entry_address:08x}, load=0x{header.arm9_ram_address:08x}, "
            f"size=0x{loaded_size:x}, offset=0x{header.arm9_rom_offset:08x} {'(decompressed)' if decompressed else ''}"
        )

        # handle arm9 bss
        # requires parsing nitrobinaryfooter (autoloader params) at the end of the loaded arm9 data
        # footer offset = arm9_ram_address + loaded_size - sizeof(footer)
        # bss_start = footer.bss_start_offset + arm9_ram_address
        # bss_end = footer.bss_end_offset + arm9_ram_address
        # if bss_start < bss_end: map segment [bss_start, bss_end - bss_start] as rw
        self.log.log_warn(
            "arm9 bss size/location not determined, requires parsing autoloader params. skipping bss mapping."
        )
        # TODO: implement parsing of autoloader params (nitrobinaryfooter)

    def _init_arm7(self):
        """loads the main arm7 binary."""
        if not self.nds_rom:
            return

        header = self.nds_rom.header
        if header.arm7_size == 0:
            self.log.log_info("arm7 size is 0, skipping loading.")
            return

        # read arm7 data from the rom view (self.raw is the binaryview)
        arm7_data: bytes = self.raw.read(header.arm7_rom_offset, header.arm7_size)
        if not arm7_data:
            self.log.log_error(
                f"failed to read arm7 data from rom offset 0x{header.arm7_rom_offset:x}"
            )
            return

        # add segment for arm7 code/data
        # use file offset 0 because we are providing the data directly via self.write
        loaded_size = len(arm7_data)
        self.add_auto_segment(
            header.arm7_ram_address,
            loaded_size,  # use actual data length read
            0,  # file offset 0 for data provided via write()
            loaded_size,
            self.RX_FLAGS,  # mark as read-execute initially
        )
        # write the data to the segment
        self.write(header.arm7_ram_address, arm7_data)

        # define entry point
        self.add_entry_point(header.arm7_entry_address)
        self.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, header.arm7_entry_address, "_start7")
        )  # type: ignore
        # add function for analysis start
        self.add_function(header.arm7_entry_address)

        self.log.log_info(
            f"arm7 loaded: entry=0x{header.arm7_entry_address:08x}, load=0x{header.arm7_ram_address:08x}, "
            f"size=0x{loaded_size:x}, offset=0x{header.arm7_rom_offset:08x}"
        )
        # TODO: handle arm7 bss if information becomes available (e.g., via autoloader params)

    def _init_debug_arm9(self):
        """loads the debug arm9 binary if present."""
        if not self.nds_rom:
            return

        header = self.nds_rom.header
        # check header fields for debug info (already checked before calling)

        # read debug arm9 data from the rom view (self.raw is the binaryview)
        debug_data: bytes = self.raw.read(header.debug_rom_offset, header.debug_size)
        if not debug_data:
            self.log.log_error(
                f"failed to read debug arm9 data from rom offset 0x{header.debug_rom_offset:x}"
            )
            return

        # default debug ram address if not specified (though usually it is)
        load_address = header.debug_ram_address
        if load_address == 0:
            # common debug ram start, but header should be trusted if non-zero
            load_address = 0x02400000
            self.log.log_warn(
                f"debug ram address is 0 in header, using default 0x{load_address:08x}"
            )

        # add segment for debug arm9 code/data
        loaded_size = len(debug_data)
        self.add_auto_segment(
            load_address,
            loaded_size,
            0,  # file offset 0 for data provided via write()
            loaded_size,
            self.RX_FLAGS,  # mark as read-execute initially
        )
        # write the data to the segment
        self.write(load_address, debug_data)

        # typically, no separate entry point is defined for the debug binary in the header
        # it might be jumped to manually or via hooks

        self.log.log_info(
            f"debug arm9 loaded: load=0x{load_address:08x}, size=0x{loaded_size:x}, offset=0x{header.debug_rom_offset:08x}"
        )

    def _load_overlays(self, cpu_name: str, overlay_table: Optional[NDSOverlayTable]):
        """loads arm9 or arm7 overlays."""
        if not self.nds_rom:
            return
        if not overlay_table or not overlay_table.entries:
            # self.log.log_info(f"no {cpu_name} overlays found or table is empty.") # too verbose
            return

        num_loaded = 0
        num_failed = 0
        for i, entry in enumerate(overlay_table.entries):
            # basic validation of overlay entry
            # file id 0xffff is sometimes used as a terminator/placeholder
            if entry.file_id == 0xFFFF or entry.file_id >= len(
                self.nds_rom.fat_entries
            ):
                # self.log.log_warn(f"skipping invalid {cpu_name} overlay {i}: invalid file id {entry.file_id}")
                continue  # skip invalid file ids silently

            if entry.ram_size == 0 and entry.bss_size == 0:
                # self.log.log_warn(f"skipping empty {cpu_name} overlay {i} (file id {entry.file_id}): ram and bss size are 0")
                continue  # skip empty overlays silently

            # get file location from fat
            fat_entry = self.nds_rom.fat_entries[entry.file_id]
            if fat_entry.start_address >= fat_entry.end_address:
                self.log.log_warn(
                    f"skipping invalid {cpu_name} overlay {i} (file id {entry.file_id}): fat entry invalid (start >= end)."
                )
                num_failed += 1
                continue

            overlay_size_in_rom = fat_entry.end_address - fat_entry.start_address
            if overlay_size_in_rom <= 0:
                self.log.log_warn(
                    f"skipping invalid {cpu_name} overlay {i} (file id {entry.file_id}): non-positive size in rom ({overlay_size_in_rom})."
                )
                num_failed += 1
                continue

            # read overlay data from rom view (self.raw is the binaryview)
            overlay_data_raw: bytes = self.raw.read(
                fat_entry.start_address, overlay_size_in_rom
            )
            if not overlay_data_raw:
                self.log.log_error(
                    f"failed to read {cpu_name} overlay {i} (file id {entry.file_id}) data from rom offset 0x{fat_entry.start_address:x}"
                )
                num_failed += 1
                continue

            # decompress overlay data (assuming mii compression)
            # overlays are almost always compressed if ram_size > 0
            loaded_data = b""
            segment_ram_size = 0
            decompressed = False
            if entry.ram_size > 0:
                try:
                    # only attempt decompression if ram_size > 0
                    decompressed_data = self._mii_uncompress_backward(overlay_data_raw)
                    # sanity check decompressed size against expected ram size
                    if len(decompressed_data) != entry.ram_size:
                        self.log.log_warn(
                            f"{cpu_name} overlay {i} (file id {entry.file_id}): decompressed size {len(decompressed_data):x} != expected ram size {entry.ram_size:x}. using decompressed size."
                        )
                        # use the actual decompressed size for the segment
                        segment_ram_size = len(decompressed_data)
                    else:
                        segment_ram_size = entry.ram_size

                    loaded_data = decompressed_data
                    decompressed = True
                except Exception as e:
                    self.log.log_warn(
                        f"failed to decompress {cpu_name} overlay {i} (file id {entry.file_id}): {e}. trying to load as uncompressed."
                    )
                    # if decompression fails, assume it might be uncompressed (less common for overlays)
                    if overlay_size_in_rom != entry.ram_size:
                        self.log.log_warn(
                            f"{cpu_name} overlay {i} (file id {entry.file_id}): uncompressed size {overlay_size_in_rom:x} != expected ram size {entry.ram_size:x}. using rom size."
                        )
                        segment_ram_size = overlay_size_in_rom
                    else:
                        segment_ram_size = entry.ram_size
                    loaded_data = overlay_data_raw  # use the raw data
            else:
                # if ram_size is 0, there's no compressed data part, only bss
                segment_ram_size = 0
                loaded_data = b""

            # add segment for the overlay's code/data section (if size > 0)
            segment_name = f"{cpu_name}_Overlay_{i}_File{entry.file_id}"
            if segment_ram_size > 0:
                self.add_auto_segment(
                    entry.ram_address,
                    segment_ram_size,
                    0,  # file offset 0 for data provided via write()
                    segment_ram_size,
                    self.RX_FLAGS,  # overlays are typically code/rodata
                )
                # write the loaded data to the segment
                self.write(
                    entry.ram_address, loaded_data[:segment_ram_size]
                )  # ensure we don't write past segment boundary
            else:
                # still log if we skipped the code segment because size was 0
                # self.log.log_info(f"{cpu_name} overlay {i} (file id {entry.file_id}): code/data size is 0.")
                pass

            # handle bss section for the overlay
            if entry.bss_size > 0:
                # bss starts right after the code/data section in ram
                bss_start_address = entry.ram_address + segment_ram_size
                self.add_auto_segment(
                    bss_start_address,
                    entry.bss_size,
                    0,
                    0,  # bss has no file data
                    self.RW_FLAGS,  # bss is rw, no execute
                )
                # bss is implicitly zero-filled by binary ninja when no data is provided

            # add comment at the start of the overlay's ram region
            self.set_comment_at(
                entry.ram_address,
                f"{cpu_name} overlay {i} (file id: {entry.file_id}){' (decompressed)' if decompressed else ''}",
            )

            # define function for static initializer if present
            if entry.static_initializer_start_address != 0:
                init_start = entry.static_initializer_start_address
                # adjust thumb address if necessary (initializers are often thumb)
                func_addr = init_start
                if func_addr & 1:
                    func_addr = (
                        func_addr - 1
                    )  # ensure word alignment for function start
                    # TODO: set thumb mode for this function if possible via api?
                    #       requires function object, might need to call add_function first, then set mode

                self.add_function(func_addr)
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, func_addr, f"{segment_name}_Init")
                )  # type: ignore
                self.set_comment_at(
                    func_addr, f"{cpu_name} overlay {i} static initializer"
                )

            num_loaded += 1

        log_func = self.log.log_info if num_failed == 0 else self.log.log_warn
        log_func(
            f"loaded {num_loaded} / {len(overlay_table.entries)} {cpu_name} overlays ({num_failed} failures)."
        )

    def _mii_uncompress_backward(self, data: bytes) -> bytes:
        """decompresses data using mii lz77 variant (backward)."""
        # basic check for minimum size (need footer)
        if len(data) < 4:
            raise ValueError("data too short for mii decompression footer")

        # --- footer parsing ---
        # common format: last 4 bytes contain header/size info.
        # bits 0-23: decompressed size
        # bits 24-27: compression type (0x1 for lz77)
        # bits 28-31: reserved? or part of size? gbatek says "data size" (32bit)
        # let's assume the last 4 bytes are the header, containing the size.
        footer = data[-4:]
        header_val = struct.unpack_from("<I", footer, 0)[0]

        # try extracting size assuming standard lz77 header type 0x10
        comp_type = (header_val >> 24) & 0xF
        if comp_type == 1:  # lz77 type
            decompressed_size = header_val & 0xFFFFFF
        else:
            # if type is not 0x1, maybe the whole dword is the size?
            # this happens in some overlay implementations.
            decompressed_size = header_val
            # log_warn(f"mii decompression: unknown compression type {comp_type}, assuming full dword is size.")

        # plausibility check for size
        if decompressed_size == 0:
            # allow zero size for potentially empty overlays? or raise error?
            # let's return empty bytes if size is 0, might happen for pure bss overlays
            # if data only contains the footer, this is valid.
            if len(data) == 4:
                return b""
            else:
                raise ValueError(
                    "mii decompression: decompressed size is zero but data is present."
                )
        if (
            decompressed_size < 0 or decompressed_size > 0x10000000
        ):  # sanity limit (256mb)
            raise ValueError(
                f"mii decompression: invalid or unreasonable decompressed size in footer: 0x{decompressed_size:x}"
            )

        # --- decompression loop ---
        result = bytearray(decompressed_size)
        dst_offs = decompressed_size  # current write position in result (counts down)
        src_offs = (
            len(data) - 4
        )  # current read position in data (counts down from end of stream)

        while dst_offs > 0:
            # check if source data is exhausted prematurely
            if src_offs <= 0:
                raise EOFError(
                    f"mii source data exhausted before destination filled (dst_offs={dst_offs}). size mismatch or corrupt data?"
                )

            # read header byte for the next 8 blocks
            block_header = data[src_offs - 1]
            src_offs -= 1

            for i in range(8):
                if dst_offs <= 0:
                    break  # decompression finished

                if (block_header & 0x80) == 0:  # type 0: literal byte
                    if src_offs <= 0:
                        raise EOFError(
                            "mii source data exhausted unexpectedly (literal)"
                        )
                    # copy literal byte from source to destination
                    literal_byte = data[src_offs - 1]
                    src_offs -= 1
                    dst_offs -= 1
                    result[dst_offs] = literal_byte
                else:  # type 1: lz77 compression block (length/displacement)
                    if src_offs <= 1:
                        raise EOFError(
                            "mii source data exhausted unexpectedly (lz77 block)"
                        )
                    # read the 2-byte block info
                    byte1 = data[src_offs - 1]
                    byte2 = data[src_offs - 2]
                    src_offs -= 2

                    # calculate displacement and length
                    # format (nds): ddddllll dddddddd (d=disp high nibble, l=length-3, d=disp low byte)
                    length = (
                        (byte1 & 0xF0) >> 4
                    ) + 3  # length of data to copy (3 to 18)
                    disp = (
                        ((byte1 & 0x0F) << 8) | byte2
                    ) + 1  # displacement (1 to 4096) relative to current output pos

                    # check if copy operation is valid
                    if dst_offs < length:
                        raise ValueError(
                            f"mii lz77 copy length ({length}) exceeds remaining destination space ({dst_offs})"
                        )

                    # copy bytes from already decompressed part of the buffer
                    copy_src_base = (
                        dst_offs + disp
                    )  # where to start copying *from* in the result buffer
                    if (
                        copy_src_base < 0 or copy_src_base > decompressed_size
                    ):  # check base offset
                        raise ValueError(
                            f"mii lz77 invalid displacement ({disp}), calculated source base offset {copy_src_base} out of bounds"
                        )

                    # perform the backward copy
                    for j in range(length):
                        # check bounds before accessing result - paranoia check
                        # the copy source offset needs to be checked against the *current* length of the result buffer
                        # since we are writing backwards, the valid source range is [dst_offs, decompressed_size)
                        current_copy_src = (
                            copy_src_base + j
                        )  # absolute position in result buffer to copy from

                        if (
                            current_copy_src < 0
                            or current_copy_src >= decompressed_size
                        ):
                            raise ValueError(
                                f"mii lz77 copy source offset {current_copy_src} went out of bounds during copy loop"
                            )

                        # write destination byte (counting down)
                        result[dst_offs - 1] = result[current_copy_src]
                        dst_offs -= 1
                        if dst_offs <= 0 and j < length - 1:
                            # check if we finished writing before finishing copying
                            raise EOFError(
                                "mii destination filled unexpectedly during lz77 copy loop"
                            )

                # move to the next bit in the block header
                block_header = (block_header << 1) & 0xFF

        # final check: if dst_offs is not 0, something went wrong
        if dst_offs != 0:
            self.log.log_warn(
                f"mii decompression: destination offset non-zero ({dst_offs}) after loop. data might be incomplete or size incorrect."
            )

        return bytes(result)

    # --- symbol definitions ---

    def _define_symbols(self):
        """defines symbols for known nds hardware registers and memory locations."""

        # --- arm9 and arm7 common i/o registers ---
        self._define_reg(0x4000004, "REG_DISPSTAT", "display status (shared)")
        self._define_reg(0x4000006, "REG_VCOUNT", "vertical counter (shared)")

        # dma (shared channels 0-3)
        for i in range(4):
            dma_base = 0x40000B0 + i * 0xC
            self._define_reg(
                dma_base + 0x0, f"REG_DMA{i}SAD", f"dma {i} source address"
            )
            self._define_reg(
                dma_base + 0x4, f"REG_DMA{i}DAD", f"dma {i} destination address"
            )
            self._define_reg(dma_base + 0x8, f"REG_DMA{i}CNT_L", f"dma {i} word count")
            self._define_reg(dma_base + 0xA, f"REG_DMA{i}CNT_H", f"dma {i} control")

        # dma fill registers (arm9 only?) - documentation is ambiguous, assume arm9 for now
        # self._define_reg(0x40000e0, "reg_dma0fill") # seems these might not exist or are arm9 specific internal?
        # ... dma1fill, dma2fill, dma3fill ...

        # timers (shared channels 0-3)
        for i in range(4):
            tmr_base = 0x4000100 + i * 0x4
            self._define_reg(
                tmr_base + 0x0, f"REG_TM{i}CNT_L", f"timer {i} data/reload"
            )
            self._define_reg(tmr_base + 0x2, f"REG_TM{i}CNT_H", f"timer {i} control")

        # keypad input (shared)
        self._define_reg(0x4000130, "REG_KEYINPUT", "key status")
        self._define_reg(0x4000132, "REG_KEYCNT", "key interrupt control")

        # ipc (inter-processor communication) (shared registers)
        self._define_reg(0x4000180, "REG_IPCSYNC", "ipc synchronize")
        self._define_reg(0x4000184, "REG_IPCFIFOCNT", "ipc fifo control")
        self._define_reg(0x4000188, "REG_IPCFIFOSEND", "ipc send fifo (write)")
        self._define_reg(0x4100000, "REG_IPCFIFORECV", "ipc receive fifo (read)")

        # game card bus control (shared registers)
        self._define_reg(0x40001A0, "REG_AUXSPICNT", "card spi control / rom control")
        self._define_reg(0x40001A2, "REG_AUXSPIDATA", "card spi data")
        self._define_reg(
            0x40001A4, "REG_ROMCTRL", "card bus timing/control (formerly romctrl)"
        )
        self._define_reg(0x40001A8, "REG_CARDCMD", "card command (8 bytes)")
        # gamecard data in (manual/dma read)
        self._define_reg(0x4100010, "REG_CARDDATA", "card data read fifo")

        # game card encryption seeds (shared?) - usually set up by arm9
        self._define_reg(0x40001B0, "REG_CARD_SECKEY1_L", "seed 0/key1 low")
        self._define_reg(0x40001B4, "REG_CARD_SECKEY2_L", "seed 1/key2 low (if used)")
        self._define_reg(0x40001B8, "REG_CARD_SECKEY1_H", "seed 0/key1 high (7 bits)")
        self._define_reg(0x40001BA, "REG_CARD_SECKEY2_H", "seed 1/key2 high (7 bits)")

        # interrupt control (shared registers, but separate ie/if bits for each cpu)
        self._define_reg(0x4000208, "REG_IME", "interrupt master enable (0/1)")
        self._define_reg(0x4000210, "REG_IE", "interrupt enable bits")
        self._define_reg(
            0x4000214, "REG_IF", "interrupt request flags (write 1 to clear)"
        )

        # power control / system (shared)
        self._define_reg(0x4000300, "REG_POSTFLG", "boot flag? undocumented")
        self._define_reg(
            0x4000301, "REG_HALTCNT", "power down control (nds bits differ from gba)"
        )

        # --- arm9 specific i/o registers ---
        # display engine a (main screen)
        self._define_reg(0x4000000, "REG_DISPCNT_A", "display control (engine a)")
        self._define_reg(0x4000008, "REG_BG0CNT_A", "bg0 control (engine a)")
        self._define_reg(0x400000A, "REG_BG1CNT_A", "bg1 control (engine a)")
        self._define_reg(0x400000C, "REG_BG2CNT_A", "bg2 control (engine a)")
        self._define_reg(0x400000E, "REG_BG3CNT_A", "bg3 control (engine a)")
        self._define_reg(0x4000010, "REG_BG0HOFS_A", "bg0 h-offset (engine a)")
        self._define_reg(0x4000012, "REG_BG0VOFS_A", "bg0 v-offset (engine a)")
        self._define_reg(0x4000014, "REG_BG1HOFS_A", "bg1 h-offset (engine a)")
        self._define_reg(0x4000016, "REG_BG1VOFS_A", "bg1 v-offset (engine a)")
        self._define_reg(0x4000018, "REG_BG2HOFS_A", "bg2 h-offset (engine a)")
        self._define_reg(0x400001A, "REG_BG2VOFS_A", "bg2 v-offset (engine a)")
        self._define_reg(0x400001C, "REG_BG3HOFS_A", "bg3 h-offset (engine a)")
        self._define_reg(0x400001E, "REG_BG3VOFS_A", "bg3 v-offset (engine a)")
        self._define_reg(0x4000020, "REG_BG2PA_A", "bg2 rotation/scaling pa (engine a)")
        self._define_reg(0x4000022, "REG_BG2PB_A", "bg2 rotation/scaling pb (engine a)")
        self._define_reg(0x4000024, "REG_BG2PC_A", "bg2 rotation/scaling pc (engine a)")
        self._define_reg(0x4000026, "REG_BG2PD_A", "bg2 rotation/scaling pd (engine a)")
        self._define_reg(
            0x4000028, "REG_BG2X_L_A", "bg2 reference point x-coord low (engine a)"
        )
        self._define_reg(
            0x400002A, "REG_BG2X_H_A", "bg2 reference point x-coord high (engine a)"
        )
        self._define_reg(
            0x400002C, "REG_BG2Y_L_A", "bg2 reference point y-coord low (engine a)"
        )
        self._define_reg(
            0x400002E, "REG_BG2Y_H_A", "bg2 reference point y-coord high (engine a)"
        )
        self._define_reg(0x4000030, "REG_BG3PA_A", "bg3 rotation/scaling pa (engine a)")
        self._define_reg(0x4000032, "REG_BG3PB_A", "bg3 rotation/scaling pb (engine a)")
        self._define_reg(0x4000034, "REG_BG3PC_A", "bg3 rotation/scaling pc (engine a)")
        self._define_reg(0x4000036, "REG_BG3PD_A", "bg3 rotation/scaling pd (engine a)")
        self._define_reg(
            0x4000038, "REG_BG3X_L_A", "bg3 reference point x-coord low (engine a)"
        )
        self._define_reg(
            0x400003A, "REG_BG3X_H_A", "bg3 reference point x-coord high (engine a)"
        )
        self._define_reg(
            0x400003C, "REG_BG3Y_L_A", "bg3 reference point y-coord low (engine a)"
        )
        self._define_reg(
            0x400003E, "REG_BG3Y_H_A", "bg3 reference point y-coord high (engine a)"
        )
        self._define_reg(
            0x4000040, "REG_WIN0H_A", "window 0 horizontal bounds (engine a)"
        )
        self._define_reg(
            0x4000042, "REG_WIN1H_A", "window 1 horizontal bounds (engine a)"
        )
        self._define_reg(
            0x4000044, "REG_WIN0V_A", "window 0 vertical bounds (engine a)"
        )
        self._define_reg(
            0x4000046, "REG_WIN1V_A", "window 1 vertical bounds (engine a)"
        )
        self._define_reg(0x4000048, "REG_WININ_A", "inside window control (engine a)")
        self._define_reg(0x400004A, "REG_WINOUT_A", "outside window control (engine a)")
        self._define_reg(0x400004C, "REG_MOSAIC_A", "mosaic size (engine a)")
        self._define_reg(
            0x4000050, "REG_BLDCNT_A", "color special effects control (engine a)"
        )
        self._define_reg(
            0x4000052, "REG_BLDALPHA_A", "alpha blending coefficients (engine a)"
        )
        self._define_reg(0x4000054, "REG_BLDY_A", "brightness coefficient (engine a)")

        self._define_reg(0x4000060, "REG_DISP3DCNT", "3d layer control")
        self._define_reg(0x4000064, "REG_DISPCAPCNT", "display capture control")
        self._define_reg(0x4000068, "REG_DISP_MMEM_FIFO", "main memory display fifo")
        self._define_reg(
            0x400006C, "REG_MASTER_BRIGHT_A", "master brightness (engine a)"
        )

        # memory control (arm9)
        self._define_reg(
            0x4000204, "REG_EXMEMCNT", "external memory control (gba slot, etc.)"
        )
        # vram control (write only)
        self._define_reg(0x4000240, "REG_VRAMCNT_A", "vram bank a control")
        self._define_reg(0x4000241, "REG_VRAMCNT_B", "vram bank b control")
        self._define_reg(0x4000242, "REG_VRAMCNT_C", "vram bank c control")
        self._define_reg(0x4000243, "REG_VRAMCNT_D", "vram bank d control")
        self._define_reg(0x4000244, "REG_VRAMCNT_E", "vram bank e control")
        self._define_reg(0x4000245, "REG_VRAMCNT_F", "vram bank f control")
        self._define_reg(0x4000246, "REG_VRAMCNT_G", "vram bank g control")
        self._define_reg(
            0x4000247, "REG_WRAMCNT", "wram bank control (shared wram mapping)"
        )
        self._define_reg(0x4000248, "REG_VRAMCNT_H", "vram bank h control")
        self._define_reg(0x4000249, "REG_VRAMCNT_I", "vram bank i control")

        # maths (arm9)
        self._define_reg(0x4000280, "REG_DIVCNT", "divider control")
        self._define_reg(0x4000290, "REG_DIV_NUMER_L", "divider numerator (low 32)")
        self._define_reg(0x4000294, "REG_DIV_NUMER_H", "divider numerator (high 32)")
        self._define_reg(0x4000298, "REG_DIV_DENOM_L", "divider denominator (low 32)")
        self._define_reg(0x400029C, "REG_DIV_DENOM_H", "divider denominator (high 32)")
        self._define_reg(
            0x40002A0, "REG_DIV_RESULT_L", "divider result (quotient low 32)"
        )
        self._define_reg(
            0x40002A4, "REG_DIV_RESULT_H", "divider result (quotient high 32)"
        )
        self._define_reg(0x40002A8, "REG_DIVREM_RESULT_L", "divider remainder (low 32)")
        self._define_reg(
            0x40002AC, "REG_DIVREM_RESULT_H", "divider remainder (high 32)"
        )
        self._define_reg(0x40002B0, "REG_SQRTCNT", "square root control")
        self._define_reg(0x40002B4, "REG_SQRT_RESULT", "square root result (32bit)")
        self._define_reg(0x40002B8, "REG_SQRT_PARAM_L", "square root param (low 32)")
        self._define_reg(0x40002BC, "REG_SQRT_PARAM_H", "square root param (high 32)")

        # graphics power (arm9)
        self._define_reg(0x4000304, "REG_POWCNT1", "graphics/system power control 1")

        # 3d engine registers (arm9) - extensive, define key ones or ranges
        # self._define_reg(0x4000320, "reg_gxfifo") # geometry fifo
        # ... many registers up to 0x40006a3 ...
        # use tags to mark the region instead of defining every register
        # --- Corrected: Use create_tag_type ---
        if "NDS 3D Registers" not in self.tag_types:
            self.create_tag_type("NDS 3D Registers", "🎮")  # type: ignore
        if "NDS 3D Registers" in self.tag_types:  # check if tag type creation succeeded
            self.add_tag(
                0x4000320, "NDS 3D Registers Start", self.tag_types["NDS 3D Registers"]
            )
            self.add_tag(
                0x40006A3, "NDS 3D Registers End", self.tag_types["NDS 3D Registers"]
            )

        # display engine b (sub screen) (arm9)
        self._define_reg(0x4001000, "REG_DISPCNT_B", "display control (engine b)")
        self._define_reg(0x4001008, "REG_BG0CNT_B", "bg0 control (engine b)")
        self._define_reg(0x400100A, "REG_BG1CNT_B", "bg1 control (engine b)")
        self._define_reg(0x400100C, "REG_BG2CNT_B", "bg2 control (engine b)")
        self._define_reg(0x400100E, "REG_BG3CNT_B", "bg3 control (engine b)")
        self._define_reg(0x4001010, "REG_BG0HOFS_B", "bg0 h-offset (engine b)")
        self._define_reg(0x4001012, "REG_BG0VOFS_B", "bg0 v-offset (engine b)")
        self._define_reg(0x4001014, "REG_BG1HOFS_B", "bg1 h-offset (engine b)")
        self._define_reg(0x4001016, "REG_BG1VOFS_B", "bg1 v-offset (engine b)")
        self._define_reg(0x4001018, "REG_BG2HOFS_B", "bg2 h-offset (engine b)")
        self._define_reg(0x400101A, "REG_BG2VOFS_B", "bg2 v-offset (engine b)")
        self._define_reg(0x400101C, "REG_BG3HOFS_B", "bg3 h-offset (engine b)")
        self._define_reg(0x400101E, "REG_BG3VOFS_B", "bg3 v-offset (engine b)")
        self._define_reg(0x4001020, "REG_BG2PA_B", "bg2 rotation/scaling pa (engine b)")
        self._define_reg(0x4001022, "REG_BG2PB_B", "bg2 rotation/scaling pb (engine b)")
        self._define_reg(0x4001024, "REG_BG2PC_B", "bg2 rotation/scaling pc (engine b)")
        self._define_reg(0x4001026, "REG_BG2PD_B", "bg2 rotation/scaling pd (engine b)")
        self._define_reg(
            0x4001028, "REG_BG2X_L_B", "bg2 reference point x-coord low (engine b)"
        )
        self._define_reg(
            0x400102A, "REG_BG2X_H_B", "bg2 reference point x-coord high (engine b)"
        )
        self._define_reg(
            0x400102C, "REG_BG2Y_L_B", "bg2 reference point y-coord low (engine b)"
        )
        self._define_reg(
            0x400102E, "REG_BG2Y_H_B", "bg2 reference point y-coord high (engine b)"
        )
        self._define_reg(0x4001030, "REG_BG3PA_B", "bg3 rotation/scaling pa (engine b)")
        self._define_reg(0x4001032, "REG_BG3PB_B", "bg3 rotation/scaling pb (engine b)")
        self._define_reg(0x4001034, "REG_BG3PC_B", "bg3 rotation/scaling pc (engine b)")
        self._define_reg(0x4001036, "REG_BG3PD_B", "bg3 rotation/scaling pd (engine b)")
        self._define_reg(
            0x4001038, "REG_BG3X_L_B", "bg3 reference point x-coord low (engine b)"
        )
        self._define_reg(
            0x400103A, "REG_BG3X_H_B", "bg3 reference point x-coord high (engine b)"
        )
        self._define_reg(
            0x400103C, "REG_BG3Y_L_B", "bg3 reference point y-coord low (engine b)"
        )
        self._define_reg(
            0x400103E, "REG_BG3Y_H_B", "bg3 reference point y-coord high (engine b)"
        )
        self._define_reg(
            0x4001040, "REG_WIN0H_B", "window 0 horizontal bounds (engine b)"
        )
        self._define_reg(
            0x4001042, "REG_WIN1H_B", "window 1 horizontal bounds (engine b)"
        )
        self._define_reg(
            0x4001044, "REG_WIN0V_B", "window 0 vertical bounds (engine b)"
        )
        self._define_reg(
            0x4001046, "REG_WIN1V_B", "window 1 vertical bounds (engine b)"
        )
        self._define_reg(0x4001048, "REG_WININ_B", "inside window control (engine b)")
        self._define_reg(0x400104A, "REG_WINOUT_B", "outside window control (engine b)")
        self._define_reg(0x400104C, "REG_MOSAIC_B", "mosaic size (engine b)")
        self._define_reg(
            0x4001050, "REG_BLDCNT_B", "color special effects control (engine b)"
        )
        self._define_reg(
            0x4001052, "REG_BLDALPHA_B", "alpha blending coefficients (engine b)"
        )
        self._define_reg(0x4001054, "REG_BLDY_B", "brightness coefficient (engine b)")
        self._define_reg(
            0x400106C, "REG_MASTER_BRIGHT_B", "master brightness (engine b)"
        )

        # --- arm7 specific i/o registers ---
        # sio (serial i/o for gba compatibility, debug) (arm7)
        self._define_reg(
            0x4000120, "REG_SIODATA32", "sio data 32bit (normal/multiplayer)"
        )
        self._define_reg(0x4000128, "REG_SIOCNT", "sio control (normal/multiplayer)")
        self._define_reg(0x4000134, "REG_RCNT", "sio mode select / general purpose io")

        # rtc (real time clock) (arm7)
        self._define_reg(0x4000138, "REG_RTCDATA", "rtc data register (via spi)")

        # spi bus (touchscreen, firmware, power management) (arm7)
        self._define_reg(0x40001C0, "REG_SPICNT", "spi control")
        self._define_reg(0x40001C2, "REG_SPIDATA", "spi data")

        # memory control (arm7)
        self._define_reg(
            0x4000204, "REG_EXMEMSTAT", "external memory status (read only)"
        )
        # vram/wram status (arm7 read only)
        self._define_reg(0x4000240, "REG_VRAMSTAT", "vram c,d bank status")
        self._define_reg(0x4000241, "REG_WRAMSTAT", "wram bank status")

        # sound / wifi power (arm7)
        self._define_reg(0x4000304, "REG_POWCNT2", "sound/wifi power control 2")

        # bios protection (arm7)
        self._define_reg(0x4000308, "REG_BIOSPROT", "bios write protection")

        # sound registers (arm7)
        # only define main control regs, individual channels are numerous
        self._define_reg(0x4000500, "REG_SOUNDCNT", "master sound control")
        self._define_reg(0x4000504, "REG_SOUNDBIAS", "sound bias / output level")
        # sound capture
        self._define_reg(0x4000508, "REG_SNDCAP0CNT", "capture 0 control")
        self._define_reg(0x4000509, "REG_SNDCAP1CNT", "capture 1 control")
        self._define_reg(0x4000510, "REG_SNDCAP0DAD", "capture 0 destination addr")
        self._define_reg(0x4000514, "REG_SNDCAP0LEN", "capture 0 length")
        self._define_reg(0x4000518, "REG_SNDCAP1DAD", "capture 1 destination addr")
        self._define_reg(0x400051C, "REG_SNDCAP1LEN", "capture 1 length")
        # individual sound channel regs range from 0x4000400 to 0x40004ff

        # wifi registers (arm7) - define base, specific registers numerous
        # self._define_reg(0x4804000, "wifi_ram_start") # wifi ram (8kb)
        # self._define_reg(0x4808000, "wifi_reg_start") # wifi registers start
        # --- Corrected: Use create_tag_type ---
        if "NDS Wifi Registers" not in self.tag_types:
            self.create_tag_type("NDS Wifi Registers", "📡")  # type: ignore
        if (
            "NDS Wifi Registers" in self.tag_types
        ):  # check if tag type creation succeeded
            self.add_tag(
                0x4800000, "NDS Wifi Region Start", self.tag_types["NDS Wifi Registers"]
            )
            self.add_tag(
                0x480FFFF, "NDS Wifi Region End", self.tag_types["NDS Wifi Registers"]
            )

        # --- hardcoded ram addresses ---
        # arm9 irq handler vector (in dtcm, address can vary, but offset is fixed)
        # cannot reliably define absolute address without knowing dtcm base.
        # self._define_reg(dtcm_base + 0x3ffc, "nds9_irq_handler_ptr")

        # arm7 irq handler vector (fixed address in arm7 wram)
        self._define_reg(
            0x0380FFF8, "NDS7_IRQ_CHECKBITS", "arm7 irq 'if' check bits mirror?"
        )
        self._define_reg(
            0x0380FFFC, "NDS7_IRQ_HANDLER_PTR", "arm7 pointer to irq handler"
        )

        # main memory control (mirror at end of main ram)
        self._define_reg(0x027FFFFE, "MAIN_MEM_CNT", "main memory control?")

    # --- overridden methods ---
    def perform_is_executable(self) -> bool:
        # nds roms contain executable code for both arm9 and arm7
        return True

    def perform_get_entry_point(self) -> int:
        # return the arm9 entry point as the primary entry
        if self.nds_rom:
            return self.nds_rom.header.arm9_entry_address
        # should not happen if init succeeded, but return 0 as fallback
        self.log.log_error(
            "perform_get_entry_point called before nds_rom was initialized."
        )
        return 0

    def perform_get_address_size(self) -> int:
        # nds uses 32-bit addresses
        return 4


# register the view type with binary ninja
NDSView.register()
