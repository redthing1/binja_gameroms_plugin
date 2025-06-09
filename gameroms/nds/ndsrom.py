"""
NDS ROM loader using the refactored base loader architecture.
"""

import struct
import traceback
from typing import Optional, List, Dict, Tuple

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
    log_debug,
)

from ..common.base_loader import BaseROMLoader
from .hardware import (
    NDS_TAG_TYPE_DEFINITIONS,
    NDS_IO_REGISTERS,
    NITRO_SDK_MODULE_PARAMS_MAGIC,
    NITRO_SDK_MODULE_PARAMS_SIZE,
    NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET,
)
from .cartridge import (
    NDSRomReader,
    NDSRom,
    NDSOverlayTable,
    NDSOverlayEntry,
)


class NDSView(BaseROMLoader):
    """
    BinaryView class for loading and analyzing Nintendo DS (NDS) ROM files.
    
    Handles parsing the NDS ROM structure, mapping memory regions for both
    ARM9 and ARM7 processors, loading binaries and overlays (including
    decompression), and defining hardware registers and entry points.
    """

    name = "NDS"
    long_name = "Nintendo DS ROM"

    def __init__(self, data: BinaryView):
        super().__init__(data)
        
        # NDS-specific attributes
        self.nds_rom: Optional[NDSRom] = None
        self._primary_arm9_entry_point: Optional[int] = None
        self._primary_arm7_entry_point: Optional[int] = None

    def get_loader_name(self) -> str:
        """Return the name for this loader (used for logging)."""
        return self.name

    def get_tag_type_definitions(self) -> Dict[str, str]:
        """Return dictionary mapping tag type names to icons."""
        return NDS_TAG_TYPE_DEFINITIONS

    def _setup_architecture_and_platform(self) -> None:
        """Set up self.arch and self.platform for NDS ROMs."""
        try:
            # NDS uses ARM946E-S (ARMv5TEJ) and ARM7TDMI (ARMv4T)
            # ARMv7 is used as a practical choice that supports both instruction sets
            self.arch: Optional[Architecture] = Architecture["armv7"]  # type: ignore
            if not self.arch:
                self.logger.log_error("critical: armv7 architecture not found in binary ninja")
                raise RuntimeError("armv7 architecture definition not found")

            self.platform: Optional[Platform] = self.arch.standalone_platform
            if not self.platform:
                self.logger.log_error(f"critical: could not get platform for {self.arch.name}")
                raise RuntimeError(f"failed to get platform for {self.arch.name}")
                
            self.logger.log_info(f"set platform: {self.platform.name}, architecture: {self.arch.name}")
        except KeyError:
            available_archs = [arch.name for arch in Architecture]
            self.logger.log_error(f"critical: armv7 architecture not found. available: {available_archs}")
            raise RuntimeError("armv7 architecture key not found")
        except Exception as e:
            self.logger.log_error(f"critical error during setup: {e}\n{traceback.format_exc()}")
            raise

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """
        Check if the provided data is likely an NDS ROM.
        
        Performs a basic heuristic check for Nintendo logo magic bytes
        in the NDS ROM header.
        """
        min_header_size = 0xC0 + 4  # Nintendo logo offset + 4 bytes
        if data.length < min_header_size:
            log_debug(f"[{cls.name}] data length {data.length} < min size {min_header_size}")
            return False

        try:
            logo_magic_bytes = data.read(0xC0, 4)
            
            # Check for Nintendo logo magic bytes
            if logo_magic_bytes == b"\x24\xff\xae\x51":
                log_info(f"[{cls.name}] found nintendo logo magic bytes at 0xc0")
                return True
            else:
                log_debug(f"[{cls.name}] nintendo logo magic not found, got {logo_magic_bytes!r}")
                return False
        except Exception as e:
            log_error(f"[{cls.name}] error reading logo magic: {e}")
            return False

    def _parse_rom_structure(self) -> bool:
        """
        Parse the complete NDS ROM structure using the external NDSRomReader.
        """
        self.logger.log_info("reading entire rom into memory for parsing with ndsromreader...")
        rom_length = self.raw_data.length
        if rom_length == 0:
            self.logger.log_error("rom file is empty (0 bytes). cannot parse.")
            return False

        # Read the entire ROM data
        rom_data_bytes: bytes = self.raw_data.read(0, rom_length)
        if not rom_data_bytes or len(rom_data_bytes) != rom_length:
            self.logger.log_error(
                f"failed to read full rom data (read {len(rom_data_bytes)} bytes, expected {rom_length} bytes)"
            )
            return False
        self.logger.log_info(f"successfully read {rom_length // (1024*1024)} MB of rom data into memory")

        # Perform header validation
        self.logger.log_info("performing nds rom header validation via ndsromreader.is_valid()...")
        validation_data_slice = rom_data_bytes[:min(0x1000, rom_length)]  # use up to first 4kb
        if not NDSRomReader.is_valid(validation_data_slice):
            self.logger.log_warn(
                "ndsromreader.is_valid() reported header validation failure. "
                "the rom might be malformed, a bad dump, or unsupported. "
                "attempting to parse anyway, but results may be unreliable."
            )
        else:
            self.logger.log_info("ndsromreader.is_valid() reported successful header validation")

        # Parse the full ROM structure
        self.logger.log_info("parsing full nds rom structure using ndsromreader.read()...")
        try:
            self.nds_rom = NDSRomReader.read(rom_data_bytes)
        except Exception as e:
            self.logger.log_error(f"ndsromreader.read() failed with an exception: {e}")
            self.logger.log_error(f"traceback:\n{traceback.format_exc()}")
            self.nds_rom = None
            del rom_data_bytes
            return False
        finally:
            # Free memory
            if "rom_data_bytes" in locals():
                del rom_data_bytes
                self.logger.log_debug("rom_data_bytes buffer has been cleared from memory")

        if not self.nds_rom or not self.nds_rom.header:
            self.logger.log_error(
                "failed to parse nds rom: ndsromreader.read() returned none, or missing header"
            )
            return False

        self.logger.log_info("successfully parsed nds rom structure using ndsromreader")
        return True

    def _map_memory_regions(self) -> None:
        """
        Map the core NDS memory regions such as main RAM, WRAM, VRAM, I/O ports,
        tightly coupled memories (TCM), and BIOS ROMs.
        """
        self.logger.log_info("mapping nds memory regions...")

        def add_nds_memory_segment(
            address: int,
            size: int,
            permissions: SegmentFlag,
            name: str,
            tag_name: str = "Memory Region",
            is_ram_for_code: bool = False,
        ):
            """Helper to add NDS memory segments with consistent logging and tagging."""
            self.logger.log_debug(
                f"  preparing to map '{name}': addr=0x{address:08x}, size=0x{size:x} ({size // 1024}KB)"
            )

            file_offset_for_backing = 0
            file_length_for_backing = 0

            if is_ram_for_code:
                # Provide minimal file backing for RAM regions that might contain executable code
                if self.raw_data.length > 0:
                    file_offset_for_backing = 0
                    file_length_for_backing = 1  # must be non-zero to indicate "file-backed"
                else:
                    self.logger.log_warn(
                        f"raw rom file length is 0, cannot provide file backing for ram region '{name}'"
                    )

            try:
                self.add_auto_segment(
                    address, size, file_offset_for_backing, file_length_for_backing, permissions
                )

                # Add tag for region identification
                tag_icon = NDS_TAG_TYPE_DEFINITIONS.get(tag_name, "🗺️")
                tag_type = self._get_or_create_tag_type(tag_name, tag_icon)
                if tag_type:
                    self.add_tag(address, tag_type.name, data=f"{name} Start")

                self.set_comment_at(address, f"{name} ({size // 1024}KB)")
                self.logger.log_info(f"  successfully mapped '{name}'")
            except Exception as e:
                self.logger.log_error(f"failed to map memory region '{name}' at 0x{address:08x}: {e}")

        # Define standard NDS memory regions
        # Main RAM: 4MB, primarily accessible by ARM9
        add_nds_memory_segment(
            0x02000000, 0x00400000, self.PERM_RWX, "Main RAM", is_ram_for_code=True
        )

        # Shared WRAM: 32KB block
        add_nds_memory_segment(
            0x03000000, 0x00008000, self.PERM_RWX, "Shared WRAM (32KB Block)", is_ram_for_code=True
        )

        # ARM7 WRAM: 64KB, typically exclusive to ARM7
        add_nds_memory_segment(
            0x03800000, 0x00010000, self.PERM_RWX, "ARM7 WRAM (64KB)", is_ram_for_code=True
        )

        # I/O ports (memory-mapped hardware registers)
        add_nds_memory_segment(
            0x04000000, 0x00001000, self.PERM_RW, 
            "I/O Registers (Main Block, 0x04000xxx)", tag_name="Hardware Register"
        )
        add_nds_memory_segment(
            0x04100000, 0x00000020, self.PERM_RW,
            "I/O Registers (IPC/Card, 0x04100xxx)", tag_name="Hardware Register"
        )
        add_nds_memory_segment(
            0x04800000, 0x00008000, self.PERM_RW,
            "Wireless Comm (I/O & RAM)", tag_name="Wifi"
        )

        # Graphics memory
        add_nds_memory_segment(0x05000000, 0x00000800, self.PERM_RW, "Standard Palette RAM (2KB)")
        add_nds_memory_segment(0x06000000, 0x000A4000, self.PERM_RW, "VRAM (Main Banks A-I, 656KB)")
        add_nds_memory_segment(0x06800000, 0x000A4000, self.PERM_RW, "VRAM (LCDC Mapped Alias)")
        add_nds_memory_segment(0x07000000, 0x00000800, self.PERM_RW, "OAM - OBJ Attribute Memory (2KB)")

        # BIOS ROMs
        add_nds_memory_segment(
            0xFFFF0000, 0x00001000, self.PERM_RX, "ARM9 BIOS (4KB)", is_ram_for_code=True
        )
        add_nds_memory_segment(
            0x00000000, 0x00004000, self.PERM_RX, "ARM7 BIOS (16KB at Physical 0x0)", is_ram_for_code=True
        )

        # Tightly coupled memories (TCM) for ARM9
        self.logger.log_info("arm9 itcm is typically at physical 0x0, mirrored to 0x01000000")
        add_nds_memory_segment(
            0x01000000, 0x00008000, self.PERM_RWX, 
            "ARM9 ITCM (32KB Code, Mapped at 0x01xxxxxx)", is_ram_for_code=True
        )

        # ARM9 DTCM at common default location
        dtcm_common_base = 0x027C0000
        self.logger.log_info(
            f"mapping arm9 dtcm at common default 0x{dtcm_common_base:08x} (16kb). actual base is configurable"
        )
        add_nds_memory_segment(
            dtcm_common_base, 0x00004000, self.PERM_RWX,
            "ARM9 DTCM (16KB Data, Common Default)", is_ram_for_code=True
        )

        self.logger.log_info("finished mapping nds memory regions")

    def _find_nitro_sdk_module_params(self, data: bytes) -> Optional[int]:
        """
        Search for the Nitro SDK's _start_moduleparams magic bytes within the provided data.
        """
        try:
            magic_index = data.find(NITRO_SDK_MODULE_PARAMS_MAGIC)
            if magic_index != -1:
                struct_start_offset = magic_index - NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET

                if (
                    struct_start_offset >= 0
                    and struct_start_offset + NITRO_SDK_MODULE_PARAMS_SIZE <= len(data)
                ):
                    self.logger.log_info(
                        f"found _start_moduleparams structure at offset 0x{struct_start_offset:x}"
                    )
                    return struct_start_offset
                else:
                    self.logger.log_warn(
                        f"found moduleparams magic at index 0x{magic_index:x}, but calculated struct start is invalid"
                    )
            else:
                self.logger.log_info(
                    "_start_moduleparams magic sequence not found. binary might be non-sdk or custom-built"
                )
        except Exception as e:
            self.logger.log_error(f"error searching for nitro sdk moduleparams: {e}")
        return None

    def _mii_uncompress_backward(self, data: bytes) -> bytes:
        """
        Decompress data assumed to be in a MII LZ77 variant format (backward decompression).
        """
        if len(data) < 4:
            raise ValueError("data too short for mii decompression (minimum 4 bytes for footer)")

        # Last 4 bytes contain the decompressed size
        footer_val_bytes = data[-4:]
        decompressed_size_from_footer = struct.unpack_from("<I", footer_val_bytes, 0)[0]

        # Sanity check on decompressed size
        if decompressed_size_from_footer > 0x10000000:
            raise ValueError(
                f"invalid mii decompressed_size_from_footer: 0x{decompressed_size_from_footer:x} (too large)"
            )

        # Handle cases based on data length and decompressed_size
        if len(data) < 8:
            if decompressed_size_from_footer == 0:
                self.logger.log_debug("mii: data length < 8 and decompressed_size is 0. returning empty")
                return b""
            if decompressed_size_from_footer == len(data) - 4:
                self.logger.log_info("mii: data length < 8, size matches (data_len - 4). assuming uncompressed")
                return data[:-4]
            raise ValueError(
                f"mii: data length {len(data)} is < 8. decompressed_size {decompressed_size_from_footer} "
                "is non-zero and does not match uncompressed expectation"
            )

        # Check the "header_val" (bytes at data[-8:-4])
        header_val_bytes = data[-8:-4]
        header_val_u32 = struct.unpack_from("<I", header_val_bytes, 0)[0]
        comp_type = (header_val_u32 >> 24) & 0xF

        self.logger.log_debug(
            f"mii: 'header_val' is 0x{header_val_u32:08x}, comp_type: 0x{comp_type:x}, footer_size: 0x{decompressed_size_from_footer:x}"
        )

        if decompressed_size_from_footer == 0:
            if comp_type == 0x1 and header_val_u32 == 0x10000000:
                self.logger.log_debug("mii: identified specific empty compressed block pattern")
                return b""
            else:
                self.logger.log_warn(
                    f"mii: decompressed_size is 0, but header_val (0x{header_val_u32:x}) doesn't match empty pattern"
                )
                return b""

        # If compression type is not 0x1 (common NDS LZ77), treat as uncompressed
        if comp_type != 0x1:
            self.logger.log_warn(f"mii: compression type is 0x{comp_type:x} (not type 1 lz77). treating as uncompressed")
            if decompressed_size_from_footer == len(data) - 4:
                self.logger.log_info("mii: uncompressed fallback, size matches (data_len - 4)")
            else:
                self.logger.log_warn(
                    f"mii: uncompressed fallback, but footer size 0x{decompressed_size_from_footer:x} != data_len-4"
                )
            return data[:-4]

        # Proceed with type 1 LZ77 backward decompression
        result_buffer = bytearray(decompressed_size_from_footer)
        dest_offset = decompressed_size_from_footer  # current write position (counts down)
        src_offset = len(data) - 8  # current read position (counts down)

        self.logger.log_debug(
            f"mii: starting lz77 decompress. target_size=0x{decompressed_size_from_footer:x}"
        )

        while dest_offset > 0:
            if src_offset <= 0:
                raise EOFError(
                    f"mii source data exhausted unexpectedly (dest_offset={dest_offset}, src_offset={src_offset})"
                )

            block_flags = data[src_offset - 1]  # read flag byte
            src_offset -= 1

            for bit_num in range(8):  # process 8 blocks/literals per flag byte
                if dest_offset <= 0:
                    break

                is_compressed_block = (block_flags & 0x80) != 0  # check MSB
                block_flags = (block_flags << 1) & 0xFF  # shift for next flag bit

                if not is_compressed_block:  # literal byte
                    if src_offset <= 0:
                        raise EOFError(f"mii source exhausted (expected literal byte)")
                    literal_byte = data[src_offset - 1]
                    src_offset -= 1
                    dest_offset -= 1
                    if dest_offset < 0:
                        raise IndexError("mii destination offset became negative while writing literal")
                    result_buffer[dest_offset] = literal_byte
                else:  # LZ77 copy block (compressed)
                    if src_offset < 2:
                        raise EOFError(f"mii source exhausted (expected lz77 block params)")

                    byte1 = data[src_offset - 1]
                    byte2 = data[src_offset - 2]
                    src_offset -= 2

                    # Length: 3-18. (byte1 upper 4 bits) + 3
                    copy_length = ((byte1 & 0xF0) >> 4) + 3
                    # Displacement: 1-4096. (byte1 lower 4 bits << 8 | byte2) + 1
                    copy_displacement = (((byte1 & 0x0F) << 8) | byte2) + 1

                    if dest_offset < copy_length:
                        raise ValueError(
                            f"mii lz77 copy length ({copy_length}) exceeds remaining destination space ({dest_offset})"
                        )

                    # Perform the backward copy
                    try:
                        for k in range(copy_length):
                            current_write_idx = dest_offset - 1 - k
                            current_read_idx = current_write_idx + copy_displacement
                            if not (
                                0 <= current_read_idx < decompressed_size_from_footer
                                and 0 <= current_write_idx < decompressed_size_from_footer
                            ):
                                raise IndexError(
                                    f"mii lz77 copy out of bounds: read_idx={current_read_idx}, write_idx={current_write_idx}"
                                )
                            result_buffer[current_write_idx] = result_buffer[current_read_idx]
                        dest_offset -= copy_length
                    except IndexError as ie:
                        raise IndexError(f"mii lz77 copy error: {ie}")
                
                if dest_offset <= 0 and bit_num < 7:
                    break

        if dest_offset != 0:
            self.logger.log_warn(
                f"mii decompression finished, but dest_offset is non-zero ({dest_offset}). result may be truncated"
            )
        return bytes(result_buffer)

    def _load_binary_segment(
        self,
        cpu_name: str,  # "ARM9" or "ARM7"
        rom_offset: int,
        rom_size: int,
        ram_address: int,
        bss_size: int,
        entry_address: int,
        is_arm9_with_module_params: bool = False,
    ) -> Optional[int]:
        """
        Load a main binary (ARM9 or ARM7) into its specified RAM address.
        Handles potential decompression for ARM9 binaries if Nitro SDK module parameters
        are found and indicate compression.
        """
        if not self.nds_rom or not self.nds_rom.header:
            self.logger.log_error(f"cannot load {cpu_name} binary, rom structure not parsed")
            return None
        
        if rom_size == 0:
            self.logger.log_info(f"{cpu_name} rom_size in header is 0. skipping loading of code/data part")
            effective_code_data_size_in_memory = 0
        else:
            self.logger.log_info(
                f"loading {cpu_name} binary: rom_offset=0x{rom_offset:x}, rom_size=0x{rom_size:x}, load_addr=0x{ram_address:x}"
            )
            raw_binary_data: bytes = self.raw_data.read(rom_offset, rom_size)
            if not raw_binary_data or len(raw_binary_data) != rom_size:
                self.logger.log_error(
                    f"failed to read full {cpu_name} binary data from rom"
                )
                return None

            effective_code_data_size_in_memory = 0
            final_data_to_write_to_ram = raw_binary_data
            segment_file_offset_for_mapping = rom_offset
            segment_file_length_for_mapping = rom_size
            was_decompressed_successfully = False
            code_section_comment_suffix = "(raw)"

            if is_arm9_with_module_params:
                module_params_struct_offset = self._find_nitro_sdk_module_params(raw_binary_data)
                sdk_derived_code_data_size_in_memory = 0
                is_compressed_by_sdk_params = False

                if module_params_struct_offset is not None:
                    try:
                        autoload_end_addr = struct.unpack_from(
                            "<I", raw_binary_data, module_params_struct_offset + 8
                        )[0]
                        compressed_static_end_marker = struct.unpack_from(
                            "<I", raw_binary_data, module_params_struct_offset + 20
                        )[0]

                        is_compressed_by_sdk_params = compressed_static_end_marker != 0
                        sdk_derived_code_data_size_in_memory = autoload_end_addr - ram_address

                        self.logger.log_info(
                            f"  {cpu_name} moduleparams found: compressed_marker=0x{compressed_static_end_marker:x} "
                            f"(is_compressed={is_compressed_by_sdk_params}), derived_sdk_code_data_size=0x{sdk_derived_code_data_size_in_memory:x}"
                        )

                        max_reasonable_decomp_size = rom_size * 25
                        if not (0 <= sdk_derived_code_data_size_in_memory <= max_reasonable_decomp_size):
                            self.logger.log_error(
                                f"  moduleparams: invalid sdk_derived_code_data_size (0x{sdk_derived_code_data_size_in_memory:x})"
                            )
                            is_compressed_by_sdk_params = False
                        elif sdk_derived_code_data_size_in_memory == 0 and is_compressed_by_sdk_params:
                            self.logger.log_info(
                                "  moduleparams indicate compression but derived size is 0. assuming empty payload"
                            )
                    except Exception as e:
                        self.logger.log_error(f"error processing _start_moduleparams for {cpu_name}: {e}")
                        is_compressed_by_sdk_params = False
                else:
                    self.logger.log_info(f"  {cpu_name}: _start_moduleparams not found. assuming uncompressed")

                if is_compressed_by_sdk_params:
                    self.logger.log_info(
                        f"  attempting {cpu_name} decompression (expected size: 0x{sdk_derived_code_data_size_in_memory:x})..."
                    )
                    try:
                        decompressed_data = self._mii_uncompress_backward(raw_binary_data)
                        actual_decompressed_size = len(decompressed_data)
                        self.logger.log_info(f"  {cpu_name} actual decompressed size: 0x{actual_decompressed_size:x}")

                        if (
                            sdk_derived_code_data_size_in_memory > 0
                            and actual_decompressed_size != sdk_derived_code_data_size_in_memory
                        ):
                            self.logger.log_warn(
                                f"  actual decompressed {cpu_name} size differs from moduleparams expected. using actual"
                            )
                        effective_code_data_size_in_memory = actual_decompressed_size
                        final_data_to_write_to_ram = decompressed_data
                        was_decompressed_successfully = True
                        code_section_comment_suffix = "(decompressed)"
                    except Exception as e:
                        self.logger.log_error(f"{cpu_name} decompression failed: {e}. falling back to raw mapping")
                        effective_code_data_size_in_memory = rom_size
                        final_data_to_write_to_ram = raw_binary_data
                        code_section_comment_suffix = "(raw, decompression failed)"
                else:
                    # Not compressed according to SDK params
                    code_section_comment_suffix = (
                        "(raw, sdk uncompressed)" if module_params_struct_offset else "(raw, no sdk params)"
                    )
                    if module_params_struct_offset and sdk_derived_code_data_size_in_memory > 0:
                        effective_code_data_size_in_memory = sdk_derived_code_data_size_in_memory
                    else:
                        effective_code_data_size_in_memory = rom_size
                    final_data_to_write_to_ram = raw_binary_data
            else:
                # Not ARM9 with module params (e.g., ARM7) -> typically not compressed
                effective_code_data_size_in_memory = rom_size
                final_data_to_write_to_ram = raw_binary_data
                code_section_comment_suffix = "(raw)"

            # Define the segment for the code/data part
            if effective_code_data_size_in_memory > 0:
                self.logger.log_info(
                    f"  adding segment for {cpu_name} code/data: mem_addr=0x{ram_address:08x}, mem_size=0x{effective_code_data_size_in_memory:x}"
                )
                self.add_auto_segment(
                    ram_address,
                    effective_code_data_size_in_memory,
                    segment_file_offset_for_mapping,
                    segment_file_length_for_mapping,
                    self.PERM_RX,
                )
                
                # Write processed data if needed
                if was_decompressed_successfully or effective_code_data_size_in_memory != segment_file_length_for_mapping:
                    self.logger.log_info(
                        f"  writing {len(final_data_to_write_to_ram)} bytes of processed {cpu_name} data to memory"
                    )
                    bytes_written = self.write(ram_address, final_data_to_write_to_ram)
                    if bytes_written != len(final_data_to_write_to_ram):
                        self.logger.log_error(f"{cpu_name} data write error: wrote {bytes_written} bytes")
                
                self.add_auto_section(
                    name=f".{cpu_name.lower()}_code_data",
                    start=ram_address,
                    length=effective_code_data_size_in_memory,
                    semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                    type="Code",
                )
                self.set_comment_at(ram_address, f"{cpu_name} code/data start {code_section_comment_suffix}")
            elif rom_size > 0:
                self.logger.log_warn(
                    f"  {cpu_name} has rom_size 0x{rom_size:x} but effective code/data size in memory is 0"
                )

        # Handle BSS section
        if bss_size > 0:
            bss_start_address = ram_address + effective_code_data_size_in_memory
            self.logger.log_info(f"  mapping {cpu_name} bss: addr=0x{bss_start_address:08x}, size=0x{bss_size:x}")
            self.add_auto_segment(bss_start_address, bss_size, 0, 0, self.PERM_RW)
            self.add_auto_section(
                name=f".{cpu_name.lower()}.bss",
                start=bss_start_address,
                length=bss_size,
                semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                type="BSS",
            )
            self.set_comment_at(bss_start_address, f"{cpu_name} BSS start")
        else:
            self.logger.log_info(f"  no {cpu_name} BSS section defined (bss_size is 0 in header)")

        self.logger.log_info(
            f"{cpu_name} binary processed: entry_addr_header=0x{entry_address:08x}, "
            f"code_data_mem_size=0x{effective_code_data_size_in_memory:x}, bss_size=0x{bss_size:x}"
        )
        return effective_code_data_size_in_memory

    def _load_overlays(self, cpu_name: str, overlay_table: Optional[NDSOverlayTable]):
        """
        Load ARM9 or ARM7 overlays into their specified RAM addresses.
        Handles decompression for compressed overlays.
        """
        if (
            not self.nds_rom
            or not self.nds_rom.fat_entries
            or not overlay_table
            or not overlay_table.entries
        ):
            self.logger.log_info(f"no {cpu_name} overlays found or prerequisites missing. skipping overlay loading")
            return
        
        # Check for compression support
        if not hasattr(NDSOverlayEntry, "is_compressed"):
            self.logger.log_error(
                f"NDSOverlayEntry class is missing 'is_compressed' attribute. cannot load {cpu_name} overlays correctly"
            )
            return

        self.logger.log_info(f"loading {cpu_name} overlays (total {len(overlay_table.entries)} entries)...")
        num_loaded_successfully = 0
        num_failed_or_skipped = 0

        for i, overlay_entry in enumerate(overlay_table.entries):
            # Skip placeholder entries
            if overlay_entry.file_id == 0xFFFF:
                self.logger.log_debug(f"  skipping {cpu_name} overlay entry {i}: file_id is 0xFFFF (placeholder)")
                continue
            
            # Validate file_id
            if overlay_entry.file_id >= len(self.nds_rom.fat_entries):
                self.logger.log_warn(
                    f"  skipping invalid {cpu_name} overlay entry {i}: file_id {overlay_entry.file_id} out of FAT bounds"
                )
                num_failed_or_skipped += 1
                continue
            
            # Skip empty overlays
            if overlay_entry.ram_size == 0 and overlay_entry.bss_size == 0:
                self.logger.log_info(
                    f"  skipping empty {cpu_name} overlay entry {i}: ram_size and bss_size are both 0"
                )
                continue

            fat_entry = self.nds_rom.fat_entries[overlay_entry.file_id]
            overlay_size_in_rom_file = fat_entry.end_address - fat_entry.start_address
            overlay_data_raw_from_rom = b""
            segment_name_base = f"{cpu_name}_Overlay_{i}_File{overlay_entry.file_id}"

            self.logger.log_debug(
                f"  processing {segment_name_base}: rom_offset=0x{fat_entry.start_address:x}, "
                f"rom_size=0x{overlay_size_in_rom_file:x}, ram_addr=0x{overlay_entry.ram_address:x}, "
                f"is_compressed={overlay_entry.is_compressed}"
            )

            # Read overlay data from ROM
            if overlay_size_in_rom_file > 0:
                overlay_data_raw_from_rom = self.raw_data.read(
                    fat_entry.start_address, overlay_size_in_rom_file
                )
                if not overlay_data_raw_from_rom or len(overlay_data_raw_from_rom) != overlay_size_in_rom_file:
                    self.logger.log_error(f"failed to read data for {segment_name_base} from rom. skipping")
                    num_failed_or_skipped += 1
                    continue
            elif overlay_entry.ram_size > 0:
                self.logger.log_warn(
                    f"{segment_name_base} expects ram content but has no data in rom. will proceed to bss if any"
                )

            load_address = overlay_entry.ram_address
            effective_ram_size_in_memory = 0
            final_data_to_write_to_ram = b""
            overlay_was_decompressed_successfully = False
            code_section_comment_suffix = "(raw)"

            if overlay_entry.is_compressed:
                if not overlay_data_raw_from_rom:
                    self.logger.log_error(f"cannot decompress {segment_name_base}: no raw data from rom")
                    if overlay_entry.ram_size > 0:
                        num_failed_or_skipped += 1
                        continue
                else:
                    self.logger.log_info(f"  decompressing {segment_name_base}...")
                    try:
                        decompressed_data = self._mii_uncompress_backward(overlay_data_raw_from_rom)
                        actual_decompressed_size = len(decompressed_data)
                        self.logger.log_info(f"   {segment_name_base} actual decompressed size: 0x{actual_decompressed_size:x}")

                        if (
                            overlay_entry.ram_size > 0
                            and actual_decompressed_size != overlay_entry.ram_size
                        ):
                            self.logger.log_warn(
                                f"   {segment_name_base}: actual decompressed size differs from overlay table ram_size"
                            )

                        effective_ram_size_in_memory = actual_decompressed_size
                        final_data_to_write_to_ram = decompressed_data
                        overlay_was_decompressed_successfully = True
                        code_section_comment_suffix = "(decompressed)"
                    except Exception as e:
                        self.logger.log_error(f"failed to decompress {segment_name_base}: {e}")
                        code_section_comment_suffix = "(raw, decompression failed)"
            else:
                # Not compressed
                effective_ram_size_in_memory = overlay_size_in_rom_file
                final_data_to_write_to_ram = overlay_data_raw_from_rom
                code_section_comment_suffix = "(raw)"

            # Add segment for the code/data part
            if effective_ram_size_in_memory > 0:
                self.logger.log_info(
                    f"  adding segment for {segment_name_base} code/data: mem_addr=0x{load_address:08x}, "
                    f"mem_size=0x{effective_ram_size_in_memory:x}"
                )
                self.add_auto_segment(
                    load_address,
                    effective_ram_size_in_memory,
                    fat_entry.start_address,
                    overlay_size_in_rom_file,
                    self.PERM_RX,
                )
                
                # Write processed data if needed
                if overlay_was_decompressed_successfully or effective_ram_size_in_memory != overlay_size_in_rom_file:
                    self.logger.log_info(f"  writing {len(final_data_to_write_to_ram)} bytes of processed data")
                    bytes_written = self.write(load_address, final_data_to_write_to_ram)
                    if bytes_written != len(final_data_to_write_to_ram):
                        self.logger.log_error(f"{segment_name_base} data write error")

                self.add_auto_section(
                    name=f".{segment_name_base}",
                    start=load_address,
                    length=effective_ram_size_in_memory,
                    semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
                    type="OverlayCode",
                )
                self.set_comment_at(load_address, f"{segment_name_base} code/data start {code_section_comment_suffix}")
            elif overlay_entry.ram_size > 0:
                self.logger.log_warn(
                    f"  {segment_name_base} expected RAM size but no valid data was mapped for code/data section"
                )

            # Add BSS segment for the overlay
            if overlay_entry.bss_size > 0:
                bss_start_address = load_address + effective_ram_size_in_memory
                self.logger.log_info(
                    f"  mapping {segment_name_base} BSS: addr=0x{bss_start_address:08x}, size=0x{overlay_entry.bss_size:x}"
                )
                self.add_auto_segment(bss_start_address, overlay_entry.bss_size, 0, 0, self.PERM_RW)
                self.add_auto_section(
                    name=f".{segment_name_base}.bss",
                    start=bss_start_address,
                    length=overlay_entry.bss_size,
                    semantics=SectionSemantics.ReadWriteDataSectionSemantics,
                    type="OverlayBSS",
                )
                self.set_comment_at(bss_start_address, f"{segment_name_base} BSS start")

            # Define symbol for static initializer function if present
            if overlay_entry.static_initializer_start_address != 0:
                init_raw_addr = overlay_entry.static_initializer_start_address
                init_func_addr = init_raw_addr & ~1  # align to 2 bytes for ARM/Thumb

                # Check if the initializer address falls within the loaded code/data part
                if effective_ram_size_in_memory > 0 and (
                    load_address <= init_func_addr < load_address + effective_ram_size_in_memory
                ):
                    self.logger.log_info(f"  defining symbol for {segment_name_base} static initializer")
                    self.define_auto_symbol(
                        Symbol(SymbolType.FunctionSymbol, init_func_addr, f"{segment_name_base}_Init")
                    )
                    self.set_comment_at(
                        init_func_addr, f"{segment_name_base} static initializer (entry point for this overlay module)"
                    )
                else:
                    self.logger.log_warn(
                        f"  {segment_name_base} static initializer address is outside its loaded RAM region"
                    )
            num_loaded_successfully += 1

        # Final log
        log_func = self.logger.log_info if num_failed_or_skipped == 0 else self.logger.log_warn
        log_func(
            f"finished loading {cpu_name} overlays: {num_loaded_successfully} processed, {num_failed_or_skipped} failed or skipped"
        )

    def _define_all_io_registers(self) -> None:
        """Define symbols and tags for all known NDS I/O hardware registers."""
        self.logger.log_info("defining nds i/o hardware registers...")
        if not NDS_IO_REGISTERS:
            self.logger.log_info("NDS_IO_REGISTERS list is empty. no registers will be defined")
            return

        defined_count = 0
        for addr, name, tag_category, desc in NDS_IO_REGISTERS:
            self.logger.log_debug(f"  defining i/o register: {name} at 0x{addr:08x} (Category: {tag_category})")
            self._define_hardware_register(addr, name, tag_category, desc)
            defined_count += 1
        self.logger.log_info(f"defined {defined_count}/{len(NDS_IO_REGISTERS)} nds i/o registers")

    def _define_rom_entry_points(self) -> None:
        """
        Define the primary entry points for ARM9 and ARM7 processors based on
        information from the parsed ROM header.
        """
        if not self.nds_rom or not self.nds_rom.header:
            self.logger.log_error("cannot define rom entry points, rom structure not parsed")
            return

        header = self.nds_rom.header

        # ARM9 entry point
        arm9_entry_raw_from_header = header.arm9_entry_address
        self._primary_arm9_entry_point = arm9_entry_raw_from_header & ~1  # align function address
        arm9_expected_load_addr = header.arm9_ram_address

        # Validate that the entry point falls within an executable segment
        segment_at_arm9_entry = self.get_segment_at(self._primary_arm9_entry_point)
        if (
            segment_at_arm9_entry
            and segment_at_arm9_entry.start == arm9_expected_load_addr
            and segment_at_arm9_entry.executable
        ):
            self.logger.log_info(f"defining arm9 entry point: symbol '_start9' at 0x{self._primary_arm9_entry_point:08x}")
            self.add_entry_point(self._primary_arm9_entry_point)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, self._primary_arm9_entry_point, "_start9")
            )
        else:
            self.logger.log_warn(
                f"arm9 entry point 0x{self._primary_arm9_entry_point:08x} is not within a valid executable segment"
            )
            self._primary_arm9_entry_point = None

        # ARM7 entry point
        arm7_entry_raw_from_header = header.arm7_entry_address
        self._primary_arm7_entry_point = arm7_entry_raw_from_header & ~1
        arm7_expected_load_addr = header.arm7_ram_address

        segment_at_arm7_entry = self.get_segment_at(self._primary_arm7_entry_point)
        if (
            segment_at_arm7_entry
            and segment_at_arm7_entry.start == arm7_expected_load_addr
            and segment_at_arm7_entry.executable
        ):
            self.logger.log_info(f"defining arm7 entry point: symbol '_start7' at 0x{self._primary_arm7_entry_point:08x}")
            self.add_entry_point(self._primary_arm7_entry_point)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, self._primary_arm7_entry_point, "_start7")
            )
        else:
            self.logger.log_warn(
                f"arm7 entry point 0x{self._primary_arm7_entry_point:08x} is not within a valid executable segment"
            )
            self._primary_arm7_entry_point = None

        # Define debug ROM symbol if present
        if header.debug_rom_offset != 0 and header.debug_size > 0:
            debug_load_addr = header.debug_ram_address if header.debug_ram_address != 0 else 0x02400000
            self.logger.log_info(
                f"debug rom info found: defining data symbol 'arm9_debug_load_address' at 0x{debug_load_addr:08x}"
            )
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, debug_load_addr, "arm9_debug_load_address"))

    def init(self) -> bool:
        """
        Initialize the NDSView using the refactored architecture.
        """
        if not self.arch or not self.platform:
            self.logger.log_error("critical: architecture or platform is not set. cannot initialize NDSView")
            return False

        try:
            self.logger.log_info(f"starting nds rom loading process for '{self.file.filename}'...")

            # Step 1: Parse the NDS ROM structure
            if not self._parse_rom_structure():
                self.logger.log_error("failed to parse nds rom structure. aborting NDSView initialization")
                return False

            # Step 2: Initialize tag types (using inherited method)
            self._initialize_tag_types()

            # Step 3: Map fixed NDS hardware memory regions
            self._map_memory_regions()

            # Ensure NDS ROM and header are valid
            if not self.nds_rom or not self.nds_rom.header:
                self.logger.log_error("nds_rom object or its header is invalid after parsing. cannot load binaries")
                return False
            header = self.nds_rom.header

            # Step 4: Load ARM9 and ARM7 main binaries
            self._load_binary_segment(
                cpu_name="ARM9",
                rom_offset=header.arm9_rom_offset,
                rom_size=header.arm9_size,
                ram_address=header.arm9_ram_address,
                bss_size=header.arm9_bss_size,
                entry_address=header.arm9_entry_address,
                is_arm9_with_module_params=True,  # ARM9 binaries often use moduleparams
            )

            self._load_binary_segment(
                cpu_name="ARM7",
                rom_offset=header.arm7_rom_offset,
                rom_size=header.arm7_size,
                ram_address=header.arm7_ram_address,
                bss_size=header.arm7_bss_size,
                entry_address=header.arm7_entry_address,
                is_arm9_with_module_params=False,  # ARM7 binaries typically do not use moduleparams
            )

            # Step 5: Load ARM9 and ARM7 overlays
            self._load_overlays("ARM9", self.nds_rom.arm9_overlay_table)
            self._load_overlays("ARM7", self.nds_rom.arm7_overlay_table)

            # Step 6: Define known NDS I/O hardware registers
            self._define_all_io_registers()

            # Step 7: Define the program entry points
            self._define_rom_entry_points()

            self.logger.log_info("nds rom loading and setup steps complete. triggering analysis...")
            self.update_analysis()
            self.logger.log_info("analysis update triggered. initial analysis will run in the background")

            return True

        except Exception as e:
            self.logger.log_error(f"critical error during nds rom initialization: {e}")
            self.logger.log_error(f"traceback:\n{traceback.format_exc()}")
            return False

    def perform_is_executable(self) -> bool:
        """Indicate that NDS ROMs contain executable code."""
        return True

    def perform_get_entry_point(self) -> int:
        """
        Return the primary entry point address of the NDS ROM.
        Prioritizes ARM9 entry point, falls back to ARM7 if needed.
        """
        if self._primary_arm9_entry_point is not None:
            self.logger.log_debug(f"returning stored primary ARM9 entry point 0x{self._primary_arm9_entry_point:08x}")
            return self._primary_arm9_entry_point
        elif self._primary_arm7_entry_point is not None:
            self.logger.log_debug(f"returning stored primary ARM7 entry point 0x{self._primary_arm7_entry_point:08x}")
            return self._primary_arm7_entry_point
        elif self.entry_points and len(self.entry_points) > 0:
            self.logger.log_warn(
                f"falling back to first entry point in binary ninja's list: 0x{self.entry_points[0]:08x}"
            )
            return self.entry_points[0]

        # Last resort
        default_entry = self.start if self.start is not None else 0
        self.logger.log_error(
            f"no valid entry points found. returning start of view (0x{default_entry:08x}) or 0"
        )
        return default_entry

    def perform_get_address_size(self) -> int:
        """Return the address size for NDS, which is 4 bytes (32-bit addresses)."""
        return 4


# Register the NDSView class with Binary Ninja
NDSView.register()