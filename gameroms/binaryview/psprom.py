from binaryninja import *
import struct
import io
import traceback

from ..readers.psp_pbp import PBPReader


class PSPView(BinaryView):
    name = "PSP"
    long_name = "PlayStation Portable"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data
        self.log = self.create_logger("PSP")
        self.pbp_data = None
        self.elf_data = None
        # PSP uses MIPS R4000 (mipsel)
        self.arch = Architecture["mipsel32"]
        self.platform = Architecture["mipsel32"].standalone_platform

    @classmethod
    def is_valid_for_data(cls, data):
        # check for PBP signature
        try:
            return PBPReader.is_valid(data.read(0, 4))
        except:
            return False

    def init(self):
        try:
            # read the entire PBP file
            self.log.log_info("Reading PSP EBOOT.PBP file")
            raw_data = self.raw.read(0, len(self.raw))
            self.pbp_data = PBPReader.read(raw_data)

            # extract the ELF executable
            self.elf_data = self.pbp_data["psp_data"]

            # Check if it's a valid ELF file
            if not self._is_valid_elf():
                self.log.log_error("Invalid ELF executable in PBP")
                return False

            # parse basic ELF header information
            self._parse_elf_header()

            # set up PSP memory map
            self._setup_memory_map()

            # load program segments
            self._load_program_segments()

            self.log.log_info("PSP ROM loaded successfully")
            return True
        except Exception as e:
            self.log.log_error(
                f"Error loading PSP ROM: {str(e)}\n{traceback.format_exc()}"
            )
            return False

    def _is_valid_elf(self):
        # check ELF magic bytes
        return self.elf_data[:4] == b"\x7fELF"

    def _parse_elf_header(self):
        # basic ELF header parsing
        self.elf_type = struct.unpack_from("<H", self.elf_data, 0x10)[0]
        self.elf_machine = struct.unpack_from("<H", self.elf_data, 0x12)[0]
        self.elf_version = struct.unpack_from("<I", self.elf_data, 0x14)[0]
        self.elf_entry = struct.unpack_from("<I", self.elf_data, 0x18)[0]
        self.elf_phoff = struct.unpack_from("<I", self.elf_data, 0x1C)[0]
        self.elf_shoff = struct.unpack_from("<I", self.elf_data, 0x20)[0]
        self.elf_flags = struct.unpack_from("<I", self.elf_data, 0x24)[0]
        self.elf_ehsize = struct.unpack_from("<H", self.elf_data, 0x28)[0]
        self.elf_phentsize = struct.unpack_from("<H", self.elf_data, 0x2A)[0]
        self.elf_phnum = struct.unpack_from("<H", self.elf_data, 0x2C)[0]
        self.elf_shentsize = struct.unpack_from("<H", self.elf_data, 0x2E)[0]
        self.elf_shnum = struct.unpack_from("<H", self.elf_data, 0x30)[0]
        self.elf_shstrndx = struct.unpack_from("<H", self.elf_data, 0x32)[0]

        self.log.log_info(f"ELF Entry point: 0x{self.elf_entry:08x}")

    def _setup_memory_map(self):
        # PSP memory map
        # Main RAM: 32MB (0x08000000 - 0x09FFFFFF)
        self.add_auto_segment(
            0x08000000,
            0x2000000,
            0,
            0,
            SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentWritable
            | SegmentFlag.SegmentExecutable,
        )

        # VRAM: 2MB (0x04000000 - 0x041FFFFF)
        self.add_auto_segment(
            0x04000000,
            0x200000,
            0,
            0,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
        )

        # Scratchpad: 64KB (0x00010000 - 0x0001FFFF)
        self.add_auto_segment(
            0x00010000,
            0x10000,
            0,
            0,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
        )

    def _load_program_segments(self):
        # load ELF program headers and segments
        for i in range(self.elf_phnum):
            phdr_offset = self.elf_phoff + i * self.elf_phentsize

            # parse program header
            p_type = struct.unpack_from("<I", self.elf_data, phdr_offset)[0]
            p_offset = struct.unpack_from("<I", self.elf_data, phdr_offset + 0x4)[0]
            p_vaddr = struct.unpack_from("<I", self.elf_data, phdr_offset + 0x8)[0]
            p_paddr = struct.unpack_from("<I", self.elf_data, phdr_offset + 0xC)[0]
            p_filesz = struct.unpack_from("<I", self.elf_data, phdr_offset + 0x10)[0]
            p_memsz = struct.unpack_from("<I", self.elf_data, phdr_offset + 0x14)[0]
            p_flags = struct.unpack_from("<I", self.elf_data, phdr_offset + 0x18)[0]
            p_align = struct.unpack_from("<I", self.elf_data, phdr_offset + 0x1C)[0]

            # Skip non-LOAD segments
            if p_type != 1:  # PT_LOAD
                continue

            # Determine segment flags
            segment_flags = SegmentFlag.SegmentReadable
            if p_flags & 2:  # PF_W
                segment_flags |= SegmentFlag.SegmentWritable
            if p_flags & 1:  # PF_X
                segment_flags |= SegmentFlag.SegmentExecutable

            # Add segment
            self.add_auto_segment(p_vaddr, p_memsz, p_offset, p_filesz, segment_flags)

            self.log.log_info(f"Added segment at 0x{p_vaddr:08x}, size 0x{p_memsz:x}")

        # Add entry point
        if self.elf_entry:
            self.add_entry_point(self.elf_entry)
            self.add_function(self.elf_entry)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, self.elf_entry, "_start")
            )

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.elf_entry if hasattr(self, "elf_entry") else 0

    def perform_get_address_size(self):
        return 4  # 32-bit addresses


PSPView.register()
