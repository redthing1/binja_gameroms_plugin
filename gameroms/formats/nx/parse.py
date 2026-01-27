from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Callable


NSO0_MAGIC = b"NSO0"


@dataclass(frozen=True)
class Nso0SectionHeader:
    file_offset: int
    memory_offset: int
    decompressed_size: int


@dataclass(frozen=True)
class Nso0Header:
    version: int
    flags: int
    text: Nso0SectionHeader
    rodata: Nso0SectionHeader
    data: Nso0SectionHeader
    module_offset: int
    module_file_size: int
    bss_size: int
    build_id: bytes
    compressed_text_size: int
    compressed_rodata_size: int
    compressed_data_size: int

    def is_section_compressed(self, section_index: int) -> bool:
        return bool(self.flags & (1 << section_index))


class Nso0ParseError(RuntimeError):
    pass


def _read_u32(blob: bytes, off: int) -> int:
    return struct.unpack_from("<I", blob, off)[0]


def _read_section(blob: bytes, off: int) -> Nso0SectionHeader:
    file_offset, memory_offset, dec_size = struct.unpack_from("<III", blob, off)
    return Nso0SectionHeader(file_offset, memory_offset, dec_size)


def parse_nso0_header(blob: bytes) -> Nso0Header:
    if len(blob) < 0x6C:
        raise Nso0ParseError("NSO0 file too small")
    magic = blob[0:4]
    if magic != NSO0_MAGIC:
        raise Nso0ParseError("invalid NSO0 magic")

    version = _read_u32(blob, 0x4)
    flags = _read_u32(blob, 0xC)

    text = _read_section(blob, 0x10)
    module_offset = _read_u32(blob, 0x1C)
    rodata = _read_section(blob, 0x20)
    module_file_size = _read_u32(blob, 0x2C)
    data = _read_section(blob, 0x30)
    bss_size = _read_u32(blob, 0x3C)
    build_id = blob[0x40:0x60]

    compressed_text_size = _read_u32(blob, 0x60)
    compressed_rodata_size = _read_u32(blob, 0x64)
    compressed_data_size = _read_u32(blob, 0x68)

    return Nso0Header(
        version=version,
        flags=flags,
        text=text,
        rodata=rodata,
        data=data,
        module_offset=module_offset,
        module_file_size=module_file_size,
        bss_size=bss_size,
        build_id=build_id,
        compressed_text_size=compressed_text_size,
        compressed_rodata_size=compressed_rodata_size,
        compressed_data_size=compressed_data_size,
    )


def extract_nso0_sections(
    blob: bytes,
    header: Nso0Header,
    lz4_decompress: Callable[[bytes, int], bytes],
) -> tuple[bytes, dict[str, int]]:
    def _section_blob(section: Nso0SectionHeader, comp_size: int, idx: int) -> bytes:
        if header.is_section_compressed(idx):
            comp = blob[section.file_offset : section.file_offset + comp_size]
            return lz4_decompress(comp, section.decompressed_size)
        return blob[
            section.file_offset : section.file_offset + section.decompressed_size
        ]

    text_blob = _section_blob(header.text, header.compressed_text_size, 0)
    rodata_blob = _section_blob(header.rodata, header.compressed_rodata_size, 1)
    data_blob = _section_blob(header.data, header.compressed_data_size, 2)

    max_end = max(
        header.text.memory_offset + header.text.decompressed_size,
        header.rodata.memory_offset + header.rodata.decompressed_size,
        header.data.memory_offset + header.data.decompressed_size,
    )

    image = bytearray(max_end)
    image[
        header.text.memory_offset : header.text.memory_offset
        + header.text.decompressed_size
    ] = text_blob
    image[
        header.rodata.memory_offset : header.rodata.memory_offset
        + header.rodata.decompressed_size
    ] = rodata_blob
    image[
        header.data.memory_offset : header.data.memory_offset
        + header.data.decompressed_size
    ] = data_blob

    meta = {
        "text_offset": header.text.memory_offset,
        "text_size": header.text.decompressed_size,
        "rodata_offset": header.rodata.memory_offset,
        "rodata_size": header.rodata.decompressed_size,
        "data_offset": header.data.memory_offset,
        "data_size": header.data.decompressed_size,
    }

    return bytes(image), meta
