"""Embedded SPU ELF discovery without copying assets or local-store zero-fill."""

from dataclasses import dataclass
import hashlib
import struct

from .elf import checked_range, validate_ranges
from .model import Module


HEADER = struct.Struct(">16sHHIIIIIHHHHHH")
PROGRAM = struct.Struct(">IIIIIIII")
SECTION = struct.Struct(">IIIIIIIIII")
LOCAL_STORE_SIZE = 0x40000
MAX_IMAGE_SIZE = 64 * 1024 * 1024


@dataclass(frozen=True)
class SpuSegment:
    offset: int
    address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int


@dataclass(frozen=True)
class SpuImage:
    address: int
    file_size: int
    kind: int
    entry: int
    name: str
    payload_hash: str
    segments: tuple[SpuSegment, ...]
    relocations: bool


def _note_name(data: bytes) -> str:
    offset = 0
    name = ""
    while offset < len(data):
        checked_range(offset, 12, len(data), "SPU note header")
        name_size, description_size, kind = struct.unpack_from(">III", data, offset)
        owner = offset + 12
        checked_range(owner, name_size, len(data), "SPU note owner")
        description = (owner + name_size + 3) & ~3
        checked_range(description, description_size, len(data), "SPU note description")
        if kind == 1 and data[owner:owner + name_size] == b"SPUNAME\0":
            name = data[description:description + description_size].split(b"\0", 1)[0].decode("ascii", errors="replace")
        offset = (description + description_size + 3) & ~3
        if offset > len(data):
            raise ValueError("SPU note padding exceeds payload")
    return name


def parse_spu(data: bytes | bytearray, offset: int = 0, address: int = 0) -> SpuImage:
    checked_range(offset, HEADER.size, len(data), "SPU ELF header")
    header = HEADER.unpack_from(data, offset)
    ident, kind, machine, version, entry, phoff, shoff, _, size, phsize, phnum, shsize, shnum, _ = header
    if ident[:7] != b"\x7fELF\x01\x02\x01" or machine != 23 or version != 1 or kind not in (2, 3):
        raise ValueError("expected an ELF32 big-endian SPU image")
    if size != HEADER.size or phsize != PROGRAM.size or not phnum:
        raise ValueError("invalid SPU program-header table")
    checked_range(offset + phoff, phsize * phnum, len(data), "SPU program headers")
    extent = max(size, phoff + phsize * phnum)
    segments = []
    name = ""
    payload = hashlib.sha256()
    relocations = False
    for index in range(phnum):
        item = PROGRAM.unpack_from(data, offset + phoff + index * phsize)
        ptype, source, base, _, file_size, memory_size, flags, alignment = item
        checked_range(offset + source, file_size, len(data), "SPU segment payload")
        extent = max(extent, source + file_size)
        if ptype == 1:
            checked_range(base, memory_size, LOCAL_STORE_SIZE, "SPU local store")
            if file_size > memory_size:
                raise ValueError("SPU file bytes exceed segment memory")
            if alignment > 1 and (alignment & (alignment - 1) or source % alignment != base % alignment):
                raise ValueError("invalid SPU segment alignment")
            segments.append(SpuSegment(source, base, file_size, memory_size, flags, alignment))
            payload.update(data[offset + source:offset + source + file_size])
        elif ptype == 4:
            name = _note_name(data[offset + source:offset + source + file_size]) or name
    if shnum:
        if shsize != SECTION.size:
            raise ValueError("invalid SPU section-header width")
        checked_range(offset + shoff, shsize * shnum, len(data), "SPU section headers")
        extent = max(extent, shoff + shsize * shnum)
        headers = [SECTION.unpack_from(data, offset + shoff + index * shsize) for index in range(shnum)]
        for section in headers:
            if section[1] not in (0, 8):
                checked_range(offset + section[4], section[5], len(data), "SPU section payload")
                extent = max(extent, section[4] + section[5])
        relocations = any(section[1] in (4, 9) and section[5] for section in headers)
    validate_ranges([(item.address, item.address + item.memory_size) for item in segments], "SPU load ranges")
    if entry % 4 or not any(item.flags & 1 and item.address <= entry < item.address + item.memory_size
                            for item in segments):
        raise ValueError("SPU entry is outside aligned executable memory")
    if extent > MAX_IMAGE_SIZE:
        raise ValueError("SPU ELF image exceeds the supported size limit")
    return SpuImage(address, extent, kind, entry, name, payload.hexdigest(), tuple(segments), relocations)


def discover_spu(module: Module) -> tuple[SpuImage, ...]:
    images = []
    for segment in module.segments:
        offset = segment.data.find(b"\x7fELF")
        while offset >= 0:
            try:
                images.append(parse_spu(segment.data, offset, segment.address + offset))
            except ValueError:
                pass  # executable data can contain ELF magic without an embedded SPU image.
            offset = segment.data.find(b"\x7fELF", offset + 4)
    return tuple(images)
