from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterable

MEDIA_UNIT_DEFAULT = 0x200


@dataclass(frozen=True)
class NcchHeader:
    signature: bytes
    content_size_blocks: int
    partition_id: int
    format_version: int
    seed_checksum: bytes
    program_id: int
    product_code: str
    exhdr_hash: bytes
    exhdr_size: int
    flags: bytes
    block_size_log: int
    content_keyx: int
    content_platform: int
    content_type: int
    other_flags: int
    plain_offset: int
    plain_size: int
    logo_offset: int
    logo_size: int
    exefs_offset: int
    exefs_size: int
    exefs_hash_size: int
    romfs_offset: int
    romfs_size: int
    romfs_hash_size: int


@dataclass(frozen=True)
class CodeSetInfo:
    address: int
    page_count: int
    size: int


@dataclass(frozen=True)
class ExHeaderSci:
    title: str
    flags: int
    remaster_version: int
    text: CodeSetInfo
    rodata: CodeSetInfo
    data: CodeSetInfo
    bss_size: int
    stack_size: int
    save_data_size: int
    jump_id: int

    @property
    def code_is_compressed(self) -> bool:
        return bool(self.flags & 0x1)


@dataclass(frozen=True)
class ExeFsFileEntry:
    name: str
    offset: int
    size: int


@dataclass(frozen=True)
class CodeLayout:
    text_offset: int
    rodata_offset: int
    data_offset: int
    layout: str


def _u32le(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buf, offset)[0]


def _u16le(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<H", buf, offset)[0]


def _u64le(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", buf, offset)[0]


def parse_ncch_header(buf: bytes) -> NcchHeader:
    if len(buf) < 0x200:
        raise ValueError("NCCH header too small")
    magic = buf[0x100:0x104]
    if magic != b"NCCH":
        raise ValueError("NCCH magic not found")

    signature = buf[0x0:0x100]
    content_size_blocks = _u32le(buf, 0x104)
    partition_id = _u64le(buf, 0x108)
    format_version = _u16le(buf, 0x112)
    seed_checksum = buf[0x114:0x118]
    program_id = _u64le(buf, 0x118)
    product_code = buf[0x150:0x160].split(b"\x00", 1)[0].decode("ascii", "replace")
    exhdr_hash = buf[0x160:0x180]
    exhdr_size = _u32le(buf, 0x180)
    flags = buf[0x188:0x190]

    block_size_log = flags[6]
    content_keyx = flags[3]
    content_platform = flags[4]
    content_type = flags[5]
    other_flags = flags[7]

    plain_offset = _u32le(buf, 0x190)
    plain_size = _u32le(buf, 0x194)
    logo_offset = _u32le(buf, 0x198)
    logo_size = _u32le(buf, 0x19C)
    exefs_offset = _u32le(buf, 0x1A0)
    exefs_size = _u32le(buf, 0x1A4)
    exefs_hash_size = _u32le(buf, 0x1A8)
    romfs_offset = _u32le(buf, 0x1B0)
    romfs_size = _u32le(buf, 0x1B4)
    romfs_hash_size = _u32le(buf, 0x1B8)

    return NcchHeader(
        signature=signature,
        content_size_blocks=content_size_blocks,
        partition_id=partition_id,
        format_version=format_version,
        seed_checksum=seed_checksum,
        program_id=program_id,
        product_code=product_code,
        exhdr_hash=exhdr_hash,
        exhdr_size=exhdr_size,
        flags=flags,
        block_size_log=block_size_log,
        content_keyx=content_keyx,
        content_platform=content_platform,
        content_type=content_type,
        other_flags=other_flags,
        plain_offset=plain_offset,
        plain_size=plain_size,
        logo_offset=logo_offset,
        logo_size=logo_size,
        exefs_offset=exefs_offset,
        exefs_size=exefs_size,
        exefs_hash_size=exefs_hash_size,
        romfs_offset=romfs_offset,
        romfs_size=romfs_size,
        romfs_hash_size=romfs_hash_size,
    )


def parse_exheader_sci(buf: bytes) -> ExHeaderSci:
    if len(buf) < 0x200:
        raise ValueError("ExHeader SCI buffer too small")

    title = buf[0x0:0x8].split(b"\x00", 1)[0].decode("ascii", "replace")
    flags = buf[0x0D]
    remaster_version = _u16le(buf, 0x0E)

    text = CodeSetInfo(
        address=_u32le(buf, 0x10),
        page_count=_u32le(buf, 0x14),
        size=_u32le(buf, 0x18),
    )
    stack_size = _u32le(buf, 0x1C)
    rodata = CodeSetInfo(
        address=_u32le(buf, 0x20),
        page_count=_u32le(buf, 0x24),
        size=_u32le(buf, 0x28),
    )
    data = CodeSetInfo(
        address=_u32le(buf, 0x30),
        page_count=_u32le(buf, 0x34),
        size=_u32le(buf, 0x38),
    )
    bss_size = _u32le(buf, 0x3C)

    save_data_size = struct.unpack_from("<Q", buf, 0x1C0)[0]
    jump_id = struct.unpack_from("<Q", buf, 0x1C8)[0]

    return ExHeaderSci(
        title=title,
        flags=flags,
        remaster_version=remaster_version,
        text=text,
        rodata=rodata,
        data=data,
        bss_size=bss_size,
        stack_size=stack_size,
        save_data_size=save_data_size,
        jump_id=jump_id,
    )


def parse_exefs_header(buf: bytes) -> list[ExeFsFileEntry]:
    if len(buf) < 0x200:
        raise ValueError("ExeFS header too small")
    entries: list[ExeFsFileEntry] = []
    for i in range(10):
        entry = buf[i * 0x10 : i * 0x10 + 0x10]
        name_raw = entry[0:8].split(b"\x00", 1)[0]
        if not name_raw:
            continue
        name = name_raw.decode("ascii", "replace")
        offset = _u32le(entry, 0x8)
        size = _u32le(entry, 0xC)
        entries.append(ExeFsFileEntry(name=name, offset=offset, size=size))
    return entries


def choose_code_layout(
    sci: ExHeaderSci, code_len: int, page_size: int = 0x1000
) -> CodeLayout:
    text_size = sci.text.size
    ro_size = sci.rodata.size
    data_size = sci.data.size
    text_pages = sci.text.page_count
    ro_pages = sci.rodata.page_count
    data_pages = sci.data.page_count

    raw_ro = text_size
    raw_data = text_size + ro_size
    raw_total = raw_data + data_size

    paged_ro = text_pages * page_size
    paged_data = paged_ro + ro_pages * page_size
    paged_total = paged_data + data_pages * page_size

    off_ro = sci.rodata.address - sci.text.address
    off_data = sci.data.address - sci.text.address

    if off_ro == paged_ro and off_data == paged_data:
        layout = "paged"
        text_off = 0
        ro_off = paged_ro
        data_off = paged_data
    elif off_ro == raw_ro and off_data == raw_data:
        layout = "raw"
        text_off = 0
        ro_off = raw_ro
        data_off = raw_data
    else:
        if paged_total > raw_total and code_len >= paged_total:
            layout = "paged"
            text_off = 0
            ro_off = paged_ro
            data_off = paged_data
        else:
            layout = "raw"
            text_off = 0
            ro_off = raw_ro
            data_off = raw_data

    if code_len < data_off + data_size:
        raise ValueError(".code blob too small for computed layout")

    return CodeLayout(
        text_offset=text_off, rodata_offset=ro_off, data_offset=data_off, layout=layout
    )


def iter_exefs_entries(
    entries: Iterable[ExeFsFileEntry], *names: str
) -> ExeFsFileEntry | None:
    name_set = set(names)
    for entry in entries:
        if entry.name in name_set:
            return entry
    return None
