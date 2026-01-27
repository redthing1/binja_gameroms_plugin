from __future__ import annotations

import posixpath
import struct
from dataclasses import dataclass

U8_MAGIC = b"\x55\xaa\x38\x2d"
U8_HEADER_STRUCT = struct.Struct(">IIII")
U8_NODE_STRUCT = struct.Struct(">III")


class U8ParseError(RuntimeError):
    pass


@dataclass(frozen=True)
class U8Entry:
    path: str
    offset: int
    size: int


def is_u8(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == U8_MAGIC


def _read_cstr(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("ascii", errors="replace")


def parse_u8(data: bytes) -> list[U8Entry]:
    if len(data) < U8_HEADER_STRUCT.size:
        raise U8ParseError("u8 header too small")

    magic, root_off, header_size, data_off = U8_HEADER_STRUCT.unpack_from(data, 0)
    if magic != int.from_bytes(U8_MAGIC, "big"):
        raise U8ParseError("u8 magic mismatch")
    if root_off + U8_NODE_STRUCT.size > len(data):
        raise U8ParseError("u8 root node offset out of range")
    if data_off > len(data):
        raise U8ParseError("u8 data offset out of range")

    root_type_name, root_data_off, root_size = U8_NODE_STRUCT.unpack_from(
        data, root_off
    )
    node_count = root_size
    node_table_size = node_count * U8_NODE_STRUCT.size
    string_table_off = root_off + node_table_size
    if string_table_off > len(data):
        raise U8ParseError("u8 string table offset out of range")

    entries: list[U8Entry] = []
    stack: list[tuple[int, str]] = [(node_count, "")]

    for index in range(1, node_count):
        node_off = root_off + index * U8_NODE_STRUCT.size
        if node_off + U8_NODE_STRUCT.size > len(data):
            raise U8ParseError("u8 node table truncated")
        type_name, node_data_off, node_size = U8_NODE_STRUCT.unpack_from(data, node_off)
        node_type = (type_name >> 24) & 0xFF
        name_off = type_name & 0x00FFFFFF

        while stack and index >= stack[-1][0]:
            stack.pop()
        parent_path = stack[-1][1] if stack else ""

        name = _read_cstr(data, string_table_off + name_off)
        if not name:
            continue

        if node_type == 1:
            dir_path = posixpath.join(parent_path, name) if parent_path else name
            stack.append((node_size, dir_path))
            continue

        file_path = posixpath.join(parent_path, name) if parent_path else name
        file_off = data_off + node_data_off
        if file_off + node_size > len(data):
            raise U8ParseError("u8 file data out of range")
        entries.append(U8Entry(path=file_path, offset=file_off, size=node_size))

    return entries
