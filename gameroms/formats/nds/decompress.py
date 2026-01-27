from __future__ import annotations

import struct


def mii_uncompress_backward(data: bytes) -> bytes:
    if len(data) < 4:
        raise ValueError("data too short for mii decompression")

    decompressed_size = struct.unpack_from("<I", data, len(data) - 4)[0]
    if decompressed_size > 0x10000000:
        raise ValueError("decompressed size too large")

    if len(data) < 8:
        if decompressed_size == 0:
            return b""
        if decompressed_size == len(data) - 4:
            return data[:-4]
        raise ValueError("data too short for header/footer structure")

    header_val = struct.unpack_from("<I", data, len(data) - 8)[0]
    comp_type = (header_val >> 24) & 0xF

    if decompressed_size == 0:
        if comp_type == 0x1 and header_val == 0x10000000:
            return b""
        return b""

    if comp_type != 0x1:
        return data[:-4]

    result = bytearray(decompressed_size)
    dest_offset = decompressed_size
    src_offset = len(data) - 8

    while dest_offset > 0:
        if src_offset <= 0:
            raise EOFError("source exhausted (flags)")
        flags = data[src_offset - 1]
        src_offset -= 1
        for _ in range(8):
            if dest_offset <= 0:
                break
            is_compressed = (flags & 0x80) != 0
            flags = (flags << 1) & 0xFF
            if not is_compressed:
                if src_offset <= 0:
                    raise EOFError("source exhausted (literal)")
                literal = data[src_offset - 1]
                src_offset -= 1
                dest_offset -= 1
                if dest_offset < 0:
                    raise IndexError("destination offset negative")
                result[dest_offset] = literal
            else:
                if src_offset < 2:
                    raise EOFError("source exhausted (lz params)")
                byte1 = data[src_offset - 1]
                byte2 = data[src_offset - 2]
                src_offset -= 2
                copy_length = ((byte1 & 0xF0) >> 4) + 3
                copy_disp = (((byte1 & 0x0F) << 8) | byte2) + 1
                if dest_offset < copy_length:
                    raise ValueError("copy length exceeds remaining output")
                for k in range(copy_length):
                    write_idx = dest_offset - 1 - k
                    read_idx = write_idx + copy_disp
                    if not (0 <= read_idx < decompressed_size):
                        raise IndexError("lz77 read out of bounds")
                    result[write_idx] = result[read_idx]
                dest_offset -= copy_length
    return bytes(result)
