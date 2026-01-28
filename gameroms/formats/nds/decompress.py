from __future__ import annotations

import struct


def mii_uncompress_backward(data: bytes) -> bytes:
    if len(data) < 8:
        raise ValueError("data too short for mii decompression")

    extra = struct.unpack_from("<I", data, len(data) - 4)[0]
    total_size = len(data) + extra
    if total_size <= 0 or total_size > 0x20000000:
        raise ValueError("decompressed size out of range")

    result = bytearray(total_size)
    result[: len(data)] = data

    header_val = struct.unpack_from("<I", data, len(data) - 8)[0]
    header_size = (header_val >> 24) & 0xFF
    comp_len = header_val & 0x00FFFFFF

    src_offset = len(data) - header_size
    dest_offset = total_size

    while True:
        if src_offset <= 0:
            raise EOFError("source exhausted (flags)")
        flags = result[src_offset - 1]
        src_offset -= 1

        for _ in range(8):
            if (flags & 0x80) == 0:
                if src_offset <= 0:
                    raise EOFError("source exhausted (literal)")
                dest_offset -= 1
                src_offset -= 1
                if dest_offset < 0:
                    raise IndexError("destination offset negative")
                result[dest_offset] = result[src_offset]
            else:
                if src_offset < 2:
                    raise EOFError("source exhausted (lz params)")
                byte_a = result[src_offset - 1]
                byte_b = result[src_offset - 2]
                src_offset -= 2

                disp = (((byte_a & 0x0F) << 8) | byte_b) + 2
                length = ((byte_a >> 4) & 0x0F) + 2
                for _ in range(length + 1):
                    if dest_offset <= 0:
                        raise IndexError("destination offset negative")
                    read_idx = dest_offset + disp
                    if read_idx >= total_size:
                        raise IndexError("lz77 read out of bounds")
                    result[dest_offset - 1] = result[read_idx]
                    dest_offset -= 1

            if src_offset <= (len(data) - comp_len):
                return bytes(result)
            flags = (flags << 1) & 0xFF
