from __future__ import annotations

import struct


def lzss_decompressed_size(data: bytes) -> int:
    if len(data) < 8:
        raise ValueError("LZSS data too short")
    original_bottom = struct.unpack_from("<I", data, len(data) - 4)[0]
    return original_bottom + len(data)


def lzss_decompress(data: bytes) -> bytes:
    if len(data) < 8:
        raise ValueError("LZSS data too short")

    compressed_size = len(data)
    buffertopandbottom = struct.unpack_from("<I", data, compressed_size - 8)[0]
    original_bottom = struct.unpack_from("<I", data, compressed_size - 4)[0]
    decompressed_size = original_bottom + compressed_size

    out = decompressed_size
    index = compressed_size - ((buffertopandbottom >> 24) & 0xFF)
    stopindex = compressed_size - (buffertopandbottom & 0xFFFFFF)

    decompressed = bytearray(decompressed_size)
    decompressed[:compressed_size] = data

    while index > stopindex:
        index -= 1
        control = data[index]

        for _ in range(8):
            if index <= stopindex or index <= 0 or out <= 0:
                break

            if control & 0x80:
                if index < 2:
                    raise ValueError("LZSS out of bounds")

                index -= 2
                segment_offset = data[index] | (data[index + 1] << 8)
                segment_size = ((segment_offset >> 12) & 0xF) + 3
                segment_offset = (segment_offset & 0x0FFF) + 2

                if out < segment_size:
                    raise ValueError("LZSS out of bounds")

                for _ in range(segment_size):
                    if out + segment_offset >= decompressed_size:
                        raise ValueError("LZSS out of bounds")
                    byte_val = decompressed[out + segment_offset]
                    out -= 1
                    decompressed[out] = byte_val
            else:
                if out < 1:
                    raise ValueError("LZSS out of bounds")
                out -= 1
                index -= 1
                decompressed[out] = data[index]

            control = (control << 1) & 0xFF

    return bytes(decompressed)
