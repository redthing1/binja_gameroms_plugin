from __future__ import annotations


class Yaz0DecompressionError(RuntimeError):
    pass


YAZ0_MAGIC = b"Yaz0"


def is_yaz0(data: bytes) -> bool:
    return data.startswith(YAZ0_MAGIC)


def decompress_yaz0(data: bytes) -> bytes:
    if not is_yaz0(data):
        raise Yaz0DecompressionError("not Yaz0")
    if len(data) < 0x10:
        raise Yaz0DecompressionError("Yaz0 header too small")
    decompressed_size = int.from_bytes(data[4:8], "big")
    out = bytearray(decompressed_size)

    read_pos = 0x10
    source_bitfield = 0
    source_byte = 0
    write_pos = 0

    while write_pos < decompressed_size:
        local_read_pos = read_pos
        if source_bitfield == 0:
            if read_pos >= len(data):
                raise Yaz0DecompressionError("unexpected end of Yaz0 stream")
            source_byte = data[read_pos]
            source_bitfield = 0x80
            local_read_pos = read_pos + 1

        if (source_byte & source_bitfield) == 0:
            if local_read_pos + 1 >= len(data):
                raise Yaz0DecompressionError("unexpected end of Yaz0 stream")
            bit_info = int.from_bytes(data[local_read_pos : local_read_pos + 2], "big")
            read_pos = local_read_pos + 2

            write_size = (bit_info >> 12) & 0xF
            read_offset = write_pos - (bit_info & 0x0FFF)
            if write_size == 0:
                if read_pos >= len(data):
                    raise Yaz0DecompressionError("unexpected end of Yaz0 stream")
                write_size = data[read_pos] + 0x12
                read_pos += 1
            else:
                write_size += 2

            for _ in range(write_size):
                if write_pos >= decompressed_size:
                    break
                src_idx = read_offset - 1
                if src_idx < 0 or src_idx >= len(out):
                    raise Yaz0DecompressionError("invalid Yaz0 back-reference")
                out[write_pos] = out[src_idx]
                write_pos += 1
                read_offset += 1
        else:
            if local_read_pos >= len(data):
                raise Yaz0DecompressionError("unexpected end of Yaz0 stream")
            out[write_pos] = data[local_read_pos]
            write_pos += 1
            read_pos = local_read_pos + 1

        source_bitfield >>= 1

    return bytes(out)
