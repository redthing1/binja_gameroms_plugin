from __future__ import annotations


class Lz4DecompressionError(RuntimeError):
    pass


def _read_length(src: bytes, idx: int, initial: int) -> tuple[int, int]:
    length = initial
    if length != 0xF:
        return length, idx
    while True:
        if idx >= len(src):
            raise Lz4DecompressionError("unexpected end of input while reading length")
        b = src[idx]
        idx += 1
        length += b
        if b != 0xFF:
            break
    return length, idx


def decompress_block(src: bytes, out_size: int) -> bytes:
    dst = bytearray(out_size)
    src_idx = 0
    dst_idx = 0

    while src_idx < len(src):
        token = src[src_idx]
        src_idx += 1

        lit_len = token >> 4
        lit_len, src_idx = _read_length(src, src_idx, lit_len)

        if src_idx + lit_len > len(src):
            raise Lz4DecompressionError("literal length exceeds input")
        if dst_idx + lit_len > out_size:
            raise Lz4DecompressionError("literal length exceeds output size")

        if lit_len:
            dst[dst_idx : dst_idx + lit_len] = src[src_idx : src_idx + lit_len]
            src_idx += lit_len
            dst_idx += lit_len

        if src_idx >= len(src):
            break

        if src_idx + 2 > len(src):
            raise Lz4DecompressionError("missing match offset")

        offset = src[src_idx] | (src[src_idx + 1] << 8)
        src_idx += 2
        if offset == 0:
            raise Lz4DecompressionError("invalid match offset 0")

        match_len = token & 0x0F
        match_len, src_idx = _read_length(src, src_idx, match_len)
        match_len += 4

        if dst_idx - offset < 0:
            raise Lz4DecompressionError("match offset before start of output")
        if dst_idx + match_len > out_size:
            raise Lz4DecompressionError("match length exceeds output size")

        # Copy with overlap handling
        for i in range(match_len):
            dst[dst_idx + i] = dst[dst_idx - offset + i]
        dst_idx += match_len

    if dst_idx != out_size:
        raise Lz4DecompressionError(
            f"decompressed size mismatch: got 0x{dst_idx:X} expected 0x{out_size:X}"
        )

    return bytes(dst)
