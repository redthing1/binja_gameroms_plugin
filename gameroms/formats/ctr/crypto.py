from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


@dataclass(frozen=True)
class NcchKeys:
    key0: bytes
    key1: bytes


def _rol128(value: int, bits: int) -> int:
    bits &= 0x7F
    return ((value << bits) | (value >> (128 - bits))) & ((1 << 128) - 1)


def _ror128(value: int, bits: int) -> int:
    bits &= 0x7F
    return ((value >> bits) | (value << (128 - bits))) & ((1 << 128) - 1)


def derive_ncch_key(key_x: bytes, key_y: bytes, generator: bytes) -> bytes:
    if len(key_x) != 16 or len(key_y) != 16 or len(generator) != 16:
        raise ValueError("AES keys must be 16 bytes")
    x_int = int.from_bytes(key_x, "big")
    y_int = int.from_bytes(key_y, "big")
    gen_int = int.from_bytes(generator, "big")
    mixed = (_rol128(x_int, 2) ^ y_int) + gen_int
    mixed &= (1 << 128) - 1
    key_int = _ror128(mixed, 41)
    return key_int.to_bytes(16, "big")


def increment_aes_counter(counter: bytes, blocks: int) -> bytes:
    if len(counter) != 16:
        raise ValueError("AES counter must be 16 bytes")
    value = int.from_bytes(counter, "big")
    value = (value + blocks) & ((1 << 128) - 1)
    return value.to_bytes(16, "big")


def aes_ctr_crypt(data: bytes, key: bytes, counter: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(counter))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def aes_counter_for_ncch(
    format_version: int, title_id: int, region_type: int, region_offset: int
) -> bytes:
    if format_version == 1:
        title_le = title_id.to_bytes(8, "little")
        offset_be = region_offset.to_bytes(8, "big")
        return title_le + offset_be
    title_be = title_id.to_bytes(8, "big")
    return title_be + bytes([region_type]) + (b"\x00" * 7)
