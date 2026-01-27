#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gameroms.formats.ctr.crypto import (
    aes_counter_for_ncch,
    aes_ctr_crypt,
    derive_ncch_key,
    increment_aes_counter,
)
from gameroms.formats.ctr.lzss import lzss_decompress
from gameroms.formats.ctr.parse import (
    NcchHeader,
    choose_code_layout,
    iter_exefs_entries,
    parse_exefs_header,
    parse_exheader_sci,
    parse_ncch_header,
)

CXIEXE_MAGIC = b"CXIEXE\x00\x00"
CXIEXE_VERSION = 1
CXIEXE_HEADER_STRUCT = struct.Struct("<8sIIII")

NO_CRYPTO_FLAG = 1 << 2
FIXED_KEY_FLAG = 1 << 0
SEEDED_KEYY_FLAG = 1 << 5

KEYX_SLOT_MAP = {
    0x00: 0x2C,
    0x01: 0x25,
    0x0A: 0x18,
    0x0B: 0x1B,
}


@dataclass(frozen=True)
class ParsedKeys:
    generator: bytes
    keyx: dict[int, bytes]


class CxiexeError(Exception):
    pass


def _read_at(f, offset: int, size: int) -> bytes:
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise CxiexeError(f"failed to read {size} bytes at 0x{offset:X}")
    return data


def _parse_keys_file(path: Path) -> ParsedKeys:
    generator: bytes | None = None
    keyx: dict[int, bytes] = {}

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("generator="):
            generator = bytes.fromhex(line.split("=", 1)[1])
            continue
        if line.startswith("slot0x") and "KeyX" in line:
            left, value = line.split("=", 1)
            slot_hex = left[len("slot") : left.index("KeyX")]
            slot = int(slot_hex, 16)
            keyx[slot] = bytes.fromhex(value.strip())

    if generator is None:
        raise CxiexeError("keys file missing generator")
    return ParsedKeys(generator=generator, keyx=keyx)


def _default_output_path(input_path: Path) -> Path:
    if input_path.suffix:
        return input_path.with_suffix(".cxiexe")
    return input_path.with_name(f"{input_path.name}.cxiexe")


def _auto_keys_path(input_path: Path) -> Path | None:
    candidates = [
        Path.cwd() / "aes_keys.txt",
        input_path.parent / "aes_keys.txt",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _load_seed_from_db(path: Path, program_id: int) -> bytes | None:
    data = path.read_bytes()
    if len(data) < 0x10:
        return None
    n_entries = struct.unpack_from("<I", data, 0)[0]
    offset = 0x10
    for _ in range(n_entries):
        if offset + 0x20 > len(data):
            break
        title_id = struct.unpack_from("<Q", data, offset)[0]
        seed = data[offset + 8 : offset + 0x18]
        if title_id == program_id:
            return seed
        offset += 0x20
    return None


def _maybe_detect_decrypted(f, header: NcchHeader, exhdr_size: int) -> bool:
    if exhdr_size == 0:
        return False
    raw = _read_at(f, 0x200, exhdr_size)
    digest = hashlib.sha256(raw).digest()
    return digest[: len(header.exhdr_hash)] == header.exhdr_hash


def _resolve_exheader_size(header: NcchHeader) -> int:
    if header.exhdr_size != 0:
        return header.exhdr_size
    if header.exhdr_hash != b"\x00" * len(header.exhdr_hash):
        return 0x400
    return 0


def _block_size(header: NcchHeader) -> int:
    if header.format_version == 1:
        return 1
    return 1 << (header.block_size_log + 9)


def _compute_ncch_keys(
    header: NcchHeader,
    keys: ParsedKeys,
    seed: bytes | None,
    fixed_key: bytes | None,
) -> tuple[bytes, bytes]:
    keyy0 = header.signature[:16]

    if header.other_flags & FIXED_KEY_FLAG:
        if fixed_key is None:
            raise CxiexeError("fixed-key NCCH requires --fixed-key")
        return fixed_key, fixed_key

    keyx0 = keys.keyx.get(0x2C)
    if keyx0 is None:
        raise CxiexeError("missing KeyX for slot 0x2C")
    key0 = derive_ncch_key(keyx0, keyy0, keys.generator)

    keyx_slot = KEYX_SLOT_MAP.get(header.content_keyx)
    if keyx_slot is None:
        raise CxiexeError(f"unsupported NCCH keyx selector 0x{header.content_keyx:02X}")
    keyx1 = keys.keyx.get(keyx_slot)
    if keyx1 is None:
        raise CxiexeError(f"missing KeyX for slot 0x{keyx_slot:02X}")

    if header.other_flags & SEEDED_KEYY_FLAG:
        if seed is None:
            raise CxiexeError("seeded NCCH requires --seed or --seeddb")
        check = hashlib.sha256(seed + header.program_id.to_bytes(8, "little")).digest()
        if check[:4] != header.seed_checksum:
            raise CxiexeError("seed checksum mismatch")
        keyy1 = hashlib.sha256(keyy0 + seed).digest()[:16]
    else:
        keyy1 = keyy0

    key1 = derive_ncch_key(keyx1, keyy1, keys.generator)
    return key0, key1


def _extract_exheader(
    f,
    header: NcchHeader,
    exhdr_size: int,
    encrypted: bool,
    key0: bytes,
) -> bytes:
    if exhdr_size == 0:
        raise CxiexeError("exheader not present")
    raw = _read_at(f, 0x200, exhdr_size)
    if not encrypted:
        return raw
    ctr = aes_counter_for_ncch(header.format_version, header.partition_id, 1, 0x200)
    return aes_ctr_crypt(raw, key0, ctr)


def _extract_exefs_header(
    f,
    header: NcchHeader,
    block_size: int,
    encrypted: bool,
    key0: bytes,
) -> tuple[bytes, int]:
    if header.exefs_size == 0:
        raise CxiexeError("ExeFS not present")
    exefs_offset = header.exefs_offset * block_size
    raw = _read_at(f, exefs_offset, 0x200)
    if not encrypted:
        return raw, exefs_offset
    ctr = aes_counter_for_ncch(
        header.format_version, header.partition_id, 2, exefs_offset
    )
    return aes_ctr_crypt(raw, key0, ctr), exefs_offset


def _extract_code(
    f,
    header: NcchHeader,
    block_size: int,
    encrypted: bool,
    key1: bytes,
    exefs_offset: int,
    code_entry,
) -> bytes:
    file_offset = exefs_offset + 0x200 + code_entry.offset
    raw = _read_at(f, file_offset, code_entry.size)
    if not encrypted:
        return raw
    ctr = aes_counter_for_ncch(
        header.format_version, header.partition_id, 2, exefs_offset
    )
    ctr = increment_aes_counter(ctr, (0x200 + code_entry.offset) >> 4)
    return aes_ctr_crypt(raw, key1, ctr)


def _write_cxiexe(out_path: Path, meta: dict, code_blob: bytes) -> None:
    meta_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    header = CXIEXE_HEADER_STRUCT.pack(
        CXIEXE_MAGIC,
        CXIEXE_VERSION,
        len(meta_bytes),
        len(code_blob),
        0,
    )
    out_path.write_bytes(header + meta_bytes + code_blob)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract CXI .code into a compact cxiexe file"
    )
    parser.add_argument(
        "-i",
        "--in",
        dest="input_path",
        required=True,
        help="Input CXI/NCCH path",
    )
    parser.add_argument(
        "-o",
        "--out",
        dest="output_path",
        help="Output .cxiexe path (defaults next to input)",
    )
    parser.add_argument(
        "-k",
        "--keys",
        dest="keys_path",
        help="AES keys file (aes_keys.txt) for encrypted CXI",
    )
    parser.add_argument(
        "-s",
        "--seed",
        dest="seed_hex",
        help="Seed hex string (16 bytes, 32 hex chars)",
    )
    parser.add_argument(
        "--seeddb",
        dest="seed_db",
        help="SeedDB file path (for seeded keyY titles)",
    )
    parser.add_argument(
        "--fixed-key",
        dest="fixed_key_hex",
        help="Fixed key hex (16 bytes, 32 hex chars)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    args = parser.parse_args()

    input_path = Path(args.input_path).expanduser()
    output_path = Path(args.output_path).expanduser() if args.output_path else None

    if not input_path.exists():
        raise CxiexeError(f"input not found: {input_path}")

    if output_path is None:
        output_path = _default_output_path(input_path)
    elif output_path.exists() and output_path.is_dir():
        output_path = output_path / _default_output_path(input_path).name

    with input_path.open("rb") as f:
        header_bytes = _read_at(f, 0, 0x200)
        header = parse_ncch_header(header_bytes)
        block_size = _block_size(header)

        exhdr_size = _resolve_exheader_size(header)
        encrypted = not bool(header.other_flags & NO_CRYPTO_FLAG)
        if encrypted and exhdr_size:
            encrypted = not _maybe_detect_decrypted(f, header, exhdr_size)

        seed = None
        if args.seed_hex:
            seed = bytes.fromhex(args.seed_hex)
            if len(seed) != 16:
                raise CxiexeError("seed must be 16 bytes (32 hex chars)")
        elif args.seed_db:
            seed = _load_seed_from_db(
                Path(args.seed_db).expanduser(), header.program_id
            )

        fixed_key = None
        if args.fixed_key_hex:
            fixed_key = bytes.fromhex(args.fixed_key_hex)
            if len(fixed_key) != 16:
                raise CxiexeError("fixed key must be 16 bytes")

        if args.verbose:
            print(
                f"[CXI] format_version=0x{header.format_version:X} block_size=0x{block_size:X}"
            )
            print(f"[CXI] exhdr_size=0x{exhdr_size:X} encrypted={encrypted}")

        key0 = key1 = b""
        if encrypted:
            keys_path = (
                Path(args.keys_path).expanduser()
                if args.keys_path
                else _auto_keys_path(input_path)
            )
            if keys_path is None:
                raise CxiexeError(
                    "encrypted CXI requires keys: pass -k/--keys or place aes_keys.txt in the input directory or current working directory"
                )
            if args.verbose and args.keys_path is None:
                print(f"[CXI] using keys: {keys_path}")
            keys = _parse_keys_file(keys_path)
            key0, key1 = _compute_ncch_keys(header, keys, seed, fixed_key)

        exhdr = _extract_exheader(f, header, exhdr_size, encrypted, key0)
        sci = parse_exheader_sci(exhdr)

        exefs_hdr, exefs_offset = _extract_exefs_header(
            f, header, block_size, encrypted, key0
        )
        exefs_entries = parse_exefs_header(exefs_hdr)
        code_entry = iter_exefs_entries(exefs_entries, ".code", "code")
        if code_entry is None:
            raise CxiexeError(".code not found in ExeFS")

        code_blob = _extract_code(
            f, header, block_size, encrypted, key1, exefs_offset, code_entry
        )
        if sci.code_is_compressed:
            if args.verbose:
                print(f"[CXI] .code compressed: 0x{len(code_blob):X}")
            code_blob = lzss_decompress(code_blob)

        layout = choose_code_layout(sci, len(code_blob))

        meta = {
            "format": "cxiexe",
            "version": CXIEXE_VERSION,
            "source": str(input_path),
            "program_id": header.program_id,
            "product_code": header.product_code,
            "title": sci.title,
            "text_addr": sci.text.address,
            "text_size": sci.text.size,
            "rodata_addr": sci.rodata.address,
            "rodata_size": sci.rodata.size,
            "data_addr": sci.data.address,
            "data_size": sci.data.size,
            "bss_addr": sci.data.address + sci.data.size,
            "bss_size": sci.bss_size,
            "stack_size": sci.stack_size,
            "entry": sci.text.address,
            "text_offset": layout.text_offset,
            "rodata_offset": layout.rodata_offset,
            "data_offset": layout.data_offset,
            "layout": layout.layout,
            "code_size": len(code_blob),
        }

        _write_cxiexe(output_path, meta, code_blob)

        if args.verbose:
            print(
                "[CXI] layout text@0x{0:X} ro@0x{1:X} data@0x{2:X} ({3})".format(
                    layout.text_offset,
                    layout.rodata_offset,
                    layout.data_offset,
                    layout.layout,
                )
            )
            print(f"[CXI] wrote {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
