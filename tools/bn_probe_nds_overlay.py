from __future__ import annotations

import argparse
import binascii
from pathlib import Path
import sys

from binaryninja import BinaryViewType


def _hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe NDS overlay bytes vs decompressed data"
    )
    parser.add_argument("--binary", required=True, help="Path to NDS ROM")
    parser.add_argument(
        "--view", required=True, help="BinaryViewType name (NDS ARM9 or NDS ARM7)"
    )
    parser.add_argument(
        "--overlay-id", type=int, required=True, help="Overlay ID to probe"
    )
    parser.add_argument("--length", type=int, default=64, help="Bytes to compare")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    import gameroms.formats.nds.view  # noqa: F401
    from gameroms.formats.nds.decompress import mii_uncompress_backward
    from gameroms.formats.nds.parse import read_nds

    view_type = BinaryViewType[args.view]
    if view_type is None:
        print(f"unknown view type: {args.view}")
        return 2

    bv = view_type.open(args.binary)
    if bv is None:
        print("failed to open view")
        return 3

    try:
        raw = bv.parent_view
        if raw is None:
            print("no parent view")
            return 4
        nds = read_nds(raw)
        if nds is None:
            print("failed to parse nds header")
            return 5
        table = (
            nds.arm9_overlay_table if "ARM9" in args.view else nds.arm7_overlay_table
        )
        if table is None:
            print("no overlay table")
            return 6
        entry = None
        for ent in table.entries:
            if ent.overlay_id == args.overlay_id:
                entry = ent
                break
        if entry is None:
            if args.overlay_id < len(table.entries):
                entry = table.entries[args.overlay_id]
            else:
                print("overlay id not found")
                return 7
        if entry.file_id >= len(nds.fat_entries):
            print("overlay file_id out of FAT bounds")
            return 8
        fat = nds.fat_entries[entry.file_id]
        rom_size = max(0, fat.end_address - fat.start_address)
        raw_data = raw.read(fat.start_address, rom_size) if rom_size > 0 else b""
        data = raw_data
        if entry.is_compressed and raw_data:
            data = mii_uncompress_backward(raw_data)
        effective_size = len(data) if data else entry.ram_size
        read_len = min(args.length, effective_size)
        mem_bytes = bv.read(entry.ram_address, read_len)
        file_bytes = data[:read_len]
        print(f"view: {args.view}")
        print(f"overlay_id: {entry.overlay_id}")
        print(f"ram_address: 0x{entry.ram_address:08x}")
        print(f"compressed: {entry.is_compressed}")
        print(f"read_len: {read_len}")
        print(f"mem_bytes: {_hex(mem_bytes)}")
        print(f"dec_bytes: {_hex(file_bytes)}")
        print(f"match: {mem_bytes == file_bytes}")
        return 0
    finally:
        bv.file.close()


if __name__ == "__main__":
    raise SystemExit(main())
