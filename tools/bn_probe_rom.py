from __future__ import annotations

import argparse
import binascii
from pathlib import Path
import sys

import binaryninja as bn
from binaryninja import BinaryViewType


def _hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe mapped bytes in a BinaryView")
    parser.add_argument("--binary", required=True, help="Path to ROM/ELF")
    parser.add_argument("--view", required=True, help="BinaryViewType name (e.g. 'GBA', 'NDS ARM9')")
    parser.add_argument("--addr", required=True, help="Virtual address to read (hex)")
    parser.add_argument("--length", type=int, default=16, help="Bytes to read")
    parser.add_argument("--file-offset", default="0x0", help="File offset to compare (hex)")
    parser.add_argument("--analysis", action="store_true", help="Run update_analysis_and_wait before reading")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    # Ensure view types are registered.
    import gameroms.formats.gba.view  # noqa: F401
    import gameroms.formats.nds.view  # noqa: F401

    view_type = BinaryViewType[args.view]
    if view_type is None:
        print(f"unknown view type: {args.view}")
        return 2

    addr = int(args.addr, 16)
    file_offset = int(args.file_offset, 16)

    bv = view_type.open(args.binary)
    if bv is None:
        print("failed to open view")
        return 3

    try:
        if args.analysis:
            bv.update_analysis_and_wait()
        mem_bytes = bv.read(addr, args.length)
        raw = bv.parent_view.read(file_offset, args.length) if bv.parent_view else b""
        print(f"view: {args.view}")
        print(f"addr: 0x{addr:08x}")
        print(f"file_offset: 0x{file_offset:08x}")
        print(f"mem_bytes: {_hex(mem_bytes)}")
        print(f"file_bytes: {_hex(raw)}")
        print(f"match: {mem_bytes == raw}")
        return 0
    finally:
        bv.file.close()


if __name__ == "__main__":
    raise SystemExit(main())
