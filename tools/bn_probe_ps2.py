from __future__ import annotations

import argparse
import binascii
from pathlib import Path
import sys

from binaryninja import BinaryViewType


def _hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe PS2 ELF mapping")
    parser.add_argument("--binary", required=True, help="Path to PS2 ELF/IRX")
    parser.add_argument("--view", default="PS2 EE ELF", help="BinaryView name")
    parser.add_argument("--length", type=int, default=16, help="Bytes to read at entry")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from gameroms.formats.ps2 import view as _ps2_view  # noqa: F401

    try:
        view_type = BinaryViewType[args.view]
    except Exception:
        view_type = None
    if view_type is None:
        print(f"view type not found: {args.view}")
        return 2

    bv = view_type.open(args.binary)
    if bv is None:
        print("failed to open binary view")
        return 3

    try:
        entry = bv.entry_point
        entry_bytes = bv.read(entry, args.length)
        seg = bv.get_segment_at(entry)
        raw = bv.parent_view or bv
        file_bytes = b""
        file_off = None
        if seg is not None and seg.data_length > 0:
            file_off = seg.data_offset + (entry - seg.start)
            if file_off >= 0 and file_off + args.length <= raw.length:
                file_bytes = raw.read(file_off, args.length)
        print(f"entry_point: 0x{entry:08x}")
        print(f"entry_bytes: {_hex(entry_bytes)}")
        print(f"file_offset: {file_off}")
        print(f"file_bytes:  {_hex(file_bytes)}")
        print(f"match: {entry_bytes == file_bytes}")
        return 0
    finally:
        bv.file.close()


if __name__ == "__main__":
    raise SystemExit(main())
