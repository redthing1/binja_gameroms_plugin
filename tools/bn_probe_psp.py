from __future__ import annotations

import argparse
import binascii
from pathlib import Path
import sys

from binaryninja import BinaryViewType


def _hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe PSP ELF annotations")
    parser.add_argument("--binary", required=True, help="Path to PSP ELF")
    parser.add_argument(
        "--length", type=int, default=16, help="Bytes to read at entry point"
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from gameroms.formats.psp import register_psp_hooks

    register_psp_hooks()

    view_type = BinaryViewType["ELF"]
    if view_type is None:
        print("ELF view type unavailable")
        return 2

    bv = view_type.open(args.binary)
    if bv is None:
        print("failed to open ELF view")
        return 3

    try:
        entry = bv.entry_point
        entry_bytes = bv.read(entry, args.length)
        reset_sym = bv.get_symbol_at(0xBFC00000)
        general_sym = bv.get_symbol_at(0xBFC00180)
        mmio_seg = bv.get_segment_at(0x1C000000)
        print(f"entry_point: 0x{entry:08x}")
        print(f"entry_bytes: {_hex(entry_bytes)}")
        print(f"reset_symbol: {reset_sym.name if reset_sym else None}")
        print(f"general_exception_symbol: {general_sym.name if general_sym else None}")
        print(f"mmio_segment_present: {mmio_seg is not None}")
        return 0
    finally:
        bv.file.close()


if __name__ == "__main__":
    raise SystemExit(main())
