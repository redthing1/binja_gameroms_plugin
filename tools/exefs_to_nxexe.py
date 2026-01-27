from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gameroms.formats.nx.constants import (
    AARCH32_BASE_ADDR,
    AARCH64_BASE_ADDR,
    NXEXE_HEADER_STRUCT,
    NXEXE_MAGIC,
    NXEXE_VERSION,
)
from gameroms.formats.nx.lz4 import Lz4DecompressionError, decompress_block
from gameroms.formats.nx.mod0 import Mod0ParseError, find_mod0_offset, parse_mod0
from gameroms.formats.nx.parse import (
    Nso0ParseError,
    extract_nso0_sections,
    parse_nso0_header,
)


class NxExeBuildError(RuntimeError):
    pass


def _detect_aarch32(image: bytes, dyn_offset: int) -> bool:
    if dyn_offset + 0x10 >= len(image):
        return False
    first = int.from_bytes(image[dyn_offset : dyn_offset + 8], "little")
    second = int.from_bytes(image[dyn_offset + 0x10 : dyn_offset + 0x18], "little")
    return first > 0xFFFFFFFF or second > 0xFFFFFFFF


def _default_output_path(exefs_dir: Path) -> Path:
    return Path(str(exefs_dir) + ".nxexe")


def _resolve_output_path(
    exefs_dir: Path, module_name: str, out_path: Path | None
) -> Path:
    if out_path is None:
        return _default_output_path(exefs_dir)
    if out_path.is_dir():
        return out_path / f"{module_name}.nxexe"
    return out_path


def _write_nxexe(out_path: Path, meta: dict, image: bytes) -> None:
    meta_bytes = json.dumps(meta, indent=2, sort_keys=True).encode("utf-8")
    header = NXEXE_HEADER_STRUCT.pack(
        NXEXE_MAGIC,
        NXEXE_VERSION,
        len(meta_bytes),
        len(image),
        0,
    )
    out_path.write_bytes(header + meta_bytes + image)


def build_nxexe_from_exefs(
    exefs_dir: Path,
    module_name: str,
    out_path: Path | None,
    arch_override: str | None,
    verbose: bool,
) -> Path:
    if not exefs_dir.is_dir():
        raise NxExeBuildError(f"not a directory: {exefs_dir}")
    module_path = exefs_dir / module_name
    if not module_path.exists():
        candidates = ", ".join(
            sorted(p.name for p in exefs_dir.iterdir() if p.is_file())
        )
        raise NxExeBuildError(
            f"module '{module_name}' not found; candidates: {candidates}"
        )

    blob = module_path.read_bytes()
    header = parse_nso0_header(blob)

    image, sections = extract_nso0_sections(blob, header, decompress_block)

    mod0_offset = find_mod0_offset(image, sections["text_offset"])
    mod0 = parse_mod0(image, mod0_offset)

    if arch_override:
        if arch_override not in ("aarch32", "aarch64"):
            raise NxExeBuildError("--arch must be aarch32 or aarch64")
        arch = arch_override
    else:
        arch = "aarch32" if _detect_aarch32(image, mod0.dynamic_offset) else "aarch64"

    base_addr = AARCH32_BASE_ADDR if arch == "aarch32" else AARCH64_BASE_ADDR

    meta = {
        "format": "nxexe",
        "version": NXEXE_VERSION,
        "module_name": module_name,
        "arch": arch,
        "base_addr": base_addr,
        "build_id": header.build_id.hex(),
        "nso_flags": header.flags,
        "text_offset": sections["text_offset"],
        "text_size": sections["text_size"],
        "rodata_offset": sections["rodata_offset"],
        "rodata_size": sections["rodata_size"],
        "data_offset": sections["data_offset"],
        "data_size": sections["data_size"],
        "bss_offset": mod0.bss_start,
        "bss_size": mod0.bss_size,
        "mod0_offset": mod0_offset,
        "dynamic_offset": mod0.dynamic_offset,
        "eh_frame_hdr_start": mod0.eh_frame_hdr_start,
        "eh_frame_hdr_end": mod0.eh_frame_hdr_end,
        "libnx_got_start": mod0.libnx_got_start,
        "libnx_got_end": mod0.libnx_got_end,
        "blob_size": len(image),
    }

    if verbose:
        print(f"[NX] module={module_name} arch={arch} base=0x{base_addr:X}")
        print(
            "[NX] text@0x{0:X} size=0x{1:X} ro@0x{2:X} size=0x{3:X} data@0x{4:X} size=0x{5:X}".format(
                sections["text_offset"],
                sections["text_size"],
                sections["rodata_offset"],
                sections["rodata_size"],
                sections["data_offset"],
                sections["data_size"],
            )
        )
        print(f"[NX] mod0=0x{mod0_offset:X} dynamic=0x{mod0.dynamic_offset:X}")
        print(f"[NX] bss=0x{mod0.bss_start:X} size=0x{mod0.bss_size:X}")
        if mod0.has_libnx:
            print(
                "[NX] libnx GOT=0x{0:X}-0x{1:X}".format(
                    mod0.libnx_got_start, mod0.libnx_got_end
                )
            )

    out_file = _resolve_output_path(exefs_dir, module_name, out_path)
    _write_nxexe(out_file, meta, image)
    if verbose:
        print(f"[NX] wrote {out_file}")
    return out_file


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pack a Switch ExeFS NSO0 module into a nxexe container"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to extracted ExeFS directory",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output nxexe path (defaults next to input directory)",
    )
    parser.add_argument(
        "-m",
        "--module",
        default="main",
        help="Module name inside ExeFS (default: main)",
    )
    parser.add_argument(
        "--arch",
        choices=["aarch32", "aarch64"],
        help="Override architecture detection",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    return parser


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()

    try:
        build_nxexe_from_exefs(
            exefs_dir=Path(args.input).expanduser(),
            module_name=args.module,
            out_path=Path(args.output).expanduser() if args.output else None,
            arch_override=args.arch,
            verbose=args.verbose,
        )
    except (
        NxExeBuildError,
        Nso0ParseError,
        Mod0ParseError,
        Lz4DecompressionError,
    ) as exc:
        print(f"[NX] error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
