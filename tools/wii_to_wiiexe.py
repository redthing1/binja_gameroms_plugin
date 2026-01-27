#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gameroms.formats.wii.constants import (
    MEM1_BASE,
    MEM1_END,
    WIIEXE_HEADER_STRUCT,
    WIIEXE_MAGIC,
    WIIEXE_VERSION,
)
from gameroms.formats.wii.dol import DolParseError, parse_dol
from gameroms.formats.wii.rel import RelParseError, parse_rel
from gameroms.formats.wii.rso import RsoParseError, parse_rso
from gameroms.formats.wii.yaz0 import Yaz0DecompressionError, is_yaz0, decompress_yaz0


class WiiExeBuildError(RuntimeError):
    pass


def _default_output_path(input_path: Path) -> Path:
    if input_path.is_dir():
        return Path(str(input_path) + ".wiiexe")
    return input_path.with_suffix(".wiiexe")


def _resolve_partition_root(path: Path, partition: str | None) -> Path:
    if path.is_file():
        if path.name.lower() == "main.dol" and path.parent.name == "sys":
            return path.parent.parent
        return path.parent

    sys_main = path / "sys" / "main.dol"
    if sys_main.exists():
        return path

    candidates = []
    for name in ("DATA", "UPDATE"):
        root = path / name
        if (root / "sys" / "main.dol").exists():
            candidates.append(root)

    if partition:
        part_root = path / partition
        if (part_root / "sys" / "main.dol").exists():
            return part_root
        raise WiiExeBuildError(f"partition '{partition}' not found in {path}")

    if candidates:
        for root in candidates:
            if root.name == "DATA":
                return root
        return candidates[0]

    raise WiiExeBuildError(f"could not locate sys/main.dol under {path}")


def _scan_overlays(root: Path) -> list[Path]:
    search_root = root / "files" if (root / "files").exists() else root
    results: list[Path] = []
    for ext in ("*.rel", "*.rso"):
        results.extend(sorted(search_root.rglob(ext)))
    return results


def _read_overlay(path: Path) -> bytes:
    data = path.read_bytes()
    if is_yaz0(data):
        data = decompress_yaz0(data)
    return data


def _align(addr: int, alignment: int) -> int:
    if alignment <= 1:
        return addr
    return (addr + alignment - 1) & ~(alignment - 1)


def _layout_rel(base_addr: int, rel) -> tuple[int, int]:
    max_end = base_addr
    for sec in rel.sections:
        if sec.size == 0 or sec.offset == 0:
            continue
        end = base_addr + sec.offset + sec.size
        if end > max_end:
            max_end = end
    if rel.header.bss_size:
        align = rel.header.bss_section_alignment or 0x20
        max_end = _align(max_end, align)
        max_end += rel.header.bss_size
    return base_addr, _align(max_end, 0x20)


def _layout_rso(base_addr: int, rso) -> tuple[int, int, int]:
    current = base_addr
    for sec in rso.sections:
        if sec.size == 0 or sec.offset == 0:
            continue
        current += sec.size
    if rso.header.bss_size:
        current = _align(current, 4)
        current += rso.header.bss_size
    external_base = 0
    if rso.imports:
        current = _align(current, 4)
        external_base = current
        current += len(rso.imports) * 4
    return base_addr, _align(current, 0x20), external_base


def build_wiiexe(
    input_path: Path,
    out_path: Path | None,
    partition: str | None,
    include_apploader: bool,
    verbose: bool,
) -> Path:
    partition_root = _resolve_partition_root(input_path, partition)
    dol_path = partition_root / "sys" / "main.dol"
    dol_bytes = dol_path.read_bytes()
    dol_info = parse_dol(dol_bytes)

    current_addr = _align(dol_info.max_end, 0x20)
    if current_addr < MEM1_BASE:
        current_addr = _align(MEM1_BASE, 0x20)
    if current_addr >= MEM1_END:
        raise WiiExeBuildError("DOL end address outside MEM1 range")

    blob = bytearray()
    modules: list[dict] = []

    dol_offset = len(blob)
    blob.extend(dol_bytes)
    modules.append(
        {
            "type": "dol",
            "name": "main.dol",
            "blob_offset": dol_offset,
            "blob_size": len(dol_bytes),
        }
    )

    # Optional apploader
    if include_apploader:
        app_path = partition_root / "sys" / "apploader.img"
        if app_path.exists():
            app_bytes = app_path.read_bytes()
            app_off = len(blob)
            blob.extend(app_bytes)
            modules.append(
                {
                    "type": "apploader",
                    "name": "apploader.img",
                    "blob_offset": app_off,
                    "blob_size": len(app_bytes),
                }
            )

    overlay_paths = _scan_overlays(partition_root)
    rel_entries: list[tuple[Path, object]] = []
    rso_entries: list[tuple[Path, object]] = []

    for path in overlay_paths:
        try:
            data = _read_overlay(path)
        except Yaz0DecompressionError:
            continue
        if path.suffix.lower() == ".rel":
            try:
                rel_entries.append((path, parse_rel(data, path.name)))
            except RelParseError:
                continue
        elif path.suffix.lower() == ".rso":
            try:
                rso_entries.append((path, parse_rso(data, path.name)))
            except RsoParseError:
                continue

    rel_entries.sort(key=lambda item: item[1].header.module_id)
    rso_entries.sort(key=lambda item: item[0].name.lower())

    for path, rel in rel_entries:
        base_addr, next_addr = _layout_rel(current_addr, rel)
        rel_off = len(blob)
        blob.extend(rel.data)
        modules.append(
            {
                "type": "rel",
                "name": path.name,
                "module_id": rel.header.module_id,
                "base_addr": base_addr,
                "blob_offset": rel_off,
                "blob_size": len(rel.data),
            }
        )
        current_addr = next_addr

    for path, rso in rso_entries:
        base_addr, next_addr, external_base = _layout_rso(current_addr, rso)
        rso_off = len(blob)
        blob.extend(rso.data)
        modules.append(
            {
                "type": "rso",
                "name": path.name,
                "base_addr": base_addr,
                "external_base": external_base,
                "blob_offset": rso_off,
                "blob_size": len(rso.data),
            }
        )
        current_addr = next_addr

    meta = {
        "format": "wiiexe",
        "version": WIIEXE_VERSION,
        "partition": partition_root.name,
        "modules": modules,
        "overlay_count": len(rel_entries) + len(rso_entries),
    }

    out_file = out_path or _default_output_path(input_path)
    meta_bytes = json.dumps(meta, indent=2, sort_keys=True).encode("utf-8")
    header = WIIEXE_HEADER_STRUCT.pack(
        WIIEXE_MAGIC,
        WIIEXE_VERSION,
        len(meta_bytes),
        len(blob),
        0,
    )
    out_file.write_bytes(header + meta_bytes + blob)

    if verbose:
        print(f"[WII] partition={partition_root}")
        print(f"[WII] DOL entry=0x{dol_info.entry_point:X}")
        print(f"[WII] overlays: rel={len(rel_entries)} rso={len(rso_entries)}")
        print(f"[WII] wrote {out_file}")

    return out_file


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pack a Wii/GameCube extracted disc into a wiiexe container"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to extracted disc root or sys/main.dol",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output wiiexe path (defaults next to input)",
    )
    parser.add_argument(
        "-p",
        "--partition",
        choices=["DATA", "UPDATE"],
        help="Partition to use when input is a multi-partition directory",
    )
    parser.add_argument(
        "--include-apploader",
        action="store_true",
        help="Include apploader.img in wiiexe",
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
        build_wiiexe(
            input_path=Path(args.input).expanduser(),
            out_path=Path(args.output).expanduser() if args.output else None,
            partition=args.partition,
            include_apploader=args.include_apploader,
            verbose=args.verbose,
        )
    except (
        WiiExeBuildError,
        DolParseError,
        RelParseError,
        RsoParseError,
        Yaz0DecompressionError,
    ) as exc:
        print(f"[WII] error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
