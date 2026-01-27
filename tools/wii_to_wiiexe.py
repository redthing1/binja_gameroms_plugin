#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
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
from gameroms.formats.wii.u8 import U8ParseError, is_u8, parse_u8
from gameroms.formats.wii.symbols import (
    find_map_for_module,
    load_map_file,
    serialize_symbols,
)
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


@dataclass(frozen=True)
class OverlayBlob:
    name: str
    data: bytes
    source: str


def _read_overlay(path: Path) -> bytes:
    data = path.read_bytes()
    if is_yaz0(data):
        data = decompress_yaz0(data)
    return data


def _scan_overlays_with_u8(root: Path, scan_u8: bool, verbose: bool) -> tuple[list[OverlayBlob], dict]:
    overlays: list[OverlayBlob] = []
    stats = {"loose_rel": 0, "loose_rso": 0, "u8_rel": 0, "u8_rso": 0, "u8_archives": 0}
    seen: set[str] = set()

    for path in _scan_overlays(root):
        try:
            data = _read_overlay(path)
        except Yaz0DecompressionError:
            continue
        key = f"loose:{path.resolve()}"
        if key in seen:
            continue
        seen.add(key)
        overlays.append(OverlayBlob(name=path.name, data=data, source=str(path)))
        if path.suffix.lower() == ".rel":
            stats["loose_rel"] += 1
        elif path.suffix.lower() == ".rso":
            stats["loose_rso"] += 1

    if not scan_u8:
        return overlays, stats

    search_root = root / "files" if (root / "files").exists() else root
    for archive_path in sorted(search_root.rglob("*")):
        if not archive_path.is_file():
            continue
        suffix = archive_path.suffix.lower()
        if suffix not in (".szs", ".arc", ".u8"):
            continue
        try:
            raw = archive_path.read_bytes()
        except OSError:
            continue
        if is_yaz0(raw):
            try:
                raw = decompress_yaz0(raw)
            except Yaz0DecompressionError:
                continue
        if not is_u8(raw):
            continue
        try:
            entries = parse_u8(raw)
        except U8ParseError:
            continue
        stats["u8_archives"] += 1
        for entry in entries:
            lower = entry.path.lower()
            if not (lower.endswith(".rel") or lower.endswith(".rso")):
                continue
            blob = raw[entry.offset : entry.offset + entry.size]
            if is_yaz0(blob):
                try:
                    blob = decompress_yaz0(blob)
                except Yaz0DecompressionError:
                    continue
            key = f"u8:{archive_path}:{entry.path}"
            if key in seen:
                continue
            seen.add(key)
            overlays.append(
                OverlayBlob(
                    name=Path(entry.path).name,
                    data=blob,
                    source=f"{archive_path}:{entry.path}",
                )
            )
            if lower.endswith(".rel"):
                stats["u8_rel"] += 1
            else:
                stats["u8_rso"] += 1

    if verbose and stats["u8_archives"]:
        print(f"[WII] u8 archives scanned={stats['u8_archives']}")
    return overlays, stats


def _align(addr: int, alignment: int) -> int:
    if alignment <= 1:
        return addr
    return (addr + alignment - 1) & ~(alignment - 1)


def _layout_rel(base_addr: int, rel) -> tuple[int, int, int]:
    max_end = base_addr
    bss_addr = 0
    for sec in rel.sections:
        if sec.size == 0 or sec.offset == 0:
            continue
        end = base_addr + sec.offset + sec.size
        if end > max_end:
            max_end = end
    if rel.header.bss_size:
        align = rel.header.bss_section_alignment or 0x20
        max_end = _align(max_end, align)
        bss_addr = max_end
        max_end += rel.header.bss_size
    return base_addr, _align(max_end, 0x20), bss_addr


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
    scan_u8: bool,
    map_dir: Path | None,
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

    blob_data = bytearray()
    modules: list[dict] = []

    dol_offset = len(blob_data)
    blob_data.extend(dol_bytes)
    modules.append(
        {
            "type": "dol",
            "name": "main.dol",
            "blob_offset": dol_offset,
            "blob_size": len(dol_bytes),
        }
    )

    map_root = map_dir.expanduser() if map_dir else None
    if map_root:
        dol_map = find_map_for_module(map_root, "main.dol")
        if dol_map:
            text_addrs = [sec.addr for sec in dol_info.sections if sec.is_text and sec.size]
            object_addr = min(text_addrs) if text_addrs else dol_info.entry_point
            bss_addr = dol_info.bss_addr or 0
            symbols = load_map_file(dol_map, object_addr, 32, bss_addr)
            if symbols:
                modules[-1]["symbols"] = serialize_symbols(symbols)
                modules[-1]["map_name"] = dol_map.name

    # Optional apploader
    if include_apploader:
        app_path = partition_root / "sys" / "apploader.img"
        if app_path.exists():
            app_bytes = app_path.read_bytes()
            app_off = len(blob_data)
            blob_data.extend(app_bytes)
            modules.append(
                {
                    "type": "apploader",
                    "name": "apploader.img",
                    "blob_offset": app_off,
                    "blob_size": len(app_bytes),
                }
            )

    overlay_blobs, overlay_stats = _scan_overlays_with_u8(
        partition_root, scan_u8=scan_u8, verbose=verbose
    )
    rel_entries: list[tuple[OverlayBlob, object]] = []
    rso_entries: list[tuple[OverlayBlob, object]] = []
    rel_seen: set[int] = set()
    rso_seen: set[str] = set()

    for blob in overlay_blobs:
        name_lower = blob.name.lower()
        if name_lower.endswith(".rel"):
            try:
                rel = parse_rel(blob.data, blob.name)
            except RelParseError:
                continue
            if rel.header.module_id in rel_seen:
                if verbose:
                    print(
                        f"[WII] skip duplicate REL module_id={rel.header.module_id} ({blob.source})"
                    )
                continue
            rel_seen.add(rel.header.module_id)
            rel_entries.append((blob, rel))
        elif name_lower.endswith(".rso"):
            try:
                rso = parse_rso(blob.data, blob.name)
            except RsoParseError:
                continue
            key = blob.name.lower()
            if key in rso_seen:
                if verbose:
                    print(f"[WII] skip duplicate RSO {blob.name} ({blob.source})")
                continue
            rso_seen.add(key)
            rso_entries.append((blob, rso))

    rel_entries.sort(key=lambda item: item[1].header.module_id)
    rso_entries.sort(key=lambda item: item[0].name.lower())

    for blob, rel in rel_entries:
        base_addr, next_addr, bss_addr = _layout_rel(current_addr, rel)
        rel_off = len(blob_data)
        blob_data.extend(rel.data)
        modules.append(
            {
                "type": "rel",
                "name": blob.name,
                "module_id": rel.header.module_id,
                "base_addr": base_addr,
                "blob_offset": rel_off,
                "blob_size": len(rel.data),
            }
        )
        if map_root:
            rel_map = find_map_for_module(map_root, blob.name)
            if rel_map:
                object_addr = base_addr + rel.header.full_size()
                symbols = load_map_file(
                    rel_map, object_addr, rel.header.section_alignment, bss_addr
                )
                if symbols:
                    modules[-1]["symbols"] = serialize_symbols(symbols)
                    modules[-1]["map_name"] = rel_map.name
        current_addr = next_addr

    for blob, rso in rso_entries:
        base_addr, next_addr, external_base = _layout_rso(current_addr, rso)
        rso_off = len(blob_data)
        blob_data.extend(rso.data)
        modules.append(
            {
                "type": "rso",
                "name": blob.name,
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
        "overlay_scan": overlay_stats,
        "scan_u8": scan_u8,
    }

    out_file = out_path or _default_output_path(input_path)
    meta_bytes = json.dumps(meta, indent=2, sort_keys=True).encode("utf-8")
    header = WIIEXE_HEADER_STRUCT.pack(
        WIIEXE_MAGIC,
        WIIEXE_VERSION,
        len(meta_bytes),
        len(blob_data),
        0,
    )
    out_file.write_bytes(header + meta_bytes + blob_data)

    if verbose:
        print(f"[WII] partition={partition_root}")
        print(f"[WII] DOL entry=0x{dol_info.entry_point:X}")
        print(f"[WII] overlays: rel={len(rel_entries)} rso={len(rso_entries)}")
        print(
            "[WII] overlay sources: "
            f"loose_rel={overlay_stats['loose_rel']} "
            f"loose_rso={overlay_stats['loose_rso']} "
            f"u8_rel={overlay_stats['u8_rel']} "
            f"u8_rso={overlay_stats['u8_rso']}"
        )
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
        "--map-dir",
        help="Directory containing CodeWarrior .map files for DOL/REL modules",
    )
    parser.add_argument(
        "--scan-u8",
        dest="scan_u8",
        action="store_true",
        default=True,
        help="Scan U8 archives (.szs/.arc) for REL/RSO overlays (default on)",
    )
    parser.add_argument(
        "--no-scan-u8",
        dest="scan_u8",
        action="store_false",
        help="Disable U8 archive scanning",
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
            scan_u8=args.scan_u8,
            map_dir=Path(args.map_dir).expanduser() if args.map_dir else None,
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
