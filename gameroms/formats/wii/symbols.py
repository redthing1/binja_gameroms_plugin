from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MapSymbol:
    addr: int
    size: int
    name: str
    container: str
    is_sub: bool


@dataclass(frozen=True)
class MemoryMapSection:
    name: str
    start: int
    size: int
    file_offset: int


class MapParseError(RuntimeError):
    pass


def _parse_memory_map(lines: list[str]) -> list[MemoryMapSection] | None:
    start_idx = -1
    for idx in range(len(lines) - 1, -1, -1):
        if "Memory map:" in lines[idx]:
            start_idx = idx + 2
            break
    if start_idx < 0:
        return None

    sections: list[MemoryMapSection] = []
    for line in lines[start_idx:]:
        if not line.strip():
            break
        parts = line.strip().split()
        if len(parts) < 4:
            continue
        try:
            name = parts[0]
            start = int(parts[1], 16) & 0xFFFFFFFF
            size = int(parts[2], 16) & 0xFFFFFFFF
            file_offset = int(parts[3], 16) & 0xFFFFFFFF
        except ValueError:
            continue
        if size:
            sections.append(
                MemoryMapSection(
                    name=name,
                    start=start,
                    size=size,
                    file_offset=file_offset,
                )
            )

    if sections and sections[0].file_offset != 0:
        adjust = sections[0].file_offset
        adjusted = []
        for sec in sections:
            if sec.file_offset:
                adjusted.append(
                    MemoryMapSection(
                        name=sec.name,
                        start=sec.start,
                        size=sec.size,
                        file_offset=sec.file_offset - adjust,
                    )
                )
            else:
                adjusted.append(sec)
        sections = adjusted
    return sections


def _parse_symbol_line(line: str) -> tuple[list[str], bool]:
    entry_start = line.find("(entry of ")
    is_sub = False
    if entry_start > -1:
        entry_end = line.find(")", entry_start)
        if entry_end > -1:
            line = line[:entry_start] + line[entry_end + 1 :]
            is_sub = True
    parts = line.strip().split()
    return parts, is_sub


def _parse_symbols_with_map(
    lines: list[str],
    mem_map: list[MemoryMapSection],
    object_address: int,
    alignment: int,
    bss_address: int,
) -> list[MapSymbol]:
    symbols: list[MapSymbol] = []
    current_section_size = 0
    effective_address = object_address
    pre_bss_address = -1
    current_section_name = ""

    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        if " section layout" in line:
            section_name = line.split(" section layout", 1)[0].strip()
            current_section_name = section_name
            section_info = next(
                (info for info in mem_map if info.name == section_name), None
            )
            if section_info is not None:
                effective_address += current_section_size
                current_section_size = section_info.size
                if current_section_size & 3:
                    current_section_size = (current_section_size + 4) & ~3

                if section_info.name == ".bss" and bss_address != -1:
                    pre_bss_address = effective_address
                    effective_address = bss_address
                elif pre_bss_address > -1:
                    effective_address = pre_bss_address
                    pre_bss_address = 0
            if idx + 1 < len(lines) and lines[idx + 1].strip().startswith("Starting"):
                continue
        else:
            parts, is_sub = _parse_symbol_line(line)
            if len(parts) < 5:
                continue
            try:
                start_addr = int(parts[0], 16) & 0xFFFFFFFF
                size = int(parts[1], 16) & 0xFFFFFFFF
                virt_addr = int(parts[2], 16) & 0xFFFFFFFF
            except ValueError:
                continue
            try:
                obj_align = int(parts[3])
            except ValueError:
                obj_align = 0

            if virt_addr < 0x80000000:
                virt_addr = (virt_addr + effective_address) & 0xFFFFFFFF

            if is_sub:
                name = parts[3] if len(parts) > 3 else ""
                container = parts[4] if len(parts) > 4 else ""
            else:
                name = parts[4] if len(parts) > 4 else ""
                container = parts[5] if len(parts) > 5 else ""

            if not is_sub and name == current_section_name:
                is_sub = True

            if not name:
                continue
            symbols.append(
                MapSymbol(
                    addr=virt_addr,
                    size=size,
                    name=name,
                    container=container,
                    is_sub=is_sub,
                )
            )
    return symbols


def _parse_symbols_no_map(
    lines: list[str],
    object_address: int,
    alignment: int,
    bss_address: int,
) -> list[MapSymbol]:
    symbols: list[MapSymbol] = []
    effective_address = object_address
    pre_bss_address = -1
    current_section_name: str | None = None
    current_symbol: MapSymbol | None = None

    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        if " section layout" in line:
            section_name = line.split(" section layout", 1)[0].strip()
            current_section_name = section_name
            if current_symbol is not None:
                end_addr = current_symbol.addr + current_symbol.size
                if alignment > 1 and alignment % 2 == 0:
                    end_addr = (end_addr + alignment - 1) & ~(alignment - 1)
                effective_address = end_addr

            if section_name == ".bss" and bss_address != -1:
                pre_bss_address = effective_address
                effective_address = bss_address
            elif pre_bss_address > -1:
                effective_address = pre_bss_address
                pre_bss_address = 0
            if idx + 1 < len(lines) and lines[idx + 1].strip().startswith("Starting"):
                continue
        else:
            parts, is_sub = _parse_symbol_line(line)
            if len(parts) < 5:
                continue
            try:
                start_addr = int(parts[0], 16) & 0xFFFFFFFF
                size = int(parts[1], 16) & 0xFFFFFFFF
                virt_addr = int(parts[2], 16) & 0xFFFFFFFF
            except ValueError:
                continue
            try:
                obj_align = int(parts[3])
            except ValueError:
                obj_align = 0

            if virt_addr < 0x80000000:
                virt_addr = (virt_addr + effective_address) & 0xFFFFFFFF

            if is_sub and obj_align == 1:
                name = parts[3] if len(parts) > 3 else ""
                container = parts[4] if len(parts) > 4 else ""
            else:
                name = parts[4] if len(parts) > 4 else ""
                container = parts[5] if len(parts) > 5 else ""

            if not name:
                continue

            if current_section_name and name == current_section_name:
                continue

            current_symbol = MapSymbol(
                addr=virt_addr,
                size=size,
                name=name,
                container=container,
                is_sub=is_sub,
            )
            symbols.append(current_symbol)
    return symbols


def parse_map_text(
    text: str,
    object_address: int,
    alignment: int,
    bss_address: int,
) -> list[MapSymbol]:
    lines = text.splitlines()
    mem_map = _parse_memory_map(lines)
    if mem_map:
        return _parse_symbols_with_map(
            lines, mem_map, object_address, alignment, bss_address
        )
    return _parse_symbols_no_map(lines, object_address, alignment, bss_address)


def find_map_for_module(map_dir: Path | None, module_name: str) -> Path | None:
    if map_dir is None:
        return None
    map_dir = map_dir.expanduser()
    if map_dir.is_file():
        return map_dir
    if not map_dir.exists():
        return None

    stem = Path(module_name).stem.lower()
    candidates = {}
    for entry in map_dir.iterdir():
        if entry.is_file() and entry.suffix.lower() == ".map":
            candidates[entry.stem.lower()] = entry

    return candidates.get(stem)


def load_map_file(
    path: Path,
    object_address: int,
    alignment: int,
    bss_address: int,
) -> list[MapSymbol]:
    text = path.read_text(errors="replace")
    return parse_map_text(text, object_address, alignment, bss_address)


def serialize_symbols(symbols: list[MapSymbol]) -> list[dict]:
    return [
        {
            "addr": sym.addr,
            "size": sym.size,
            "name": sym.name,
            "container": sym.container,
            "is_sub": sym.is_sub,
        }
        for sym in symbols
    ]
