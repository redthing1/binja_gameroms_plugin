"""PS3EXE snapshots: compact mapped bytes, sparse fixups and module provenance."""

from dataclasses import asdict, dataclass
import hashlib
import json
import struct

from .elf import EXECUTABLE, PRX, Section, checked_range, validate_ranges
from .link import Binding, descriptor, reference_fixups
from .model import Module, Segment, Source, Symbol, TlsTemplate, validate_modules
from .prepare import Program, module_facts
from .reloc import WIDTHS, Patch


MAGIC = b"PS3EXE\0\0"
HEADER = struct.Struct("<8sIIQ")
VERSION = 1
MAX_METADATA_SIZE = 64 * 1024 * 1024


@dataclass(frozen=True)
class Mapping:
    module: str
    segment: int
    address: int
    size: int
    file_offset: int
    file_size: int
    flags: int


@dataclass(frozen=True)
class Bundle:
    program: Program
    mappings: tuple[Mapping, ...]


def _hash(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_bundle(program: Program) -> bytes:
    validate_modules(program.modules)
    payload = bytearray()
    modules = []
    for module in program.modules:
        segments = []
        for segment in module.segments:
            chunks = []
            runs = ([(0, bytes(segment.data))] if segment.data else []) + segment.sparse_runs()
            for relative, data in runs:
                chunks.append({"relative": relative, "offset": len(payload), "size": len(data), "sha256": _hash(data)})
                payload.extend(data)
            segments.append({"source_offset": segment.source_offset, "original_address": segment.original_address,
                             "address": segment.address, "memory_size": segment.memory_size,
                             "file_size": len(segment.data), "flags": segment.flags,
                             "alignment": segment.alignment, "chunks": chunks})
        modules.append({"name": module.name, "source_sha256": module.source_hash, "kind": module.kind,
                        "entry_descriptor": module.entry_descriptor, "aliases": module.aliases,
                        "linkage_address": module.linkage_address, "segments": segments,
                        "sections": [asdict(section) for section in module.sections],
                        "tls": [asdict(template) for template in module.tls],
                        "symbols": [asdict(symbol) for symbol in module.symbols],
                        "sources": [asdict(source) for source in module.sources]})
    bindings = []
    for binding in program.bindings:
        if binding.target is None:
            continue
        bindings.append({"importer": binding.importer, "exporter": binding.exporter,
                         "library": binding.library, "kind": binding.kind, "nid": binding.nid,
                         "slot": binding.slot, "original_value": binding.original_value, "target": binding.target,
                         "fixups": [{"address": patch.address, "kind": patch.kind,
                                     "before": patch.before.hex(), "after": patch.after.hex()}
                                    for patch in binding.fixups]})
    metadata = json.dumps({"modules": modules, "bindings": bindings, "relocations": program.relocation_count},
                          separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(metadata) > MAX_METADATA_SIZE:
        raise ValueError("PS3EXE metadata exceeds the supported size")
    return HEADER.pack(MAGIC, VERSION, len(metadata), len(payload)) + metadata + payload


def _integer(record: dict, key: str, maximum: int = 0xFFFFFFFF) -> int:
    value = record[key]
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"invalid {key}")
    return value


def _text(record: dict, key: str, allow_empty: bool = False, maximum: int = 1024) -> str:
    value = record[key]
    if not isinstance(value, str) or len(value) > maximum or "\0" in value or (not value and not allow_empty):
        raise ValueError(f"invalid {key}")
    return value


def _digest(record: dict, key: str) -> str:
    value = _text(record, key)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"invalid {key}")
    return value


def _read_sources(records) -> tuple[Source, ...]:
    sources = []
    for record in records:
        kind, mode = _text(record, "kind"), _text(record, "sector_mode", allow_empty=True)
        if kind not in ("elf", "self") or mode not in ("", "plain", "encrypted"):
            raise ValueError("unsupported executable source format")
        size = _integer(record, "size", (1 << 64) - 1)
        container_size = _integer(record, "container_size", (1 << 64) - 1)
        extents = []
        for item in record["extents"]:
            if not isinstance(item, list) or len(item) != 2 or any(type(value) is not int for value in item):
                raise ValueError("invalid source extent")
            offset, length = item
            checked_range(offset, length, container_size, "source extent")
            extents.append((offset, length))
        if extents and sum(length for _, length in extents) != size:
            raise ValueError("source extents disagree with source size")
        sources.append(Source(_text(record, "path"), _digest(record, "sha256"), kind, size,
                              _text(record, "container", allow_empty=True), container_size, tuple(extents), mode,
                              _integer(record, "verified_loads"), _integer(record, "unhashed_loads"),
                              _integer(record, "supplemental_mismatches"),
                              _text(record, "key_name", allow_empty=True)))
    return tuple(sources)


def _read_module(item: dict, payload: bytes, payload_start: int, used: list[tuple[int, int]],
                 mappings: list[Mapping], allow_modified: bool) -> Module:
    name = _text(item, "name")
    kind = _integer(item, "kind")
    if kind not in (EXECUTABLE, PRX):
        raise ValueError("unsupported bundled module type")
    if not isinstance(item["aliases"], list) or any(not isinstance(alias, str) or "\0" in alias
                                                  for alias in item["aliases"]):
        raise ValueError("invalid module source aliases")
    segments = []
    for index, record in enumerate(item["segments"]):
        address, memory_size = _integer(record, "address"), _integer(record, "memory_size", 1 << 32)
        checked_range(address, memory_size, 1 << 32, "bundled segment")
        file_size = _integer(record, "file_size")
        if file_size > memory_size:
            raise ValueError("bundled file bytes exceed memory")
        segment = Segment(index, _integer(record, "source_offset", (1 << 64) - 1),
                          _integer(record, "original_address"), address, memory_size,
                          _integer(record, "flags"), _integer(record, "alignment", 1 << 32), bytearray())
        alignment = segment.alignment
        if alignment > 1 and (alignment & (alignment - 1) or
                              address % alignment != segment.original_address % alignment):
            raise ValueError("invalid bundled segment alignment")
        chunks = record["chunks"]
        if file_size and (not chunks or chunks[0]["relative"] != 0 or chunks[0]["size"] != file_size):
            raise ValueError("missing initialized segment payload")
        cursor = 0
        for chunk_index, chunk in enumerate(chunks):
            relative = _integer(chunk, "relative")
            offset, size = _integer(chunk, "offset", len(payload)), _integer(chunk, "size", len(payload))
            checked_range(offset, size, len(payload), "bundle payload")
            checked_range(relative, size, memory_size, "bundle chunk")
            if not size or relative < cursor or (relative < file_size and (chunk_index != 0 or size != file_size)):
                raise ValueError("overlapping or misplaced segment chunks")
            data = payload[offset:offset + size]
            expected_hash = _digest(chunk, "sha256")
            if not allow_modified and _hash(data) != expected_hash:
                raise ValueError("bundle payload hash mismatch")
            used.append((offset, offset + size))
            if relative > cursor:
                mappings.append(Mapping(name, index, address + cursor, relative - cursor, 0, 0, segment.flags))
            mappings.append(Mapping(name, index, address + relative, size, payload_start + offset, size, segment.flags))
            if relative == 0 and file_size:
                segment.data = bytearray(data)
            else:
                segment.write(relative, data)
            cursor = relative + size
        if cursor < memory_size:
            mappings.append(Mapping(name, index, address + cursor, memory_size - cursor, 0, 0, segment.flags))
        segments.append(segment)
    if not segments:
        raise ValueError("module has no segments")
    sections = []
    for record in item["sections"]:
        values = [_integer(record, field, (1 << 64) - 1) for field in
                  ("kind", "flags", "address", "offset", "size", "link", "info", "alignment", "entry_size")]
        sections.append(Section(_text(record, "name", allow_empty=True), *values))
    tls = []
    for record in item["tls"]:
        fields = ("address", "file_size", "memory_size", "alignment")
        template = TlsTemplate(*[_integer(record, field) for field in fields])
        if template.file_size > template.memory_size:
            raise ValueError("TLS template bytes exceed its thread allocation size")
        tls.append(template)
    module = Module(name, _digest(item, "source_sha256"), kind, _integer(item, "entry_descriptor"), segments,
                    tuple(sections), tuple(item["aliases"]), _integer(item, "linkage_address"), tuple(tls))
    for section in module.sections:
        module.locate(section.address, section.size)
    for template in module.tls:
        module.locate(template.address, max(1, template.file_size))
    symbols = []
    for record in item.get("symbols", []):
        is_descriptor = record["is_descriptor"]
        if type(is_descriptor) is not bool:
            raise ValueError("invalid symbol descriptor flag")
        symbol = Symbol(_text(record, "name", maximum=MAX_METADATA_SIZE), _integer(record, "address"),
                        _integer(record, "size", (1 << 64) - 1), _integer(record, "kind", 2),
                        _integer(record, "binding", 15), _integer(record, "visibility", 7), is_descriptor)
        if symbol.is_descriptor and symbol.kind != 2:
            raise ValueError("a function descriptor must have function symbol type")
        module.locate(symbol.address, max(1, symbol.size) if symbol.kind == 1 else 1)
        symbols.append(symbol)
    module.symbols = tuple(symbols)
    module.sources = _read_sources(item.get("sources", []))
    return module


def _snapshot_binding(record, importer, exporter, library, kind, entry, exports):
    target, nid = _integer(record, "target"), _integer(record, "nid")
    original_value = _integer(record, "original_value")
    if library != _text(record, "library") or kind != _text(record, "kind") or nid != entry.nid:
        raise ValueError("bundle binding disagrees with its import table")
    if exports.get((exporter.name, library, kind, nid)) != {target}:
        raise ValueError("bundle binding disagrees with its export table")
    opd = descriptor(exporter, target) if kind == "function" else None
    exporter.locate(target)
    if (opd and entry.value != target) or (not opd and entry.value != original_value):
        raise ValueError("bound slot disagrees with its snapshot")
    patches = []
    for item in record["fixups"]:
        address, patch_kind = _integer(item, "address"), _integer(item, "kind")
        before, after = bytes.fromhex(_text(item, "before")), bytes.fromhex(_text(item, "after"))
        if len(before) != WIDTHS.get(patch_kind) or len(before) != len(after):
            raise ValueError("invalid bound-reference patch")
        if address % min(len(after), 4) or importer.read(address, len(after)) != after:
            raise ValueError("bound reference disagrees with its mapped bytes")
        patches.append(Patch(address, before, after, patch_kind))
    expected = []
    if opd:
        expected.append(Patch(entry.slot, original_value.to_bytes(4, "big"), target.to_bytes(4, "big"), 1))
    expected.extend(reference_fixups(importer, entry.references if opd else entry.value, target))
    if [(patch.address, patch.kind, patch.after) for patch in patches] != [
            (patch.address, patch.kind, patch.after) for patch in expected]:
        raise ValueError("binding references disagree with their linkage records")
    return Binding(importer.name, exporter.name, library, kind, nid, entry.slot,
                   original_value, target, opd, tuple(patches))


def _read_bindings(records: list, modules: list[Module], facts: list, allow_modified: bool) -> list[Binding]:
    by_name = {module.name: module for module in modules}
    imports = {}
    exports = {}
    for module, info in zip(modules, facts):
        for library in info.linkage.imports:
            for kind, entries in (("function", library.functions), ("variable", library.variables)):
                for entry in entries:
                    key = module.name, entry.slot
                    if key in imports:
                        raise ValueError("duplicate import slot")
                    imports[key] = library.name, kind, entry
        for library in info.linkage.exports:
            for kind, entries in (("function", library.functions), ("variable", library.variables)):
                for entry in entries:
                    exports.setdefault((module.name, library.name, kind, entry.nid), set()).add(entry.value)
    bindings = []
    for record in records:
        importer, exporter = by_name[_text(record, "importer")], by_name[_text(record, "exporter")]
        key = importer.name, _integer(record, "slot")
        if key not in imports:
            if allow_modified:
                continue
            raise ValueError("binding has no corresponding import")
        library, kind, entry = imports[key]
        try:
            binding = _snapshot_binding(record, importer, exporter, library, kind, entry, exports)
        except ValueError:
            if not allow_modified:
                raise
            continue  # database edits revoke snapshot assertions that no longer match the bytes.
        bindings.append(binding)
        del imports[key]
    for (module_name, slot), (library, kind, entry) in imports.items():
        bindings.append(Binding(module_name, None, library, kind, entry.nid, slot, entry.value))
    return bindings


def read_bundle(data: bytes, *, allow_modified: bool = False) -> Bundle:
    try:
        checked_range(0, HEADER.size, len(data), "PS3EXE header")
        magic, version, metadata_size, payload_size = HEADER.unpack_from(data)
        if magic != MAGIC or version != VERSION or metadata_size > MAX_METADATA_SIZE:
            raise ValueError("unsupported PS3EXE header")
        payload_start = HEADER.size + metadata_size
        if payload_start + payload_size != len(data):
            raise ValueError("PS3EXE length mismatch")
        metadata = json.loads(data[HEADER.size:payload_start])
        payload = data[payload_start:]
        used: list[tuple[int, int]] = []
        mappings: list[Mapping] = []
        modules = [_read_module(item, payload, payload_start, used, mappings, allow_modified)
                   for item in metadata["modules"]]
        if not modules:
            raise ValueError("PS3EXE has no modules")
        validate_modules(modules)
        validate_ranges(used, "bundle payloads")
        ordered = sorted(used)
        if (ordered and (ordered[0][0] != 0 or ordered[-1][1] != len(payload))) or (
                not ordered and payload) or any(left[1] != right[0] for left, right in zip(ordered, ordered[1:])):
            raise ValueError("PS3EXE contains unreferenced payload bytes")
        facts = [module_facts(module, strict=not allow_modified) for module in modules]
        bindings = _read_bindings(metadata["bindings"], modules, facts, allow_modified)
        return Bundle(Program(modules, facts, bindings, _integer(metadata, "relocations")), tuple(mappings))
    except (KeyError, TypeError, IndexError, struct.error, UnicodeError) as error:
        raise ValueError(f"invalid PS3EXE metadata: {error}") from error
