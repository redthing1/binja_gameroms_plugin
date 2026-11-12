"""PPU module linkage records, descriptors and import resolution."""

from dataclasses import dataclass
import struct

from .model import Module, validate_modules
from .reloc import WIDTHS, Patch, apply_patches, encode


@dataclass(frozen=True)
class Entry:
    nid: int
    slot: int
    value: int
    references: int = 0


@dataclass(frozen=True)
class Library:
    name: str
    address: int
    version: int
    attributes: int
    functions: tuple[Entry, ...]
    variables: tuple[Entry, ...]


@dataclass(frozen=True)
class Linkage:
    name: str
    exports: tuple[Library, ...]
    imports: tuple[Library, ...]


@dataclass(frozen=True)
class Descriptor:
    address: int
    code: int
    toc: int


@dataclass(frozen=True)
class Binding:
    importer: str
    exporter: str | None
    library: str
    kind: str
    nid: int
    slot: int
    original_value: int
    target: int | None = None
    descriptor: Descriptor | None = None
    fixups: tuple[Patch, ...] = ()


def cstring(module: Module, address: int) -> str:
    if not address:
        return ""
    data = bytearray()
    for offset in range(256):
        value = module.read(address + offset, 1)
        if value == b"\0":
            return data.decode("ascii")
        data.extend(value)
    raise ValueError("unterminated module or library name")


def library_records(module: Module, start: int, end: int, importing: bool) -> tuple[Library, ...]:
    if end < start:
        raise ValueError("reversed linkage-table bounds")
    if end > start:
        module.locate(start, end - start)
    records = []
    address = start
    while address < end:
        prefix = module.read(address, 28)
        size = prefix[0] or 44
        if size < 28 or address + size > end:
            raise ValueError("invalid linkage record size")
        version, attributes, functions, variables, tls = struct.unpack_from(">HHHHH", prefix, 2)
        if tls:
            raise ValueError("TLS library imports/exports are not supported")
        name, nids, slots = struct.unpack_from(">III", prefix, 16)
        entries = []
        for index in range(functions):
            nid = int.from_bytes(module.read(nids + index * 4, 4), "big")
            slot = slots + index * 4
            value = int.from_bytes(module.read(slot, 4), "big")
            reference = 0
            if importing and attributes & 0x2000:
                reference = int.from_bytes(module.read(nids + (functions + index) * 4, 4), "big")
            entries.append(Entry(nid, slot, value, reference))
        if importing and variables:
            if size < 36:
                raise ValueError("variable imports need an extended linkage record")
            variable_nids, variable_slots = struct.unpack(">II", module.read(address + 28, 8))
        else:
            variable_nids, variable_slots = nids + functions * 4, slots + functions * 4
        variable_entries = []
        for index in range(variables):
            nid = int.from_bytes(module.read(variable_nids + index * 4, 4), "big")
            slot = variable_slots + index * 4
            value = int.from_bytes(module.read(slot, 4), "big")
            variable_entries.append(Entry(nid, slot, value))
        records.append(Library(cstring(module, name), address, version, attributes,
                               tuple(entries), tuple(variable_entries)))
        address += size
    return tuple(records)


def linkage_tables(module: Module) -> Linkage:
    if not module.linkage_address:
        return Linkage(module.name, (), ())
    if module.kind == 2:
        params = struct.unpack(">10I", module.read(module.linkage_address, 40))
        if params[0] < 40 or params[1] != 0x1B434CEC:
            raise ValueError("invalid process PRX parameters")
        exports_start, exports_end, imports_start, imports_end = params[4:8]
        name = module.name
    else:
        info = module.read(module.linkage_address, 52)
        name = info[4:32].split(b"\0", 1)[0].decode("ascii") or module.name
        _, exports_start, exports_end, imports_start, imports_end = struct.unpack_from(">5I", info, 32)
    return Linkage(name, library_records(module, exports_start, exports_end, False),
                   library_records(module, imports_start, imports_end, True))


def descriptor(module: Module, address: int) -> Descriptor:
    code, toc = struct.unpack(">II", module.read(address, 8))
    segment, _ = module.locate(code, 4)
    if address % 4 or code % 4 or not segment.flags & 1:
        raise ValueError("function descriptor does not identify aligned executable code")
    module.locate(toc)
    return Descriptor(address, code, toc)


def reference_fixups(module: Module, start: int, value: int) -> tuple[Patch, ...]:
    if not start:
        return ()
    patches = []
    for index in range(4096):
        kind = int.from_bytes(module.read(start + index * 12, 4), "big")
        if not kind:
            return tuple(patches)
        if kind not in (1, 4, 6, 57):
            raise ValueError(f"unsupported linkage reference type {kind}")
        address, addend = struct.unpack(">II", module.read(start + index * 12 + 4, 8))
        width = WIDTHS[kind]
        if address % min(width, 4):
            raise ValueError("misaligned linkage reference")
        before = module.read(address, width)
        patches.append(Patch(address, before, encode(kind, value + addend, address, before), kind))
    raise ValueError("unterminated linkage reference list")


def link_modules(modules: list[Module], tables: list[Linkage]) -> list[Binding]:
    validate_modules(modules)
    if len(modules) != len(tables):
        raise ValueError("module/linkage count mismatch")
    exports = {}
    for module, table in zip(modules, tables):
        for library in table.exports:
            if not library.name:
                continue
            for kind, entries in (("function", library.functions), ("variable", library.variables)):
                for entry in entries:
                    key = library.name, kind, entry.nid
                    target = module.name, entry.value
                    if key in exports and exports[key] != target:
                        raise ValueError(f"ambiguous export {key}")
                    exports[key] = target
    by_name = {module.name: module for module in modules}
    bindings = []
    seen_slots = set()
    plans: dict[str, list[Patch]] = {module.name: [] for module in modules}
    for module, table in zip(modules, tables):
        for library in table.imports:
            for kind, entries in (("function", library.functions), ("variable", library.variables)):
                for entry in entries:
                    slot_key = module.name, entry.slot
                    if slot_key in seen_slots:
                        raise ValueError("duplicate import slot")
                    seen_slots.add(slot_key)
                    target = exports.get((library.name, kind, entry.nid))
                    if target is None:
                        bindings.append(Binding(module.name, None, library.name, kind, entry.nid,
                                                entry.slot, entry.value))
                        continue
                    exporter_name, value = target
                    exporter = by_name[exporter_name]
                    opd = descriptor(exporter, value) if kind == "function" else None
                    exporter.locate(value)
                    patches = []
                    if opd:
                        patches.append(Patch(entry.slot, entry.value.to_bytes(4, "big"),
                                             value.to_bytes(4, "big"), 1))
                    patches.extend(reference_fixups(module, entry.references if opd else entry.value, value))
                    plans[module.name].extend(patches)
                    bindings.append(Binding(module.name, exporter_name, library.name, kind, entry.nid,
                                            entry.slot, entry.value, value, opd, tuple(patches)))
    # Validate every module's complete plan before changing any module.
    for name, patches in plans.items():
        module = by_name[name]
        intervals = sorted((patch.address, patch.address + len(patch.after)) for patch in patches)
        if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:])):
            raise ValueError("overlapping import-link writes")
        for patch in patches:
            if module.read(patch.address, len(patch.before)) != patch.before:
                raise ValueError("link fixup precondition changed")
    for name, patches in plans.items():
        apply_patches(by_name[name], patches)
    return bindings
