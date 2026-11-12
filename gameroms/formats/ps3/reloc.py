"""Sony PPU relocations, following RPCS3's module-loader semantics."""

from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class Relocation:
    offset: int
    value_segment: int
    address_segment: int
    kind: int
    addend: int


@dataclass(frozen=True)
class Patch:
    address: int
    before: bytes
    after: bytes
    kind: int


def read_relocations(image):
    records = []
    for p in image.program_headers:
        if p.kind != 0x700000A4:
            continue
        data = image.slice(p.offset, p.file_size)
        if len(data) % 24:
            raise ValueError("truncated Sony relocation record")
        for offset, unused, value, address, kind, addend in struct.iter_unpack(">QHBBIQ", data):
            if unused:
                raise ValueError("unrecognized relocation reserved bits")
            records.append(Relocation(offset, value, address, kind, addend))
    return records


def encode(kind, value, place, original):
    if kind == 1:
        if not 0 <= value < 1 << 32:
            raise ValueError("ADDR32 overflow")
        return value.to_bytes(4, "big")
    if kind in (4, 5, 6):
        half = {4: value, 5: value >> 16, 6: (value + 0x8000) >> 16}[kind]
        return (half & 0xFFFF).to_bytes(2, "big")
    if kind in (10, 11):
        displacement = value - place
        bits, mask = (26, 0x03FFFFFC) if kind == 10 else (16, 0xFFFC)
        if displacement % 4 or not -(1 << (bits - 1)) <= displacement < 1 << (bits - 1):
            raise ValueError("relative branch alignment/range error")
        word = int.from_bytes(original, "big")
        return ((word & ~mask) | (displacement & mask)).to_bytes(4, "big")
    if kind == 38:
        if not 0 <= value < 1 << 64:
            raise ValueError("ADDR64 overflow")
        return value.to_bytes(8, "big")
    if kind == 44:
        difference = value - place
        if not -(1 << 63) <= difference < 1 << 63:
            raise ValueError("REL64 overflow")
        return (difference & ((1 << 64) - 1)).to_bytes(8, "big")
    if kind == 57:
        if value % 4:
            raise ValueError("DS address is not four-byte aligned")
        return ((int.from_bytes(original, "big") & 3) | (value & 0xFFFC)).to_bytes(2, "big")
    raise ValueError(f"unsupported relocation {kind}")


WIDTHS = {1: 4, 4: 2, 5: 2, 6: 2, 10: 4, 11: 4, 38: 8, 44: 8, 57: 2}


def plan_relocations(module, records):
    patches, intervals = [], []
    for record in records:
        if record.kind == 0:
            continue
        if record.kind not in WIDTHS:
            raise ValueError(f"unsupported relocation {record.kind}")
        width = WIDTHS[record.kind]
        if not 0 <= record.address_segment < len(module.segments):
            raise ValueError("invalid destination segment index")
        if record.offset < 0 or record.offset + width > module.segments[record.address_segment].memory_size:
            raise ValueError("relocation extends beyond segment memory")
        if record.value_segment == 0xFF:
            base = 0
        elif 0 <= record.value_segment < len(module.segments) and module.segments[record.value_segment].memory_size:
            base = module.segments[record.value_segment].address
        else:
            raise ValueError("invalid source segment index")
        place = module.segments[record.address_segment].address + record.offset
        if place % min(width, 4):
            raise ValueError("misaligned relocation destination")
        before = module.read(place, width)
        after = encode(record.kind, base + record.addend, place, before)
        patches.append(Patch(place, before, after, record.kind))
        intervals.append((place, place + width))
    intervals.sort()
    if any(a[1] > b[0] for a, b in zip(intervals, intervals[1:])):
        raise ValueError("overlapping relocation writes require explicit composition")
    return patches


def apply_patches(module, patches):
    intervals = sorted((patch.address, patch.address + len(patch.after)) for patch in patches)
    if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:])):
        raise ValueError("overlapping patch writes")
    for patch in patches:
        if len(patch.before) != len(patch.after):
            raise ValueError("patch changes memory extent")
        if module.read(patch.address, len(patch.before)) != patch.before:
            raise ValueError("patch precondition changed")
    for patch in patches:
        module.write(patch.address, patch.after)
