"""Mapped modules with byte-backed segments and sparse zero-fill writes."""

from dataclasses import dataclass, field, replace

from .elf import ElfImage, Section, checked_range, validate_ranges


@dataclass
class Segment:
    index: int
    source_offset: int
    original_address: int
    address: int
    memory_size: int
    flags: int
    alignment: int
    data: bytearray
    zero_fill: dict[int, int] = field(default_factory=dict)

    def read(self, offset: int, size: int) -> bytes:
        checked_range(offset, size, self.memory_size, "segment read")
        backed = max(0, min(size, len(self.data) - offset))
        result = bytearray(self.data[offset:offset + backed]) + bytearray(size - backed)
        for position, value in self.zero_fill.items():
            if offset <= position < offset + size:
                result[position - offset] = value
        return bytes(result)

    def write(self, offset: int, data: bytes) -> None:
        checked_range(offset, len(data), self.memory_size, "segment write")
        backed = max(0, min(len(data), len(self.data) - offset))
        if backed:
            self.data[offset:offset + backed] = data[:backed]
        for index, value in enumerate(data[backed:], offset + backed):
            if value:
                self.zero_fill[index] = value
            else:
                self.zero_fill.pop(index, None)

    def sparse_runs(self) -> list[tuple[int, bytes]]:
        runs: list[tuple[int, bytearray]] = []
        for position in sorted(self.zero_fill):
            if runs and runs[-1][0] + len(runs[-1][1]) == position:
                runs[-1][1].append(self.zero_fill[position])
            else:
                runs.append((position, bytearray([self.zero_fill[position]])))
        return [(offset, bytes(data)) for offset, data in runs]


@dataclass(frozen=True)
class TlsTemplate:
    address: int
    file_size: int
    memory_size: int
    alignment: int


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int
    kind: int
    binding: int
    visibility: int
    is_descriptor: bool = False


@dataclass(frozen=True)
class Source:
    path: str
    sha256: str
    kind: str
    size: int
    container: str = ""
    container_size: int = 0
    extents: tuple[tuple[int, int], ...] = ()
    sector_mode: str = ""
    verified_loads: int = 0
    unhashed_loads: int = 0
    supplemental_mismatches: int = 0
    key_name: str = ""


@dataclass
class Module:
    name: str
    source_hash: str
    kind: int
    entry_descriptor: int
    segments: list[Segment]
    sections: tuple[Section, ...] = ()
    aliases: tuple[str, ...] = ()
    linkage_address: int = 0
    tls: tuple[TlsTemplate, ...] = ()
    symbols: tuple[Symbol, ...] = ()
    sources: tuple[Source, ...] = ()

    @property
    def descriptor_sections(self) -> tuple[Section, ...]:
        return tuple(section for section in self.sections if section.name == ".opd" or
                     (self.entry_descriptor and
                      section.address <= self.entry_descriptor < section.address + section.size))

    @classmethod
    def from_elf(cls, image: ElfImage, bases: list[int] | None = None) -> "Module":
        bases = [segment.address for segment in image.segments] if bases is None else bases
        if len(bases) != len(image.segments):
            raise ValueError("placement must preserve every PT_LOAD ordinal")
        segments = []
        for index, (program, base) in enumerate(zip(image.segments, bases)):
            checked_range(program.address, program.memory_size, 1 << 32, "original PPU segment")
            checked_range(base, program.memory_size, 1 << 32, "PPU segment")
            if program.alignment > 1 and base % program.alignment != program.address % program.alignment:
                raise ValueError("segment placement violates ELF alignment")
            segments.append(Segment(index, program.offset, program.address, base, program.memory_size,
                                    program.flags, program.alignment,
                                    bytearray(image.slice(program.offset, program.file_size))))
        validate_ranges([(item.address, item.address + item.memory_size) for item in segments], "module segments")
        module = cls(image.name, image.sha256, image.kind, 0, segments)
        if image.kind == 2 and image.entry:
            module.entry_descriptor = module.translate(image.entry, 8)
        module.sections = tuple(replace(section, address=(module.translate(section.address, section.size)
                                                          if section.kind == 8 else
                                                          module.file_address(section.offset, section.size)))
                                for section in image.sections if section.flags & 2 and section.size)
        module.tls = tuple(TlsTemplate(module.file_address(program.offset, program.file_size) if program.file_size else
                                       module.translate(program.address),
                                       program.file_size, program.memory_size, program.alignment)
                           for program in image.program_headers if program.kind == 7)
        symbols = {}
        for symbol in image.symbols():
            # Undefined, absolute, file and TLS-offset symbols do not label mapped storage.
            if not symbol.name or not 0 < symbol.section < 0xFF00 or symbol.kind not in (0, 1, 2):
                continue
            section = image.sections[symbol.section]
            if not section.flags & 2 or not section.size:
                continue
            relative = symbol.value - section.address
            checked_range(relative, symbol.size if symbol.kind == 1 else 0,
                          section.size, "ELF symbol definition")
            start = (module.translate(section.address, section.size) if section.kind == 8 else
                     module.file_address(section.offset, section.size))
            if relative == section.size:
                # Zero-sized boundary labels are valid ELF. Retain only mapped labels.
                if symbol.kind == 2:
                    continue
                try:
                    module.locate(start + relative)
                except ValueError:
                    continue
            mapped = Symbol(symbol.name, start + relative, symbol.size, symbol.kind,
                            symbol.binding, symbol.visibility, symbol.kind == 2 and not bool(section.flags & 4))
            symbols[mapped] = None  # A definition can appear in both symbol tables.
        module.symbols = tuple(symbols)
        if image.kind == 2:
            params = [program for program in image.program_headers if program.kind == 0x60000002]
            if len(params) > 1:
                raise ValueError("multiple process PRX parameter tables")
            if params:
                module.linkage_address = module.translate(params[0].address, 40)
        else:
            first = image.segments[0]
            info_offset = first.physical_address - first.offset
            checked_range(info_offset, 52, first.memory_size, "PRX module info")
            module.linkage_address = bases[0] + info_offset
        return module

    def file_address(self, offset: int, size: int) -> int:
        matches = [item for item in self.segments if item.data and
                   item.source_offset <= offset and offset + size <= item.source_offset + len(item.data)]
        if len(matches) != 1:
            raise ValueError(f"ambiguous or unmapped ELF file range {offset:#x}+{size:#x}")
        return matches[0].address + offset - matches[0].source_offset

    def translate(self, original: int, size: int = 1) -> int:
        matches = [item for item in self.segments if item.memory_size and
                   item.original_address <= original and original + size <= item.original_address + item.memory_size]
        if len(matches) != 1:
            raise ValueError(f"ambiguous or unmapped original address {original:#x}")
        return matches[0].address + original - matches[0].original_address

    def locate(self, address: int, size: int = 1) -> tuple[Segment, int]:
        if size < 0:
            raise ValueError("negative memory range")
        matches = [item for item in self.segments if item.memory_size and
                   item.address <= address and address + size <= item.address + item.memory_size]
        if len(matches) != 1:
            raise ValueError(f"ambiguous or unmapped address {address:#x}")
        return matches[0], address - matches[0].address

    def read(self, address: int, size: int) -> bytes:
        segment, offset = self.locate(address, size)
        return segment.read(offset, size)

    def write(self, address: int, data: bytes) -> None:
        segment, offset = self.locate(address, len(data))
        segment.write(offset, data)


def validate_modules(modules: list[Module]) -> None:
    names = [module.name for module in modules]
    if len(set(names)) != len(names):
        raise ValueError("module names must be unique")
    validate_ranges([(item.address, item.address + item.memory_size)
                     for module in modules for item in module.segments], "module placements")
