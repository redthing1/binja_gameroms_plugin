"""Normalize, relocate and link executable modules into an analysis snapshot."""

from dataclasses import dataclass

from .elf import EXECUTABLE, PRX, ElfImage
from .link import Binding, Descriptor, Linkage, descriptor, link_modules, linkage_tables
from .model import Module, validate_modules
from .reloc import apply_patches, plan_relocations, read_relocations
from .spu import SpuImage, discover_spu


@dataclass(frozen=True)
class ModuleFacts:
    linkage: Linkage
    descriptors: tuple[Descriptor, ...]
    spu_images: tuple[SpuImage, ...]


@dataclass
class Program:
    modules: list[Module]
    facts: list[ModuleFacts]
    bindings: list[Binding]
    relocation_count: int = 0

    @property
    def entry_code(self) -> int:
        main = self.modules[0]
        return next((item.code for item in self.facts[0].descriptors
                     if item.address == main.entry_descriptor), 0)

    @property
    def function_tocs(self) -> dict[int, int]:
        contexts: dict[int, set[int]] = {}
        for facts in self.facts:
            for item in facts.descriptors:
                contexts.setdefault(item.code, set()).add(item.toc)
        return {code: next(iter(tocs)) for code, tocs in contexts.items() if len(tocs) == 1}


def module_facts(module: Module, *, strict: bool = True) -> ModuleFacts:
    linkage = linkage_tables(module)
    descriptors = {}

    def remember(address):
        try:
            descriptors[address] = descriptor(module, address)
        except ValueError:
            if strict:
                raise

    candidates = module.descriptor_sections
    if len(candidates) > 1:
        raise ValueError("ambiguous OPD section")
    for section in candidates:
        if section.kind != 1 or section.address % 8 or section.size % 8:
            raise ValueError("invalid compact OPD section")
        # A descriptor table must be initialized; never scan virtual BSS as an OPD table.
        segment, offset = module.locate(section.address, section.size)
        if offset + section.size > len(segment.data):
            raise ValueError("OPD table extends into zero-fill")
        for address in range(section.address, section.address + section.size, 8):
            if module.read(address, 8) != bytes(8):
                remember(address)
    if module.entry_descriptor:
        remember(module.entry_descriptor)
    for library in linkage.exports:
        for entry in library.functions:
            remember(entry.value)
    for symbol in module.symbols:
        if symbol.is_descriptor:
            remember(symbol.address)
    return ModuleFacts(linkage, tuple(descriptors[address] for address in sorted(descriptors)), discover_spu(module))


def _place_prx(image: ElfImage, cursor: int, occupied: list[tuple[int, int]]) -> tuple[list[int], int]:
    bases = []
    for segment in image.segments:
        alignment = max(0x1000, segment.alignment)
        residue = segment.address % alignment
        while True:
            base = ((cursor - residue + alignment - 1) // alignment) * alignment + residue
            conflicts = [end for start, end in occupied
                         if segment.memory_size and base < end and start < base + segment.memory_size]
            if not conflicts:
                break
            cursor = max(conflicts)
        bases.append(base)
        if segment.memory_size:
            occupied.append((base, base + segment.memory_size))
        cursor = base + max(segment.memory_size, 0x1000)
    return bases, cursor


def prepare_program(images: list[ElfImage], placements: dict[str, list[int]] | None = None) -> Program:
    if not images:
        raise ValueError("at least one executable module is required")
    placements = placements or {}
    if set(placements) - {image.name for image in images}:
        raise ValueError("placement names an unknown module")
    modules = []
    unique: dict[str, Module] = {}
    occupied = []
    for image in images:
        bases = placements.get(image.name)
        if bases is not None and len(bases) != len(image.segments):
            raise ValueError("placement must preserve every PT_LOAD ordinal")
        if image.kind == EXECUTABLE:
            bases = [segment.address for segment in image.segments]
        if bases is not None:
            occupied.extend((base, base + segment.memory_size) for base, segment in zip(bases, image.segments)
                            if segment.memory_size)
    cursor = 0x20000000
    relocation_count = 0
    for image in images:
        bases = placements.get(image.name)
        if image.sha256 in unique:
            previous = unique[image.sha256]
            if bases is not None and bases != [segment.address for segment in previous.segments]:
                raise ValueError("an executable alias requests a different placement")
            if image.name not in previous.aliases:
                previous.aliases += (image.name,)
            continue
        if image.kind == EXECUTABLE and bases is not None and bases != [item.address for item in image.segments]:
            raise ValueError("fixed executables cannot be rebased without relocation records")
        if image.kind == PRX and bases is None:
            bases, cursor = _place_prx(image, cursor, occupied)
        module = Module.from_elf(image, bases)
        module.aliases = (image.name,)
        patches = plan_relocations(module, read_relocations(image))
        apply_patches(module, patches)
        relocation_count += len(patches)
        modules.append(module)
        unique[image.sha256] = module
    validate_modules(modules)
    tables = [linkage_tables(module) for module in modules]
    bindings = link_modules(modules, tables)
    return Program(modules, [module_facts(module) for module in modules], bindings, relocation_count)
