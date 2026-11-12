"""Native-backed PPU bundles and independent SPU executable views."""

import binaryninja as bn
from binaryninja import _binaryninjacore as core

from ...core.view_base import BaseRomView
from .annotate import annotate_import_symbols, annotate_program, context_metadata, module_metadata, spu_metadata
from .bundle import MAGIC, Bundle, Mapping, encode_bundle, read_bundle
from .elf import EXECUTABLE, ElfImage
from .prepare import Program, prepare_program
from .reloc import read_relocations
from .spu import MAX_IMAGE_SIZE, parse_spu


class _ContextNotifications(bn.BinaryDataNotification):
    def __init__(self, program: Program):
        super().__init__(bn.NotificationType.DataWritten)
        self.toc_roots = set(program.function_tocs)
        self.dependencies: dict[tuple[int, int], set[int]] = {}
        for facts in program.facts:
            for descriptor in facts.descriptors:
                self.dependencies.setdefault((descriptor.address, 8), set()).add(descriptor.code)
        for binding in program.bindings:
            if binding.descriptor is not None:
                self.dependencies.setdefault((binding.slot, 4), set()).add(binding.original_value)
                self.dependencies.setdefault((binding.descriptor.address, 8), set()).add(binding.original_value)

    def data_written(self, view: bn.BinaryView, offset: int, length: int) -> None:
        if not length:
            return
        affected = set()
        generation = view.get_metadata("ps3.context_generation", 0)
        generation = generation if type(generation) is int and 0 <= generation < 2**64 else 0
        view.store_metadata("ps3.context_generation", (generation + 1) % 2**64,
                            bn.MetadataStoreFlag.MetadataStorePersistent)
        inferred = view.get_metadata("ps3.call_contexts")
        if isinstance(inferred, dict) and inferred.get("version") == 1:
            for name in ["tocs", "ambiguous"]:
                values = inferred.get(name, {})
                for key in values if isinstance(values, dict) else ():
                    try:
                        address = int(key)
                    except (TypeError, ValueError):
                        continue
                    if 0 <= address <= 0xFFFFFFFF:
                        affected.add(address)
            view.remove_metadata("ps3.call_contexts")
        descriptor_changes = set()
        for (address, size), functions in self.dependencies.items():
            if offset < address + size and address < offset + length:
                affected.update(functions)
                if size == 8:
                    descriptor_changes.add(address)
        if descriptor_changes:
            for function in view.functions:
                reads = function.get_metadata("ps3.descriptor_reads", [])
                if isinstance(reads, list) and any(address in descriptor_changes for address in reads):
                    affected.add(function.start)
        context_changes = set()
        # Native call effects inspect up to 32 bytes from a stub's entry.
        # Revoke the caller's cached effect when any of that prefix is edited.
        lookback = min(offset, 31)
        for reference in view.get_code_refs(offset - lookback, length + lookback):
            function = reference.function
            if function is not None:
                affected.add(function.start)
                if function.start not in self.toc_roots:
                    context_changes.add(function.start)
        # An adjustment chain's saved value depends on its downstream stubs.
        # Follow references through functions without an independent TOC anchor.
        pending = list(context_changes)
        visited = set()
        while pending:
            address = pending.pop()
            if address in visited:
                continue
            visited.add(address)
            for reference in view.get_code_refs(address):
                function = reference.function
                if function is not None:
                    affected.add(function.start)
                    if function.start not in self.toc_roots:
                        pending.append(function.start)
        for address in affected:
            function = view.get_function_at(address)
            if function is not None:
                # The native activity's replaced loads no longer create core memory dependencies.
                function.reanalyze()
        if affected:
            view.update_analysis()


class Ps3View(BaseRomView):
    def perform_get_default_endianness(self):
        return bn.Endianness.BigEndian

    def _export_data(self) -> bytes:
        return self.raw.read(0, self.raw.length)

    def _save(self, ctxt, accessor):
        # BN 6.0's Python save wrapper constructs an invalid CoreFileAccessor.
        # Pass the core accessor through unchanged.
        try:
            raw = bn.BinaryView.new(self._export_data())
            try:
                return core.BNSaveToFile(raw.handle, accessor)
            finally:
                raw.file.close()
        except Exception as error:
            bn.log_error(f"PS3 executable export: {error}")
            return False

    def _snapshot(self) -> Bundle:
        raise NotImplementedError

    def init(self) -> bool:
        try:
            if "ps3-lv2" not in bn.Platform:
                raise ValueError("install binja-ps3-platform to analyze PS3 executables")
            self.platform = bn.Platform["ps3-lv2"]
            if self.parse_only:
                return True
            if not self.file.has_database:
                bn.Settings().set_string("analysis.workflows.functionWorkflow", "ps3.function", self)
            snapshot = self._snapshot()
            program = snapshot.program
            self._entry_point = program.entry_code
            for mapping in snapshot.mappings:
                flags = bn.SegmentFlag(0)
                for elf_flag, flag in ((4, bn.SegmentFlag.SegmentReadable),
                                       (2, bn.SegmentFlag.SegmentWritable),
                                       (1, bn.SegmentFlag.SegmentExecutable)):
                    if mapping.flags & elf_flag:
                        flags |= flag
                self.add_auto_segment(mapping.address, mapping.size, mapping.file_offset, mapping.file_size, flags)
            for module, facts in zip(program.modules, program.facts):
                for index, section in enumerate(module.sections):
                    semantics = (bn.SectionSemantics.ReadOnlyCodeSectionSemantics if section.flags & 4 else
                                 bn.SectionSemantics.ReadWriteDataSectionSemantics if section.flags & 1 else
                                 bn.SectionSemantics.ReadOnlyDataSectionSemantics)
                    self.add_auto_section(f"{module.name}:{section.name or index}",
                                          section.address, section.size, semantics)
                for index, image in enumerate(facts.spu_images):
                    self.add_auto_section(f"{module.name}:spu_{index}", image.address, image.file_size,
                                          bn.SectionSemantics.ReadOnlyDataSectionSemantics)
            # These facts are reconstructed from the snapshot on every open, including database opens.
            self.store_metadata("ps3.contexts", context_metadata(program), bn.MetadataStoreFlag.MetadataStoreEphemeral)
            generation = self.get_metadata("ps3.context_generation")
            if type(generation) is not int or not 0 <= generation < 2**64:
                self.store_metadata("ps3.context_generation", 0, bn.MetadataStoreFlag.MetadataStorePersistent)
            self.store_metadata("ps3.spu_images", spu_metadata(program), bn.MetadataStoreFlag.MetadataStoreEphemeral)
            self.store_metadata("ps3.modules", module_metadata(program), bn.MetadataStoreFlag.MetadataStoreEphemeral)
            self.register_notification(_ContextNotifications(program))
            if not self.file.has_database:
                annotate_program(self, program)
            annotate_import_symbols(self, program)
            if self._entry_point:
                self.add_entry_point(self._entry_point)
            return True
        except (ValueError, KeyError) as error:
            bn.log_error(f"PS3 executable: {error}")
            return False

class Ps3ExeView(Ps3View):
    name = "PS3 PS3EXE"
    long_name = "PlayStation 3 Executable Bundle"

    @classmethod
    def is_valid_for_data(cls, data):
        return data.read(0, len(MAGIC)) == MAGIC

    def _snapshot(self):
        return read_bundle(self.raw.read(0, self.raw.length), allow_modified=self.file.has_database)

    def _export_data(self):
        snapshot = read_bundle(self.raw.read(0, self.raw.length), allow_modified=True)
        return encode_bundle(snapshot.program)


class Ps3ElfView(Ps3View):
    name = "PS3 ELF"
    long_name = "PlayStation 3 PPU Executable"

    @classmethod
    def is_valid_for_data(cls, data):
        header = data.read(0, 20)
        return (len(header) == 20 and header[:8] == b"\x7fELF\x02\x02\x01\x66" and
                int.from_bytes(header[16:18], "big") == EXECUTABLE and header[18:20] == b"\0\x15")

    def _snapshot(self):
        image = ElfImage("main", self.raw.read(0, self.raw.length))
        if read_relocations(image):
            raise ValueError("prepare a PS3EXE snapshot for executables with Sony relocations")
        program = prepare_program([image])
        mappings = tuple(Mapping("main", item.index, item.address, item.memory_size,
                                 item.source_offset, len(item.data), item.flags)
                         for item in program.modules[0].segments if item.memory_size)
        return Bundle(program, mappings)


def open_spu_image(parent: bn.BinaryView, address: int) -> bn.BinaryView:
    """Open an inventoried embedded ELF in a new file with independent local-store addresses."""
    images = parent.query_metadata("ps3.spu_images")
    matches = [item for item in images if item["address"] == address]
    if len(matches) != 1:
        raise ValueError("expected the start address of one embedded SPU executable")
    source = matches[0]
    if not 0 < source["size"] <= MAX_IMAGE_SIZE:
        raise ValueError("invalid embedded SPU image size")
    data = parent.read(address, source["size"])
    if len(data) != source["size"]:
        raise ValueError("embedded SPU executable is not fully backed")
    image = parse_spu(data)
    if image.relocations:
        raise ValueError("SPU relocations require a linked executable image")
    raw = bn.BinaryView.new(data)
    raw.file.filename = f"spu_{address:x}.elf"
    view = bn.load(raw, update_analysis=False)
    if view is None or view.arch is None or view.arch.name != "ps3-spu":
        raw.file.close()
        raise ValueError("install binja-ps3-platform to analyze SPU executables")
    view.store_metadata("ps3.spu_source", {"version": 1, "module": source["module"], "address": address,
                                           "payload_sha256": image.payload_hash})
    return view


Ps3ExeView.register()
Ps3ElfView.register()
