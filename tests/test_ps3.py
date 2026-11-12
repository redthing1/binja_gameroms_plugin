"""Pure preparation tests; Binary Ninja and game dumps are not required."""

from dataclasses import replace
import hashlib
import json
import struct
import unittest

from gameroms.formats.ps3.bundle import HEADER, MAGIC, VERSION, encode_bundle, read_bundle
from gameroms.formats.ps3.elf import ElfImage, Section
from gameroms.formats.ps3.link import descriptor, link_modules, linkage_tables
from gameroms.formats.ps3.model import Module, Segment
from gameroms.formats.ps3.prepare import Program, module_facts, prepare_program
from gameroms.formats.ps3.reloc import Relocation, apply_patches, encode, plan_relocations, read_relocations
from gameroms.formats.ps3.spu import parse_spu


def elf_bytes(memory_size=0x80, relocation=None):
    data = bytearray(0x140 + (24 if relocation else 0))
    ident = b"\x7fELF\x02\x02\x01\x66" + bytes(8)
    struct.pack_into(">16sHHIQQQIHHHHHH", data, 0, ident, 2, 21, 1, 0, 64, 0, 0, 64, 56,
                     2 if relocation else 1, 64, 0, 0)
    struct.pack_into(">IIQQQQQQ", data, 64, 1, 7, 0x100, 0x10000, 0, 0x40, memory_size, 16)
    if relocation:
        struct.pack_into(">IIQQQQQQ", data, 120, 0x700000A4, 0, 0x140, 0, 0, 24, 24, 8)
        struct.pack_into(">QHBBIQ", data, 0x140, relocation.offset, 0, relocation.value_segment,
                         relocation.address_segment, relocation.kind, relocation.addend)
    return bytes(data)


def small_module(name="main", base=0x10000, importing=False, exporting=False):
    data = bytearray(0x300)
    data[0:4] = bytes.fromhex("4e800020")
    struct.pack_into(">II", data, 0x200, base, base + 0x280)
    segment = Segment(0, 0, base, base, 0x400, 7, 16, data)
    section = Section(".opd", 1, 2, base + 0x200, 0x200, 8, 0, 0, 8, 8)
    module = Module(name, hashlib.sha256(data).hexdigest(), 2, base + 0x200, [segment], (section,), (name,))
    if not importing and not exporting:
        return module
    module.linkage_address = base + 0x40
    struct.pack_into(">10I", data, 0x40, 40, 0x1B434CEC, 0, 0,
                     base + 0x80 if exporting else 0, base + 0xAC if exporting else 0,
                     base + 0x80 if importing else 0, base + 0xAC if importing else 0, 0, 0)
    struct.pack_into(">BBHHHHH", data, 0x80, 44, 0, 1, 0x2000 if importing else 0, 1, 1, 0)
    struct.pack_into(">III", data, 0x90, base + 0x100, base + 0x120, base + 0x140)
    data[0x100:0x105] = b"demo\0"
    struct.pack_into(">II", data, 0x120, 0x12345678, base + 0x180 if importing else 0x87654321)
    if exporting:
        struct.pack_into(">II", data, 0x140, base + 0x200, base + 0x2C0)
    else:
        struct.pack_into(">II", data, 0x9C, base + 0x130, base + 0x150)
        struct.pack_into(">I", data, 0x130, 0x87654321)
        struct.pack_into(">I", data, 0x140, base + 0x10)
        struct.pack_into(">I", data, 0x150, base + 0x1B0)
        struct.pack_into(">III", data, 0x180, 1, base + 0x2E0, 0)
        struct.pack_into(">III", data, 0x1B0, 4, base + 0x2E4, 0)
        struct.pack_into(">III", data, 0x1BC, 6, base + 0x2E6, 0)
    return module


def linked_program():
    modules = [small_module(importing=True), small_module("library", 0x20000, exporting=True)]
    bindings = link_modules(modules, [linkage_tables(module) for module in modules])
    return Program(modules, [module_facts(module) for module in modules], bindings)


def prx_bytes(empty_segment=False):
    data = bytearray(0x280)
    ident = b"\x7fELF\x02\x02\x01\x66" + bytes(8)
    count = 3 if empty_segment else 2
    struct.pack_into(">16sHHIQQQIHHHHHH", data, 0, ident, 0xFFA4, 21, 1, 0, 64, 0, 0, 64, 56, count, 64, 0, 0)
    struct.pack_into(">IIQQQQQQ", data, 64, 1, 5, 0x100, 0, 0x100, 0x80, 0x80, 16)
    if empty_segment:
        struct.pack_into(">IIQQQQQQ", data, 120, 1, 0, 0, 0, 0, 0, 0, 16)
    struct.pack_into(">IIQQQQQQ", data, 64 + (count - 1) * 56, 1, 6, 0x200, 0, 0, 0x80, 0x100, 16)
    return bytes(data)


def symbol_elf_bytes():
    data = bytearray(elf_bytes()) + bytearray(0x600 - len(elf_bytes()))
    struct.pack_into(">Q", data, 40, 0x400)
    struct.pack_into(">HH", data, 60, 7, 6)
    data[0x100:0x108] = bytes.fromhex("806200004e800020")
    struct.pack_into(">II", data, 0x120, 0x10000, 0x10030)
    strings = b"\0.entry_fn\0entry_fn\0counter\0scratch\0tlsvar\0undefined\0source.c\0absolute\0"
    data[0x300:0x300 + len(strings)] = strings
    entries = [("", 0, 0, 0, 0), (".entry_fn", 0x10000, 8, 1, 0x12),
               ("entry_fn", 0x10020, 8, 2, 0x12), ("counter", 0x10030, 4, 2, 0x21),
               ("scratch", 0x10040, 0x40, 3, 1), ("tlsvar", 8, 4, 2, 0x16),
               ("undefined", 0, 0, 0, 0x12), ("source.c", 0, 0, 0xFFF1, 4),
               ("absolute", 0x10010, 0, 0xFFF1, 0x10)]
    for index, (name, value, size, section, info) in enumerate(entries):
        struct.pack_into(">IBBHQQ", data, 0x180 + index * 24,
                         strings.index(name.encode() + b"\0") if name else 0, info, 0, section, value, size)
    names = b"\0.text\0.data\0.bss\0.symtab\0.strtab\0.shstrtab\0"
    data[0x380:0x380 + len(names)] = names
    sections = [("", 0, 0, 0, 0, 0, 0, 0),
                (".text", 1, 6, 0x10000, 0x100, 0x20, 0, 0),
                (".data", 1, 3, 0x10020, 0x120, 0x20, 0, 0),
                (".bss", 8, 3, 0x10040, 0x140, 0x40, 0, 0),
                (".symtab", 2, 0, 0, 0x180, len(entries) * 24, 5, 24),
                (".strtab", 3, 0, 0, 0x300, len(strings), 0, 0),
                (".shstrtab", 3, 0, 0, 0x380, len(names), 0, 0)]
    for index, (name, kind, flags, address, offset, size, link, width) in enumerate(sections):
        struct.pack_into(">IIQQQQIIQQ", data, 0x400 + index * 64,
                         names.index(name.encode() + b"\0") if name else 0,
                         kind, flags, address, offset, size, link, 0, 1, width)
    return bytes(data)


class Symbols(unittest.TestCase):
    def test_mapped_definitions_survive_lean_bundle(self):
        program = prepare_program([ElfImage("main", symbol_elf_bytes())])
        symbols = program.modules[0].symbols
        self.assertEqual([symbol.name for symbol in symbols], [".entry_fn", "entry_fn", "counter", "scratch"])
        self.assertEqual([symbol.address for symbol in symbols], [0x10000, 0x10020, 0x10030, 0x10040])
        self.assertEqual(symbols[2].binding, 2)
        # A named function descriptor is useful even without an entry point or .opd section.
        self.assertEqual(program.function_tocs, {0x10000: 0x10030})
        encoded = encode_bundle(program)
        restored = read_bundle(encoded).program
        self.assertEqual(restored.modules[0].symbols, symbols)
        self.assertEqual(restored.function_tocs, program.function_tocs)
        self.assertEqual(HEADER.unpack_from(encoded)[3], 0x40)
        self.assertNotIn(b"source.c", encoded)

    def test_prx_symbols_use_section_identity_when_original_addresses_overlap(self):
        data = bytearray(symbol_elf_bytes()) + bytearray(0x80)
        struct.pack_into(">H", data, 16, 0xFFA4)
        struct.pack_into(">H", data, 56, 2)
        struct.pack_into(">IIQQQQQQ", data, 64, 1, 5, 0x100, 0, 0x100, 0x40, 0x40, 16)
        struct.pack_into(">IIQQQQQQ", data, 120, 1, 6, 0x600, 0, 0, 0x40, 0x80, 16)
        data[0x100:0x134] = bytes(52)  # empty PRX module-info record
        for index, address, offset in [(1, 0, 0x100), (2, 0, 0x600), (3, 0x40, 0x640)]:
            struct.pack_into(">QQ", data, 0x400 + index * 64 + 16, address, offset)
        struct.pack_into(">I", data, 0x400 + 4 * 64 + 4, 11)  # SHT_DYNSYM is also accepted
        for index, address, kind in [(1, 0, 0x12), (2, 4, 0x11), (3, 0x10, 0x21), (4, 0x40, 1)]:
            struct.pack_into(">B", data, 0x180 + index * 24 + 4, kind)
            struct.pack_into(">Q", data, 0x180 + index * 24 + 8, address)
        program = prepare_program([ElfImage("module", bytes(data))], {"module": [0x20000, 0x30000]})
        self.assertEqual([symbol.address for symbol in program.modules[0].symbols],
                         [0x20000, 0x30004, 0x30010, 0x30040])

    def test_invalid_symbol_tables_and_definitions(self):
        mutations = [(0x400 + 4 * 64 + 56, ">Q", 16),  # wrong entry size
                     (0x400 + 4 * 64 + 40, ">I", 1),   # linked section is not strings
                     (0x180 + 24, ">I", 0xFFFFFF),      # out-of-range name
                     (0x180 + 24 + 6, ">H", 7),        # invalid section index
                     (0x180 + 24 + 8, ">Q", 0x10080),  # function outside its section
                     (0x180 + 3 * 24 + 16, ">Q", 0x40)]  # data exceeds its section
        for offset, encoding, value in mutations:
            data = bytearray(symbol_elf_bytes())
            struct.pack_into(encoding, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                prepare_program([ElfImage("invalid", bytes(data))])

    def test_zero_sized_boundary_labels_do_not_require_storage(self):
        data = bytearray(symbol_elf_bytes())
        for index, value in [(1, 0x10020), (4, 0x10080)]:
            struct.pack_into(">B", data, 0x180 + index * 24 + 4, 0x10)
            struct.pack_into(">QQ", data, 0x180 + index * 24 + 8, value, 0)
        symbols = Module.from_elf(ElfImage("main", bytes(data))).symbols
        self.assertEqual(next(symbol for symbol in symbols if symbol.name == ".entry_fn").address, 0x10020)
        self.assertFalse(any(symbol.name == "scratch" for symbol in symbols))


class ElfParsing(unittest.TestCase):
    def test_program_bytes_and_empty_section_table(self):
        image = ElfImage("main", elf_bytes())
        module = Module.from_elf(image)
        self.assertEqual(module.read(0x10000, 0x80), bytes(0x80))
        self.assertEqual(len(module.segments[0].data), 0x40)
        self.assertFalse(image.sections)

    def test_header_and_payload_bounds(self):
        for data in (b"", elf_bytes()[:63], elf_bytes()[:100], elf_bytes()[:-1]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                ElfImage("short", data)

    def test_wrong_machine_and_endianness(self):
        for position, value in ((5, 1), (18, 1)):
            data = bytearray(elf_bytes())
            data[position] = value
            with self.subTest(position=position), self.assertRaises(ValueError):
                ElfImage("wrong", data)

    def test_file_bytes_cannot_exceed_memory(self):
        with self.assertRaises(ValueError):
            ElfImage("short-memory", elf_bytes(0x20))

    def test_placement_preserves_ordinals_and_alignment(self):
        image = ElfImage("main", elf_bytes())
        for bases in ([], [0x10001], [0xFFFFFFF0]):
            with self.subTest(bases=bases), self.assertRaises(ValueError):
                Module.from_elf(image, bases)

    def test_aliases_share_one_payload(self):
        program = prepare_program([ElfImage("main", elf_bytes()), ElfImage("alias", elf_bytes())])
        self.assertEqual(len(program.modules), 1)
        self.assertEqual(program.modules[0].aliases, ("main", "alias"))

    def test_fixed_executables_cannot_be_rebased(self):
        with self.assertRaises(ValueError):
            prepare_program([ElfImage("main", elf_bytes())], {"main": [0x20000]})

    def test_prx_file_ranges_distinguish_equal_original_addresses(self):
        module = Module.from_elf(ElfImage("module", prx_bytes()), [0x10000, 0x20000])
        self.assertEqual(module.file_address(0x110, 4), 0x10010)
        self.assertEqual(module.file_address(0x210, 4), 0x20010)
        with self.assertRaises(ValueError):
            module.translate(0x10, 4)
        apply_patches(module, plan_relocations(module, [Relocation(0, 1, 0, 1, 0x10)]))
        self.assertEqual(module.read(0x10000, 4), (0x20010).to_bytes(4, "big"))

    def test_empty_loads_keep_their_relocation_ordinals(self):
        module = Module.from_elf(ElfImage("module", prx_bytes(True)), [0x10000, 0, 0x20000])
        self.assertEqual(len(module.segments), 3)
        apply_patches(module, plan_relocations(module, [Relocation(0, 2, 0, 1, 0x10)]))
        self.assertEqual(module.read(0x10000, 4), (0x20010).to_bytes(4, "big"))

    def test_automatic_prx_placement_avoids_explicit_modules(self):
        changed = bytearray(prx_bytes())
        changed[0x17F] = 1
        program = prepare_program([ElfImage("fixed", prx_bytes()), ElfImage("automatic", bytes(changed))],
                                  {"fixed": [0x20000000, 0x21000000]})
        self.assertEqual(program.modules[1].segments[0].address, 0x20001000)


class Relocations(unittest.TestCase):
    def test_record_and_absolute_base_sentinel(self):
        record = Relocation(4, 0xFF, 0, 1, 0x12345678)
        image = ElfImage("main", elf_bytes(relocation=record))
        self.assertEqual(read_relocations(image), [record])
        module = Module.from_elf(image)
        apply_patches(module, plan_relocations(module, [record]))
        self.assertEqual(module.read(0x10004, 4), bytes.fromhex("12345678"))

    def test_invalid_indices_and_full_write_bounds(self):
        for record in (Relocation(0, 1, 0, 1, 0), Relocation(0, 0, 1, 1, 0),
                       Relocation(0x7E, 0, 0, 1, 0), Relocation(0, 0, 0, 999, 0)):
            with self.subTest(record=record), self.assertRaises(ValueError):
                plan_relocations(Module.from_elf(ElfImage("main", elf_bytes())), [record])

    def test_plan_validation_is_transactional(self):
        module = Module.from_elf(ElfImage("main", elf_bytes()))
        before = bytes(module.segments[0].data)
        with self.assertRaises(ValueError):
            plan_relocations(module, [Relocation(0, 0xFF, 0, 1, 1), Relocation(0x80, 0, 0, 1, 0)])
        self.assertEqual(bytes(module.segments[0].data), before)

    def test_duplicate_writes_and_changed_preconditions(self):
        module = Module.from_elf(ElfImage("main", elf_bytes()))
        record = Relocation(0, 0xFF, 0, 1, 1)
        with self.assertRaises(ValueError):
            plan_relocations(module, [record, record])
        patches = plan_relocations(module, [record])
        module.write(0x10000, b"test")
        with self.assertRaises(ValueError):
            apply_patches(module, patches)

    def test_halfwords_carry_and_wrap(self):
        for value, high, adjusted, low in ((0x12347FFF, 0x1234, 0x1234, 0x7FFF),
                                           (0x12348000, 0x1234, 0x1235, 0x8000),
                                           (0xFFFF8000, 0xFFFF, 0, 0x8000)):
            for kind, expected in ((4, low), (5, high), (6, adjusted)):
                with self.subTest(value=value, kind=kind):
                    self.assertEqual(int.from_bytes(encode(kind, value, 0, bytes(2)), "big"), expected)

    def test_branch_fields_preserve_opcode_and_link(self):
        for kind, opcode in ((10, "48000001"), (11, "41820001")):
            self.assertEqual(encode(kind, 0x1020, 0x1000, bytes.fromhex(opcode)),
                             (int(opcode, 16) | 0x20).to_bytes(4, "big"))
            bits = 26 if kind == 10 else 16
            for delta in (1 << (bits - 1), -(1 << (bits - 1)) - 4, 2):
                with self.subTest(kind=kind, delta=delta), self.assertRaises(ValueError):
                    encode(kind, 0x4000000 + delta, 0x4000000, bytes.fromhex(opcode))

    def test_ds_and_64_bit_values(self):
        self.assertEqual(encode(57, 0x1234, 0, bytes.fromhex("0003")), bytes.fromhex("1237"))
        self.assertEqual(encode(38, 0x123456789ABCDEF0, 0, bytes(8)), bytes.fromhex("123456789abcdef0"))
        self.assertEqual(encode(44, 0x1000, 0x1008, bytes(8)), bytes.fromhex("fffffffffffffff8"))
        with self.assertRaises(ValueError):
            encode(57, 0x1235, 0, bytes(2))
        with self.assertRaises(ValueError):
            encode(1, 1 << 32, 0, bytes(4))


class Linkage(unittest.TestCase):
    def test_functions_variables_and_additional_references(self):
        program = linked_program()
        main, _ = program.modules
        self.assertEqual(len(program.bindings), 2)
        self.assertEqual(main.read(0x10140, 4), (0x20200).to_bytes(4, "big"))
        self.assertEqual(main.read(0x102E0, 4), (0x20200).to_bytes(4, "big"))
        self.assertEqual(main.read(0x102E4, 4), bytes.fromhex("02c00002"))
        function = next(binding for binding in program.bindings if binding.kind == "function")
        self.assertEqual(function.descriptor.code, 0x20000)
        self.assertEqual(function.descriptor.toc, 0x20280)

    def test_unresolved_slots_retain_original_stub_values(self):
        module = small_module(importing=True)
        bindings = link_modules([module], [linkage_tables(module)])
        self.assertTrue(all(binding.target is None for binding in bindings))
        self.assertEqual(module.read(0x10140, 4), (0x10010).to_bytes(4, "big"))

    def test_ambiguous_exports_do_not_change_imports(self):
        modules = [small_module(importing=True), small_module("one", 0x20000, exporting=True),
                   small_module("two", 0x30000, exporting=True)]
        before = bytes(modules[0].segments[0].data)
        with self.assertRaises(ValueError):
            link_modules(modules, [linkage_tables(module) for module in modules])
        self.assertEqual(bytes(modules[0].segments[0].data), before)

    def test_invalid_reference_does_not_partially_link(self):
        modules = [small_module(importing=True), small_module("library", 0x20000, exporting=True)]
        modules[0].write(0x101B0, (999).to_bytes(4, "big"))
        before = bytes(modules[0].segments[0].data)
        with self.assertRaises(ValueError):
            link_modules(modules, [linkage_tables(module) for module in modules])
        self.assertEqual(bytes(modules[0].segments[0].data), before)

    def test_shared_code_with_two_tocs_stays_ambiguous(self):
        module = small_module()
        module.sections = (replace(module.sections[0], size=16),)
        module.write(0x10208, struct.pack(">II", 0x10000, 0x10290))
        facts = module_facts(module)
        program = Program([module], [facts], [])
        self.assertEqual(len(facts.descriptors), 2)
        self.assertNotIn(0x10000, program.function_tocs)

    def test_nonexecutable_descriptor_is_rejected(self):
        module = small_module()
        module.segments[0].flags = 6
        with self.assertRaises(ValueError):
            descriptor(module, 0x10200)


class Bundles(unittest.TestCase):
    def test_linked_snapshot_roundtrip(self):
        original = linked_program()
        bundle = read_bundle(encode_bundle(original))
        self.assertEqual(bundle.program.entry_code, original.entry_code)
        self.assertEqual(bundle.program.function_tocs, original.function_tocs)
        self.assertEqual(bundle.program.bindings, original.bindings)
        for before, after in zip(original.modules, bundle.program.modules):
            self.assertEqual(before.segments[0].data, after.segments[0].data)

    def test_large_bss_with_a_fixup_stays_sparse(self):
        image = ElfImage("main", elf_bytes(memory_size=0x40000000))
        module = Module.from_elf(image)
        apply_patches(module, plan_relocations(module, [Relocation(0x10000000, 0xFF, 0, 1, 0xBAADF00D)]))
        program = Program([module], [module_facts(module)], [], 1)
        encoded = encode_bundle(program)
        self.assertLess(len(encoded), 2048)
        bundle = read_bundle(encoded)
        restored = bundle.program.modules[0]
        self.assertEqual(restored.read(0x10010000, 4), bytes.fromhex("baadf00d"))
        self.assertEqual(restored.read(0x10010004, 8), bytes(8))
        self.assertEqual(len(restored.segments[0].data), 64)
        self.assertEqual(sum(mapping.size for mapping in bundle.mappings), 0x40000000)
        self.assertEqual(sum(mapping.file_size for mapping in bundle.mappings), 68)

    def test_corrupt_and_truncated_payloads(self):
        original = encode_bundle(linked_program())
        for data in (original[:10], original[:-1], original + b"extra", original[:-1] + b"\xff"):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                read_bundle(data)

    def test_database_edits_revoke_stale_snapshot_bindings(self):
        encoded = bytearray(encode_bundle(linked_program()))
        data_start = read_bundle(encoded).mappings[0].file_offset
        encoded[data_start + 0x140:data_start + 0x144] = bytes(4)
        with self.assertRaises(ValueError):
            read_bundle(encoded)
        modified = read_bundle(encoded, allow_modified=True).program
        function = next(binding for binding in modified.bindings if binding.kind == "function")
        self.assertIsNone(function.target)
        self.assertEqual(function.original_value, 0)
        self.assertIsNotNone(next(binding for binding in modified.bindings if binding.kind == "variable").target)
        self.assertEqual(read_bundle(encode_bundle(modified)).program.bindings, modified.bindings)

    def test_invalid_edited_descriptor_does_not_supply_an_entry_context(self):
        encoded = bytearray(encode_bundle(linked_program()))
        data_start = read_bundle(encoded).mappings[0].file_offset
        encoded[data_start + 0x200:data_start + 0x204] = (3).to_bytes(4, "big")
        modified = read_bundle(encoded, allow_modified=True).program
        self.assertEqual(modified.entry_code, 0)
        self.assertNotIn(0x10000, modified.function_tocs)

    def test_manifest_ranges_and_bindings_are_validated(self):
        original = encode_bundle(linked_program())
        _, _, metadata_size, _ = HEADER.unpack_from(original)
        metadata = json.loads(original[HEADER.size:HEADER.size + metadata_size])
        payload = original[HEADER.size + metadata_size:]
        mutations = [lambda item: item["modules"][0]["segments"][0].update(address=0xFFFFFFFF),
                     lambda item: item["modules"][0]["segments"][0]["chunks"][0].update(offset=1),
                     lambda item: item["bindings"][0].update(target=0x20204),
                     lambda item: item["modules"][0].update(source_sha256="bad")]
        for mutate in mutations:
            altered = json.loads(json.dumps(metadata))
            mutate(altered)
            encoded = json.dumps(altered).encode()
            with self.assertRaises(ValueError):
                read_bundle(HEADER.pack(MAGIC, VERSION, len(encoded), len(payload)) + encoded + payload)


def spu_elf_bytes(writable=True):
    data = bytearray(0x250)
    code = bytes.fromhex("40ffff83420000841801018321a00e8330804005208042053500000040200000")
    names = b"\0.text\0.data\0.shstrtab\0.strtab\0.symtab\0"
    strings = b"\0entry\0value\0"
    struct.pack_into(">16sHHIIIIIHHHHHH", data, 0, b"\x7fELF\x01\x02\x01" + bytes(9),
                     2, 23, 1, 0x100, 52, 0x160, 0, 52, 32, 2, 40, 6, 3)
    struct.pack_into(">IIIIIIII", data, 52, 1, 0x80, 0x100, 0, len(code), len(code), 5, 16)
    struct.pack_into(">IIIIIIII", data, 84, 1, 0xA0, 0x200, 0, 16, 32, 6 if writable else 4, 16)
    data[0x80:0xA0] = code
    data[0xA0:0xB0] = bytes.fromhex("123456789abcdef0fedcba9876543210")
    struct.pack_into(">IIIBBH", data, 0xD0, 1, 0x100, len(code), 0x12, 0, 1)
    struct.pack_into(">IIIBBH", data, 0xE0, 7, 0x200, 16, 0x11, 0, 2)
    data[0x100:0x100 + len(strings)] = strings
    data[0x120:0x120 + len(names)] = names
    for index, values in enumerate([
            (1, 1, 6, 0x100, 0x80, len(code), 0, 0, 4, 0),
            (7, 1, 3 if writable else 2, 0x200, 0xA0, 16, 0, 0, 16, 0),
            (13, 3, 0, 0, 0x120, len(names), 0, 0, 1, 0),
            (23, 3, 0, 0, 0x100, len(strings), 0, 0, 1, 0),
            (31, 2, 0, 0, 0xC0, 48, 4, 1, 4, 16)], 1):
        struct.pack_into(">10I", data, 0x160 + 40 * index, *values)
    return bytes(data)


def spu_stack_elf_bytes():
    """A caller passing a quadword stack slot to a separate SPU function."""
    data = bytearray(0x210)
    struct.pack_into(">16sHHIIIIIHHHHHH", data, 0, b"\x7fELF\x01\x02\x01" + bytes(9),
                     2, 23, 1, 0x100, 52, 0, 0, 52, 32, 3, 0, 0, 0)
    for index, segment in enumerate([
            (1, 0x100, 0x100, 0, 0x80, 0x80, 5, 16),
            (1, 0x200, 0x200, 0, 16, 16, 4, 16),
            (1, 0x210, 0x210, 0, 0, 16, 6, 16)]):
        struct.pack_into(">8I", data, 52 + 32 * index, *segment)
    # Save LR and back chain, allocate 64 bytes, load/spill the final argument,
    # call, store the result, restore SP/LR and return.
    caller = [0x24004080, 0x24FF0081, 0x1CF00081, 0x3080404B, 0x240080CB,
              0x33000580, 0x20804203, 0x1C100081, 0x34004080, 0x35000000]
    struct.pack_into(">10I", data, 0x100, *caller)
    struct.pack_into(">2I", data, 0x140, 0x34008083, 0x35000000) # lqd r3,32(sp); bi lr.
    data[0x200:0x210] = bytes.fromhex("123456789abcdef0fedcba9876543210")
    return bytes(data)


class SpuParsing(unittest.TestCase):
    def test_independent_local_store_bounds(self):
        data = bytearray(0x84)
        ident = b"\x7fELF\x01\x02\x01" + bytes(9)
        struct.pack_into(">16sHHIIIIIHHHHHH", data, 0, ident, 2, 23, 1, 0x100, 52, 0, 0, 52, 32, 1, 40, 0, 0)
        struct.pack_into(">IIIIIIII", data, 52, 1, 0x80, 0x100, 0, 4, 0x100, 5, 16)
        image = parse_spu(data, address=0x50000)
        self.assertEqual(image.address, 0x50000)
        self.assertEqual(image.entry, 0x100)
        struct.pack_into(">I", data, 52 + 20, 0x40000)
        with self.assertRaises(ValueError):
            parse_spu(data)


if __name__ == "__main__":
    unittest.main()
