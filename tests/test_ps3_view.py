"""Integration checks for an installation with gameroms and binja-ps3-platform."""

from pathlib import Path
from dataclasses import replace
from itertools import product
import struct
import tempfile
import unittest

try:
    import binaryninja as bn
except ImportError:
    bn = None

from gameroms.formats.ps3.bundle import encode_bundle, read_bundle
from gameroms.formats.ps3.elf import ElfImage
from gameroms.formats.ps3.inputs import prepare_input
from gameroms.formats.ps3.prepare import Program, module_facts, prepare_program
from gameroms.formats.ps3.reloc import Relocation
from test_ps3 import elf_bytes, linked_program, small_module, spu_elf_bytes, spu_stack_elf_bytes, symbol_elf_bytes


@unittest.skipIf(bn is None, "requires Binary Ninja")
class Ps3ViewIntegration(unittest.TestCase):
    def setUp(self):
        self.assertFalse(bn.Settings().get_bool("analysis.suppressNewAutoFunctionAnalysis"),
                         "Integration checks require analysis of newly discovered functions.")

    def open_snapshot(self, data):
        view = bn.BinaryViewType["PS3 PS3EXE"].create(bn.BinaryView.new(data))
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        return view

    def check_spu_words(self, view, address, register, expected):
        function = view.get_function_at(0x100)
        for lane, bits in enumerate(expected):
            info = view.arch.regs[f"r{register}.w{lane}"]
            storage = view.arch.get_reg_index(info.full_width_reg)
            assignments = [item for item in function.mlil.instructions
                if isinstance(item, bn.mediumlevelil.MediumLevelILSetVar)
                and item.address == address and item.size == 4
                and item.dest.source_type == bn.VariableSourceType.RegisterVariableSourceType
                and item.dest.storage == storage]
            self.assertEqual(len(assignments), 1)
            value = assignments[0].src.value
            self.assertEqual(value.type, bn.RegisterValueType.ConstantValue)
            self.assertEqual(value.value & 0xFFFFFFFF, bits)
            self.assertIsNotNone(assignments[0].low_level_il)
            self.assertEqual(assignments[0].low_level_il.address, address)
        self.assertIsNotNone(function.hlil)

    def check_spu_constant_memory(self, view, function, start, expected):
        actual = {}
        # The core may combine adjacent constant stores into a builtin copy.
        for item in function.mlil.instructions:
            if isinstance(item, bn.mediumlevelil.MediumLevelILStore):
                self.assertEqual(item.src.value.type, bn.RegisterValueType.ConstantValue)
                address = item.dest.value.value
                payload = (item.src.value.value & ((1 << (8 * item.size)) - 1)).to_bytes(item.size, "big")
            elif isinstance(item, bn.mediumlevelil.MediumLevelILCall):
                self.assertEqual(view.get_symbol_at(item.dest.value.value).raw_name, "__builtin_memcpy")
                self.assertEqual(len(item.params), 3)
                self.assertIsInstance(item.params[1], bn.mediumlevelil.MediumLevelILConstData)
                address = item.params[0].value.value
                payload = bytes(item.params[1].constant_data.data)
                self.assertEqual(len(payload), item.params[2].value.value)
            else:
                continue
            actual.update((address + offset, value) for offset, value in enumerate(payload))
        self.assertEqual(set(actual), set(range(start, start + len(expected))))
        self.assertEqual(bytes(actual[start + offset] for offset in range(len(expected))), expected)

    def test_spu_mapping_scalar_analysis_and_vector_memory(self):
        # Read-only constants may be folded; writable local-store data remains mutable.
        source = bytearray(spu_elf_bytes(writable=False))
        source[0x8C:0x90] = bytes.fromhex("40200000")  # nop before the constant load.
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        self.assertEqual((view.arch.name, view.platform.name, view.entry_point), ("ps3-spu", "ps3-spu", 0x100))
        self.assertEqual(view.read(0x210, 16), bytes(16))
        self.assertEqual(view.get_symbol_at(0x100).name, "entry")
        self.assertEqual(view.get_symbol_at(0x200).name, "value")
        function = view.create_user_function(0x100)
        view.update_analysis_and_wait()
        self.assertEqual(function.get_reg_value_after(0x108, "r3.w0").value, 0)
        for lane, expected in enumerate([0x12345678, 0x9abcdef0, 0xfedcba98, 0x76543210]):
            register = f"r5.w{lane}"
            value = function.get_reg_value_after(0x110, register)
            self.assertEqual(value.type, bn.RegisterValueType.ConstantValue, (register, value))
            self.assertEqual(value.value & 0xFFFFFFFF, expected)
        calls = [item for item in function.mlil.instructions if isinstance(item, bn.mediumlevelil.MediumLevelILIntrinsic)]
        self.assertEqual(len(calls), 0)
        stores = [item for item in function.mlil.instructions if isinstance(item, bn.mediumlevelil.MediumLevelILStore)]
        self.assertEqual([(item.size, item.dest.value.value) for item in stores],
                         [(4, 0x210 + 4 * lane) for lane in range(4)])
        self.assertIsNotNone(function.hlil)

    def test_spu_load_preserves_the_original_aliased_address(self):
        source = bytearray(spu_elf_bytes(writable=False))
        # ila r3,0x208; lqd r3,0(r3); bi r0. The load aligns down to 0x200.
        source[0x80:0x8C] = bytes.fromhex("420104033400018335000000")
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        function = view.create_user_function(0x100)
        view.update_analysis_and_wait()
        for lane, expected in enumerate([0x12345678, 0x9abcdef0, 0xfedcba98, 0x76543210]):
            name = f"r3.w{lane}"
            value = function.get_reg_value_after(0x104, name)
            self.assertEqual(value.type, bn.RegisterValueType.ConstantValue)
            self.assertEqual(value.value & 0xFFFFFFFF, expected)

    def test_spu_scalar_calls_recover_loaded_arguments_after_reopen_and_reanalysis(self):
        source = bytearray(spu_elf_bytes(writable=False))
        # lqa r3,0x200; brsl r0,0x118; bi r0. Callee: ai r3,r3,1; bi r0.
        source[0x80:0x8C] = bytes.fromhex("308040033300028035000000")
        source[0x98:0xA0] = bytes.fromhex("1c00418335000000")
        for width, expected in [(1, 0x78), (2, 0x5678), (4, 0x12345678)]:
            with self.subTest(width=width), tempfile.TemporaryDirectory() as folder:
                view = bn.load(source, update_analysis=False)
                self.assertIsNotNone(view)
                try:
                    caller = view.create_user_function(0x100)
                    callee = view.create_user_function(0x118)
                    scalar = bn.Type.int(width, False)
                    callee.set_user_type(bn.Type.function(scalar, [bn.FunctionParameter(scalar, "value")],
                        calling_convention=view.platform.default_calling_convention))
                    caller.reanalyze()
                    view.update_analysis_and_wait()
                    view.set_comment_at(0x118, "Increment the preferred scalar argument.")

                    def check(current):
                        calls = [item for item in current.get_function_at(0x100).mlil.instructions
                                 if isinstance(item, bn.mediumlevelil.MediumLevelILCall)]
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(len(calls[0].params), 1)
                        argument = calls[0].params[0]
                        self.assertEqual(argument.size, width)
                        self.assertEqual(argument.value.type, bn.RegisterValueType.ConstantValue)
                        self.assertEqual(argument.value.value, expected)
                        self.assertEqual(current.get_comment_at(0x118), "Increment the preferred scalar argument.")
                        self.assertIsNotNone(current.get_function_at(0x118).hlil)

                    check(view)
                    path = Path(folder) / "scalar.bndb"
                    self.assertTrue(view.create_database(str(path)))
                    reopened = bn.load(str(path), update_analysis=False)
                    self.assertIsNotNone(reopened)
                    try:
                        check(reopened)
                        reopened.reanalyze()
                        reopened.update_analysis_and_wait()
                        check(reopened)
                    finally:
                        reopened.file.close()
                finally:
                    view.file.close()

    def test_spu_stack_information_remains_implicit_after_edits_and_reopen(self):
        source = bytearray(spu_stack_elf_bytes())
        # Save LR/SP and R2, allocate a frame, then store every argument word.
        source[0x100:0x120] = bytes.fromhex(
            "24004080040000851cf000812400008524008082208050031c10008135000000")
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        function = view.create_user_function(0x100)
        view.update_analysis_and_wait()
        view.set_comment_at(0x100, "Preserve stack information independently of arguments.")

        def check(current, address):
            function = current.get_function_at(0x100)
            self.assertFalse(function.analysis_skipped)
            expected = {current.arch.get_reg_index(f"r3.w{word}") for word in range(4)}
            self.assertEqual({p.storage for p in function.parameter_vars}, expected)
            for word in range(1, 4):
                self.assertEqual(function.get_reg_value_at(0x100, f"r1.w{word}").type,
                                 bn.RegisterValueType.EntryValue)
            for word in range(4):
                self.assertEqual(function.get_reg_value_at(0x100, f"r2.w{word}").type,
                                 bn.RegisterValueType.EntryValue)
            stores = [item for item in function.mlil.instructions
                      if item.address == 0x114 and isinstance(item, bn.mediumlevelil.MediumLevelILStore)]
            self.assertEqual(len(stores), 4)
            self.assertEqual({item.src.src.storage for item in stores}, expected)
            self.assertEqual([item.dest.value.value for item in stores],
                             [address + 4 * word for word in range(4)])
            self.assertIsNotNone(function.hlil)
            self.assertEqual(current.get_comment_at(0x100),
                             "Preserve stack information independently of arguments.")

        check(view, 0x280)
        self.assertEqual(view.write(0x114, bytes.fromhex("20805203")), 4)  # stqa r3,0x290.
        function.reanalyze()
        view.update_analysis_and_wait()
        check(view, 0x290)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "stack-state.bndb"
            self.assertTrue(view.create_database(str(path)))
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                check(reopened, 0x290)
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                check(reopened, 0x290)
            finally:
                reopened.file.close()

    def test_spu_multiply_words_recompute_after_data_edits_and_database_reopen(self):
        # MPY/MPYU/MPYH/MPYS/MPYHH/MPYHHU, immediate -1, MPYA and both high accumulates.
        cases = [
            (0x78810303, [0xfffffffe, 0x00008000, 0xc0008000, 0xffffa988], 0x00000004),
            (0x79810303, [0x0001fffe, 0x7fff8000, 0x3fff8000, 0x5677a988], 0x00000004),
            (0x78a10303, [0x00000000, 0x80010000, 0x80000000, 0xedcc0000], 0x00000000),
            (0x78e10303, [0xffffffff, 0x00000000, 0xffffc000, 0xffffffff], 0x00000000),
            (0x78c10303, [0x00008000, 0xc0008000, 0xffffffff, 0xfa034fa4], 0x00008000),
            (0x79c10303, [0x7fff8000, 0x3fff8000, 0x0000ffff, 0x0c374fa4], 0x7fff8000),
            (0x74ffc303, [0x00000001, 0x00008000, 0xffff8001, 0xffffa988], 0xfffffffe),
            (0x75ffc303, [0xfffe0001, 0x7fff8000, 0x7ffe8001, 0x5677a988], 0x0001fffe),
            (0xc0610303, [0xfffffffd, 0x80007fff, 0xc0007fff, 0xfeffa988], 0x00000003),
            (0x68c10303, [0x00007fff, 0x40007fff, 0xfffffffe, 0xf9034fa4], 0x00007fff),
            (0x69c10303, [0x7fff7fff, 0xbfff7fff, 0x0000fffe, 0x0b374fa4], 0x7fff7fff),
        ]
        source = bytearray(spu_stack_elf_bytes())
        source.extend(bytes(0x230 - len(source)))
        struct.pack_into(">8I", source, 52, 1, 0x100, 0x100, 0, 0x100, 0x100, 5, 16)
        struct.pack_into(">8I", source, 84, 1, 0x200, 0x200, 0, 48, 48, 4, 16)
        struct.pack_into(">8I", source, 116, 1, 0x230, 0x300, 0, 0, 16 * len(cases), 6, 16)
        code = []
        for index, (operation, _, _) in enumerate(cases):
            # Load RA, RB and the accumulator separately; overwrite the accumulator.
            code.extend([0x30804006, 0x30804204, 0x30804403, operation,
                         0x20800003 | ((0x300 + 16 * index) >> 2) << 7])
        code.append(0x35000000)
        source[0x100:0x200] = bytes(0x100)
        struct.pack_into(f">{len(code)}I", source, 0x100, *code)
        struct.pack_into(">12I", source, 0x200,
            0x8000ffff, 0x7fff8000, 0xffff7fff, 0x12345678,
            0xffff0002, 0x8000ffff, 0x00018000, 0xabcdffff,
            0xffffffff, 0x7fffffff, 0xffffffff, 0xff000000)
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        function = view.create_user_function(0x100)
        view.update_analysis_and_wait()
        view.set_comment_at(0x100, "Packed integer products and wrapping accumulators.")

        def check(current, edited):
            function = current.get_function_at(0x100)
            self.assertFalse(function.analysis_skipped)
            self.assertEqual(bn.Settings().get_string("analysis.workflows.functionWorkflow", current),
                             "ps3.spu.function")
            words = [word for _, expected, first in cases
                     for word in ([first, *expected[1:]] if edited else expected)]
            expected = struct.pack(f">{len(words)}I", *words)
            self.check_spu_constant_memory(current, function, 0x300, expected)
            self.assertIsNotNone(function.hlil)
            self.assertEqual(current.get_comment_at(0x100),
                             "Packed integer products and wrapping accumulators.")

        check(view, False)
        self.assertEqual(view.write(0x200, bytes.fromhex("80000002")), 4)
        function.reanalyze()
        view.update_analysis_and_wait()
        check(view, True)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "multiply.bndb"
            self.assertTrue(view.create_database(str(path)))
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                check(reopened, True)
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                check(reopened, True)
            finally:
                reopened.file.close()

    def test_spu_extensions_and_carry_chains_recompute_after_edits_and_reopen(self):
        extensions = [
            (0x2b6, [0x0034007f, 0x0078ff80, 0xffbcffff, 0],
                    [0x0034007f, 0x0000ff80, 0xffbcffff, 0]),
            (0x2ae, [0xffff807f, 0x00007f80, 0xffffffff, 0xffff8000],
                    [0xffff807f, 0x00000080, 0xffffffff, 0xffff8000]),
            (0x2a6, [0, 0x56787f80, 0, 0x00008000],
                    [0xffffffff, 0x80000080, 0, 0x00008000]),
        ]
        carries = [
            (0xc2, [1, 0, 0, 1], [1, 0, 0, 1]),
            (0x342, [1, 1, 0, 1], [1, 0, 1, 1]),
            (0x340, [0, 0, 0xffffffff, 0xffffffff], [1, 0xffffffff, 0, 0xfffffffe]),
            (0x42, [0, 1, 1, 1], [0, 1, 1, 1]),
            (0x343, [0, 1, 1, 1], [0, 1, 1, 0]),
            (0x341, [1, 1, 0xfffffffe, 0], [2, 0, 0xffffffff, 0xffffffff]),
        ]
        code = []
        for index, (operation, _, _) in enumerate(extensions):
            code.extend([0x30804a03, operation << 21 | 3 << 7 | 3,
                         0x20806003 | index << 9])
        for index, (operation, _, _) in enumerate(carries, len(extensions)):
            code.extend([0x30804003, 0x30804204, 0x30804405,
                         operation << 21 | 4 << 14 | 3 << 7 | 5,
                         0x20806005 | index << 9])
        for subtract in (False, True):
            code.extend([0x30804003, 0x30804204, 0x30804606, 0x30804807,
                         (0x42 if subtract else 0xc2) << 21 | 4 << 14 | 3 << 7 | 5,
                         0x1ff << 21 | 4 << 14 | 5 << 7 | 5,
                         0xc1 << 21 | 6 << 14 | 5 << 7 | 5])
            if subtract:
                code.append(0x41 << 21 | 7 << 14 | 5 << 7 | 5)
            code.extend([(0x341 if subtract else 0x340) << 21 | 4 << 14 | 3 << 7 | 5,
                         0x20806005 | (10 if subtract else 9) << 9])
        code.append(0x35000000)
        source = bytearray(spu_stack_elf_bytes())
        source.extend(bytes(0x260 - len(source)))
        struct.pack_into(">8I", source, 52, 1, 0x100, 0x100, 0, 0x100, 0x100, 5, 16)
        struct.pack_into(">8I", source, 84, 1, 0x200, 0x200, 0, 96, 96, 4, 16)
        struct.pack_into(">8I", source, 116, 1, 0x260, 0x300, 0, 0, 176, 6, 16)
        source[0x100:0x200] = bytes(0x100)
        struct.pack_into(f">{len(code)}I", source, 0x100, *code)
        struct.pack_into(">24I", source, 0x200,
            0xffffffff, 0x7fffffff, 0, 0xffffffff,
            1, 0x80000000, 0xffffffff, 0xffffffff,
            0, 1, 0x80000000, 0xffffffff,
            1, 0, 1, 0, 0, 1, 0, 1,
            0x1234807f, 0x56787f80, 0x9abcffff, 0x00008000)
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        function = view.create_user_function(0x100)
        view.update_analysis_and_wait()
        view.set_comment_at(0x100, "Sign extension and doubleword carry chains.")

        def check(current, edited):
            function = current.get_function_at(0x100)
            self.assertFalse(function.analysis_skipped)
            words = [word for _, before, after in extensions + carries
                     for word in (after if edited else before)]
            words.extend([0, 0xffffffff, 0, 0xfffffffe, 2, 1, 0xffffffff, 0])
            self.check_spu_constant_memory(current, function, 0x300, struct.pack(">44I", *words))
            self.assertIsNotNone(function.hlil)
            self.assertEqual(current.get_comment_at(0x100), "Sign extension and doubleword carry chains.")

        check(view, False)
        self.assertEqual(view.write(0x220, struct.pack(">4I", 1, 0, 0xffffffff, 0xfffffffe)), 16)
        self.assertEqual(view.write(0x254, bytes.fromhex("80000080")), 4)
        function.reanalyze()
        view.update_analysis_and_wait()
        check(view, True)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "integer.bndb"
            self.assertTrue(view.create_database(str(path)))
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                check(reopened, True)
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                check(reopened, True)
            finally:
                reopened.file.close()

    def test_spu_counts_and_masks_recompute_after_edits_and_database_reopen(self):
        operations = [0x2a5, 0x2b4, 0x1b0, 0x1b1, 0x1b2, 0x1b4, 0x1b5, 0x1b6, 0x1f0]
        source = bytearray(spu_stack_elf_bytes())
        struct.pack_into(">8I", source, 84, 1, 0x200, 0x200, 0, 16, 16, 4, 16)
        struct.pack_into(">8I", source, 116, 1, 0x210, 0x300, 0, 0, 16 * len(operations), 6, 16)
        code = []
        for index, operation in enumerate(operations):
            code.extend([0x30804003, operation << 21 | 3 << 7 | 3,
                         0x20800003 | ((0x300 + 16 * index) // 4) << 7])
        code.append(0x35000000)
        struct.pack_into(">28I", source, 0x100, *code)
        struct.pack_into(">4I", source, 0x200, 0x00015a69, 0x80000000, 0x01020304, 0xffffffff)
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        function = view.create_user_function(0x100)
        view.update_analysis_and_wait()
        view.set_comment_at(0x100, "Count, gather and form masks in architectural byte order.")

        def check(current, edited):
            function = current.get_function_at(0x100)
            results = [
                [0, 0, 7, 0] if edited else [15, 0, 7, 0],
                [0x01000404 if edited else 0x00010404, 0x01000000, 0x01010201, 0x08080808],
                [1 if edited else 9, 0, 0, 0],
                [3 if edited else 0xc3, 0, 0, 0],
                [0x20af if edited else 0x50af, 0, 0, 0],
                [0, 0xffffffff, 0xffffffff, 0] if edited else [0xffffffff, 0, 0, 0xffffffff],
                [0xffff0000, 0x0000ffff, 0x0000ffff, 0xffff0000] if edited else
                    [0x0000ffff, 0xffff0000, 0xffff0000, 0x0000ffff],
                [0xff00ff00, 0x00ff00ff, 0xff0000ff, 0x00ffff00] if edited else
                    [0x00ff00ff, 0xff00ff00, 0x00ffff00, 0xff0000ff],
                [0xffffffff, 0, 0, 0],
            ]
            expected = b"".join(struct.pack(">4I", *result) for result in results)
            self.check_spu_constant_memory(current, function, 0x300, expected)
            self.assertFalse(any(item.operation == bn.LowLevelILOperation.LLIL_UNIMPL
                                 for item in function.lifted_il.instructions))
            self.assertIsNotNone(function.hlil)
            self.assertEqual(current.get_comment_at(0x100),
                             "Count, gather and form masks in architectural byte order.")

        check(view, False)
        self.assertEqual(view.write(0x200, bytes.fromhex("8000a596")), 4)
        function.reanalyze()
        view.update_analysis_and_wait()
        check(view, True)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "counts.bndb"
            self.assertTrue(view.create_database(str(path)))
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                check(reopened, True)
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                check(reopened, True)
            finally:
                reopened.file.close()

    def test_spu_shuffle_chains_and_special_selectors_survive_edits_and_reopen(self):
        source = bytearray(spu_stack_elf_bytes())
        source.extend(bytes(0x260 - len(source)))
        struct.pack_into(">8I", source, 84, 1, 0x200, 0x200, 0, 96, 96, 4, 16)
        struct.pack_into(">8I", source, 116, 1, 0x260, 0x300, 0, 0, 32, 6, 16)
        code = [0x30804003, 0x30804204, 0x30804405, 0xb0c10185,
                0x30804603, 0x30804804, 0xb0610186, 0x20806003,
                0x30804603, 0x30804804, 0x30804a05, 0xb0a10185, 0x20806205, 0x35000000]
        source[0x100:0x180] = bytes(0x80)
        struct.pack_into(">14I", source, 0x100, *code)
        source[0x200:0x260] = (bytes(range(32)) + bytes(range(31, 15, -1)) +
            bytes(range(0x40, 0x50)) + bytes(range(0xc0, 0xd0)) +
            bytes.fromhex("80bfc0dfe0ff7f6003201f1055aacdef"))
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        function = view.create_user_function(0x100)
        view.update_analysis_and_wait()
        view.set_comment_at(0x100, "Dependent shuffle selectors and constant byte classes.")

        def check(current, edited):
            function = current.get_function_at(0x100)
            self.assertFalse(bn.Settings().get_bool("analysis.outlining.builtins", current))
            raw = [i for i in function.lifted_il.instructions if isinstance(i, bn.lowlevelil.LowLevelILIntrinsic)]
            self.assertEqual([i.address for i in raw], [0x10c, 0x118, 0x12c])
            self.assertFalse(any(isinstance(i, bn.lowlevelil.LowLevelILIntrinsic) for i in function.llil.instructions))
            expected = bytearray(bytes(range(0xcf, 0xbf, -1)) + bytes.fromhex("0000ffff8080cf404340cfc0c500ff80"))
            if edited:
                expected[:4] = bytes(range(0x40, 0x44))
                expected[16:20] = bytes.fromhex("80ff0047")
            self.check_spu_constant_memory(current, function, 0x300, bytes(expected))
            self.assertEqual(current.get_comment_at(0x100), "Dependent shuffle selectors and constant byte classes.")
            self.assertIsNotNone(function.hlil)

        check(view, False)
        self.assertEqual(view.write(0x220, bytes.fromhex("00010203")), 4)
        self.assertEqual(view.write(0x250, bytes.fromhex("e0c08007")), 4)
        function.reanalyze()
        view.update_analysis_and_wait()
        check(view, True)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "shuffle.bndb"
            self.assertTrue(view.create_database(str(path)))
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                check(reopened, True)
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                check(reopened, True)
            finally:
                reopened.file.close()

    def test_spu_typed_shuffle_calls_preserve_unknown_words_after_edits_and_reopen(self):
        source = bytearray(spu_stack_elf_bytes())
        source.extend(bytes(0x230 - len(source)))
        struct.pack_into(">8I", source, 84, 1, 0x200, 0x200, 0, 48, 48, 4, 16)
        struct.pack_into(">8I", source, 116, 1, 0x230, 0x230, 0, 0, 16, 6, 16)
        code = [0x24004080, 0x24ff0081, 0x1cf00081, 0x30804003, 0x30804204,
                0x33000580, 0x20804603, 0x1c100081, 0x34004080, 0x35000000]
        source[0x100:0x180] = bytes(0x80)
        struct.pack_into(">10I", source, 0x100, *code)
        struct.pack_into(">3I", source, 0x140, 0x30804405, 0xb0610185, 0x35000000)
        source[0x200:0x230] = bytes(range(32)) + bytes.fromhex("18191a1b0c0d0e0f1011121300010203")
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        vector = bn.Type.named_type_from_registered_type(view, "ps3_v128")
        caller = view.create_user_function(0x100)
        callee = view.create_user_function(0x140)
        callee.set_user_type(bn.Type.function(vector,
            [bn.FunctionParameter(vector, "left"), bn.FunctionParameter(vector, "right")],
            calling_convention=view.platform.default_calling_convention))
        caller.reanalyze()
        view.update_analysis_and_wait()
        view.set_comment_at(0x140, "Select words from two vector arguments.")

        def check(current, edited):
            caller = current.get_function_at(0x100)
            callee = current.get_function_at(0x140)
            self.assertFalse(caller.analysis_skipped or callee.analysis_skipped)
            calls = [i for i in caller.mlil.instructions if isinstance(i, bn.mediumlevelil.MediumLevelILCall)]
            self.assertEqual(len(calls), 1)
            self.assertEqual([p.expr_type.width for p in calls[0].params], [16, 16])
            sources = ([(3, 2), (4, 3), (3, 1), (4, 1)] if edited
                       else [(4, 2), (3, 3), (4, 0), (3, 0)])
            for word, (reg, lane) in enumerate(sources):
                before = callee.get_reg_value_at(0x140, f"r{reg}.w{lane}")
                after = callee.get_reg_value_after(0x144, f"r3.w{word}")
                self.assertEqual(before.type, bn.RegisterValueType.EntryValue)
                self.assertEqual((after.type, after.value), (before.type, before.value))
            self.assertFalse(any(isinstance(i, bn.lowlevelil.LowLevelILIntrinsic) for i in callee.llil.instructions))
            returns = [i for i in callee.hlil.instructions if isinstance(i, bn.highlevelil.HighLevelILRet)]
            self.assertEqual(len(returns), 1)
            self.assertEqual(returns[0].src[0].size, 16)
            self.assertEqual(current.get_comment_at(0x140), "Select words from two vector arguments.")

        check(view, False)
        self.assertEqual(view.write(0x220, bytes.fromhex("08090a0b1c1d1e1f0405060714151617")), 16)
        callee.reanalyze()
        caller.reanalyze()
        view.update_analysis_and_wait()
        check(view, True)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "shuffle-call.bndb"
            self.assertTrue(view.create_database(str(path)))
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                check(reopened, True)
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                check(reopened, True)
            finally:
                reopened.file.close()

    def test_spu_vector_calls_preserve_all_words_after_edits_and_database_reopen(self):
        source = bytearray(spu_elf_bytes(writable=False))
        # lqa r3,0x200; brsl r0,0x118; stqa r3,0x210; bi r0.
        # Callee: ai r3,r3,1; bi r0.
        source[0x80:0x90] = bytes.fromhex("30804003330002802080420335000000")
        source[0x98:0xA0] = bytes.fromhex("1c00418335000000")
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        self.assertIsNotNone(view.get_type_by_id("ps3.v128"))
        vector = bn.Type.named_type_from_registered_type(view, "ps3_v128")
        view.define_user_type("VectorAlias", vector)
        signature, _ = view.parse_type_string("VectorAlias increment(VectorAlias value)")
        caller = view.create_user_function(0x100)
        view.create_user_function(0x118).set_user_type(signature)
        caller.reanalyze()
        view.update_analysis_and_wait()
        view.rename_type("ps3_v128", "VectorBits")
        view.set_comment_at(0x118, "Increment four vector words.")
        view.update_analysis_and_wait()

        def check(current, increment):
            caller = current.get_function_at(0x100)
            callee = current.get_function_at(0x118)
            calls = [item for item in caller.mlil.instructions
                     if isinstance(item, bn.mediumlevelil.MediumLevelILCall)]
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(calls[0].params), 1)
            argument = calls[0].params[0]
            self.assertIsInstance(argument, bn.mediumlevelil.MediumLevelILVar)
            self.assertEqual(argument.expr_type.width, 16)
            words = {item.offset: item.src.value.value for item in caller.mlil.instructions
                     if isinstance(item, bn.mediumlevelil.MediumLevelILSetVarField)
                     and item.dest == argument.src}
            self.assertEqual(words, {12: 0x12345678, 8: 0x9ABCDEF0, 4: 0xFEDCBA98, 0: 0x76543210})
            result = calls[0].output[0]
            reads = [item for item in caller.mlil.instructions
                     if isinstance(item, bn.mediumlevelil.MediumLevelILSetVar)
                     and isinstance(item.src, bn.mediumlevelil.MediumLevelILVarField)
                     and item.src.src == result]
            self.assertEqual({item.src.offset for item in reads}, {0, 4, 8, 12})
            stores = [item for item in caller.mlil.instructions
                      if isinstance(item, bn.mediumlevelil.MediumLevelILStore)]
            self.assertEqual([(item.size, item.dest.value.value) for item in stores],
                             [(4, 0x210 + 4 * lane) for lane in range(4)])
            self.assertEqual([item.src.src for item in stores], [item.dest for item in reads])
            inputs = [item.src for item in callee.mlil.instructions
                      if isinstance(item, bn.mediumlevelil.MediumLevelILSetVar)
                      and isinstance(item.src, bn.mediumlevelil.MediumLevelILVarField)
                      and item.src.src == callee.parameter_vars[0]]
            self.assertEqual({item.offset for item in inputs}, {0, 4, 8, 12})
            additions = [node for item in callee.mlil.instructions for node in item.traverse(lambda node: node)
                         if isinstance(node, bn.mediumlevelil.MediumLevelILAdd)]
            self.assertEqual(len(additions), 4)
            self.assertTrue(all(item.right.value.value == increment for item in additions))
            returns = [item for item in callee.hlil.instructions
                       if isinstance(item, bn.highlevelil.HighLevelILRet)]
            self.assertEqual(len(returns), 1)
            self.assertEqual(returns[0].src[0].size, 16)
            self.assertEqual(current.get_comment_at(0x118), "Increment four vector words.")

        check(view, 1)
        self.assertEqual(view.write(0x118, bytes.fromhex("1c008183")), 4) # ai r3,r3,2.
        view.reanalyze()
        view.update_analysis_and_wait()
        check(view, 2)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "vector.bndb"
            self.assertTrue(view.create_database(str(path)))
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                check(reopened, 2)
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                check(reopened, 2)
            finally:
                reopened.file.close()

    def test_spu_stack_arguments_preserve_scalar_and_vector_words_after_reopen(self):
        for width, aliased in product((1, 2, 4, 8, 16), ("direct", "copied", "unaligned")):
            with self.subTest(width=width, aliased=aliased), tempfile.TemporaryDirectory() as folder:
                source = bytearray(spu_stack_elf_bytes())
                if aliased != "direct":
                    # Copy the caller's SP to r76 before its store. The callee
                    # copies SP to r6 before loading the declared argument.
                    caller = [0x24004080, 0x24FF0081, 0x1CF00081, 0x3080404B, 0x040000CC,
                              0x2400A64B, 0x33000500, 0x20804203, 0x1C100081, 0x34004080, 0x35000000]
                    callee = [0x04000086, 0x34008303, 0x35000000]
                    if aliased == "unaligned":
                        caller.insert(5, 0x1C03E64C) # ai r76,r76,15; stqd still addresses the same quadword.
                        caller[7] = 0x33000480 # Call moved by one instruction.
                        callee.insert(1, 0x1C004306) # ai r6,r6,1; lqd rounds down to the argument slot.
                    source[0x100:0x100 + 4 * len(caller)] = b"".join(word.to_bytes(4, "big") for word in caller)
                    source[0x140:0x140 + 4 * len(callee)] = b"".join(word.to_bytes(4, "big") for word in callee)
                view = bn.load(source, update_analysis=False)
                self.assertIsNotNone(view)
                self.addCleanup(view.file.close)
                value_type = (bn.Type.named_type_from_registered_type(view, "ps3_v128") if width == 16
                              else bn.Type.int(width, False))
                params = [bn.FunctionParameter(bn.Type.int(4, False), f"arg{index}") for index in range(72)]
                params.append(bn.FunctionParameter(value_type, "last"))
                view.create_user_function(0x140).set_user_type(bn.Type.function(
                    value_type, params, calling_convention=view.platform.default_calling_convention))
                view.create_user_function(0x100).reanalyze()
                view.update_analysis_and_wait()
                view.set_comment_at(0x140, "Return the final stack argument.")

                def check(current, first):
                    caller = current.get_function_at(0x100)
                    callee = current.get_function_at(0x140)
                    calls = [item for item in caller.mlil.instructions
                             if isinstance(item, bn.mediumlevelil.MediumLevelILCall)]
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(len(calls[0].params), 73)
                    argument = calls[0].params[-1]
                    self.assertEqual(argument.expr_type.width, width)
                    if width <= 4:
                        self.assertEqual(argument.value.type, bn.RegisterValueType.ConstantValue)
                        self.assertEqual(argument.value.value, first & ((1 << (8 * width)) - 1))
                    else:
                        self.assertIsInstance(argument, bn.mediumlevelil.MediumLevelILVar)
                        fields = {item.offset: item.src.value.value for item in caller.mlil.instructions
                                  if isinstance(item, bn.mediumlevelil.MediumLevelILSetVarField)
                                  and item.dest == argument.src}
                        words = [first, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210][:width // 4]
                        self.assertEqual(fields, {width - 4 * (i + 1): word for i, word in enumerate(words)})
                        reads = [item.src for item in callee.mlil.instructions
                                 if isinstance(item, bn.mediumlevelil.MediumLevelILSetVar)
                                 and isinstance(item.src, bn.mediumlevelil.MediumLevelILVarField)
                                 and item.src.src == callee.parameter_vars[-1]]
                        self.assertEqual({item.offset for item in reads}, set(range(0, width, 4)))
                    returns = [item for item in callee.hlil.instructions
                               if isinstance(item, bn.highlevelil.HighLevelILRet)]
                    self.assertEqual(len(returns), 1)
                    self.assertEqual(returns[0].src[0].expr_type.width, width)
                    self.assertEqual(current.get_comment_at(0x140), "Return the final stack argument.")

                check(view, 0x12345678)
                self.assertEqual(view.write(0x200, bytes.fromhex("11335577")), 4)
                view.reanalyze()
                view.update_analysis_and_wait()
                check(view, 0x11335577)
                path = Path(folder) / "stack.bndb"
                self.assertTrue(view.create_database(str(path)))
                reopened = bn.load(str(path), update_analysis=False)
                self.assertIsNotNone(reopened)
                try:
                    check(reopened, 0x11335577)
                    reopened.reanalyze()
                    reopened.update_analysis_and_wait()
                    check(reopened, 0x11335577)
                finally:
                    reopened.file.close()

    def test_spu_reanalysis_adds_vector_type_to_an_older_database(self):
        view = bn.load(spu_elf_bytes(), update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        view.update_analysis_and_wait()
        view.set_analysis_hold(True)
        view.undefine_type("ps3.v128")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "older.bndb"
            self.assertTrue(view.create_database(str(path)))
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                self.assertIsNone(reopened.get_type_by_id("ps3.v128"))
                reopened.set_analysis_hold(False)
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                self.assertIsNotNone(reopened.get_type_by_id("ps3.v128"))
                signature, _ = reopened.parse_type_string("ps3_v128 increment(ps3_v128 value)")
                self.assertEqual(signature.return_value.width, 16)
            finally:
                reopened.file.close()

    def test_spu_floating_workflow_recomputes_readonly_constants_and_persists(self):
        source = bytearray(spu_elf_bytes(writable=False))
        # Load four distinct lanes; multiply by two, add two, store the result.
        source[0x80:0x98] = bytes.fromhex("308040034120000458c10185588102862080420635000000")
        source[0xA0:0xB0] = bytes.fromhex("3fc000003f8000004000000040400000")
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        settings = bn.Settings()
        self.assertEqual(settings.get_string("analysis.workflows.functionWorkflow", view), "ps3.spu.function")
        function = view.create_user_function(0x100)
        view.update_analysis_and_wait()

        self.check_spu_words(view, 0x10C, 6, [0x40A00000, 0x40800000, 0x40C00000, 0x41000000])
        self.assertEqual(view.write(0x200, bytes.fromhex("3f000000")), 4)
        function.reanalyze()
        view.update_analysis_and_wait()
        expected = [0x40400000, 0x40800000, 0x40C00000, 0x41000000]
        self.check_spu_words(view, 0x10C, 6, expected)

        # Disabling the activity keeps typed arithmetic instead of stale constants.
        self.assertTrue(settings.set_bool("analysis.ps3.spuFloat", False, view))
        function.reanalyze()
        view.update_analysis_and_wait()
        calls = [item for item in function.mlil.instructions
                 if isinstance(item, bn.mediumlevelil.MediumLevelILIntrinsic)]
        self.assertEqual([item.intrinsic.name for item in calls], ["__spu_fm"] * 4 + ["__spu_fa"] * 4)
        self.assertTrue(settings.set_bool("analysis.ps3.spuFloat", True, view))
        function.reanalyze()
        view.update_analysis_and_wait()
        self.check_spu_words(view, 0x10C, 6, expected)

        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "floating.bndb"
            self.assertTrue(view.create_database(str(database)))
            view.file.close()
            reopened = bn.load(str(database), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                self.assertEqual(settings.get_string("analysis.workflows.functionWorkflow", reopened), "ps3.spu.function")
                self.check_spu_words(reopened, 0x10C, 6, expected)
                reopened.get_function_at(0x100).reanalyze()
                reopened.update_analysis_and_wait()
                self.check_spu_words(reopened, 0x10C, 6, expected)
            finally:
                reopened.file.close()

    def test_spu_loaded_integer_words_reach_medium_dataflow(self):
        source = bytearray(spu_elf_bytes(writable=False))
        # Add two to each loaded word twice; all lanes have different inputs.
        source[0x80:0x98] = bytes.fromhex("308040034200010418010185180102862080420635000000")
        source[0xA0:0xB0] = bytes.fromhex("7fffffffffffffff8000000012345678")
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        view.create_user_function(0x100)
        view.update_analysis_and_wait()
        function = view.get_function_at(0x100)
        stores = [item for item in function.mlil.instructions
                  if isinstance(item, bn.mediumlevelil.MediumLevelILStore)]
        self.assertEqual([(item.dest.value.value, item.size, item.src.value.value) for item in stores],
                         [(0x210 + 4 * lane, 4, value) for lane, value in
                          enumerate([0x80000003, 3, 0x80000004, 0x1234567C])])
        self.assertTrue(all(item.src.value.type == bn.RegisterValueType.ConstantValue for item in stores))
        self.assertIsNotNone(function.hlil)

    def test_spu_floating_constants_do_not_cross_an_ambiguous_branch(self):
        source = bytearray(spu_elf_bytes(writable=False))
        # r3 is one or three depending on incoming r7; the product is unknown.
        source[0x80:0x9C] = bytes.fromhex("411fc00341200004200001075881018358c101852080420535000000")
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        function = view.create_user_function(0x100)
        view.update_analysis_and_wait()
        calls = [item for item in function.mlil.instructions
                 if isinstance(item, bn.mediumlevelil.MediumLevelILIntrinsic)]
        self.assertEqual([item.intrinsic.name for item in calls], ["__spu_fm"] * 4)
        for item in calls:
            self.assertNotIn(item.params[0].value.type,
                             [bn.RegisterValueType.ConstantValue, bn.RegisterValueType.ConstantPointerValue])
        self.assertTrue(any(item.operation == bn.MediumLevelILOperation.MLIL_IF
                            for item in function.mlil.instructions))

    def test_embedded_spu_views_are_independent_and_persist_edits(self):
        from gameroms.formats.ps3.view import open_spu_image

        module = small_module()
        payload = spu_elf_bytes()
        module.segments[0].data.extend(bytes(0xA00 - len(module.segments[0].data)))
        module.segments[0].memory_size = 0xA00
        module.write(0x10400, payload)
        module.write(0x10700, payload)
        parent = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        first = open_spu_image(parent, 0x10400)
        second = open_spu_image(parent, 0x10700)
        self.addCleanup(first.file.close)
        self.addCleanup(second.file.close)
        self.assertNotEqual(first.file, second.file)
        self.assertEqual((first.entry_point, second.entry_point), (0x100, 0x100))
        self.assertEqual(first.parent_view.length, len(payload))
        original = second.read(0x200, 4)
        self.assertEqual(first.write(0x200, bytes.fromhex("aabbccdd")), 4)
        self.assertEqual(second.read(0x200, 4), original)
        self.assertEqual(parent.read(0x104A0, 4), original)
        first.set_comment_at(0x200, "Decoded worker data")
        first.create_user_function(0x100).name = "worker_entry"
        first.update_analysis_and_wait()
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "worker.bndb"
            export = Path(folder) / "worker.elf"
            self.assertTrue(first.save(str(export)))
            self.assertEqual(export.read_bytes()[0xA0:0xA4], bytes.fromhex("aabbccdd"))
            self.assertTrue(first.create_database(str(database)))
            first.file.close()
            reopened = bn.load(str(database), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                self.assertEqual(reopened.view_type, "ELF")
                self.assertEqual(reopened.arch.name, "ps3-spu")
                self.assertEqual(reopened.read(0x200, 4), bytes.fromhex("aabbccdd"))
                self.assertEqual(reopened.get_comment_at(0x200), "Decoded worker data")
                self.assertEqual(reopened.get_function_at(0x100).name, "worker_entry")
                self.assertEqual(reopened.query_metadata("ps3.spu_source")["address"], 0x10400)
            finally:
                reopened.file.close()

    def test_spu_channels_keep_scalar_widths_and_memory_effects(self):
        source = bytearray(spu_elf_bytes())
        # rdch r3,ch28; wrch ch29,r3; bi r0.
        source[0x80:0x8C] = bytes.fromhex("01a00e0321a00e8335000000")
        view = bn.load(source, update_analysis=False)
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        function = view.create_user_function(0x100)
        view.update_analysis_and_wait()
        for lane in range(1, 4):
            value = function.get_reg_value_after(0x100, f"r3.w{lane}")
            self.assertEqual(value.type, bn.RegisterValueType.ConstantValue)
            self.assertEqual(value.value, 0)
        calls = [item for item in function.mlil.instructions if isinstance(item, bn.mediumlevelil.MediumLevelILIntrinsic)]
        self.assertEqual([item.intrinsic.name for item in calls], ["__spu_read_channel", "__spu_write_channel"])
        self.assertEqual([item.params[0].value.value for item in calls], [28, 29])
        self.assertEqual(calls[0].output[0].type.width, 4)
        self.assertEqual(calls[1].params[1].size, 4)
        for item in calls:
            self.assertEqual(view.arch.get_intrinsic_class(item.intrinsic.index),
                             bn.IntrinsicClass.MemoryIntrinsicClass)

    def test_native_context_and_descriptor_annotations(self):
        module = small_module()
        module.write(0x10000, bytes.fromhex("806200004e800020"))
        module.write(0x10280, bytes.fromhex("12345678"))
        program = Program([module], [module_facts(module)], [])
        view = self.open_snapshot(encode_bundle(program))
        self.assertEqual(view.arch.name, "ps3-ppu")
        self.assertEqual(view.platform.name, "ps3-lv2")
        self.assertEqual(view.entry_point, 0x10000)
        self.assertEqual(view.get_data_var_at(0x10200).type.width, 8)
        function = view.create_user_function(0x10000)
        view.update_analysis_and_wait()
        self.assertEqual(function.get_reg_value_at(0x10000, "r2").value, 0x10280)
        loads = list(function.mlil.traverse(lambda node: node.src.value.value
                     if isinstance(node, bn.mediumlevelil.MediumLevelILLoad) else None))
        self.assertEqual(loads, [0x10280])
        self.assertIn(0x10000, view.get_data_refs_from(0x10200))
        self.assertIn(0x10280, view.get_data_refs_from(0x10204))

    def test_small_record_arguments_and_results_keep_mixed_locations_after_reopen(self):
        module = small_module()
        instructions = ["lis r3, 1", "ori r3, r3, 0x280", "li r4, 17", "li r6, 34",
                        "bl 0x10040", "lis r3, 0x1122", "ori r3, r3, 0x3344", "sldi r3, r3, 32",
                        "oris r3, r3, 0x5566", "ori r3, r3, 0x7788", "li r5, 7", "bl 0x10080", "blr"]
        for index, instruction in enumerate(instructions):
            address = 0x10000 + index * 4
            module.write(address, bn.Architecture["ps3-ppu"].assemble(instruction, address))
        for index, instruction in enumerate(["stdu r1, -128(r1)", "std r3, 48(r1)", "lwz r3, 48(r1)",
                                              "add r3, r3, r5", "addi r1, r1, 128", "blr"]):
            address = 0x10080 + index * 4
            module.write(address, bn.Architecture["ps3-ppu"].assemble(instruction, address))
        for index, instruction in enumerate(["stw r4, 0(r3)", "stw r6, 4(r3)", "blr"]):
            address = 0x10040 + index * 4
            module.write(address, bn.Architecture["ps3-ppu"].assemble(instruction, address))
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        caller = view.create_user_function(0x10000)
        callee = view.create_user_function(0x10040)
        consumer = view.create_user_function(0x10080)
        result, _ = view.parse_type_string("struct Result { unsigned first; unsigned second; }")
        view.define_user_type("Result", result)
        result, _ = view.parse_type_string("struct Result")
        integer = bn.Type.int(4, False)
        callee.set_user_type(bn.Type.function(result, [bn.FunctionParameter(integer, "first"),
            bn.FunctionParameter(bn.Type.float(8), "real"), bn.FunctionParameter(integer, "second")],
            calling_convention=view.platform.default_calling_convention))
        consumer.set_user_type(bn.Type.function(integer, [bn.FunctionParameter(result, "record"),
            bn.FunctionParameter(bn.Type.float(8), "real"), bn.FunctionParameter(integer, "word")],
            calling_convention=view.platform.default_calling_convention))
        caller.reanalyze()
        view.update_analysis_and_wait()

        def verify(active):
            caller = active.get_function_at(0x10000)
            callee = active.get_function_at(0x10040)
            self.assertTrue(callee.return_value_location.location.indirect)
            calls = [item for item in caller.mlil.instructions
                     if isinstance(item, bn.mediumlevelil.MediumLevelILCall)]
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(calls[0].params), 3)
            self.assertEqual(calls[0].params[0].value.value, 17)
            self.assertEqual(calls[0].params[1].size, 8)
            self.assertEqual(calls[0].params[2].value.value, 34)
            self.assertEqual(len(calls[1].params), 3)
            self.assertEqual(calls[1].params[0].value.value, 0x1122334455667788)
            self.assertEqual(calls[1].params[0].size, 8)
            self.assertEqual(calls[1].params[2].value.value, 7)
            self.assertIsNotNone(callee.hlil)

        verify(view)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "record-return.bndb"
            self.assertTrue(view.create_database(str(path)))
            view.file.close()
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                verify(reopened)
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                verify(reopened)
            finally:
                reopened.file.close()

    def test_toc_saving_call_stubs_revoke_and_recover_after_edits_and_reopen(self):
        module = small_module()
        # Two calls through a TOC-adjustment stub; each reloads the caller's TOC.
        code = bytes.fromhex("f821ff814800003de84100288062000048000031e841002880820004382100804e800020")
        module.write(0x10000, code)
        module.write(0x10040, bytes.fromhex("f84100283c42000038420040480000044e800020"))
        module.write(0x10208, bytes.fromhex("00010050000102c0"))
        module.sections = (replace(module.sections[0], size=16),)
        module.write(0x10280, bytes.fromhex("123456789abcdef0"))
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        view.create_user_function(0x10000)
        view.create_user_function(0x10040)
        view.update_analysis_and_wait()

        def check_restores(active, known):
            function = active.get_function_at(0x10000)
            for address in [0x10008, 0x10014]:
                value = function.get_reg_value_after(address, "r2")
                self.assertEqual(value.type in [bn.RegisterValueType.ConstantValue,
                                                bn.RegisterValueType.ConstantPointerValue], known)
                if known:
                    self.assertEqual(value.value, 0x10280)
            stores = [item for item in function.lifted_il.instructions
                      if item.operation == bn.LowLevelILOperation.LLIL_STORE
                      and item.address in [0x10004, 0x10010]]
            self.assertEqual(len(stores), 2 if known else 0)
            self.assertIsNotNone(function.hlil)

        def edit_and_restore(active):
            check_restores(active, True)
            # Change the saved register inside the stub, away from its entry.
            self.assertEqual(active.write(0x10041, b"\x61"), 1)  # std r3,40(r1)
            active.update_analysis_and_wait()
            check_restores(active, False)
            self.assertEqual(active.write(0x10041, b"\x41"), 1)
            active.update_analysis_and_wait()
            check_restores(active, True)
            stub = active.get_function_at(0x10040)
            value = stub.get_reg_value_at(0x10040, "r2")
            self.assertEqual(value.type, bn.RegisterValueType.ConstantPointerValue)
            self.assertEqual(value.value, 0x10280)
            for byte in [b"\xc4", b"\xc0"]:
                self.assertEqual(active.write(0x1020F, byte), 1)
                active.update_analysis_and_wait()
                value = stub.get_reg_value_at(0x10040, "r2")
                self.assertEqual(value.type, bn.RegisterValueType.ConstantPointerValue)
                self.assertEqual(value.value, 0x10280)
                check_restores(active, True)

        edit_and_restore(view)
        view.set_comment_at(0x10004, "Call with a distinct callee TOC")
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "toc-calls.bndb"
            self.assertTrue(view.create_database(str(database)))
            view.file.close()
            reopened = bn.load(str(database), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                self.assertEqual(reopened.get_comment_at(0x10004), "Call with a distinct callee TOC")
                edit_and_restore(reopened)
            finally:
                reopened.file.close()

    def test_forward_toc_chains_recompute_after_edits_and_database_reopen(self):
        module = small_module()
        for address, code in [(0x10000, "480000214e800020"),
                              (0x10020, "480000214e800020"),
                              (0x10040, "806200004e800020")]:
            module.write(address, bytes.fromhex(code))
        module.write(0x10280, bytes.fromhex("12345678"))
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        for address in [0x10000, 0x10020, 0x10040]:
            view.create_user_function(address)
        view.update_analysis_and_wait()

        def check(active, toc):
            for address in [0x10020, 0x10040]:
                function = active.get_function_at(address)
                self.assertFalse(function.analysis_skipped, (hex(address), function.analysis_skip_reason))
                self.assertIsNotNone(function.llil, hex(address))
                value = function.get_reg_value_at(address, "r2")
                if toc is None:
                    self.assertNotIn(value.type, [bn.RegisterValueType.ConstantValue,
                                                 bn.RegisterValueType.ConstantPointerValue])
                else:
                    self.assertEqual(value.type, bn.RegisterValueType.ConstantPointerValue)
                    self.assertEqual(value.value, toc)

        def edit_and_restore(active):
            check(active, 0x10280)
            # The call now supplies a different anchor to both downstream functions.
            self.assertEqual(active.write(0x10000, bytes.fromhex("384200204800001d4e800020")), 12)
            active.update_analysis_and_wait()
            check(active, 0x102A0)
            # Descriptor evidence is stale: the entire chain must lose its anchor.
            self.assertEqual(active.write(0x10204, bytes.fromhex("000102c0")), 4)
            active.update_analysis_and_wait()
            check(active, None)
            self.assertEqual(active.write(0x10204, bytes.fromhex("00010280")), 4)
            self.assertEqual(active.write(0x10000, bytes.fromhex("480000214e80002060000000")), 12)
            active.update_analysis_and_wait()
            check(active, 0x10280)

        edit_and_restore(view)
        view.set_comment_at(0x10040, "Forward context survives reopening")
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "forward-toc.bndb"
            self.assertTrue(view.create_database(str(database)))
            view.file.close()
            reopened = bn.load(str(database), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                check(reopened, 0x10280)
                self.assertEqual(reopened.get_comment_at(0x10040), "Forward context survives reopening")
                edit_and_restore(reopened)
                settings = bn.Settings()
                self.assertTrue(settings.set_bool("analysis.ps3.callContexts", False, reopened))
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                check(reopened, None)
                self.assertEqual(reopened.get_function_at(0x10000).get_reg_value_at(0x10000, "r2").value,
                                 0x10280)
                self.assertTrue(settings.set_bool("analysis.ps3.callContexts", True, reopened))
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                check(reopened, 0x10280)
            finally:
                reopened.file.close()

    def test_chained_toc_saves_follow_edits_through_a_descriptor_backed_stub(self):
        module = small_module()
        module.write(0x10000, bytes.fromhex("f821ff814800003de8410028382100804e800020"))
        module.write(0x10040, bytes.fromhex("f84100283c4200003842004048000014"))
        module.write(0x10060, bytes.fromhex("f84100283c4200003842004048000014"))
        module.write(0x10080, bytes.fromhex("f84100283c4200003842ff8048000014"))
        module.write(0x100A0, bytes.fromhex("4e800020"))
        module.write(0x10208, bytes.fromhex("0001004000010280"))
        module.sections = (replace(module.sections[0], size=16),)
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        for address in [0x10000, 0x10040, 0x10060, 0x10080, 0x100A0]:
            view.create_user_function(address)
        view.update_analysis_and_wait()
        function = view.get_function_at(0x10000)
        initial = function.get_reg_value_after(0x10008, "r2")
        self.assertEqual(initial.type, bn.RegisterValueType.ConstantPointerValue)
        self.assertEqual(initial.value, 0x10300)
        # The final save sees both preceding adjustments, even though their net
        # change at the leaf is zero. Changing the middle stub changes that save.
        for byte, expected in [(b"\x80", 0x10340), (b"\x40", 0x10300)]:
            self.assertEqual(view.write(0x1006B, byte), 1)
            view.update_analysis_and_wait()
            value = function.get_reg_value_after(0x10008, "r2")
            self.assertEqual(value.type, bn.RegisterValueType.ConstantPointerValue)
            self.assertEqual(value.value, expected)

    def test_elf_symbols_name_code_descriptors_and_data(self):
        program = prepare_program([ElfImage("main", symbol_elf_bytes())])
        view = self.open_snapshot(encode_bundle(program))
        for name, address, kind, binding in [
                ("entry_fn", 0x10000, bn.SymbolType.FunctionSymbol, bn.SymbolBinding.GlobalBinding),
                ("entry_fn_opd", 0x10020, bn.SymbolType.DataSymbol, bn.SymbolBinding.GlobalBinding),
                ("counter", 0x10030, bn.SymbolType.DataSymbol, bn.SymbolBinding.WeakBinding),
                ("scratch", 0x10040, bn.SymbolType.DataSymbol, bn.SymbolBinding.LocalBinding)]:
            symbols = view.get_symbols_by_name(name)
            self.assertEqual(len(symbols), 1)
            self.assertEqual((symbols[0].address, symbols[0].type, symbols[0].binding), (address, kind, binding))
        self.assertEqual(view.get_data_var_at(0x10020).type.width, 8)
        function = view.create_user_function(0x10000)
        view.update_analysis_and_wait()
        self.assertEqual(function.get_reg_value_at(0x10000, "r2").value, 0x10030)

    def test_changed_descriptor_revokes_incoming_toc_automatically(self):
        module = small_module()
        module.write(0x10000, bytes.fromhex("806200004e800020"))
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        function = view.create_user_function(0x10000)
        view.update_analysis_and_wait()
        self.assertEqual(function.get_reg_value_at(0x10000, "r2").value, 0x10280)
        self.assertEqual(view.write(0x10204, bytes.fromhex("00010290")), 4)
        view.update_analysis_and_wait()
        self.assertEqual(function.get_reg_value_at(0x10000, "r2").type,
                         bn.RegisterValueType.EntryValue)
        self.assertEqual(view.write(0x10204, bytes.fromhex("00010280")), 4)
        view.update_analysis_and_wait()
        self.assertEqual(function.get_reg_value_at(0x10000, "r2").value, 0x10280)

    def check_vector_roundtrip(self, code, intrinsic=None):
        module = small_module()
        module.write(0x10000, bytes.fromhex(code))
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))

        def verify(current):
            function = current.create_user_function(0x10000)
            function.reanalyze()
            current.update_analysis_and_wait()
            self.assertFalse(any(item.operation == bn.LowLevelILOperation.LLIL_UNIMPL
                                 for item in function.lifted_il.instructions))
            stores = [item for item in function.mlil.instructions
                      if isinstance(item, bn.mediumlevelil.MediumLevelILStore)]
            self.assertEqual(len(stores), 1)
            self.assertEqual((stores[0].size, stores[0].src.size, stores[0].dest.value.value), (16, 16, 0x10290))
            intrinsics = [item for item in function.mlil.instructions
                          if isinstance(item, bn.mediumlevelil.MediumLevelILIntrinsic)]
            self.assertEqual(len(intrinsics), int(intrinsic is not None))
            if intrinsic:
                self.assertEqual(intrinsics[0].intrinsic.name, intrinsic)
                widths = [16, 16, 16] + ([] if intrinsic == "__vmx_vperm" else [1])
                self.assertEqual([item.size for item in intrinsics[0].params], widths)
                if intrinsic != "__vmx_vperm":
                    self.assertEqual(intrinsics[0].params[-1].value.type, bn.RegisterValueType.ConstantValue)
                    self.assertEqual(intrinsics[0].params[-1].value.value, 0)
                self.assertEqual(len(intrinsics[0].output), 1)
                self.assertEqual(intrinsics[0].output[0].type.width, 16)

        verify(view)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "vectors.bndb"
            self.assertTrue(view.create_database(str(path)))
            view.file.close()
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                verify(reopened)
            finally:
                reopened.file.close()

    def test_vector_memory_dataflow_survives_database_reopen(self):
        # lvx v1,0,r2; vmr v2,v1; addi r4,r2,16; stvx v2,0,r4; blr.
        self.check_vector_roundtrip("7c2010ce10410c84388200107c4021ce4e800020")

    def test_vector_rearrangement_and_permutation_survive_database_reopen(self):
        # lvx; vspltw v2,v1,2; vsldoi v2,v2,v1,7; vperm v2,v1,v2,v3; store; blr.
        self.check_vector_roundtrip("7c2010ce10420a8c104209ec104110eb388200107c4021ce4e800020", "__vmx_vperm")

    def test_vector_integer_dataflow_survives_database_reopen(self):
        # lvx v1; vspltisw v3,1; vadduwm v2,v1,v3; vslw v2,v2,v3;
        # vcmpgtsw. v2,v2,v1; store the comparison mask; blr.
        self.check_vector_roundtrip("7c2010ce1061038c104118801042198410420f86388200107c4021ce4e800020")

    def test_reanalysis_adds_platform_types_to_an_older_database_with_contexts_disabled(self):
        module = small_module()
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        view.update_analysis_and_wait()
        # Model a database saved before the platform vector type was available.
        view.set_analysis_hold(True)
        view.undefine_type("ps3.v128")
        self.assertIsNone(view.get_type_by_id("ps3.v128"))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "older.bndb"
            self.assertTrue(view.create_database(str(path)))
            view.file.close()
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                self.assertIsNone(reopened.get_type_by_id("ps3.v128"))
                self.assertTrue(bn.Settings().set_bool("analysis.ps3.callContexts", False, reopened))
                reopened.set_analysis_hold(False)
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                self.assertIsNotNone(reopened.get_type_by_id("ps3.v128"))
                signature, _ = reopened.parse_type_string("ps3_v128 vector_operation(ps3_v128 value)")
                self.assertEqual(signature.return_value.width, 16)
            finally:
                reopened.file.close()

    def test_fixed_vector_calls_keep_register_and_stack_values_after_reopen(self):
        arch = bn.Architecture["ps3-ppu"]
        for stacked in (False, True):
            with self.subTest(stacked=stacked):
                module = small_module()
                if stacked:
                    caller = ["stdu r1,-288(r1)", "lvx v1,0,r2", "addi r4,r1,240", "stvx v1,0,r4",
                              "bl 0x10080", "addi r4,r2,16", "stvx v2,0,r4", "addi r1,r1,288", "blr"]
                    callee = ["addi r4,r1,240", "lvx v2,0,r4", "blr"]
                else:
                    caller = ["lvx v2,0,r2", "bl 0x10080", "addi r4,r2,16", "stvx v2,0,r4", "blr"]
                    callee = ["vspltisw v0,0", "vsubuwm v0,v0,v2", "vmaxsw v2,v0,v2", "blr"]
                for base, instructions in [(0x10000, caller), (0x10080, callee)]:
                    for index, source in enumerate(instructions):
                        address = base + 4 * index
                        module.write(address, arch.assemble(source, address))
                view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
                self.assertIsNotNone(view.get_type_by_id("ps3.v128"))
                vector = bn.Type.named_type_from_registered_type(view, "ps3_v128")
                view.define_user_type("VectorAlias", vector)
                function = view.create_user_function(0x10080)
                params = ", ".join(f"VectorAlias value{index}" for index in range(13 if stacked else 1))
                signature, _ = view.parse_type_string(f"VectorAlias vector_operation({params})")
                function.set_user_type(signature)
                view.create_user_function(0x10000).reanalyze()
                view.update_analysis_and_wait()
                view.rename_type("ps3_v128", "VectorBits")
                view.set_comment_at(0x10080, "Vector result")
                view.update_analysis_and_wait()

                def check(current):
                    caller_function = current.get_function_at(0x10000)
                    callee_function = current.get_function_at(0x10080)
                    location = callee_function.return_value_location.location
                    self.assertFalse(location.indirect)
                    self.assertEqual(location.components[0].var.storage, arch.get_reg_index("v2"))
                    calls = [item for item in caller_function.mlil.instructions
                             if isinstance(item, bn.mediumlevelil.MediumLevelILCall)]
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(len(calls[0].params), 13 if stacked else 1)
                    argument = calls[0].params[-1]
                    self.assertEqual(argument.size, 16)
                    self.assertIsInstance(argument, bn.mediumlevelil.MediumLevelILVar)
                    definitions = caller_function.mlil.get_var_definitions(argument.src)
                    self.assertEqual(len(definitions), 1)
                    if stacked:
                        self.assertIsInstance(definitions[0].src, bn.mediumlevelil.MediumLevelILVar)
                        definitions = caller_function.mlil.get_var_definitions(definitions[0].src.src)
                        self.assertEqual(len(definitions), 1)
                    self.assertIsInstance(definitions[0].src, bn.mediumlevelil.MediumLevelILLoad)
                    self.assertEqual(definitions[0].src.size, 16)
                    stores = [item for item in caller_function.mlil.instructions
                              if isinstance(item, bn.mediumlevelil.MediumLevelILStore)]
                    self.assertEqual(len(stores), 1)
                    self.assertEqual(stores[0].src.size, 16)
                    self.assertIn(stores[0].src.src, calls[0].output)
                    reads = {var for item in callee_function.mlil.instructions for var in item.vars_read}
                    self.assertIn(callee_function.parameter_vars[-1], reads)
                    returns = [item for item in callee_function.hlil.instructions
                               if isinstance(item, bn.highlevelil.HighLevelILRet)]
                    self.assertEqual(len(returns), 1)
                    self.assertEqual(len(returns[0].src), 1)
                    self.assertEqual(returns[0].src[0].size, 16)
                    self.assertEqual(current.get_comment_at(0x10080), "Vector result")

                check(view)
                with tempfile.TemporaryDirectory() as folder:
                    path = Path(folder) / "vectors.bndb"
                    self.assertTrue(view.create_database(str(path)))
                    reopened = bn.load(str(path), update_analysis=False)
                    self.assertIsNotNone(reopened)
                    try:
                        check(reopened)
                        reopened.reanalyze()
                        reopened.update_analysis_and_wait()
                        check(reopened)
                    finally:
                        reopened.file.close()

    def test_vector_integer_minmax_survives_edits_and_database_reopen(self):
        arch = bn.Architecture["ps3-ppu"]
        forms = [f"v{kind}{sign}{size}" for kind in ("max", "min")
                 for sign in ("u", "s") for size in ("b", "h", "w")]
        instructions = ["addi r4,r2,16"]
        for name in forms:
            instructions.extend([f"{name} v3,v1,v2", "stvx v3,0,r4"])
        instructions.append("blr")
        module = small_module()
        for index, source in enumerate(instructions):
            address = 0x10000 + 4 * index
            module.write(address, arch.assemble(source, address))
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))

        def check(current, first_signed=False, *, reanalyze=True):
            function = current.create_user_function(0x10000)
            if reanalyze:
                function.reanalyze()
                current.update_analysis_and_wait()
            self.assertFalse(any(item.operation == bn.LowLevelILOperation.LLIL_UNIMPL
                                 for item in function.lifted_il.instructions))
            for index, name in enumerate(forms):
                address = 0x10004 + 8 * index
                signed = name[-2] == "s" or (index == 0 and first_signed)
                operation = (bn.MediumLevelILOperation.MLIL_CMP_SGT if signed else
                             bn.MediumLevelILOperation.MLIL_CMP_UGT)
                comparisons = {node.expr_index: node
                    for item in function.mlil.instructions if item.address == address
                    for node in item.traverse(lambda node: node) if node.operation == operation}
                size = {"b": 1, "h": 2, "w": 4}[name[-1]]
                self.assertGreaterEqual(len(comparisons), 16 // size)
                self.assertTrue(all(item.size == size for item in comparisons.values()))
            stores = [item for item in function.mlil.instructions
                      if isinstance(item, bn.mediumlevelil.MediumLevelILStore)]
            self.assertEqual(len(stores), len(forms))
            self.assertTrue(all(item.size == 16 and item.src.size == 16 for item in stores))
            self.assertIsNotNone(function.hlil)

        check(view)
        address = 0x10004
        self.assertEqual(view.write(address, arch.assemble("vmaxsb v3,v1,v2", address)), 4)
        check(view, first_signed=True)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "minmax.bndb"
            self.assertTrue(view.create_database(str(path)))
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                check(reopened, first_signed=True, reanalyze=False)
                self.assertEqual(reopened.write(address, arch.assemble("vmaxub v3,v1,v2", address)), 4)
                check(reopened)
            finally:
                reopened.file.close()

    def test_vector_saturation_status_updates_after_edits_and_database_reopen(self):
        module = small_module()
        instructions = ["lis r14,1", "ori r14,r14,0x28c", "vspltisw v0,0", "mtvscr v0",
            "vspltisb v1,-1", "vspltisb v2,0", "vaddubs v3,v1,v2", "mfvscr v4", "stvewx v4,0,r14",
            "vspltisb v2,1", "vaddubs v1,v1,v2", "mfvscr v4", "addi r14,r14,16", "stvewx v4,0,r14",
            "vsububs v1,v1,v1", "mfvscr v4", "addi r14,r14,16", "stvewx v4,0,r14", "mtvscr v0",
            "vspltish v1,-1", "vpkshus v1,v1,v1", "mfvscr v4", "addi r14,r14,16", "stvewx v4,0,r14", "blr"]
        arch = bn.Architecture["ps3-ppu"]
        for index, instruction in enumerate(instructions):
            address = 0x10000 + 4 * index
            module.write(address, arch.assemble(instruction, address))
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        view.create_user_function(0x10000)

        def check(current, operation=bn.MediumLevelILOperation.MLIL_ADD, values=(0, 1, 1, 1)):
            current.update_analysis_and_wait()
            function = current.get_function_at(0x10000)
            self.assertFalse(any(item.operation == bn.LowLevelILOperation.LLIL_UNIMPL
                                 for item in function.lifted_il.instructions))
            stores = [item for item in function.mlil.instructions
                      if isinstance(item, bn.mediumlevelil.MediumLevelILStore)]
            self.assertEqual(len(stores), 4)
            for index, (store, value) in enumerate(zip(stores, values)):
                self.assertEqual(store.size, 4)
                self.assertEqual(store.dest.value.value, 0x1028C + 16 * index)
                # Wide vector constants can remain unknown in core value queries.
                # The shared arithmetic and status dependencies are checked below.
                if store.src.value.type == bn.RegisterValueType.ConstantValue:
                    self.assertEqual(store.src.value.value, value)
            assignments = [item for item in function.mlil.instructions
                           if item.address == 0x10028 and isinstance(item, bn.mediumlevelil.MediumLevelILSetVar)]
            lanes = {item.dest for item in assignments if item.src.operation == operation}
            self.assertEqual(len(lanes), 16)
            effects = [item for item in assignments
                       if item.dest.source_type == bn.VariableSourceType.RegisterVariableSourceType
                       and item.dest.storage in {arch.get_reg_index("v1"), arch.get_reg_index("vscr")}]
            self.assertEqual(len(effects), 2)
            for effect in effects:
                self.assertTrue(lanes.issubset(set(effect.src.vars_read)))
                if effect.dest.storage == arch.get_reg_index("vscr"):
                    self.assertTrue(any(var.storage == arch.get_reg_index("vscr")
                                        and var.source_type == bn.VariableSourceType.RegisterVariableSourceType
                                        for var in effect.src.vars_read))
            self.assertIsNotNone(function.hlil)

        check(view)
        address = 0x10000 + 4 * 10
        self.assertEqual(view.write(address, arch.assemble("vsububs v1,v1,v2", address)), 4)
        check(view, bn.MediumLevelILOperation.MLIL_SUB, (0, 0, 0, 1))
        self.assertEqual(view.write(address, arch.assemble(instructions[10], address)), 4)
        check(view)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "saturation.bndb"
            self.assertTrue(view.create_database(str(path)))
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                check(reopened)
                reopened.reanalyze()
                check(reopened)
            finally:
                reopened.file.close()

    def test_vector_float_dataflow_survives_database_reopen(self):
        # lvx v1; vaddfp v2,v1,v3; vsubfp v2,v2,v3; vcmpgefp. v2,v2,v1; store; blr.
        self.check_vector_roundtrip("7c2010ce1041180a1042184a10420dc6388200107c4021ce4e800020")

    def test_fused_vector_float_dataflow_survives_database_reopen(self):
        for name, opcode in [("__vmx_vmaddfp", "104108ee"), ("__vmx_vnmsubfp", "104108ef")]:
            with self.subTest(name=name):
                # lvx v1; clear NJ via v4; fused v2,v1,v3,v1; store v2; blr.
                self.check_vector_roundtrip("7c2010ce1080038c10002644" + opcode + "388200107c4021ce4e800020", name)

    def test_unsupported_vector_write_does_not_retain_a_previous_constant(self):
        module = small_module()
        # vxor v1,v1,v1; vmulouh v1,v2,v3; addi r4,r2,16; stvx v1,0,r4; blr.
        module.write(0x10000, bytes.fromhex("10210cc410221848388200107c2021ce4e800020"))
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        function = view.create_user_function(0x10000)
        view.update_analysis_and_wait()
        stores = [item for item in function.mlil.instructions
                  if isinstance(item, bn.mediumlevelil.MediumLevelILStore)]
        self.assertEqual(len(stores), 1)
        self.assertIn(stores[0].src.value.type,
                      (bn.RegisterValueType.UndeterminedValue, bn.RegisterValueType.EntryValue))

    def test_sparse_bss_mapping_and_database(self):
        image = ElfImage("main", elf_bytes(memory_size=0x40000000,
                                          relocation=Relocation(0x10000000, 0xFF, 0, 1, 0xBAADF00D)))
        view = self.open_snapshot(encode_bundle(prepare_program([image])))
        self.assertEqual(view.read(0x10010000, 4), bytes.fromhex("baadf00d"))
        self.assertEqual(view.read(0x10010004, 8), bytes(8))
        self.assertEqual(sum(segment.data_length for segment in view.segments), 68)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sparse.bndb"
            self.assertTrue(view.create_database(str(path)))
            view.file.close()
            self.assertLess(path.stat().st_size, 2 * 1024 * 1024)
            reopened = bn.load(str(path))
            self.assertIsNotNone(reopened)
            try:
                self.assertEqual(reopened.arch.name, "ps3-ppu")
                self.assertEqual(reopened.read(0x10010000, 4), bytes.fromhex("baadf00d"))
                self.assertEqual(sum(segment.data_length for segment in reopened.segments), 68)
            finally:
                reopened.file.close()

    def test_linked_calls_keep_distinct_tocs_and_user_annotations_after_reopen(self):
        program = linked_program()
        main, library = program.modules
        for module in program.modules:
            module.write(module.segments[0].address, bytes.fromhex("806200004e800020"))
        main.write(0x10010, bytes.fromhex(
            "39800000658c0001818c0140f8410028800c0000804c00047c0903a64e800420"))
        program.facts = [module_facts(module) for module in program.modules]
        view = self.open_snapshot(encode_bundle(program))

        def verify(current):
            for address in [0x10000, 0x10010, 0x20000]:
                current.create_user_function(address).reanalyze()
            current.update_analysis_and_wait()
            self.assertEqual(current.get_function_at(0x10000).get_reg_value_at(0x10000, "r2").value, 0x10280)
            self.assertEqual(current.get_function_at(0x20000).get_reg_value_at(0x20000, "r2").value, 0x20280)
            stub = current.get_function_at(0x10010)
            self.assertEqual(stub.get_reg_value_at(0x1002C, "ctr").value, 0x20000)
            self.assertEqual(stub.get_reg_value_at(0x1002C, "r2").value, 0x20280)
            # Slot, code-address and TOC edits must revoke the corresponding old fact.
            for address, patch, register, old_value in [
                    (0x10140, bytes(4), "ctr", 0x20000),
                    (0x20203, bytes.fromhex("10"), "ctr", 0x20000),
                    (0x20207, bytes.fromhex("90"), "r2", 0x20280)]:
                original = current.read(address, len(patch))
                self.assertEqual(current.write(address, patch), len(patch))
                current.update_analysis_and_wait()
                value = stub.get_reg_value_at(0x1002C, register)
                self.assertFalse(value.type in (bn.RegisterValueType.ConstantValue,
                                               bn.RegisterValueType.ConstantPointerValue)
                                 and value.value == old_value, (hex(address), register, value))
                if address != 0x10140:
                    self.assertEqual(current.get_function_at(0x20000).get_reg_value_at(0x20000, "r2").type,
                                     bn.RegisterValueType.EntryValue)
                self.assertEqual(current.write(address, original), len(original))
                current.update_analysis_and_wait()
                self.assertEqual(stub.get_reg_value_at(0x1002C, "ctr").value, 0x20000)
                self.assertEqual(stub.get_reg_value_at(0x1002C, "r2").value, 0x20280)
                self.assertEqual(current.get_function_at(0x20000).get_reg_value_at(0x20000, "r2").value, 0x20280)

        verify(view)
        view.set_comment_at(0x10000, "entry context")
        view.define_user_symbol(bn.Symbol(bn.SymbolType.FunctionSymbol, 0x10000, "named_entry"))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "contexts.bndb"
            self.assertTrue(view.create_database(str(path)))
            view.file.close()
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                verify(reopened)
                self.assertEqual(reopened.get_comment_at(0x10000), "entry context")
                self.assertEqual(reopened.get_symbol_at(0x10000).raw_name, "named_entry")
            finally:
                reopened.file.close()

    def test_import_symbols_preserve_descriptor_identity_and_user_annotations(self):
        from gameroms.formats.ps3.annotate import annotate_import_symbols
        from gameroms.formats.ps3.names import entry_name

        program = linked_program()
        view = self.open_snapshot(encode_bundle(program))

        def verify(active):
            imports = active.get_symbols_of_type(bn.SymbolType.ImportAddressSymbol)
            self.assertEqual({symbol.address for symbol in imports}, {item.slot for item in program.bindings})
            for item in program.bindings:
                name = entry_name(item.library, item.nid) + "_import_slot"
                symbols = active.get_symbols(item.slot, 1)
                self.assertEqual(len([s for s in symbols if s.auto and s.raw_name == name]), 1)
                self.assertTrue(any(s.type == bn.SymbolType.ImportAddressSymbol and s.raw_name == name
                                    for s in symbols))
                self.assertEqual(active.get_data_var_at(item.slot).type.width, 4)
                if item.descriptor:
                    self.assertIsNone(active.get_function_at(item.descriptor.address))
                    self.assertEqual(active.get_symbol_at(item.descriptor.code).type, bn.SymbolType.FunctionSymbol)

        view.update_analysis_and_wait()
        verify(view)
        self.assertEqual(view.get_data_var_at(program.bindings[0].slot).type.target.width, 8)
        slot = program.bindings[0].slot
        name = entry_name(program.bindings[0].library, program.bindings[0].nid) + "_import_slot"
        view.define_auto_symbol(bn.Symbol(bn.SymbolType.DataSymbol, slot, name))
        view.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, slot, "my_import"))
        view.set_comment_at(slot, "User import annotation")
        view.define_user_data_var(slot, bn.Type.int(4, False))
        annotate_import_symbols(view, program)
        self.assertEqual(view.get_symbol_at(slot).raw_name, "my_import")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "imports.bndb"
            self.assertTrue(view.create_database(str(path)))
            view.file.close()
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                verify(reopened)
                self.assertEqual(reopened.get_symbol_at(slot).raw_name, "my_import")
                self.assertEqual(reopened.get_comment_at(slot), "User import annotation")
                self.assertEqual(reopened.get_data_var_at(slot).type.width, 4)
            finally:
                reopened.file.close()

    def test_inline_descriptor_calls_keep_distinct_contexts_after_edits_and_reopen(self):
        module = small_module()
        arch = bn.Architecture["ps3-ppu"]
        for start, descriptor in [(0x10000, 0x10208), (0x10040, 0x10210)]:
            instructions = ["stdu r1, -128(r1)", "lis r11, 1", f"ori r11, r11, {descriptor & 0xffff}",
                            "lwz r0, 0(r11)", "std r2, 40(r1)", "mtctr r0", "lwz r2, 4(r11)",
                            "bctrl", "ld r2, 40(r1)", "addi r1, r1, 128", "blr"]
            for index, instruction in enumerate(instructions):
                address = start + index * 4
                module.write(address, arch.assemble(instruction, address))
        module.write(0x10080, arch.assemble("blr", 0x10080))
        module.write(0x10208, bytes.fromhex("00010080000102c000010080000102d0"))
        # Both descriptors are physically writable; their per-entry facts differ.
        module.sections = (replace(module.sections[0], size=24, flags=3),)
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        for address in [0x10000, 0x10040, 0x10080]:
            view.create_user_function(address)
        view.get_function_at(0x10040).store_metadata("ps3.toc", 0x10280)
        view.update_analysis_and_wait()

        def verify(active, first_known=True):
            for start, toc, known in [(0x10000, 0x102C0, first_known), (0x10040, 0x102D0, True)]:
                function = active.get_function_at(start)
                value = function.get_reg_value_at(start + 28, "r2")
                target = function.get_reg_value_at(start + 28, "ctr")
                if known:
                    self.assertEqual(value.value, toc)
                    self.assertEqual(value.type, bn.RegisterValueType.ConstantPointerValue)
                    self.assertEqual(target.value, 0x10080)
                    self.assertIn(0x10080, active.get_callees(start + 28, function))
                else:
                    self.assertNotIn(target.type, [bn.RegisterValueType.ConstantValue,
                                                  bn.RegisterValueType.ConstantPointerValue])
                self.assertEqual(function.get_reg_value_after(start + 32, "r2").value, 0x10280)
                self.assertIsNotNone(function.hlil)
            callee = active.get_function_at(0x10080)
            self.assertNotIn(callee.get_reg_value_at(callee.start, "r2").type,
                             [bn.RegisterValueType.ConstantValue, bn.RegisterValueType.ConstantPointerValue])

        def edit_and_restore(active):
            verify(active)
            self.assertEqual(active.write(0x1020F, b"\xc4"), 1)
            active.update_analysis_and_wait()
            verify(active, False)
            self.assertEqual(active.write(0x1020F, b"\xc0"), 1)
            active.update_analysis_and_wait()
            verify(active)

        edit_and_restore(view)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "descriptor-calls.bndb"
            self.assertTrue(view.create_database(str(path)))
            view.file.close()
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                edit_and_restore(reopened)
                self.assertTrue(bn.Settings().set_bool("analysis.ps3.descriptors", False, reopened))
                reopened.reanalyze()
                reopened.update_analysis_and_wait()
                for start in [0x10000, 0x10040]:
                    target = reopened.get_function_at(start).get_reg_value_at(start + 28, "ctr")
                    self.assertNotIn(target.type, [bn.RegisterValueType.ConstantValue,
                                                  bn.RegisterValueType.ConstantPointerValue])
            finally:
                reopened.file.close()

    def test_user_data_patches_survive_database_reopen(self):
        module = small_module()
        view = self.open_snapshot(encode_bundle(Program([module], [module_facts(module)], [])))
        self.assertEqual(view.write(0x10280, bytes.fromhex("12345678")), 4)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "patched.bndb"
            export = Path(folder) / "patched.ps3exe"
            self.assertTrue(view.save(str(export)))
            self.assertEqual(read_bundle(export.read_bytes()).program.modules[0].read(0x10280, 4),
                             bytes.fromhex("12345678"))
            self.assertTrue(view.create_database(str(path)))
            view.file.close()
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                self.assertEqual(reopened.view_type, "PS3 PS3EXE")
                self.assertEqual(reopened.read(0x10280, 4), bytes.fromhex("12345678"))
            finally:
                reopened.file.close()

    def test_direct_elf_export_preserves_layout_and_byte_edits(self):
        source = symbol_elf_bytes()
        view = bn.BinaryViewType["PS3 ELF"].create(bn.BinaryView.new(source))
        self.assertIsNotNone(view)
        self.addCleanup(view.file.close)
        patch = bytes.fromhex("12345678")
        self.assertEqual(view.write(0x10030, patch), 4)
        expected = bytearray(source)
        expected[0x130:0x134] = patch
        with tempfile.TemporaryDirectory() as folder:
            export = Path(folder) / "patched.elf"
            self.assertTrue(view.save(str(export)))
            self.assertEqual(export.read_bytes(), expected)

    def test_prepared_source_metadata_survives_database_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "EBOOT.BIN").write_bytes(symbol_elf_bytes())
            program = prepare_input(root).program
            view = self.open_snapshot(encode_bundle(program))
            metadata = view.query_metadata("ps3.modules")
            self.assertEqual(metadata["version"], 1)
            self.assertEqual(metadata["modules"][0]["sources"][0]["path"], "EBOOT.BIN")
            self.assertEqual(metadata["modules"][0]["normalized_sha256"], program.modules[0].source_hash)
            database = root / "source.bndb"
            self.assertTrue(view.create_database(str(database)))
            view.file.close()
            reopened = bn.load(str(database), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                self.assertEqual(reopened.query_metadata("ps3.modules"), metadata)
            finally:
                reopened.file.close()

    def test_editing_an_import_slot_revokes_its_snapshot_assertion(self):
        view = self.open_snapshot(encode_bundle(linked_program()))
        self.assertEqual(view.write(0x10140, bytes(4)), 4)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unlinked.bndb"
            self.assertTrue(view.create_database(str(path)))
            view.file.close()
            reopened = bn.load(str(path), update_analysis=False)
            self.assertIsNotNone(reopened)
            try:
                self.assertEqual(reopened.view_type, "PS3 PS3EXE")
                self.assertNotIn(str(0x10140), reopened.query_metadata("ps3.contexts")["bindings"])
                self.assertEqual(reopened.read(0x10140, 4), bytes(4))
            finally:
                reopened.file.close()


if __name__ == "__main__":
    unittest.main()
