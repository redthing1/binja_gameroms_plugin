"""Executable preparation and bounded container reads, with synthetic fixtures."""

import hashlib
import hmac
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

from gameroms.formats.ps3.bundle import HEADER, MAGIC, VERSION, encode_bundle, read_bundle
from gameroms.formats.ps3.inputs import prepare_input
from gameroms.formats.ps3.iso import IsoImage, SECTOR_SIZE
from gameroms.formats.ps3.prepare import prepare_program
from gameroms.formats.ps3.self import NP_KLIC_FREE, NP_KLIC_KEY, SelfImage, normalize
from test_ps3 import elf_bytes, prx_bytes, spu_elf_bytes, symbol_elf_bytes


HAS_CRYPTO = importlib.util.find_spec("cryptography") is not None
ROOT_KEY, ROOT_IV = bytes([0x44]) * 32, bytes([0x55]) * 16


def aes(data, key, iv, mode):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    context = Cipher(algorithms.AES(key), {"cbc": modes.CBC, "ctr": modes.CTR}[mode](iv)).encryptor()
    return context.update(data) + context.finalize()


def self_bytes(*, debug=False, compressed=False, supplemental=False, key_index=0, np_license=None):
    elf = bytearray(elf_bytes())
    elf[0x100:0x140] = bytes(range(64))
    payload = zlib.compress(elf[0x100:0x140]) if compressed else bytes(elf[0x100:0x140])
    data_key, data_iv = bytes([0x11]) * 16, bytes([0x22]) * 16
    hash_key = bytes(range(64))
    key_table = data_key + data_iv + hmac.digest(hash_key, payload, "sha1") + bytes(12) + hash_key
    count = 2 if supplemental else 1
    metadata_size = 32 + 48 * count + len(key_table)
    info_offset = 0x1C0 if np_license is not None else 0x160
    metadata_offset = info_offset + 64
    header_size = (metadata_offset + metadata_size + 127) & ~127
    source = bytearray(header_size)
    struct.pack_into(">4sIHHIQQ", source, 0, b"SCE\0", 2, 0x8000 if debug else 1, 1,
                     info_offset - 32, header_size, len(elf))
    struct.pack_into(">9Q", source, 0x20, 3, 0x70, 0xA0, 0xE0, 0, 0x120, 0,
                     0x140 if np_license is not None else 0, 80 if np_license is not None else 0)
    struct.pack_into(">I", source, 0x7C, 8 if np_license is not None else 4)
    if np_license is not None:
        struct.pack_into(">IIQ", source, 0x140, 3, 80, 0)
        source[0x150:0x154] = b"NPD\0"
        struct.pack_into(">I", source, 0x158, np_license)
    source[0xA0:0xE0] = elf[:64]
    source[0xE0:0x118] = elf[64:120]
    struct.pack_into(">QQIIQ", source, 0x120, header_size, len(payload), 2 if compressed else 1, 0, 0)
    if not debug:
        metadata = bytearray(header_size - metadata_offset)
        struct.pack_into(">QIIII", metadata, 0, 0, 0, count, len(key_table) // 16, 0)
        struct.pack_into(">QQIIIIIIII", metadata, 32, header_size, len(payload), 2, 0, 2, 2,
                         3, key_index, 1, 2 if compressed else 1)
        if supplemental:
            struct.pack_into(">QQIIIIIIII", metadata, 80, header_size + len(payload), 16,
                             1, 0, 2, 2, 1, 0, 0, 1)
        start = 32 + count * 48
        metadata[start:start + len(key_table)] = key_table
        metadata_key, metadata_iv = bytes([0x33]) * 16, bytes([0x66]) * 16
        info = metadata_key + bytes(16) + metadata_iv + bytes(16)
        info = aes(info, ROOT_KEY, ROOT_IV, "cbc")
        if np_license is not None:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            context = Cipher(algorithms.AES(NP_KLIC_KEY), modes.ECB()).decryptor()
            np_key = context.update(NP_KLIC_FREE) + context.finalize()
            info = aes(info, np_key, bytes(16), "cbc")
        source[info_offset:metadata_offset] = info
        source[metadata_offset:header_size] = aes(metadata, metadata_key, metadata_iv, "ctr")
        payload = aes(payload, data_key, data_iv, "ctr")
    source.extend(payload)
    if supplemental:
        source.extend(b"supplemental....")
    return bytes(source), bytes(elf)


def both(data, offset, value, width):
    data[offset:offset + width] = value.to_bytes(width, "little")
    data[offset + width:offset + 2 * width] = value.to_bytes(width, "big")


def directory_record(name, lba, size, flags=0):
    name = name if isinstance(name, bytes) else name.encode("ascii")
    record = bytearray(33 + len(name) + (not len(name) % 2))
    record[0] = len(record)
    both(record, 2, lba, 4)
    both(record, 10, size, 4)
    record[25] = flags
    both(record, 28, 1, 2)
    record[32], record[33:33 + len(name)] = len(name), name
    return bytes(record)


def iso_bytes(files=None, *, ps3=True, encrypted=False, key=bytes(range(16)), volume_sectors=64):
    files = files or {"EBOOT.BIN": elf_bytes()}
    image = bytearray(64 * SECTOR_SIZE)
    if ps3:
        struct.pack_into(">I", image, 0, 2)
        struct.pack_into(">IIII", image, 8, 0, 31, 48, volume_sectors - 1)
        image[SECTOR_SIZE:SECTOR_SIZE + 12] = b"PlayStation3"
    pvd = bytearray(SECTOR_SIZE)
    pvd[:7] = b"\x01CD001\x01"
    both(pvd, 80, volume_sectors, 4)
    both(pvd, 128, SECTOR_SIZE, 2)
    root = directory_record(b"\0", 20, SECTOR_SIZE, 2)
    pvd[156:156 + len(root)] = root
    image[16 * SECTOR_SIZE:17 * SECTOR_SIZE] = pvd
    image[17 * SECTOR_SIZE:17 * SECTOR_SIZE + 7] = b"\xffCD001\x01"
    for lba, child, target in [(20, "PS3_GAME", 21), (21, "USRDIR", 22)]:
        entries = directory_record(b"\0", lba, SECTOR_SIZE, 2)
        entries += directory_record(b"\1", 20, SECTOR_SIZE, 2)
        entries += directory_record(child, target, SECTOR_SIZE, 2)
        image[lba * SECTOR_SIZE:lba * SECTOR_SIZE + len(entries)] = entries
    records = directory_record(b"\0", 22, SECTOR_SIZE, 2) + directory_record(b"\1", 21, SECTOR_SIZE, 2)
    for index, (name, data) in enumerate(files.items()):
        lba = 32 + index * 2
        records += directory_record(name + ";1", lba, len(data))
        image[lba * SECTOR_SIZE:lba * SECTOR_SIZE + len(data)] = data
    image[22 * SECTOR_SIZE:22 * SECTOR_SIZE + len(records)] = records
    if encrypted:
        for lba in range(32, 48):
            offset = lba * SECTOR_SIZE
            image[offset:offset + SECTOR_SIZE] = aes(image[offset:offset + SECTOR_SIZE], key,
                                                    lba.to_bytes(16, "big"), "cbc")
    return bytes(image)


class SelfParsing(unittest.TestCase):
    def test_plain_elf_is_unchanged(self):
        data = elf_bytes()
        self.assertEqual(normalize("main", data).image.data, data)

    def test_debug_payload_and_compression(self):
        for compressed in (False, True):
            source, expected = self_bytes(debug=True, compressed=compressed)
            result = normalize("main", source)
            self.assertEqual(result.image.data, expected)
            self.assertEqual(result.integrity.unhashed_loads, 1)
            self.assertEqual(result.integrity.key_name, "debug")

    def test_header_and_output_bounds(self):
        source, _ = self_bytes(debug=True)
        for data in [source[:50], source[:-1], source[:16] + (1 << 40).to_bytes(8, "big") + source[24:]]:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                normalize("bad", data)
        oversized = bytearray(source)
        struct.pack_into(">Q", oversized, 0xE0 + 8, 1 << 40)
        with self.assertRaises(ValueError):
            SelfImage(bytes(oversized))

    def test_inflate_rejects_a_trailing_stream_or_wrong_length(self):
        from gameroms.formats.ps3.self import _inflate
        for data, size in [(zlib.compress(b"data") + b"extra", 4), (zlib.compress(b"data"), 3),
                           (zlib.compress(b"data")[:-1], 4)]:
            with self.assertRaises(ValueError):
                _inflate(data, size)

    def test_structural_headers_do_not_substitute_for_a_missing_load_payload(self):
        source, _ = self_bytes(debug=True)
        changed = bytearray(source)
        struct.pack_into(">Q", changed, 0xE0 + 8, 0)
        struct.pack_into(">Q", changed, 0x120 + 8, 0)
        with self.assertRaisesRegex(ValueError, "missing a program payload"):
            normalize("missing", bytes(changed))

    def test_debug_elf_symbols_outside_loads_are_preserved(self):
        elf = symbol_elf_bytes()
        size = 0x200
        source = bytearray(size) + bytearray(elf)
        struct.pack_into(">4sIHHIQQ", source, 0, b"SCE\0", 2, 0x8000, 1, 0, size, len(elf))
        struct.pack_into(">9Q", source, 0x20, 3, 0x70, 0xA0, 0xE0, size + 0x400, 0x120, 0, 0, 0)
        struct.pack_into(">I", source, 0x7C, 4)
        source[0xA0:0xE0] = elf[:64]
        source[0xE0:0x118] = elf[64:120]
        struct.pack_into(">QQIIQ", source, 0x120, size + 0x100, 0x40, 1, 0, 0)
        result = normalize("symbols", bytes(source))
        program = prepare_program([result.image])
        self.assertEqual([symbol.name for symbol in program.modules[0].symbols],
                         [".entry_fn", "entry_fn", "counter", "scratch"])


@unittest.skipUnless(HAS_CRYPTO, "requires the preparation CLI's locked cryptography dependency")
class EncryptedSelf(unittest.TestCase):
    def setUp(self):
        self.keys = patch("gameroms.formats.ps3.self.metadata_keys", return_value=(("fixture", ROOT_KEY, ROOT_IV),))
        self.keys.start()
        self.addCleanup(self.keys.stop)

    def test_encryption_compression_and_hashes(self):
        for compressed in (False, True):
            source, expected = self_bytes(compressed=compressed)
            result = normalize("main", source)
            self.assertEqual(result.image.data, expected)
            self.assertEqual(result.integrity.verified_loads, 1)

    def test_load_hmac_failure_and_invalid_key_index(self):
        source, _ = self_bytes()
        changed = bytearray(source)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "load HMAC"):
            normalize("bad", bytes(changed))
        source, _ = self_bytes(key_index=9)
        with self.assertRaisesRegex(ValueError, "payload key"):
            normalize("bad", source)

    def test_supplemental_mismatches_are_distinguished_from_load_failures(self):
        source, expected = self_bytes(supplemental=True)
        result = normalize("main", source)
        self.assertEqual(result.image.data, expected)
        self.assertEqual(result.integrity.supplemental_mismatches, 1)
        with self.assertRaisesRegex(ValueError, "supplemental HMAC"):
            normalize("main", source, strict_integrity=True)

    def test_npdrm_free_and_explicit_klicensee_layers(self):
        source, expected = self_bytes(np_license=3)
        self.assertEqual(normalize("free", source).image.data, expected)
        source, expected = self_bytes(np_license=2)
        with self.assertRaisesRegex(ValueError, "requires a klicensee"):
            normalize("licensed", source)
        self.assertEqual(normalize("licensed", source, klicensee=NP_KLIC_FREE).image.data, expected)
        with self.assertRaisesRegex(ValueError, "no metadata key"):
            normalize("licensed", source, klicensee=bytes(16))


class IsoParsing(unittest.TestCase):
    def test_filesystem_inventory_and_plain_executable(self):
        image = IsoImage(io.BytesIO(iso_bytes()))
        main = image.entries["ps3_game/usrdir/eboot.bin"]
        image.configure(main, None)
        self.assertFalse(image.encrypted)
        self.assertEqual(image.read_file(main), elf_bytes())

    def test_generic_iso_has_no_disc_encryption(self):
        image = IsoImage(io.BytesIO(iso_bytes(ps3=False)))
        main = image.entries["ps3_game/usrdir/eboot.bin"]
        image.configure(main, None)
        self.assertFalse(image.encrypted)

    def test_fully_plain_ps3_region_table_is_unambiguous(self):
        data = bytearray(iso_bytes())
        struct.pack_into(">I", data, 0, 1)
        struct.pack_into(">II", data, 8, 0, 63)
        image = IsoImage(io.BytesIO(data))
        image.configure(image.entries["ps3_game/usrdir/eboot.bin"], None)
        self.assertFalse(image.encrypted)

    def test_already_decrypted_ps3_disc_does_not_apply_a_supplied_key(self):
        image = IsoImage(io.BytesIO(iso_bytes()))
        with patch("gameroms.formats.ps3.iso.decrypt", side_effect=AssertionError("unexpected decryption")):
            main = image.entries["ps3_game/usrdir/eboot.bin"]
            image.configure(main, bytes(16))
            self.assertEqual(image.read_file(main), elf_bytes())

    @unittest.skipUnless(HAS_CRYPTO, "requires cryptography")
    def test_encrypted_sectors_use_absolute_lbas_and_do_not_touch_plaintext(self):
        image = IsoImage(io.BytesIO(iso_bytes(encrypted=True)))
        main = image.entries["ps3_game/usrdir/eboot.bin"]
        with self.assertRaisesRegex(ValueError, "disc key"):
            image.configure(main, None)
        with self.assertRaisesRegex(ValueError, "mode or key"):
            image.configure(main, bytes(16))
        image.configure(main, bytes(range(16)))
        self.assertTrue(image.encrypted)
        self.assertEqual(image.read_file(main), elf_bytes())
        self.assertEqual(image.read_at(16 * SECTOR_SIZE, 7), b"\x01CD001\x01")

    def test_endian_range_and_directory_validation(self):
        valid = iso_bytes()
        mutations = [(16 * SECTOR_SIZE + 84, 1), (16 * SECTOR_SIZE + 129, 0),
                     (22 * SECTOR_SIZE, 3), (20 * SECTOR_SIZE + 101, ord("/"))]
        for offset, value in mutations:
            data = bytearray(valid)
            data[offset] = value
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                IsoImage(io.BytesIO(data))

    def test_multi_extent_file_is_reassembled(self):
        data = bytearray(iso_bytes())
        records = directory_record(b"\0", 22, SECTOR_SIZE, 2) + directory_record(b"\1", 21, SECTOR_SIZE, 2)
        records += directory_record("EBOOT.BIN;1", 32, SECTOR_SIZE, 0x80)
        records += directory_record("EBOOT.BIN;1", 36, 4)
        data[22 * SECTOR_SIZE:23 * SECTOR_SIZE] = records + bytes(SECTOR_SIZE - len(records))
        data[36 * SECTOR_SIZE:36 * SECTOR_SIZE + 4] = b"tail"
        image = IsoImage(io.BytesIO(data))
        main = image.entries["ps3_game/usrdir/eboot.bin"]
        self.assertEqual(len(main.extents), 2)
        self.assertEqual(image.read_file(main), bytes(data[32 * SECTOR_SIZE:33 * SECTOR_SIZE]) + b"tail")


class SourcePreparation(unittest.TestCase):
    def test_directory_aliases_and_sparse_assets_stay_out_of_the_bundle(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            directory = root / "PS3_GAME" / "USRDIR"
            directory.mkdir(parents=True)
            (directory / "EBOOT.BIN").write_bytes(elf_bytes())
            (directory / "GAME.SELF").write_bytes(elf_bytes())
            with (directory / "ASSETS.BIN").open("wb") as stream:
                stream.truncate(3 * 1024 ** 3)
            from gameroms.formats.ps3.inputs import _read_file

            def bounded_read(path, size=None):
                if path.name == "ASSETS.BIN":
                    self.assertEqual(size, 64)
                return _read_file(path, size)

            with patch("gameroms.formats.ps3.inputs._read_file", side_effect=bounded_read):
                prepared = prepare_input(root)
            self.assertEqual(len(prepared.program.modules), 1)
            module = prepared.program.modules[0]
            self.assertEqual(set(module.aliases), {"PS3_GAME/USRDIR/EBOOT.BIN", "PS3_GAME/USRDIR/GAME.SELF"})
            self.assertEqual(len(module.sources), 2)
            encoded = encode_bundle(prepared.program)
            self.assertLess(len(encoded), 4096)
            self.assertEqual(read_bundle(encoded).program.modules[0].sources, module.sources)

    def test_large_iso_reads_only_metadata_and_executable_extents(self):
        with tempfile.TemporaryDirectory() as folder:
            volume_size = 16 * 1024 ** 3
            data = bytearray(iso_bytes(volume_sectors=volume_size // SECTOR_SIZE))
            extra = directory_record("ASSETS.BIN;1", 1000, 3 * 1024 ** 3)
            position = 22 * SECTOR_SIZE
            while data[position]:
                position += data[position]
            data[position:position + len(extra)] = extra
            path = Path(folder) / "large.iso"
            with path.open("wb") as stream:
                stream.write(data)
                stream.truncate(volume_size)
            original = IsoImage.read_file

            def bounded_read(image, entry, size=None):
                if entry.path.endswith("ASSETS.BIN"):
                    self.assertEqual(size, 64)
                return original(image, entry, size)

            with patch.object(IsoImage, "read_file", bounded_read):
                program = prepare_input(path).program
            self.assertLess(len(encode_bundle(program)), 4096)
            self.assertEqual(program.modules[0].sources[0].container_size, volume_size)

    def test_iso_aliases_and_module_discovery_share_the_same_pipeline(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "game.iso"
            files = {"EBOOT.BIN": elf_bytes(), "GAME.SELF": elf_bytes(), "ENGINE.SPRX": prx_bytes()}
            path.write_bytes(iso_bytes(files))
            prepared = prepare_input(path)
            self.assertEqual([module.name for module in prepared.program.modules], ["EBOOT", "ENGINE"])
            self.assertEqual(len(prepared.program.modules[0].sources), 2)
            source = prepared.program.modules[0].sources[0]
            self.assertEqual(source.container, "game.iso")
            self.assertEqual(source.sha256, hashlib.sha256(elf_bytes()).hexdigest())
            self.assertEqual(source.sector_mode, "plain")
            self.assertEqual(len(prepare_input(path, discover_modules=False).program.modules), 1)

    def test_alternate_mains_require_selection_and_non_ppu_files_are_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "EBOOT.BIN").write_bytes(elf_bytes())
            alternate = bytearray(elf_bytes())
            alternate[-1] = 1
            (root / "OTHER.SELF").write_bytes(alternate)
            worker = bytearray(elf_bytes())
            struct.pack_into(">H", worker, 18, 23)
            (root / "WORKER.elf").write_bytes(worker)
            prepared = prepare_input(root)
            self.assertEqual(prepared.alternatives, ("OTHER.SELF",))
            self.assertEqual(prepared.other_machines, ("WORKER.elf",))
            selected = prepare_input(root, executable="OTHER.SELF")
            self.assertEqual(selected.program.modules[0].name, "OTHER")
            with self.assertRaisesRegex(ValueError, "PPU"):
                prepare_input(root, executable="WORKER.elf")

    def test_equivalent_directory_and_iso_inputs_have_identical_module_placements_and_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            directory = root / "dump" / "PS3_GAME" / "USRDIR"
            directory.mkdir(parents=True)
            modified = bytearray(prx_bytes())
            modified[-1] = 1
            files = {"EBOOT.BIN": elf_bytes(), "Z.SPRX": bytes(modified), "A.SPRX": prx_bytes()}
            for name, data in files.items():
                (directory / name).write_bytes(data)
            image = root / "game.iso"
            image.write_bytes(iso_bytes(files))
            programs = [prepare_input(root / "dump").program, prepare_input(image).program]
            layouts = [[(module.source_hash, [(segment.address, segment.data, segment.zero_fill)
                                              for segment in module.segments]) for module in program.modules]
                       for program in programs]
            self.assertEqual(layouts[0], layouts[1])

    def test_bundled_source_ranges_and_hashes_are_validated(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "game.iso"
            path.write_bytes(iso_bytes())
            encoded = encode_bundle(prepare_input(path).program)
            _, _, metadata_size, _ = HEADER.unpack_from(encoded)
            metadata = json.loads(encoded[HEADER.size:HEADER.size + metadata_size])
            payload = encoded[HEADER.size + metadata_size:]
            for field, value in [("sha256", "bad"), ("extents", [[32 * SECTOR_SIZE, 1 << 30]]),
                                  ("extents", [[32 * SECTOR_SIZE, 4]])]:
                changed = json.loads(json.dumps(metadata))
                changed["modules"][0]["sources"][0][field] = value
                header = json.dumps(changed).encode()
                with self.subTest(field=field), self.assertRaises(ValueError):
                    read_bundle(HEADER.pack(MAGIC, VERSION, len(header), len(payload)) + header + payload)

    def test_cli_preserves_input_executables_and_key_files(self):
        script = Path(__file__).resolve().parents[1] / "tools" / "ps3_to_ps3exe.py"
        with tempfile.TemporaryDirectory() as folder:
            source, key = Path(folder) / "main.elf", Path(folder) / "license.key"
            source.write_bytes(elf_bytes())
            key.write_bytes(bytes([0x42]) * 16)
            for output in (source, key):
                before = output.read_bytes()
                result = subprocess.run([sys.executable, str(script), str(source), "--klicensee", str(key),
                                         "-o", str(output)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must not replace", result.stderr)
                self.assertEqual(output.read_bytes(), before)

    def test_cli_extracts_only_embedded_spu_executables(self):
        script = Path(__file__).resolve().parents[1] / "tools" / "ps3_to_ps3exe.py"
        payload = spu_elf_bytes()
        source_data = bytearray(elf_bytes(memory_size=0x1000))
        source_data.extend(bytes(0x200 + len(payload) - len(source_data)))
        source_data[0x200:] = payload
        struct.pack_into(">Q", source_data, 64 + 32, len(source_data) - 0x100)
        with tempfile.TemporaryDirectory() as folder:
            source, output, workers = (Path(folder) / name for name in ("main.elf", "game.ps3exe", "workers"))
            source.write_bytes(source_data)
            command = [sys.executable, str(script), str(source), "-o", str(output), "--spu-directory", str(workers)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            extracted = list(workers.glob("*.elf"))
            self.assertEqual(len(extracted), 1)
            self.assertEqual(extracted[0].read_bytes(), payload)
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SPU output already exists", result.stderr)
            self.assertEqual(extracted[0].read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
