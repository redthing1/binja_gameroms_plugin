"""Bounded PPU SELF normalization, metadata decryption and section integrity."""

from dataclasses import dataclass
from bisect import bisect_right
from functools import lru_cache
from itertools import accumulate
import hmac
from pathlib import Path
import struct
import zlib

from .crypto import decrypt
from .elf import ELF_HEADER, PROGRAM_HEADER, SECTION_HEADER, ElfImage, checked_range


SCE_HEADER = struct.Struct(">4sIHHIQQ")
SELF_HEADER = struct.Struct(">9Q")
METADATA_SECTION = struct.Struct(">QQIIIIIIII")
MAX_ELF_SIZE = 512 * 1024 * 1024
MAX_HEADER_SIZE = 64 * 1024 * 1024
NP_KLIC_KEY = bytes.fromhex("f2fbca7a75b04edc1390638ccdfdd1ee")
NP_KLIC_FREE = bytes.fromhex("72f990788f9cff745725f08e4c128387")


@dataclass(frozen=True)
class Integrity:
    verified_loads: int = 0
    unhashed_loads: int = 0
    supplemental_mismatches: int = 0
    key_name: str = ""


@dataclass(frozen=True)
class Normalized:
    image: ElfImage
    integrity: Integrity


@lru_cache(maxsize=1)
def metadata_keys() -> tuple[tuple[str, bytes, bytes], ...]:
    rows = Path(__file__).with_name("data").joinpath("self_keys.txt").read_text().splitlines()
    return tuple((name, bytes.fromhex(key), bytes.fromhex(iv))
                 for row in rows if row and not row.startswith("#") for name, key, iv in [row.split()])


def _inflate(data: bytes, expected: int) -> bytes:
    if expected > MAX_ELF_SIZE:
        raise ValueError("SELF decoded payload exceeds the supported size")
    decoder = zlib.decompressobj()
    result = decoder.decompress(data, expected + 1)
    if len(result) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("SELF compressed payload size or stream mismatch")
    return result


class SelfImage:
    def __init__(self, data: bytes):
        self.data = data
        self.read(0, 0x70)
        magic, version, flags, kind, metadata, self.header_size, elf_size = SCE_HEADER.unpack_from(data)
        if magic != b"SCE\0" or version != 2 or kind != 1:
            raise ValueError("expected a version 2 SELF executable")
        if not 0x70 <= self.header_size <= min(len(data), MAX_HEADER_SIZE) or elf_size > MAX_ELF_SIZE:
            raise ValueError("invalid SELF header or executable size")
        self.debug = bool(flags & 0x8000)
        self.metadata_offset = metadata + SCE_HEADER.size
        _, app, elf, phdrs, self.section_info, self.segment_info, _, controls, control_size = (
            SELF_HEADER.unpack_from(data, 0x20))
        self.read(app, 32, header=True)
        self.self_type = int.from_bytes(self.read(app + 12, 4), "big")
        self.elf_header = self.read(elf, ELF_HEADER.size, header=True)
        fields = ELF_HEADER.unpack(self.elf_header)
        if fields[0][:7] != b"\x7fELF\x02\x02\x01" or fields[2] != 21:
            raise ValueError("SELF does not contain a big-endian ELF64 PPU executable")
        _, _, _, _, _, self.phoff, self.shoff, _, ehsize, phsize, phnum, shsize, shnum, _ = fields
        if ehsize != ELF_HEADER.size or not phnum or phnum == 0xFFFF or phsize != PROGRAM_HEADER.size:
            raise ValueError("unsupported SELF program-header table")
        self.phdr_bytes = self.read(phdrs, phnum * phsize, header=True)
        self.programs = tuple(PROGRAM_HEADER.unpack_from(self.phdr_bytes, i * phsize) for i in range(phnum))
        self.shdr_bytes = b""
        if shnum:
            if not self.section_info or shsize != SECTION_HEADER.size or shnum == 0xFFFF:
                raise ValueError("unsupported SELF section-header table")
            self.shdr_bytes = self.read(self.section_info, shnum * shsize)
        self.sections = tuple(SECTION_HEADER.iter_unpack(self.shdr_bytes))
        self.controls = self.read(controls, control_size, header=True) if control_size else b""
        for program in self.programs:
            checked_range(program[2], program[5], MAX_ELF_SIZE, "normalized ELF segment")
        checked_range(self.phoff, len(self.phdr_bytes), MAX_ELF_SIZE, "normalized ELF program table")
        checked_range(self.shoff, len(self.shdr_bytes), MAX_ELF_SIZE, "normalized ELF section table")

    def read(self, offset: int, size: int, *, header: bool = False) -> bytes:
        checked_range(offset, size, self.header_size if header else len(self.data), "SELF")
        return self.data[offset:offset + size]

    def _npdrm_key(self, klicensee: bytes | None) -> bytes | None:
        offset = 0
        while offset < len(self.controls):
            checked_range(offset, 16, len(self.controls), "SELF control header")
            kind, size = struct.unpack_from(">II", self.controls, offset)
            if size < 16:
                raise ValueError("invalid SELF control record size")
            checked_range(offset, size, len(self.controls), "SELF control record")
            if kind == 3:
                payload = self.controls[offset + 16:offset + size]
                if len(payload) < 64 or payload[:4] != b"NPD\0":
                    raise ValueError("invalid SELF NPDRM control record")
                license_type = int.from_bytes(payload[8:12], "big")
                if license_type not in (1, 2, 3):
                    raise ValueError("unsupported SELF NPDRM license type")
                if klicensee is None:
                    if license_type != 3:
                        raise ValueError("this NPDRM SELF requires a klicensee")
                    klicensee = NP_KLIC_FREE
                if len(klicensee) != 16:
                    raise ValueError("a klicensee must contain 16 bytes")
                return decrypt(klicensee, NP_KLIC_KEY, None, "ecb")
            offset += size
        if self.self_type == 8:
            raise ValueError("NPDRM SELF has no license control record")
        return None

    def _metadata(self, klicensee):
        info = self.read(self.metadata_offset, 64, header=True)
        encrypted = self.read(self.metadata_offset + 64,
                              self.header_size - self.metadata_offset - 64, header=True)
        np_key = self._npdrm_key(klicensee)
        if np_key:
            info = decrypt(info, np_key, bytes(16), "cbc")
        for name, key, iv in metadata_keys():
            plain = decrypt(info, key, iv, "cbc")
            if plain[16:32] != bytes(16) or plain[48:64] != bytes(16):
                continue
            metadata = decrypt(encrypted, plain[:16], plain[32:48], "ctr")
            checked_range(0, 32, len(metadata), "SELF metadata header")
            _, _, section_count, key_count, optional_size = struct.unpack_from(">QIIII", metadata)
            records_end = 32 + section_count * METADATA_SECTION.size
            checked_range(32, records_end - 32, len(metadata), "SELF metadata sections")
            checked_range(records_end, key_count * 16 + optional_size, len(metadata), "SELF metadata keys")
            records = tuple(METADATA_SECTION.iter_unpack(metadata[32:records_end]))
            keys = metadata[records_end:records_end + key_count * 16]
            return name, records, keys
        raise ValueError("no metadata key matches this SELF")

    def normalize(self, name: str, *, klicensee: bytes | None = None, strict_integrity: bool = False) -> Normalized:
        pieces = [(0, self.elf_header), (self.phoff, self.phdr_bytes), (self.shoff, self.shdr_bytes)]
        verified = unhashed = mismatches = 0
        covered = set()
        payloads = []
        regions = []
        stored_total = decoded_total = 0
        if self.debug:
            key_name, keys = "debug", b""
            table = self.read(self.segment_info, 32 * len(self.programs), header=True)
            records = []
            for index, (offset, size, compression, _, encryption) in enumerate(struct.iter_unpack(">QQIIQ", table)):
                if size and offset >= self.header_size:
                    records.append((offset, size, 2, index, 0, 0, 1, 0, 0, compression))
        else:
            key_name, records, keys = self._metadata(klicensee)
        for offset, size, kind, index, hashed, hash_index, encrypted, key_index, iv_index, compressed in records:
            if kind not in (1, 2, 3) or encrypted not in (1, 3) or compressed not in (1, 2):
                raise ValueError("unsupported SELF metadata section encoding")
            stored_total += size
            if stored_total > MAX_ELF_SIZE:
                raise ValueError("SELF stored payload total exceeds the supported size")
            blob = self.read(offset, size)
            if encrypted == 3:
                checked_range(key_index * 16, 16, len(keys), "SELF payload key")
                checked_range(iv_index * 16, 16, len(keys), "SELF payload IV")
                blob = decrypt(blob, keys[key_index * 16:(key_index + 1) * 16],
                               keys[iv_index * 16:(iv_index + 1) * 16], "ctr")
            matches = None
            if hashed == 2 and hash_index != 0xFFFFFFFF:
                hash_offset = hash_index * 16
                checked_range(hash_offset, 96, len(keys), "SELF HMAC record")
                expected, hash_key = keys[hash_offset:hash_offset + 20], keys[hash_offset + 32:hash_offset + 96]
                matches = hmac.compare_digest(hmac.digest(hash_key, blob, "sha1"), expected)
            elif hashed not in (0, 1):
                raise ValueError("unsupported SELF section hash mode")
            if kind == 1:
                if matches is False:
                    mismatches += 1
                    if strict_integrity:
                        raise ValueError("SELF supplemental HMAC mismatch")
                continue
            headers = self.programs if kind == 2 else self.sections
            if index >= len(headers):
                raise ValueError("SELF payload has an invalid header index")
            header = headers[index]
            destination, expected_size = (header[2], header[5]) if kind == 2 else (header[4], header[5])
            decoded_total += expected_size
            if decoded_total > MAX_ELF_SIZE:
                raise ValueError("SELF decoded payload total exceeds the supported size")
            is_load = kind == 2 and header[0] == 1
            if matches is False:
                if is_load or strict_integrity:
                    raise ValueError("SELF load HMAC mismatch" if is_load else "SELF supplemental HMAC mismatch")
                mismatches += 1
            if is_load:
                verified += matches is True
                unhashed += matches is None
            decoded = _inflate(blob, expected_size) if compressed == 2 else blob
            if len(decoded) != expected_size:
                raise ValueError("SELF payload disagrees with its ELF size")
            pieces.append((destination, decoded))
            if kind == 2:
                if index in covered:
                    raise ValueError("duplicate SELF program payload")
                covered.add(index)
                payloads.append((destination, len(decoded)))
                regions.append((destination, destination + len(decoded), offset, offset + size))
        if self.debug and self.shdr_bytes:
            regions.append((self.shoff, self.shoff + len(self.shdr_bytes),
                            self.section_info, self.section_info + len(self.shdr_bytes)))
            for section in self.sections:
                if section[1] in (0, 8) or not section[5]:
                    continue
                start, size = section[4], section[5]
                if any(offset <= start and start + size <= offset + len(blob) for offset, blob in pieces):
                    continue
                previous = max((region for region in regions if region[1] <= start),
                               key=lambda region: region[1], default=None)
                physical = previous[3] + start - previous[1] if previous else self.header_size + start
                if any(physical < end and begin < physical + size for _, _, begin, end in regions):
                    raise ValueError("missing debug SELF section data")
                decoded_total += size
                if decoded_total > MAX_ELF_SIZE:
                    raise ValueError("SELF debug section total exceeds the supported size")
                pieces.append((start, self.read(physical, size)))
        # A nested PHDR may describe bytes already supplied by a containing segment.
        ranges = sorted(payloads)
        starts = [start for start, _ in ranges]
        ends = list(accumulate((start + size for start, size in ranges), max))
        for index, header in enumerate(self.programs):
            if header[5] and index not in covered:
                parent = bisect_right(starts, header[2]) - 1
                if parent < 0 or ends[parent] < header[2] + header[5]:
                    raise ValueError("SELF is missing a program payload")
        end = max(offset + len(blob) for offset, blob in pieces if blob)
        checked_range(0, end, MAX_ELF_SIZE, "normalized SELF")
        output = bytearray(end)
        filled_end = 0
        for offset, blob in sorted(pieces, key=lambda piece: piece[0]):
            # Earlier pieces start before this one, so any overlap is a contiguous prefix.
            overlap = max(0, min(offset + len(blob), filled_end) - offset)
            if overlap and output[offset:offset + overlap] != blob[:overlap]:
                raise ValueError("conflicting normalized SELF payloads")
            output[offset:offset + len(blob)] = blob
            filled_end = max(filled_end, offset + len(blob))
        return Normalized(ElfImage(name, bytes(output)), Integrity(verified, unhashed, mismatches, key_name))


def normalize(name: str, data: bytes, **options) -> Normalized:
    if data[:4] == b"\x7fELF":
        return Normalized(ElfImage(name, data), Integrity())
    if data[:4] != b"SCE\0":
        raise ValueError("expected a PPU ELF or SELF executable")
    return SelfImage(data).normalize(name, **options)


def executable_type(data: bytes) -> tuple[int, int]:
    offset = 0
    if data[:4] == b"SCE\0":
        checked_range(0x30, 8, len(data), "SELF ELF pointer")
        offset = int.from_bytes(data[0x30:0x38], "big")
    checked_range(offset, 20, len(data), "executable header")
    header = data[offset:offset + 20]
    if header[:4] != b"\x7fELF" or header[5] != 2:
        raise ValueError("expected a big-endian ELF or SELF header")
    return int.from_bytes(header[16:18], "big"), int.from_bytes(header[18:20], "big")
