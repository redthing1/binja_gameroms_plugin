"""Selective ISO9660 reads with optional PS3 disc-sector decryption."""

from dataclasses import dataclass
from typing import BinaryIO

from .crypto import decrypt
from .elf import checked_range, validate_ranges


SECTOR_SIZE = 2048
MAX_DIRECTORY_SIZE = 64 * 1024 * 1024
MAX_ENTRIES = 1_000_000


def _both(data: bytes, offset: int, width: int) -> int:
    little = int.from_bytes(data[offset:offset + width], "little")
    big = int.from_bytes(data[offset + width:offset + 2 * width], "big")
    if little != big:
        raise ValueError("ISO9660 little/big-endian fields disagree")
    return little


@dataclass(frozen=True)
class Extent:
    offset: int
    size: int


@dataclass(frozen=True)
class IsoEntry:
    path: str
    extents: tuple[Extent, ...]
    interleaved: bool = False

    @property
    def size(self) -> int:
        return sum(extent.size for extent in self.extents)


class IsoImage:
    def __init__(self, source: BinaryIO):
        self.source = source
        source.seek(0, 2)
        self.size = source.tell()
        self.volume_size = self.size
        self.encrypted = False
        self.key = None
        self.plaintext = ()
        if self.size % SECTOR_SIZE:
            raise ValueError("ISO size is not a whole number of 2048-byte sectors")
        primary = None
        for sector in range(16, min(self.size // SECTOR_SIZE, 272)):
            record = self.read_at(sector * SECTOR_SIZE, SECTOR_SIZE)
            if record[1:7] != b"CD001\1":
                raise ValueError("expected ISO9660 volume descriptors")
            if record[0] == 1:
                primary = record
            if record[0] == 255:
                break
        else:
            raise ValueError("ISO9660 volume descriptor terminator is missing")
        if primary is None or _both(primary, 128, 2) != SECTOR_SIZE:
            raise ValueError("expected an ISO9660 primary volume with 2048-byte sectors")
        self.volume_size = _both(primary, 80, 4) * SECTOR_SIZE
        if not 17 * SECTOR_SIZE <= self.volume_size <= self.size:
            raise ValueError("invalid ISO9660 volume size")
        marker = self.read_at(SECTOR_SIZE, 16).rstrip(b"\0")
        if marker == b"PlayStation3":
            header = self.read_at(0, SECTOR_SIZE)
            count = int.from_bytes(header[:4], "big")
            if not 0 < count <= (SECTOR_SIZE - 8) // 8:
                raise ValueError("invalid PS3 plaintext-region count")
            ranges = [(int.from_bytes(header[8 + i * 8:12 + i * 8], "big"),
                       int.from_bytes(header[12 + i * 8:16 + i * 8], "big")) for i in range(count)]
            if any(start > end or end >= self.volume_size // SECTOR_SIZE for start, end in ranges):
                raise ValueError("invalid PS3 plaintext-sector range")
            validate_ranges([(start, end + 1) for start, end in ranges], "PS3 plaintext regions")
            self.plaintext = tuple(ranges)
        root = self._record(primary, 156)
        if not root or not root[3] & 2:
            raise ValueError("ISO9660 root is not a directory")
        self.entries = self._inventory(root[1])

    def read_at(self, offset: int, size: int) -> bytes:
        checked_range(offset, size, self.volume_size, "ISO")
        self.source.seek(offset)
        data = self.source.read(size)
        if len(data) != size:
            raise ValueError("truncated ISO read")
        return data

    def _record(self, data: bytes, offset: int):
        length = data[offset]
        if not length:
            return None
        if length < 34 or length > SECTOR_SIZE - offset % SECTOR_SIZE:
            raise ValueError("invalid ISO9660 directory record length")
        checked_range(offset, length, len(data), "ISO directory record")
        record = data[offset:offset + length]
        name_size = record[32]
        if not name_size or 33 + name_size > length:
            raise ValueError("invalid ISO9660 identifier")
        lba, size = _both(record, 2, 4), _both(record, 10, 4)
        if _both(record, 28, 2) != 1:
            raise ValueError("multi-volume ISO9660 entries are unsupported")
        extent = Extent((lba + record[1]) * SECTOR_SIZE, size)
        checked_range(extent.offset, extent.size, self.volume_size, "ISO extent")
        return length, extent, record[33:33 + name_size], record[25], bool(record[26] or record[27])

    def _inventory(self, root: Extent) -> dict[str, IsoEntry]:
        directories = [("", root)]
        seen = set()
        entries = {}
        count = 0
        while directories:
            prefix, directory = directories.pop()
            identity = directory.offset, directory.size
            if identity in seen or prefix.count("/") > 128:
                raise ValueError("cyclic or excessively deep ISO directories")
            seen.add(identity)
            if directory.size > MAX_DIRECTORY_SIZE:
                raise ValueError("ISO directory exceeds the supported size")
            data = self.read_at(directory.offset, directory.size)
            offset = 0
            pending = None
            while offset < len(data):
                record = self._record(data, offset)
                if record is None:
                    offset = (offset // SECTOR_SIZE + 1) * SECTOR_SIZE
                    continue
                length, extent, raw_name, flags, interleaved = record
                offset += length
                count += 1
                if count > MAX_ENTRIES:
                    raise ValueError("ISO directory entry limit exceeded")
                if raw_name in (b"\0", b"\1"):
                    continue
                try:
                    name = raw_name.decode("ascii")
                except UnicodeError as error:
                    raise ValueError("unsupported non-ASCII ISO identifier") from error
                stem, separator, version = name.rpartition(";")
                if separator and version.isdigit():
                    name = stem
                if not name or name in (".", "..") or any(char in name for char in ("/", "\\", "\0")):
                    raise ValueError("invalid ISO path component")
                path = prefix + name
                if pending:
                    if path != pending.path or flags & 2:
                        raise ValueError("incomplete multi-extent ISO file")
                    entry = IsoEntry(path, pending.extents + (extent,), pending.interleaved or interleaved)
                else:
                    entry = IsoEntry(path, (extent,), interleaved)
                pending = entry if flags & 0x80 else None
                if pending:
                    continue
                if flags & 2:
                    if interleaved:
                        raise ValueError("interleaved ISO directories are unsupported")
                    directories.append((path + "/", extent))
                else:
                    key = path.casefold()
                    if key in entries:
                        raise ValueError("duplicate ISO file path")
                    entries[key] = entry
            if pending:
                raise ValueError("incomplete multi-extent ISO file")
        return entries

    def configure(self, main: IsoEntry, key: bytes | None, mode: str = "auto") -> None:
        self.encrypted, self.key = False, None
        if mode not in ("auto", "plain", "encrypted"):
            raise ValueError("invalid disc mode")
        if key is not None and len(key) != 16:
            raise ValueError("a disc key must contain 16 bytes")
        if mode == "auto":
            header = self.read_file(main, 64)
            readable = header[:4] in (b"SCE\0", b"\x7fELF")
            lba = main.extents[0].offset // SECTOR_SIZE
            in_plaintext = any(start <= lba <= end for start, end in self.plaintext)
            all_plaintext = sum(end - start + 1 for start, end in self.plaintext) == self.volume_size // SECTOR_SIZE
            if readable and (not self.plaintext or not in_plaintext or all_plaintext):
                mode = "plain"
            elif readable and self.plaintext:
                raise ValueError("disc encryption is ambiguous; select --disc-mode plain or encrypted")
            elif self.plaintext and key is not None:
                mode = "encrypted"
            else:
                raise ValueError("executable header is unreadable; provide a disc key or a decrypted ISO")
        if mode == "encrypted" and (not self.plaintext or key is None):
            raise ValueError("encrypted disc reads require a PS3 region table and disc key")
        self.encrypted, self.key = mode == "encrypted", key
        if self.read_file(main, 64)[:4] not in (b"SCE\0", b"\x7fELF"):
            raise ValueError("disc mode or key does not produce a readable executable header")

    def read_file(self, entry: IsoEntry, size: int | None = None) -> bytes:
        if size is not None and size < 0:
            raise ValueError("negative ISO file read size")
        if entry.interleaved:
            raise ValueError("interleaved ISO files are unsupported")
        remaining = entry.size if size is None else min(size, entry.size)
        result = bytearray()
        for extent in entry.extents:
            length = min(remaining, extent.size)
            if not length:
                break
            if not self.encrypted:
                result.extend(self.read_at(extent.offset, length))
            else:
                for offset in range(0, length, SECTOR_SIZE):
                    position = extent.offset + offset
                    lba = position // SECTOR_SIZE
                    sector = self.read_at(position, SECTOR_SIZE)
                    if not any(start <= lba <= end for start, end in self.plaintext):
                        sector = decrypt(sector, self.key, lba.to_bytes(16, "big"), "cbc")
                    result.extend(sector[:min(SECTOR_SIZE, length - offset)])
            remaining -= length
        return bytes(result)
