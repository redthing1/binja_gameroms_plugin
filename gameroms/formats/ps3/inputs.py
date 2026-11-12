"""Discover executable inputs and normalize them into the shared module pipeline."""

from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
import hashlib
import os
from pathlib import Path, PurePosixPath
from typing import Callable

from .elf import PRX
from .iso import IsoImage
from .model import Source
from .prepare import Program, prepare_program
from .self import MAX_ELF_SIZE, executable_type, normalize


EXECUTABLE_SUFFIXES = {".bin", ".elf", ".self", ".sprx", ".prx"}


@dataclass(frozen=True)
class InputFile:
    path: str
    size: int
    read: Callable[[int | None], bytes]
    physical_path: Path | None = None
    extents: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class Prepared:
    program: Program
    alternatives: tuple[str, ...]
    other_machines: tuple[str, ...]
    input_paths: tuple[Path, ...]


def _read_file(path: Path, size: int | None = None) -> bytes:
    with path.open("rb") as stream:
        return stream.read() if size is None else stream.read(size)


def _file(path: Path, name: str | None = None) -> InputFile:
    return InputFile(name or path.name, path.stat().st_size, partial(_read_file, path), path)


def _directory_files(root: Path):
    count = 0
    for current, directories, filenames in os.walk(root):
        folder = Path(current)
        if len(folder.relative_to(root).parts) > 128:
            raise ValueError("executable directory nesting limit exceeded")
        directories.sort()
        for name in sorted(filenames):
            item = folder / name
            if item.suffix.casefold() in EXECUTABLE_SUFFIXES and item.is_file():
                count += 1
                if count > 1_000_000:
                    raise ValueError("executable candidate limit exceeded")
                yield _file(item, item.relative_to(root).as_posix())


@contextmanager
def _catalog(path: Path):
    if path.is_dir():
        yield sorted(_directory_files(path), key=lambda item: (item.path.casefold(), item.path)), None
    elif path.suffix.casefold() in (".iso", ".img"):
        with path.open("rb") as stream:
            image = IsoImage(stream)
            files = [InputFile(entry.path, entry.size, partial(image.read_file, entry),
                               extents=tuple((extent.offset, extent.size) for extent in entry.extents))
                     for entry in image.entries.values()
                     if PurePosixPath(entry.path).suffix.casefold() in EXECUTABLE_SUFFIXES]
            yield sorted(files, key=lambda item: (item.path.casefold(), item.path)), image
    else:
        yield [_file(path)], None


def _select(files: list[InputFile], executable: str | None, single: bool) -> InputFile:
    if executable:
        matches = [item for item in files if item.path.casefold() == executable.casefold()]
    elif single:
        matches = files
    else:
        matches = [item for item in files if ("/" + item.path.casefold()).endswith("/ps3_game/usrdir/eboot.bin")]
        if not matches:
            matches = [item for item in files if PurePosixPath(item.path).name.casefold() == "eboot.bin"]
    if len(matches) != 1:
        raise ValueError("main executable is missing or ambiguous; select its relative path with --executable")
    return matches[0]


def prepare_input(path: Path, *, executable: str | None = None, modules: list[str] | None = None,
                  discover_modules: bool = True, placements: dict[str, list[int]] | None = None,
                  disc_key: bytes | None = None, disc_mode: str = "auto", klicensee: bytes | None = None,
                  strict_integrity: bool = False) -> Prepared:
    with _catalog(path) as (files, disc):
        main = _select(files, executable, not path.is_dir() and disc is None)
        if disc:
            entry = disc.entries[main.path.casefold()]
            disc.configure(entry, disc_key, disc_mode)
        elif disc_key is not None or disc_mode != "auto":
            raise ValueError("disc keys and modes apply only to ISO inputs")
        requested = []
        for value in modules or []:
            matches = [item for item in files if item.path.casefold() == value.casefold()]
            if matches:
                requested.append(matches[0])
            elif Path(value).is_file():
                requested.append(_file(Path(value)))
            else:
                raise ValueError(f"module input not found: {value}")
        selected = [main, *requested]
        if discover_modules and (path.is_dir() or disc is not None):
            selected.extend(item for item in files if item not in selected)
        images, sources, names, cache = {}, {}, set(), {}
        alternatives, other_machines = [], []
        physical_paths = {path.resolve()}
        required = {main, *requested}
        seen = set()
        main_digest = None
        for item in selected:
            identity = item.path, item.physical_path.resolve() if item.physical_path else None
            if identity in seen:
                continue
            seen.add(identity)
            header = item.read(64)
            if header[:4] not in (b"SCE\0", b"\x7fELF"):
                if item in required:
                    raise ValueError(f"{item.path}: expected a PPU ELF or SELF header")
                continue
            if item.size > MAX_ELF_SIZE:
                raise ValueError(f"{item.path}: executable exceeds the supported size")
            data = item.read(None)
            if len(data) != item.size:
                raise ValueError(f"{item.path}: executable changed or was truncated during preparation")
            kind, machine = executable_type(data)
            if machine != 21:
                if item in required:
                    raise ValueError(f"{item.path}: expected a PPU executable")
                other_machines.append(item.path)
                continue
            digest = hashlib.sha256(data).hexdigest()
            if main_digest is not None and kind != PRX and item not in required and digest not in cache:
                alternatives.append(item.path)
                continue
            if digest not in cache:
                cache[digest] = normalize(PurePosixPath(item.path).stem, data,
                                          klicensee=klicensee, strict_integrity=strict_integrity)
            normalized = cache[digest]
            image = normalized.image
            if main_digest is None:
                main_digest = image.sha256
            if image.sha256 != main_digest and image.kind != PRX and item not in required:
                alternatives.append(item.path)
                continue
            if image.sha256 not in images:
                name = image.name
                if name in names:
                    name = str(PurePosixPath(item.path).with_suffix(""))
                base, ordinal = name, 2
                while name in names:
                    name = f"{base}_{ordinal}"
                    ordinal += 1
                image.name = name
                names.add(name)
                images[image.sha256] = image
                sources[image.sha256] = []
            integrity = normalized.integrity
            # External --module files have their own bytes, not an ISO extent.
            from_disc = disc is not None and item.physical_path is None
            sources[image.sha256].append(Source(
                item.path, digest, "self" if data[:4] == b"SCE\0" else "elf", item.size,
                path.name if from_disc else "", disc.size if from_disc else 0, item.extents,
                ("encrypted" if disc.encrypted else "plain") if from_disc else "",
                integrity.verified_loads, integrity.unhashed_loads, integrity.supplemental_mismatches,
                integrity.key_name))
            if item.physical_path:
                physical_paths.add(item.physical_path.resolve())
        program = prepare_program(list(images.values()), placements)
        for module in program.modules:
            module.sources = tuple(sources[module.source_hash])
            module.aliases = tuple(source.path for source in module.sources)
        return Prepared(program, tuple(alternatives), tuple(other_machines), tuple(sorted(physical_paths)))
