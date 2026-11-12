#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "cryptography==50.0.2",
# ]
#
# [[tool.uv.index]]
# url = "https://pypi.org/simple"
# default = true
# ///
"""Prepare lean PS3 executable bundles from ELF/SELF files, directories or ISOs."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gameroms.formats.ps3.bundle import encode_bundle
from gameroms.formats.ps3.inputs import prepare_input


def _placement(value: str) -> tuple[str, list[int]]:
    try:
        name, numbers = value.split("=", 1)
        bases = [int(number, 0) for number in numbers.split(",")]
        if not name or not bases or any(base < 0 for base in bases):
            raise ValueError
        return name, bases
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected MODULE=BASE,BASE,... using PT_LOAD order") from error


def _key(path: Path | None) -> bytes | None:
    if path is None:
        return None
    data = path.read_bytes()
    if len(data) == 16:
        return data
    try:
        key = bytes.fromhex(data.decode("ascii").strip())
        if len(key) == 16:
            return key
    except (UnicodeError, ValueError):
        pass
    raise ValueError(f"{path.name}: expected a 16-byte key or 32 hexadecimal digits")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="main ELF/SELF, extracted game directory or ISO")
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--executable", help="main executable's relative path within a directory or ISO")
    parser.add_argument("--module", action="append", default=[], help="additional file or path within the input")
    parser.add_argument("--no-modules", action="store_false", dest="discover_modules",
                        help="include only the main executable and explicitly selected modules")
    parser.add_argument("--base", type=_placement, action="append", default=[],
                        help="explicit analysis placement, e.g. MODULE=0x20000000,0x21000000")
    parser.add_argument("--disc-key", type=Path, help="raw or hexadecimal 16-byte disc key file")
    parser.add_argument("--disc-mode", choices=("auto", "plain", "encrypted"), default="auto")
    parser.add_argument("--klicensee", type=Path, help="raw or hexadecimal 16-byte NPDRM klicensee file")
    parser.add_argument("--strict-integrity", action="store_true", help="also reject supplemental SELF HMAC mismatches")
    parser.add_argument("--spu-directory", type=Path, help="also write embedded SPU executables as independent ELF files")
    args = parser.parse_args()
    try:
        if len({name for name, _ in args.base}) != len(args.base):
            raise ValueError("duplicate module placement")
        prepared = prepare_input(args.input, executable=args.executable, modules=args.module,
                                 discover_modules=args.discover_modules, placements=dict(args.base),
                                 disc_key=_key(args.disc_key), disc_mode=args.disc_mode,
                                 klicensee=_key(args.klicensee), strict_integrity=args.strict_integrity)
        protected = {*prepared.input_paths, *(item.resolve() for item in (args.disc_key, args.klicensee) if item)}
        if args.output.resolve() in protected:
            raise ValueError("output must not replace an input executable, ISO or key file")
        program = prepared.program
        data = encode_bundle(program)
        spu_files = []
        if args.spu_directory:
            for module_index, (module, facts) in enumerate(zip(program.modules, program.facts)):
                for image_index, image in enumerate(facts.spu_images):
                    path = args.spu_directory / f"{module_index:02d}_{image_index:02d}_{image.address:x}.elf"
                    if path.exists() or path.resolve() == args.output.resolve():
                        raise ValueError(f"SPU output already exists or conflicts with the bundle: {path}")
                    spu_files.append((path, module.read(image.address, image.file_size)))
            args.spu_directory.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(data)
        for path, payload in spu_files:
            path.write_bytes(payload)
    except (OSError, ValueError) as error:
        parser.exit(1, f"ps3_to_ps3exe: {error}\n")
    resolved = sum(binding.target is not None for binding in program.bindings)
    module_label = "module" if len(program.modules) == 1 else "modules"
    print(f"{args.output}: {len(data):,} bytes, {len(program.modules)} {module_label}, "
          f"{program.relocation_count:,} relocations, {resolved} linked imports")
    if args.spu_directory:
        print(f"{args.spu_directory}: {len(spu_files)} SPU executables")
    for module in program.modules:
        for source in module.sources:
            if source.kind == "self":
                print(f"  {source.path}: load records: {source.verified_loads} verified, "
                      f"{source.unhashed_loads} unhashed; "
                      f"supplemental HMAC mismatches: {source.supplemental_mismatches}")
    if prepared.alternatives:
        print("Alternative main executables (select with --executable): " + ", ".join(prepared.alternatives))
    if prepared.other_machines:
        print("Other processor executables: " + ", ".join(prepared.other_machines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
