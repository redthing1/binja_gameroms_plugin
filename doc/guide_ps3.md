# PlayStation 3

Install the native `binja-ps3-platform` plugin to analyze PPU and SPU executables.
Preparation runs independently with Python 3.11+ and uv.

## Prepare and open

Open normalized PPU ELF files with the **PS3 ELF** view. For SELF files, extracted
directories or ISOs, prepare a bundle and open it with **PS3 PS3EXE**:

```sh
uv run --locked --script tools/ps3_to_ps3exe.py game_directory -o game.ps3exe
uv run --locked --script tools/ps3_to_ps3exe.py game.iso --disc-key game.dkey -o game.ps3exe
uv run --locked --script tools/ps3_to_ps3exe.py EBOOT.BIN --module engine.sprx -o game.ps3exe
```

Directories and ISOs select `PS3_GAME/USRDIR/EBOOT.BIN` and discover PRX modules.
Bundles contain initialized loadable bytes, relocations and module metadata;
zero-fill and address gaps stay virtual, and unrelated assets are omitted.
Identical executable inputs share one payload.

| Option | Purpose |
| --- | --- |
| `--executable PATH` | Choose another main executable relative to the directory or ISO. |
| `--module PATH`, `--no-modules` | Add modules explicitly or disable automatic discovery. |
| `--disc-key FILE` | Supply a disc key as 16 raw bytes or 32 hexadecimal digits. |
| `--disc-mode plain`, `--disc-mode encrypted` | Resolve ambiguous disc-sector encryption detection. |
| `--klicensee FILE` | Supply a content key for NPDRM SELF files. |
| `--base MODULE=BASE,BASE,...` | Set PRX analysis addresses, one per `PT_LOAD` entry in header order, including empty entries. |
| `--strict-integrity` | Reject supplemental SELF HMAC mismatches as well as load-section mismatches. |

Fixed executables keep their addresses; PRX placements describe analysis memory.
Imports resolve by library, kind and NID. Unresolved imports retain their stubs.
Run the tool with `--help` for all options.

SELF normalization supports compressed and debug wrappers, using the included
metadata-key catalog. Disc-sector encryption is a separate layer; decrypted ISOs
need no disc key. NPDRM free-content and explicit-key handling currently have
synthetic-fixture coverage. Publisher signatures are not verified.
ISO support covers ISO9660, 2048-byte sectors and multi-extent files. Extract
archive-contained executables before preparation.

## Analysis

Views annotate sections, ELF symbols, descriptors, imports/exports and TLS
templates. Known NIDs receive names without inferred API prototypes. Native
analysis resolves validated descriptors and TOC contexts; byte edits invalidate
dependent results. Source identities and integrity summaries are available in
`ps3.modules` metadata.

Database saves retain user annotations and backed-byte edits. PS3EXE exports
update payload checksums and discard binding assertions invalidated by edits.

## SPU images

Write embedded workers during preparation:

```sh
uv run --locked --script tools/ps3_to_ps3exe.py game_directory -o game.ps3exe --spu-directory workers
```

Open each ELF normally with the native plugin installed. Each has independent
local-store mappings and its own database. Existing SPU output files are not
overwritten. Images requiring relocations need linking first.

A loaded PPU view can also open a worker directly:

```python
from binja_gameroms_plugin.gameroms.formats.ps3.view import open_spu_image

image = bv.query_metadata("ps3.spu_images")[0]
worker = open_spu_image(bv, image["address"])
worker.update_analysis_and_wait()
```

The worker's `ps3.spu_source` metadata records its parent module, source address
and original payload hash. See the native plugin's README for instruction/ABI
coverage and settings for existing SPU databases.

## Tests

```sh
uv export --script tools/ps3_to_ps3exe.py --locked > ps3-requirements.txt
uv run --no-project --with-requirements ps3-requirements.txt python -m unittest discover -s tests
```

View tests additionally require Binary Ninja and both installed plugins.
