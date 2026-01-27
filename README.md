
# Game ROM Loader

Binary Ninja loader for some game ROMs.
Supports a lot of major consoles now.

## features

+ [x] GBA (GameBoy Advance) ROMs (`armv4`)
+ [x] NDS (Nintendo DS) ROMs (`armv4`/`armv5`)
+ [x] PSP (PlayStation Portable) ELF ([guide](doc/guide_psp.md)) (`mipsel32`)
+ [x] PS2 (PlayStation 2) ELF (`r5900l`)
+ [x] 3DS (Nintendo 3DS) CXI ([guide](doc/guide_3ds.md)) (`armv5`/`armv6`)
+ [x] Switch (Nintendo Switch) NSO0 ([guide](doc/guide_switch.md)) (`aarch64`)
+ [x] Wii (Nintendo Wii) Executable ([guide](doc/guide_wii.md)) (`ppc_ps`)

## usage

see [guides](./doc) for platform-specific instructions.

for some consoles, the raw cartridge data can be quite huge.
to avoid importing the full cartridge, which can be many GBs, we instead use scripts to pack custom containers (see guides), then write loaders for those containers.
at the cost of having a slightly nonstandard format, we now are very space efficient, as we load only the executable data and still map it neatly into virtual address space.
