
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
+ [ ] planned: Wii (Nintendo Wii) binary (`powerpc`)

## usage

see [guides](./doc) for platform-specific instructions.

> for some consoles, the raw cartridge data can be quite huge.
> for those, instead of directly importing the cartridge, we use scripts (see guide) to pack only the executable and its metadata into a single file.
> the loader then loads this file and maps it into the binaryview.
> at the cost of having a slightly nonstandard format, we now are very space efficient, as we load only the executable data and still map it neatly into virtual address space.
