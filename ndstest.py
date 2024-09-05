from dataclasses import dataclass
import struct
from typing import List, Optional, Dict


@dataclass
class NDSCartridgeHeader:
    game_title: str
    gamecode: str
    makercode: str
    unitcode: int
    encryption_seed_select: int
    devicecapacity: int
    reserved1: bytes
    rom_version: int
    autostart: int
    arm9_rom_offset: int
    arm9_entry_address: int
    arm9_ram_address: int
    arm9_size: int
    arm7_rom_offset: int
    arm7_entry_address: int
    arm7_ram_address: int
    arm7_size: int
    fnt_offset: int
    fnt_size: int
    fat_offset: int
    fat_size: int
    arm9_overlay_offset: int
    arm9_overlay_size: int
    arm7_overlay_offset: int
    arm7_overlay_size: int
    port_40001a4_normal: int
    port_40001a4_key1: int
    icon_title_offset: int
    secure_area_checksum: int
    secure_area_delay: int
    arm9_auto_load_list_ram_address: int
    arm7_auto_load_list_ram_address: int
    secure_area_disable: bytes
    total_used_rom_size: int
    rom_header_size: int
    reserved2: bytes
    nintendo_logo: bytes
    nintendo_logo_checksum: int
    header_checksum: int
    debug_rom_offset: int
    debug_size: int
    debug_ram_address: int
    reserved3: int
    reserved4: bytes


@dataclass
class NDSOverlayEntry:
    overlay_id: int
    ram_address: int
    ram_size: int
    bss_size: int
    static_initializer_start_address: int
    static_initializer_end_address: int
    file_id: int
    reserved: int


@dataclass
class NDSOverlayTable:
    entries: List[NDSOverlayEntry]


@dataclass
class FATEntry:
    start_address: int
    end_address: int


@dataclass
class FNTDirectoryEntry:
    sub_table_offset: int
    first_file_id: int
    parent_directory_id: Optional[int]


@dataclass
class FNTFileEntry:
    name: str
    is_directory: bool
    directory_id: Optional[int]


def read_nds_cartridge_header(rom_file: str) -> NDSCartridgeHeader:
    with open(rom_file, "rb") as f:
        header_data = f.read(0x200)  # Read the entire header (512 bytes)

    header = NDSCartridgeHeader(
        game_title=header_data[:12].decode("ascii").rstrip("\x00"),
        gamecode=header_data[0xC:0x10].decode("ascii"),
        makercode=header_data[0x10:0x12].decode("ascii"),
        unitcode=header_data[0x12],
        encryption_seed_select=header_data[0x13],
        devicecapacity=header_data[0x14],
        reserved1=header_data[0x15:0x1E],
        rom_version=header_data[0x1E],
        autostart=header_data[0x1F],
        arm9_rom_offset=struct.unpack_from("<I", header_data, 0x20)[0],
        arm9_entry_address=struct.unpack_from("<I", header_data, 0x24)[0],
        arm9_ram_address=struct.unpack_from("<I", header_data, 0x28)[0],
        arm9_size=struct.unpack_from("<I", header_data, 0x2C)[0],
        arm7_rom_offset=struct.unpack_from("<I", header_data, 0x30)[0],
        arm7_entry_address=struct.unpack_from("<I", header_data, 0x34)[0],
        arm7_ram_address=struct.unpack_from("<I", header_data, 0x38)[0],
        arm7_size=struct.unpack_from("<I", header_data, 0x3C)[0],
        fnt_offset=struct.unpack_from("<I", header_data, 0x40)[0],
        fnt_size=struct.unpack_from("<I", header_data, 0x44)[0],
        fat_offset=struct.unpack_from("<I", header_data, 0x48)[0],
        fat_size=struct.unpack_from("<I", header_data, 0x4C)[0],
        arm9_overlay_offset=struct.unpack_from("<I", header_data, 0x50)[0],
        arm9_overlay_size=struct.unpack_from("<I", header_data, 0x54)[0],
        arm7_overlay_offset=struct.unpack_from("<I", header_data, 0x58)[0],
        arm7_overlay_size=struct.unpack_from("<I", header_data, 0x5C)[0],
        port_40001a4_normal=struct.unpack_from("<I", header_data, 0x60)[0],
        port_40001a4_key1=struct.unpack_from("<I", header_data, 0x64)[0],
        icon_title_offset=struct.unpack_from("<I", header_data, 0x68)[0],
        secure_area_checksum=struct.unpack_from("<H", header_data, 0x6C)[0],
        secure_area_delay=struct.unpack_from("<H", header_data, 0x6E)[0],
        arm9_auto_load_list_ram_address=struct.unpack_from("<I", header_data, 0x70)[0],
        arm7_auto_load_list_ram_address=struct.unpack_from("<I", header_data, 0x74)[0],
        secure_area_disable=header_data[0x78:0x80],
        total_used_rom_size=struct.unpack_from("<I", header_data, 0x80)[0],
        rom_header_size=struct.unpack_from("<I", header_data, 0x84)[0],
        reserved2=header_data[0x88:0xC0],
        nintendo_logo=header_data[0xC0:0x15C],
        nintendo_logo_checksum=struct.unpack_from("<H", header_data, 0x15C)[0],
        header_checksum=struct.unpack_from("<H", header_data, 0x15E)[0],
        debug_rom_offset=struct.unpack_from("<I", header_data, 0x160)[0],
        debug_size=struct.unpack_from("<I", header_data, 0x164)[0],
        debug_ram_address=struct.unpack_from("<I", header_data, 0x168)[0],
        reserved3=struct.unpack_from("<I", header_data, 0x16C)[0],
        reserved4=header_data[0x170:0x200],
    )
    return header


def read_overlay_table(rom_file: str, offset: int, size: int) -> NDSOverlayTable:
    entries = []
    with open(rom_file, "rb") as f:
        f.seek(offset)
        overlay_data = f.read(size)

    for i in range(0, len(overlay_data), 32):  # Each entry is 32 bytes
        entry = NDSOverlayEntry(
            overlay_id=struct.unpack_from("<I", overlay_data, i)[0],
            ram_address=struct.unpack_from("<I", overlay_data, i + 4)[0],
            ram_size=struct.unpack_from("<I", overlay_data, i + 8)[0],
            bss_size=struct.unpack_from("<I", overlay_data, i + 12)[0],
            static_initializer_start_address=struct.unpack_from(
                "<I", overlay_data, i + 16
            )[0],
            static_initializer_end_address=struct.unpack_from(
                "<I", overlay_data, i + 20
            )[0],
            file_id=struct.unpack_from("<I", overlay_data, i + 24)[0],
            reserved=struct.unpack_from("<I", overlay_data, i + 28)[0],
        )
        entries.append(entry)

    return NDSOverlayTable(entries)


def parse_fat(rom_data: bytes, fat_offset: int, fat_size: int) -> List[FATEntry]:
    fat_entries = []
    for i in range(0, fat_size, 8):
        start_address = int.from_bytes(
            rom_data[fat_offset + i : fat_offset + i + 4], "little"
        )
        end_address = int.from_bytes(
            rom_data[fat_offset + i + 4 : fat_offset + i + 8], "little"
        )
        if start_address != 0 or end_address != 0:
            fat_entries.append(FATEntry(start_address, end_address))
    return fat_entries


def parse_fnt(
    rom_data: bytes, fnt_offset: int, fnt_size: int
) -> Dict[int, FNTDirectoryEntry]:
    directory_entries = {}

    # Parse main table
    total_directories = int.from_bytes(
        rom_data[fnt_offset + 6 : fnt_offset + 8], "little"
    )

    for i in range(total_directories):
        offset = fnt_offset + i * 8
        sub_table_offset = int.from_bytes(rom_data[offset : offset + 4], "little")
        first_file_id = int.from_bytes(rom_data[offset + 4 : offset + 6], "little")

        if i == 0:  # Root directory
            parent_directory_id = None
        else:
            parent_directory_id = int.from_bytes(
                rom_data[offset + 6 : offset + 8], "little"
            )

        directory_entries[0xF000 + i] = FNTDirectoryEntry(
            sub_table_offset, first_file_id, parent_directory_id
        )

    return directory_entries


def parse_fnt_sub_table(
    rom_data: bytes, fnt_offset: int, sub_table_offset: int
) -> List[FNTFileEntry]:
    entries = []
    offset = fnt_offset + sub_table_offset

    while True:
        type_length = rom_data[offset]
        if type_length == 0:  # End of sub-table
            break

        is_directory = type_length & 0x80 != 0
        name_length = type_length & 0x7F

        name = rom_data[offset + 1 : offset + 1 + name_length].decode("ascii")
        offset += 1 + name_length

        if is_directory:
            directory_id = int.from_bytes(rom_data[offset : offset + 2], "little")
            offset += 2
            entries.append(FNTFileEntry(name, True, directory_id))
        else:
            entries.append(FNTFileEntry(name, False, None))

    return entries


def load_nds_rom(rom_file: str):
    header = read_nds_cartridge_header(rom_file)
    arm9_overlay_table = read_overlay_table(
        rom_file, header.arm9_overlay_offset, header.arm9_overlay_size
    )
    arm7_overlay_table = read_overlay_table(
        rom_file, header.arm7_overlay_offset, header.arm7_overlay_size
    )

    return header, arm9_overlay_table, arm7_overlay_table


import sys


def print_overlay_table(name: str, ovt: NDSOverlayTable):
    print(f"\n{name} Overlay Table:")
    print("=" * (len(name) + 15))
    for i, entry in enumerate(ovt.entries):
        print(f"Overlay {i}:")
        print(f"  Overlay ID: {entry.overlay_id}")
        print(f"  RAM Address: 0x{entry.ram_address:08X}")
        print(f"  RAM Size: 0x{entry.ram_size:08X}")
        print(f"  BSS Size: 0x{entry.bss_size:08X}")
        print(
            f"  Static Initializer Start: 0x{entry.static_initializer_start_address:08X}"
        )
        print(f"  Static Initializer End: 0x{entry.static_initializer_end_address:08X}")
        print(f"  File ID: {entry.file_id}")
        print(f"  Reserved: 0x{entry.reserved:08X}")
        print()


def print_file_system(
    directory_entries: Dict[int, FNTDirectoryEntry], rom_data: bytes, fnt_offset: int
):
    def print_directory(dir_id: int, indent: str = ""):
        dir_entry = directory_entries[dir_id]
        print(f"{indent}Directory ID: {dir_id:04X}")

        sub_table = parse_fnt_sub_table(
            rom_data, fnt_offset, dir_entry.sub_table_offset
        )
        for entry in sub_table:
            if entry.is_directory:
                print(f"{indent}  [{entry.name}]")
                print_directory(entry.directory_id, indent + "    ")
            else:
                print(f"{indent}  {entry.name}")

    print_directory(0xF000)  # Start with root directory


import sys


def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_nds_rom>")
        sys.exit(1)

    rom_file = sys.argv[1]
    rom_data = open(rom_file, "rb").read()
    header, arm9_ovt, arm7_ovt = load_nds_rom(rom_file)

    print("NDS ROM Header Information:")
    print("===========================")
    print(f"Game Title: {header.game_title}")
    print(f"Game Code: {header.gamecode}")
    print(f"Maker Code: {header.makercode}")
    print(f"Unit Code: {header.unitcode:02X}h")
    print(f"Encryption Seed Select: {header.encryption_seed_select:02X}h")
    print(f"Device Capacity: {header.devicecapacity:02X}h")
    print(f"ROM Version: {header.rom_version:02X}h")
    print(f"Autostart: {header.autostart:02X}h")

    print("\nARM9:")
    print(f"  ROM Offset: 0x{header.arm9_rom_offset:08X}")
    print(f"  Entry Address: 0x{header.arm9_entry_address:08X}")
    print(f"  RAM Address: 0x{header.arm9_ram_address:08X}")
    print(f"  Size: 0x{header.arm9_size:08X}")

    print("\nARM7:")
    print(f"  ROM Offset: 0x{header.arm7_rom_offset:08X}")
    print(f"  Entry Address: 0x{header.arm7_entry_address:08X}")
    print(f"  RAM Address: 0x{header.arm7_ram_address:08X}")
    print(f"  Size: 0x{header.arm7_size:08X}")

    print("\nFile Tables:")
    print(f"  FNT Offset: 0x{header.fnt_offset:08X}")
    print(f"  FNT Size: 0x{header.fnt_size:08X}")
    print(f"  FAT Offset: 0x{header.fat_offset:08X}")
    print(f"  FAT Size: 0x{header.fat_size:08X}")

    print("\nOverlay Tables:")
    print(f"  ARM9 Overlay Offset: 0x{header.arm9_overlay_offset:08X}")
    print(f"  ARM9 Overlay Size: 0x{header.arm9_overlay_size:08X}")
    print(f"  ARM7 Overlay Offset: 0x{header.arm7_overlay_offset:08X}")
    print(f"  ARM7 Overlay Size: 0x{header.arm7_overlay_size:08X}")

    print("\nPort 40001A4h Settings:")
    print(f"  Normal: 0x{header.port_40001a4_normal:08X}")
    print(f"  KEY1: 0x{header.port_40001a4_key1:08X}")

    print(f"\nIcon/Title Offset: 0x{header.icon_title_offset:08X}")
    print(f"Secure Area Checksum: 0x{header.secure_area_checksum:04X}")
    print(f"Secure Area Delay: 0x{header.secure_area_delay:04X}")

    print("\nAuto Load List RAM Addresses:")
    print(f"  ARM9: 0x{header.arm9_auto_load_list_ram_address:08X}")
    print(f"  ARM7: 0x{header.arm7_auto_load_list_ram_address:08X}")

    print(f"\nSecure Area Disable: {header.secure_area_disable.hex()}")
    print(f"Total Used ROM Size: 0x{header.total_used_rom_size:08X}")
    print(f"ROM Header Size: 0x{header.rom_header_size:08X}")

    print(f"\nNintendo Logo Checksum: 0x{header.nintendo_logo_checksum:04X}")
    print(f"Header Checksum: 0x{header.header_checksum:04X}")

    print("\nDebug Info:")
    print(f"  ROM Offset: 0x{header.debug_rom_offset:08X}")
    print(f"  Size: 0x{header.debug_size:08X}")
    print(f"  RAM Address: 0x{header.debug_ram_address:08X}")

    print("\nFile Allocation Table (FAT):")
    fat_entries = parse_fat(rom_data, header.fat_offset, header.fat_size)
    for i, entry in enumerate(fat_entries):
        print(
            f"File {i:04X}: Start: 0x{entry.start_address:08X}, End: 0x{entry.end_address:08X}"
        )

    print("\nFile Name Table (FNT):")
    directory_entries = parse_fnt(rom_data, header.fnt_offset, header.fnt_size)
    print_file_system(directory_entries, rom_data, header.fnt_offset)

    print(f"\nNumber of ARM9 Overlays: {len(arm9_ovt.entries)}")
    print(f"Number of ARM7 Overlays: {len(arm7_ovt.entries)}")

    print_overlay_table("ARM9", arm9_ovt)
    print_overlay_table("ARM7", arm7_ovt)


if __name__ == "__main__":
    main()
