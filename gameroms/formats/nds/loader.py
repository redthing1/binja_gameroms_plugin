from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Optional

from binaryninja import log_error

from .decompress import mii_uncompress_backward
from .model import NdsBinary, NdsImage, NdsOverlayInfo
from .parse import (
    ModuleParamsInfo,
    NITRO_SDK_MODULE_PARAMS_MAGIC_OFFSET,
    NITRO_SDK_MODULE_PARAMS_SIZE,
    parse_module_params,
)

NITRO_FOOTER_MAGIC = 0xDEC00621


@dataclass(frozen=True)
class LoadedBinary:
    data: bytes
    rom_offset: int
    rom_size: int
    load_addr: int
    entry: int
    effective_size: int
    decompressed: bool
    bss_start: Optional[int]
    bss_size: Optional[int]
    module_params: Optional[ModuleParamsInfo]


def _parse_module_params_at(data: bytes, offset: int) -> Optional[ModuleParamsInfo]:
    if offset < 0:
        return None
    end = offset + NITRO_SDK_MODULE_PARAMS_SIZE
    if end > len(data):
        return None
    try:
        autoload_end = struct.unpack_from("<I", data, offset + 8)[0]
        bss_start = struct.unpack_from("<I", data, offset + 12)[0]
        bss_end = struct.unpack_from("<I", data, offset + 16)[0]
        compressed_static_end = struct.unpack_from("<I", data, offset + 20)[0]
        return ModuleParamsInfo(
            autoload_end_addr=autoload_end,
            compressed_static_end_marker=compressed_static_end,
            bss_start=bss_start,
            bss_end=bss_end,
        )
    except struct.error:
        return None


def _module_params_from_footer(data: bytes) -> Optional[ModuleParamsInfo]:
    if len(data) < 12:
        return None
    try:
        footer_magic = struct.unpack_from("<I", data, len(data) - 12)[0]
    except struct.error:
        return None
    if footer_magic != NITRO_FOOTER_MAGIC:
        return None
    try:
        offset = struct.unpack_from("<I", data, len(data) - 8)[0]
    except struct.error:
        return None
    return _parse_module_params_at(data, offset)


def extract_module_params(data: bytes) -> Optional[ModuleParamsInfo]:
    module_params = _module_params_from_footer(data)
    if module_params is not None:
        return module_params
    return parse_module_params(data)


def load_main_binary(image: NdsImage, cpu: str) -> Optional[LoadedBinary]:
    info: NdsBinary
    cpu_lower = cpu.lower()
    if cpu_lower == "arm9":
        info = image.arm9
    elif cpu_lower == "arm7":
        info = image.arm7
    else:
        log_error(f"[NDS] unknown cpu name: {cpu}")
        return None

    if info.rom_size <= 0:
        return None

    raw_data = image.raw.read(info.rom_offset, info.rom_size)
    if len(raw_data) != info.rom_size:
        log_error(f"[NDS {cpu}] failed to read main binary")
        return None

    effective_size = info.rom_size
    decompressed_data: Optional[bytes] = None
    bss_start: Optional[int] = None
    bss_size: Optional[int] = None
    module_params: Optional[ModuleParamsInfo] = None

    if cpu_lower == "arm9":
        module_params = extract_module_params(raw_data)
        if module_params is not None:
            expected_size = module_params.autoload_end_addr - info.ram_address
            if expected_size >= info.rom_size and expected_size < info.rom_size * 25:
                effective_size = expected_size
            compressed_marker = module_params.compressed_static_end_marker
            compressed = False
            if compressed_marker != 0:
                upper = info.ram_address + (info.rom_size * 25)
                if info.ram_address <= compressed_marker < upper:
                    compressed = True
            if compressed:
                try:
                    decompressed_data = mii_uncompress_backward(raw_data)
                    effective_size = len(decompressed_data)
                except Exception as exc:
                    log_error(f"[NDS ARM9] decompression failed: {exc}")
                    decompressed_data = None
            if module_params.bss_end > module_params.bss_start:
                candidate_size = module_params.bss_end - module_params.bss_start
                if (
                    module_params.bss_start >= info.ram_address
                    and candidate_size < 0x10000000
                ):
                    bss_start = module_params.bss_start
                    bss_size = candidate_size

    return LoadedBinary(
        data=decompressed_data if decompressed_data is not None else raw_data,
        rom_offset=info.rom_offset,
        rom_size=info.rom_size,
        load_addr=info.ram_address,
        entry=info.entry_address,
        effective_size=effective_size,
        decompressed=decompressed_data is not None,
        bss_start=bss_start,
        bss_size=bss_size,
        module_params=module_params,
    )


def load_overlay_bytes(image: NdsImage, overlay: NdsOverlayInfo) -> bytes:
    size = overlay.file_size
    if size <= 0:
        return b""
    raw_data = image.raw.read(overlay.file_start, size)
    if len(raw_data) != size:
        log_error(
            f"[NDS] overlay {overlay.overlay_id} read failed ({len(raw_data)} != {size})"
        )
        return raw_data
    if overlay.is_compressed and raw_data:
        try:
            return mii_uncompress_backward(raw_data)
        except Exception as exc:
            log_error(f"[NDS] overlay {overlay.overlay_id} decompression failed: {exc}")
    return raw_data


def overlay_effective_size(overlay: NdsOverlayInfo, data: bytes) -> int:
    if overlay.ram_size > 0:
        return overlay.ram_size
    if data:
        return len(data)
    return overlay.file_size


def pad_overlay_data(data: bytes, effective_size: int) -> bytes:
    if len(data) >= effective_size:
        return data[:effective_size]
    return data + (b"\x00" * (effective_size - len(data)))
