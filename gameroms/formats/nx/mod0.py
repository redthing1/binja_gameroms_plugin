from __future__ import annotations

from dataclasses import dataclass
import struct


class Mod0ParseError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mod0Info:
    mod0_offset: int
    dynamic_offset: int
    bss_start: int
    bss_end: int
    eh_frame_hdr_start: int
    eh_frame_hdr_end: int
    runtime_module_offset: int
    libnx_got_start: int
    libnx_got_end: int

    @property
    def bss_size(self) -> int:
        return max(0, self.bss_end - self.bss_start)

    @property
    def has_libnx(self) -> bool:
        return self.libnx_got_end > self.libnx_got_start > 0


def find_mod0_offset(image: bytes, text_offset: int) -> int:
    if text_offset + 8 > len(image):
        raise Mod0ParseError("text offset outside image")
    mod0_off = struct.unpack_from("<I", image, text_offset + 4)[0]
    if mod0_off >= len(image):
        raise Mod0ParseError("MOD0 offset outside image")
    if image[mod0_off : mod0_off + 4] != b"MOD0":
        raise Mod0ParseError("MOD0 magic not found")
    return mod0_off


def parse_mod0(image: bytes, mod0_offset: int) -> Mod0Info:
    if mod0_offset + 0x20 > len(image):
        raise Mod0ParseError("MOD0 header truncated")
    if image[mod0_offset : mod0_offset + 4] != b"MOD0":
        raise Mod0ParseError("MOD0 magic not found")

    def rel32(off: int) -> int:
        return mod0_offset + struct.unpack_from("<I", image, off)[0]

    dynamic_offset = rel32(mod0_offset + 0x4)
    bss_start = rel32(mod0_offset + 0x8)
    bss_end = rel32(mod0_offset + 0xC)
    eh_frame_hdr_start = rel32(mod0_offset + 0x10)
    eh_frame_hdr_end = rel32(mod0_offset + 0x14)
    runtime_module_offset = rel32(mod0_offset + 0x18)

    lny_magic = image[mod0_offset + 0x1C : mod0_offset + 0x20]
    libnx_got_start = 0
    libnx_got_end = 0
    if lny_magic == b"LNY0":
        if mod0_offset + 0x28 > len(image):
            raise Mod0ParseError("MOD0 LNY0 header truncated")
        libnx_got_start = rel32(mod0_offset + 0x20)
        libnx_got_end = rel32(mod0_offset + 0x24)

    return Mod0Info(
        mod0_offset=mod0_offset,
        dynamic_offset=dynamic_offset,
        bss_start=bss_start,
        bss_end=bss_end,
        eh_frame_hdr_start=eh_frame_hdr_start,
        eh_frame_hdr_end=eh_frame_hdr_end,
        runtime_module_offset=runtime_module_offset,
        libnx_got_start=libnx_got_start,
        libnx_got_end=libnx_got_end,
    )
