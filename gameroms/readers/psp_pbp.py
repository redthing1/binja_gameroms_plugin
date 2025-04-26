from dataclasses import dataclass
import struct
from typing import List, Optional, Dict


@dataclass
class PBPHeader:
    signature: str  # "PBP\x00" signature
    version: int  # PBP version (usually 0x10000)
    param_sfo_offset: int
    icon0_offset: int
    icon1_offset: int
    pic0_offset: int
    pic1_offset: int
    snd0_offset: int
    psp_data_offset: int  # PSP executable data offset
    psar_offset: int  # PSAR data offset


class PBPReader:
    @staticmethod
    def read(data: bytes) -> dict:
        """Read a PBP file and return its components"""
        if len(data) < 0x28:  # PBP header size
            raise ValueError("Data too small for PBP header")

        header = PBPReader._parse_header(data)

        # calculate section sizes
        sections = {
            "param_sfo": (
                header.param_sfo_offset,
                header.icon0_offset - header.param_sfo_offset,
            ),
            "icon0": (header.icon0_offset, header.icon1_offset - header.icon0_offset),
            "icon1": (header.icon1_offset, header.pic0_offset - header.icon1_offset),
            "pic0": (header.pic0_offset, header.pic1_offset - header.pic0_offset),
            "pic1": (header.pic1_offset, header.snd0_offset - header.pic1_offset),
            "snd0": (header.snd0_offset, header.psp_data_offset - header.snd0_offset),
            "psp_data": (
                header.psp_data_offset,
                header.psar_offset - header.psp_data_offset,
            ),
            "psar": (header.psar_offset, len(data) - header.psar_offset),
        }

        # extract data sections
        result = {"header": header}
        for name, (offset, size) in sections.items():
            if size > 0:
                result[name] = data[offset : offset + size]
            else:
                result[name] = b""

        return result

    @staticmethod
    def _parse_header(data: bytes) -> PBPHeader:
        """Parse PBP header from data"""
        signature = data[0:4].decode("ascii", errors="replace")
        if signature != "PBP\x00":
            raise ValueError(f"Invalid PBP signature: {signature}")

        return PBPHeader(
            signature=signature,
            version=struct.unpack_from("<I", data, 4)[0],
            param_sfo_offset=struct.unpack_from("<I", data, 8)[0],
            icon0_offset=struct.unpack_from("<I", data, 12)[0],
            icon1_offset=struct.unpack_from("<I", data, 16)[0],
            pic0_offset=struct.unpack_from("<I", data, 20)[0],
            pic1_offset=struct.unpack_from("<I", data, 24)[0],
            snd0_offset=struct.unpack_from("<I", data, 28)[0],
            psp_data_offset=struct.unpack_from("<I", data, 32)[0],
            psar_offset=struct.unpack_from("<I", data, 36)[0],
        )

    @staticmethod
    def is_valid(data: bytes) -> bool:
        """Check if data is a valid PBP file"""
        if len(data) < 4:
            return False
        return data[0:4] == b"PBP\x00"
