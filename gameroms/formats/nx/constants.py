from __future__ import annotations

import struct

NXEXE_MAGIC = b"NXEXE\x00\x00\x00"
NXEXE_VERSION = 1
NXEXE_HEADER_STRUCT = struct.Struct("<8sIIII")

AARCH64_BASE_ADDR = 0x7100000000
AARCH32_BASE_ADDR = 0x60000000
