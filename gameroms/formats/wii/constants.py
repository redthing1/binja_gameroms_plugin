from __future__ import annotations

import struct

WIIEXE_MAGIC = b"WIIEXE\x00\x00"
WIIEXE_VERSION = 1
WIIEXE_HEADER_STRUCT = struct.Struct("<8sIIII")

MEM1_BASE = 0x80000000
MEM1_END = 0x81800000
