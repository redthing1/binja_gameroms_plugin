from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DemangledName:
    name: str
    namespace: list[str]


_OPERATOR_MAP = {
    "nw": "operator new",
    "nwa": "operator new[]",
    "dl": "operator delete",
    "dla": "operator delete[]",
    "pl": "operator +",
    "mi": "operator -",
    "ml": "operator *",
    "dv": "operator /",
    "md": "operator %",
    "er": "operator ^",
    "ad": "operator &",
    "or": "operator |",
    "co": "operator ~",
    "nt": "operator !",
    "as": "operator =",
    "lt": "operator <",
    "gt": "operator >",
    "apl": "operator +=",
    "ami": "operator -=",
    "amu": "operator *=",
    "adv": "operator /=",
    "amd": "operator %=",
    "aer": "operator ^=",
    "aad": "operator &=",
    "aor": "operator |=",
    "ls": "operator <<",
    "rs": "operator >>",
    "ars": "operator >>=",
    "als": "operator <<=",
    "eq": "operator ==",
    "ne": "operator !=",
    "le": "operator <=",
    "ge": "operator >=",
    "aa": "operator &&",
    "oo": "operator ||",
    "pp": "operator ++",
    "mm": "operator --",
    "cl": "operator ()",
    "vc": "operator []",
    "rf": "operator ->",
    "cm": "operator ,",
    "rm": "operator ->*",
}


def _parse_number(text: str, start: int) -> tuple[int, int]:
    value = 0
    pos = start
    while pos < len(text) and text[pos].isdigit():
        value = value * 10 + (ord(text[pos]) - ord("0"))
        pos += 1
    return value, pos


def _parse_qualified(text: str, start: int) -> tuple[list[str], int]:
    if start >= len(text):
        return [], start
    if text[start] == "Q":
        count, pos = _parse_number(text, start + 1)
        names: list[str] = []
        for _ in range(count):
            length, pos = _parse_number(text, pos)
            if length <= 0 or pos + length > len(text):
                break
            names.append(text[pos : pos + length])
            pos += length
        return names, pos

    if text[start].isdigit():
        length, pos = _parse_number(text, start)
        if length > 0 and pos + length <= len(text):
            return [text[pos : pos + length]], pos + length

    return [], start


def demangle_codewarrior(name: str) -> DemangledName | None:
    if "__" not in name:
        return None

    if name.startswith("@"):
        last = name.rfind("@")
        if last != -1 and last + 1 < len(name):
            name = name[last + 1 :]

    dunder = name.find("__", 1)
    if dunder < 0:
        return None

    while dunder + 2 < len(name) and name[dunder + 2] == "_":
        dunder += 1

    func_name = name[:dunder]
    rest = name[dunder + 2 :]
    if not rest:
        return None

    pos = 0
    if rest.startswith(("C", "c")) and len(rest) > 1:
        pos = 1

    namespace: list[str] = []
    if pos < len(rest) and rest[pos] != "F":
        namespace, pos = _parse_qualified(rest, pos)

    if func_name.startswith("__"):
        op_key = func_name[2:]
        op_name = _OPERATOR_MAP.get(op_key)
        if op_name:
            func_name = op_name

    if func_name == "__ct" and namespace:
        func_name = namespace[-1]
    elif func_name == "__dt" and namespace:
        func_name = "~" + namespace[-1]

    return DemangledName(name=func_name, namespace=namespace)
