"""NID labels without inferred API declarations."""

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def nid_names() -> dict[int, str]:
    candidates: dict[int, set[str]] = {}
    for line in Path(__file__).with_name("data").joinpath("nids.txt").read_text().splitlines():
        number, name = line.split(maxsplit=1)
        candidates.setdefault(int(number, 16), set()).add(name)
    return {nid: next(iter(names)) for nid, names in candidates.items() if len(names) == 1}


def entry_name(library: str, nid: int) -> str:
    return nid_names().get(nid, f"{library or 'module'}_nid_{nid:08x}")
