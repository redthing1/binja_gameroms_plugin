from __future__ import annotations

from dataclasses import dataclass

from binaryninja import BinaryView, log_error


@dataclass(frozen=True)
class TagSpec:
    name: str
    icon: str


TAG_SPECS: dict[str, TagSpec] = {
    "Region": TagSpec(name="Region", icon="RG"),
    "Entry": TagSpec(name="Entry", icon="EN"),
    "MMIO": TagSpec(name="MMIO", icon="MM"),
    "Overlay": TagSpec(name="Overlay", icon="OV"),
    "Vector": TagSpec(name="Vector", icon="VC"),
}


def ensure_tag_type(bv: BinaryView, tag_name: str) -> str | None:
    spec = TAG_SPECS.get(tag_name)
    if spec is None:
        log_error(f"unknown tag type: {tag_name}")
        return None
    if bv.get_tag_type(spec.name) is None:
        bv.create_tag_type(spec.name, spec.icon)
    return spec.name


def add_tag(bv: BinaryView, addr: int, tag_name: str, data: str, user: bool = False) -> None:
    resolved_name = ensure_tag_type(bv, tag_name)
    if resolved_name is None:
        return
    for tag in bv.get_tags_at(addr, auto=None):
        if tag.type.name == resolved_name and tag.data == data:
            return
    bv.add_tag(addr, resolved_name, data, user=user)
