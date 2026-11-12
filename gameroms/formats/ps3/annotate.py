"""Apply module facts through Binary Ninja's public annotation API."""

from dataclasses import asdict

import binaryninja as bn

from .names import entry_name
from .prepare import Program


def _symbol(view, kind, address, name):
    view.define_auto_symbol(bn.Symbol(kind, address, name))


def annotate_import_symbols(view: bn.BinaryView, program: Program) -> None:
    for binding in program.bindings:
        name = entry_name(binding.library, binding.nid) + "_import_slot"
        # Keep one automatic slot label; user symbols and types take precedence.
        for symbol in view.get_symbols(binding.slot, 1):
            if symbol.auto and symbol.type == bn.SymbolType.DataSymbol and symbol.raw_name == name:
                view.undefine_auto_symbol(symbol)
        _symbol(view, bn.SymbolType.ImportAddressSymbol, binding.slot, name)


def annotate_program(view: bn.BinaryView, program: Program) -> None:
    opd_type, _ = view.parse_type_string("struct { void *code; void *toc; }")
    word = bn.Type.int(4, False)
    for module, facts in zip(program.modules, program.facts):
        descriptors = {item.address: item for item in facts.descriptors}
        tables = module.descriptor_sections
        for section in tables:
            view.define_data_var(section.address, bn.Type.array(opd_type, section.size // 8), module.name + "_opd")
        for item in facts.descriptors:
            if not any(section.address <= item.address < section.address + section.size for section in tables):
                view.define_data_var(item.address, opd_type)
            _symbol(view, bn.SymbolType.DataSymbol, item.address, f"{module.name}_opd_{item.address:08x}")
            _symbol(view, bn.SymbolType.FunctionSymbol, item.code, f"{module.name}_sub_{item.code:08x}")
            view.add_user_data_ref(item.address, item.code)
            view.add_user_data_ref(item.address + 4, item.toc)
        for template in module.tls:
            view.set_comment_at(template.address,
                                f"TLS initialization template: {template.file_size} initialized bytes; "
                                f"{template.memory_size} bytes per thread.")
        for library in facts.linkage.exports:
            for entry in library.functions:
                item = descriptors[entry.value]
                name = entry_name(library.name, entry.nid)
                _symbol(view, bn.SymbolType.DataSymbol, item.address, name + "_opd")
                _symbol(view, bn.SymbolType.FunctionSymbol, item.code, name)
            for entry in library.variables:
                _symbol(view, bn.SymbolType.DataSymbol, entry.value, entry_name(library.name, entry.nid))
        for symbol in module.symbols:
            binding = {0: bn.SymbolBinding.LocalBinding, 1: bn.SymbolBinding.GlobalBinding,
                       2: bn.SymbolBinding.WeakBinding}.get(symbol.binding, bn.SymbolBinding.NoBinding)
            item = descriptors.get(symbol.address) if symbol.is_descriptor else None
            if item:
                view.define_auto_symbol(bn.Symbol(bn.SymbolType.DataSymbol, item.address,
                                                 symbol.name + "_opd", binding=binding))
                view.define_auto_symbol(bn.Symbol(bn.SymbolType.FunctionSymbol, item.code,
                                                 symbol.name, binding=binding))
            else:
                executable = module.locate(symbol.address)[0].flags & 1
                kind = bn.SymbolType.FunctionSymbol if symbol.kind == 2 and executable else bn.SymbolType.DataSymbol
                view.define_auto_symbol(bn.Symbol(kind, symbol.address, symbol.name, binding=binding))
    by_name = {module.name: module for module in program.modules}
    for binding in program.bindings:
        name = entry_name(binding.library, binding.nid)
        view.define_data_var(binding.slot, word)
        view.set_comment_at(binding.slot, f"{binding.library} {binding.kind} import, NID {binding.nid:08x}")
        if binding.descriptor:
            item = binding.descriptor
            pointer = bn.Type.pointer_of_width(4, opd_type, const=True)
            view.define_data_var(binding.slot, pointer)
            view.add_user_data_ref(binding.slot, item.address)
            for patch in binding.fixups[1:]:
                view.add_user_data_ref(patch.address, item.address)
        elif binding.target is not None:
            for patch in binding.fixups:
                view.add_user_data_ref(patch.address, binding.target)
        elif binding.kind == "function" and binding.original_value % 4 == 0:
            module = by_name[binding.importer]
            try:
                segment, _ = module.locate(binding.original_value, 4)
            except ValueError:
                continue
            if segment.flags & 1:
                _symbol(view, bn.SymbolType.FunctionSymbol, binding.original_value, name)


def context_metadata(program: Program) -> dict:
    tocs = program.function_tocs
    descriptors = {}
    records = {}
    for facts in program.facts:
        for item in facts.descriptors:
            descriptors.setdefault(str(item.code), []).append(item.address)
            records[str(item.address)] = {"code": item.code, "toc": item.toc}
    bindings = {str(binding.slot): {"descriptor": binding.descriptor.address,
                                    "code": binding.descriptor.code, "toc": binding.descriptor.toc}
                for binding in program.bindings if binding.descriptor is not None}
    return {"version": 1, "tocs": {str(address): toc for address, toc in tocs.items()},
            "toc_descriptors": descriptors, "descriptors": records, "bindings": bindings}


def spu_metadata(program: Program) -> list[dict]:
    return [{"module": module.name, "address": image.address, "size": image.file_size,
             "entry": image.entry, "name": image.name, "payload_sha256": image.payload_hash}
            for module, facts in zip(program.modules, program.facts) for image in facts.spu_images]


def module_metadata(program: Program) -> dict:
    return {"version": 1, "modules": [
        {"name": module.name, "aliases": list(module.aliases), "normalized_sha256": module.source_hash,
         "sources": [asdict(source) for source in module.sources],
         "segments": [{"address": segment.address, "file_size": len(segment.data),
                       "memory_size": segment.memory_size, "flags": segment.flags}
                      for segment in module.segments]}
        for module in program.modules]}
