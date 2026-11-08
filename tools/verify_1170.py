"""Audit the MaxsuIFrame 1.6.1170 hook sites and selected virtual slots.

Requires Python 3 and capstone (pip install capstone). The audit reads the
plugin source, CommonLib declarations, the Address Library, and an unpacked
SkyrimSE 1.6.1170 executable. It does not launch or modify the game.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs


RUNTIME = (1, 6, 1170, 0)
TARGET_ID = 37275
EXPECTED_CALLS = [
    {"name": "IsGhost call 1", "id": 38627, "delta": 0x47},
    {"name": "IsGhost call 2", "id": 37725, "delta": 0x22},
    {"name": "IsGhost call 3", "id": 40504, "delta": 0x14},
]


def address_library(path: Path) -> dict[int, int]:
    data = path.read_bytes()
    at = 0

    def read(fmt: str) -> int | tuple[int, ...]:
        nonlocal at
        size = struct.calcsize("<" + fmt)
        values = struct.unpack_from("<" + fmt, data, at)
        at += size
        return values[0] if len(values) == 1 else values

    if read("I") not in (1, 2):
        raise ValueError("Unsupported Address Library format")
    version = read("4I")
    name_size = read("I")
    at += name_size
    pointer_size, count = read("2I")
    result: dict[int, int] = {}
    previous_id = previous_offset = 0

    def decode(code: int, previous: int) -> int:
        if code == 0:
            return read("Q")
        if code == 1:
            return previous + 1
        if code == 2:
            return previous + read("B")
        if code == 3:
            return previous - read("B")
        if code == 4:
            return previous + read("H")
        if code == 5:
            return previous - read("H")
        if code == 6:
            return read("H")
        if code == 7:
            return read("I")
        raise ValueError(f"Invalid Address Library entry code {code}")

    for _ in range(count):
        kind = read("B")
        entry_id = decode(kind & 0x0F, previous_id)
        high = kind >> 4
        offset = decode(high & 0x07, previous_offset // pointer_size if high & 0x08 else previous_offset)
        if high & 0x08:
            offset *= pointer_size
        result[entry_id] = offset
        previous_id, previous_offset = entry_id, offset

    if at != len(data) or version != RUNTIME or pointer_size != 8:
        raise ValueError("Expected the complete x64 Address Library for 1.6.1170.0")
    return result


class PEImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe : pe + 4] != b"PE\0\0":
            raise ValueError("Expected a PE executable")
        machine, section_count, optional_size = struct.unpack_from("<HH12xH", self.data, pe + 4)
        if machine != 0x8664 or struct.unpack_from("<H", self.data, pe + 24)[0] != 0x20B:
            raise ValueError("Expected an x64 PE32+ executable")
        self.image_base = struct.unpack_from("<Q", self.data, pe + 48)[0]
        self.sections: list[tuple[int, int, int, int]] = []
        self.section_details: list[dict] = []
        for index in range(section_count):
            at = pe + 24 + optional_size + index * 40
            virtual_size, rva, raw_size, raw = struct.unpack_from("<4I", self.data, at + 8)
            characteristics = struct.unpack_from("<I", self.data, at + 36)[0]
            self.sections.append((rva, raw_size, raw, characteristics))
            self.section_details.append(
                {
                    "name": self.data[at : at + 8].split(b"\0")[0].decode("ascii", "replace"),
                    "rva": rva,
                    "virtual_size": virtual_size,
                    "raw_size": raw_size,
                }
            )

    def read_rva(self, rva: int, length: int) -> bytes:
        for start, size, raw, _ in self.sections:
            if start <= rva and rva + length <= start + size:
                offset = raw + rva - start
                return self.data[offset : offset + length]
        raise ValueError(f"RVA {rva:#x} is not backed by file data")

    def is_executable_rva(self, rva: int) -> bool:
        return any(start <= rva < start + size and flags & 0x20000000 for start, size, _, flags in self.sections)

    def section_for_rva(self, rva: int) -> dict | None:
        return next(
            (section for section in self.section_details if section["rva"] <= rva < section["rva"] + section["virtual_size"]),
            None,
        )

    def is_file_backed_rva(self, rva: int) -> bool:
        return any(section["rva"] <= rva < section["rva"] + section["raw_size"] for section in self.section_details)


def source_line(path: Path, fragment: str) -> int:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if fragment in line:
            return number
    raise ValueError(f"Could not find {fragment!r} in {path}")


def vtable_ids(offsets_path: Path, name: str) -> list[int]:
    text = offsets_path.read_text(encoding="utf-8")
    match = re.search(rf"\bVTABLE_{re.escape(name)}\s*\{{([^}}]+)\}}", text)
    if not match:
        raise ValueError(f"Could not find VTABLE_{name} in {offsets_path}")
    variants = re.findall(r"REL::VariantID\(\s*\d+\s*,\s*(\d+)\s*,\s*0x[\da-fA-F]+\s*\)", match.group(1))
    if not variants:
        raise ValueError(f"Could not parse VTABLE_{name} runtime IDs")
    return [int(value) for value in variants]


def vtable_entry(image: PEImage, addresses: dict[int, int], entry_id: int, slot: int) -> dict:
    table_rva = addresses[entry_id]
    raw_value = struct.unpack("<Q", image.read_rva(table_rva + slot * 8, 8))[0]
    target_rva = raw_value - image.image_base
    return {
        "address_library_id": entry_id,
        "table_rva": hex(table_rva),
        "slot": slot,
        "byte_offset": hex(slot * 8),
        "pointer_value": hex(raw_value),
        "target_rva": hex(target_rva),
        "target_is_executable": image.is_executable_rva(target_rva),
    }


def nearby_instructions(image: PEImage, decoder: Cs, start_rva: int, call_rva: int) -> list[dict]:
    raw = image.read_rva(start_rva, call_rva - start_rva + 12)
    instructions = list(decoder.disasm(raw, image.image_base + start_rva))
    index = next((i for i, ins in enumerate(instructions) if ins.address == image.image_base + call_rva), None)
    if index is None:
        raise ValueError(f"Could not decode a call instruction at RVA {call_rva:#x}")
    return [
        {
            "rva": hex(ins.address - image.image_base),
            "bytes": ins.bytes.hex(" "),
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
        }
        for ins in instructions[max(0, index - 3) : index + 4]
    ]


def disassembly_window(image: PEImage, decoder: Cs, start_rva: int, count: int = 5) -> list[dict]:
    raw = image.read_rva(start_rva, 32)
    return [
        {
            "rva": hex(ins.address - image.image_base),
            "bytes": ins.bytes.hex(" "),
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
        }
        for ins in list(decoder.disasm(raw, image.image_base + start_rva))[:count]
    ]


def verify(executable: Path, library: Path, project_root: Path, commonlib_root: Path) -> dict:
    addresses = address_library(library)
    image = PEImage(executable)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = False
    errors: list[str] = []

    hooks_path = project_root / "src" / "Hooks.h"
    hook_source = hooks_path.read_text(encoding="utf-8")
    source_sites = [
        {"id": int(entry_id), "delta": int(delta, 0)}
        for entry_id, delta in re.findall(
            r"REL::ID\(\s*(\d+)\s*\)\.address\(\)\s*\+\s*(0x[\da-fA-F]+|\d+)", hook_source
        )
    ]
    expected_source_sites = [{"id": item["id"], "delta": item["delta"]} for item in EXPECTED_CALLS]
    source_target_match = re.search(
        r"\bisGhost\s*=\s*REL::ID\(\s*(\d+)\s*\)\.address\(\)", hook_source
    )
    source_target_id = int(source_target_match.group(1)) if source_target_match else None
    if source_sites != expected_source_sites:
        errors.append("src/Hooks.h IsGhost site IDs/offsets differ from the audited 1.6.1170 contract")
    if source_target_id != TARGET_ID:
        errors.append(f"src/Hooks.h target ID is {source_target_id}, expected {TARGET_ID}")
    if "write_call<5>(site, IsGhost)" not in hook_source:
        errors.append("src/Hooks.h no longer writes five-byte calls to IsGhost")

    actor_cpp = commonlib_root / "src" / "RE" / "A" / "Actor.cpp"
    commonlib_target_match = re.search(r"RELOCATION_ID\(\s*36286\s*,\s*(\d+)\s*\)", actor_cpp.read_text(encoding="utf-8"))
    commonlib_target_id = int(commonlib_target_match.group(1)) if commonlib_target_match else None
    if commonlib_target_id != TARGET_ID:
        errors.append(f"CommonLib Actor::IsGhost AE ID is {commonlib_target_id}, expected {TARGET_ID}")

    if TARGET_ID not in addresses:
        raise ValueError(f"Address Library does not contain IsGhost ID {TARGET_ID}")
    target_rva = addresses[TARGET_ID]
    call_sites = []
    for item in EXPECTED_CALLS:
        entry_id, delta = item["id"], item["delta"]
        if entry_id not in addresses:
            errors.append(f"Address Library does not contain site ID {entry_id}")
            continue
        function_rva = addresses[entry_id]
        call_rva = function_rva + delta
        code = image.read_rva(call_rva, 5)
        rel32_target = call_rva + 5 + struct.unpack_from("<i", code, 1)[0]
        valid = code[0] == 0xE8 and rel32_target == target_rva
        if not valid:
            errors.append(f"{item['name']} at RVA {call_rva:#x} does not E8-call ID {TARGET_ID} at {target_rva:#x}")
        call_sites.append(
            {
                **item,
                "function_rva": hex(function_rva),
                "rva": hex(call_rva),
                "bytes": code.hex(" "),
                "opcode_is_e8": code[0] == 0xE8,
                "rel32_target_rva": hex(rel32_target),
                "target_id": TARGET_ID,
                "target_id_rva": hex(target_rva),
                "valid": valid,
                "nearby_instructions": nearby_instructions(image, decoder, function_rva, call_rva),
            }
        )

    offsets_path = commonlib_root / "include" / "RE" / "Offsets_VTABLE.h"
    hk_ref_id = vtable_ids(offsets_path, "hkReferencedObject")[0]
    hkb_node_id = vtable_ids(offsets_path, "hkbNode")[0]
    hkb_clip_id = vtable_ids(offsets_path, "hkbClipGenerator")[0]
    ianim_id = vtable_ids(offsets_path, "IAnimationGraphManagerHolder")[0]
    tesobjref_ids = vtable_ids(offsets_path, "TESObjectREFR")
    actor_ids = vtable_ids(offsets_path, "Actor")
    if len(tesobjref_ids) < 4 or len(actor_ids) < 4:
        raise ValueError("Expected multiple-inheritance vtable entries for TESObjectREFR and Actor")

    hk_ref_get_class = vtable_entry(image, addresses, hk_ref_id, 1)
    hkb_node_get_class = vtable_entry(image, addresses, hkb_node_id, 1)
    hkb_clip_get_class = vtable_entry(image, addresses, hkb_clip_id, 1)
    ianim_get_manager = vtable_entry(image, addresses, ianim_id, 2)
    tesobjref_get_manager = vtable_entry(image, addresses, tesobjref_ids[3], 2)
    actor_get_manager = vtable_entry(image, addresses, actor_ids[3], 2)
    ianim_get_graph_var_bool = vtable_entry(image, addresses, ianim_id, 18)
    tesobjref_get_graph_var_bool = vtable_entry(image, addresses, tesobjref_ids[3], 18)
    actor_get_graph_var_bool = vtable_entry(image, addresses, actor_ids[3], 18)
    clip_function = int(hkb_clip_get_class["target_rva"], 16)
    clip_thunk_code = image.read_rva(clip_function, 5)
    clip_thunk_target = (
        clip_function + 5 + struct.unpack_from("<i", clip_thunk_code, 1)[0]
        if clip_thunk_code[0] == 0xE9
        else None
    )
    clip_type_code = image.read_rva(clip_thunk_target, 7) if clip_thunk_target is not None else b""
    clip_descriptor_rva = (
        clip_thunk_target + 7 + struct.unpack_from("<i", clip_type_code, 3)[0]
        if len(clip_type_code) == 7 and clip_type_code[:3] == b"\x48\x8d\x05"
        else None
    )
    clip_descriptor_section = image.section_for_rva(clip_descriptor_rva) if clip_descriptor_rva is not None else None
    clip_descriptor_file_backed = image.is_file_backed_rva(clip_descriptor_rva) if clip_descriptor_rva is not None else False
    get_class_slot_valid = (
        hk_ref_get_class["target_rva"] == hkb_node_get_class["target_rva"]
        and hkb_clip_get_class["target_is_executable"]
    )
    manager_slot_valid = tesobjref_get_manager["target_is_executable"] and actor_get_manager["target_is_executable"]
    graph_var_slot_valid = all(
        entry["target_is_executable"]
        for entry in (ianim_get_graph_var_bool, tesobjref_get_graph_var_bool, actor_get_graph_var_bool)
    )
    if not get_class_slot_valid:
        errors.append("GetClassType slot evidence does not agree across the Havok base/node/clip vtables")
    if not manager_slot_valid:
        errors.append("GetAnimationGraphManagerImpl slot 2 is not executable in the derived vtables")
    if not graph_var_slot_valid:
        errors.append("GetGraphVariableImpl3 slot 0x12 is not executable in the interface and derived vtables")

    headers = {
        "hkBaseObject_destructor_slot_00": {
            "path": "include/RE/H/hkBaseObject.h",
            "line": source_line(commonlib_root / "include/RE/H/hkBaseObject.h", "virtual ~hkBaseObject()"),
        },
        "hkReferencedObject_GetClassType_slot_01": {
            "path": "include/RE/H/hkReferencedObject.h",
            "line": source_line(commonlib_root / "include/RE/H/hkReferencedObject.h", "GetClassType() const;"),
        },
        "hkbNode_inherits_hkbBindable": {
            "path": "include/RE/H/hkbNode.h",
            "line": source_line(commonlib_root / "include/RE/H/hkbNode.h", "class hkbNode : public hkbBindable"),
        },
        "hkbBindable_inherits_hkReferencedObject": {
            "path": "include/RE/H/hkbBindable.h",
            "line": source_line(commonlib_root / "include/RE/H/hkbBindable.h", "class hkbBindable : public hkReferencedObject"),
        },
        "IAnimationGraphManagerHolder_GetAnimationGraphManagerImpl_slot_02": {
            "path": "include/RE/I/IAnimationGraphManagerHolder.h",
            "line": source_line(commonlib_root / "include/RE/I/IAnimationGraphManagerHolder.h", "GetAnimationGraphManagerImpl("),
        },
        "IAnimationGraphManagerHolder_GetGraphVariableImpl3_slot_12": {
            "path": "include/RE/I/IAnimationGraphManagerHolder.h",
            "line": source_line(commonlib_root / "include/RE/I/IAnimationGraphManagerHolder.h", "GetGraphVariableImpl3("),
        },
        "GetAnimationGraphManager_nonvirtual_wrapper": {
            "path": "include/RE/I/IAnimationGraphManagerHolder.h",
            "line": source_line(commonlib_root / "include/RE/I/IAnimationGraphManagerHolder.h", "bool GetAnimationGraphManager("),
        },
        "GetAnimationGraphManager_wrapper_dispatch": {
            "path": "src/RE/I/IAnimationGraphManagerHolder.cpp",
            "line": source_line(commonlib_root / "src/RE/I/IAnimationGraphManagerHolder.cpp", "return GetAnimationGraphManagerImpl(a_out);"),
        },
        "TESObjectREFR_IAnimationGraphManagerHolder_base_offset_38": {
            "path": "include/RE/T/TESObjectREFR.h",
            "line": source_line(commonlib_root / "include/RE/T/TESObjectREFR.h", "public IAnimationGraphManagerHolder"),
        },
        "TESObjectREFR_GetAnimationGraphManagerImpl_override_slot_02": {
            "path": "include/RE/T/TESObjectREFR.h",
            "line": source_line(commonlib_root / "include/RE/T/TESObjectREFR.h", "GetAnimationGraphManagerImpl("),
        },
    }

    return {
        "runtime": ".".join(map(str, RUNTIME)),
        "image_base": hex(image.image_base),
        "executable": {"name": executable.name, "sha256": hashlib.sha256(image.data).hexdigest()},
        "address_library": {
            "name": library.name,
            "sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
            "version": ".".join(map(str, RUNTIME)),
        },
        "source_contract": {
            "hooks_file": "src/Hooks.h",
            "sites": source_sites,
            "target_id": source_target_id,
            "commonlib_actor_is_ghost_ae_id": commonlib_target_id,
            "valid": source_sites == expected_source_sites and source_target_id == TARGET_ID and commonlib_target_id == TARGET_ID,
        },
        "is_ghost_target": {"address_library_id": TARGET_ID, "rva": hex(target_rva)},
        "call_sites": call_sites,
        "virtual_slots": {
            "havok_GetClassType": {
                "declared_slot": 1,
                "byte_offset": "0x8",
                "declaration_source": "header-only slot numbering; virtual dispatch slot contents read from PE vtables",
                "hkReferencedObject": hk_ref_get_class,
                "hkbNode": hkb_node_get_class,
                "hkbClipGenerator": hkb_clip_get_class,
                "hkbClipGenerator_target_disassembly": disassembly_window(image, decoder, clip_function, 1),
                "hkbClipGenerator_thunk_disassembly": (
                    disassembly_window(image, decoder, clip_thunk_target, 2)
                    if clip_thunk_target is not None
                    else []
                ),
                "hkbClipGenerator_descriptor_rva": hex(clip_descriptor_rva) if clip_descriptor_rva is not None else None,
                "hkbClipGenerator_descriptor_section": (
                    {
                        "name": clip_descriptor_section["name"],
                        "section_rva": hex(clip_descriptor_section["rva"]),
                        "virtual_size": hex(clip_descriptor_section["virtual_size"]),
                        "raw_size": hex(clip_descriptor_section["raw_size"]),
                        "descriptor_is_file_backed": clip_descriptor_file_backed,
                    }
                    if clip_descriptor_section is not None
                    else None
                ),
                "hkbClipGenerator_class_name_verified_from_pe": False,
                "hkbClipGenerator_class_name_limit": (
                    "GetClassType returns a descriptor address in virtual-only .data; its class-name pointer is not file-backed in this executable."
                    if clip_descriptor_section is not None and not clip_descriptor_file_backed
                    else "The class-name field was not independently decoded from the PE."
                ),
                "slot_consistent": get_class_slot_valid,
            },
            "animation_graph_manager": {
                "wrapper_is_virtual": False,
                "wrapper_dispatches_to_virtual": "GetAnimationGraphManagerImpl",
                "declared_virtual_slot": 2,
                "byte_offset": "0x10",
                "interface_vtable_entry": ianim_get_manager,
                "TESObjectREFR_interface_subtable_entry": tesobjref_get_manager,
                "Actor_interface_subtable_entry": actor_get_manager,
                "derived_vtable_slots_executable": manager_slot_valid,
            },
            "GetGraphVariableImpl3": {
                "declared_virtual_slot": 18,
                "header_slot_comment": "0x12",
                "byte_offset": "0x90",
                "interface_vtable_entry": ianim_get_graph_var_bool,
                "TESObjectREFR_interface_subtable_entry": tesobjref_get_graph_var_bool,
                "Actor_interface_subtable_entry": actor_get_graph_var_bool,
                "Actor_target_disassembly": disassembly_window(
                    image, decoder, int(actor_get_graph_var_bool["target_rva"], 16), 5
                ),
                "slots_are_executable": graph_var_slot_valid,
            },
        },
        "abi_header_facts": {
            "evidence_type": "CommonLib declarations and static_asserts only; not independently proven from executable layout",
            "sources": headers,
            "hkBaseObject_size": "0x8",
            "hkReferencedObject_size": "0x10",
            "hkReferencedObject_fields": {"memSizeAndFlags": "0x08", "referenceCount": "0x0A"},
            "IAnimationGraphManagerHolder_size": "0x8",
            "TESObjectREFR_IAnimationGraphManagerHolder_base_offset": "0x38",
        },
        "limitations": [
            "PE checks validate bytes, direct-call targets, and vtable pointer slots for this exact executable; they do not execute the plugin or prove runtime object validity.",
            "CommonLib slot comments and static_asserts are declaration evidence. Vtable subobject association follows the declared inheritance and generated vtable order.",
            "The audit does not establish SKSE loader behavior or gameplay correctness; no game process is started.",
        ],
        "errors": errors,
        "valid": not errors and len(call_sites) == len(EXPECTED_CALLS) and get_class_slot_valid and manager_slot_valid and graph_var_slot_valid,
    }


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path, help="unpacked SkyrimSE-1.6.1170.exe")
    parser.add_argument("address_library", type=Path, help="versionlib-1-6-1170-0.bin")
    parser.add_argument(
        "--commonlib-root",
        type=Path,
        default=project_root.parent / "CommonLibSSE-NG-ng",
        help="CommonLibSSE-NG checkout (default: sibling CommonLibSSE-NG-ng)",
    )
    parser.add_argument("--output", type=Path, help="write the full JSON audit to this path")
    args = parser.parse_args()

    try:
        result = verify(args.executable, args.address_library, project_root, args.commonlib_root)
    except (OSError, ValueError, KeyError, struct.error) as exc:
        parser.error(str(exc))
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(
        f"MaxsuIFrame 1.6.1170 audit: {'PASS' if result['valid'] else 'FAIL'}; "
        f"{len(result['call_sites'])} IsGhost callsites, 3 virtual-slot checks"
    )
    if not result["valid"]:
        for error in result["errors"]:
            print(f"ERROR: {error}")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
