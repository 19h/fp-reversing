#!/usr/bin/env python3
"""Verify selector 22 and 23 results across the pinned and current collections."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from audit_live_kext_selector26 import (
    Collection, DRIVER, IDENTITIES, PROVIDER, method_map, mig_map, synchronous_path,
)
from resolve_kernel_collection_interfaces import commands


MASK = (1 << 64) - 1
POOL_DELTA = 0x16aa0
BANK_DELTA = 0xa2c0
CONTROLLER_DELTA = 0x7fde0
OLD_POOL = 0xfffffe0008471f00
OLD_TABLE = 0xfffffe0008472f20
OLD_GUARD_SLOT = 0xfffffe000847c5f8
RECEIPT = Path(__file__).with_name("kext_query_getter_values_source.json.zst")

# Each triple identifies the page instruction, use, and corresponding original
# address. The two controller reloads reuse the earlier page-base registers.
REFERENCES = {
    "version_getter": [
        (0x10, 0x14, OLD_GUARD_SLOT), (0x1ec, 0x1f0, OLD_GUARD_SLOT),
        (0x20, 0x24, 0xfffffe000ccc3368), (0x20, 0x18c, 0xfffffe000ccc3368),
        (0x28, 0x2c, 0xfffffe000ccc32f8), (0x28, 0x190, 0xfffffe000ccc32f8),
        (0x54, 0x58, 0xfffffe0007949dd0), (0x6c, 0x70, 0xfffffe000792fbc0),
        (0x84, 0x88, OLD_POOL),
        (0x1a0, 0x1a4, 0xfffffe000792fcc0), (0x1b4, 0x1b8, 0xfffffe00079391f0),
    ],
    "capability_getter": [
        (0x10, 0x14, OLD_GUARD_SLOT), (0x1c4, 0x1c8, OLD_GUARD_SLOT),
        (0x20, 0x24, 0xfffffe000ccc3670), (0x20, 0x160, 0xfffffe000ccc3670),
        (0x28, 0x2c, 0xfffffe000ccc32f8), (0x28, 0x164, 0xfffffe000ccc32f8),
        (0x50, 0x54, 0xfffffe000792fcc0), (0x68, 0x6c, 0xfffffe00079391f0),
        (0x84, 0x88, OLD_POOL),
        (0xa0, 0xa4, 0xfffffe0007949dd0), (0xb8, 0xbc, 0xfffffe000792fbc0),
        (0x174, 0x178, 0xfffffe0007949fd0), (0x18c, 0x190, 0xfffffe000792ffc0),
    ],
    "version_adapter": [
        (0x18, 0x1c, OLD_GUARD_SLOT), (0x210, 0x214, OLD_GUARD_SLOT),
        (0x28, 0x2c, 0xfffffe000ccc7790), (0x28, 0x1bc, 0xfffffe000ccc7790),
        (0x30, 0x34, 0xfffffe000ccc32f8), (0x30, 0x1c0, 0xfffffe000ccc32f8),
        (0x5c, 0x60, 0xfffffe0007949dd0), (0x70, 0x74, 0xfffffe000792fbc0),
        (0x88, 0x8c, OLD_POOL),
    ],
}
SELECTORS = {
    22: ("ucGetVersion", 0x8c0, 0xc54a, "version_getter", "_V2F1SYee"),
    23: ("ucGetProtocolCapabilities", 0x8c8, 0xb3ee, "capability_getter", "_QIWEiU"),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def function_bounds(image):
    obj = image.entries[DRIVER]
    base = next(segment["address"] for segment in obj["segments"] if segment["name"] == "__TEXT")
    at, = [at for at, cmd, _ in commands(image.data, obj["header_offset"]) if cmd == 0x26]
    pos, length = struct.unpack_from("<II", image.data, at + 8)
    end = pos + length
    starts = []
    while pos < end:
        delta = shift = 0
        while True:
            part = image.data[pos]
            pos += 1
            delta |= (part & 127) << shift
            if part < 128:
                break
            shift += 7
            assert pos < end and shift < 64
        if delta == 0:
            break
        base += delta
        starts.append(base)
    return dict(zip(starts, starts[1:]))


def member_route(image, record, selector):
    name, vtable_offset, modifier, role, symbol = SELECTORS[selector]
    assert (record["target_word"], record["adjustment"], record["flags"],
            record["count_in"], record["count_out"]) == ("0x0", 0, 3, 0, 4)
    assert any(name + "EPj" in member for member in record["member_symbols"])
    pc = int(record["member"]["target"], 16)
    for offset, mnemonic, operands in [
        (0x14, "mov", "x19, x1"), (0x18, "ldr", "x0, [x0, #0xd8]"),
        (0x2c, "mov", f"x17, #{vtable_offset:#x}"), (0x34, "ldr", "x8, [x16]"),
        (0x38, "movk", f"x16, #{modifier:#x}, lsl #48"), (0x3c, "blraa", "x8, x16"),
        (0x40, "mov", "x8, x0"), (0x44, "mov", "w0, #0"), (0x48, "str", "w8, [x19]"),
    ]:
        image.instruction(pc + offset, mnemonic, operands)
    provider = image.pointer(image.named(f"__ZTV{PROVIDER}") + 0x10 + vtable_offset)
    assert (provider["auth"], provider["diversity"], provider["key"], provider["address_diversity"]) == (
        1, hex(modifier), 0, 1,
    )
    stub = int(provider["target"], 16)
    image.instruction(stub, "bti", "c")
    target = image.branch(stub + 4, "b")
    assert target == image.named(symbol)
    return {
        "method": record, "provider_slot": provider, "provider_symbols": image.names(stub),
        "provider_call": hex(pc + 0x3c), "output_store": hex(pc + 0x48),
        "getter_role": role, "getter": hex(target), "getter_symbol": symbol,
    }


def data_address(page, operand):
    assert page.mnemonic == "adrp"
    page_register, base = page.op_str.split(", #")
    if operand.mnemonic == "add":
        dest, source, offset = operand.op_str.split(", ")
        assert dest == source == page_register
    else:
        load = re.fullmatch(r"[xw]\d+, \[(" + page_register + r"), (#0x[0-9a-f]+)\]", operand.op_str)
        assert operand.mnemonic == "ldr" and load
        offset = load[2]
    return int(base, 0) + int(offset[1:], 0)


def instruction_pair(old, new):
    assert old.mnemonic == new.mnemonic
    # Only the immediate in these instruction encodings may differ.
    mask = 0x9f00001f if old.mnemonic == "adrp" else 0xffc003ff
    assert int.from_bytes(old.bytes, "little") & mask == int.from_bytes(new.bytes, "little") & mask


def compare_function(label, current, pinned, current_bounds, pinned_bounds, reference, entry, addresses):
    original_entry = int(reference["start"], 16)
    original_end = pinned_bounds[original_entry]
    end = current_bounds[entry]
    size = original_end - original_entry
    assert end - entry == size and original_end == int(reference["end"], 16)
    original = pinned.read(original_entry, size)
    raw = current.read(entry, size)
    assert original.hex() == reference["bytes"] and sha(original) == reference["sha256"]

    before = pinned.instructions(original_entry, size)
    after = current.instructions(entry, size)
    checked_references = []
    expected_changes = set()
    for page, use, address in REFERENCES.get(label, ()):
        assert data_address(before[page // 4], before[use // 4]) == address
        target = addresses[address]
        assert data_address(after[page // 4], after[use // 4]) == target
        for off in (page, use):
            instruction_pair(before[off // 4], after[off // 4])
        checked_references.append({"page_at": hex(entry + page), "use_at": hex(entry + use),
                                   "pinned_address": hex(address), "current_address": hex(target)})
        expected_changes.update((page, use))
    differences = {i * 4 for i, (o, n) in enumerate(zip(before, after, strict=True)) if o.bytes != n.bytes}
    assert differences == expected_changes, (label, differences ^ expected_changes)
    return {"pinned_start": hex(original_entry), "current_start": hex(entry), "current_end": hex(end),
            "pinned_sha256": sha(original), "current_sha256": sha(raw), "current_bytes": raw.hex(),
            "instruction_count": size // 4, "changed_address_operands": len(differences),
            "address_references": checked_references}


def matching_fixups(current, pinned, old_slot):
    old = pinned.pointer(old_slot)
    new = current.pointer(old_slot + POOL_DELTA)
    fields = ("format", "auth", "diversity", "address_diversity", "key")
    assert all(new[key] == old[key] for key in fields)
    return old, new


def check_tables(current, pinned, published, addresses):
    banks = {}
    bank_records = []
    for name, record in published["banks"].items():
        old = int(record["address"], 16)
        new = old + BANK_DELTA
        banks[name] = current.read(new, 256)
        assert pinned.read(old, 256) == banks[name] == bytes.fromhex(record["bytes"])
        addresses[old] = new
        bank_records.append({"bank": name, "pinned": hex(old), "current": hex(new), "sha256": sha(banks[name])})
    literal_records = []
    for record in published["literal_pool_records"]:
        slot = int(record["slot"], 16)
        old, new = matching_fixups(current, pinned, slot)
        assert int(new["target"], 16) - int(old["target"], 16) == BANK_DELTA
        literal_records.append(new)

    derived = {}
    rules = []
    for rule in published["bank_rules"]:
        family = rule["family"]
        left, right = banks[family + "L"], banks[family + "R"]
        key = int(rule["key"], 16)
        constant, = {x ^ right[left[x] ^ key] for x in range(256)}
        assert constant == int(rule["constant"], 16)
        index = constant + int(rule["additive"], 16)
        base = OLD_TABLE if rule["name"].endswith("_call") else OLD_POOL
        slot = base + index * 8
        assert slot == int(rule["slot"], 16)
        old, new = matching_fixups(current, pinned, slot)
        bias = int(rule["bias"], 16)
        old_target = (int(old["target"], 16) + bias) & MASK
        target = (int(new["target"], 16) + bias) & MASK
        if not rule["name"].endswith("_call"):
            delta = POOL_DELTA if old_target == OLD_TABLE else CONTROLLER_DELTA
            assert target == old_target + delta
        assert old_target == int(rule["target"], 16)
        derived[rule["name"]] = target
        rules.append({"rule": rule["name"], "bank_family": family, "key": hex(key),
                      "constant": hex(constant), "slot": new, "effective_target": hex(target),
                      "inputs_checked": 256})
    return {"banks": bank_records, "literal_pool_entries": literal_records, "rules": rules}, derived


def verify_results(image, functions):
    version = int(functions["version_getter"]["current_start"], 16)
    capability = int(functions["capability_getter"]["current_start"], 16)
    adapter = int(functions["version_adapter"]["current_start"], 16)
    leaf = int(functions["capability_leaf"]["current_start"], 16)
    image.instruction(version + 0x1e4, "ldr", "w0, [sp, #0x14]")
    image.instruction(capability + 0x1bc, "ldr", "w0, [sp, #0x14]")
    assert struct.unpack("<II", image.read(adapter + 0x204, 8)) == (0x52a98168, 0xb9000668)
    assert struct.unpack("<II", image.read(leaf + 4, 8)) == (0x52803f08, 0xb9000408)
    image.instruction(adapter + 0x200, "blraa", "x8, x17")
    image.instruction(version + 0x1e0, "blraa", "x8, x17")
    image.instruction(capability + 0x1b8, "blraa", "x8, x17")
    return {
        "22": {"value_u32": "0x4c0b0000", "output_hex": "00000b4c", "setter": hex(adapter + 0x208),
               "getter_load": hex(version + 0x1e4), "outer_status_u32": 0},
        "23": {"value_u32": "0x000001f8", "output_hex": "f8010000", "setter": hex(leaf + 8),
               "getter_load": hex(capability + 0x1bc), "outer_status_u32": 0},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("current_collection", type=Path)
    parser.add_argument("pinned_collection", type=Path)
    args = parser.parse_args()
    current = Collection(args.current_collection, IDENTITIES[1])
    pinned = Collection(args.pinned_collection, IDENTITIES[0])
    source = subprocess.check_output(["zstd", "-dc", RECEIPT])
    published = json.loads(source)
    addresses = {
        OLD_GUARD_SLOT: 0xfffffe0008493098, OLD_POOL: OLD_POOL + POOL_DELTA,
        **{a: a + CONTROLLER_DELTA for a in (
            0xfffffe000ccc32f8, 0xfffffe000ccc3368, 0xfffffe000ccc3670, 0xfffffe000ccc7790,
        )},
    }
    old_guard = pinned.pointer(OLD_GUARD_SLOT)
    new_guard = current.pointer(addresses[OLD_GUARD_SLOT])
    for image, binding in [(pinned, old_guard), (current, new_guard)]:
        assert any("stack_chk_guard" in name for name in image.names(int(binding["target"], 16)))
    table_evidence, derived = check_tables(current, pinned, published, addresses)
    current_map = method_map(current)
    routes = {i: member_route(current, current_map["methods"][i], i) for i in SELECTORS}
    entries = {route["getter_role"]: int(route["getter"], 16) for route in routes.values()}
    entries.update(version_adapter=derived["version_call"], capability_leaf=derived["capability_call"],
                   status_leaf=derived["adapter_call"])
    cb, pb = function_bounds(current), function_bounds(pinned)
    functions = {name: compare_function(name, current, pinned, cb, pb, published["fragments"][name],
                                        entry, addresses) for name, entry in entries.items()}
    report = {
        "current_identity": IDENTITIES[1], "pinned_identity": IDENTITIES[0],
        "original_receipt_sha256": sha(source), "methods": routes, "functions": functions,
        "tables": table_evidence, "stack_guard_slots": [old_guard, new_guard],
        "shared_dispatch": synchronous_path(current, current_map, mig_map(current)),
        "conditional_metadata": verify_results(current, functions),
        "live_method_transaction_observed": False,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
