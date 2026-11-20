#!/usr/bin/env python3
"""Check the installed lskdd recursive parent's state and return ABI offline."""

import argparse
import json
from itertools import product
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn import arm64_const as regs

from audit_live_lskdd_selector19_binding import (
    POOL, SHA, TABLE, ThinView, bindings, daemon_slices, selected_identity,
    selection, window,
)

IMAGE = "/System/Library/PrivateFrameworks/CoreLSKD.framework/Versions/A/lskdd"
SP = 0x700000000
COPY = 0x10034e248
STATUS_MATCH = 0x2ee02eab
STATUS_REPLAY = 0x2edf880f
MARKER = 0x7c36115800000001
STATE = 0x45b9
PC = regs.UC_ARM64_REG_PC
WINDOWS = {
    "bank_publication": (0x1005b3e84, 0x1005b3ea8),
    "state_publication": (0x1005bb164, 0x1005bb170),
    "prepare_block": (0x1008daec4, 0x1008daf68),
    "parent_call_and_return": (0x1008d5760, 0x1008d59c4),
    "copy_leaf": (COPY, 0x10034e4a4),
    "mismatch_continuation": (0x1005474cc, 0x10054751c),
}
FIXUPS = {
    POOL + 0x1fd0: "rebase 0x100D3F724",
    POOL + 0x2648: "rebase 0x100E06F98",
    0x100e30a90: "auth-rebase 0x1008DAEC4 (div=0xDB1D ad=0 key=IA)",
    0x100e48aa8: "auth-rebase 0x10093054C (div=0xA11F ad=0 key=IA)",
    0x100e48c30: "auth-rebase 0x10051F214 (div=0xA11F ad=0 key=IA)",
    0x100e63ef8: "auth-rebase 0x1008D5760 (div=0xA11F ad=0 key=IA)",
    0x100e3abe0: "auth-rebase 0x1009A7A48 (div=0x0637 ad=0 key=IA)",
    0x100e3ac68: "auth-rebase 0x1005474CC (div=0x0637 ad=0 key=IA)",
    0x100e435d0: "auth-rebase 0x10051F214 (div=0xF71D ad=0 key=IA)",
}
SITES = {
    0x1005bb16c: ("str", "w9, [sp, #0x3b8c]"),
    0x1008d5760: ("ldr", "w20, [sp, #0x3b8c]"),
    0x1008d5888: ("add", "w8, w20, w8"),
    0x1008d5890: ("str", "w8, [x22, #0x708]"),
    0x1008d5898: ("str", "w8, [x22, #0x6e0]"),
    0x1008d595c: ("ldr", "w12, [x8, #0x3ffc]"),
    0x1008d596c: ("mov", "sp, x8"),
    0x1008d5988: ("ldr", "x8, [x8, #0xf68]"),
    0x1008d5998: ("ccmp", "x8, x9, #0, eq"),
    0x1008d59b0: ("ldr", "x11, [x27, w8, sxtw #3]"),
    0x1008d59c0: ("braa", "x11, x17"),
    0x1008daf08: ("str", "w9, [x12, #0x3ffc]"),
    0x1008daf14: ("str", "xzr, [x9, #0x9f0]"),
    0x1008daf3c: ("stp", "w12, wzr, [x13, #8]"),
}


def put(cpu, address, value, width=8):
    cpu.mem_write(address, value.to_bytes(width, "little"))


def number(cpu, address, width=8):
    return int.from_bytes(cpu.mem_read(address, width), "little")


def machine(image, names):
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(regs.UC_CPU_ARM64_MAX)
    for name in names:
        start, end = WINDOWS[name]
        page = start & ~0xfff
        cpu.mem_map(page, ((end + 0xfff) & ~0xfff) - page)
        cpu.mem_write(start, image.read(start, end - start))
    cpu.mem_map(SP, 0x60000)
    cpu.reg_write(regs.UC_ARM64_REG_SP, SP)
    return cpu


def install_targets(cpu, slots):
    page = TABLE & ~0xfff
    cpu.mem_map(page, 0x90000)
    for slot in slots:
        put(cpu, slot, int(FIXUPS[slot].split()[1], 16))


def execute(cpu, start, end):
    cpu.emu_start(start, end, count=1024)
    assert cpu.reg_read(PC) == end, hex(cpu.reg_read(PC))


def replay_copy(image):
    cpu = machine(image, ("copy_leaf",))
    end = 0x10034e4a4
    source_page, dest_page = SP + 0x20000, SP + 0x21000
    data = bytes((47 * i + 11) % 256 for i in range(32))
    guard = b"\xaa" * 64
    for a, b in product(range(8), repeat=2):
        cpu.mem_write(source_page, guard)
        cpu.mem_write(dest_page, guard)
        source = source_page + 8 + a
        dest = dest_page + 8 + b
        cpu.mem_write(source, data)
        cpu.reg_write(regs.UC_ARM64_REG_X0, source)
        cpu.reg_write(regs.UC_ARM64_REG_X1, dest)
        cpu.reg_write(regs.UC_ARM64_REG_X2, len(data))
        cpu.reg_write(regs.UC_ARM64_REG_LR, end)
        execute(cpu, COPY, end)
        assert cpu.mem_read(dest_page, 64) == guard[:8 + b] + data + guard[40 + b:]
        assert cpu.mem_read(source_page, 64) == guard[:8 + a] + data + guard[40 + a:]
    return {"length_bytes": len(data), "alignment_pairs": 64}


def replay_prepare(image):
    cpu = machine(image, ("prepare_block",))
    slots = {False: 0x100e48c30, True: 0x100e48aa8}
    install_targets(cpu, slots.values())
    source, dest = SP + 0x20000, SP + 0x21000
    data = bytes(range(16))
    put(cpu, SP + 0x5b94, STATE, 4)
    put(cpu, SP + 0x65b0, source)
    put(cpu, SP + 0x8ae0, dest)
    put(cpu, SP + 0x5ff8, TABLE)
    cpu.mem_write(source, data)
    cases = []
    for present, slot in slots.items():
        put(cpu, SP + 0x54d0, source if present else 0)
        put(cpu, SP + 0x9574, 0xff, 4)
        put(cpu, SP + 0x9f48, 0xffff)
        cpu.mem_write(dest, b"\xaa" * 17)
        cpu.reg_write(regs.UC_ARM64_REG_W9, 0x12345678)
        execute(cpu, 0x1008daec4, 0x1008daf64)
        assert number(cpu, SP + 0x9574, 4) == 0x12345678
        assert number(cpu, SP + 0x9f48) == 0
        assert cpu.mem_read(dest, 17) == data[:12] + bytes(4) + b"\xaa"
        assert cpu.reg_read(regs.UC_ARM64_REG_X10) == int(FIXUPS[slot].split()[1], 16)
        assert cpu.reg_read(regs.UC_ARM64_REG_X17) == 0xa11f
        cases.append({"pointer_present": present, "table_slot": hex(slot)})
    return cases


def replay_return(image):
    cpu = machine(image, ("state_publication", "parent_call_and_return", "mismatch_continuation"))
    slots = {False: 0x100e3ac68, True: 0x100e3abe0}
    install_targets(cpu, (*slots.values(), 0x100e435d0))
    cpu.reg_write(regs.UC_ARM64_REG_W21, STATE)
    execute(cpu, 0x1005bb164, 0x1005bb170)
    w20 = number(cpu, SP + 0x3b8c, 4)
    assert w20 + 0x2a03 == STATE
    cpu.reg_write(regs.UC_ARM64_REG_X29, SP + 0x1ca50)
    cpu.reg_write(regs.UC_ARM64_REG_X19, SP + 0x23000)
    put(cpu, SP + 0x54d0, SP + 0x24000)
    put(cpu, SP + 0x8ae0, SP + 0x25000)
    put(cpu, SP + 0x9574, 0x12345678, 4)
    execute(cpu, 0x1008d5760, 0x1008d5780)
    execute(cpu, 0x1008d5810, 0x1008d589c)
    context = SP + 0x1c968
    mask = 0xffffffff
    residue = ((context ^ 0x113ef3f5 ^ 0xc86cc8b9) * 0x58fbd727) & mask
    assert number(cpu, context, 4) ^ residue == 0x12345678
    assert (number(cpu, context + 0x28, 4) - residue) & mask == STATE
    assert [number(cpu, context + offset) for offset in (8, 16, 24, 32)] == [
        SP + 0x23000, SP + 0x24000, SP + 0x25000, SP + 0x9f48,
    ]
    assert number(cpu, SP + 0x5ff0, 4) == ((w20 << 1) ^ 0x1b98)
    cpu.reg_write(regs.UC_ARM64_REG_X22, SP + 0x1c288)
    cpu.reg_write(regs.UC_ARM64_REG_X27, TABLE)
    put(cpu, SP + 0x5ff8, TABLE)
    put(cpu, SP + 0x20 + 0x5ff8, TABLE)
    cases = []
    for delta, status, marker_matches in product((0, 32), (STATUS_REPLAY, STATUS_MATCH), (False, True)):
        put(cpu, SP + 0x10c88, delta)
        put(cpu, SP + 0x1c994, status, 4)
        marker = MARKER if marker_matches else MARKER ^ 1
        put(cpu, SP + 0xa4c0, marker ^ 1)
        put(cpu, SP + delta + 0xa4c0, marker)
        cpu.reg_write(regs.UC_ARM64_REG_SP, SP)
        cpu.reg_write(regs.UC_ARM64_REG_X19, SP + 0x10870)
        execute(cpu, 0x1008d5954, 0x1008d59c0)
        match = status == STATUS_MATCH and marker_matches
        slot = slots[match]
        assert cpu.reg_read(regs.UC_ARM64_REG_SP) == SP + delta
        assert TABLE + 8 * cpu.reg_read(regs.UC_ARM64_REG_W8) == slot
        assert cpu.reg_read(regs.UC_ARM64_REG_X11) == int(FIXUPS[slot].split()[1], 16)
        assert cpu.reg_read(regs.UC_ARM64_REG_X17) == 0x637
        following_slot = None
        if status == STATUS_REPLAY:
            execute(cpu, 0x1005474cc, 0x100547518)
            following_slot = 0x100e435d0
            assert cpu.reg_read(regs.UC_ARM64_REG_X9) == int(FIXUPS[following_slot].split()[1], 16)
            assert cpu.reg_read(regs.UC_ARM64_REG_X17) == 0xf71d
        cases.append({
            "delta_bytes": delta, "status": hex(status), "marker_matches": marker_matches,
            "table_slot": hex(slot), "following_slot": hex(following_slot) if following_slot else None,
        })
    encoding = {
        "decoded_word_at_0x00": "0x12345678",
        "decoded_word_at_0x28": hex(STATE),
        "parent_state_slot_value": hex(w20),
    }
    return {"context_encoding": encoding, "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, default=Path(IMAGE))
    args = parser.parse_args()
    thin = next(data for _, subtype, data in daemon_slices(args.image.read_bytes())
                if subtype == 0x80000002)
    identity = selected_identity(thin)
    assert identity["sha256"] == SHA
    image = ThinView(thin)
    fixups = bindings(args.image, "-arch", "arm64e")
    assert all(fixups.get(address) == row for address, row in FIXUPS.items())
    copy = selection(image, fixups, (0x100d3f720, 0x100e06f90), 0x62, 0x8c44, TABLE, COPY)
    assert copy["binding"] == "auth-rebase 0x10034E248 (div=0x81D1 ad=0 key=IA)"
    instructions = {name: window(image, *bounds) for name, bounds in WINDOWS.items()}
    by_pc = {int(row[0], 16): tuple(row[2:]) for rows in instructions.values() for row in rows}
    assert all(by_pc.get(pc) == expected for pc, expected in SITES.items())
    print(json.dumps({
        "identity": identity,
        "instructions": instructions,
        "fixups": {hex(pc): {"record": row, "bytes": image.read(pc, 8).hex()}
                   for pc, row in FIXUPS.items()},
        "copy_binding": copy,
        "copy_cases": replay_copy(image),
        "prepared_state_cases": replay_prepare(image),
        "context_and_return": replay_return(image),
        "native_ipc_observed": False,
    }, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
