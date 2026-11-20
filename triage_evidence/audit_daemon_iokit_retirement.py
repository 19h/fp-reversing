#!/usr/bin/env python3
"""Audit pinned daemon close, deallocation, and direct transport evidence."""

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

from analyze_zut_trace import digest, image_info
from audit_archived_iokit_open_retirement import (
    DEALLOCATE,
    GUEST_MESSAGE,
    HOST_RECEIVE,
    HOST_SEND,
    THIN_SHA,
    TRACE_SHA,
    decode_guest,
)
from audit_daemon_iokit_callsite_capture import BASELINE_SHA, FRAME, RETRY_SHA
from verify_interface_contracts import Image


TABLE = 0x101039ef0
POOL = 0x1010a1960
CS = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
FIXUP_ROW = re.compile(
    r"\s+(\S+)\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+"
    r"(auth-(?:bind|rebase)|bind|rebase)\s+(\S+)(?:\s+\(div=(0x[0-9a-fA-F]+) "
    r"ad=(\d) key=(\w+)\))?"
)
SYMBOL = re.compile(r"^\s+0x[\da-fA-F]+\s+(_\S+)\s+", re.MULTILINE)
CLOSE = re.compile(rb"(?:IOServiceClose|IOConnect(?:AddRef|Release)|io_service_close)", re.I)
MODIFIERS = {0xf00f, 0xbe7e, 0x67eb, 0x19ad, 0xc052}
STUBS = {
    0x100e2a940: "_IOObjectRelease",
    0x100e2aaf0: "_mach_msg",
    0x100e2ab00: "_mach_msg2_internal",
    0x100e2ab10: "_mach_msg_destroy",
}
LIFETIME_IDS = {2816, 2916, 2862, 2962, 2865, 2965}


def xcrun(tool, path, *options):
    return subprocess.run(
        ["xcrun", tool, *options, str(path)], check=True, capture_output=True, text=True
    ).stdout


def fixups(path):
    result = {}
    for line in xcrun("dyld_info", path, "-fixups").splitlines():
        hit = FIXUP_ROW.match(line)
        if hit is None:
            continue
        seg, section, slot, kind, target, modifier, ad, key = hit.groups()
        result[int(slot, 16)] = dict(
            segment=seg, section=section, kind=kind, target=target.lower() if target.startswith("0x") else target,
            modifier=None if modifier is None else int(modifier, 16),
            address_diversity=None if ad is None else int(ad), key=key,
        )
    return result


def instructions(image, address, size):
    raw = image.read(address, size)
    rows = [
        dict(pc=hex(i.address), bytes=i.bytes.hex(), mnemonic=i.mnemonic, operands=i.op_str)
        for i in CS.disasm(raw, address)
    ]
    assert len(rows) * 4 == size, hex(address)
    return rows


def check_instruction(image, address, mnemonic, operands):
    row, = instructions(image, address, 4)
    assert (row["mnemonic"], row["operands"]) == (mnemonic, operands), row
    return row


def branch_census(code, base):
    sites = {modifier: [] for modifier in MODIFIERS}
    stubs = {name: [] for name in STUBS.values()}
    for offset, (word,) in enumerate(struct.iter_unpack("<I", code)):
        pc = base + offset * 4
        if word & 0x7fe0001f == 0x52800011 and (modifier := (word >> 5) & 0xffff) in MODIFIERS:
            following = next(CS.disasm(code[offset * 4 + 4:offset * 4 + 8], pc + 4), None)
            if following and following.mnemonic in {"braa", "blraa"} and following.op_str.endswith(", x17"):
                sites[modifier].append(hex(following.address))
        if word & 0x7c000000 == 0x14000000:
            displacement = ((word & 0x1ffffff) - (word & 0x2000000)) * 4
            if pc + displacement in STUBS:
                stubs[STUBS[pc + displacement]].append(hex(pc))
    assert [len(sites[k]) for k in sorted(sites)] == [20, 4, 12, 5, 5]
    assert stubs["_mach_msg"] == ["0x100de9fac"] and stubs["_mach_msg2_internal"] == ["0x100004428"]
    assert len(stubs["_IOObjectRelease"]) == 9
    return sites, stubs


def select_bank(image, left, right, key, additive):
    lhs, rhs = image.read(left, 256), image.read(right, 256)
    constant, = {byte ^ rhs[lhs[byte] ^ key] for byte in range(256)}
    result = dict(left=hex(left), right=hex(right), key=hex(key), additive=hex(additive),
                  constant=hex(constant), index=hex(additive + constant),
                  left_sha256=digest(lhs), right_sha256=digest(rhs), inputs_checked=256)
    return additive + constant, result


def selected_targets(image, records):
    bank_a = (0x100fc4230, 0x101031fa0)
    bank_d = (0x100e99a00, 0x100f4e390)
    direct = (
        (0x100090094, (0x100e99800, 0x100f4e290), 0x61, 0xce2b, 0x1010a1110,
         "0x10044ada4", "original PC-relative banks, canonical table"),
        (0x100261070, (0x101031da0, 0x100e99900), 0x86, 0xcdec, 0x1010a1110,
         "0x10044ada4", "conditional on incoming SP+8, X23 and X25"),
        (0x100383608, bank_a, 0xf3, 0xce13, 0x1010a11a0,
         "0x100418e28", "original PC-relative banks, canonical table"),
        (0x100494310, bank_a, 0x6c, 0xcdd7, 0x1010a11e0,
         "libSystem/_mach_port_deallocate", "prior arcade registration peer cleanup"),
        (0x1004ecebc, bank_d, 0x6d, 0xcd84, 0x1010a1190,
         "0x10041ac7c", "conditional on incoming SP+0x600, SP+0x5f8 and SP+0x9d8"),
        (0x10013ec8c, (0x100fc4130, 0x101031ea0), 0x4e, 0xcdb7, 0x1010a14a0,
         "0x100422bcc", "conditional on X22 pool 0x1010a4328 and canonical table"),
        (0x1005ec5e8, bank_d, 0x6d, 0xce1c, 0x1010a1650,
         "0x1004263f4", "conditional on incoming SP+0x600, SP+0x5f8 and SP+0x9d8"),
    )
    roots = (
        (0x1010a7fa0, 0x2514674a, 0x100e99800),
        (0x1010a59a8, 0x468e29b7, 0x100f4e290),
        (0x1010a7a50, 0x58a4e9be, 0x100fc4230),
        (0x1010a3ba0, 0x05e7b9ca, 0x101031fa0),
        (0x1010a4328, 0x55a6e8c7, 0x100fc4130),
        (0x1010a6578, 0x75079233, 0x101031ea0),
        (POOL + 0x1658, 0x5918054b, 0x100e99a00),
        (POOL + 0x26a0, 0x62f83f4e, 0x100f4e390),
    )
    for slot, subtract, bank in roots:
        assert int(records[slot]["target"], 16) - subtract == bank
    result = {}
    for pc, (left, right), key, add, slot, target, scope in direct:
        index, row = select_bank(image, left, right, key, add)
        assert TABLE + index * 8 == slot and records[slot]["target"] == target
        result[hex(pc)] = dict(scope=scope, slot=hex(slot), target=target, bank=row)

    index, first = select_bank(image, 0x100e99800, 0x100f4e290, 0x61, 0x901)
    other, second = select_bank(image, *bank_d, 0x54, 0xce1a)
    slot = int(records[POOL + 8 * index]["target"], 16) + 8 * other - 0x2f3b2e12
    assert slot == 0x1010a1570 and records[slot]["target"] == "0x1004aca80"
    result["0x1004ad334"] = dict(
        scope="original inline two-bank pointer expression", slot=hex(slot),
        target=records[slot]["target"], banks=[first, second], first_pool_slot=hex(POOL + 8 * index),
    )
    for row in result.values():
        slot = int(row["slot"], 16)
        word, = struct.unpack("<Q", image.read(slot, 8))
        rec = records[slot]
        assert word >> 63 == 1 and (word >> 32) & 0xffff == rec["modifier"]
        assert (word >> 48) & 7 == 0 and rec["address_diversity"] == 0 and rec["key"] == "IA"
        if rec["kind"] == "auth-rebase":
            assert 0x100000000 + (word & 0xffffffff) == int(rec["target"], 16)
        else:
            assert rec["kind"] == "auth-bind" and (word >> 62) & 1 == 1
        row.update(authenticated_slot_word=hex(word), fixup=rec)
    return result


def trace_summary(path, sha, expected_lines, expected_releases):
    raw = path.read_bytes()
    assert digest(raw) == sha, path.name
    lines = raw.decode().splitlines()
    assert len(lines) == expected_lines
    messages, host, releases = [], [], []
    for n, line in enumerate(lines, 1):
        if (m := GUEST_MESSAGE.fullmatch(line)) and int(m[8]) in LIFETIME_IDS:
            message, _ = decode_guest(lines, n, m[2], tuple(int(x, 0) for x in m.groups()[2:]))
            messages.append(message)
        if (m := HOST_SEND.fullmatch(line) or HOST_RECEIVE.fullmatch(line)) and int(m[1]) in LIFETIME_IDS:
            host.append(dict(line=n, id=int(m[1])))
        if m := DEALLOCATE.fullmatch(line):
            shared = []
            first_daemon = None
            for idx in range(n, len(lines)):
                frame = FRAME.fullmatch(lines[idx])
                if frame is None:
                    break
                assert frame[1] == m[1]
                if frame[3] == "[shared region]":
                    shared.append(frame[2])
                if Path(frame[3]).name == "fairplayd.arm64e":
                    first_daemon = frame[2]
                    break
            releases.append(dict(line=n, task=hex(int(m[3])), name=hex(int(m[4])),
                                 result=m[5], first_daemon_return=first_daemon, earlier_shared_frames=shared))
    assert len(releases) == expected_releases and all(row["result"] == "0x0" for row in releases)
    assert [row["id"] for row in messages] == ([] if expected_lines == 14196 else [2862, 2962])
    assert [row["id"] for row in host] == ([] if expected_lines == 14196 else [2862, 2962])
    if messages:
        assert messages[1]["descriptors"][0]["name"] == "0x0"
        assert struct.unpack_from("<I", bytes.fromhex(messages[1]["message_hex"]), 48)[0] == 0xe00002c2
    return dict(sha256=sha, lines=expected_lines, messages=messages, host=host, deallocations=releases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("daemon", "archived", "baseline", "retry", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    image = Image(args.daemon)
    identity = image_info(args.daemon)
    del identity["path"]
    assert identity["sha256"] == THIN_SHA
    assert identity["uuid"] == "204741e9-b89f-32b4-9321-51f3975c7cac"
    text_section = next(row for row in identity["text_sections"] if row["section"] == "__text")
    base = int(text_section["address"], 16)
    code = image.read(base, text_section["size"])
    assert text_section["sha256"] == digest(code)
    sites, stubs = branch_census(code, base)
    imports = set(SYMBOL.findall(xcrun("dyld_info", args.daemon, "-imports")))
    close_names = {"_IOServiceClose", "_io_service_close", "_IOConnectRelease", "_IOConnectAddRef"}
    assert not (imports & close_names or CLOSE.search(image.data))
    control = {"_IOServiceOpen", "_IOObjectRelease", "_mach_msg", "_mach_msg2_internal",
               "_mach_port_deallocate", "_dlopen", "_dlsym"}
    assert control <= imports, control - imports
    indirect = xcrun("llvm-objdump", args.daemon, "--macho", "--indirect-symbols")
    for stub, symbol in STUBS.items():
        assert re.search(rf"^0x{stub:016x}\s+\d+\s+{symbol}$", indirect, re.MULTILINE)
    records = fixups(args.daemon)
    assert not {rec["target"].split("/")[-1] for rec in records.values()} & close_names
    selected = selected_targets(image, records)
    assert {slot for slot, row in records.items() if row["modifier"] == 0xf00f and row["key"] == "IA"} == {
        0x1010a1110, 0x1010a1190, 0x1010a11a0, 0x1010a11e0
    }
    windows = {
        pc: instructions(image, int(pc, 16) - 0x30, 0x44)
        for values in sites.values() for pc in values
    }
    assertions = [
        (0x10009008c, "add", "x0, sp, #0x50"),
        (0x10044af3c, "ldr", "w13, [x0, #0x1c]"),
        (0x100261068, "add", "x0, sp, #0x28"),
        (0x100383600, "add", "x0, sp, #0x10"),
        (0x100418e78, "ldr", "x9, [x0, #0x10]"),
        (0x100418ec4, "str", "x8, [x0, #8]"),
        (0x100418ec8, "ret", ""),
        (0x1004942f0, "ldr", "w0, [x10]"),
        (0x100494308, "ldr", "w1, [sp, #0x9d0]"),
        (0x1004eceb0, "add", "x0, sp, #0x10, lsl #12"),
        (0x1004eceb4, "add", "x0, x0, #0xcb8"),
        (0x10041ada8, "ldr", "w16, [x0, #0x14]"),
        (0x100478ba8, "str", "x3, [sp, #8]"),
        (0x10044038c, "blraa", "x8, x17"),
        (0x100de9f58, "stp", "w21, w0, [sp, #8]"),
        (0x100de9f70, "str", "d0, [sp, #0x10]"),
        (0x100de9f9c, "mov", "w2, #0x38"),
        (0x100de9fa0, "mov", "w3, #0x40"),
        (0x100de9fac, "bl", "#0x100e2aaf0"),
        (0x100dea00c, "cmp", "w8, #0x514"),
        (0x100dea080, "cmp", "w8, #0x38"),
        (0x100dea0b4, "str", "x9, [x20]"),
        (0x100dea0b8, "str", "w8, [x19]"),
    ]
    checked = [check_instruction(image, *spec) for spec in assertions]
    assert struct.unpack("<II", image.read(0x101032d70, 8)) == (0, 1200)
    archive = trace_summary(args.archived, TRACE_SHA, 1748, 10)
    baseline = trace_summary(args.baseline, BASELINE_SHA, 14196, 7)
    retry = trace_summary(args.retry, RETRY_SHA, 16380, 15)
    daemon_releases = [(row["first_daemon_return"], row["name"]) for row in retry["deallocations"]
                       if row["first_daemon_return"] is not None]
    assert daemon_releases == [("0x100440390", "0x707")] * 5 + [
        ("0x100461cc8", "0xc03"), ("0x100478c30", "0x2103"), ("0x100483cc4", "0x2003")
    ]
    assert [row["name"] for row in archive["deallocations"][-2:]] == ["0x1903", "0x1803"]
    assert [row["line"] for row in retry["deallocations"][-3:]] == [16276, 16356, 16365]
    assert all(row["first_daemon_return"] is None for row in archive["deallocations"] + baseline["deallocations"])

    output = dict(
        image=identity, import_positive_controls=sorted(control), close_symbol_candidates=[],
        exact_adjacent_modifier_sites={hex(k): sites[k] for k in sorted(sites)},
        same_modifier_fixups={
            hex(slot): row for slot, row in records.items()
            if row["modifier"] in MODIFIERS and row["address_diversity"] == 0 and row["key"] == "IA"
        },
        immediate_branches_to_import_stubs=stubs, selected_targets=selected,
        instruction_windows=windows, checked_instructions=checked,
        additional_direct_transport=dict(call="0x100de9fac", request_id=1200, success_reply_id=1300,
                                         send_bytes=56, receive_capacity_bytes=64, success_reply_bytes=56,
                                         destination_register="entry W0", pool_address="0x101032d70"),
        traces=dict(archive=archive, baseline=baseline, retry=retry),
    )
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print("Verified original daemon imports, interface candidates, and 32 deallocation trap records.")


if __name__ == "__main__":
    main()
