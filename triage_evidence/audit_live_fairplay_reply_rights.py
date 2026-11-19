#!/usr/bin/env python3
"""Recheck the installed FairPlay kernel RPC reply-right lifecycle."""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess

from audit_live_fairplay_rpc_abi import Daemon
from audit_live_kext_selector26 import Collection, DRIVER, IDENTITIES
from audit_live_kext_selector26_transfer import imported_call, words
from bootpolicy_cache_reader import uleb
from resolve_kernel_collection_interfaces import commands


FUNCTIONS = {
    "rpc": (0xFFFFFE000BCF59E0, 0xFFFFFE000BD3D8D4),
    "reply_space_init": (0xFFFFFE000C629780, 0xFFFFFE000C679074),
    "bind_reply": (0xFFFFFE000BCF8E14, 0xFFFFFE000BD40D08),
    "port_init": (0xFFFFFE000BCCD170, 0xFFFFFE000BD15064),
    "copyin": (0xFFFFFE000BCC6B10, 0xFFFFFE000BD0EACC),
    "copyin_right": (0xFFFFFE000BCC9718, 0xFFFFFE000BD116D4),
    "make_send_once": (0xFFFFFE000BCD0628, 0xFFFFFE000BD1851C),
    "link_to_destination": (0xFFFFFE000BCCEF30, 0xFFFFFE000BD16E24),
    "copyout_header": (0xFFFFFE000BCC4E98, 0xFFFFFE000BD0CE54),
    "allocate_name": (0xFFFFFE000BCBC0F0, 0xFFFFFE000BD04088),
    "publish_right": (0xFFFFFE000BCD5B90, 0xFFFFFE000BD1DA84),
    "pack_for_user": (0xFFFFFE000BCC62D0, 0xFFFFFE000BD0E28C),
    "unbind_reply": (0xFFFFFE000BCF837C, 0xFFFFFE000BD40270),
    "mig_get_reply_port": (0xFFFFFE000BCF5F18, 0xFFFFFE000BD3DE0C),
    "mig_put_reply_port": (0xFFFFFE000BCF5F2C, 0xFFFFFE000BD3DE20),
    "mig_dealloc_reply_port": (0xFFFFFE000BCF5F24, 0xFFFFFE000BD3DE18),
}
IMMEDIATES = {
    "adrp": 0x60FFFFE0, "add": 0x003FFC00, "ldr": 0x003FFC00, "str": 0x003FFC00,
    "b": 0x03FFFFFF, "bl": 0x03FFFFFF, "mov": 0x001FFFE0,
}
REPLY_SPACE = 0xFFFFFE0007E6F348
RPC_ABI_RECEIPT = "live_fairplay_rpc_abi_audit.json.zst"


def compiler_ranges(image):
    kernel = image.entries["com.apple.kernel"]
    command, = (at for at, kind, _ in commands(image.data, kernel["header_offset"]) if kind == 0x26)
    file_offset, size = struct.unpack_from("<II", image.data, command + 8)
    stream = image.data[file_offset:file_offset + size]
    current = next(segment["address"] for segment in kernel["segments"] if segment["name"] == "__TEXT")
    starts = []
    cursor = 0
    while cursor < size:
        delta, cursor = uleb(stream, cursor)
        if delta == 0:
            break
        current += delta
        starts.append(current)
    return {start: (index, end) for index, (start, end) in enumerate(zip(starts, starts[1:]))}


def compare(pinned, current):
    old_bounds, new_bounds = compiler_ranges(pinned), compiler_ranges(current)
    result = {}
    for role, (before, after) in FUNCTIONS.items():
        old_ordinal, old_end = old_bounds[before]
        new_ordinal, new_end = new_bounds[after]
        size = old_end - before
        assert size == new_end - after
        if role != "reply_space_init":
            assert old_ordinal == new_ordinal
        original = pinned.instructions(before, size)
        installed = current.instructions(after, size)
        changed = []
        for left, right in zip(original, installed, strict=True):
            if left.bytes == right.bytes:
                continue
            assert left.mnemonic == right.mnemonic
            before_word = int.from_bytes(left.bytes, "little")
            after_word = int.from_bytes(right.bytes, "little")
            assert (before_word ^ after_word) & ~IMMEDIATES[right.mnemonic] == 0, (role, right.address)
            if right.mnemonic == "mov":
                assert (right.address, left.op_str, right.op_str) == (
                    0xFFFFFE000BD1DCE4, "w8, #0x9ac", "w8, #0x9b3"
                )
            if right.mnemonic in ("b", "bl"):
                old_target = pinned.branch(left.address, left.mnemonic)
                new_target = current.branch(right.address, right.mnemonic)
                if before <= old_target < old_end:
                    assert old_target - before == new_target - after
            changed.append(dict(offset=right.address - after, opcode=right.mnemonic,
                                pinned=left.bytes.hex(), current=right.bytes.hex(),
                                pinned_operands=left.op_str, current_operands=right.op_str))
        result[role] = dict(pinned_start=hex(before), current_start=hex(after), size_bytes=size,
                            pinned_ordinal=old_ordinal, current_ordinal=new_ordinal,
                            pinned_sha256=sha256(pinned.read(before, size)).hexdigest(),
                            current_sha256=sha256(current.read(after, size)).hexdigest(),
                            change_counts=dict(Counter(row["opcode"] for row in changed)),
                            changed=changed, current_words=words(current, after, size))
    return result


def reply_space_refs(image):
    text = next(segment for segment in image.entries["com.apple.kernel"]["segments"]
                if segment["name"] == "__TEXT_EXEC")
    section = image.read(text["address"], text["file_size"])
    instructions = (word for (word,) in struct.iter_unpack("<I", section))
    prior = next(instructions)
    refs = []
    for index, word in enumerate(instructions):
        kind = word & 0xFFC00000
        if (prior & 0x9F000000 == 0x90000000 and kind in (0xF9000000, 0xF9400000)
                and prior & 31 == (word >> 5) & 31):
            pc = text["address"] + 4 * index
            immediate = (((prior >> 5) & 0x7FFFF) << 2) | ((prior >> 29) & 3)
            page = (pc & ~0xFFF) + 4096 * ((immediate ^ 0x100000) - 0x100000)
            if page + 8 * ((word >> 10) & 0xFFF) == REPLY_SPACE:
                refs.append(dict(pc=hex(pc + 4), role="load" if kind == 0xF9400000 else "store",
                                 words=words(image, pc, 8)))
        prior = word
    assert [(row["pc"], row["role"]) for row in refs] == [
        ("0xfffffe000bd17988", "load"), ("0xfffffe000bd17ad8", "load"),
        ("0xfffffe000bd3dc68", "load"), ("0xfffffe000bd40d64", "load"),
        ("0xfffffe000c67911c", "store"),
    ]
    initial = image.read(REPLY_SPACE, 8)
    assert initial == bytes(8)
    return dict(global_address=hex(REPLY_SPACE), file_bytes=initial.hex(),
                text_base=hex(text["address"]), examined_words=len(section) // 4, references=refs)


def branch_sites(image):
    calls = (
        (0xFFFFFE000C6790F0, 0xFFFFFE000BDBDB58),
        (0xFFFFFE000BD3D99C, 0xFFFFFE000BD40D08),
        (0xFFFFFE000BD40D98, 0xFFFFFE000BD15064),
        (0xFFFFFE000BD3DA34, 0xFFFFFE000BD0EACC),
        (0xFFFFFE000BD0EB7C, 0xFFFFFE000BD116D4),
        (0xFFFFFE000BD0EB94, 0xFFFFFE000BD116D4),
        (0xFFFFFE000BD1173C, 0xFFFFFE000BD1851C),
        (0xFFFFFE000BD3DA9C, 0xFFFFFE000BD0EFFC),
        (0xFFFFFE000BD3DB08, 0xFFFFFE000BD16E24),
        (0xFFFFFE000BD3DB38, 0xFFFFFE000BD10370),
        (0xFFFFFE000BD0D160, 0xFFFFFE000BD04088),
        (0xFFFFFE000BD0D1D0, 0xFFFFFE000BD1DA84),
        (0xFFFFFE000BD1DBA0, 0xFFFFFE000BD164AC),
        (0xFFFFFE000BD3DBD8, 0xFFFFFE000BD111FC),
        (0xFFFFFE000BD3DC70, 0xFFFFFE000BD0E110),
        (0xFFFFFE000BD3DB80, 0xFFFFFE000BD40270),
        (0xFFFFFE000BD3DC08, 0xFFFFFE000BD40270),
    )
    results = []
    for site, target in calls:
        assert image.branch(site, "bl") == target
        word, = struct.unpack("<I", image.read(site, 4))
        assert word >> 26 == 0x25
        displacement = (word & 0x1FFFFFF) - (word & 0x2000000)
        assert site + 4 * displacement == target
        results.append(dict(site=hex(site), target=hex(target), bytes=image.read(site, 4).hex()))
    return results


def endpoint_fields(pinned, current, daemon_path):
    sites = (
        (0xFFFFFE000BD3D8FC, "mrs", "x19, tpidr_el1"),
        (0xFFFFFE000BD3D960, "ldr", "x21, [x19, #0x3f0]"),
        (0xFFFFFE000BD40DB8, "str", "x20, [x19, #0x3f0]"),
        (0xFFFFFE000BD40DC4, "pacda", "x17, x16"),
        (0xFFFFFE000BD40DC8, "str", "x17, [x20, #0x40]"),
        (0xFFFFFE000BD15118, "str", "w5, [x0, #0x34]"),
        (0xFFFFFE000BD15138, "str", "x17, [x0, #0x48]"),
        (0xFFFFFE000BD3DA20, "str", "x21, [x23, #0x10]"),
        (0xFFFFFE000BD0EB6C, "and", "w23, w25, #0x1f"),
        (0xFFFFFE000BD0EB70, "ubfx", "w21, w25, #8, #5"),
        (0xFFFFFE000BD18540, "str", "w8, [x0, #0x8c]"),
        (0xFFFFFE000BD18554, "ldadd", "w9, w9, [x8]"),
        (0xFFFFFE000BD11860, "str", "w8, [x19, #0x88]"),
        (0xFFFFFE000BD3DA7C, "ldadd", "w8, w8, [x0]"),
        (0xFFFFFE000BD0D130, "cmp", "w8, #0x12"),
        (0xFFFFFE000BD1DB78, "cmp", "w24, #0x12"),
        (0xFFFFFE000BD1DB84, "cmp", "w8, #0xb"),
        (0xFFFFFE000BD1DC3C, "movk", "w8, #4, lsl #16"),
        (0xFFFFFE000BD1DC44, "str", "w8, [x21, #8]"),
        (0xFFFFFE000BD0D398, "stp", "x9, x8, [x22, #8]"),
        (0xFFFFFE000BD0E5F8, "xtn", "v1.2s, v1.2d"),
        (0xFFFFFE000BD0E608, "stp", "d1, d0, [x0, #8]"),
        (0xFFFFFE000BD3DB24, "add", "x0, x21, #0x10"),
        (0xFFFFFE000BD3DB70, "tbz", "w8, #5, #0xfffffe000bd3dae0"),
        (0xFFFFFE000BD40290, "str", "xzr, [x19, #0x3f0]"),
    )
    for site, mnemonic, operands in sites:
        current.instruction(site, mnemonic, operands)
    tables = (0xFFFFFE0007010AB0, 0xFFFFFE0007010B40)
    for image, table in zip((pinned, current), tables):
        assert struct.unpack("<6I", image.read(table, 24)) == (16, 17, 18, 17, 17, 18)
    stubs = {}
    for name, size in (("mig_get_reply_port", 12), ("mig_put_reply_port", 8),
                       ("mig_dealloc_reply_port", 8)):
        stub = current.named("_" + name)
        rows = [("bti", "c"), ("ret", "")]
        if name == "mig_get_reply_port":
            rows.insert(1, ("mov", "x0, #0"))
        assert [(row.mnemonic, row.op_str) for row in current.instructions(stub, size)] == rows
        stubs[name] = words(current, stub, size)
    constructors = {}
    for request, entry in ((502, 0xFFFFFE000A5E31F4), (700, 0xFFFFFE000A5E3464)):
        current.instruction(entry + 0x6C, "mov", "w8, #0x1513")
        current.instruction(entry + 0x70, "movk", "w8, #0x8000, lsl #16")
        current.instruction(entry + 0x78, "stp", "x19, x0, [sp, #0x10]")
        constructors[request] = dict(
            getter=imported_call(current, entry + 0x68, "_mig_get_reply_port"),
            put=imported_call(current, entry + 0xC4, "_mig_put_reply_port"),
            dealloc=imported_call(current, entry + 0x114, "_mig_dealloc_reply_port"),
            header=words(current, entry + 0x68, 0x14),
        )
    prior = subprocess.check_output(["zstd", "-dc", Path(__file__).with_name(RPC_ABI_RECEIPT)])
    identity = json.loads(prior)
    assert identity["kernel_identity"] == list(IDENTITIES[1])
    daemon = Daemon(daemon_path)
    assert sha256(daemon.data).hexdigest() == identity["daemon"]["thin_sha256"]
    for site, op, operands in (
        (0x10000527C, "and", "w9, w9, #0x1f"),
        (0x100005280, "ldr", "w10, [x0, #8]"),
        (0x100005284, "stp", "w9, w8, [x1]"),
        (0x100005290, "stp", "w10, wzr, [x1, #8]"),
        (0x100035184, "blraa", "x8, x17"),
    ):
        daemon.instruction(site, op, operands)
    diagnostic = current.read(0xFFFFFE0007049FF8, 128).split(b"\0", 1)[0].decode()
    assert diagnostic.startswith("Expected to deny after handling IPC security policy violation")
    return dict(checks=[words(current, site, 4)[0] for site, _, _ in sites],
                dispositions_16_through_21=[16, 17, 18, 17, 17, 18],
                disposition_tables=[hex(table) for table in tables], mig_stubs=stubs,
                constructors=constructors, daemon_abi_receipt_hash=sha256(prior).hexdigest(),
                daemon_thin_sha256=identity["daemon"]["thin_sha256"],
                publication_diagnostic_format=diagnostic,
                daemon_response_header=words(daemon, 0x100005274, 0x24))


def observe_kernel_identity():
    kernel = subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.uuid"], text=True).strip().lower()
    build = subprocess.check_output(["/usr/bin/sw_vers", "-buildVersion"], text=True).strip()
    output = subprocess.check_output(["/usr/bin/kmutil", "showloaded", "-b", DRIVER],
                                     text=True, stderr=subprocess.DEVNULL)
    assert kernel == IDENTITIES[1][1] and build == "26C5035r"
    assert any(DRIVER in line and IDENTITIES[1][2] in line.lower() for line in output.splitlines())
    return dict(build=build, kernel_uuid=kernel, kext_uuid=IDENTITIES[1][2])


def check_mach_sdk():
    source = """
#include <mach/message.h>
_Static_assert(MACH_MSG_TYPE_COPY_SEND == 19, "copy-send");
_Static_assert(MACH_MSG_TYPE_MAKE_SEND_ONCE == 21, "make-send-once");
_Static_assert(MACH_MSG_TYPE_MOVE_SEND_ONCE == 18, "move-send-once");
_Static_assert(MACH_MSG_TYPE_PORT_SEND_ONCE == 18, "received send-once");
_Static_assert(MACH_MSG_TYPE_PORT_SEND == 17, "received send");
_Static_assert(sizeof(mach_msg_header_t) == 24, "user mach header");
"""
    subprocess.run(["xcrun", "--sdk", "macosx", "clang", "-arch", "arm64e",
                    "-x", "c", "-fsyntax-only", "-"], input=source, text=True, check=True)
    return dict(passed=source.count("_Static_assert"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pinned", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("daemon", type=Path)
    args = parser.parse_args()
    pinned = Collection(args.pinned, IDENTITIES[0])
    current = Collection(args.current, IDENTITIES[1])
    receipt = dict(collection_identities=IDENTITIES, runtime_identity=observe_kernel_identity(), sdk=check_mach_sdk(),
                   compared_functions=compare(pinned, current), reply_space=reply_space_refs(current),
                   control_edges=branch_sites(current), endpoint_fields=endpoint_fields(pinned, current, args.daemon))
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
