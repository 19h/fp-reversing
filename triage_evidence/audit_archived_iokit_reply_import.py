#!/usr/bin/env python3
"""Recheck the archived IOKit replies and the candidate bridge's import path."""

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

from analyze_zut_trace import digest
from audit_archived_iokit_open_retirement import (
    HOST_RECEIVE, RAX_COMMIT, TRACE_SHA, decode_guest, verified_record,
)
from audit_archived_iokit_task_translation import XNU_COMMIT, check_source


RAX_SOURCES = {
    "bridge/mod.rs": {288: "fn reply_export", 293: "host::reply_port()?",
                     296: "self.imports.insert(r, Import::Port(port.clone()))"},
    "bridge/host.rs": {56: "SEND_MSG", 57: "RCV_MSG", 58: "RCV_LARGE", 61: "3 << 24",
                      62: "KOBJECT_CALL: u64 = 0x2_0000_0000", 268: "0x1000u32.to_le_bytes()",
                      271: "mach_port_construct(task()"},
    "bridge/translate.rs": {
        20: "64 << 10", 208: "host::disp::MAKE_SEND_ONCE",
        402: "class == host::opt64::KOBJECT_CALL", 404: "host::opt64::TRAILER_AUDIT",
        411: "if combined { local }", 413: "kernel::names_memory(m.id)",
        424: "host::msg2(", 432: "combined && mr == host::mr::SUCCESS",
        436: "received(proc, &buf)", 522: "host::opt::TRAILER_AUDIT",
        554: "u32_at(raw, 12)", 564: "bridge: received id", 591: "Some(Import::Port(p))",
        594: "to_guest(&mut proc.bridge, raw, p, &own)", 595: "kmsg::enqueue(proc, m);",
        634: "name == host::NULL", 635: "return None;", 638: "Some(Right::Dead)",
        687: "bridge.proxy(name)", 689: "Some(Right::Send(p))", 721: "raw[HEADER_SIZE..size].to_vec()",
        724: "u32_at(&body, 0)", 736: "desc::PORT", 738: "from_host(bridge, u32_at(&body, off)",
        739: "items.push((off, Item::Port", 774: "(size + 3) & !3", 775: "raw.len() >= t + 52",
        778: "u32_at(raw, t + 20 + 4 * i)", 781: "sec: [u32_at(raw, t + 12), u32_at(raw, t + 16)]",
        785: "Sender::KERNEL",
    },
    "mach/ipc.rs": {439: "(index << 8) | u32::from(generation)", 460: "0x03", 462: "| 0x03",
                    557: "Self::name(i, e.generation)", 564: "Self::name(i, e.generation)"},
    "mach/msg.rs": {120: "pub fn rcv_elements", 121: "((o >> 24) & 0xf)", 128: "0 => 8",
                    131: "3 => 52", 151: "sec: [0, 1]", 152: "audit: [0; 8]",
                    261: "0u32.to_le_bytes()", 262: "size as u32", 272: "t.truncate(size)"},
    "syscall/mach/kmsg.rs": {
        877: "None => MACH_PORT_NULL", 878: "Some(Right::Dead) => MACH_PORT_DEAD",
        884: "proc.ipc.insert(r.clone())", 888: "MACH_PORT_DEAD", 948: "bits::set(reply_type, dest_type",
        969: "out.extend_from_slice(&m.body)", 1001: "copyout_right(proc, right)",
        1002: "m.body[pos..pos + 4]", 1004: "m.body[pos + 10] = d as u8",
    },
    "syscall/mach/msg.rs": {628: "let sender = m.sender", 641: "kmsg::copyout(ctx.proc",
                            657: "msg::trailer(options, seqno, &sender, context)",
                            660: "dump::received(ctx, &out, &aux, &sender)"},
    "syscall/mach/dump.rs": {65: "*sender == Sender::KERNEL", 66: "text.push_str(\" from the kernel\")"},
    "mig/host.rs": {80: "h::HOST_GET_IO_MAIN =>", 87: "bridge::io_main(ctx.proc)", 88: "Ok(Out::Complex("},
    "mig/mod.rs": {358: "id: req.id.wrapping_add(100)", 361: "sender: Sender::KERNEL"},
}
XNU_SOURCES = {
    "osfmk/ipc/ipc_kmsg.c": (
        "0b7ee06c334d9b891ec3643c0b68f20bc419225ff6f3413e6bb7e5b05bcdeea2",
        {535: "KERNEL_SECURITY_TOKEN_VALUE", 536: "KERNEL_AUDIT_TOKEN_VALUE",
         541: "sender == TASK_NULL", 5236: "ipc_kobject_server(", 5243: "ipc_kmsg_init_trailer_and_sign(kmsg, TASK_NULL)"},
    ),
    "osfmk/mach/message.h": (
        "ad64b7b413b42e196dc43a54a5978aa049b9133db1fe9369893f12ad4718c615",
        {765: "} mach_msg_audit_trailer_t;", 845: "MACH_MSG_TRAILER_MINIMUM_SIZE",
         878: "KERNEL_SECURITY_TOKEN_VALUE", 881: "KERNEL_AUDIT_TOKEN_VALUE", 1180: "MACH_RCV_TRAILER_AUDIT  3"},
    ),
    "osfmk/mach/port.h": (
        "0ec7d265d9d27ea8911506038edbf7e14498340661470157ea31913736c3473c",
        {519: "MPO_REPLY_PORT                      = MPO_MAKE_PORT_TYPE(0, 4),  /* 0x1000 */"},
    ),
}
REPLIES = [
    (305, 1681, 1686, 40, "0x1703"),
    (2977, 1692, 1697, 44, None),
    (2981, 1709, 1714, 40, "0x1803"),
    (2902, 1720, 1725, 40, "0x1903"),
    (2962, 1736, 1742, 52, "0x0"),
]


def check_replies(trace):
    original = trace.read_bytes()
    assert digest(original) == TRACE_SHA
    lines = original.decode().splitlines()
    records = []
    for msgid, line, trap_line, width, name in REPLIES:
        count = int(name is not None)
        bits = 0x1200 | count * 0x80000000
        guest, body = decode_guest(lines, line, "received", (bits, width, 0, 0x507, 0, msgid))
        expected = [] if name is None else [{"kind": "port", "offset": 28, "name": name, "disposition": 17}]
        assert guest["descriptors"] == expected
        assert guest["trailer_hex"] == "0000000008000000"
        assert guest["thread"] == "0x2de300001"
        assert f"({width + 8} bytes with trailer) from the kernel" in lines[line - 1]
        trap = re.fullmatch(r"\[0x2de300001\] pc=0x180547c20 mach_msg2_trap\((.*)\) = 0x0",
                            lines[trap_line - 1])
        assert trap, trap_line
        _, options, _, port_pair, id_pair, recv_pair, rcv_size, _ = [
            int(arg, 0) for arg in trap[1].split(", ")
        ]
        assert (options, id_pair >> 32, recv_pair >> 32, port_pair >> 32, rcv_size) == (
            0x200000003, msgid - 100, 0x507, 0x507, width + 8
        )
        record = {"guest": guest, "trap_line": trap_line, "trap_options": hex(options),
                  "guest_receive_capacity_bytes": rcv_size}
        if msgid == 305:
            assert lines[line - 2].endswith("mig host_get_io_main(205) = KERN_SUCCESS")
        else:
            record["host"] = verified_record(lines, line - 1, HOST_RECEIVE,
                                             (str(msgid), str(width), str(count), "0x1603"))
        if msgid == 2962:
            assert body[40:48] == bytes.fromhex("0000000001000000")
            assert struct.unpack_from("<I", body, 48) == (0xE00002C2,)
        records.append(record)
    return records


def check_memory_routines(checkout):
    relative = "src/user/darwin/bridge/kernel.rs"
    raw = subprocess.check_output(["git", "-C", checkout, "show", f"{RAX_COMMIT}:{relative}"])
    source = raw.decode()
    ids = {name: int(value) for name, value in re.findall(r"pub const (\w+): i32 = (\d+);", source)}
    sets = {}
    for name in ("refused", "names_memory"):
        body = re.search(rf"pub fn {name}\(id: i32\) -> bool \{{([^}}]+)\}}", source)
        assert body is not None, name
        sets[name] = sorted(ids[key] for key in re.findall(r"id::(\w+)", body[1]))
        assert sets[name] and 2862 not in sets[name]
    return {"path": relative, "sha256": digest(raw), "members": sets}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("rax_checkout", type=Path)
    parser.add_argument("xnu_checkout", type=Path)
    args = parser.parse_args()
    print(json.dumps({
        "trace_sha256": TRACE_SHA, "records": check_replies(args.trace),
        "candidate_rax": {
            "revision": RAX_COMMIT,
            "files": [check_source(args.rax_checkout, RAX_COMMIT, "src/user/darwin/" + rel, anchors)
                      for rel, anchors in RAX_SOURCES.items()],
            "routine_dispatch": check_memory_routines(args.rax_checkout),
        },
        "reference_xnu": {
            "revision": XNU_COMMIT,
            "files": [check_source(args.xnu_checkout, XNU_COMMIT, rel, anchors, sha)
                      for rel, (sha, anchors) in XNU_SOURCES.items()],
        },
        "candidate_combined_host_receive": {
            "options": hex(0x200000000 | 3 << 24 | 7), "capacity_bytes": 64 << 10,
            "audit_trailer_bytes": 52, "historical_raw_trailer": "unknown",
        },
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
