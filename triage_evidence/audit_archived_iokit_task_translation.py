#!/usr/bin/env python3
"""Check the archived IOKit task descriptor and the pinned bridge source offline."""

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

from analyze_zut_trace import digest
from audit_archived_iokit_open_retirement import RAX_COMMIT, TRACE_SHA, trace_record


XNU_COMMIT = "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea"
XNU_SOURCES = {
    "iokit/Kernel/IOUserClient.cpp": (
        "a09c525b144ecbf834bb2b69f0c78b93358601ee22045340609b30acc8e0a6e7",
        {4399: "owningTask != current_task()", 4442: "service->newUserClient( owningTask, (void *) owningTask",
         4606: "*result = res;"},
    ),
    "osfmk/device/device.defs": (
        "3d94c7a74cbd20ac30a62d104422ece961654f6f8cb787118a5f563d6e08a6de",
        {585: "routine io_service_open_extended(", 587: "owningTask", 591: "out result"},
    ),
    "osfmk/mach/mach_types.defs": (
        "cd4efafcca16f949be52003c4451e6724b2596edd4770d4fdc7ae5ff0c9de6da",
        {125: "type task_t = mach_port_t", 127: "convert_port_to_task_mig"},
    ),
    "osfmk/ipc/ipc_kmsg.c": (
        "0b7ee06c334d9b891ec3643c0b68f20bc419225ff6f3413e6bb7e5b05bcdeea2",
        {5227: "ip_in_space(port, ipc_space_kernel)", 5236: "ipc_kobject_server(port, kmsg, options)"},
    ),
}
RAX_SOURCES = {
    "syscall/mach/mod.rs": {250: "trap::TASK_SELF_TRAP", 253: "ctx.proc.task_port.clone()"},
    "process.rs": {1187: "Port::new(KObject::Task)", 1189: "ipc.insert(Right::Send(task_port.clone()))"},
    "syscall/mach/msg.rs": {
        456: "dump::send(ctx", 458: "kmsg::copyin(ctx", 487: "options & opt::CFI_MASK",
        488: "bridge::send(ctx.proc, m, wait, class)",
    },
    "syscall/mach/kmsg.rs": {
        732: "copyin_right(ctx.proc, name, ud)",
        746: "vec![0u8; size as usize]",
        859: "m.items.push((4 + pos, item))",
    },
    "mach/ipc.rs": {746: "disp::COPY_SEND", 751: "srights += 1", 752: "Ok(Right::Send(port))"},
    "mach/msg.rs": {15: "HEADER_SIZE: usize = 24", 51: "((local & 0x1f) << 8)"},
    "bridge/mod.rs": {575: "allows_host_services()", 582: "translate::forward(proc, m, timeout, class)"},
    "bridge/host.rs": {
        27: "MOVE_SEND: u32 = 17", 31: "MAKE_SEND_ONCE: u32 = 21", 62: "KOBJECT_CALL: u64 = 0x2_0000_0000",
        202: "unsafe { mach_task_self_ }", 242: "mach_msg2_internal(", 283: "mach_port_mod_refs",
        382: "mod_refs(task(), right::SEND, 1).then(task)",
    },
    "bridge/translate.rs": {
        103: "host::mod_refs(n, host::right::SEND, 1)",
        120: "bridge.mirror.arm()", 121: "host::task_port()", 141: "moved(n, host::disp::MOVE_SEND)",
        208: "host::disp::MAKE_SEND_ONCE", 229: "host::deallocate(m.name)", 263: "kmsg::release_send(proc, &p)",
        324: "bits::set(remote_disp, local_disp, 0", 335: "HEADER_SIZE + off",
        342: "copy_from_slice(&name.to_le_bytes())", 343: "buf[at + 10] = d as u8",
        353: "data.as_ptr() as u64", 356: "data.len() as u32", 402: "local_disp == host::disp::MAKE_SEND_ONCE",
        420: "super::mirror::before_send(proc)", 424: "host::msg2(", 432: "combined && mr == host::mr::SUCCESS",
        436: "received(proc, &buf)", 553: "super::mirror::after_receive(proc)",
    },
    "bridge/kernel.rs": {36: "pub fn refused", 39: "MAP_SHARED_MEMORY | id::MAP_MEMORY_INTO_TASK",
                         44: "pub fn names_memory", 51: "id::PROPERTY_BIN_BUF"},
    "bridge/mirror.rs": {57: "self.armed = true", 67: "reserve(proc)", 82: "host::vm_stamp()",
                         103: "adopt(proc, r)", 126: "proc.space.is_free", 162: "proc.space.map"},
}
KERNEL_RECEIPT = Path(__file__).with_name("live_fairplay_iokit_open_audit.json.zst")
KERNEL_RECEIPT_SHA = "e97b28781c8260712dd3768c7ce7f2b8f49d270d48b5dda9a64eb341ac35889c"
KERNEL_WORDS = {
    "0xfffffe000be81bb4": "d000fb97", "0xfffffe000be81bf4": "24f01c94",
    "0xfffffe000c5bdd38": "d4feffb4", "0xfffffe000c5bdd48": "9f0200eb",
    "0xfffffe000c5bdda8": "e10314aa", "0xfffffe000c5bddac": "e20314aa",
    "0xfffffe000c5bddbc": "10093fd7", "0xfffffe000c5bdde0": "390100b9",
    "0xfffffe000a5452a4": "206c0694",
}


def check_source(checkout, revision, relative, anchors, sha256=None):
    data = subprocess.check_output(["git", "-C", checkout, "show", f"{revision}:{relative}"])
    if sha256 is not None:
        assert digest(data) == sha256, relative
    lines = data.decode().splitlines()
    for line, anchor in anchors.items():
        assert anchor in lines[line - 1], (relative, line)
    return {"path": relative, "sha256": digest(data), "checked_lines": list(anchors)}


def check_trace(path):
    archived = trace_record(path)
    raw = path.read_bytes()
    assert digest(raw) == TRACE_SHA
    lines = raw.decode().splitlines()
    task_self_pattern = re.compile(r"\[(0x[0-9a-f]+)\] pc=(0x[0-9a-f]+) task_self_trap\(\) = (0x[0-9a-f]+)")
    task_self = [(i, *hit.groups()) for i, line in enumerate(lines, 1)
                 if (hit := task_self_pattern.fullmatch(line))]
    assert task_self == [(1, "0x2de300001", "0x1010e1654", "0x203"),
                         (1125, "0x2de300001", "0x180547b48", "0x203")]
    request = next(record for record in archived["guest_messages"] if record["id"] == 2862)
    reply = next(record for record in archived["guest_messages"] if record["id"] == 2962)
    assert request["descriptors"][0]["name"] == task_self[-1][3]
    assert request["thread"] == task_self[-1][1]
    body = bytes.fromhex(request["message_hex"])
    bits, size, remote, local, voucher, msgid = struct.unpack_from("<6I", body)
    assert (bits & 31, bits >> 8 & 31, body[38]) == (19, 21, 19)
    assert (size, remote, local, voucher, msgid) == (80, 0x1903, 0x507, 0, 2862)
    host_bits = (bits & 0x80000000) | (21 << 8) | 17
    assert host_bits == 0x80001511
    mirror_logs = [i for i, line in enumerate(lines, 1) if line.startswith((
        "rax-user: bridge: host service mapped ", "rax-user: bridge: host mapping ",
        "rax-user: bridge: no memory entry of host mapping ",
    ))]
    assert not mirror_logs
    return {
        "sha256": TRACE_SHA, "task_self_traps": task_self, "guest_open_request": request,
        "guest_open_reply": reply, "host_open_bridge_records": archived["bridge_exchange"][-2:],
        "printed_mapping_diagnostic_lines": mirror_logs,
        "conditional_host_projection": {
            "message_bits": hex(host_bits), "task_name": "host mach_task_self_ (numeric name unknown)",
            "task_name_offset_bytes": 28, "task_disposition": 17, "task_disposition_offset_bytes": 38,
            "properties_bytes": 0,
        },
    }


def check_kernel_receipt():
    raw = subprocess.check_output(["zstd", "-dc", KERNEL_RECEIPT])
    assert digest(raw) == KERNEL_RECEIPT_SHA
    receipt = json.loads(raw)
    checks = {record["address"]: record for record in receipt["current_kernel_checks"]}
    assert receipt["trace"]["sha256"] == TRACE_SHA
    assert receipt["open_record"]["stub"]["target"] == "0xfffffe000be81ac4"
    assert all(checks[pc]["bytes"] == word for pc, word in KERNEL_WORDS.items())
    return {"receipt_sha256": KERNEL_RECEIPT_SHA, "build": receipt["build"],
            "kernel_identity": receipt["kernel_identity"], "sites": [checks[pc] for pc in KERNEL_WORDS]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("rax_checkout", type=Path)
    parser.add_argument("xnu_checkout", type=Path)
    args = parser.parse_args()
    print(json.dumps({
        "trace": check_trace(args.trace),
        "candidate_rax": {
            "commit": RAX_COMMIT,
            "files": [check_source(args.rax_checkout, RAX_COMMIT, "src/user/darwin/" + rel, anchors)
                      for rel, anchors in RAX_SOURCES.items()],
        },
        "reference_xnu": {
            "commit": XNU_COMMIT,
            "files": [check_source(args.xnu_checkout, XNU_COMMIT, rel, anchors, sha)
                      for rel, (sha, anchors) in XNU_SOURCES.items()],
        },
        "current_kernel_receipt": check_kernel_receipt(),
        "historical_producer_task_port_and_entitlement_state": "unknown",
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
