#!/usr/bin/env python3
"""Audit the archived open and its two host notifications without running the daemon."""

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

from analyze_zut_trace import decode_descriptors, digest, image_info


RAX_COMMIT = "4748a6ae8bd285369fe1413787b35587832f4dd3"
TRACE_SHA = "78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e"
THIN_SHA = "4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e"
FAT_SHA = "4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7"
GUEST_MESSAGE = re.compile(
    r"\[(0x[0-9a-f]+)\]\s+(send|received) bits=(0x[0-9a-f]+) size=(\d+) "
    r"remote=(0x[0-9a-f]+) local=(0x[0-9a-f]+) voucher=(0x[0-9a-f]+) id=(\d+).*"
)
HEX_ROW = re.compile(r"\[(0x[0-9a-f]+)\]\s+([0-9a-f]{4})\s+((?:[0-9a-f]{2}\s+)+)\|.*")
HOST_SEND = re.compile(
    r"rax-user: bridge: sent id (\d+) \((\d+) bytes, (\d+) descriptors, "
    r"class (0x[0-9a-f]+)\) to host (0x[0-9a-f]+) reply (0x[0-9a-f]+): (0x[0-9a-f]+)"
)
HOST_RECEIVE = re.compile(
    r"rax-user: bridge: received id (\d+) \((\d+) bytes, (\d+) descriptors\) on host (0x[0-9a-f]+)"
)
DEALLOCATE = re.compile(
    r"\[(0x[0-9a-f]+)\] pc=(0x[0-9a-f]+) _kernelrpc_mach_port_deallocate_trap"
    r"\((\d+), (\d+)\) = (0x[0-9a-f]+)"
)


def decode_guest(lines, number, direction, header):
    annotation = GUEST_MESSAGE.fullmatch(lines[number - 1])
    assert annotation and annotation[2] == direction, number
    assert tuple(int(value, 0) for value in annotation.groups()[2:]) == header, number
    raw = bytearray()
    for line in lines[number:]:
        row = HEX_ROW.fullmatch(line)
        if row is None:
            break
        assert row[1] == annotation[1] and int(row[2], 16) == len(raw), number
        raw.extend(bytes.fromhex(row[3]))
    bits, size, remote, local, voucher, message_id = struct.unpack_from("<6I", raw)
    assert (bits, size, remote, local, voucher, message_id) == header and len(raw) >= size
    body = bytes(raw[:size])
    return {
        "line": number,
        "thread": annotation[1],
        "direction": direction,
        "id": message_id,
        "bits": hex(bits),
        "size_bytes": size,
        "remote": hex(remote),
        "local": hex(local),
        "descriptors": decode_descriptors(body, bits),
        "message_hex": body.hex(),
        "trailer_hex": raw[size:].hex(),
    }, body


def verified_record(lines, number, pattern, expected):
    match = pattern.fullmatch(lines[number - 1])
    assert match and match.groups() == expected, number
    return {"line": number, "record": match[0]}


def trace_record(path):
    original = path.read_bytes()
    assert digest(original) == TRACE_SHA
    lines = original.decode().splitlines()
    assert len(lines) == 1748
    matching, body = decode_guest(lines, 1699, "send", (0x1513, 100, 0x1703, 0x507, 0, 2881))
    assert b"IOProviderClass\0" in body and b"com_apple_driver_FairPlayIOKit\0" in body
    matching_reply, _ = decode_guest(lines, 1709, "received", (0x80001200, 40, 0, 0x507, 0, 2981))
    iterator, _ = decode_guest(lines, 1715, "send", (0x1513, 24, 0x1803, 0x507, 0, 2802))
    iterator_reply, _ = decode_guest(lines, 1720, "received", (0x80001200, 40, 0, 0x507, 0, 2902))
    open_request, body = decode_guest(lines, 1726, "send", (0x80001513, 80, 0x1903, 0x507, 0, 2862))
    assert struct.unpack_from("<I", body, 64) == (0,)
    assert struct.unpack_from("<I", body, 76) == (0,)
    open_reply, body = decode_guest(lines, 1736, "received", (0x80001200, 52, 0, 0x507, 0, 2962))
    assert struct.unpack_from("<I", body, 48) == (0xE00002C2,)
    for event, name in [(matching_reply, "0x1803"), (iterator_reply, "0x1903"), (open_reply, "0x0")]:
        assert event["descriptors"] == [{"kind": "port", "offset": 28, "name": name, "disposition": 17}]
    task, properties = open_request["descriptors"]
    assert task == {"kind": "port", "offset": 28, "name": "0x203", "disposition": 19}
    assert properties == {"kind": "ool", "offset": 40, "address": "0x0", "size": 0,
                          "deallocate": 0, "copy": 0, "type": 1}
    guest = [matching, matching_reply, iterator, iterator_reply, open_request, open_reply]
    thread = "0x2de300001"
    assert all(event["thread"] == thread for event in guest)
    assert lines[1741].startswith(f"[{thread}] pc=0x180547c20 mach_msg2_trap(")
    assert lines[1741].endswith(" = 0x0")
    assert lines[1746].startswith(f"[{thread}] pc=0x18054f5dc exit(0)")
    assert lines[1747] == "rax-user: fairplayd.arm64e: exited with status 0"

    bridge = []
    exchanges = [
        (1707, "2881", "100", "0", "0xf03", "2981", "40"),
        (1718, "2802", "24", "0", "0x1103", "2902", "40"),
        (1734, "2862", "80", "2", "0x1503", "2962", "52"),
    ]
    for line, request_id, width, descriptors, destination, reply_id, reply_width in exchanges:
        bridge.append(verified_record(
            lines, line, HOST_SEND,
            (request_id, width, descriptors, "0x200000000", destination, "0x1603", "0x0"),
        ))
        bridge.append(verified_record(lines, line + 1, HOST_RECEIVE, (reply_id, reply_width, "1", "0x1603")))
    ending = []
    for line, name in [(1743, "6403"), (1745, "6147")]:
        ending.append(verified_record(lines, line, DEALLOCATE, (thread, "0x180547ad0", "515", name, "0x0")))
        ending.append(verified_record(lines, line + 1, HOST_RECEIVE, ("65", "36", "0", "0x1c03")))
    host_65 = [i for i, line in enumerate(lines, 1) if line.startswith("rax-user: bridge: received id 65 ")]
    guest_messages = [match.groups() for line in lines if (match := GUEST_MESSAGE.fullmatch(line))]
    guest_65 = [m for m in guest_messages if m[1] == "received" and m[-1] == "65"]
    guest_sends = [int(m[-1]) for m in guest_messages if m[1] == "send"]
    assert host_65 == [1744, 1746] and not guest_65
    assert len(guest_sends) == 22 and 2865 not in guest_sends
    return {
        "sha256": TRACE_SHA,
        "line_count": len(lines),
        "guest_messages": guest,
        "bridge_exchange": bridge,
        "release_and_receive_sequence": ending,
        "host_id_65_lines": host_65,
        "guest_id_65_count": len(guest_65),
        "guest_send_ids": guest_sends,
        "application_result": "0xe00002c2",
        "mach_transport_result": "0x0",
    }


def verify_images(thin_path, container_path):
    thin = thin_path.read_bytes()
    container = container_path.read_bytes()
    assert digest(thin) == THIN_SHA and digest(container) == FAT_SHA
    signature, count = struct.unpack_from(">II", container)
    assert signature == 0xCAFEBABE
    records = [struct.unpack_from(">5I", container, 8 + 20 * i) for i in range(count)]
    matches = [entry for entry in records if entry[:2] == (0x100000C, 0x80000002)]
    assert len(matches) == 1
    _, _, offset, size, alignment = matches[0]
    assert (offset, size, alignment) == (3407872, 17668912, 14)
    assert container[offset:offset + size] == thin
    image = image_info(thin_path)
    code = next(section for section in image["text_sections"] if section["section"] == "__text")
    assert code["sha256"] == "94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e"
    assert image["uuid"] == "204741e9-b89f-32b4-9321-51f3975c7cac"
    del image["path"]
    return {"thin": image, "container_sha256": FAT_SHA, "slice_offset_bytes": offset}


def verify_rax(checkout):
    anchors = {
        "bridge/mod.rs": {
            101: "host::deallocate(n);",
            236: "self.imports.insert(control, Import::Control);",
            249: "HostRight::new(name, false)",
            251: "host::request(name, host::notify::DEAD_NAME, 1, self.control);",
            253: "self.proxies.insert(name, Arc::downgrade(&p));",
        },
        "bridge/host.rs": {
            38: "pub const DEAD_NAME: i32 = 0o110;",
            277: "mach_port_deallocate(task(), name)",
            314: "mach_port_request_notification(",
            320: "disp::MAKE_SEND_ONCE,",
        },
        "bridge/translate.rs": {
            554: "u32_at(raw, 12)",
            555: "u32_at(raw, 20)",
            564: "rax-user: bridge: received id",
            569: "Some(Import::Control)",
            570: "if id == host::notify::DEAD_NAME",
            572: "u32_at(raw, HEADER_SIZE + 8)",
            595: "kmsg::enqueue(proc, m);",
            634: "if name == host::NULL",
            687: "bridge.proxy(name)",
        },
        "mach/ipc.rs": {807: "e.send -= delta;", 808: "if e.send == 0", 812: "self.release(i);"},
        "syscall/mach/port.rs": {169: "proc.ipc.drop_refs(name, kind, 1)", 171: "kmsg::release(proc, rights);"},
    }
    records = []
    for relative, checks in anchors.items():
        path = "src/user/darwin/" + relative
        source = subprocess.check_output(["git", "-C", checkout, "show", f"{RAX_COMMIT}:{path}"])
        lines = source.decode().splitlines()
        assert all(fragment in lines[line - 1] for line, fragment in checks.items()), relative
        records.append({"path": path, "sha256": digest(source), "checked_lines": list(checks)})
    return {"commit": RAX_COMMIT, "files": records, "capture_producer_identity": "unknown"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("thin_daemon", type=Path)
    parser.add_argument("universal_daemon", type=Path)
    parser.add_argument("rax_checkout", type=Path)
    args = parser.parse_args()
    result = {
        "trace": trace_record(args.trace),
        "daemon_image": verify_images(args.thin_daemon, args.universal_daemon),
        "candidate_rax_source": verify_rax(args.rax_checkout),
        "unknown": [
            "capture producer build and historical host kernel build",
            "notification bodies, host receive-map state and exact host deallocation results",
            "historical daemon return address and exact open rejection gate",
        ],
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
