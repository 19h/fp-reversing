#!/usr/bin/env python3
"""Compare two fresh captures and the archived exchange against original call sites."""

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

from analyze_zut_trace import digest, image_info
from audit_archived_iokit_open_retirement import (
    DEALLOCATE,
    GUEST_MESSAGE,
    HOST_RECEIVE,
    HOST_SEND,
    THIN_SHA,
    decode_guest,
    trace_record,
    verified_record,
)


BASELINE_SHA = "3ebfd9c04b5b956e0f090c7f0829771b68adba5b1b94de623843e13463c19747"
RETRY_SHA = "65dac7d52cb4e87eb6a63f751a3d2e5989f72776b276968d65815e04820ebb9c"
RAX_SHA = "b0f3e0f221c9a68b6a9d4be013917d40d0d4d8307c25c84f2feb73add5a78a16"
DAEMON_UUID = "204741e9-b89f-32b4-9321-51f3975c7cac"
THREAD = "0x13ecf00001"
TRAP = re.compile(r"\[(0x[0-9a-f]+)\] pc=(0x[0-9a-f]+) mach_msg2_trap\((.*?)\) = (0x[0-9a-f]+)")
FRAME = re.compile(r"\[(0x[0-9a-f]+)\]\s+> (0x[0-9a-f]+) (.+)")
MAIN_PORT_RETURN = 0x100461cc8
MESSAGE_LINES = [
    (16285, "send", (0x1513, 100, 0x1f03, 0x507, 0, 2881)),
    (16295, "received", (0x80001200, 40, 0, 0x507, 0, 2981)),
    (16310, "send", (0x1513, 24, 0x2003, 0x507, 0, 2802)),
    (16315, "received", (0x80001200, 40, 0, 0x507, 0, 2902)),
    (16330, "send", (0x80001513, 80, 0x2103, 0x507, 0, 2862)),
    (16340, "received", (0x80001200, 52, 0, 0x507, 0, 2962)),
]
SITES = [
    (16300, 0x1003f9598, 0x1010a0d88, 0xa027, "_IOServiceGetMatchingServices"),
    (16320, 0x10036c4a8, 0x1010a0e38, 0xd62a, "_IOIteratorNext"),
    (16346, 0x100478bb4, 0x1010a0b48, 0xe82b, "_IOServiceOpen"),
    (16356, 0x100478c30, 0x1010a0240, 0xbe7e, "_IOObjectRelease"),
    (16365, 0x100483cc4, 0x1010a0240, 0xbe7e, "_IOObjectRelease"),
]
PARENT_FRAMES = (0x1004c9200, 0x1005599a4, 0x1002089cc)
PRIOR_CANDIDATES = (0x1002b7b94, 0x10018458c, 0x100176a0c, 0x1001dcab8, 0x100205980)
TRANSPORT_CALLS = {
    16243: 0x18056b448, 16263: 0x184ebc3cc, 16300: 0x184ebd3dc,
    16320: 0x184ebd59c, 16346: 0x184ebdc6c,
}


def load_capture(path, expected_sha, count):
    data = path.read_bytes()
    assert digest(data) == expected_sha, path.name
    lines = data.decode().splitlines()
    assert len(lines) == count
    return lines


def message_ids(lines, direction):
    return [int(m[8]) for line in lines if (m := GUEST_MESSAGE.fullmatch(line)) and m[2] == direction]


def trap_record(lines, at, thread, sent):
    m = TRAP.fullmatch(lines[at - 1])
    assert m and m[1] == thread and m[2] == "0x180548c20" and m[4] == "0x0", at
    args = [int(arg, 0) for arg in m[3].split(", ")]
    assert len(args) == 8 and args[1] & 3 == 3
    assert args[3] == int(sent["remote"], 16) | int(sent["local"], 16) << 32
    assert args[4] >> 32 == sent["id"]
    assert args[5] & 0xffffffff == len(sent["descriptors"])
    record = {"line": at, "guest_trap_return_pc": m[2], "result": m[4]}
    if at in TRANSPORT_CALLS:
        emit = TRANSPORT_CALLS[at]
        for index, expected in [(at + 1, 0x180548c20), (at + 2, 0x18055b964), (at + 3, emit + 4)]:
            frame = FRAME.fullmatch(lines[index - 1])
            assert frame and frame.groups() == (thread, hex(expected), "[shared region]"), index
        record["framework_transport_call_pc"] = hex(emit)
    return record


def check_memory_entry(lines, request_line, reply_line, trap_line, success):
    request, wire = decode_guest(lines, request_line, "send", (0x80001513, 68, 0x203, 0x507, 0, 4817))
    extent = struct.unpack_from("<Q", wire, 0x30)[0]
    protection = struct.unpack_from("<I", wire, 0x40)[0]
    assert (extent, protection) == (262144, 0x00400001)
    assert request["descriptors"] == [{"kind": "port", "offset": 28, "name": "0x0", "disposition": 19}]
    result = "KERN_SUCCESS" if success else "KERN_RESOURCE_SHORTAGE"
    assert lines[reply_line - 2] == f'[{request["thread"]}] mig mach_make_memory_entry(4817) = {result}'
    reply, body = decode_guest(lines, reply_line, "received",
                               (0x80001200 if success else 0x1200, 56 if success else 36, 0, 0x507, 0, 4917))
    assert reply["thread"] == request["thread"]
    if success:
        assert reply["descriptors"] == [{"kind": "port", "offset": 28, "name": "0x1403", "disposition": 17}]
        assert struct.unpack_from("<Q", body, 0x30)[0] == extent
    else:
        assert struct.unpack_from("<I", body, 0x20)[0] == 6
    return {
        "request_line": request_line, "request_bytes": 68, "requested_extent_bytes": extent,
        "permission": hex(protection), "reply_line": reply_line, "reply_bytes": len(body),
        "reply_descriptors": reply["descriptors"], "mig_status": result,
        "transport": trap_record(lines, trap_line, request["thread"], request),
    }


def check_frames(lines, at, expected_daemon_returns):
    frames = []
    for number, line in enumerate(lines[at:], at + 1):
        hit = FRAME.fullmatch(line)
        if hit is None:
            break
        assert hit[1] == THREAD
        mapping = hit[3]
        if mapping == "[shared region]":
            image = "shared region"
        else:
            assert Path(mapping).name in {"dyld", "fairplayd.arm64e"}, number
            image = Path(mapping).name
        frames.append({"line": number, "pc": hit[2], "image": image})
    assert [int(f["pc"], 16) for f in frames if f["image"] == "fairplayd.arm64e"] == list(expected_daemon_returns)
    trap = TRAP.fullmatch(lines[at - 1]) or DEALLOCATE.fullmatch(lines[at - 1])
    assert trap and frames[0]["pc"] == trap[2]
    return frames


def normalized(message):
    wire = bytearray.fromhex(message["message_hex"])
    wire[8:16] = b"\0" * 8
    if message["id"] in (2981, 2902):
        wire[28:32] = b"\0" * 4
    return bytes(wire)


def check_main_port(lines):
    request, _ = decode_guest(lines, 16234, "send", (0x1513, 24, 0xc03, 0x507, 0, 205))
    reply, _ = decode_guest(lines, 16238, "received", (0x80001200, 40, 0, 0x507, 0, 305))
    version_request, _ = decode_guest(lines, 16253, "send", (0x1513, 24, 0x1f03, 0x507, 0, 2877))
    version_reply, body = decode_guest(lines, 16258, "received", (0x1200, 44, 0, 0x507, 0, 2977))
    assert reply["descriptors"] == [{"kind": "port", "offset": 28, "name": "0x1f03", "disposition": 17}]
    assert struct.unpack_from("<IQ", body, 32) == (0, 0x134647a)
    assert lines[16236] == f"[{THREAD}] mig host_get_io_main(205) = KERN_SUCCESS"
    assert all(message["thread"] == THREAD for message in (request, reply, version_request, version_reply))
    return {
        "guest_messages": [request, reply, version_request, version_reply],
        "transport": [trap_record(lines, 16243, THREAD, request),
                      trap_record(lines, 16263, THREAD, version_request)],
        "bridge": [
            verified_record(lines, 16256, HOST_SEND,
                            ("2877", "24", "0", "0x200000000", "0x2103", "0x2903", "0x0")),
            verified_record(lines, 16257, HOST_RECEIVE, ("2977", "44", "0", "0x2903")),
        ],
        "version_result": "0x134647a",
        "first_host_name_release": verified_record(
            lines, 16276, DEALLOCATE, (THREAD, "0x180548ad0", "515", "3075", "0x0")
        ),
    }


def check_exchange(lines, archived):
    messages = [decode_guest(lines, *spec)[0] for spec in MESSAGE_LINES]
    for message, old in zip(messages, archived["guest_messages"], strict=True):
        assert message["id"] == old["id"] and message["thread"] == THREAD
        assert normalized(message) == normalized(old), message["id"]
    assert messages[1]["descriptors"][0]["name"] == messages[2]["remote"]
    assert messages[3]["descriptors"][0]["name"] == messages[4]["remote"]
    assert all(message["local"] == "0x507" for message in messages)
    transport = [trap_record(lines, spec[0], THREAD, send) for spec, send in zip(SITES[:3], messages[::2])]
    release = [
        verified_record(lines, 16356, DEALLOCATE, (THREAD, "0x180548ad0", "515", "8451", "0x0")),
        verified_record(lines, 16365, DEALLOCATE, (THREAD, "0x180548ad0", "515", "8195", "0x0")),
    ]
    bridge = []
    for at, msg, reply, dest, width, reply_width, desc in [
        (16293, "2881", "2981", "0x2103", "100", "40", "0"),
        (16313, "2802", "2902", "0x2803", "24", "40", "0"),
        (16338, "2862", "2962", "0x2703", "80", "52", "2"),
    ]:
        bridge.append(verified_record(lines, at, HOST_SEND, (msg, width, desc, "0x200000000", dest, "0x2903", "0x0")))
        bridge.append(verified_record(lines, at + 1, HOST_RECEIVE, (reply, reply_width, "1", "0x2903")))
    notification_lines = [14228, 16364, 16373]
    notifications = [verified_record(lines, at, HOST_RECEIVE, ("65", "36", "0", "0x1c03"))
                     for at in notification_lines]
    assert [i for i, line in enumerate(lines, 1) if line.startswith("rax-user: bridge: received id 65 ")] == notification_lines
    sends = message_ids(lines, "send")
    receives = message_ids(lines, "received")
    assert sends[-5:] == [205, 2877, 2881, 2802, 2862]
    assert not {2816, 2865}.intersection(sends) and not {65, 2916, 2965}.intersection(receives)
    assert lines[16373] == f"[{THREAD}] pc=0x1805505dc exit(0) = -1 Errno(-2)"
    exit_record = re.fullmatch(r"rax-user: (.+): exited with status 0", lines[-1])
    assert exit_record and Path(exit_record[1]).name == "fairplayd.arm64e"
    return {
        "guest_messages": messages, "guest_transport": transport, "guest_release": release,
        "host_bridge": bridge, "host_notifications": notifications,
        "guest_send_ids": sends, "guest_receive_ids": receives,
        "message_bytes_matching_archive_after_name_normalization": [message["id"] for message in messages],
        "normalization": "Clear 32-bit remote/local names, and iterator/service descriptor name in replies 2981/2902.",
        "application_result": "0xe00002c2", "connection": "0x0",
        "guest_exit_argument": 0, "runner_status": 0,
    }


def call_word(binary, raw, text, pc, modifier=None):
    start = pc if modifier is None else pc - 4
    output = subprocess.check_output([
        "xcrun", "llvm-objdump", "--disassemble", f"--start-address={start:#x}",
        f"--stop-address={pc + 4:#x}", binary,
    ], text=True)
    assert re.search(rf"(?m)^\s*{pc:x}:\s+d73f0911\s+blraa\s+x8, x17\s*$", output)
    offset = text["file_offset"] + pc - int(text["address"], 16)
    assert raw[offset:offset + 4] == bytes.fromhex("11093fd7")
    if modifier is not None:
        assert struct.unpack_from("<I", raw, offset - 4)[0] == 0xd2800011 | modifier << 5
    return {"pc": hex(pc), "file_offset_bytes": offset, "instruction_hex": raw[offset:offset + 4].hex()}


def check_sites(lines, binary):
    raw = binary.read_bytes()
    image = image_info(binary)
    del image["path"]
    assert image["uuid"] == DAEMON_UUID and image["sha256"] == THIN_SHA
    text = next(section for section in image["text_sections"] if section["section"] == "__text")
    frame_cell_accesses = []
    for pc, word, meaning in [
        (0x100461cb8, 0x9101f3e1, "IOMainPort X1 points to SP+0x7c"),
        (0x1003f9578, 0xb9407fe0, "Matching W0 loads the u32 at SP+0x7c"),
    ]:
        offset = text["file_offset"] + pc - int(text["address"], 16)
        assert struct.unpack_from("<I", raw, offset)[0] == word
        frame_cell_accesses.append({"pc": hex(pc), "instruction": hex(word), "meaning": meaning})
    binds = subprocess.check_output(["xcrun", "dyld_info", "-fixups", "-arch", "arm64e", binary], text=True)
    assert re.search(r"0x1010A0988\s+auth-bind\s+IOKit/_IOMainPort \(div=0x6240 ad=0 key=IA\)", binds)
    main_port = {
        "return_address": hex(MAIN_PORT_RETURN),
        "call": call_word(binary, raw, text, MAIN_PORT_RETURN - 4, 0x6240),
        "slot": "0x1010a0988", "symbol": "_IOMainPort", "ia_diversity": "0x6240",
        "trace_frames": [check_frames(lines, at, (MAIN_PORT_RETURN, *PARENT_FRAMES))
                         for at in (16243, 16263, 16276)],
    }
    result = []
    for (line, ret, slot, modifier, symbol), prior in zip(SITES, PRIOR_CANDIDATES, strict=True):
        assert re.search(rf"0x{slot:X}\s+auth-bind\s+IOKit/{symbol} \(div=0x{modifier:X} ad=0 key=IA\)", binds)
        result.append({
            "trace_frames": check_frames(lines, line, (ret, *PARENT_FRAMES)),
            "return_address": hex(ret), "call": call_word(binary, raw, text, ret - 4, modifier),
            "slot": hex(slot), "symbol": symbol, "ia_diversity": hex(modifier),
            "selector26_candidate_pc": hex(prior),
        })
    parents = [call_word(binary, raw, text, pc - 4, modifier)
               for pc, modifier in zip(PARENT_FRAMES, (0x0a74, 0x9843, 0x43e9), strict=True)]
    return {"image": image, "main_port": main_port, "sites": result, "common_outer_call_words": parents,
            "main_port_cell_accesses": frame_cell_accesses}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("initial_capture", type=Path)
    parser.add_argument("retry_capture", type=Path)
    parser.add_argument("archive", type=Path)
    parser.add_argument("daemon", type=Path)
    parser.add_argument("rax_user", type=Path)
    args = parser.parse_args()
    assert digest(args.rax_user.read_bytes()) == RAX_SHA
    baseline = load_capture(args.initial_capture, BASELINE_SHA, 14196)
    retry = load_capture(args.retry_capture, RETRY_SHA, 16380)
    archive = trace_record(args.archive)
    assert not {2881, 2802, 2862, 2865}.intersection(message_ids(baseline, "send"))
    assert baseline[14194].endswith("exception Breakpoint { pc: 6532433904, imm: 1 }")
    report = {
        "capture_runner": {"version": "0.1.0", "sha256": RAX_SHA, "host_build": "26C5035r",
                           "arguments": ["--clear-env", "--strace", "--strace-pc", "--strace-stack=64",
                                         "--strace-mach-msg=128"]},
        "initial_capture": {"sha256": BASELINE_SHA, "lines": len(baseline), "runner_status": 133,
                            "guest_breakpoint_pc": hex(6532433904),
                            "startup_vm": check_memory_entry(baseline, 14150, 14158, 14162, False)},
        "retry_capture": {"sha256": RETRY_SHA, "lines": len(retry),
                          "startup_vm": check_memory_entry(retry, 14068, 14076, 14082, True),
                          "main_port": check_main_port(retry), "exchange": check_exchange(retry, archive)},
        "archive_sha256": archive["sha256"],
        "daemon_callsite_correlation": check_sites(retry, args.daemon),
        "native_daemon_observed": False,
        "successful_connection_observed": False,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
