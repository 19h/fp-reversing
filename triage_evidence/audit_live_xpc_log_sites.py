#!/usr/bin/env python3
"""Join recorded libxpc event offsets to original installed-cache instructions."""

from bisect import bisect_right
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess

from bootpolicy_cache_reader import Cache, Dylib, CS


NATIVE_RECEIPT = "fairplay_native_xpc_observation.json.zst"
LIBXPC = "/usr/lib/system/libxpc.dylib"
STUBS = {
    0x18806CB50: ("/usr/lib/system/libsystem_pthread.dylib", "_pthread_getspecific"),
    0x18806CB80: ("/usr/lib/system/libsystem_pthread.dylib", "_pthread_setspecific"),
    0x188087490: ("/usr/lib/system/libsystem_trace.dylib", "__os_log_impl"),
    0x1880879D0: ("/usr/lib/system/libsystem_kernel.dylib", "_mach_port_request_notification"),
    0x18806D230: ("/usr/lib/system/libsystem_kernel.dylib", "_mach_msg"),
    0x188087690: ("/usr/lib/system/libdispatch.dylib", "_dispatch_mach_cancel"),
    0x1880876A0: ("/usr/lib/system/libdispatch.dylib", "_dispatch_mach_connect"),
    0x1880876B0: ("/usr/lib/system/libdispatch.dylib", "_dispatch_mach_create_4libxpc"),
    0x188087710: ("/usr/lib/system/libdispatch.dylib", "_dispatch_mach_msg_get_msg"),
    0x188087730: ("/usr/lib/system/libdispatch.dylib", "_dispatch_mach_reconnect"),
}
FUNCTIONS = {
    0x184BBA4E0: "__xpc_connection_check_in",
    0x184BBC0C0: "_xpc_connection_activate",
    0x184BBC15C: "__xpc_connection_activate_if_needed",
    0x184BBC4A8: "__xpc_connection_init",
    0x184BBDFA0: "__xpc_connection_mach_event",
    0x184BBEA54: "__xpc_connection_set_creds",
    0x184BBF320: "_xpc_connection_resume",
    0x184BC6900: "__xpc_connection_pass2mig",
    0x184BC73F4: "__Xmach_notify_no_senders",
    0x184BCE224: "__xpc_connection_create",
    0x184BD8E00: "__xpc_connection_cancel",
    0x184BF4814: "_notify_server_routine",
}
FORMATS = {
    0x184C0257A: "[%p] %{public}s connection: mach=%{bool}d "
                 "listener=%{bool}d peer=%{bool}d name=%{public}s",
    0x184C01CFE: "[%p] invalidated because the client process (pid %d) either "
                 "cancelled the connection or exited",
    0x184BFBD02: "activating",
    0x184BFBA5D: "%s.peer[%d]",
    0x184BFB9B9: "%s.%p",
}


def connect_stub(cache, stub, library, symbol):
    raw = cache.read(stub, 16)
    instructions = list(CS.disasm(raw, stub))
    assert [insn.mnemonic for insn in instructions] == ["adrp", "add", "ldr", "braa"]
    slot = sum(int(insn.op_str.split("#")[1], 0) for insn in instructions[:2])
    pointer = cache.pointer(slot)
    target = int(pointer["target"], 16)
    assert library.exports[symbol]["address"] == target
    return dict(stub=hex(stub), bytes=raw.hex(), slot=hex(slot), word=pointer["raw_word"],
                target=hex(target), image=Path(library.path).name, uuid=library.uuid, symbol=symbol)


def direct_call(cache, site, target):
    raw = cache.read(site, 4)
    word, = struct.unpack("<I", raw)
    assert word >> 26 == 0b100101
    imm26 = word & 0x3FFFFFF
    displacement = (imm26 ^ 0x2000000) - 0x2000000
    assert site + 4 * displacement == target
    return dict(site=hex(site), target=hex(target), bytes=raw.hex())


def literal_references(cache, library):
    section = next(section for section in library.sections if section["name"] == "__text")
    start = section["address"]
    raw = cache.read(start, section["size"])
    refs = {address: [] for address in FORMATS}
    words = (word for (word,) in struct.iter_unpack("<I", raw))
    first = next(words)
    for index, second in enumerate(words):
        if (first & 0x9F000000 == 0x90000000 and second & 0xFF800000 == 0x91000000
                and first & 31 == (second >> 5) & 31):
            pc = start + 4 * index
            imm = (((first >> 5) & 0x7FFFF) << 2) | ((first >> 29) & 3)
            page = (pc & ~0xFFF) + 4096 * ((imm ^ 0x100000) - 0x100000)
            immediate = (second >> 10) & 0xFFF
            target = page + (immediate << (12 if second & (1 << 22) else 0))
            if target in refs:
                refs[target].append(hex(pc))
        first = second
    return dict(text_bytes=len(raw), text_sha256=sha256(raw).hexdigest(),
                references={hex(address): locations for address, locations in refs.items()})


def verify_sdk():
    sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
    assertions = (
        ("header_size", "sizeof(mach_msg_header_t)", 24),
        ("message_id_offset", "offsetof(mach_msg_header_t, msgh_id)", 20),
        ("port_descriptor_size", "sizeof(mach_msg_port_descriptor_t)", 12),
        ("audit_token_offset", "offsetof(mach_msg_audit_trailer_t, msgh_audit)", 20),
        ("no_senders_size_excluding_trailer", "offsetof(mach_no_senders_notification_t, trailer)", 36),
        ("no_senders_id", "MACH_NOTIFY_NO_SENDERS", 70),
        ("port_destroyed_id", "MACH_NOTIFY_PORT_DESTROYED", 69),
        ("copy_send", "MACH_MSG_TYPE_COPY_SEND", 19),
        ("make_send", "MACH_MSG_TYPE_MAKE_SEND", 20),
        ("make_send_once", "MACH_MSG_TYPE_MAKE_SEND_ONCE", 21),
        ("received_receive", "MACH_MSG_TYPE_PORT_RECEIVE", 16),
        ("received_send", "MACH_MSG_TYPE_PORT_SEND", 17),
        ("descriptor_port_type", "MACH_MSG_PORT_DESCRIPTOR", 0),
    )
    source = "#include <stddef.h>\n#include <mach/notify.h>\n"
    source += "".join(f'_Static_assert(({expr}) == {value}, "{key}");\n'
                      for key, expr, value in assertions)
    subprocess.run(["xcrun", "--sdk", "macosx", "clang", "-isysroot", sdk, "-arch", "arm64e",
                    "-x", "c", "-fsyntax-only", "-"], input=source, text=True, check=True)
    return dict(sdk=Path(sdk).name, assertions={key: value for key, _, value in assertions})


def audit():
    receipt = Path(__file__).with_name(NATIVE_RECEIPT)
    source = subprocess.check_output(["zstd", "-dc", receipt])
    native = json.loads(source)
    cache = Cache()
    libraries = {path: Dylib(cache, path)
                 for path in sorted({LIBXPC} | {path for path, _ in STUBS.values()})}
    xpc = libraries[LIBXPC]
    functions = {}
    instructions = {}
    for address, symbol in FUNCTIONS.items():
        assert symbol in {row["name"] for row in xpc.symbols_at(address)}
        function = xpc.function(address)
        assert len(function["instructions"]) * 4 == len(bytes.fromhex(function["bytes"]))
        functions[symbol] = function
        instructions.update((int(row["ea"], 16), (row["mnemonic"], row["operands"]))
                            for row in function["instructions"])
    stubs = [connect_stub(cache, stub, libraries[library], symbol)
             for stub, (library, symbol) in sorted(STUBS.items())]
    events = {}
    for role, symbol in (("akd_activation", "__xpc_connection_activate_if_needed"),
                         ("adid_activation", "__xpc_connection_activate_if_needed"),
                         ("adid_invalidation", "__Xmach_notify_no_senders")):
        log, = native[role + "_log_sites"]
        assert log["uuid"].lower() == xpc.uuid and log["image"] == "libxpc.dylib"
        pc = xpc.base + log["program_counter"]
        containing_entry = xpc.functions[bisect_right(xpc.functions, pc) - 1]
        assert containing_entry == int(functions[symbol]["start"], 16)
        logger = direct_call(cache, pc - 4, 0x188087490)
        events[role] = dict(**log, symbol=symbol, pc=hex(pc), logger=logger)
    calls = [direct_call(cache, site, target) for site, target in (
        (0x184BBC364, 0x184BBC4A8), (0x184BBC37C, 0x184BBC4A8),
        (0x184BBCA34, 0x184BBA4E0), (0x184BBA668, 0x1880876A0),
        (0x184BBA6B0, 0x188087730), (0x184BBA68C, 0x18806D230),
        (0x184BBA638, 0x1880879D0), (0x184BBC940, 0x1880879D0),
        (0x184BBE4B4, 0x184BC6900), (0x184BBE508, 0x184BDA15C),
        (0x184BBE518, 0x184BDA9C0), (0x184BBE52C, 0x184BDAA88),
        (0x184BBE598, 0x184BCE224), (0x184BBE608, 0x184BBEA54),
        (0x184BBE874, 0x184BBFFB8), (0x184BBE8D0, 0x184BBF320),
        (0x184BC6994, 0x18806CB80), (0x184BC742C, 0x18806CB50),
        (0x184BC7444, 0x184BD8E00), (0x184BD8E50, 0x188087690),
    )]
    for address, expected in FORMATS.items():
        assert cache.cstring(address, 256) == expected
    for address, page, offset in ((0x184BBC33C, 0x184C02000, 0x57A),
                                  (0x184BC74AC, 0x184C01000, 0xCFE)):
        assert instructions[address] == ("adrp", f"x3, #{page:#x}")
        assert instructions[address + 4] == ("add", f"x3, x3, #{offset:#x}")
        assert page + offset in FORMATS
    references = literal_references(cache, xpc)
    assert references["references"]["0x184c0257a"] == ["0x184bbc33c"]
    assert references["references"]["0x184c01cfe"] == ["0x184bc74ac"]
    assert references["references"]["0x184bfba5d"] == ["0x184bbe578"]
    assert references["references"]["0x184bfb9b9"] == ["0x184bce26c"]

    table = 0x1E240C818
    notification_id = 70
    selector_slot = table + notification_id * 40 - 0x9F8
    selection = cache.pointer(selector_slot)
    assert selection["target"] == functions["__Xmach_notify_no_senders"]["start"]
    assert instructions[0x184BC69FC] == ("blraaz", "x9")
    assert instructions[0x184BC6950] == ("ldr", "w8, [x9, #0x28]")
    assert instructions[0x184BC741C] == ("cmp", "w8, #0x24")
    assert instructions[0x184BC7484] == ("ldr", "w8, [x20, #0x7c]")
    assert instructions[0x184BBC934] == ("mov", "w2, #0x46")
    assert instructions[0x184BBE5A8] == ("str", "w8, [x21, #0x44]")
    assert instructions[0x184BBE5B0] == ("str", "w8, [x21, #0x4c]")
    assert instructions[0x184BBA59C] == ("stp", "w9, w22, [x21]")
    assert instructions[0x184BBA5A4] == ("stp", "wzr, w8, [x21, #0x10]")

    bsm = Dylib(cache, "/usr/lib/libbsm.0.dylib")
    pid_entry = bsm.exports["_audit_token_to_pid"]["address"]
    pid_body = bsm.function(pid_entry)
    assert [(row["mnemonic"], row["operands"]) for row in pid_body["instructions"]] == [
        ("ldr", "w0, [x0, #0x14]"), ("ret", "")
    ]
    return dict(
        native_receipt=NATIVE_RECEIPT, native_receipt_sha256=sha256(source).hexdigest(),
        native_interval_utc=[native["start_utc"], native["end_utc"]],
        macos_build=native["macos_build"], cache_uuid=cache.uuid, image_uuid=xpc.uuid,
        image_base=hex(xpc.base), event_sites=events, checked_calls=calls, functions=functions,
        stubs=stubs, formats={hex(address): value for address, value in FORMATS.items()},
        literal_references=references,
        notification_selector=dict(message_id=notification_id, table=hex(table),
                                   stride_bytes=40, bias_bytes=-0x9F8, slot=hex(selector_slot),
                                   word=selection["raw_word"], target=selection["target"]),
        audit_pid_accessor=dict(uuid=bsm.uuid, function="_audit_token_to_pid", **pid_body),
        sdk=verify_sdk(),
    )


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2, sort_keys=True))
