#!/usr/bin/env python3
"""Verify the ordinary ADID synchronous transport sites without sending IPC."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from audit_adid_legacy_mach_receive import Evidence, cached_image, symbol, veneer
from audit_archived_iokit_open_retirement import GUEST_MESSAGE, TRACE_SHA, decode_guest
from audit_live_fairplay_adid_ipc import fairplay, provider
from audit_live_iokit_mach_transport import CACHE_UUID, dyld_uuid
from bootpolicy_cache_reader import Cache


def transport():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    xpc = cached_image(cache, 'libxpc.dylib', '94e40b03-44c5-3636-aa1a-c64a5d6b6bbb')
    dispatch = cached_image(cache, 'libdispatch.dylib', '435a06f9-1bc8-3282-8663-b6418c44a05e')
    kernel = cached_image(cache, 'libsystem_kernel.dylib', '780a6c1f-be02-34cc-84dd-00e05f61c89b')
    evidence = Evidence(cache.read)
    for image, name, address in (
        (xpc, '_xpc_connection_send_message_with_reply_sync', 0x184bbd44c),
        (xpc, '__xpc_connection_pack_message', 0x184bbd790),
        (xpc, '__xpc_dictionary_extract_reply_port', 0x184bb6cdc),
        (xpc, '__xpc_connection_mach_event', 0x184bbdfa0),
        (xpc, '__xpc_connection_unpack_message', 0x184bbddfc),
        (xpc, '__xpc_connection_check_peer_requirement', 0x184bda15c),
        (xpc, '_xpc_receive_mach_msg', 0x184bb80ec),
        (xpc, '__xpc_graph_unpack_impl', 0x184bb85f4),
        (xpc, '__xpc_connection_call_event_handler', 0x184bbffb8),
        (xpc, '_xpc_dictionary_create_reply', 0x184bc6820),
        (xpc, '_xpc_dictionary_send_reply', 0x184bdbc48),
        (xpc, '_xpc_connection_send_message', 0x184bbf01c),
        (xpc, '__xpc_connection_enqueue', 0x184bbf150),
        (dispatch, '__dispatch_mach_send_and_wait_for_reply', 0x1855b0b30),
        (dispatch, '__dispatch_mach_msg_send', 0x1855b4504),
        (kernel, '_mach_msg_overwrite', 0x180551848),
        (kernel, '_mach_msg2_trap', 0x180548c18),
    ):
        symbol(image, name, address)
    bindings = {}
    for call, stub, image, name, address in (
        (0x184bba668, 0x1880876a0, dispatch, '_dispatch_mach_connect', 0x1855afa54),
        (0x184bbd590, 0x188087780, dispatch, '_dispatch_mach_send_with_result_and_wait_for_reply', 0x1855b10b8),
        (0x184bbf218, 0x188087760, dispatch, '_dispatch_mach_send_with_result', 0x1855b0a5c),
        (0x1855b0bec, 0x188087d50, kernel, '_thread_get_special_reply_port', 0x180548c3c),
        (0x1855b0d50, 0x18806d230, kernel, '_mach_msg', 0x180548f94),
        (0x1855b487c, 0x18808c6e0, kernel, '_mach_msg2_internal', 0x18055b918),
    ):
        evidence.check([(call, 'bl', f'#{stub:#x}')])
        bindings[hex(call)] = veneer(cache, evidence, stub, image, name, address)

    evidence.check([
        (0x184bba65c, 'ldr', 'w1, [x20, #0x44]'),
        (0x184bba660, 'ldr', 'w2, [x20, #0x4c]'),
        (0x184bbe5a8, 'str', 'w8, [x21, #0x44]'),
        (0x184bbe5b0, 'str', 'w8, [x21, #0x4c]'),
        (0x184bce304, 'str', 'wzr, [x19, #0xd0]'),
        (0x184bb7120, 'ldr', 'q0, [x9, #0x350]'),
        (0x184bb7124, 'stur', 'q0, [x21, #8]'),
        (0x184bbd4d8, 'mov', 'w2, #0'),
        (0x184bbd4dc, 'bl', '#0x184bbd790'),
        (0x184bbd4f0, 'mov', 'w8, #0x1500'),
        (0x184bbd4fc, 'str', 'w8, [x0]'),
        (0x184bbd500, 'ldr', 'w8, [x22, #0xd0]'),
        (0x184bbd504, 'cbnz', 'w8, #0x184bbd510'),
        (0x184bbd508, 'mov', 'w8, #0x40000000'),
        (0x184bbd50c, 'str', 'w8, [x0, #0x14]'),
        (0x184bbd518, 'ldrb', 'w8, [x8]'),
        (0x184bbd51c, 'cmp', 'w8, #1'),
        (0x184bbd520, 'b.ne', '#0x184bbd52c'),
        (0x184bbd524, 'mov', 'w8, #0x10000000'),
        (0x184bbd528, 'str', 'w8, [x0, #0x14]'),
        (0x184bbd578, 'ldr', 'x0, [x22, #0xa8]'),
        (0x184bbd604, 'mov', 'w9, #0x20000000'),
        (0x184bbd60c, 'b.eq', '#0x184bbd6c4'),
        (0x184bbd6cc, 'bl', '#0x184bbddfc'),
        (0x184bbd7b8, 'bl', '#0x184bb6cdc'),
        (0x184bbd810, 'cbz', 'w20, #0x184bbd824'),
        (0x184bbd814, 'mov', 'w8, #0x20000000'),
        (0x184bbd818, 'str', 'w8, [x0, #0x14]'),
        (0x184bbd81c, 'mov', 'w8, #0x12'),
        (0x184bbd824, 'mov', 'w8, #0x13'),
        (0x184bbd838, 'stp', 'w20, w19, [x0, #8]'),
        (0x184bbe308, 'mov', 'w9, #0x10000000'),
        (0x184bbe310, 'b.eq', '#0x184bbe3d0'),
        (0x184bbe358, 'mov', 'w9, #0x40000000'),
        (0x184bbe360, 'b.eq', '#0x184bbe3d0'),
        (0x184bbe3e8, 'tbnz', 'w8, #3, #0x184bbe494'),
        (0x184bbe3f0, 'cbnz', 'w8, #0x184bbe4a4'),
        (0x184bbe3fc, 'bl', '#0x184bbddfc'),
        (0x184bbe400, 'cbz', 'x0, #0x184bbe700'),
        (0x184bbe410, 'bl', '#0x184bbffb8'),
        (0x184bbde40, 'bl', '#0x184bda15c'),
        (0x184bbde44, 'tbz', 'w0, #0, #0x184bbde74'),
        (0x184bbdf28, 'bl', '#0x184bb80ec'),
        (0x184bb816c, 'ldp', 'w9, w8, [x19, #4]'),
        (0x184bb8170, 'str', 'wzr, [x19, #8]'),
        (0x184bb8198, 'stp', 'w8, wzr, [sp, #0x10]'),
        (0x184bb88ec, 'stur', 'q0, [x20, #0x58]'),
        (0x184bb88f0, 'stp', 'xzr, xzr, [x19]'),
        (0x184bb8904, 'stur', 'q0, [x20, #0x78]'),
        (0x184bc6868, 'ldr', 'x8, [x21, #0x58]!'),
        (0x184bc6894, 'orr', 'w8, w8, #2'),
        (0x184bc68a0, 'str', 'q0, [x0, #0x60]'),
        (0x184bc68ac, 'stp', 'xzr, xzr, [x21]'),
        (0x184bc68b0, 'str', 'xzr, [x21, #0x10]'),
        (0x184bc68c0, 'str', 'x0, [x20, #0x58]'),
        (0x184bdbcac, 'add', 'x9, x19, #0x60'),
        (0x184bdbcbc, 'tbz', 'w9, #0, #0x184bdbd1c'),
        (0x184bdbd58, 'b', '#0x184bbf01c'),
        (0x184bb6cfc, 'mov', 'w8, #0x60'),
        (0x184bb6d0c, 'ldr', 'w0, [x9]'),
        (0x184bb6d10, 'str', 'wzr, [x9]'),
        (0x184bbf09c, 'mov', 'w2, #0'),
        (0x184bbf0a0, 'bl', '#0x184bbd790'),
        (0x184bbf0c8, 'bl', '#0x184bbf150'),
        (0x184bbf1b0, 'b.eq', '#0x184bbf1f4'),
    ])

    evidence.check([
        (0x1855afa84, 'str', 'w1, [x8, #0x18]'),
        (0x1855afa88, 'str', 'w2, [x21, #0x5c]'),
        (0x1855b10f0, 'bl', '#0x1855b0b30'),
        (0x1855b0bc0, 'ldr', 'w24, [x9, #0xc]'),
        (0x1855b0be4, 'ldr', 'w24, [x28, #0x40]'),
        (0x1855b0be8, 'cbnz', 'w24, #0x1855b0c0c'),
        (0x1855b0bf4, 'str', 'x8, [x28, #0x40]'),
        (0x1855b0c14, 'str', 'w24, [x19, #0xc]'),
        (0x1855b0c54, 'bl', '#0x1855b0844'),
        (0x1855b0c74, 'str', 'xzr, [x28, #0x40]'),
        (0x1855b0d00, 'mov', 'w9, #0xe'),
        (0x1855b0d04, 'movk', 'w9, #0x700, lsl #16'),
        (0x1855b0d08, 'orr', 'w10, w9, #0x4000'),
        (0x1855b0d3c, 'mov', 'w2, #0'),
        (0x1855b0d44, 'mov', 'x4, x24'),
        (0x1855b0d80, 'bl', '#0x18806ca40'),
        (0x1855b0da0, 'b', '#0x1855b0d34'),
        (0x1855b0ed0, 'cmp', 'w25, w0'),
        (0x1855b0f8c, 'str', 'wzr, [x24, #0xc]'),
        (0x1855b0fbc, 'bl', '#0x1855b32e8'),
        (0x1855b1044, 'str', 'x25, [x28, #0x40]'),
        (0x1855b0a8c, 'bl', '#0x1855b0844'),
        (0x1855b0978, 'bl', '#0x1855b4504'),
        (0x1855b09c8, 'bl', '#0x1855b5200'),
        (0x1855b409c, 'bl', '#0x1855b4504'),
        (0x1855b4580, 'cmp', 'w23, #0x12'),
        (0x1855b4584, 'b.ne', '#0x1855b45b0'),
        (0x1855b45a8, 'orr', 'w26, w8, #1'),
        (0x1855b45ac, 'b', '#0x1855b47a8'),
        (0x1855b45ec, 'ldr', 'w8, [x27, #0x5c]'),
        (0x1855b45f0, 'str', 'w8, [x22, #8]'),
        (0x1855b47e0, 'str', 'xzr, [x8, #0x40]'),
        (0x1855b484c, 'ldr', 'x3, [x22, #8]'),
        (0x180548fa8, 'bl', '#0x180551848'),
        (0x180551a24, 'bl', '#0x18055b918'),
        (0x18055b960, 'bl', '#0x180548c18'),
        (0x180548c18, 'mov', 'x16, #-0x2f'),
        (0x180548c1c, 'svc', '#0x80'),
        (0x180548c3c, 'mov', 'x16, #-0x32'),
        (0x180548c40, 'svc', '#0x80'),
    ])
    assert evidence.record(0x184bf9350, 16) == bytes.fromhex('00000000000000000000000000000010')
    return {'cache_uuid': CACHE_UUID, 'image_uuids': [xpc.uuid, dispatch.uuid, kernel.uuid],
            'bindings': bindings, 'instruction_words': evidence.windows}


def archive(path):
    original = path.read_bytes()
    assert sha256(original).hexdigest() == TRACE_SHA
    lines = original.decode().splitlines()
    assert len(lines) == 1748
    matched = [(i, m[2], int(m[8])) for i, line in enumerate(lines, 1)
               if (m := GUEST_MESSAGE.fullmatch(line))]
    assert not any(direction == 'send' and msgid in (0x40000000, 0x10000000)
                   for _, direction, msgid in matched)
    assert [i for i, direction, msgid in matched if direction == 'received' and msgid == 0x20000000] == [
        1516, 1557, 1591, 1625, 1659]
    rows = []
    for send_line, received_line, size, name, receive_name in (
        (1500, 1516, 172, 'com.apple.unfreed', '0xe03'),
        (1541, 1557, 172, 'com.apple.fairplayd', '0x1303'),
        (1575, 1591, 168, 'com.apple.fpsd', '0x1403'),
        (1609, 1625, 176, 'com.apple.arcade.fpsd', '0x1503'),
        (1643, 1659, 172, 'com.apple.fpsd.sim', '0x1603'),
    ):
        send = (0x80131513, size, 0x707, 0xb03, 0xd03, 0x400000ce)
        reply = (0x80001200, 72, 0, 0xb03, 0, 0x20000000)
        request_record, data = decode_guest(lines, send_line, 'send', send)
        reply_record, _ = decode_guest(lines, received_line, 'received', reply)
        assert name.encode() + b'\0' in data
        assert request_record['descriptors'] == [
            {'kind': 'port', 'offset': 28, 'name': '0x707', 'disposition': 19}]
        assert reply_record['descriptors'] == [
            {'kind': 'port', 'offset': 28, 'name': receive_name, 'disposition': 16}]
        assert lines[received_line - 4].endswith('to host 0x80b reply 0xc03: 0x0')
        assert lines[received_line - 2].endswith('on host 0xc03')
        rows.append({'send_line': send_line, 'send_header': send, 'receive_line': received_line,
                     'receive_header': reply, 'service': name, 'returned_receive_name': receive_name,
                     'host_destination': '0x80b', 'host_reply': '0xc03'})
    return {'sha256': TRACE_SHA, 'lines': len(lines), 'bootstrap_controls': rows,
            'ordinary_request_sends': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fairplayd', type=Path)
    parser.add_argument('adid', type=Path)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    result = {'transport': transport(), 'client': fairplay(args.fairplayd),
              'peer': provider(args.adid), 'archive': archive(args.trace)}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
