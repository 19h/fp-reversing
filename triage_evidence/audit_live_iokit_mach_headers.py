#!/usr/bin/env python3
"""Capture Mach headers around the installed IOKit calls in a native verifier."""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile

HEADER = struct.Struct('<6I')
LIBRARY_ANCHORS = {
    'fp_iokit_anchor': (0x184ebdb74, 'IOKit', '82be1de5-91c4-3152-b63b-81db4c5e7992'),
    'fp_kernel_anchor': (0x180549e9c, 'libsystem_kernel.dylib', '780a6c1f-be02-34cc-84dd-00e05f61c89b'),
}
SITES = (
    ('get_main', 205, 0x18056b448, 0x18055b918, 'fp_kernel_anchor'),
    ('server_version', 2877, 0x184ebc3cc, 0x188088af0, 'fp_iokit_anchor'),
    ('class_matching', 2881, 0x184ebd3dc, 0x188088af0, 'fp_iokit_anchor'),
    ('iterator_next', 2802, 0x184ebd59c, 0x188088af0, 'fp_iokit_anchor'),
    ('open', 2862, 0x184ebdc6c, 0x188088af0, 'fp_iokit_anchor'),
    ('close', 2816, 0x184ec1a44, 0x188088af0, 'fp_iokit_anchor'),
)

VERIFIER = r"""
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <stddef.h>
#include <stdint.h>

_Static_assert(sizeof(mach_msg_header_t) == 24, "Mach message header");
_Static_assert(offsetof(mach_msg_header_t, msgh_id) == 20, "Message ID offset");
_Static_assert(sizeof(mach_msg_port_descriptor_t) == 12, "Port descriptor");

uintptr_t fp_iokit_anchor, fp_kernel_anchor;
uint32_t fp_task, fp_main, fp_iterator, fp_service, fp_connection;
uint32_t fp_open_result, fp_close_attempted, fp_close_result, fp_release_results;
uint32_t fp_reply_before, fp_reply_after;

__attribute__((noinline)) void fp_begin(void) { __asm__ volatile(""); }
__attribute__((noinline)) void fp_finish(void) { __asm__ volatile(""); }

int main(void)
{
    fp_iokit_anchor = (uintptr_t)dlsym(RTLD_DEFAULT, "IOServiceOpen");
    fp_kernel_anchor = (uintptr_t)dlsym(RTLD_DEFAULT, "mach_port_construct");
    if (fp_iokit_anchor == 0 || fp_kernel_anchor == 0) {
        return 1;
    }

    fp_task = mach_task_self();
    fp_reply_before = mig_get_reply_port();
    fp_begin();
    kern_return_t result = IOMainPort(MACH_PORT_NULL, &fp_main);
    if (result != KERN_SUCCESS || !MACH_PORT_VALID(fp_main)) {
        return 2;
    }
    CFMutableDictionaryRef match = IOServiceMatching("com_apple_driver_FairPlayIOKit");
    if (match == NULL) {
        mach_port_deallocate(fp_task, fp_main);
        return 3;
    }
    result = IOServiceGetMatchingServices(fp_main, match, &fp_iterator);
    if (result != KERN_SUCCESS || !MACH_PORT_VALID(fp_iterator)) {
        mach_port_deallocate(fp_task, fp_main);
        return 4;
    }
    fp_service = IOIteratorNext(fp_iterator);
    if (!MACH_PORT_VALID(fp_service)) {
        IOObjectRelease(fp_iterator);
        mach_port_deallocate(fp_task, fp_main);
        return 5;
    }
    fp_open_result = (uint32_t)IOServiceOpen(fp_service, fp_task, 0, &fp_connection);
    if (fp_open_result == KERN_SUCCESS && MACH_PORT_VALID(fp_connection)) {
        fp_close_attempted = 1;
        fp_close_result = (uint32_t)IOServiceClose(fp_connection);
    }
    fp_release_results = (uint32_t)IOObjectRelease(fp_service);
    fp_release_results |= (uint32_t)IOObjectRelease(fp_iterator);
    fp_release_results |= (uint32_t)mach_port_deallocate(fp_task, fp_main);
    fp_reply_after = mig_get_reply_port();
    fp_finish();
    mig_dealloc_reply_port(fp_reply_after);
    return fp_release_results != KERN_SUCCESS;
}
"""


def words_from_header(raw):
    bits, size, remote, local, voucher, request_id = HEADER.unpack_from(raw)
    return dict(bits=bits, size_bytes=size, remote=remote, local=local, voucher=voucher, id=request_id)


def capture(debugger, lldb):
    debugger.SetAsync(False)
    target = debugger.GetSelectedTarget()
    start = target.BreakpointCreateByName('fp_begin')
    finish = target.BreakpointCreateByName('fp_finish')
    assert start.GetNumLocations() == finish.GetNumLocations() == 1
    process = target.LaunchSimple(None, None, None)
    assert process.IsValid() and process.GetState() == lldb.eStateStopped, process.GetState()

    def frame_at_stop():
        thread = process.GetSelectedThread()
        assert process.GetState() == lldb.eStateStopped
        assert thread.IsValid() and thread.GetStopReason() == lldb.eStopReasonBreakpoint
        return thread.GetFrameAtIndex(0)

    def scalar(name):
        symbol = target.FindFirstGlobalVariable(name)
        assert symbol.IsValid() and symbol.GetError().Success(), name
        return symbol.GetValueAsUnsigned()

    def read(address, size):
        error = lldb.SBError()
        value = process.ReadMemory(address, size, error)
        assert error.Success() and len(value) == size, f'memory read of {size} B failed'
        return value

    def resume():
        error = process.Continue()
        assert error.Success(), 'verifier did not resume'

    def message(address, capacity):
        header = words_from_header(read(address, HEADER.size))
        size = header['size_bytes']
        assert HEADER.size <= size <= capacity
        return header, read(address, size)

    frame = frame_at_stop()
    assert frame.GetFunctionName() == 'fp_begin'
    issuer = frame.GetThread().GetThreadID()
    slides, images = {}, {}
    for name, (preferred, library, uuid) in LIBRARY_ANCHORS.items():
        load = scalar(name)
        module = target.ResolveLoadAddress(load).GetModule()
        assert module.IsValid() and module.GetFileSpec().GetFilename() == library
        assert module.GetUUIDString().lower() == uuid
        slides[name] = load - preferred
        images[library] = uuid
    assert len(set(slides.values())) == 1

    locations = {}
    for tag, expected_id, preferred_pc, callee, anchor in SITES:
        pc = preferred_pc + slides[anchor]
        branch = 0x94000000 | (((callee - preferred_pc) >> 2) & 0x03ffffff)
        assert read(pc, 4) == struct.pack('<I', branch), tag
        for offset in (0, 4):
            breakpoint = target.BreakpointCreateByAddress(pc + offset)
            assert breakpoint.GetNumLocations() == 1
            locations[pc + offset] = tag, expected_id, preferred_pc, offset

    exchanges = []
    outstanding = None
    for _ in range(2 * len(SITES) + 1):
        resume()
        frame = frame_at_stop()
        assert frame.GetThread().GetThreadID() == issuer
        if frame.GetFunctionName() == 'fp_finish':
            break
        tag, expected_id, preferred_pc, offset = locations[frame.GetPC()]
        if offset == 0:
            assert outstanding is None
            x = [frame.FindRegister(f'x{i}').GetValueAsUnsigned() for i in range(8)]
            address, options, sizes_bits, names, ids, receive, max_receive, timeout = x
            header, raw = message(address, sizes_bits >> 32)
            descriptors = struct.unpack_from('<I', raw, HEADER.size)[0] if header['bits'] & 0x80000000 else 0
            assert options == 0x200000003 and timeout == 0
            assert sizes_bits == header['size_bytes'] << 32 | header['bits']
            assert names == header['local'] << 32 | header['remote']
            assert ids == expected_id << 32 | header['voucher'] and header['id'] == expected_id
            assert receive == header['local'] << 32 | descriptors
            outstanding = address, tag, max_receive, header
            exchanges.append(dict(operation=tag, call_site=hex(preferred_pc), request=header,
                                  request_bytes=raw.hex(), request_descriptors=descriptors,
                                  options=hex(options), receive_capacity_bytes=max_receive))
        else:
            assert outstanding and tag == outstanding[1]
            address, _, max_receive, request = outstanding
            transport = frame.FindRegister('x0').GetValueAsUnsigned() & 0xffffffff
            assert transport == 0, (tag, hex(transport))
            header, raw = message(address, max_receive)
            assert header['id'] == request['id'] + 100
            assert header['remote'] == header['voucher'] == 0
            assert header['local'] == request['local']
            exchanges[-1].update(reply=header, reply_bytes=raw.hex(), transport_result=transport)
            outstanding = None
    else:
        raise AssertionError('the verifier did not reach its final marker')

    assert outstanding is None
    outputs = {name: scalar(f'fp_{name}') for name in (
        'task', 'main', 'iterator', 'service', 'connection', 'open_result', 'close_attempted',
        'close_result', 'release_results', 'reply_before', 'reply_after',
    )}
    resume()
    assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0
    return {'loaded_images': images, 'exchanges': exchanges, 'verifier_outputs': outputs}


def lldb_command(debugger, command, result, _internal):
    import lldb

    try:
        assert not command.strip()
        observation = capture(debugger, lldb)
        result.AppendMessage('FP_CAPTURE ' + json.dumps(observation, sort_keys=True))
    except (AssertionError, KeyError) as error:
        result.SetError(f'capture invariant failed: {error}')


def __lldb_init_module(debugger, _internal):
    debugger.HandleCommand(f'command script add -f {__name__}.lldb_command fp_capture')


def verify(observation):
    exchanges = observation['exchanges']
    outputs = observation['verifier_outputs']
    assert outputs['release_results'] == 0
    assert len(exchanges) == (6 if outputs['connection'] and outputs['open_result'] == 0 else 5)
    assert outputs['close_attempted'] == len(exchanges) - 5
    assert [row['request']['id'] for row in exchanges[:5]] == [205, 2877, 2881, 2802, 2862]
    assert [row['request']['size_bytes'] for row in exchanges[:5]] == [24, 24, 100, 24, 80]
    assert all(row['request']['local'] == outputs['reply_before'] == outputs['reply_after'] for row in exchanges)
    assert all(row['request']['bits'] & 0xffff == 0x1513 for row in exchanges)
    assert all(row['reply']['bits'] & 0xffff == 0x1200 for row in exchanges)

    main, version, match, iterator, opened = exchanges[:5]
    for row, name in ((main, 'main'), (match, 'iterator'), (iterator, 'service')):
        assert row['reply']['size_bytes'] == 40 and row['reply']['bits'] >> 31
        raw = bytes.fromhex(row['reply_bytes'])
        assert struct.unpack_from('<II', raw, 24) == (1, outputs[name])
        assert struct.unpack_from('<H', raw, 38) == (0x11,)
    assert version['reply']['size_bytes'] == 44
    assert struct.unpack_from('<IQ', bytes.fromhex(version['reply_bytes']), 32) == (0, 0x0134647a)
    assert version['request']['remote'] == match['request']['remote'] == outputs['main']
    assert iterator['request']['remote'] == outputs['iterator']
    assert opened['request']['remote'] == outputs['service']
    query = bytes.fromhex(match['request_bytes'])
    assert b'IOProviderClass\0' in query and b'com_apple_driver_FairPlayIOKit\0' in query
    raw = bytes.fromhex(opened['request_bytes'])
    assert struct.unpack_from('<II', raw, 24) == (2, outputs['task'])
    assert struct.unpack_from('<H', raw, 38) == (0x13,)
    assert struct.unpack_from('<Q4BI', raw, 40) == (0, 0, 0, 0, 1, 0)
    assert struct.unpack_from('<I', raw, 64) == (0,)
    assert struct.unpack_from('<I', raw, 76) == (0,)

    reply = bytes.fromhex(opened['reply_bytes'])
    if opened['reply']['bits'] >> 31:
        assert len(reply) == 52 and struct.unpack_from('<II', reply, 24) == (1, outputs['connection'])
        assert struct.unpack_from('<H', reply, 38) == (0x11,)
        assert struct.unpack_from('<I', reply, 48) == (outputs['open_result'],)
        observation['open_result_channel'] = 'application'
    else:
        assert len(reply) == 36 and outputs['connection'] == 0 and outputs['open_result'] != 0
        assert struct.unpack_from('<I', reply, 32) == (outputs['open_result'],)
        observation['open_result_channel'] = 'routine'
    if len(exchanges) == 6:
        close = exchanges[-1]
        assert close['request']['id'] == 2816 and close['request']['remote'] == outputs['connection']
        assert close['reply']['size_bytes'] == 36
        assert struct.unpack_from('<I', bytes.fromhex(close['reply_bytes']), 32) == (outputs['close_result'],)


def compare_archive(observation, trace):
    from audit_archived_iokit_open_retirement import trace_record
    from audit_live_iokit_discovery import archived_discovery

    discovery = archived_discovery(trace)
    open_trace = trace_record(trace)
    archived_pairs = [(row['send_hex'], row['reply_hex']) for row in discovery['transactions']]
    archived_pairs.append(tuple(row['message_hex'] for row in open_trace['guest_messages'][-2:]))
    assert discovery['trace_sha256'] == open_trace['sha256']

    def canonical(hex_bytes, name_offsets):
        message = bytearray.fromhex(hex_bytes)
        for offset in name_offsets:
            struct.pack_into('<I', message, offset, 0)
        return bytes(message)

    comparison = []
    for observed, (request_hex, reply_hex) in zip(observation['exchanges'][:5], archived_pairs, strict=True):
        request_id = observed['request']['id']
        request_names = [8, 12, 28] if request_id == 2862 else [8, 12]
        reply_names = [12, 28] if request_id in (205, 2881, 2802) else [12]
        paired = {'request_id': request_id}
        for direction, historical, offsets in (('request', request_hex, request_names),
                                               ('reply', reply_hex, reply_names)):
            archived = canonical(historical, offsets)
            live = canonical(observed[direction + '_bytes'], offsets)
            paired[direction] = {
                'name_offsets_bytes': offsets, 'other_bytes_equal': live == archived,
                'canonical_archive_sha256': hashlib.sha256(archived).hexdigest(),
                'canonical_live_sha256': hashlib.sha256(live).hexdigest(),
            }
        comparison.append(paired)
    return {'trace_sha256': discovery['trace_sha256'], 'pairs': comparison}


def main():
    from audit_live_iokit_mach_transport import CACHE_UUID, dyld_uuid
    from audit_live_iokit_main_port import BUILD
    from audit_live_kext_selector26 import IDENTITIES

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    assert dyld_uuid() == CACHE_UUID
    with tempfile.TemporaryDirectory(prefix='fp-native-headers-') as folder:
        root = Path(folder)
        source, probe = root / 'probe.c', root / 'probe'
        source.write_text(VERIFIER)
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-g', '-O0', '-Wall', '-Wextra', '-Werror',
                        '-framework', 'IOKit', str(source), '-o', str(probe)], check=True)
        script = shlex.quote(str(Path(__file__).resolve()))
        transcript = subprocess.run(['xcrun', 'lldb', '-b', '-x', '-o', f'command script import {script}',
                                     '-o', 'fp_capture', str(probe)], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        output = transcript.stdout.splitlines()
        lines = [line.removeprefix('FP_CAPTURE ') for line in output if line.startswith('FP_CAPTURE ')]
        if transcript.returncode or len(lines) != 1:
            diagnostics = [line for line in output if 'Error' in line or line.startswith('error:')]
            raise RuntimeError(f'LLDB capture failed: {diagnostics}')
    observation = json.loads(lines[0])
    verify(observation)
    observation['archive_comparison'] = compare_archive(observation, args.trace)
    observation.update(build=BUILD, cache_uuid=CACHE_UUID, kernel_uuid=IDENTITIES[1][1],
                       verifier_source_sha256=hashlib.sha256(VERIFIER.encode()).hexdigest())
    print(json.dumps(observation, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
