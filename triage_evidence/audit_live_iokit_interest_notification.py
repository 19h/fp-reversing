#!/usr/bin/env python3
"""Audit per-client IOKit interest registration and termination delivery."""

import argparse
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from audit_live_adid_peer_entitlement import checked_instructions
from audit_live_iokit_mach_transport import CACHE_UUID, IOKIT, Cache, Dylib, dyld_uuid
from audit_live_iokit_open_owner import BUILD
from audit_live_kext_selector26 import Collection, IDENTITIES

CONTROL = r"""
#include <assert.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

typedef kern_return_t (*description_fn)(mach_port_t, mach_port_name_t, natural_t *,
                                        mach_vm_address_t *, char *);
static void handler(void *context, io_service_t service, natural_t type, void *arg)
{
    printf("callback %d %u %x %" PRIxPTR "\n", context != NULL, service, type, (uintptr_t)arg);
}
int main(int argc, char **argv)
{
    (void)argv;
    description_fn describe = (description_fn)dlsym(RTLD_DEFAULT, "mach_port_kobject_description");
    assert(describe);
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOSurfaceRoot"));
    assert(service != IO_OBJECT_NULL);
    io_connect_t conn;
    assert(IOServiceOpen(service, mach_task_self(), 0, &conn) == KERN_SUCCESS);
    natural_t type;
    mach_vm_address_t address;
    char text[512];
    assert(describe(mach_task_self(), conn, &type, &address, text) == KERN_SUCCESS);
    uint64_t id;
    assert(sscanf(text, "IOSurfaceRootUserClient(0x%" SCNx64 ")", &id) == 1);
    io_iterator_t iter;
    assert(IORegistryEntryGetChildIterator(service, kIOServicePlane, &iter) == KERN_SUCCESS);
    io_registry_entry_t child;
    while ((child = IOIteratorNext(iter))) {
        uint64_t got;
        if (IORegistryEntryGetRegistryEntryID(child, &got) == KERN_SUCCESS && got == id) break;
        IOObjectRelease(child);
    }
    assert(child);
    IONotificationPortRef notifier = IONotificationPortCreate(kIOMainPortDefault);
    assert(notifier);
    mach_port_t wake = IONotificationPortGetMachPort(notifier);
    io_object_t registration = IO_OBJECT_NULL;
    kern_return_t ret = IOServiceAddInterestNotification(notifier, child, kIOGeneralInterest, handler,
        &type, &registration);
    printf("id=%#" PRIx64 " names c=%#x child=%#x reg=%#x wake=%#x add=%#x\n",
        id, conn, child, registration, wake, ret);
    assert(ret == KERN_SUCCESS);
    union {
        mach_msg_header_t header;
        unsigned char raw[2048];
    } buffer = {0};
    ret = mach_msg(&buffer.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(buffer), wake, 10, 0);
    printf("before=%#x\n", ret);
    assert(ret == MACH_RCV_TIMED_OUT);
    kern_return_t close_result = IOServiceClose(conn);
    assert(close_result == KERN_SUCCESS);
    puts("close=0");
    ret = mach_msg(&buffer.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(buffer), wake, 1000, 0);
    printf("after=%#x size=%u\n", ret, buffer.header.msgh_size);
    assert(ret == KERN_SUCCESS);
    {
        assert(buffer.header.msgh_size == 124);
        unsigned char sanitized[124];
        memcpy(sanitized, buffer.raw, sizeof(sanitized));
        memset(&sanitized[56], 0, 16);
        for (unsigned i = 0; i < sizeof(sanitized); ++i) printf("%02x", sanitized[i]);
        puts("");
        kern_return_t child_result = describe(mach_task_self(), child, &type, &address, text);
        printf("child description: %d\n", child_result);
        mach_port_t described;
        memcpy(&described, &buffer.raw[28], sizeof(described));
        kern_return_t desc_result = describe(mach_task_self(), described, &type, &address, text);
        printf("descriptor description: %d %u %s\n", desc_result, type, text);
        kern_return_t reg_result = describe(mach_task_self(), registration, &type, &address, text);
        printf("reg description: %d %u %s\n", reg_result, type, text);
        mach_port_urefs_t refs;
        assert(mach_port_get_refs(mach_task_self(), registration, MACH_PORT_RIGHT_SEND, &refs) == KERN_SUCCESS);
        printf("before-dispatch refs=%u\n", refs);
        if (argc > 1) {
            assert(IOObjectRelease(registration) == KERN_SUCCESS);
            assert(mach_port_get_refs(mach_task_self(), registration, MACH_PORT_RIGHT_SEND, &refs) == KERN_SUCCESS);
            printf("released-before-dispatch refs=%u\n", refs);
        }
        IODispatchCalloutFromMessage(NULL, &buffer.header, notifier);
        kern_return_t refs_result = mach_port_get_refs(mach_task_self(), registration, MACH_PORT_RIGHT_SEND, &refs);
        printf("after-dispatch result=%d refs=%u\n", refs_result,
            refs_result == KERN_SUCCESS ? refs : 0);
        if (argc > 1) registration = IO_OBJECT_NULL;
    }
    if (registration) IOObjectRelease(registration);
    IONotificationPortDestroy(notifier);
    IOObjectRelease(child);
    IOObjectRelease(iter);
    IOObjectRelease(service);
    return 0;
}
"""

REQUEST = 2869
REPLY = 2969
IOKIT_UUID = '82be1de5-91c4-3152-b63b-81db4c5e7992'

USER_CHECKS = (
    (0x184ebf90c, 'stp xzr, x3, [sp, #8]'),
    (0x184ebf914, 'stp x4, x9, [sp, #0x18]'),
    (0x184ebf918, 'ldr w2, [x0, #4]'),
    (0x184ebf928, 'mov w4, #4'),
    (0x184ebf92c, 'bl #0x184ebf958'),
    (0x184ebf9c4, 'stp w8, w2, [sp, #0x18]'),
    (0x184ebf9c8, 'mov w8, #0x140000'),
    (0x184ebfa54, 'stp w20, w0, [sp, #8]'),
    (0x184ebfa84, 'mov x4, #0xb3500000000'),
    (0x184ebfa90, 'bl #0x188088af0'),
    (0x184ebfadc, 'cmp w8, #0xb99'),
    (0x184ebfb34, 'cmp w9, #1'),
    (0x184ebfb3c, 'cmp w8, #0x28'),
    (0x184ee29d8, 'b #0x184ec021c'),
    (0x184ec0220, 'cmp w8, #0x35'),
    (0x184ec026c, 'ldr w20, [x21, #0x1c]'),
    (0x184ec0288, 'ldp w25, w19, [x21, #4]'),
    (0x184ec02ac, 'bl #0x188080ca0'),
    (0x184ec02b8, 'ccmp w8, #2, #0, eq'),
    (0x184ec02bc, 'b.lo #0x184ec036c'),
    (0x184ec02f4, 'cmp w9, #0xa0'),
    (0x184ec034c, 'ldr x3, [x3]'),
    (0x184ec0358, 'ldr w20, [x24, #0x20]'),
    (0x184ec0364, 'blraaz x9'),
    (0x184ec0374, 'bl #0x18806c480'),
    (0x184ec0398, 'bl #0x18806c480'),
)

KERNEL_CHECKS = (
    (0xfffffe000be80dfc, 'cmp w9, #1'),
    (0xfffffe000be80e28, 'cmp w10, #0x80'),
    (0xfffffe000be80e5c, 'cmp w8, #8'),
    (0xfffffe000be80ec4, 'bl #0xfffffe000be7e18c'),
    (0xfffffe000be80f18, 'bl #0xfffffe000c5ba704'),
    (0xfffffe000be80f60, 'bl #0xfffffe000be7e7b8'),
    (0xfffffe000c52188c, 'mov w1, #0x10'),
    (0xfffffe000c521890, 'movk w1, #0xe000, lsl #16'),
    (0xfffffe000c5218a0, 'blraa x8, x16'),
    (0xfffffe000c5b1518, 'bl #0xfffffe000c5b07cc'),
    (0xfffffe000c5b1528, 'bl #0xfffffe000c5b07cc'),
    (0xfffffe000c5b155c, 'add x16, x16, #0x628'),
    (0xfffffe000c5b1588, 'stp x0, x22, [sp, #0x40]'),
    (0xfffffe000c5b158c, 'mov w8, #0x4c'),
    (0xfffffe000c5b15a0, 'mov w0, #1'),
    (0xfffffe000c5b15b8, 'bl #0xfffffe000bd3d6bc'),
    (0xfffffe000c5b1648, 'ldr x8, [x21, #0x28]'),
    (0xfffffe000c5b164c, 'str x8, [x1, #8]'),
    (0xfffffe000c5b1658, 'mov w8, #0x1113'),
    (0xfffffe000c5b165c, 'movk w8, #0x8000, lsl #16'),
    (0xfffffe000c5b166c, 'mov w8, #0x35'),
    (0xfffffe000c5b1670, 'str w8, [x1, #0x1c]'),
    (0xfffffe000c5b168c, 'mov w8, #0x11'),
    (0xfffffe000c5b1690, 'strh w8, [x2, #0xa]'),
    (0xfffffe000c5b16a0, 'str w8, [x20, #4]'),
    (0xfffffe000c5b16b8, 'bl #0xfffffe000c697810'),
    (0xfffffe000c5b16cc, 'str w9, [x8]'),
    (0xfffffe000c5b16f8, 'stur x9, [x8, #4]'),
)


def audit_static(image):
    cache = Cache()
    iokit = Dylib(cache, IOKIT)
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    assert iokit.uuid == IOKIT_UUID
    assert iokit.exports['_IOServiceAddInterestNotification']['address'] == 0x184ebf8e8
    assert iokit.exports['_IODispatchCalloutFromMessage']['address'] == 0x184ee29d8
    assert struct.unpack('<II', cache.read(0x184f98b20, 8)) == (0, REQUEST)
    subsystem = image.pointer(0xfffffe000caff050)
    base = int(subsystem['target'], 16)
    start, end = struct.unpack('<II', image.read(base + 8, 8))
    assert (start, end) == (2800, 2892)
    stub = image.pointer(base + 40 + (REQUEST - start) * 32)
    assert (stub['target'], stub['auth'], stub['key'], stub['diversity']) == (
        '0xfffffe000be80da4', 1, 0, '0x3a83')
    return {'kernel_uuid': IDENTITIES[1][1], 'collection_sha256': image.digest,
            'cache_uuid': cache.uuid, 'iokit_uuid': iokit.uuid, 'subsystem': subsystem,
            'registration_request_id': REQUEST, 'registration_reply_id': REPLY,
            'registration_stub': stub,
            'kernel_instructions': checked_instructions(image.read, KERNEL_CHECKS),
            'iokit_instructions': checked_instructions(cache.read, USER_CHECKS)}


def parse_capture(raw, cancel):
    names = re.search(r'^id=(\S+) names c=(\S+) child=(\S+) reg=(\S+) wake=(\S+) add=0$', raw, re.M)
    assert names is not None
    registry_id, connection, child, registration, wake = (int(value, 16) for value in names.groups())
    capture = re.search(r'^([a-f0-9]{248})$', raw, re.M)
    assert capture is not None
    message = bytes.fromhex(capture[1])
    bits, size, remote, local, voucher, message_id, count, provider = struct.unpack_from('<8I', message)
    assert (bits, size, remote, local, voucher, message_id, count) == (
        0x80001111, 124, registration, wake, 0, 53, 1)
    assert len({connection, child, registration, wake, provider}) == 5
    assert message[38:40] == b'\x11\0'
    assert struct.unpack_from('<II8QIQ', message, 40) == (
        76, 160, 0, 0, 0, child, 0, 0, 0, 0, 0xe0000010, 1)
    lines = set(raw.splitlines())
    assert {'before=0x10004003', 'close=0', 'after=0 size=124', 'child description: 15',
            f'descriptor description: 0 30 IOSurfaceRootUserClient({registry_id:#x})',
            'reg description: 0 30 IOServiceMessageUserNotification', 'before-dispatch refs=2'} <= lines
    callbacks = [line for line in raw.splitlines() if line.startswith('callback ')]
    if cancel:
        assert not callbacks
        assert {'released-before-dispatch refs=1', 'after-dispatch result=15 refs=0'} <= lines
    else:
        assert callbacks == [f'callback 1 {provider} e0000010 1']
        assert 'after-dispatch result=0 refs=1' in lines
    return {'released_before_dispatch': cancel, 'connection_name': hex(connection),
            'original_child_name': hex(child), 'notification_name': hex(registration),
            'wake_name': hex(wake), 'provider_descriptor_name': hex(provider),
            'client_registry_id': hex(registry_id), 'received_message_sanitized_hex': message.hex()}


def run_control():
    with tempfile.TemporaryDirectory() as work:
        verifier = Path(work) / 'verify-iokit-interest'
        subprocess.run(['xcrun', 'clang', '-x', 'c', '-Wall', '-Wextra', '-Werror',
                        '-framework', 'IOKit', '-framework', 'CoreFoundation',
                        '-o', str(verifier), '-'], input=CONTROL, text=True, check=True)
        kept = parse_capture(subprocess.check_output([str(verifier)], text=True), cancel=False)
        released = parse_capture(subprocess.check_output([str(verifier), 'cancel'], text=True), cancel=True)
    return {'control_source_sha256': hashlib.sha256(CONTROL.encode()).hexdigest(),
            'receive_before_close_bound_ms': 10, 'receive_after_close_bound_ms': 1000,
            'callback_and_context_bytes_redacted': [56, 72],
            'retained_registration_callbacks': 1, 'released_registration_callbacks': 0,
            'received_id': 53, 'received_size_bytes': 124, 'provider_ids_match_preclose': True,
            'examples': [kept, released]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    image = Collection(args.collection, IDENTITIES[1])
    print(json.dumps({'build': BUILD, 'installed': audit_static(image), 'control': run_control()},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
