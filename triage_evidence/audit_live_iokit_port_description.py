#!/usr/bin/env python3
"""Audit IOKit port descriptions and join two local control connections to the registry."""

import argparse
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from audit_live_adid_peer_entitlement import checked_instructions
from audit_live_iokit_mach_transport import CACHE_UUID, LIBKERNEL, Cache, Dylib, dyld_uuid
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
#include <unistd.h>

typedef kern_return_t (*description_fn)(mach_port_t, mach_port_name_t, natural_t *,
                                        mach_vm_address_t *, char *);

static uint64_t describe(description_fn describe_port, mach_port_name_t name,
                         natural_t expected_type, const char *expected_class)
{
    natural_t type = 0;
    mach_vm_address_t address = UINT64_MAX;
    char text[512] = {0};
    assert(describe_port(mach_task_self(), name, &type, &address, text) == KERN_SUCCESS);
    assert(address == 0 && type == expected_type);
    if (!expected_class) {
        assert(text[0] == '\0');
        return 0;
    }
    size_t length = strlen(expected_class);
    assert(strncmp(text, expected_class, length) == 0);
    uint64_t id = 0;
    int end = 0;
    assert(sscanf(text + length, "(0x%" SCNx64 ")%n", &id, &end) == 1);
    assert(end > 0 && text[length + end] == '\0' && id != 0);
    return id;
}

int main(void)
{
    description_fn describe_port = (description_fn)dlsym(RTLD_DEFAULT, "mach_port_kobject_description");
    assert(describe_port);
    mach_port_t receive = MACH_PORT_NULL;
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive) == KERN_SUCCESS);
    describe(describe_port, receive, UINT32_MAX, NULL);
    assert(mach_port_mod_refs(mach_task_self(), receive, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOSurfaceRoot"));
    assert(service != IO_OBJECT_NULL);
    uint64_t service_id = 0;
    assert(IORegistryEntryGetRegistryEntryID(service, &service_id) == KERN_SUCCESS);
    assert(describe(describe_port, service, 0x1e, "IOSurfaceRoot") == service_id);

    const char *client_class = "IOSurfaceRootUserClient";
    io_connect_t connections[2] = {IO_OBJECT_NULL, IO_OBJECT_NULL};
    uint64_t client_ids[2] = {0, 0};
    unsigned matched[2] = {0, 0};
    for (size_t index = 0; index < 2; index++) {
        assert(IOServiceOpen(service, mach_task_self(), 0, &connections[index]) == KERN_SUCCESS);
        assert(connections[index] != IO_OBJECT_NULL);
        client_ids[index] = describe(describe_port, connections[index], 0x1d, client_class);
        uint64_t unused_id = 0;
        assert(IORegistryEntryGetRegistryEntryID(connections[index], &unused_id) == kIOReturnBadArgument);
        assert(unused_id == 0);
    }
    assert(client_ids[0] != client_ids[1] && connections[0] != connections[1]);

    io_iterator_t children = IO_OBJECT_NULL;
    assert(IORegistryEntryGetChildIterator(service, kIOServicePlane, &children) == KERN_SUCCESS);
    io_registry_entry_t child;
    while ((child = IOIteratorNext(children)) != IO_OBJECT_NULL) {
        uint64_t entry_id = 0;
        if (IORegistryEntryGetRegistryEntryID(child, &entry_id) == KERN_SUCCESS) {
            for (size_t index = 0; index < 2; index++) {
                if (entry_id != client_ids[index]) continue;
                assert(describe(describe_port, child, 0x1e, client_class) == entry_id);
                io_registry_entry_t parent = IO_OBJECT_NULL;
                uint64_t parent_id = 0;
                assert(IORegistryEntryGetParentEntry(child, kIOServicePlane, &parent) == KERN_SUCCESS);
                assert(IORegistryEntryGetRegistryEntryID(parent, &parent_id) == KERN_SUCCESS);
                assert(parent_id == service_id);
                assert(IOObjectRelease(parent) == KERN_SUCCESS);

                CFTypeRef creator = IORegistryEntryCreateCFProperty(child, CFSTR("IOUserClientCreator"),
                    kCFAllocatorDefault, 0);
                assert(creator && CFGetTypeID(creator) == CFStringGetTypeID());
                char label[128], prefix[32];
                assert(CFStringGetCString((CFStringRef)creator, label, sizeof(label), kCFStringEncodingUTF8));
                int length = snprintf(prefix, sizeof(prefix), "pid %d, ", getpid());
                assert(length > 0 && (size_t)length < sizeof(prefix));
                assert(strncmp(label, prefix, (size_t)length) == 0);
                CFRelease(creator);
                matched[index]++;
            }
        }
        assert(IOObjectRelease(child) == KERN_SUCCESS);
    }
    assert(IOIteratorIsValid(children));
    assert(IOObjectRelease(children) == KERN_SUCCESS);
    for (size_t index = 0; index < 2; index++) {
        assert(matched[index] == 1);
        assert(describe(describe_port, connections[index], 0x1d, client_class) == client_ids[index]);
        printf("%" PRIx32 " %" PRIx64 " %" PRIx64 "\n", connections[index], client_ids[index], service_id);
        assert(IOServiceClose(connections[index]) == KERN_SUCCESS);
    }
    assert(IOObjectRelease(service) == KERN_SUCCESS);
    return 0;
}
"""

REQUEST = 3239
REPLY = 3339
LIBKERNEL_UUID = '780a6c1f-be02-34cc-84dd-00e05f61c89b'
SYMBOL = '_mach_port_kobject_description'
STUB = '__kernelrpc_mach_port_kobject_description'
FORMAT = 0xfffffe00070e0e17

USER_CHECKS = (
    (0x180567034, 'b #0x18056f964'),
    (0x18056fa04, 'str w1, [sp, #0x20]'),
    (0x18056fa08, 'bl #0x180548f00'),
    (0x18056fa18, 'stp w22, w0, [sp, #8]'),
    (0x18056fa2c, 'lsl x5, x0, #0x20'),
    (0x18056fa3c, 'mov x2, #0x1513'),
    (0x18056fa40, 'movk x2, #0x24, lsl #32'),
    (0x18056fa44, 'mov x4, #0xca700000000'),
    (0x18056fa48, 'mov w6, #0x240'),
    (0x18056fa50, 'bl #0x18055b918'),
    (0x18056fa90, 'cmp w8, #0xd0b'),
    (0x18056fb30, 'cmp w9, #0x200'),
    (0x18056fb58, 'ldr w8, [sp, #0x24]'),
    (0x18056fb60, 'ldr x8, [sp, #0x28]'),
)

KERNEL_CHECKS = (
    (0xfffffe000bdcf05c, 'tbnz w8, #0x1f, #0xfffffe000bdcf0b8'),
    (0xfffffe000bdcf064, 'cmp w8, #0x2c'),
    (0xfffffe000bdcf088, 'ldr x0, [x0, #8]'),
    (0xfffffe000bdcf08c, 'ldr w1, [x1, #8]'),
    (0xfffffe000bdcf09c, 'bl #0xfffffe000bd22fd4'),
    (0xfffffe000bdcf0e0, 'bl #0xfffffe000bce5b70'),
    (0xfffffe000bdcf0e4, 'add x8, x0, #1'),
    (0xfffffe000bdcf0f0, 'stp wzr, w8, [x19, #0x18]'),
    (0xfffffe000bdcf0f8, 'and w8, w8, #0xfffffffc'),
    (0xfffffe000bdcf0fc, 'add w8, w8, #0x40'),
    (0xfffffe000bd23008, 'bl #0xfffffe000bd42cb4'),
    (0xfffffe000bd23028, 'bl #0xfffffe000bd1abb4'),
    (0xfffffe000bd23038, 'tst w8, #3'),
    (0xfffffe000bd23044, 'sub w8, w8, #9'),
    (0xfffffe000bd23054, 'adrp x9, #0xfffffe0007010000'),
    (0xfffffe000bd23058, 'add x9, x9, #0xd74'),
    (0xfffffe000bd2305c, 'ldr w8, [x9, x8, lsl #2]'),
    (0xfffffe000bd2309c, 'ldr x16, [x17, #0x50]!'),
    (0xfffffe000bd230ac, 'autda x16, x17'),
    (0xfffffe000bd230b4, 'str xzr, [x21]'),
    (0xfffffe000bd230dc, 'sub w8, w8, #0x26'),
    (0xfffffe000bd230e0, 'cmp w8, #3'),
    (0xfffffe000bd23120, 'bl #0xfffffe000bd52a0c'),
    (0xfffffe000bd23128, 'ldr x16, [x8, #0x20]!'),
    (0xfffffe000bd23138, 'autda x16, x17'),
    (0xfffffe000bd23244, 'bl #0xfffffe000c5b6388'),
    (0xfffffe000c5b63cc, 'blraa x8, x16'),
    (0xfffffe000c5b63e0, 'ldr x0, [x0, #0x10]'),
    (0xfffffe000c5b6450, 'ldr x8, [x20, #0x10]'),
    (0xfffffe000c5b6458, 'ldr x8, [x8, #8]'),
    (0xfffffe000c5b6460, 'adrp x2, #0xfffffe00070e0000'),
    (0xfffffe000c5b6464, 'add x2, x2, #0xe17'),
    (0xfffffe000c5b647c, 'mov w1, #0x200'),
    (0xfffffe000c5b6480, 'bl #0xfffffe000c34e4f0'),
    (0xfffffe000c51ae9c, 'ldr x8, [x0, #0x10]'),
    (0xfffffe000c51aea4, 'ldr x0, [x8, #8]'),
)


def audit_collection(image):
    subsystem = image.pointer(0xfffffe000caff020)
    record = int(subsystem['target'], 16)
    start, end, largest_reply = struct.unpack('<III', image.read(record + 8, 12))
    assert (start, end, largest_reply) == (3200, 3243, 576)
    slot = record + 40 + (REQUEST - start) * 32
    stub = image.pointer(slot)
    assert (stub['target'], stub['auth'], stub['key'], stub['diversity']) == (
        '0xfffffe000bdcf054', 1, 0, '0x3a83')
    assert struct.unpack('<II', image.read(slot + 16, 8)) == (0, 576)
    types = dict(zip(range(0x26, 0x2a), struct.unpack('<4I', image.read(0xfffffe0007010de8, 16)), strict=True))
    assert types == {0x26: 0x1b, 0x27: 0x1d, 0x28: 0x1e, 0x29: 0x29}
    assert image.read(FORMAT, 10) == b'%s(0x%qx)\0'
    assert image.named('_snprintf') == 0xfffffe000c34e4f0
    assert image.named('__ZN15IORegistryEntry18getRegistryEntryIDEv') == 0xfffffe000c51ae98
    return {'collection_sha256': image.digest, 'kernel_uuid': IDENTITIES[1][1], 'subsystem': subsystem,
            'stub': stub, 'request_id': REQUEST, 'reply_id': REPLY,
            'description_format': '%s(0x%qx)', 'kernel_to_exported_type': types,
            'instructions': checked_instructions(image.read, KERNEL_CHECKS)}


def audit_cache():
    cache = Cache()
    libkernel = Dylib(cache, LIBKERNEL)
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    assert libkernel.uuid == LIBKERNEL_UUID
    assert (libkernel.exports[SYMBOL]['address'], libkernel.exports[STUB]['address']) == (0x180567034, 0x18056f964)
    assert struct.unpack('<II', cache.read(0x18057e7c0, 8)) == (0, REQUEST)
    return {'cache_uuid': cache.uuid, 'libkernel_uuid': libkernel.uuid,
            'instructions': checked_instructions(cache.read, USER_CHECKS)}


def run_control():
    with tempfile.TemporaryDirectory() as work:
        verifier = Path(work) / 'verify-iokit-port-description'
        subprocess.run(['xcrun', 'clang', '-x', 'c', '-Wall', '-Wextra', '-Werror',
                        '-framework', 'IOKit', '-framework', 'CoreFoundation',
                        '-o', str(verifier), '-'], input=CONTROL, text=True, check=True)
        raw = subprocess.check_output([str(verifier)], text=True)
    rows = re.findall(r'^([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+)$', raw, re.M)
    assert len(rows) == 2 and len(raw.splitlines()) == 2
    return {'control_source_sha256': hashlib.sha256(CONTROL.encode()).hexdigest(),
            'simultaneous_client_registry_joins': len(rows),
            'connection_type': 0x1d, 'registry_object_type': 0x1e, 'address_output': 0,
            'private_receive_type': 0xffffffff, 'connection_name_as_registry_right_status': '0xe00002c2',
            'examples': [{'connection_name': f'0x{name}', 'child_id': f'0x{child}', 'parent_id': f'0x{parent}'}
                         for name, child, parent in rows]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    image = Collection(args.collection, IDENTITIES[1])
    result = {'build': BUILD, 'kernel': audit_collection(image), 'libkernel': audit_cache(),
              'control': run_control()}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
