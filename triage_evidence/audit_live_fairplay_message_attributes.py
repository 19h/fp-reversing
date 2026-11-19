#!/usr/bin/env python3
"""Replay installed FPMessageAttr construction and verify random registration."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
import struct

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import POOL, POOL_ROOTS, TABLE, replay_proof
from audit_live_fairplay_early_publication import PROOF_TIMEOUT_SECONDS
from audit_live_fairplay_entry import CONTROLLERS, in_private, shifted, verify_layout
from audit_live_fairplay_schema_lookup_result import (
    CHECKS as LOOKUP_CHECKS, READY, SUCCESS, U64, LookupReplay, lookup_cases, verify_result_source,
)
from audit_live_fairplay_shared_table import EXTRA_BANKS, HOLDER
from audit_live_fairplay_tunnel import verify_descriptor
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES, commands, macho, string

CHECKS = '96933aa62724a9225566d8f3c98028eed287ba17ff313da5f575e2c333334f5c'
AUDIT = '40f81d032a2c3ccf4ee0651efa887889c068bed24e59841f08f13be7efb7a1d0'
INSTALLED_LOOKUP = 'f3ef2ff34fca8da92595779352931ab7812cd9c64c0f4228b1caee72ead5012c'
ATTR_SUCCESS = shifted('0xfffffe000a6575b0')
ATTR_ERROR = shifted('0xfffffe000a6621e4')
ATTR_CALL = shifted('0xfffffe000a652ecc')
RANDOM_CALLS = tuple(map(shifted, ('0xfffffe000a652fbc', '0xfffffe000a65305c')))
ATTRIBUTE = 0x630001d000
MODES = {'mode_zero': 0, 'mode_nonzero': 0x55, 'allocation_null': None}
BANKS = dict(allocate_L='UL', allocate_R='UR', descriptor_L='FL', descriptor_R='FR',
             random_first_L='TL', random_first_R='TR', random_second_L='VL', random_second_R='VR')
CONTEXT_STORES = {
    shifted(hex(0xfffffe0000000000 + addr)): (root, offset, width)
    for addr, root, offset, width in [
        (0xa636984, 'C', 0x100, 8), (0xa636988, 'S', 0xb60, 4),
        (0xa63698c, 'S', 0xf4, 4), (0xa636990, 'C', 0x360, 8),
        (0xa636994, 'C', 0x1b0, 8), (0xa636998, 'C', 0x700, 8),
        (0xa6369b0, 'F', 0x9e0, 8), (0xa652e18, 'C', 0x480, 8),
        (0xa652f1c, 'F', 0x9d0, 4), (0xa653110, 'C', 0x1b0, 8),
        (0xa6369dc, 'S', 0xd0c, 4), (0xa636b1c, 'C', 0x4a8, 8),
        (0xa641b1c, 'S', 0xab8, 4),
    ]
}


def check_corecrypto(image, register):
    name = 'com.apple.kec.corecrypto'
    for offset, kind, _ in commands(image.data, 0):
        if kind == 0x80000035:
            _, pos, name_offset, _ = struct.unpack_from('<QQII', image.data, offset + 8)
            if string(image.data, offset + name_offset) == name:
                break
    else:
        raise AssertionError(name)
    image_info = macho(image.data, pos, name)
    assert image_info['uuid'] == '3c2dd778-ef71-38be-ab61-559b8e8856bc'
    start, count, strings, _ = image_info['symtab']
    symbols = {name: set() for name in ('_corecrypto_kext_start', '_kprng_ctx',
                                       '_cckprng_refresh', '_cckprng_generate')}
    for n in range(count):
        index, kind, _, _, value = struct.unpack_from('<IBBHQ', image.data, start+n*16)
        if index and kind & 0x0e == 0x0e and not kind & 0xe0:
            symbol = string(image.data, strings+index)
            if symbol in symbols:
                symbols[symbol].add(value)
    resolved = {}
    for symbol, values in symbols.items():
        value, = values
        resolved[symbol] = value
    boot = resolved['_corecrypto_kext_start']
    ctx = resolved['_kprng_ctx']
    assert boot == 0xfffffe000bb3b5ac and ctx == 0xfffffe000ce72920
    boot_call = boot + 0x378
    stub = image.branch(boot_call, 'bl')
    import_slot = 0xfffffe0008acd650
    fixup = image.pointer(import_slot)
    assert fixup['target'] == hex(register)
    assert (fixup['format'], fixup['auth'], fixup['key'], fixup['diversity'],
            fixup['address_diversity']) == (8, 1, 0, '0x0', 1)
    lines = [
        (boot+0x2c4, 'add', 'x8, sp, #0x20'),
        (boot_call-12, 'adrp', 'x0, #0xfffffe000ce72000'),
        (boot_call-8, 'add', 'x0, x0, #0x920'),
        (boot_call-4, 'add', 'x1, sp, #0x20'),
        (stub, 'adrp', 'x17, #0xfffffe0008acd000'),
        (stub+4, 'add', 'x17, x17, #0x650'),
        (stub+8, 'ldr', 'x16, [x17]'),
        (stub+12, 'braa', 'x16, x17'),
    ]
    for role, offset, stack_offset, modifier in (
        ('refresh', 0x318, 0x38, 0x4d5f), ('generate', 0x334, 0x40, 0xedeb)
    ):
        target = resolved['_cckprng_' + role]
        at = boot + offset
        lines.extend([
            (at, 'add', f'x9, x8, #{stack_offset-0x20:#x}'),
            (at+4, 'adrp', f'x16, #{target & ~0xfff:#x}'),
            (at+8, 'add', f'x16, x16, #{target & 0xfff:#x}'),
            (at+12, 'mov', 'x17, x9'),
            (at+16, 'movk', f'x17, #{modifier:#x}, lsl #48'),
            (at+20, 'pacia', 'x16, x17'),
            (at+24, 'str', f'x16, [sp, #{stack_offset:#x}]'),
        ])
    return dict(uuid=image_info['uuid'], symbols={k: hex(v) for k, v in resolved.items()},
                registration_call=hex(boot_call), stub=hex(stub), import_slot=fixup,
                source=assert_instructions(image.read, lines))


def verify_random(image, original):
    wrapper = image.named('_random')
    register = image.named('_register_and_init_prng')
    image.instruction(wrapper, 'pacibsp', '')
    image.instruction(wrapper+112, 'retab', '')
    archived = bytes.fromhex(original['bytes'])
    raw = image.read(wrapper, 116)
    assert len(archived) == len(raw) and sha256(archived).hexdigest() == original['sha256']
    assert [i for i in range(0, 116, 4) if archived[i:i+4] != raw[i:i+4]] == [0x18, 0x24, 0x28, 0x40]
    provider_page, context_page = 0xfffffe0007e78000, 0xfffffe000cc05000
    provider, ctx = provider_page+0x9a0, context_page+0x48
    for cell in (provider, provider+8, ctx):
        assert image.read(cell, 8) == bytes(8) and image.offset(cell, 8) not in image.fixups
    source = assert_instructions(image.read, [
        (wrapper+0x18, 'adrp', f'x19, #{provider_page:#x}'),
        (wrapper+0x1c, 'add', 'x19, x19, #0x9a0'),
        (wrapper+0x20, 'ldr', 'x8, [x19]'),
        (wrapper+0x24, 'adrp', f'x20, #{context_page:#x}'),
        (wrapper+0x28, 'ldr', 'x0, [x20, #0x48]'),
        (wrapper+0x2c, 'mov', 'x17, x19'),
        (wrapper+0x30, 'movk', 'x17, #0x4d5f, lsl #48'),
        (wrapper+0x34, 'blraa', 'x8, x17'),
        (wrapper+0x38, 'mrs', 'x8, tpidr_el1'),
        (wrapper+0x3c, 'ldr', 'x9, [x19, #8]!'),
        (wrapper+0x40, 'ldr', 'x0, [x20, #0x48]'),
        (wrapper+0x44, 'ldrh', 'w1, [x8, #0x1b8]'),
        (wrapper+0x48, 'add', 'x3, sp, #0xc'),
        (wrapper+0x4c, 'mov', 'w2, #4'),
        (wrapper+0x50, 'mov', 'x17, x19'),
        (wrapper+0x54, 'movk', 'x17, #0xedeb, lsl #48'),
        (wrapper+0x58, 'blraa', 'x9, x17'),
        (wrapper+0x5c, 'ldr', 'w8, [sp, #0xc]'),
        (wrapper+0x60, 'and', 'w0, w8, #0x7fffffff'),
    ])
    registry_words = [(register+0x18, 'mov', 'x19, x1'), (register+0x1c, 'mov', 'x20, x0'),
                      (register+0x30, 'adrp', f'x21, #{context_page:#x}'),
                      (register+0x34, 'str', 'x20, [x21, #0x48]')]
    for relative, offset, immediate, diversity in ((0xc8, 0x18, 0x9a0, 0x4d5f),
                                                  (0xf8, 0x20, 0x9a8, 0xedeb)):
        site = register + relative
        assert image.branch(site+8, 'cbz') == site+0x28
        registry_words.extend([
            (site, 'mov', 'x17, x19'),
            (site+4, 'ldr', f'x16, [x17, #{offset:#x}]!'),
            (site+12, 'adrp', f'x8, #{provider_page:#x}'),
            (site+16, 'add', f'x8, x8, #{immediate:#x}'),
            (site+20, 'movk', f'x17, #{diversity:#x}, lsl #48'),
            (site+24, 'autia', 'x16, x17'),
            (site+28, 'mov', 'x17, x8'),
            (site+32, 'movk', f'x17, #{diversity:#x}, lsl #48'),
            (site+36, 'pacia', 'x16, x17'),
            (site+40, 'adrp', f'x8, #{provider_page:#x}'),
            (site+44, 'str', f'x16, [x8, #{immediate:#x}]'),
        ])
    return dict(address=hex(wrapper), size_bytes=len(raw), sha256=sha256(raw).hexdigest(),
                context_cell=hex(ctx), provider_cells=[hex(provider), hex(provider+8)],
                zero_file_cells_without_fixups=3, source=source, registration=hex(register),
                registration_words=assert_instructions(image.read, registry_words),
                corecrypto=check_corecrypto(image, register), native_provider_observed=False)


def verify_attribute_source(image, checks, allocate, random):
    source = checks['source']
    spans = [span for span in source['spans'] if span['label'].startswith('attr_')]
    layout = verify_layout(image, {'attribute': dict(source, spans=spans)})
    rows = layout['spans']['attribute']
    assert len(spans) == 19 and sum(row['words'] for row in rows) == 487
    assert len(layout['branch_fixups']) == 115
    assert [word['address'] for row in rows for word in row['changes']] == [
        '0xfffffe000a694048', '0xfffffe000a69404c'
    ]
    layout['relocated'] = assert_instructions(image.read, [
        (0xfffffe000a694048, 'adrp', 'x9, #0xfffffe0008488000'),
        (0xfffffe000a69404c, 'add', 'x9, x9, #0x9a0'),
    ])
    roots = {name: (offset, target, bias)
             for offset, (target, name, bias) in (POOL_ROOTS | EXTRA_BANKS).items()}
    known = {}
    bank_bytes, bank_fixups = {}, {}
    for role, name in BANKS.items():
        offset, target, bias = roots[name]
        bank_fixups[role] = verify_fixup(image, POOL+offset, target)
        base = target + bias
        archived = checks['attribute_banks'][role]
        bank_bytes[role] = image.read(base, 256)
        assert bank_bytes[role].hex() == archived['bytes_hex']
        known[int(archived['address'], 16)] = base
    descriptor = 0xfffffe0008491c80
    targets = dict(allocate=allocate, descriptor=descriptor, random_first=random, random_second=random)
    bindings = {}
    for rule in checks['attribute_bank_rules']:
        name = rule['name']
        left, right = [bank_bytes[rule[f'{side}_name']] for side in ('left', 'right')]
        key = int(rule['key'], 16)
        constant, = {i ^ right[left[i] ^ key] for i in range(256)}
        index = constant + int(rule['additive'], 16)
        assert (constant, index) == tuple(int(rule[k], 16) for k in ('constant', 'index'))
        pointer = rule['original_pointer']
        slot = (TABLE if pointer['authenticated'] else POOL) + index*8
        raw_target = (targets[name] - int(rule['bias'], 16)) & U64
        bindings[name] = dict(inputs=256, target=hex(targets[name]),
                              fixup=verify_fixup(image, slot, raw_target, pointer['diversity']))
    assert bindings.keys() == targets.keys()
    read = verify_descriptor(image, descriptor, 112, 'site.FPMessageAttr')
    archived = bytes.fromhex(checks['attribute_descriptor']['normalized64_bytes_hex'])
    current = bytes.fromhex(read['bytes'])
    assert current[:16] == archived[:16] and current[24:32] == archived[24:32]
    assert current[40:] == archived[40:]
    layout.update(descriptor=read, banks=bank_fixups, bank_bindings=bindings)
    allowed = {shifted(word['pc']) for span in spans for word in span['instructions']}
    return layout, allowed, known


class AttributeReplay(LookupReplay):
    attribute_reads = None

    def load(self, address, width, discarded=False):
        value = super().load(address, width, discarded)
        if self.attribute_reads is not None and self.payload <= address < self.payload + 56:
            assert not discarded and address + width <= self.payload + 56
            self.attribute_reads.append((self.pc, address-self.payload, width, value))
        return value

    def external_return(self, word, pc, frame, target, modifier, result, index):
        assert word.mnemonic == 'blraa' and self.sp == frame
        assert self.step(word) == target and self.g[30] == pc+4
        edge = self.edges[-1]
        assert edge['modifier64'] == hex(modifier)
        for reg in range(19):
            self.g[reg] = 0xe900000000000000 + index*0x100 + reg
        self.g[30] = 0xe900000000010000 + index
        self.nzcv = 0xf0000000
        self.g[0] = result
        return dict(pc=hex(pc), target=hex(target), modifier=hex(modifier), link=hex(pc+4),
                    modeled_x0=hex(result), callee_executed=False)

    def attribute(self, allowed, archive, banks, profile, descriptor, allocate, random, seed):
        F = self.sp
        S, C, H, J, Z = (int(cut['result'], 16) for cut in self.cuts)
        assert self.pc == READY
        self.payload = P = self.value(C+0x440, 8)
        inputs = {}
        for cell in archive['attribute_additional_source_cells']:
            assert cell['root'] == 'F'
            offset, width = int(cell['offset'], 16), cell['size_bytes']
            old = int.from_bytes(bytes.fromhex(cell['reconstructed_bytes_hex']), 'little')
            value = self.value(F+offset, width)
            assert value == banks.get(old, old), (hex(offset), hex(value), hex(old))
            inputs[hex(offset)] = hex(value)
        assert len(inputs) == 11 and not archive['initial_workspace_d0c_defined_by_prefix']
        assert in_private(P, 56) and in_private(ATTRIBUTE, 112)
        assert P+56 <= ATTRIBUTE
        table_base, table_end = self.table_bounds
        assert all(table_end <= base or base+length <= table_base
                   for base, length in ((P, 56), (ATTRIBUTE, 112)))
        for base, n in ((P, 56), (ATTRIBUTE, 112), (S+0xd0c, 4)):
            assert not any(base+i in self.state for i in range(n))
        mode = MODES[profile]
        created = mode is not None
        A = ATTRIBUTE if created else 0
        payload = bytearray((17*i+29+seed) & 255 for i in range(56))
        if created:
            payload[4] = mode
            self.state.update((P+i, v) for i, v in enumerate(payload))
        workspace = 0xa6201100 + seed
        self.state.update((S+0xd0c+i, b) for i, b in enumerate(workspace.to_bytes(4, 'little')))
        protected = self.value(Z, 14)
        preserved = [(H, 16), (J, 32), (Z, 14), (P, 56), (F+0xaa8, 8), (C+0x440, 8),
                     (S+0xbc4, 4), (self.holder, 16), (table_base, table_end-table_base)]
        assert self.value(F+0x9e0, 8) == HOLDER
        initial = [tuple(self.state.get(a+i) for i in range(n)) for a, n in preserved]
        self.attribute_reads = []
        first_store, first_edge = len(self.publication_stores), len(self.edges)
        calls, raw_words = [], []
        visits = 0
        endpoint = ATTR_SUCCESS if created else ATTR_ERROR
        while self.pc != endpoint:
            assert visits < 8*len(allowed) and self.pc in allowed, (profile, hex(self.pc))
            self.ix += 1
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            if self.pc == ATTR_CALL:
                assert not calls and self.g[0] == descriptor
                calls.append(self.external_return(word, self.pc, F, allocate, 0xd0c8, A, 0))
                self.pc += 4
            elif self.pc in RANDOM_CALLS:
                n = len(raw_words)
                assert created and n < 64 and self.pc == RANDOM_CALLS[n//32]
                boundary_words = (0, 0x7fffffff, 0x80000000, 0xffffffff)
                pos = n % 32
                raw_word = (boundary_words[pos] if pos < len(boundary_words) else
                            ((n+seed)*0x01f24b7d+0x92fce199) & 0xffffffff)
                raw_words.append(raw_word)
                result = raw_word & 0x7fffffff
                calls.append(self.external_return(word, self.pc, F, random, 0xc350, result, n+1))
                self.pc += 4
            else:
                assert word.mnemonic != 'blraa'
                self.pc = self.step(word)
            visits += 1
        assert self.sp == F and self.value(S+0xd0c, 4) == workspace
        assert self.value(C+0x480, 8) == shifted('0xfffffe000a6369c8')
        assert self.value(C+0x1b0, 8) == A and self.value(C+0x700, 8) == P
        assert self.value(F+0x9e0, 8) == C+0x1b0
        assert self.value(C+0x100, 8) == C+0x90 and self.value(C+0x360, 8) == 0
        assert self.value(S+0xb60, 4) == self.value(S+0xf4, 4) == SUCCESS
        assert self.value(Z, 14) == protected
        for (a, n), before in zip(preserved, initial, strict=True):
            assert tuple(self.state.get(a+i) for i in range(n)) == before

        stores = self.publication_stores[first_store:]
        ctx = dict(C=C, S=S, F=F)
        attribute_stores = []
        for pc_hex, address_hex, width, val_hex in stores:
            pc, addr = int(pc_hex, 16), int(address_hex, 16)
            if created and A <= addr < A+112:
                assert addr+width <= A+112
                attribute_stores.append((pc, addr-A, width, int(val_hex, 16)))
            else:
                root, offset, wanted_width = CONTEXT_STORES[pc]
                assert (addr, width) == (ctx[root]+offset, wanted_width)
        edges = self.edges[first_edge:]
        tail = edges[-1]
        if created:
            assert len(calls) == 65 and len(raw_words) == 64 and self.value(C+0x4a8, 8) == P
            assert self.g[22] == self.value(F+0x524, 4)
            assert self.g[8] == C+0x360 and self.g[20] == self.value(F+0x8f8, 8)
            generated = bytes((w & 255) ^ 0xc7 for w in raw_words)
            for first, orig_pc in ((0, '0xfffffe000a652fe4'), (32, '0xfffffe000a653080')):
                assert [s[1:] for s in attribute_stores if s[0] == shifted(orig_pc)] == [
                    (8+i, 1, generated[i]) for i in range(first, first+32)
                ]
            want = bytearray(112)
            want[:4] = (0x3908f615).to_bytes(4, 'little')
            want[8:40] = payload[24:56] if mode == 0 else generated[:32]
            want[40:72] = generated[32:]
            want[0x48], want[0x50], want[0x51] = (32 if mode == 0 else 0), int(mode != 0), 0x1a
            want[0x54:0x58], want[0x58:0x68] = payload[:4], payload[8:24]
            want[0x68], want[0x6c] = 16, 3
            holes = {0x52, 0x53, 0x6d, 0x6e, 0x6f}
            assert {i for i in range(112) if A+i not in self.state} == holes
            assert {i for _, off, n, _ in attribute_stores for i in range(off, off+n)} == set(range(112))-holes
            assert all(self.state[A+i] == b for i, b in enumerate(want) if i not in holes)
            reads = [(offset, 1, payload[offset]) for offset in range(0x17, 7, -1)]
            reads.append((4, 1, mode))
            if mode == 0:
                reads.extend((offset, 1, payload[offset]) for offset in range(0x37, 0x17, -1))
            reads.append((0, 4, int.from_bytes(payload[:4], 'little')))
            assert [event[1:] for event in self.attribute_reads] == reads
            attribute = ''.join('??' if i in holes else f'{want[i]:02x}' for i in range(112))
            status = None
            last_pc, modifier = shifted('0xfffffe000a636d30'), 0x2854
        else:
            assert len(calls) == 1 and not self.attribute_reads and not attribute_stores
            status = self.value(S+0xab8, 4)
            assert status == 0xce515bb2
            attribute = None
            last_pc, modifier = shifted('0xfffffe000a641b38'), 0x682a
        assert (tail['pc'], tail['target'], tail['modifier64'], tail['kind']) == (
            hex(last_pc), hex(endpoint), hex(modifier), 'braa')
        return dict(profile=profile, caller_bindings=inputs, payload_mode=mode, payload_address=hex(P),
                    attribute_address=hex(A), attribute_bytes_hex_or_unknown=attribute,
                    workspace_fixture_u32=hex(workspace), workspace_restored=True,
                    caller_error=hex(status) if status is not None else None, endpoint=hex(endpoint),
                    instruction_visits=visits, external_returns=calls,
                    random_provider_word_fixtures=list(map(hex, raw_words)),
                    payload_loads=[dict(pc=hex(pc), offset=off, width=n, value=hex(v))
                                   for pc, off, n, v in self.attribute_reads],
                    attribute_writes=len(attribute_stores), stores=stores, edges=edges)


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    checks = receipt('userclient_message_attributes_checks', CHECKS)
    prior = receipt('userclient_message_attributes_audit', AUDIT)
    lookup = receipt('userclient_schema_lookup_result_checks', LOOKUP_CHECKS)
    previous = receipt('live_fairplay_schema_lookup_result_audit', INSTALLED_LOOKUP)
    assert checks['lookup_result_source'] == lookup['source'] and prior['checks_sha256'] == CHECKS
    assert previous['identity'] == list(IDENTITIES[1]) and previous['historical_checks_sha256'] == LOOKUP_CHECKS
    assert checks['kernel_collection_sha256'] == prior['kernel_collection_sha256'] == IDENTITIES[0][0]
    allocate, random = image.named('_IOMallocTypeImpl'), image.named('_random')
    layout, allowed, banks = verify_attribute_source(image, checks, allocate, random)
    provider = verify_random(image, checks['kernel_random_function'])
    verify_result_source(image, lookup)
    predecessors = {row['predecessor_case_index']: row for row in checks['predecessor_states']}
    references = {c['fixture']: c for c in previous['cases'] if c['result']['profile'] == 'hit_nonnull'}
    cases = []
    for found, replay in lookup_cases(image, lookup, profiles=('hit_nonnull',)*len(MODES),
                                      replay_type=AttributeReplay):
        name, index = found['fixture'], found['case_index']
        assert json.loads(json.dumps(found)) == references[name]
        profile = list(MODES)[len(cases)//len(references)]
        result = replay.attribute(allowed, predecessors[index], banks, profile,
                                  int(layout['descriptor']['address'], 16), allocate, random,
                                  seed=index + 11*(len(cases)//len(references)))
        cases.append(dict(fixture=name, case_index=index, result=result))
    proofs = prior['source_proofs']
    assert len(cases) == 6 and len(proofs) == 199
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(partial(replay_proof, timeout_seconds=PROOF_TIMEOUT_SECONDS), proofs))
    return dict(build=build, identity=IDENTITIES[1], layout=layout, random_interface=provider,
                cases=cases, source_proofs=results, historical_checks_sha256=CHECKS, historical_audit_sha256=AUDIT,
                installed_lookup_audit_sha256=INSTALLED_LOOKUP, proof_timeout_seconds=PROOF_TIMEOUT_SECONDS,
                native_allocator_observed=False, native_random_provider_observed=False,
                native_PAC_verified=False, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
