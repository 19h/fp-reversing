#!/usr/bin/env python3
"""Extract append-field source spans and input custody from pinned journals.
No new execution, API return, owner, root or payload premise is introduced.
O(parent receipt bytes + selected visits + reads*writes) time;
O(parent receipts + selected evidence) space. Native identities stay unknown.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from audit_daemon_environment_outputs import DEC
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_descriptor_growth as Parent

P = 'daemon_append_fields'
PINS = {'daemon_descriptor_growth_checks.json': 'b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2',
        'daemon_descriptor_growth_replay.json': 'bee4ab3224710559fefdd8bca070110e48c03ab52d01c92b617988b9b3d5bd67'}
DEPS = ['daemon_receive_tools.py', 'recover_daemon_descriptor_growth.py', 'audit_daemon_environment_outputs.py',
        'verify_daemon_reader_record_payloads_publication.py']
SPANS = {'word_writer': (0x100c70dd8, 0x100c70f1c),
         'half_writer': (0x100b75548, 0x100b755fc),
         'array_mixer': (0x1009dabb0, 0x1009dad18),
         'packed_word_producer': (0x100c29254, 0x100c29804),
         'half_producer': (0x100b75220, 0x100b75548),
         'packed_word_caller_a': (0x100b9e52c, 0x100b9e538),
         'packed_word_caller_b': (0x100aec72c, 0x100aec738)}
BANKS = {'A': (0x148, 0x100ed2440, 17), 'B': (0x150, 0x100e36310, 16),
         'C': (0x140, 0x100f2f6b0, 19), 'D': (0x278, 0x100f21190, 16),
         'E': (0x270, 0x100fa38b0, 20), 'K': (0x280, 0x100ffc9e0, 17)}


def parents():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest
    return json.loads(read(ROOT/'daemon_descriptor_growth_checks.json'))


def slices(e):
    for ci in [2, 3]:
        c = e['classes'][ci]
        assert c['pointer_return64'] == hex(Parent.H)
        for ii, item in enumerate(c['intervals']):
            row = Parent.unpack(item['interval_packed'])
            for kind, (a, b) in SPANS.items():
                for j, visit in enumerate(row['source_visits']):
                    if visit['pc'] != hex(a):
                        continue
                    end = j+(b-a)//4
                    assert [int(v['pc'], 16) for v in row['source_visits'][j:end]] == list(range(a, b, 4))
                    yield ci, ii, kind, j, end, row


def custody(row, r):
    out = []
    a = int(r['address'], 16)
    for at in range(a, a+r['size_bytes']):
        writers = [w for w in row['source_writes'] if w['source_visit_index'] < r['source_visit_index']
                   and int(w['address'], 16) <= at < int(w['address'], 16)+w['size_bytes']]
        out.append({'address': hex(at), 'last_writer_in_this_interval': writers[-1] if writers else None,
                    'earlier_source_or_entry_required': not writers})
    return out


def extract():
    e = parents()
    out, counts = [], Counter()
    for ci, ii, kind, lo, hi, row in slices(e):
        entry, exit = row['source_frames'][lo], row['source_frames'][hi]
        reads = [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi]
        writes = [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]
        values = {}
        regs = [int(x, 16) for x in entry['registers31']]
        if kind == 'word_writer':
            values = {'base': hex(regs[9]), 'offset32': (regs[10]+0xae20ac2a)&0xffffffff,
                      'mixed32': hex(regs[11]&0xffffffff), 'unmasked32': hex((regs[11]^0xe4b5bf34)&0xffffffff),
                      'mixed_last_GP_definition': last_definition(row, lo, 'x11')}
        elif kind == 'half_writer':
            n = (-2-regs[8]-regs[10])&0xffffffff
            values = {'base': hex(regs[22]), 'offset32': (regs[21]+0x8927158e)&0xffffffff,
                      'sum_complement32': hex(n), 'consumed16': hex(n&65535)}
        elif kind == 'array_mixer':
            prior = next(r for r in row['source_reads'] if r['pc'] == '0x1009dab70' and r['source_visit_index'] == lo-16)
            pointer = next(r for r in row['source_reads'] if r['source_visit_index'] == prior['source_visit_index']-1)
            raw = int.from_bytes(bytes.fromhex(prior['bytes_hex']), 'little')
            pointer_value = int.from_bytes(bytes.fromhex(pointer['bytes_hex']), 'little')
            index = int(row['source_frames'][prior['source_visit_index']]['registers31'][11], 16)
            assert index == 2 and int(prior['address'], 16) == pointer_value+4*index
            values = {'array_pointer_read': pointer, 'array_element_read': prior,
                      'element_custody': custody(row, prior), 'index32': index,
                      'additive_unmasked32': hex((raw+0xb69f7313)&0xffffffff)}
        elif kind == 'packed_word_producer':
            assert len(reads) == 2
            values = {'entry_word32': hex(regs[8]&0xffffffff),
                      'count32': int.from_bytes(bytes.fromhex(reads[0]['bytes_hex']), 'little'),
                      'second_stack_word32': hex(int.from_bytes(bytes.fromhex(reads[1]['bytes_hex']), 'little')),
                      'entry_word_last_GP_definition': last_definition(row, lo, 'x8')}
        elif kind == 'half_producer':
            values = {'phase_W23': hex(regs[23]&0xffffffff), 'phase_W24': hex(regs[24]&0xffffffff),
                      'phase_W25': hex(regs[25]&0xffffffff)}
        else:
            values = {'input_W11': hex(regs[11]&0xffffffff),
                      'output_W11': hex(int(exit['registers31'][11], 16)&0xffffffff)}
        out.append({'class_index': ci, 'interval_index': ii, 'kind': kind, 'start_visit': lo, 'end_visit_exclusive': hi,
                    'entry': entry, 'exit': exit, 'reads': reads, 'writes': writes,
                    'read_custody': [{'read': r, 'custody': custody(row, r)} for r in reads if kind in ['packed_word_producer', 'half_producer']],
                    'values': values})
        counts.update(slices=1, selected_visits=hi-lo, selected_reads=len(reads), selected_writes=len(writes))
    assert Counter(o['kind'] for o in out) == {'word_writer': 8, 'half_writer': 4, 'array_mixer': 2,
                                               'packed_word_producer': 6, 'half_producer': 4,
                                               'packed_word_caller_a': 4, 'packed_word_caller_b': 2}
    joins = []
    for o in out:
        if o['kind'] != 'packed_word_producer':
            continue
        targets = sorted((x for x in out if x['class_index'] == o['class_index'] and x['interval_index'] == o['interval_index']
                          and x['kind'] == 'word_writer' and x['start_visit'] > o['end_visit_exclusive']), key=lambda x: x['start_visit'])
        target = targets[0]
        produced = int(o['exit']['registers31'][11], 16)&0xffffffff
        consumed = int(target['values']['mixed32'], 16)
        assert produced^0x25e3467a == consumed
        definition = target['values']['mixed_last_GP_definition']
        assert definition['pc'] in ['0x100b9e534', '0x100aec734']
        joins.append({'class_index': o['class_index'], 'interval_index': o['interval_index'],
                      'producer_start_visit': o['start_visit'], 'writer_start_visit': target['start_visit'],
                      'offset32': target['values']['offset32'], 'producer_output32': hex(produced),
                      'caller_XOR32': '0x25e3467a', 'writer_input32': hex(consumed), 'last_W11_definition': definition})
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'source_spans': [{'kind': k, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': IMAGE.read(a, b-a).hex()}
                             for k, (a, b) in SPANS.items()],
            'banks': {k: {'SP_offset_bytes': o, 'address': hex(a), 'size_bytes': n, 'bytes_hex': IMAGE.read(a, n).hex()}
                      for k, (o, a, n) in BANKS.items()}, 'occurrences': out, 'producer_writer_joins': joins,
            'inherited_nonnull_branch_members': sum(len(e['classes'][j]['members']) for j in [2, 3]),
            'verified_counts': dict(counts), 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


def last_definition(row, lo, name):
    for k in range(lo-1, -1, -1):
        v = row['source_visits'][k]
        pc = int(v['pc'], 16)
        ins = next(DEC.disasm(IMAGE.read(pc, 4), pc))
        names = {ins.reg_name(x).replace('w', 'x', 1) for x in ins.regs_access()[1]}
        if name in names:
            return {'visit': k, 'pc': hex(pc), 'mnemonic': ins.mnemonic, 'operands': ins.op_str,
                    'value_after': row['source_frames'][k+1]['registers31'][int(name[1:])]}
    return None


if __name__ == '__main__':
    result = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']), flush=True)
