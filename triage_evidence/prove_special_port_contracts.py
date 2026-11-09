#!/usr/bin/env python3
"""Prove bounded native dispatcher selections; no target execution.

The source-to-formula translation is manually audited in the linked report.
All 256 possible byte indices are checked for each selector-bank identity.
Z3 proves the status predicate over the complete 32-bit domain. Frame/table
protocol assumptions do not become entry-reachability or PAC proofs.
"""
import json
from pathlib import Path
import struct
import subprocess
from verify_interface_contracts import Image

ROOT = Path(__file__).resolve().parent
BASE = 0xfffffe0008472f20
MASK = 0xffffffff


def u32(value):
    return value & MASK


def main():
    image = Image(ROOT.parent/'com.apple.driver.FairPlayIOKit')
    evidence = json.loads((ROOT/'host_port_rpc_callers_native.json').read_text())
    for r in evidence:
        expected = bytes.fromhex(r['bytes'])
        assert image.read(int(r['start'], 16), len(expected)) == expected
    def qword(a):
        return struct.unpack('<Q', image.read(a, 8))[0]
    assert qword(0xfffffe0008472098)-12 == BASE
    # These pool loads and frame writes are in core2_dispatch_prefix_native.json.
    assert qword(0xfffffe0008472740) == 0xfffffe0007949dd0
    assert qword(0xfffffe0008472ab8) == 0xfffffe000792fbc0
    assert qword(0xfffffe0008472a70) == 0xfffffe0007949ed0
    assert qword(0xfffffe0008472910) == 0xfffffe000792fec0
    assert qword(0xfffffe0008472b08)-8 == 0xfffffe0007941f60
    assert qword(0xfffffe0008472058)-4 == 0xfffffe000794a0d0
    selections = []
    cases = [
        ('host_priv_self', 0xfffffe0007949dd0, 0xfffffe000792fbc0,
         0x3e, 0xf4a, 0x54, 0xfffffe000bcf27ac, 0xfffffe000a60ac04),
        ('host_get_special_port', 0xfffffe0007949ed0, 0xfffffe000792fec0,
         0x32, 0xeb4, 0xf9, 0xfffffe000bcf258c, 0xfffffe000a60acb8),
        ('rpc502', 0xfffffe0007941f60, 0xfffffe000794a0d0,
         0x98, 0xed9, 0x95, 0xfffffe000a5a2064, 0xfffffe000a60b8a8),
        ('rpc700', 0xfffffe0007949ed0, 0xfffffe000792fec0,
         0x32, 0xec0, 0xf9, 0xfffffe000a5a22d4, 0xfffffe000a60d3bc),
    ]
    for name, left, right, key, additive, constant, target, site in cases:
        l, r = image.read(left, 256), image.read(right, 256)
        assert {x ^ r[l[x] ^ key] for x in range(256)} == {constant}
        index = additive+constant
        slot = BASE+8*index
        assert qword(slot) == target
        selections.append({'name': name, 'call_site': hex(site),
                           'left_bank': hex(left), 'right_bank': hex(right),
                           'xor_key': hex(key), 'constant': hex(constant),
                           'index': hex(index), 'slot': hex(slot),
                           'target': hex(target), 'byte_inputs_checked': 256})
    # Conditional predecessor: non-NULL allocation at AB2C followed by AB70.
    assert qword(BASE+8*0xc96) == 0xfffffe000a60ab74
    previous_w20 = 0xc96
    incoming_w23 = u32(previous_w20-0xc187bb5e)
    w22 = u32(incoming_w23+0x392c3c43) & 0x885b76cc
    w20 = u32(w22+0x8fb0c137) & 0x704f3ebf
    compare_value = u32(w20-0x43e)
    assert (incoming_w23, w22, w20, compare_value) == (0x3e785138, 0x448, 0x43f, 1)
    assert u32(w22+0x9b2) ^ 0xdfb == 1  # variable shift amount at ACEC
    predicates = []
    for which, c, mask, addition in [
        ('selector17', 0x71cff3bf, 0xe39fe77e, 0xbfbfbf53),
        ('selector34', 0xfbefb35f, 0xf7df66be, 0x359fffb3),
    ]:
        assert u32(c*2) == mask and u32(c+addition) == 0x318fb312
        smt = f'''(set-logic QF_BV)
(declare-fun status () (_ BitVec 32))
(define-fun folded () (_ BitVec 32)
  (bvadd (bvxor status #x{c:08x}) #x{addition:08x}
    (bvand (bvshl status #x00000001) #x{mask:08x})))
(assert (not (= (= folded #x318fb312) (= status #x00000000))))
(check-sat)
'''
        path = ROOT/f'host_port_status_{which}.smt2'
        path.write_text(smt)
        result = subprocess.run(['z3', '-smt2', str(path)], check=True,
                                capture_output=True, text=True).stdout.strip()
        assert result == 'unsat', result
        predicates.append({'case': which, 'query': path.name, 'result': result})
    assert qword(BASE+8*(0x448 ^ 0x942)) == 0xfffffe000a60ad28
    # B81C's operation selection is conditional on this dispatcher word.
    rpc_state = 0x8ea
    assert qword(BASE+8*rpc_state) == 0xfffffe000a60d334
    assert qword(BASE+8*(rpc_state ^ (rpc_state-0x6fe))) == 0xfffffe000a60b820
    result = {'selections': selections,
              'host_lookup_predecessor': {'nonnull_allocation': True,
                                         'previous_w20': hex(previous_w20),
                                         'incoming_w23': hex(incoming_w23),
                                         'comparison_word': compare_value},
              'port_selection': 'request_record_u32_at_0x24 == 1 ? 17 : 34',
              'lookup_node': -1, 'port_output': 'X28 + 0x18',
              'status_predicates': predicates,
              'rpc_variant_precondition': 'W11 == 0x8ea at 0xfffffe000a60b7f0',
              'rpc_variant': 'request_record_u32_at_0x24 == 1 ? RPC502 : RPC700',
              'assumptions': [
                  'common dispatcher table base and bank/frame pointers initialized by captured prefix',
                  'predecessor path and callee-saved register/frame preservation hold',
                  'no concurrent mutation of table/bank/frame inputs during the local slices',
                  'no function-entry reachability, complete object-alias chain, or native PAC validation claimed'],
              'target_executed': False}
    (ROOT/'special_port_contract_proof.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
