#!/usr/bin/env python3
"""Reproduce local frame-code normalization; does not emulate the driver."""
import json
import random
from pathlib import Path

MASK=(1<<32)-1
A=0xEF54FF65
NEG_A=0x10AB009B
K=0x3E784FF5
KEY=0x97099BC0
TAGS={'cmam7f':0x1414EE04,'uzZm1ih0':0xEAB485F6,'fcHfFIGhsx':0xD11612F2,
      'fd9eLZ4':0x511BAFD6,'bRyEnFcB':0xDF8CDD16,'EQlZPp':0x94F8574B,
      'RUD5XlDtQjk':0x5A29762C,'egYabpIOCbFA':0x6CD79A35}
assert (A+NEG_A)&MASK==0
assert ((~0x43476868)&MASK)^0x12BF9670==0xAE0701E7
assert ((~0x5E64C9B1)&MASK)^0x3692AD8E==KEY
# The proof is algebraic: for every 32-bit p, X XOR X = 0 and
# (-A*X - (-A)*X) mod 2**32 = 0. The secondary equalities use
# 2*(p&M)-p = M-(p XOR M), an exact integer identity.
rng=random.Random(0xF410)
values=[0,1,MASK,0x7FFFFFFF,0x80000000]+[rng.getrandbits(32) for _ in range(100000)]
for p in values:
    x=A*(p^KEY)&MASK
    assert ((K-x)-NEG_A*(p^KEY))&MASK==K
    for tag in TAGS.values(): assert ((x^tag)^x)&MASK==tag
    expression=(2*(p&0x5E64C9B1)-p-0x5E64C9B2)&MASK
    assert (expression^0x3692AD8E)==(p^KEY)
    encoded=0x952F3CB7*(p^0xAE0701E7)&MASK
    decoder=0x952F3CB7*(((MASK-(p^0x43476868))&MASK)^0x12BF9670)&MASK
    assert ((encoded^0x563)^decoder)==0x563
out={'word_bits':32,'tag_by_wrapper':{k:hex(v) for k,v in TAGS.items()},
     'secondary_state':hex(K),'core1_execute_tag':'0x563',
     'proof':'Identical-term XOR cancellation and additive inverses modulo 2^32; rewritten input mask follows exact bitwise addition identity.',
     'regression_values':len(values),'regression_role':'Finite implementation cross-check, separate from the algebraic identities.',
     'scope':'Lifted local frame encoding/decoding only; no reachability, PAC, runtime allocator, global-state, or payload semantics proof.'}
(Path(__file__).resolve().parent/'triage_evidence/dispatch_algebra.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
