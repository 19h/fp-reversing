# CoreFP1201 byte importer and nested descriptor ABI

Routine0x17bbb8 imports an unsigned big-endian byte string into encoded32-bit limbs, stores the normalized limb count and returns an internal result marker. Under selected decoded state0x66dc, its exact unsigned length admission is0..256 B inclusive. The request1201 nested continuation calls it with128 bytes from context C, rather than candidate input P+0x880. Its local success does not establish completion of the protected operation or a request1200-to1201 port handoff.

The eight retained nested prefixes now reach call0x98189c ->0x14fac64. That call is captured before execution. Whole-parent reachability, native context contents, eventual cursor adjustment, successful protected processing and matched daemon/kext/deeper transactions remain unknown. The full investigation remains active.

## Source and reproducible artifacts

Addresses use CoreFP arm64e preferred base0. The matching reference file named `CoreFP` has universal SHA-256 `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`; its selected30797904 B arm64e slice has SHA-256 `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Fresh read-only IDA bytes for0x17bbb8..0x17c090 equal IDA original bytes and the reference file:1240 B,SHA-256 `43ecb5a423f86b154cf35ba2fe2dc900d91ff003ed7d4e708426d03c797cb93c`. The retained compiler function-start list establishes that complete interval.

Both producer and auditor independently parse the reference FAT/Mach-O file and corroborate all1602 compiler starts,all79512 retained original fixup words,5348 B of selected code,3072 B of bank data and the earlier85464 B parent body. This establishes snapshot correspondence. It does not establish which image a native process selects. The changed installed framework is not substituted for the reference.

Artifacts: [producer](triage_evidence/recover_fpsd1201_import.py), [checks and private states](triage_evidence/fpsd1201_import_checks.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_import.py), [audit receipt](triage_evidence/fpsd1201_import_audit.json.zst), [fresh IDA readback](triage_evidence/fpsd1201_import_ida_readback.json.zst), [publication verifier](triage_evidence/verify_fpsd1201_import_publication.py). The [preceding record report](fpsd1201_record_report.md) establishes constructor/helper/child staging and rejection paths; the [caller report](fpsd1201_caller_report.md) retains the unresolved stack epochs and adjacent buffers. These artifacts are primary binary evidence. No native framework,IPC,allocator or synchronization operation executes.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BI1 | The pinned reference image and compiler starts describe the analyzed snapshot. Every address and semantic claim depends on identity. | Fresh IDA bytes,full parent,selected code,banks,starts and original fixup words match the independently parsed file. A mismatch invalidates correspondence; effective native selection remains unknown. |
| BI2 | Decoded state0x66dc selects this importer route. Length and result claims depend on that state. | Original source decodes each fixture and branches through retained original slots. Other decoded states are outside this contract. |
| BI3 | Isolated input,record,descriptor and256 B limb backing are mapped and nonoverlapping. The complete isolated returns depend on these declared fixtures. |60 cases cover empty/NULL,word boundaries,256 B maximum and invalid unsigned lengths. Descriptor capacity64 is a fixture; arbitrary capacity,aliasing,unmapped pointers and faults remain unknown. |
| BI4 | Nested entry context,globals and cursor seeds retain the predecessor's declared diagnostic environment. The continued prefixes depend on that environment. | Eight source-staged/null-auxiliary cases cover four64-bit seeds. Imported A5 bytes come from private context backing,not a recovered native context producer. |
| BI5 | Original pointer decoding and modeled PAC determine private branches. Continuation depends on this model. | Every selected pointer/modifier association and complete PAC CPU frame is independently replayed; all raw fixup words match the reference file. Native PAC,loader execution and concurrency are not exercised. |
| BI6 | Integer semantics are inferred from original byte reads,limb writes and count normalization under the selected state. Naming depends on this evidence. | The independent big-endian integer oracle checks exact descending input addresses,all written limbs,unchanged tails and normalized counts. Full-u32 solver checks cover the length gate and limb codec; they do not prove every payload's complete execution. |
| BI7 | Stopping before0x14fac64 bounds nested evidence. Frontier/output claims depend on that boundary. | The call is not executed; root status and output seed are separately checked. Importer success is not propagated into a fabricated successful protected result. |
| BI8 | Record result words and descriptor fields retain source-local meanings until their consumers are joined. Architectural conclusions depend on that distinction. | Exact field widths,stores and callers are retained. No new Mach port emission,ownership transfer,external return code or daemon/kext endpoint identity is inferred. |

## Import record and length admission [BI1-BI3,BI5,BI8]

Let R be the32 B import record and p=low32(R). Arithmetic on encoded words is modulo2^32:

```text
M = ((NOT(p XOR 0x7232c2dc) XOR 0xfd8e9ed9) * 0x4ecee2ad) mod 2^32
decoded_state = MEM32[R] XOR M
N = (MEM32[R+0x1c] + M - 0x62b6a411) mod 2^32
```

| Offset | Width | Selected ABI role |
| --- | --- | --- |
|+0x00 |32 bits | Encoded state;0x66dc XOR M in these cases |
|+0x08 |64 bits | Source byte pointer |
|+0x10 |64 bits | Destination descriptor pointer |
|+0x18 |32 bits | Internal result marker |
|+0x1c |32 bits | Encoded length;(0x62b6a411+N-M) mod2^32 |

The source computes W8=N-257,executes `CMN W8,#258` at0x17bc74 and takes the HI flag at0x17bc78. Carry-set/nonzero is exactly unsigned N<=256 over every32-bit N. Zero is admitted. This gate is proved independently using33-bit addition and an unsigned overflow predicate; both queries are UNSAT for a counterexample. It is a length gate,not established validation of descriptor capacity or every referent.

| Selected branch | Table slot | Target | PAC modifier |
| --- | --- | --- | --- |
| Admitted;index0x66f7 |0x1cb50f8 |0x17bcf4 | IA0xca94 |
| Rejected;index0x66dc |0x1cb5020 |0x17c06c | IA0xca94 |

The common table base is0x1c81940. Selected invalid lengths257 and0xffffffff return marker0x45e2a205 without source-byte reads or descriptor/payload changes. Empty NULL input with N=0 returns the local success marker without a source-byte dereference; descriptor backing is still supplied.

## Byte order,limb codec and descriptor [BI1-BI3,BI5,BI6,BI8]

Original `LDRB` at0x17bde0 reads source addresses N-1,N-2,...,0. These bytes form the low limb first from a big-endian unsigned input integer. Full-word store0x17be90 and partial-word store0x17bf24 write32-bit words at successive destination addresses. Every ceil(N/4) limb is written,including limbs later excluded by normalization.

```text
value = unsigned_big_endian(source[0:N])
for j in 0 .. ceil(N/4)-1:
    word = (value >> (32*j)) AND 0xffffffff
    MEM32[payload+4*j] = word XOR 0x1ac70ef2
count = ceil(bit_length(value)/32)     # count=0 when value=0
MEM32[descriptor+4] = 0x4b0cf050 + count
MEM32[record+0x18] = 0xba1df9db
```

The source limb expression `w-2*(w AND 0x1ac70ef2)+0x1ac70ef2` equals `w XOR 0x1ac70ef2` for all32-bit w. Independent universal queries prove that identity. The representation also agrees with the preceding65537 initializer:65537 XOR0x1ac70ef2=0x1ac60ef3.

| Descriptor offset | Width | Observed importer effect |
| --- | --- | --- |
|+0x00 |32 bits | Preserved;64 in isolated fixtures. A capacity interpretation is not established. |
|+0x04 |32 bits |0x4b0cf050 + normalized limb count;store0x17c054 |
|+0x08 |64 bits | Preserved payload pointer |

The high-limb scan compares against encoded zero0x1ac70ef2 at0x17c000. A zero-valued byte string produces normalized count0 despite writing ceil(N/4) encoded-zero limbs. Unwritten payload tails remain unchanged in all isolated cases. Local success marker0xba1df9db is stored at0x17c06c,the same instruction used for the selected failure marker. No external OSStatus or Mach result meaning is assigned to either value.

## Nested source selection and next record [BI1,BI4-BI8]

```text
parent construction -> helper0x981c38 -> child0x981104
    [optional65537 initializer0x181b00]
    call0x981754 -> importer0x17bbb8
        source=C,length=128 B
        32 encoded limbs,count=32,local marker=0xba1df9db
    return0x981758
    stop before call0x98189c ->0x14fac64
```

All eight nested cases import C[0..127],which contains declared A5 diagnostic bytes. They produce32 words0xbf62ab57 (`0xa5a5a5a5 XOR 0x1ac70ef2`) and descriptor count word0x4b0cf070. The raw source pointer is C,not the candidate P+0x880 from the enclosing record. No read/write in these prefixes overlaps P+0x880..P+0x8ff.

The new frontier selects0x14fac64 through original slot0x1d05948,IA modifier0x0b1e,address diversity0. Full CPU state and80 argument-record bytes are retained before the call. That next record's complete grammar and callee effects remain unknown. The enclosing root status remains diagnostic0xa5a5a5a5 and the parent output cell retains its original seed. Neither value is an output of a completed protected operation. In particular,the seed0 case does not establish a computed zero cursor adjustment.

This recovers a private numeric representation between existing request1201 source stages. No new incoming/outgoing Mach right is emitted here. The previously established request1201 serializer and daemon failure ABI remain separate evidence until the unresolved parent/context/port lineage is joined.

## Validation and continuation

The independent auditor imports the frozen predecessor's replay machinery,never this increment's producer. It reconstructs isolated fixtures,independently parses reference source and uses a separate big-endian integer oracle. Its68 cases comprise57 length/pattern cases over19 lengths,2 invalid-length cases,1 empty-NULL case and8 nested cases. The three patterns are zero,byte[j]=(37*j+11) mod256,and a leading-zero integer1.

All checks pass:204945 original instruction visits,23954 reads,2815 writes,11335 PAC models,11643 complete CPU frames,4231 input bytes,1075 limb values,68 import outcomes and10305536 B final RAM. Sixteen cursor checkpoints and four selected65537 initializers retain the predecessor contract. Two new retained and two independently reconstructed SMT obligations pass; predecessor source/proof checks also pass. These are finite original-byte executions plus the specifically stated universal identities,not a full algorithm or native execution proof.

```text
$PYTHON triage_evidence/recover_fpsd1201_import.py
$PYTHON triage_evidence/audit_fpsd1201_import.py
$PYTHON triage_evidence/verify_fpsd1201_import_publication.py
```

For reference bytes I,selected code B,fixups F,cases C,visits V,PAC sites P,journal entries J,retained RAM R and bank identities K,the retained implementation costs O(I+C(B+F+V+PJ+R)+256K) time and O(I+B+F+C(V+J+P+R)) space. The importer algorithm itself is O(N) time and O(ceil(N/4)) destination space. Solver cost is separate,with30 s query limits. These are implementation bounds,not native timing measurements.

| Impact | Next discriminating evidence |
| --- | --- |
| High | Recover0x14fac64's80 B argument record,descriptor consumers and complete return; preserve the distinction between numeric import and protected-operation completion. |
| High | Recover source-produced C and its+0x290/+0x3a0 referents; determine the imported128-byte value's provenance rather than interpreting diagnostic A5 bytes. |
| High | Establish P+0x880's producer/consumer,all parent SP epochs and actual destination-right lineage before joining request1200,request1201 and a native daemon/kext transaction. |
| Medium | Establish descriptor+0 semantics,aliasing/capacity preconditions and other decoded record controls from actual callers. |
| Medium | Follow both local result markers to their consumers and distinguish internal failure propagation from external protocol statuses. |

**QG1** passes:factual technical analysis. **QG2** passes:BI1-BI8 state assumptions,dependencies and probes. **QG3** passes for the import/descriptor increment;the full goal remains incomplete. **QG4** passes:byte extents,unsigned modular widths,byte order,count normalization and reproduction agree. **QG5** passes:local versus protected success,diagnostic context,capacity,empty input and stopped nested paths remain explicit. **QG6** passes:fresh IDA,matching reference file,original fixups,independent replay and scoped solver evidence support the claims. **QG7** passes:impact-ranked continuation covers representation,source provenance,port lineage and deeper interfaces.
