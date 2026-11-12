# CoreFP1201 protected record, nested admission and cursor compensation

The request1201 parent's stack helper at0x981c38 selects original child0x981104. The child adds0xe0 to the scratch cursor after the helper subtracts0xe0. Sixteen complete private rejection cases return through original code, store internal record status0x45e2a202 and cause the helper to write a zero stack adjustment. The source-staged record instead reaches call0x981754 ->0x17bbb8 before returning; its caller output cell still contains the original seed. That unchanged seed is not a computed adjustment.

This increment recovers the80-byte parent record, two admission predicates, a selected one-limb initializer for65537 and the exact unresolved call. No candidate input bytes at owner+0x880 are read or written in these prefixes. Full successful helper return, production of the128-byte input, complete request1200-to1201 stack continuity and native daemon/kext/deeper interaction remain unknown. The full investigation remains active.

## Reference and evidence

Addresses use reference CoreFP arm64e preferred base0,SHA-256 `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`, universal SHA-256 `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`. Original parent/helper bytes and bank bytes were already frozen and are reused. Two missing bodies are read from IDA without edits and equal IDA's original bytes:

| Body | Compiler-bounded range | Size | SHA-256 |
| --- | --- | --- | --- |
| Nested child |0x981104..0x981c38 |2868 B | `ca3b47be5250abb4fecd61d0b5a2c571721d23525d868b377fb155746cff8e3f` |
| Selected initializer |0x181b00..0x181cf4 |500 B | `338f96d28ab564007b357a65e1899f5fef8dfe773376c6d67f568c861c0a220a` |

The retained compiler function-start list establishes both extents. IDA's initial function at0x981104 ended at0x981368, before its indirect continuations; that612-byte range would omit most of the routine. The audit uses the2868-byte compiler interval rather than silently treating the IDA function as complete. The changed installed CoreFP file is not used as the reference.

Artifacts: [recovery](triage_evidence/recover_fpsd1201_record.py), [checks and complete private states](triage_evidence/fpsd1201_record_checks.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_record.py), [audit receipt](triage_evidence/fpsd1201_record_audit.json.zst), [fresh read-only IDA bytes](triage_evidence/fpsd1201_record_ida_readback.json.zst), [publication verifier](triage_evidence/verify_fpsd1201_record_publication.py). The [preceding caller report](fpsd1201_caller_report.md) establishes the candidate input/destination loads and identifies the stack-epoch gap; the [serializer/parser report](fpsd1201_client_report.md) establishes request1201's emission ABI. No target, framework, native IPC, allocator or synchronization operation executes here.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PR1 | The pinned source snapshot and retained compiler starts describe the analyzed code. Every offset and local semantic claim depends on identity. | Fresh child/initializer bytes equal IDA original bytes; parent/helper match frozen evidence. A hash mismatch or different function-start list invalidates the mapping. Effective native image selection remains unknown. |
| PR2 | Selected original rebases/banks and the declared stack-guard binding define the private mapping. Constant callee selection and branch replay depend on this mapping. | Eight exhaustive256-input bank identities,392 profile/pointer associations and every selected PAC target/modifier are independently checked. Native loader fixups and hardware authentication are not exercised. |
| PR3 | Constructor entry W22=0x7bd0 and eight-byte-aligned record R describe the selected local route. Record decoding and gate predicates depend on these values. | Original construction gives loop state W20=0x55e1 and decoded control0x9265. An all-u32 pointer proof holds under alignment; pointer1 is an explicit counterexample without that premise. Whole-parent reaching definitions remain unjoined. |
| PR4 | Private context/global referents, readable extents and distinct stack/owner regions supply declared diagnostic backing. Continued prefixes depend on this environment. | Four seeds include zero,one,all-ones and a mixed64-bit value; four global-state sets are explicit. Context+0x294 receives a declared raw metadata word,not a source-produced context. Native contents, ownership, concurrency and allocation bounds remain unknown. |
| PR5 | Null-field and comparison-word changes are diagnostic input controls. Their rejection/initializer results are conditional. | Every control patch retains before/after bytes separately from original stores. The as-staged case has no record patch. No protected return, output or successful cryptographic result is supplied. |
| PR6 | PAC and authenticated returns follow decoded reference targets in the private executor. Nested continuation depends on this model. |184 modeled PAC operations retain full CPU frames; original branch cells, IA key, address diversity0 and discriminators agree. Native PAC, scheduling and exceptions are not inferred. |
| PR7 | Stopping before an unretained callee bounds the evidence. Frontier definedness and lack of candidate-buffer access depend on this boundary. | Call0x981754 is not executed; no final status or computed adjustment is inferred from retained seed/A5 bytes. Complete rejection paths and stopped paths are reported separately. |
| PR8 | Record status, count and comparison words retain source-local meanings until external consumers are joined. Architectural conclusions depend on this distinction. | Exact store locations, pointer roles, widths and prior serializer ABI are cross-checked.0x45e2a202 is an internal record word,not an established Mach return code. Native rights, endpoint identity and daemon/kext/deeper effects remain unknown. |

## Source-staged record [PR1,PR3-PR5,PR8]

The original constructor fragment0x8f3448..0x8f34f8 writes the record at `R=parentFP-0xb8`. It stages the address subsequently passed as X0 to helper0x981c38. Entry X12 is the declared context C; nominal stack cells supply candidate input P+0x880 and a pointer to the seed. The full parent that produces C and P is not replayed.

Let p=low32(R). All mask arithmetic below is modulo2^32:

```text
Mparent = ((((2*(p AND 0x55860eb0) - p + 0x2a79f14c)
             XOR 0x84f565d4) * 0x9e8a2055)) mod 2^32
Mchild  = ((NOT(p XOR 0x4014fca6) XOR 0x116797c1)
             * 0x9e8a2055) mod 2^32
```

The masks agree for every p divisible by8. This is a local record codec; it is not cryptographic authentication. The independent unaligned pointer1 counterexample demonstrates why the alignment premise is retained.

| Record offset | Width | Original construction | Child-local use |
| --- | --- | --- | --- |
|+0x00 |64 bits |0 | Loaded into X28; one input to first nonnull OR test |
|+0x08 |32 bits | Mparent XOR0x5a617ac0 | XOR Mchild yields comparison word0x5a617ac0 |
|+0x10 |64 bits | parentSP+0x5c4; that cell is set to128 | Output/count pointer X13; second admission predicate |
|+0x18 |64 bits | C+0x290 | Descriptor pointer X24; its+4 word is read before first admission branch |
|+0x20 |64 bits | MEM64[parentSP+0x1b8],declared P+0x880 | Input referent X16; second admission predicate |
|+0x28 |64 bits | C+0x3a0 | Auxiliary pointer; NULL selects the observed initializer |
|+0x30 |32 bits | No store in this constructor fragment | Internal status written on completed rejection |
|+0x38 |64 bits | C | Loaded into X26; other input to first nonnull OR test |
|+0x40 |64 bits |0 | Alternate pointer; ORed with the+0x20 input |
|+0x48 |32 bits | Mparent +0x9265 | Subtract Mchild yields selected control0x9265 |

The parent fragment also copies the declared seed through the pointer at nominal SP+0x398 into SP+0x978, the helper's X1 argument. It does not initialize every byte of the80-byte record. Retained A5 padding/status values are diagnostic private backing,not native initializedness observations.

The descriptor dereference at0x981264 precedes the first branch: X24 comes from record+0x18,then W11 is read from X24+4. The first admission predicate therefore does not constitute validation of every pointer before use. The null-context control clears record+0x38 while leaving the independently staged descriptor pointer readable; it is not a native NULL-context fault test.

## Helper-to-child selection and cursor sequence [PR1,PR2,PR4,PR6]

The helper's retained bank identities select its two mutable state cells, scratch metadata cell and nested child:

| Role | Original selected pointer / calculation | Result |
| --- | --- | --- |
| Helper state1 |0x1d0ada0 |0x1d356f0 |
| Helper state2 |0x1d120a8 |0x1d37f68 |
| Seed-derived metadata |0x1d0b550 target minus4 |0x1d435c0 |
| Child table base |0x1d108e8 target minus4 |0x1c81940 |
| Nested child | `0x1c81940+8*(0x1079d+0x94)=0x1d05ac8` |0x981104,IA,discriminator0x3f61,address diversity0 |

The original word at0x1d05ac8 is `0x80083f6100981104`. Helper call0x981e44 uses `BLRAA X8,X17` with modifier0x3f61 and X1 equal to a helper-local scratch address.

```text
parent fragment: output cell <- seed
  -> helper: save seed from *X1
       temp = helper-local stack cursor
       *temp <- seed - 0xe0                         # 0x981da8
       child0x981104(record,temp)
         *temp <- *temp + 0xe0                      # 0x981214
         [admission and further processing]
       if child returns:
         output cell <- ((low32(*temp)-low32(seed)) AND 0xffff) << 4
```

Subtraction and addition cancel for every64-bit seed,including wraparound. All48 child-entry/post-increment checkpoints agree with that formula. The child updates the scratch cursor before validating the record. The helper's internal stack reservation is controlled by the high nibble of `seed*0x2ecd+1`; its source size expression yields16..256 B in multiples of16. This internal reservation is distinct from the caller-visible adjustment written by the helper suffix.

Cancellation at the prefix does not prove the cursor remains unchanged through later callees. On the16 complete rejections, original source returns without changing it further, the helper writes zero at0x981e54 and restores its entry SP. On the eight stopped paths, that suffix has not executed and the parent output cell retains its seed. In particular, seed0 leaves a zero-looking cell without any nested output store; it is not evidence of a computed zero adjustment.

## Two selected admission predicates [PR1-PR6,PR8]

With decoded control0x9265, the first original branch continues to0x981368 exactly when both conditions hold:

```text
(MEM64[R+0x00] OR MEM64[R+0x38]) != 0
decoded_comparison_word != 0x5a617a40
```

The source-staged comparison word is0x5a617ac0. XORing its encoded representation by0x80 creates the comparison-equal diagnostic control,which rejects. A semantic name such as operation/version/authentication value is not assigned to this word.

The first branch index is0x9266 for continuation and0x9265 for rejection. Under that continuation,the second original predicate selects0x9813dc exactly when:

```text
MEM64[R+0x10] != 0
(MEM64[R+0x20] OR MEM64[R+0x40]) != 0
```

Its table index is0x8c0d for continuation and0x8c1c for rejection. All pointer tests above are64-bit; the comparison word and encoded control arithmetic are32-bit. Four local retained SMT obligations and four independent obligations check the codec,cursor cancellation and both predicate roles. The first selected-state predicate does not establish validity of arbitrary record controls or an external authorization policy.

| Private record condition | Cases | Original outcome |
| --- | --- | --- |
| As staged |4 | Stops before call0x981754 ->0x17bbb8 |
| Context field+0x38 cleared |4 | Complete rejection,record+0x30=0x45e2a202,helper output0 |
| Count/output pointer+0x10 cleared |4 | Same complete rejection/output |
| Input pointer+0x20 cleared; alternate+0x40 already0 |4 | Same complete rejection/output |
| Decoded comparison changed to0x5a617a40 |4 | Same complete rejection/output |
| Auxiliary pointer+0x28 cleared |4 | Executes original selected initializer,then stops at the same unresolved call |

The status is stored at0x981bf8. It is not returned as an established Mach protocol status in this increment. The caller's later interpretation and any error propagation into request1201 remain open.

## Selected initializer and unresolved call [PR1,PR4-PR8]

The auxiliary-NULL route calls0x181b00 at0x98151c using original pointer0x1d039d8,IA discriminator0x58b1. Four cases complete this initializer through its original RET. The source input word0x0c9700c5 plus0xf369ff3c modulo2^32 yields65537 (`0x10001`). The selected representation has one32-bit limb; limb count1 must be distinguished from the scalar value65537.

After return,the16-byte descriptor contains `0x4b0cf05100000001` and a pointer to the encoded limb. The observed limb is `0x1ac60ef3`,matching:

```text
encoded_limb = (65537 - (0x358e1de4 AND (65537 << 1))
                     + 0x1ac70ef2) mod 2^32
```

These are exact selected source/representation facts. A full numeric API,cryptographic operation or successful processing result is not inferred from the constant65537.

Both continuing input classes stop before0x981754,which selects0x17bbb8 through original slot0x1d03900,IA discriminator0xc2d9,address diversity0. The capture retains the full CPU and80 bytes at X0 for that next record. Its nested pointer at+8 refers to C; +0x10 points to a stack descriptor. The next record's complete grammar,callee effects and eventual returned status/cursor remain unknown.

Every profile has zero source reads and zero source writes overlapping candidate input range P+0x880..P+0x8ff. The raw pointer itself is loaded from the parent record and tested. Thus this prefix does not establish defined input bytes,buffer production or a transformation from request1200's adjacent128-byte output.

## Validation and continuation

The independent auditor reconstructs all private entry bytes and diagnostic patches without importing the new producer. It verifies24 profiles,10296 original instruction visits,2020 reads,1300 writes,184 PAC models,332 complete CPU frames,48 cursor checkpoints and3637248 B of final mutable RAM. It checks54 selected exact source instructions,392 profile/pointer associations,eight exhaustive bank identities over2048 inputs,the two compiler-bounded fresh bodies and four complete selected65537 initializations. All checks pass. No whole parent,native target,hardware PAC,successful protected result or matched daemon/kext transaction is claimed.

```text
$PYTHON triage_evidence/recover_fpsd1201_record.py
$PYTHON triage_evidence/audit_fpsd1201_record.py
$PYTHON triage_evidence/verify_fpsd1201_record_publication.py
```

For source bytes B,fixups F,cases C,visits V,PAC sites P,journal entries J,retained RAM R and bank identities K,the implementation costs O(C(B+F+V+PJ+R)+256K) time and O(B+F+C(V+J+P+R)) space. The PJ term accounts for retained-read searches when associating PAC targets with source slots. Solver cost is separate,with30 s query limits. Byte extents and32/64-bit modular arithmetic are explicit; these are implementation bounds,not native performance measurements.

| Impact | Next discriminating evidence |
| --- | --- |
| High | Recover0x17bbb8's record decoder,descriptor effects and return. Determine whether the source-staged path preserves the scratch cursor through completion. |
| High | Recover the actual context C and its+0x290/+0x3a0 referents,including source-produced metadata rather than diagnostic backing. |
| High | Continue the exact P+0x880 buffer producer/consumer and successful helper return before joining request1200's returned name to request1201's destination. |
| High | Resolve the other dynamic SP assignments,competing stores and alias effects across the whole parent; then match native endpoint/right identity and daemon/kext/deeper lineage. |
| Medium | Recover other aligned record controls and initializer scalar/count representations; the current predicates apply to selected control0x9265. |
| Medium | Establish source status initialization/consumption and global-state synchronization across actual caller contexts. |

**QG1** passes: factual technical analysis. **QG2** passes: PR1-PR8 state dependencies and falsification probes. **QG3** passes for the nested-record/cursor increment; the full goal remains incomplete. **QG4** passes: modular widths,byte extents,encoded scalar/count distinction and reproduction agree. **QG5** passes: incomplete IDA bounds,alignment,cursor/output distinction,diagnostic backing and stopped versus returned paths are explicit. **QG6** passes: frozen source,compiler boundaries,fresh IDA,original pointer words,solver and independent replay evidence are distinguished. **QG7** passes: impact-ranked continuation covers the remaining interface and ownership joins.

The [CoreFP1201 byte-import report](fpsd1201_import_report.md) identifies0x17bbb8 as a big-endian byte-to-encoded-limb importer,with selected unsigned length0..256 B and normalized limb counts. Eight nested prefixes import128 bytes from diagnostic context C,leave candidate P+0x880 untouched and stop before0x98189c ->0x14fac64. Sixty-eight independently audited cases and matching reference-file corroboration establish this local ABI; complete protected processing,native port lineage and daemon/kext pairing remain unknown.

The [export/status-flow continuation](fpsd1201_export_report.md) completes the original arithmetic/export child and root wrapper for 16 retained backed/canonicalized controls. It verifies output bytes, separate nominal-width and marker stores, child RETAB 0x981c30, zero cursor emission 0x981e54 and wrapper RETAB 0x981e68. Two short-export controls qualify root success as independent of the unread exporter status. Original native parent continuation and transport remain unestablished.

The [explicit parent handoff](fpsd1201_handoff_report.md) restores these exact completed-helper states and declares missing parent cells/registers before entering 0x8f3564. It verifies the root-marker branch and original payload copy through the first import-call frontier. Two shortened-export controls also reach staging under the root marker. No output result is replaced, no API executes, and native parent reachability remains unknown.
