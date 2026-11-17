# Staged allocation outcomes, input restoration and first tag-field decode

The [actual protected fallback](userclient_failure_fallback_report.md) now continues through the staged FPTTLV allocation result. NULL resumes the saved caller with raw error `0xce515bb2`, preserves its zero output, decodes all 14 staged bytes back into the retained input and requests release of the staging buffer. Non-NULL initializes a new 16 B container and decodes the first BE32 tag field from staged offsets 0 through 3. This composes the previously separate protected writer and reader at the same modeled buffer epoch. It does not establish native allocation effects, input writability/lifetime, a complete header/body parse or the authenticated outer return.

The existing frozen images supplied the evidence. No live IDA access, IDB mutation, continuous guest extension or native target call was required. F/C/S/I/B retain their preceding roles: SP, private context, workspace, original input and 14 B protected buffer. T is the new typed allocator result. M/A/H/J/Z are the already retired message, attribute, original container, node and record. All offsets below are hexadecimal; byte counts are decimal.

| Evidence | Identity / coverage |
| --- | --- |
| Original collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Checks, decoded SHA-256 | `9ce8b6a8fb97684baa377e2b84807af8d91fdd92b54e3751adc79b4c4d51b54f` |
| Audit, decoded SHA-256 | `a9eabdf76b55c214954776429c8cbcb31f2f5f44b5f365984dffdd0e53013386` |
| Selected source | 19 spans / 467 words; 462 composed words and five captured alternate-retag words |
| Setup custody | Two original words; 30 frame-cell reconstructions / 240 B |
| Original pointer observations | 19 PC/slot observations / 18 distinct slots |
| Bank identity | One complete byte-bank composition / 256 byte-input cases |

The [extractor](triage_evidence/recover_userclient_fallback_parser.py), [auditor](triage_evidence/audit_userclient_fallback_parser.py), [checks](triage_evidence/userclient_fallback_parser_checks.json.zst), [audit](triage_evidence/userclient_fallback_parser_audit.json.zst) and [delivery verifier](triage_evidence/verify_userclient_fallback_parser_delivery.py) preserve and reproduce the source receipts. The audit reconstructs the actual predecessor state; these are not independently seeded parser fixtures.

## Control and data flow

```text
pending IOMallocTypeImpl(site.FPTTLV,16 B) at a642098
  |
  +-- T==0 --> C+228=0; W23=frame saved raw error
  |            -> saved continuation a656c08
  |            -> error classifier a65f358
  |            -> C+600 remains zero; S+de4=raw error
  |            -> C+3c0 remains zero; select restore setup
  |            -> decode B[13] ... B[0] into I[13] ... I[0]
  |            -> IOFreeData(B,14) at a666188 [pending]
  |
  +-- T!=0 --> C+228=T; T+0=T+8=0
               -> cursor=0, N=14: nonempty header fits
               -> retain B at C+3d8
               -> protected BE32 helper reads B[0..3]
               -> S+a18 = BE32(original observed I[0..3]) XOR SUCCESS
               -> remaining header/body parse [pending]
```

Every abbreviated PC in the diagram has prefix `0xfffffe000`. SUCCESS is `0x31ae0066`. The NULL branch writes I; writable I is an additional storage premise, not an inferred native property. The final release request is a new emission site and buffer epoch, despite sharing an imported target with the earlier original-record release.

| Contract | Established source consequence |
| --- | --- |
| FP1 | The qualified typed-allocation return stores T at C+0x228 and reloads W23 from F+0x9ec, whose original setup proves raw error `0xce515bb2`. T==0 selects `0xfffffe000a660ae0`; T!=0 selects `0xfffffe000a6420f8`, modifier `0xcd46`. |
| FP2 | The NULL path resumes C+0x5c8=`0xfffffe000a656c08`, modifier `0x481b`. Its actual error selects `0xfffffe000a65f358`, then `0xfffffe000a656f00`. The caller retains C+0x600=0 and stores raw error at S+0xde4. No reader setup executes. |
| FP3 | Original ADD/STR at `0xfffffe000a63612c..0xfffffe000a636134` establishes F+0x728=C+0x3c0. All 30 retained prefixes reconstruct this 8 B cell from their last original stores. The selected cleanup observes its already cleared pointee, then obtains B through F+0x670=C+0x90. |
| FP4 | The NULL restore setup independently reconstructs count 14 from retained size channels, reloads destination I through F+0x8f8, and assigns the inverse protection keys. Its 14 iterations visit indices 13 through 0 exactly once. Each stored byte equals the symbolic byte originally observed at that I index by the preceding staging copy. |
| FP5 | After the last restore store, `0xfffffe000a666188` requests `_IOFreeData` at `0xfffffe000c4ba84c`, X0=B, X1=14 B, modifier `0x085d`, nominal return `0xfffffe000a66618c`. W19 retains raw error. The native release and its return are not applied. |
| FP6 | Non-NULL T owns a fresh modeled 16 B writable extent separate from currently live extents. STP at `0xfffffe000a642100` clears both 8 B fields. C+0x600 remains zero; no publication of T to that caller output has occurred. |
| FP7 | Cursor zero and N=14 select the nonempty path. The source retains B at C+0x3d8 and cursor zero at F+0xbd8, takes the ten-byte header-fit path and requests the protected field reader through `0xfffffe000a656ef0` to `0xfffffe000a637138`, modifier `0xf930`. Its first byte address is B+0. |
| FP8 | The helper reads indices 0,1,2,3, removes their address-keyed protection, builds BE32 D and encodes it as D XOR SUCCESS. Continuation `0xfffffe000a638db8`, modifier `0xb745`, stores that u32 at S+0xa18 via `0xfffffe000a638dc4`. The remaining header fields and body are outside this composition. |

## Byte custody and error interpretation

The parent source writes each protected byte as `stored_B[j] = observed_I[j] XOR mask8(B+j)`. Both new consumers use that same B epoch and address-keyed mask:

```text
mask8(a) = low8(((ROR64(a AND ~7,8) + 02e859d27e491464)
                XOR 4dae26df20976138) >> ((a AND 7)*8))
decoded(j) = stored_B[j] XOR mask8(B+j) = observed_I[j]
D = (observed_I[0]<<24) OR (observed_I[1]<<16)
    OR (observed_I[2]<<8) OR observed_I[3]
```

Addition wraps modulo 2^64; field assembly is u32. No concrete input contents are supplied. D remains arbitrary in this model. S+0xa18 is the encoded tag channel identified by the [metadata report](userclient_record_metadata_report.md), rather than the payload length. The proof establishes the transformation for every four observed bytes without equating D to a prior abstract record tag or claiming a successful nonempty parse or matching native wire record.

B may reuse retired physical storage under the preceding buffer-epoch premises. New protected reads explicitly refer to the surviving B allocation and its source-written bytes, rather than assuming that retired objects preserve their contents. New T is separate from B, I, F/C/S, live holder/table/payload extents and image segments; it is not required to be separate from already retired objects. Native allocator reuse is not observed. Ordinary typed-allocation return preserves surviving caller storage and callee-saved registers/SP while X0..X18/X30 are forgotten and X0 receives the abstract result.

The selected normal pointer branches are premises at all 14 restoration reads and all four header reads. Five alternate MOVK words are captured and excluded from composed execution. Their native retagged-address equivalence remains unknown. The source restoration writes no terminator and does not write index 14. Bytes outside I[0..13] receive no restore stores.

The NULL path's W23/F+0x9ec/S+0xde4 values belong to the same selected raw-error domain. This is not the externally returned error value: the final compiler guard, native callees, saved-frame restoration and RETAB remain unbridged. The prior [qualified return arithmetic](userclient_failure_fallback_report.md) retains its narrower scope.

## Validation

The independent audit proves 470 new source queries across ten semantic contracts in two modes, ten source-domain queries, ten retired/image ownership queries, five image separation lemmas and one original setup query. It re-solves 346 retained parser-request proofs. All counterexample partitions are UNSAT with satisfiable premises. Coverage is 462 newly composed words; the five alternate-retag words remain captured and unexecuted.

Three copied-source mutations produce SAT violations and reject the changed behavior:

| Mutated PC | Rejected change |
| --- | --- |
| `0xfffffe000a6420e4` | Remove the saved-error reload |
| `0xfffffe000a6660f0` | Remove the restore-byte inverse XOR |
| `0xfffffe000a637174` | Remove the first tag-byte inverse XOR |

Each NULL-mode trace restores indices 13 through 0; each non-NULL-mode trace reads tag indices 0 through 3. No concrete input contents or native target calls are supplied.

Each contract checks satisfiable premises, proves the selected N=14/L=4 domain before normalization, and includes every newly lifted address/transfer obligation. Separate retired/image ownership certificates and five unsigned image-range separation lemmas cover new static reads. A fresh verifier rebuilds the extractor and audit, compares canonical queries and checks exact manifest/file custody. Source mutation controls operate on copied bytes, without changing the original images.

No new Mach port, right disposition or Mach-message emitter is established. The new external request is a local kernel allocator interface. The selected source still does not identify the native daemon transaction, task or kernel object paired with I/B/T. See the separate [Mach-port inventory](mach_ports_report.md) and [interface ABI report](interface_abi_report.md).

Restoration takes O(N) time and O(1) auxiliary algorithm state; N=14 here. The first BE32 decode takes O(1) time/space and reads four bytes. The new container request is 16 B. Evidence construction is O(Bin+Iwords+256R+C*W+query-DAG size), with Bin inspected image/receipt bytes, Iwords captured words, R bank identities, C predecessor records and W scanned stores per record. SMT search is separate, bounded at 60 s per new query and 120 s per retained query. No whole-parser complexity or termination bound is established.

## Assumption register

| Assumption | Dependent results / stress test or falsification probe |
| --- | --- |
| FP-A1: Pinned source and predecessor identities | FP1-FP8. Rehash both images, original words/pointers/bank and dependencies; rebuild the full predecessor and this audit. |
| FP-A2: Same frame, caller and buffer epochs | FP1-FP8. Reconstruct F+0x728 in all 30 prefixes; inspect intervening alias writers, callback replacement and B lifetime before native generalization. |
| FP-A3: Selected prior NULL message parse, 14 B protected fallback and both retained modes | FP1-FP8. Re-solve the parent parser-request proofs and the source-entailed N/L certificates. Other sizes, objects and errors require separate compositions. |
| FP-A4: Ordinary typed-allocation return preserves callee-saved registers/SP and surviving storage | FP1-FP8. Check the exact imported target, descriptor, modifier and link, forget volatile registers, and inspect native allocator admission/effects independently. |
| FP-A5: Live readable B retains the preceding protected bytes | FP4, FP7-FP8. Prove every byte address against the original source-written B epoch; reject inverse-XOR mutations. Establish native survival and alias writers separately. |
| FP-A6: I is writable, stable and separate from B and other live extents | FP4-FP5. Check exactly 14 destination addresses/values and no extra store. Investigate native I ownership/protection; the source's retained pointer alone does not establish writability. |
| FP-A7: Non-NULL T is a writable nonwrapping 16 B allocation separate from live extents | FP6-FP8. Check both initialization stores and all live-extent separations; inspect native descriptor admission and allocation identity independently. |
| FP-A8: Normal pointer branches, source lift and complete counterexample partitions | FP1-FP8. Check branch guards, all captured words and the complete byte-bank identity; re-solve retained proofs and require source-mutation rejection. Do not infer native retagging/PAC or a complete parse. |

## Bounded continuation

| Impact | Specific next interface / falsification target |
| --- | --- |
| High | Follow the tag-store continuation through remaining header fields, body-fit checks and record construction; connect the newly decoded tag to prior abstract metadata only with source byte custody. |
| High | Follow the restore buffer-release return into context/workspace retirement and bridge the compiler guard/frame/RETAB to the caller. |
| High | Establish native input writability and B/T epochs across allocation failure, restore and release, including address reuse and alias writers. |
| High | Correlate the actual original input with daemon message fields and a matched transport transaction. |
| Medium | Extend the restoration proof to all admitted extents and error outcomes; this composition uses the selected 14 B predecessor. |
| Low | Name an external error only after the final caller's decoding and propagation are proved. |

## Quality gates

- **QG1**: Pass. Factual source/interface analysis requires no normative judgment.
- **QG2**: Pass. FP-A1 through FP-A8 give dependencies and falsification probes.
- **QG3**: Pass. Both staged-allocation outcomes, restore release and first field decode are covered; the full investigation remains active.
- **QG4**: Pass. Byte extents, widths, masks, BE assembly, index ranges and complexity are explicit.
- **QG5**: Pass. Native effects, buffer epochs, observed bytes, tag identity limits and whole-return limits remain distinct.
- **QG6**: Pass. Original words, pointers, stores, bank identity and rebuilt solver/mutation receipts supply primary provenance.
- **QG7**: Pass. Continuations address remaining parsing, cleanup/return, native lifetimes/writability, transport and wider domains.

## Subsequent actual fallback metadata composition

The [actual fallback-metadata report](userclient_fallback_metadata_report.md) advances the non-NULL tag-store cut through the remaining six header bytes, exact body bounds and the selected type0x6685 metadata path. Zero tag publishes the initialized empty container to the saved caller; nonzero tag enters record construction. It certifies both actual predecessor modes and source-written byte custody. This report's NULL restoration boundary retains its earlier scope.
