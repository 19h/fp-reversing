# Original-container retirement and protected-staging fallback

The actual second-parser allocation-NULL failure does not immediately finish the outer operation. After message/attribute retirement from the [preceding report](userclient_message_failure_report.md), the selected source requests retirement of the original protected record, its node and its container, then requests another buffer of the original outer extent. A non-NULL result receives a protected copy of the original input and enters the staged FPTTLV parser. A NULL result instead requests retirement of the private context and release of the aligned workspace. Native callee effects, complete fallback parsing and the final authenticated return remain unknown.

This is a source-state composition under explicit ordinary-return and storage premises. It joins the preceding actual failure frontier to the earlier [conditional staging contracts](userclient_container_staging_report.md). Existing reference data sufficed; no live IDA access, IDB change, continuous guest extension or native target call is added. F is the retained SP; C the 4096 B private context; S the 16384 B workspace; H/J/Z the original 16 B container, 32 B node and 14 B protected record; I the retained original input; B the new fallback buffer. M/A denote the preceding message/attribute. The selected predecessor has body length 4 B and outer extent N=14 B. Mode0/nonzero denote the two previously established attribute profiles.

| Evidence | Identity / coverage |
| --- | --- |
| Original collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Checks, decoded SHA-256 | `5df0f69a8c378790121a13ddb8f30576e1cb079ab60a08f8436e3db6cfee11b1` |
| Audit, decoded SHA-256 | `fb5f2768dade65ef0a761e8dcc1522b9e2dde0b56350d49c769a3866b72c882c` |
| Selected source | 21 spans / 504 instruction words |
| Additional source | 68 words across two setup proofs and one qualified return-decoding cut |
| Original pointers | 28 PC/slot observations, 25 distinct slots |
| Bank custody | 11 complete byte-bank identities / 2816 byte-input cases |
| Prefix custody | 11 cells / 84 B per predecessor; 30 predecessors: 330 cells / 2520 B |

The [extractor](triage_evidence/recover_userclient_failure_fallback.py), [auditor](triage_evidence/audit_userclient_failure_fallback.py), [checks](triage_evidence/userclient_failure_fallback_checks.json.zst), [audit](triage_evidence/userclient_failure_fallback_audit.json.zst) and [publication verifier](triage_evidence/verify_userclient_failure_fallback_delivery.py) preserve source provenance and reproduce the receipts. Decoded hashes above differ from compressed Git-blob hashes.

## Composed control flow

```text
actual second-parser allocation NULL; message/attribute unwind completed
  |
  v
original H -> J -> Z: one node, no successor, 14 B protected record
  |
  +-> IOFreeData(Z,14) -> IOFreeTypeImpl(node descriptor,J)
  |                      -> IOFreeTypeImpl(container descriptor,H)
  |                         clear C+418
  v
saved raw error ce515bb2 passes both local status tests
  |
  v
IOMallocData(N=14) -> B; retain B in C+90
  |
  +-- B==0 --> typed context retirement(C,4096 B)
  |            -> IOFreeAligned(S,16384)
  |            -> compiler-cookie/return epilogue remains pending
  |
  +-- B!=0 --> read I[13] ... I[0], write protected B[13] ... B[0]
               -> C+358=B; C+600=0; C+3c0=0; S+be4=SUCCESS
               -> staged parser: input B, encoded N, output &C+600
               -> new 16 B site.FPTTLV allocation request
```

Offsets in the diagram are hexadecimal; byte counts are decimal. Ordinary retirement/allocator returns separate the relevant source intervals. The staged parser is a new invocation with a different input/output epoch from the message parser that failed. Matching type-site names do not identify the underlying runtime objects.

| Contract | Exact source consequence |
| --- | --- |
| FF1 | The pending bridge at `0xfffffe000a66229c` receives X19=C+0x418. The shared destructor visits H's head J, retains J's zero successor and requests retirement of Z with the node's 14 B extent. |
| FF2 | After Z's qualified return, the source clears J+0x18, requests typed retirement of J, then selects container retirement because the retained successor is zero. No next-node load follows J's retirement. |
| FF3 | After H's qualified return, STR `0xfffffe000a6605e0` clears C+0x418. The saved callback resumes at `0xfffffe000a641c60`. Raw status from S+0x1c is neither SUCCESS=`0x31ae0066` nor the separately tested `0xce515bc4`, so both direct branches fall through. |
| FF4 | `0xfffffe000a641cf8` requests `_IOMallocData` with X0=zero_extend64(N), exactly 14 B here. F+0x4d8 reconstructs N; F+0x4d0 carries the other encoded length saved to S+0xe10. These are length channels, not pointer values. |
| FF5 | The return stores B through F+0x670=C+0x90, reloads I through F+0x8f8 and reloads W26 from F+0x9ec. NULL selects `0xfffffe000a6661bc`; non-NULL selects `0xfffffe000a641d54`, modifier `0x3ad3`. |
| FF6 | On NULL, the selected path sets W23=SUCCESS, requests typed retirement of C, then requests `_IOFreeAligned(S,16384)`. At that final request W26 remains the setup's `0xce515bb2`. The retired C extent receives no subsequent source dereference. |
| FF7 | On non-NULL, the selected 14 iterations read indices 13 through 0 exactly once and write each protected byte to B at the same index. The live input and new output are separate admitted extents; B may reuse a retired object's address. No terminator is added. |
| FF8 | The post-copy path retains B in C+0x358, clears C+0x600/C+0x3c0 and writes SUCCESS to S+0xbe4. Entry `0xfffffe000a641fb4` retains B at C+0x618, N XOR SUCCESS at S+0xc8c, output address C+0x600 at C+0x188 and continuation `0xfffffe000a656c08` at C+0x5c8. Its cursor F+0xa80 is zero before the new typed allocation request. |

## Deeper API requests

Every address in this table is in the pinned source. Size is an argument for data/aligned releases and a descriptor field for typed requests. A descriptor match establishes source compatibility, not allocator ownership or admission.

| Emission PC | Target | Arguments / descriptor | Modifier | Nominal return PC |
| --- | --- | --- | --- | --- |
| `0xfffffe000a6607e8` | `_IOFreeData`, `0xfffffe000c4ba84c` | X0=Z; X1=14 B | `0x085d` | `0xfffffe000a6607ec` |
| `0xfffffe000a660708` | `_IOFreeTypeImpl`, `0xfffffe000c4ba368` | X0=`0xfffffe000847be20`, `site.FPTTLVNode`, signature `1121`, flags `0x64`, 32 B; X1=J | `0x4d6a` | `0xfffffe000a66070c` |
| `0xfffffe000a6605c4` | `_IOFreeTypeImpl` | X0=`0xfffffe000847bde0`, `site.FPTTLV`, signature `11`, flags `0xe4`, 16 B; X1=H | `0x4d6a` | `0xfffffe000a6605c8` |
| `0xfffffe000a641cf8` | `_IOMallocData`, `0xfffffe000c4ba60c` | X0=14 B | `0xca0c` | `0xfffffe000a641cfc` |
| `0xfffffe000a666260` | `_IOFreeTypeImpl` | X0=`0xfffffe000847ba60`, `site.AllocType`, flags `0xe4`, 4096 B; X1=C | `0x4d6a` | `0xfffffe000a666264` |
| `0xfffffe000a6662b0` | `_IOFreeAligned`, `0xfffffe000c4b9a24` | X0=S; W1=16384 B | `0x84ff` | `0xfffffe000a6662b4` |
| `0xfffffe000a642098` | `_IOMallocTypeImpl`, `0xfffffe000c4ba154` | X0=`0xfffffe000847b620`, `site.FPTTLV`, signature `11`, flags `0xe4`, 16 B | `0xd0c8` | `0xfffffe000a64209c` |

The context retirement descriptor's complete normalized 64 B match allocation descriptor `0xfffffe000847bea0`. The original container retirement descriptor similarly matches the pending staged-parser allocation descriptor, with original pointer encodings retained independently. Those are descriptor comparisons across distinct invocations.

After a modeled retirement, every later source load/store excludes that retired extent, except the new allocation's admitted writes in its new epoch. The model explicitly permits B to overlap retired M/A/H/J/Z storage. It preserves neither retired object contents nor every alias. The NULL path stops at the aligned-workspace release request; its native return and the compiler epilogue are not composed.

## Size, bytes and status custody

Two original setup spans independently establish, for every u32 N:

```text
F+4d8 = zero_extend64(N) + e33fe5fefaffb7f5  (modulo 2^64)
F+4d0 = zero_extend64(N) + 621745fcc03f95d4  (modulo 2^64)
```

All eleven reconstructed cells match their last overlapping original stores in all 30 predecessor records. The preexisting abstract saved-status cell F+0x9ec is refined to `0xce515bb2` using the original setup at `0xfffffe000a636678..0xfffffe000a636694`, independently lifted here. Other previously missing private values remain symbolic. The retained original extent satisfies N=L+10=4+10=14 B in this actual path; earlier all-size staging proofs are rechecked separately.

The copied bytes are arbitrary symbolic observations of the admitted stable original input, not newly supplied concrete target bytes. For each j in 0..13 under the normal pointer branch:

```text
a = B+j
mask8(a) = low8(((ROR64(a AND ~7,8) + 02e859d27e491464)
                XOR 4dae26df20976138) >> ((a AND 7)*8))
stored_byte(B+j) = input_byte(I+j) XOR mask8(B+j)
```

The addition is modulo 2^64. Alternate MOVK at `0xfffffe000a641e24` has the separately rechecked upper16 replacement contract; retagged native storage equivalence is unknown. The actual composition admits the normal branch at every iteration.

The final return-decoding instruction, `EOR W0,W26,W23` at `0xfffffe000a6662cc`, has a separate qualified cut. Given the NULL path's retained W26=`0xce515bb2` and W23=SUCCESS, it produces u32 `0xffff5bd4`=4294925268. Signed32 interpretation subtracts 2^32: 4294925268-4294967296=-42028. This establishes the arithmetic at that instruction. The intervening compiler guard at `0xfffffe000a6662b4..0xfffffe000a6662cc`, saved-frame restoration and RETAB are unbridged; no native return value or external error-name mapping is inferred.

## Verification and scope

The independent audit proves 1034 new source queries across 14 semantic contracts in both modes, plus 3 setup/qualified-cut queries, and rechecks 74 prior source queries. It covers 503 newly executed words and the remaining alternate-retag word through its retained proof. All counterexample partitions are UNSAT with satisfiable premises. The fresh delivery verifier rebuilds the extractor, lifts and solves these queries again, and compares canonical query structures and receipts.

Three copied-source mutations are rejected by satisfiable counterexamples:

| Mutated PC | Rejected change |
| --- | --- |
| `0xfffffe000a6605e0` | Remove the owner clear after container retirement |
| `0xfffffe000a641ce8` | Discard the reconstructed allocation size instead of writing X0 |
| `0xfffffe000a641e44` | Remove the protected-byte XOR |

Ten additional SAT checks cover both modes with B reusing each retired M/A/H/J/Z address. These establish nonvacuous new-epoch premises; they do not observe native allocator reuse. No concrete input contents or native target calls are supplied.

Five generic image-range separation lemmas cover static reads; fourteen ownership instantiations discharge their premises for the actual retired objects. Each static read retains its source address and admitted-range checks. Heap reads/stores retain direct retired-extent obligations, except stores admitted in the new buffer epoch. Fourteen source-domain certificates prove N=14 and L=4 before those equalities normalize the counterexamples. This is a reduction within the already selected source path, not a restriction added to obtain passing results.

No new incoming/outgoing Mach port, right disposition or Mach-message emitter is established. These are local kernel API calls and private data/control transfers. I has original-entry pointer custody in the retained model, without a newly established daemon packet field, task identity, external-control guarantee or matched transaction. The [Mach-port inventory](mach_ports_report.md) retains the separate transport evidence.

For the fixed one-node cleanup, selected source work/auxiliary space are O(1), excluding callees. The staging algorithm is O(N) time, requests N B and uses O(1) auxiliary state; this composition executes N=14 iterations. Evidence construction is O(Bin+Iwords+256R+C*W+query-DAG size), where Bin is inspected image/receipt bytes, Iwords captured instructions, R bank identities, C predecessor records and W writes scanned per record. SMT cost is separate: 60 s per new query and 120 s per retained query in fresh contexts. No complete-parser runtime bound is claimed.

## Assumption register

| Assumption | Dependent contracts / stress test or falsification probe |
| --- | --- |
| FF-A1: Pinned images and retained receipt identities | FF1-FF8. Rehash both images, original words/pointers/descriptors/banks and predecessors; rebuild the extractor and independent audit. |
| FF-A2: Same original record, caller and frame epochs | FF1-FF8. Reconstruct the 330 additional cells from last original stores; inspect any intervening writer, object replacement or callback reuse before native generalization. |
| FF-A3: Actual second-parser NULL allocation, one-node original list and selected 14 B outer extent | FF1-FF8. Verify retained NULL status, zero successor, node extent and N=L+10. Other parser outcomes, list lengths or extents require separate compositions. |
| FF-A4: Ordinary retirement/allocator returns preserve callee-saved registers, SP and surviving storage | FF2-FF8. Check exact targets/modifiers/arguments/links, havoc X0..X18/X30 and exclude retired storage. Inspect native callee admission and lifetime independently. |
| FF-A5: Readable stable 14 B input and writable nonwrapping new buffer, separate from live allocations/input | FF7-FF8. Prove all 14 input/store addresses and bytes; test admitted reuse of retired addresses. Establish native input lifetime and object epochs before claiming runtime byte custody. |
| FF-A6: Source normal pointer branch throughout the copy | FF7-FF8. Check the branch guards and independent alternate MOVK contract; native retagged-address equivalence remains unknown. |
| FF-A7: Saved-error refinement and phase-qualified decoding | FF3-FF6. Rebuild the original constant-producing setup and 30 stored observations; distinguish S+0x1c, F+0x9ec, temporary W23=SUCCESS and the separate EOR cut. |
| FF-A8: Source lift, bank identities and complete counterexample partitions | FF1-FF8. Rebuild every captured word and all 2816 byte cases, re-solve retained contracts and reject changed cleanup/size/copy instructions. Bridge the compiler guard/frame/RETAB before a whole-return claim. |

## Bounded continuation

| Impact | Specific next interface / falsification target |
| --- | --- |
| High | Follow the new staged-parser allocation through its two result paths and establish a complete nonempty fallback parse tied to this 14 B buffer epoch. |
| High | Bridge the NULL fallback's pending aligned-release return, compiler guard, saved frame and RETAB to the real outer caller. |
| High | Inspect native retirement/allocation validation and reuse before claiming free effects, descriptor admission or runtime object identity. |
| High | Establish native I lifetime and transaction pairing across the message failure and fallback; the source transformation alone does not supply those joins. |
| Medium | Test other original list lengths, parser errors and outer extents against this failure-to-staging convergence. |
| Low | Map the signed return candidate to an external error domain only after recovering the caller's actual decoding and propagation. |

## Quality gates

- **QG1**: Pass. Factual interface analysis requires no normative judgment.
- **QG2**: Pass. FF-A1 through FF-A8 identify dependencies and falsification probes.
- **QG3**: Pass. Both fallback allocation outcomes and their distinct next interfaces are covered; the full investigation remains active.
- **QG4**: Pass. Widths, modular arithmetic, B extents, exact indices, status interpretation and complexity are explicit.
- **QG5**: Pass. Actual source composition, new allocation epoch, ordinary returns and the qualified EOR cut have distinct scopes.
- **QG6**: Pass. Original source, descriptors, symbols, prefix stores, banks, solver receipts and source mutations supply primary provenance.
- **QG7**: Pass. Continuation covers nonempty fallback parsing, compiler return, deeper admission, native lifetime/transport and wider error/extent cases.


## Staged fallback allocation outcomes

The [fallback-parser report](userclient_fallback_parser_report.md) composes the actual protected buffer through staged-allocation outcomes. NULL restores all 14 source-observed input bytes before a new buffer-release request; non-NULL initializes the new container and decodes its first BE32 tag from protected offsets 0..3. Ordinary-return, surviving-buffer and writable-input premises remain explicit; complete parsing, native effects and authenticated outer return remain unknown.
