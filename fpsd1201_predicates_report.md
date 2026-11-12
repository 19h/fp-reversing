# CoreFP1201 initialized workspace, predicate records and control frontiers

Later corroboration: the [cold request1200 failure and fallback report](corefp_request1200_failure_report.md) establishes a different, coherent cold fallback prefix through the same constructor/atomic region to the first entropy API. Original fallback flags0 bypass request1200 and its status checks, so that prefix needs no PC gap. This does not remove the explicit gap from the experiments below or establish successful primary processing; their frame epochs remain distinct.

The original modeled caller prefix supplies the previously missing frame cells: cursor `0x9a0`, owner P=SP+0x9c0 and the address-derived record key. A separate continuation recovers two complete obfuscated predicate leaves and reaches either an atomic instruction or an unresolved global-pointer read. The request1200 call and its return checks are explicitly omitted. This establishes conditional source contracts and improves the workspace geometry; native success, remaining context bytes, actual ports and daemon/kext pairing remain unknown.

The subsequent [token, entropy and seed report](fpsd1201_seed_report.md) resumes the pinned zero-control CASAL frontier through a declared sequential model. Source token restoration precedes entropy and a complete 624-word seed expansion. The saved C+0x6f0 view is used as a 32-byte tuple/time scratch area. Twelve cases retain the request1200 gap and stop before later key mixing; native initialization, complete context-byte generation and pairing remain unknown.

## Primary evidence and assumption register

The [producer](triage_evidence/recover_fpsd1201_predicates.py), [checks](triage_evidence/fpsd1201_predicates_checks.json), [independent auditor](triage_evidence/audit_fpsd1201_predicates.py), [receipt](triage_evidence/fpsd1201_predicates_audit.json) and [publication verifier](triage_evidence/verify_fpsd1201_predicates_publication.py) retain the evidence. Logical JSON links resolve to compressed `.json.zst` files. Existing original file bytes and parent capture are sufficient; no new IDA access or IDB edit is required.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| PR1 | All source addresses identify the pinned original CoreFP arm64e image. | Verify universal/slice hashes, complete compiler-bounded parent and leaf bytes, original fixup decoding and dependency hashes. A changed installed framework is not substituted. |
| PR2 | The refreshed prefix uses the frozen `cached_owned_cleanup` private fixture. Its cache, already-initialized-once, abstract lock, stack-probe and allocator/free models are declared premises. | Refresh 19717 original prefix visits plus six modeled steps and compare the complete returned journal/CPU. Recover the omitted native initializers before interpreting zero global backing or modeled port names as runtime facts. |
| PR3 | A PC-only gap moves from the unexecuted request1200 call at 0x8ea14c to 0x8ea164. All later reachability depends on this gap. | Execute or independently validate the call, outputs and both original return checks. No reply, return status or protected result is supplied here. |
| PR4 | Authenticated IA edges use normalized private targets and bypass PAC. | Compare every reaching table load, original pointer row, diversity and complete pre-branch CPU frame. Native PAC acceptance remains unknown. |
| PR5 | The u32 word at image+0x1d45f6c is a declared control changed to 0, 1, 2 or 0xffffffff. Its native producer/meaning is unknown. | Trace actual writers, initialization and synchronization. The selected zero/nonzero partition is proved; the later continuations are finite source replays. |
| PR6 | Whole-leaf contracts use modular u32/u64 arithmetic and valid record backing. These are local record ABIs. | Lift every original leaf instruction, prove output equivalence, test both mode parities, equality/ordering and wrap extremes at four addresses, and verify every untouched record byte. |
| PR7 | Zero-filled private stack/global backing is a diagnostic premise, not a source-defined initialization or a native object. | Check every source store and complete touched RAM; stop before the first unresolved pointer read and before the atomic instruction. Do not infer the remaining 119 context bytes or matched IPC from their diagnostic values. |

Universal image SHA-256: `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`. Selected slice SHA-256: `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Parent `[0x8e81c8,0x8fcfa0)` is 85464 B, SHA-256 `4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e`.

## Prefix and explicit request boundary [PR1-PR3]

The frozen original-byte prefix starts at the protected caller entry and stops before `BLRAA` at 0x8ea14c. It does not invoke request1200. Its existing fixture declares cached port-name u32 `0x5017`, flag word 10, mode 0, a private successful allocator and private free handling; already-initialized-once, abstract locks and stack-probe behavior come from the frozen engine. It source-copies the previously recovered certificate and performs the recorded private cleanup. None is a native API operation.

The omitted source range is exactly `[0x8ea14c,0x8ea164)`: the call, construction/comparison of `0x10000003`, `B.EQ 0x8f148c`, and `CBNZ W0,0x8f14d4`. Re-entry changes only PC to the later fallthrough join; W0 and all other captured CPU/RAM retain their prefix values. This does not claim that the omitted return checks pass. Four controls then change only the explicitly declared global word.

```text
original entry -- frozen declared API models --> before 0x8ea14c
                                                   |
                         request1200 + status checks omitted
                                                   |
                                       declared PC = 0x8ea164
                                                   |
                                       original context constructor
                                                   |
                                       predicate at 0x274ed0
                                          /                \
                               control == 0              control != 0
                                   |                          |
                         before CASAL 0x8ea868      predicate at 0x1abbe0
                                                              |
                                                  before read 0x8ea3b4
```

The later [pre-helper gate](fpsd1201_workspace_report.md), arithmetic/helper and [request1201 handoff](fpsd1201_handoff_report.md) are not joined to these frontiers. Their earlier independent-fragment boundaries remain in force.

## Initialized private workspace geometry [PR1-PR3,PR7]

At the stopped prefix SP=`0x7a036190`, FP=`0x7a037ff0`, P=`0x7a036b50`, cursor=`0x9a0`, and record R=FP-0xb8=`0x7a037f38`. The original constructor gives C=SP+0x9a0+cursor=SP+0x1340=P+0x980=`0x7a0374d0`. Its selected cursor advance is the previously recovered 1872 B, producing cursor `0x10f0`.

| View | Relative address | Private address | 128-byte half-open interval |
| --- | --- | --- | --- |
| Candidate arithmetic/export destination | P+0x880 = SP+0x1240 | 0x7a0373d0 | [0x7a0373d0,0x7a037450) |
| Separate XOR destination | P+0x900 = SP+0x12c0 | 0x7a037450 | [0x7a037450,0x7a0374d0) |
| Context C | P+0x980 = SP+0x1340 | 0x7a0374d0 | [0x7a0374d0,0x7a037550) |

These three views are adjacent and disjoint in this source-initialized private prefix. This refines the earlier constructor's independently declared owner/cursor geometry; it does not prove native allocation, capacity, no-wrap or a complete same-epoch path to request1201.

The prefix also produces SP+0x308=`0xe7ad7247557d3c20`, exactly the first leaf's full address-derived key for R. It produces low u32 SP+0x294=`0xf00b`; after the zero predicate branch, the original reload at 0x8ea840 selects the atomic block. Treating that cell as zero would produce a different dispatch target and is not evidence for this initialized route.

All four continuations source-write exactly C[0:8]=`00 66 64 70 63 00 00 00` at 0x8ea1f8 and C[8]=`01` at 0x8ea200. No other C[0:128] store occurs before either frontier. The remaining 119 bytes read as zero solely because the frozen private stack backing is zero; their actual producers and native values remain unknown. SP+0x1f0 continues to contain C on these bounded routes. This does not extend that lifetime across the earlier unexecuted gap to the pre-helper gate or across the later selector reuse at 0x8f4cf0.

## Complete address-keyed predicate records [PR1,PR6]

Both leaves are pure, complete compiler-bounded routines. They keep X0 as the record pointer, preserve SP and write one u32 record field. Neither emits a Mach message, obtains a port, calls an import, allocates memory or performs the earlier large-integer arithmetic.

| Leaf | Complete extent | Bytes | SHA-256 |
| --- | --- | --- | --- |
| First predicate | [0x274ed0,0x274f74) | 164 | baa1b848ea34973bfe413958c2e5b6a836dda2d9ae73e83633ed29b2260c3210 |
| Second predicate | [0x1abbe0,0x1abc70) | 144 | 62c3ecd634376a8e8ef96cf09a172bedfbbfe8a03fa047bc72fd4d4380bb9be7 |

Let p be the record address, I(o)=little-endian u32 at p+o, Q(o)=little-endian u64, H the u64 key and h=low32(H). Every u32/u64 operation below wraps at its stated width. NOT is the 64-bit complement.

```text
0x274ed0:
  H = ((p XOR 0x83d2a2b8ac4eec68 XOR 0x4c51ef0102c278f0)
        * 0x9e8a2055) mod 2^64

0x1abbe0:
  H = ((NOT(p XOR 0x43e21bde5aac752d) XOR 0xa8964ff1d5102928)
        * 0x4ecee2ad) mod 2^64
```

| Decoded role | First predicate | Second predicate |
| --- | --- | --- |
| Mode | I(0x18)-h | I(0)-h |
| XOR mask | I(0)+h | I(4)-h |
| True candidate | I(8)-h | I(0x0c) XOR h |
| False candidate | I(0x1c)+h | I(8)+h |
| Left operand A | Q(0x10)-H | Q(0x10)+H |
| Right operand B | Q(0x20)+H | Q(0x18)+H |
| Even-mode test | B == A | Q(0x10) == Q(0x18), equivalently A == B |
| Odd-mode test | unsigned B > A | unsigned A > B |
| Output | u32 at +0x28 | u32 at +0x20 |

Each output is `(test ? true_candidate : false_candidate) XOR mask`. Only mode bit zero selects the relation. The second leaf's equality test uses encoded operands directly because adding the same H is a bijection. Its unsigned greater-than test compares the decoded, modular sums; unsigned ordering is not invariant under modular addition. The retained SAT countermodel demonstrates that replacing it with encoded-word ordering is invalid.

Two independent source lifts cover all 41 and 36 original instructions respectively and prove output equivalence for arbitrary record bytes/address bitvectors. The lifts verify the single store offset/width and unchanged X0. Separately, 256 original-byte executions exercise both leaves, four addresses, modes 0/1/2/0xffffffff, and eight operand pairs including equal, zero, u64 maximum and the signed-boundary neighbors. They compare all 48 backing bytes, exact output, unchanged X0 and SP. These local contracts remain conditional on valid record backing and original instruction semantics.

## Parent use and resolved control edges [PR1-PR6]

The first parent call at 0x8ea7a4 uses table slot 0x1d037b0, IA diversity `0x2d01`, target 0x274ed0. Its staged mode is zero, A=0, B=zero-extended MEM32[image+0x1d45f6c], true=`0xa3efbea0`, false=`0xa3efbe98`, mask=`0xa3ef9f65`. Its output is therefore `0x21c5` for zero and `0x21fd` for every nonzero u32 control. This partition is proved independently of the four finite continuations.

| Source edge / condition | Source index or cell | Original slot | IA diversity | Selected target / boundary |
| --- | --- | --- | --- | --- |
| First predicate call, 0x8ea7a4 | Staged record R | 0x1d037b0 | 0x2d01 | 0x274ed0 |
| 0x8ea830, control zero | index 0x21c5 | 0x1c92768 | 0x8527 | 0x8ea834 |
| 0x8ea830, control nonzero | index 0x21fd | 0x1c92928 | 0x8527 | 0x8ecda4 |
| Zero-route edge 0x8ea860 | Reaching SP+0x294 state | 0x1cf9998 | 0xefc2 | 0x8ea864; stop before 0x8ea868 |
| Nonzero-route call 0x8ed058 | Reused record R | 0x1d03a70 | 0x9eeb | 0x1abbe0 |
| Nonzero-route edge 0x8ed06c | New output at R+0x20 = 0x23b0 | 0x1c936c0 | 0xf640 | 0x8ea250 |

The last edge's raw pointer row and full CPU state are retained in the journals. All authenticated transfers remain private PAC models.

In the three retained nonzero cases, the second predicate's key is `0xd498c818f0d4731a`, mode 1, decoded A=1 and B=`0x13ff`; the test is false. True=`0xc453da4c`, false=`0xc453da3e`, mask=`0xc453f98e`, and output is `0x23b0`. The same R backing is reused. Its earlier R+0x28=`0x21fd` remains stale after this call; the parent consumes the new R+0x20 through `LDURSW` at 0x8ed05c. These meanings must not be transferred between the two record ABIs or to the separate arithmetic-root record.

## Atomic and global-pointer frontiers [PR2-PR5,PR7]

The zero-control case stops before `CASAL W8,W11,[X12]` at 0x8ea868. X12=image+0x1d33108, comparison W8=`0x5d96`, replacement W11=`0xa94ef`. No atomic memory effect, observed old value, contention, acquire/release ordering or native lock ownership is modeled at this boundary.

The three nonzero cases continue through the second predicate, return to the context-byte path and stop before `LDR W13,[X13]` at 0x8ea3b4. The original source computes:

```text
base64   = MEM64[image + 0x1d45f60]              (read 0x8ea398)
offset32 = MEM32[image + 0x1d44440]              (read 0x8ea3a0)
address  = base64 + (offset32 AND 0x316a8270)   (u64 addition)
next     = MEM32[address]                      (0x8ea3b4, not executed)
```

Both reads yield zero in the frozen modeled prefix, hence X13=0 at the stop. The correct remaining question is the initialization/provenance of these globals, including the already-initialized-once premise. This is not a native null-dereference finding and does not establish that request1200 supplies these values. No synthetic replacement pointer or data byte is introduced.

The prefix's cached port is a fixture name. The continuation reaches no imported Mach operation and adds no native incoming/outgoing port identity, right transfer or emission site. The existing [port report](mach_ports_report.md) and [request1201 builder boundary](fpsd1201_handoff_report.md) retain their earlier evidence boundaries.

## Validation and bounded continuation

Fresh prefix replay checks 19717 original visits plus six modeled steps using the frozen model engine. A separate continuation engine checks 41357 original visits, 7913 reads, 2077 writes, 1911 PAC models, 14 complete record/CPU checkpoints and all touched initial/final RAM, 450560 B each. Complete parent and both leaves are compared to the pinned original file. Six retained UNSAT queries and one SAT ordering countermodel pass; the independent auditor adds two complete source-lifted leaf proofs and 256 finite original-byte leaf cases. The receipt and publication verifier pin exact artifact/source hashes. No native target, API, IPC, IDB mutation, omitted call or whole-parent execution is claimed.

| Impact | Bounded continuation | Falsification / remaining boundary |
| --- | --- | --- |
| High | Recover initialization and writers of 0x1d45f60, 0x1d44440 and 0x1d45f6c. | Frozen warm-once and zero backing do not establish actual native readiness or data ownership. |
| High | Recover C[9:128] and the C-derived descriptors from a source-initialized route. | The shared nine-byte prefix and 119 diagnostic zero bytes are not a full admitted representative or protocol identity. |
| High | Discharge request1200, its reply and the skipped status branches before connecting this constructor to later helper/request1201. | Current PC re-entry does not prove a native success path, stable frame epoch or preserved pointer lifetime. |
| Medium | Recover the atomic cell's initialization and actual ordering/lifecycle. | Pre-instruction register values do not prove CASAL success, ownership or concurrent behavior. |
| Medium | Pair native client/daemon port rights, wire bytes and downstream kext consumption. | Local predicate records and source-buffer geometry supply no transport pairing. |
| Low | Reuse the two proven local record contracts when classifying further callers. | Record address, key constants, output offsets and greater-than direction differ and must be checked for each caller. |

Quality gates: **QG1** factual technical analysis requires no normative content. **QG2** PR1-PR7 state premises and falsification probes. **QG3** this increment covers initialized parent state, workspace/data geometry, complete obfuscated local ABIs, authenticated control edges and environmental frontiers. **QG4** B denotes bytes; half-open extents, unsigned widths, modular arithmetic and algorithmic bounds are explicit. **QG5** PC gaps, return checks, record reuse, diagnostic/native state, local contracts and unexecuted atomic/read boundaries remain distinct. **QG6** pinned original bytes, independent continuation replay, complete source lifts, finite leaf cases and exact receipts support claims. **QG7** the continuation table ranks bounded opportunities and limitations. The full investigation remains active.
