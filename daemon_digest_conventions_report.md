# Digest update and finalization calling conventions

Two update interfaces share the same modulo-u32 64-byte threshold but encode their arguments differently. Two finalization interfaces share the first encoded padding operation but use different argument and saved-frame layouts. The retained identity-string paths use the encoded update and inline finalization conventions. Their 32-byte output reservation is distinct from the separate 36-byte cache; neither output nor cache contains source-defined digest bytes at the retained frontier. A conditional return from the other finalizer reaches a 1,028-byte allocation request, whose native owner and purpose remain unknown. The full daemon/kext/deeper-interface investigation remains active.

This extends the [routing/continuation report](daemon_digest_routes_report.md) and [identity preparation report](daemon_identity_cache_report.md). Results concern original source fragments and retained conditional journals. Native caller continuity, completed digest/cache contents and linkage to a Mach/IOKit emission remain unknown.

## Evidence and verification

| Evidence | Verified extent |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Original source | 13 spans; 17 decoded original fixups |
| Current IDB | `fairplayd`, target `6b117c693e3b`; eight read-only byte ranges / 596 bytes, raw identical |
| Source identities | 12 rebuilt proof pairs; 24 original/simplified SMT files, all UNSAT; 181 lifted instructions |
| New isolated A64 cases | 377 persisted and freshly recomputed fragments; 8,326 instruction visits; 516 reads / 972 writes |
| Retained identity audit | 480 successful-conversion cases; 3,357,408 retained visits / 404,448 retained effects inspected |
| Retained branches | 480 encoded-update entries, 288 inline-finalization paths, 192 long-update frontiers |
| Allocation dispatch | All 256 byte-bank inputs resolve the same original malloc binding under the stated roots |

Primary evidence is retained in [source contracts](triage_evidence/daemon_digest_conventions_contracts.json), [proofs](triage_evidence/daemon_digest_conventions_proofs.json), [isolated A64 cases](triage_evidence/daemon_digest_conventions_profiles.json), [independent checks](triage_evidence/daemon_digest_conventions_checks.json) and [IDA bytes](triage_evidence/daemon_digest_conventions_ida_bytes.json). [Preservation](triage_evidence/daemon_digest_conventions_preservation.json) and [delivery gates](triage_evidence/daemon_digest_conventions_quality_gates.json) seal this increment. The retained journals are audited rather than re-executed in this increment; the 377 new fragments are re-executed independently. No target process, native API, Mach/IOKit operation, hardware PAC or IDB mutation executes.

All addresses, offsets, indices and control constants have explicit `0x` prefixes below. Byte extents and counts are decimal. F denotes the applicable outer SP; T=`0x101039EF0`. u32/u64 arithmetic wraps modulo 2^32/2^64. Symbolic memory cells require the separated-owner/frame premises in DC2; universal arithmetic claims do not establish valid native memory for every numeric address or index.

## Update interface pair

| Property | Raw-count interface | Encoded-count interface |
| --- | --- | --- |
| Entry | `0x100AEE3A4` | `0x100A0AAD0` |
| Context C | X4 | X4 |
| Input I | X8 | X21 |
| Count N | W2 | `(W5 - 0x1AD72F12) mod 2^32` |
| Continuation index P | W9 | W20 |
| Saved continuation | F+0x2F48 | F+0x2EA8 |
| Saved context | F+0x2B88 | F+0x2BF8 |
| Saved count word | F+0x2C8C, raw | F+0x31DC, still encoded |
| Saved input | F+0x3490 | F+0x2F50 |
| Saved target expression | `load64(T + 8*signed32(P))` | `load64(T + 8*signed32(P))` |
| Source mode premise | Earlier raw-count caller modes | W19=0x9930 |
| Resulting internal phase | 0x471C | W9=0x471C |
| Return consumer | `0x100BB2278..280`, IA0x7315 | `0x100BD9BA0..BA8`, IA0xE0D4 |

Let H denote the raw interface's W10 or the encoded interface's load32(C+0x44), respectively. Both local threshold contracts reduce to:

```text
S = (N + (H AND 63)) mod 2^32
raw test:      unsigned S < 64
encoded test:  unsigned (S - 64) < 0xFFFFFFC0  <=>  unsigned S >= 64
```

The tests are complements and describe the same threshold. This is an all-u32 arithmetic equivalence, not full-procedure equivalence or a native frame-join proof.

| Encoded-update predicate | Index / original slot | Target / IA diversity |
| --- | --- | --- |
| S < 64 | 0x9930 / `0x101086870` | `0x1009F15D4` / 0x2B92 |
| S >= 64 | 0x995B / `0x1010869C8` | `0x100BB18EC` / 0x2B92 |

The caller at `0x100BE25B8`, conditional on saved mode F+0x273C=0x471C, loads A from F+0x2F08 and C from F+0x30B8. It passes X21=A+0x238, X4=C, W5=0x1AD72F26, W19=0x9930 and W20=0xB5D. Thus its decoded input count is exactly 20 bytes. Entry slot `0x10105ED20` (index0x49C6) targets `0x100A0AAD0`, IA0x5522. The input owner's type and extent beyond the required slice are unknown. Continuation index0xB5D loads slot `0x10103F9D8`, target `0x100BAAF1C`, IA0xE0D4.

The retained identity caller instead supplies index0xB75, slot `0x10103FA98`, target `0x100BAFF6C`. All 480 audited successful-conversion cases enter A0AAD0 through `0x1009154F8`. The saved context/count/input and selected threshold branch match the retained source effects independently. The count is the UTF-8 byte length established by the prior strlen/API model; UTF-16 unit count is not substituted for arbitrary strings.

## Finalization interface pair

| Property | Wrapped finalizer | Inline finalizer |
| --- | --- | --- |
| Entry | `0x100C03B20` | `0x100BB2284` |
| Arguments | X10 points to a cell containing C; X11 points to a cell containing O | X4=C; X10=O |
| Continuation | W9 signed table index | Enclosing path's continuation state |
| Saved continuation | `load64(T+8*signed32(W9))` -> F+0x3590 | Not captured by this checked prefix |
| Saved context / output | F+0x2DF0 / F+0x3418 | F+0x2F40 / F+0x2FE0 |
| First padding block | `0x100AC0FE8` | Within BB2284 prefix |
| First encoded byte | `store8(C+(H&63), 0x18)` | Same |
| Next position | W13=(H&63)+1 | W12=(H&63)+1 |
| Long padding gate | `(H&63)>55` | Same |

Here 0x18 is 0x80 XOR 0x98, consistent with the previously recovered encoded SHA-1 buffer. Agreement on this operation and gate does not establish equality of the full finalizers or a completed digest.

For the wrapped entry under W13=0x471C, O!=0 selects index0xC567 / target `0x100AC0FE8`; O==0 selects index0xC554 / target `0x100B2050C`, both IA0x9D35. The NULL-output handler branches through the captured X9 with IA0x7D32 without executing the padding fragment. Valid context ownership is required for the non-NULL path. Wrapped padding uses indices0x3B/0xBFC2; the latter targets `0x100B35598`. Inline padding uses indices0x18/0xBE37, targets `0x10097FA98`/`0x100CBE9EC`. Both padding dispatches use IA0xD737. Normal wrapped cleanup includes `0x1009F2FBC` loading F+0x3590 and `0x1009F2FC8` reloading saved mode F+0x273C; continuous entry-to-return preservation remains a premise, not a proved complete path.

| Conditional wrapped caller | X10 / X11 | W9 and original continuation |
| --- | --- | --- |
| `0x10094DEC4`, saved mode0x471C | F+0x3388 / F+0x31C8 | 0x9C -> slot `0x10103A3D0` -> `0x100A0E340`, IA0x7D32 |
| `0x100BAAF1C`, saved mode0x471C | F+0x30B8 / F+0x3678 | 0x9B -> slot `0x10103A3C8` -> `0x1009D7C0C`, IA0x7D32 |

Both callers select entry index0xAC2E, slot `0x101090060`, target C03B20, IA0xCB9B. The first caller's output cell contains C+0x64 (100 bytes) under the earlier new-context setup. That setup reserves 128 bytes total. The output capacity and subsequent writes still require downstream evidence; the reservation alone does not establish a completed output.

## Actual retained identity workspace

The short retained identity paths return from the encoded update through BD9BA8 to BAFF6C, reserve output, and then enter BB2284. None of the 480 successful-conversion journals visits C03B20.

| BAFF6C source effect | Retained short-case value / consequence |
| --- | --- |
| C=load64(F+0x3238), saved at F+0x3610 | C=F+0x3C70, 100-byte context |
| Q=load64(F+0x3620) | Q=0x2F0 before reservation |
| O=F+0x39F0+Q, saved at F+0x31A8 | O=F+0x3CE0=C+0x70 (112 bytes) |
| F+0x3620=Q+32 | A separate 32-byte reservation; retained cursor becomes0x310 |
| load64(F+0x2F00) -> F+0x32E8 | Borrowed source value; native role unknown |
| Enter BB2284, save C/O again | 288 retained inline-finalization paths |

There is a 12-byte gap between the 100-byte context and this output reservation. This arrangement differs from the wrapped caller's C+0x64 placement. All 288 reservations are distinct from the separately allocated 36-byte global cache owner. Independent effect inspection finds no source writes into either the 32-byte output region or the 36-byte cache before these retained frontiers. The 192 remaining successful-conversion cases stop during long updates before output reservation. These finite paths retain the prior unknown-frame-read stops; no missing pointer or phase is supplied to continue them.

```text
retained identity:
  UTF-8 bytes -> encoded update A0AAD0
                  | short return: BD9BA8 -> BAFF6C
                  +-> reserve O[32] -> inline finalizer BB2284 -> frame-read frontier
                  `-> long update -> separate frame-read frontier

other conditional source route:
  raw update -> 94DEC4 -> wrapped finalizer C03B20
                               | return index0x9C, if preserved
                               `-> A0E340 -> three-value gate -> malloc(1028)

separate cache[36] -> contents and digest-to-cache join unknown
Mach/IOKit emission from these digest paths -> unknown
```

## Conditional post-finalization sink

At `0x100A0E340`, under W13=0x471C, let O=load64(F+0x31C8), A=load64(F+0x3648), B=load64(F+0x35A8). A and B remain opaque u64 values; nonzero tests do not establish pointer types.

| Destination | Exact u64 source value |
| --- | --- |
| F+0x37E8 | A+0x2BEF09D10E3BDD6E |
| F+0x37F8 | B |
| F+0x3800 | O |
| F+0x3810 | A+0x63604E5D3CFF75DB |
| F+0x37F0 | B |

All three values nonzero selects index0x3C2D, slot `0x101058058`, target `0x100BB02A8`; otherwise index0x3BFF, slot `0x101057EE8`, target `0x100A42248`. Both use IA0x74F9. The gate and saved-field identities are proved for every u64 A/B/O under separated-memory premises and checked in all eight presence combinations.

At BB02A8, conditional roots F+0x2960=`0x101031DA0` and F+0x2968=`0x100E99900`, key0x86 and additive0xCBB5 select original import slot `0x10109FF58`, index0xCC0D, `_malloc`, IA0x6AA4 for all 256 bank inputs. Instructions `0x100BB030C..310` set X0=0x404=1,028 bytes and X17=0x6AA4 before call site `0x100BB0314`. The check stops before the call. Native allocation, success/failure handling, owner/layout and cryptographic purpose of these 1,028 bytes are unknown. This numeric extent does not establish a particular cryptographic object type.

## Assumption register and bounded next evidence

| ID | Assumption / dependent results | Stress or falsification probe |
| --- | --- | --- |
| DC1 | Original thin image, fixups and IDB identity / all addresses | Rehash input and compare eight current byte windows; mismatches invalidate source joins |
| DC2 | Symbolic word cells and accessed context/frame/table ranges are separated except explicit intended aliases / source identities | Byte-level effect ledgers, distinct private owners and two placements; arbitrary aliasing and wrapped native owner bounds remain outside the proofs |
| DC3 | Dispatch roots, valid signed-index cells and original authenticated targets hold / branch identities | Decode original fixups, inspect actual root producers and preservation; metadata is not hardware authentication |
| DC4 | Mode0x471C, W19=0x9930 and stated entry registers are cutpoint premises / local ABI identities | Trace actual predecessors; do not replace missing native control state with fixtures |
| DC5 | Encoded-count decoding is modulo u32 / shared threshold | Rebuild both predicates for every u32 count/counter; native arbitrary-length handling remains unknown |
| DC6 | Borrowed inputs and source pointer cells are valid / fragment loads and output reservations | Reject undefined private reads and check exact widths; recover native owner extents and cursor bounds |
| DC7 | Retained journals preserve prior conditional API models / identity case counts | Recheck payload/dependency hashes and ordered source effects; UTF-8 length and UTF-16 units remain distinct |
| DC8 | Saved continuation, mode and frame survive intervening paths / complete return interpretation | Establish continuous source paths and intervening writes; separate local captures/consumers from a proved return |
| DC9 | First-padding equivalence is local / finalizer classification | Check all 64 low6 positions with both high-word patterns; require downstream compression/output evidence for full equivalence |
| DC10 | 32-byte reservation and 36-byte allocation have different owners in this corpus / output/cache separation | Compare actual addresses and all source write overlaps; require an explicit later copy/publication join |
| DC11 | Malloc-bank roots equal the stated retained common roots / 1,028-byte allocation target | Exhaust256 bank inputs and trace roots; native call and resulting object type remain unknown |
| DC12 | Source contracts are process-local / architectural scope | Require a known message/right/selector producer and consumer before assigning any transport role |

| Impact | Additional opportunity / unresolved pattern | Required next evidence |
| --- | --- | --- |
| High | Distinct update conventions explain why transplanting raw-count frame fields cannot complete the identity path | Recover the actual producers of identity SP+0x2E50 / SP+0x2C8C and enclosing mode state |
| High | Inline and wrapped outputs occupy different locations | Follow actual final digest writes and explicit cache copy/publication; retain owner distinctions |
| High | Fixed20 caller consumes base+0x238 and returns to another finalizer | Establish the base owner, the 20-byte input producer and context/output cell owners |
| High | Conditional finalizer result reaches a 1,028-byte request | Establish native caller, full return preservation and allocation consumers before assigning purpose |
| Medium | NULL-output path returns without padding in the checked wrapped entry | Recover callers' output-presence semantics and full cleanup paths |
| Medium | Digest-to-driver relationship remains open | Join actual digest/cache bytes to an existing Mach/IOKit emission and matching driver input |
| Low | Equivalent first-padding operations may share further semantics | Compare subsequent zero fill, length encoding, compression and output encoding from original source |

Reproduction uses the pinned Python/Z3 environment of the preceding reports. Run `recover_daemon_digest_conventions.py`, `prove_daemon_digest_conventions.py`, `probe_daemon_digest_conventions.py`, then `validate_daemon_digest_conventions.py` in `triage_evidence`. The validator rebuilds obligations, checks both SMT forms against their source expressions, reruns the 377 isolated A64 fragments, checks independent byte ledgers and audits frozen journals. Time is O(source bytes + retained visits/effects + new visits/effects + 256 bank inputs + solver resources); memory is O(loaded artifact bytes + largest decoded retained journal + one private mapping + solver expressions). The generators retain their case journals for serialization; their memory bound includes that output artifact. Each solver query has a 30-second limit; no polynomial SMT complexity claim is made.

QG1: factual technical scope. QG2: DC1-DC12 list premises, dependent claims and probes. QG3: paired ABI and retained-output increment covered; full objective remains incomplete. QG4: explicit hexadecimal offsets, decimal byte extents, signed indices and modulo widths. QG5: local threshold/padding equivalence, retained continuity, borrowed ownership and native execution remain distinct. QG6: original image/fixups, current IDB bytes, rebuilt source proofs, fresh A64 fragments and independently inspected retained effects support scoped claims. QG7: impact-ranked additional evidence table provided.
