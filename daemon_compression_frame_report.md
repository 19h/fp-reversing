# Compression copy loop, shared frame, selector and return ABI

The retained identity frontiers now have a source-level explanation. Long updates fill the remainder of a 64-byte block, save the context at SP+0x2E50, and enter the shared compression-frame setup. Short finalization enters that setup without the same writer. The setup also copies raw-update count/input fields, accounting for the existing undefined-frame stops; those fields are not supplied here. The next source target reserves 320 bytes, captures a continuation and dispatches on the context selector. Its complete byte-domain dispatch reduces to selector1, selector2 and a common other-value leaf. Selector2 reaches `0x100A361B0`, connecting the previously recovered encoded SHA-1 context to a specific core entry. Completed compression/digest/cache contents, native caller continuity and driver IPC linkage remain unknown. The full daemon/kext/deeper-interface investigation remains active.

This extends the [paired digest ABI report](daemon_digest_conventions_report.md). It establishes local compositions and independently audits retained journals; it does not resume those journals by inventing missing frame inputs.

## Primary evidence and verification

| Evidence | Verified extent |
| --- | --- |
| Original daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Original source | 17 source spans; 15 original authenticated fixups |
| Current IDB | `fairplayd`, target `6b117c693e3b`; ten read-only ranges / 880 bytes, raw identical |
| Source proofs | 12 rebuilt proof pairs / 24 SMT files; 181 lifted instructions; two nonempty arithmetic premises checked |
| New isolated cases | 716 persisted and freshly recomputed local A64 compositions; 114,390 source instruction visits |
| Dispatch distinction | Of those visits, 6,092 are modeled BRAA dispatches; 108,298 instructions execute in the isolated A64 engine |
| Ordered effects | 14,460 reads / 7,082 writes checked independently |
| Copy coverage | 128 complete first-chunk cases; all 64 starting offsets at two placements; 4,160 encoded bytes |
| Selector coverage | All 256 byte values at both retained continuation indices; 512 cases |
| Other cases | Eight shared-frame layouts, two short callers, 64 next-block predicates, two return epilogues |
| Retained audit | 480 successful-conversion journals; 3,357,408 retained visits / 404,448 retained effects inspected |

[Source contracts and censuses](triage_evidence/daemon_compression_frame_contracts.json), [proofs](triage_evidence/daemon_compression_frame_proofs.json), [isolated case journals](triage_evidence/daemon_compression_frame_profiles.json), [independent checks](triage_evidence/daemon_compression_frame_checks.json), [IDA ranges](triage_evidence/daemon_compression_frame_ida_bytes.json), and [IDA return bytes](triage_evidence/daemon_compression_frame_ida_return.json) contain the primary evidence. [Preservation](triage_evidence/daemon_compression_frame_preservation.json) and [scoped delivery gates](triage_evidence/daemon_compression_frame_quality_gates.json) seal the increment. The retained cases are inspected, not freshly re-executed here. No native target, API, IPC, hardware authentication or IDB mutation executes.

All addresses, offsets, indices and control constants below use explicit `0x` prefixes. Extents/counts are decimal bytes unless indicated. F is the applicable outer SP, C is context, I is input, T=`0x101039EF0`; u32/u64 arithmetic wraps modulo 2^32/2^64. Source proofs use separated word cells and valid-owner premises; they are not whole-program alias or native memory-validity proofs.

## First complete block from the encoded update

The prior encoded entry produces W10=0x6F67867F under W19=0x9930. At `0x100BB18EC`, let h be the current counter low6. The source produces L=64-h, W9=0x71B7, W20=0x0E and X11=L-1, then selects index0x71C3 / slot `0x101072D08` / target `0x100B3940C`, IA0x5414. L is between 1 and 64. The modulo-u32 entry condition `(N+h) mod 2^32 >= 64` implies unsigned N>=L; owner validity and nonwrapping input-address extents remain separate requirements.

At B3940C, each iteration loads one byte through X21 and increments that pointer, stores an encoded byte at C+X8, increments X8 and decrements X11. The source byte expression reduces over every u8 b to:

```text
store8(C+position, b - ((b << 1) AND 0x30) - 0x68)
             == store8(C+position, b XOR 0x98)
```

The branch selects index0x71C3 while the pre-decrement X11 is nonzero, and index0x71B7 / slot `0x101072CA8` / target `0x100926E88` on the last byte. Thus the final X11 wraps to all ones after the last iteration; no additional byte is read before the exit. The 128 isolated compositions check the exact L source reads, contiguous destination interval C+h through C+63, final input I+L and L+2 modeled dispatches.

At `0x100926E88`, with W20=0x0E, the source stores L to F+0x30FC and C to F+0x2E50, copies C into X12, produces W8=0x471C and selects index0x385F / slot `0x1010561E8` / target `0x100ABEE44`, IA0xD370. This source contract explains the actual writer seen on all 192 retained long paths.

The short caller at `0x10094A390`, under W8=0x471C, instead produces W20=0x58, copies X4 into X12 and selects that same shared target. All 288 retained short paths take this caller. They do not execute the long writer at 926EA4. At both retained frontiers X4=C, X10=`0x100B76438`, W1=0x318C and X30=T. The retained paths have not executed B76438 or the raw update entry AEE3A4.

## Shared compression-frame layout and ambient dependencies

The source prefix `0x100ABEE44..0x100ABEF14`, conditional on W8=W15=0x471C and X30=T, selects index0x36C8 / slot `0x101055530` / target `0x100B76438`, IA0x89B3. It establishes this frame layout before dispatch:

| Destination | Source / meaning within this prefix |
| --- | --- |
| F+0x2A08, u32 | E=load32(F+0x31DC), still encoded count |
| F+0x2A60, u32 | E+0x318C+0x1960F475; equals N+0x34385513 when E=N+0x1AD72F12 |
| F+0x2A58, u64 | load64(F+0x2F50), encoded-update saved input |
| F+0x2A50, u64 | load64(F+0x2E50), context on the retained long path |
| F+0x2A68, u32 | load32(F+0x2C8C), captured by the separate raw update entry |
| F+0x2A20, u64 | load64(F+0x3490), captured by the separate raw update entry |
| F+0x2A18 / F+0x2A48, u32 | 0x20 / 0xA243 |
| F+0x2A10 / F+0x2A40, u32 | 0x42 / 0xA34A |
| F+0x2A38, u32 | 0x34385513 |
| F+0x2A30 / F+0x2A28, u32 | 0xA351 / 64 |

It also produces W1=0x318C, W9=0x98 and W14=0xF4F92DF7. The prefix copies the ambient values from F+0x2E50/+0x2C8C/+0x3490 without dereferencing their copied contents. Whether all of them influence the eventual identity result is unknown. They cannot be discarded as dead inputs without following the complete consumers and intervening aliases. In particular, the conditional next-block path below consumes F+0x2A50 and F+0x2A58 as arguments.

The long retained paths define F+0x2E50=C and then stop before reading F+0x2C8C at ABEE84. The short paths stop earlier, before reading F+0x2E50 at ABEE7C. Independent frame cases quantify the copied values and exercise their local layout; they are separate cutpoint fixtures, not continuations of those retained paths.

| Exact direct SP offset | Original scalar unsigned-immediate accesses | Interpretation boundary |
| --- | --- | --- |
| 0x2E50 | STR64: `0x1005F51C8`, `0x100926EA4`; LDR64: `0x100554C8C`, `0x100ABEE7C` | First writer stores X28+0x100; second stores X4. The other reader dereferences the stored value. Same offset does not establish same native owner/type. |
| 0x2C8C | STR32: `0x100AEE3B8`; LDR32: `0x100ABEE84` | Raw-update capture and shared-frame copy |
| 0x3490 | STR64: `0x100AEE3BC`; LDR64: `0x100A4A09C`, `0x100ABEE8C`; STR32: `0x1007FA490`; LDR32: `0x1007F4678` | Narrow overlapping uses prohibit treating the offset as a globally typed pointer |
| 0x2DE0 | STR64: `0x100B76454`; LDR64: `0x100BDFB0C` | Compression continuation capture/consumer |

This is a 13-access census of four exact offsets and scalar32/64 unsigned-immediate SP encodings. Other offsets overlapping these cells, pairs, computed addresses, aliases and alternate frame bases are outside its completeness claim. The exact original text extent and text-only SHA-256 are recorded with the census.

## Compression entry and compact selector dispatch

At `0x100B76438`, under W1=0x318C, let P be W20 and Q=load64(F+0x3620):

| Source effect | Exact result |
| --- | --- |
| Saved continuation | `load64(T + 8*signed32(P))` -> F+0x2DE0 |
| Scratch base | X16=F+0x39F0+Q |
| Cursor | F+0x3620=Q+320 (0x140) |
| State reads | Four encoded u32 words at C+0x48/+0x4C/+0x50/+0x54 -> W11/W19/W0/W30 |
| Saved state words | W0 -> F+0x2EBC; W30 -> F+0x303C |
| Dispatch root transfer | X2=T before W30 receives a state word |
| Selector | One byte at C+0x60; C is subsequently saved to F+0x2A70 before X4 is repurposed |

This prefix does not yet read the 64-byte message buffer or the fifth state word at C+0x58. A 320-byte reservation is consistent with 80 u32 cells, but a complete message-schedule layout is not established by the reservation alone.

The source enters `0x100D9F60C` through index0x318C / slot `0x101052B50`, IA0x686A. Two more obfuscated decisions pass through `0x1009A0398` or `0x100B0A24C`. Exhaustive byte-domain checks against original A64 give this compact final dispatch under the stated entry mode:

| Selector byte at C+0x60 | Final index / slot | Target / IA diversity |
| --- | --- | --- |
| 1 | 0x21A3 / `0x10104AC08` | `0x1009E0CC4` / 0x40BD |
| 2 | 0x5A21 / `0x101066FF8` | `0x100A361B0` / 0x40BD |
| Every other byte value (254 values) | 0x2183 / `0x10104AB08` | `0x100BDF3BC` / 0x40BD |

All 256 values are checked at P=0x0E and P=0x58; the final leaf is unchanged by that choice. The first obfuscated decision alone partitions 64/192 values, whereas the complete dispatch isolates selector1 and selector2. Native admitted selector values, the role of the common other-value leaf, complete core semantics and successful native authentication remain unknown. The source association of selector2 with the previously recovered SHA-1 IV/output-size context is now explicit; no completed hash is claimed.

## Saved return and conditional next-block contract

The epilogue `0x100BDFAF0..0x100BDFB2C` subtracts 320 from the cursor at F+0x3620, loads X1 from F+0x2DE0, restores X30 from X2, loads saved mode F+0x273C into X15, restores X24/X27 from F+0x2978/+0x2980, and branches through X1 with IA0xD737. It also sets X0=F+0x2E5C and X16=F+0x35E4. The 320-byte additions/subtractions are arithmetic inverses if they concern the same cursor with the required intervening preservation. A continuous path through the full compression body, preservation of X2/saved target/frame, and native PAC remain unproved.

| Candidate continuation P from retained caller state | Original target / slot | Source-local next role |
| --- | --- | --- |
| 0x58, short finalization | `0x1009DE090` / `0x10103A1B0` | Reloads saved mode, context F+0x2F40 and selector word C+0x60; further processing remains open |
| 0x0E, long update | `0x100C0B4D4` / `0x101039F60` | Reads F+0x2A10; under the shared layout index0x42 selects `0x100B51C00`, slot `0x10103A100`, IA0xD737 |

At B51C00, let N be the decoded count and L=load32(F+0x30FC). Under the shared saved fields and 1<=L<=64, the obfuscated comparisons reduce for every u32 N to unsigned `N >= L+64`. Since L+64 is at most 128, this comparison introduces no addition wrap. This is the condition that a further full block remains after the first L bytes.

| Predicate | Selected index / target | Arguments captured by this local source path |
| --- | --- | --- |
| N >= L+64 | 0xA351 / `0x100BAE8D0` | X0=load64(F+0x2A58), X1=load64(F+0x2A50), W2=load32(F+0x2A30)=0xA351, W4=load32(F+0x2A28)=64 |
| N < L+64 | 0xA34A / `0x100C9F804` | Same argument loads; subsequent meaning remains to be recovered |

Both targets use IA0xC27E. N=64/L=64 takes the second target; N=256/L=64 takes the first. These are checked local post-return compositions with preserved-frame premises, not executed returns from a completed native or modeled hash core. Input advancement, residual-count updates and output publication after these targets remain unknown.

```text
encoded long update -> BB18EC -> B3940C byte loop -> 926E88
                                                    | save C at F+0x2E50
short finalization -> 94A390 ------------------------+-> ABEE44 shared frame
                                                         | ambient field reads
                                                         | retained stops remain
                                                         v
                                                B76438: reserve320, save return
                                                         |
                                                selector 1 / 2 / other
                                                         |
                                                full core body: not completed
                                                         |
conditional epilogue BDFAF0: cursor-320, root restore, saved return
  P=0x58 -> short continuation
  P=0x0E -> C0B4D4 -> B51C00 -> next full block / remainder

digest -> cache[36] -> Mach/IOKit emission: unknown joins
```

## Assumption register and bounded continuation

| ID | Premise / dependent claims | Stress or falsification probe |
| --- | --- | --- |
| CF1 | Original image/fixups/current IDB identity / source addresses | Rehash input/text and compare ten live ranges; invalidate mismatching joins |
| CF2 | Separated word cells, frame/context/table ranges and valid owners / symbolic source identities | Independent defined-byte ledgers and alternate placements; arbitrary aliasing and native owner bounds are not proved |
| CF3 | Encoded entry W19=0x9930 and produced W10 / first-copy setup | Trace the actual predecessor; do not assign this mode to an arbitrary native entry |
| CF4 | Declared input contains L bytes; destination covers C+h..C+63 / complete local copy | Universal count/byte lemmas and 128 exact read/write journals; prove native extents separately |
| CF5 | W8=W15=0x471C and X30=T / shared-frame layout | Actual retained frontier registers plus universal local proofs; upstream native reachability remains unknown |
| CF6 | Retained conditional API models and parent contexts remain applicable / 480-path audit | Verify payload/dependency hashes and actual source edges; no fresh execution of those complete journals is claimed |
| CF7 | Ambient copied fields retain valid source provenance / meaningful full continuation | Recover actual producers, overlapping writes and consumers; do not fill undefined fields or discard them as dead |
| CF8 | W1=0x318C, valid signed continuation cell and context / entry and selector classification | Check all256 selector bytes at two original continuation slots; recover native admitted values |
| CF9 | X2, F+0x2DE0, saved fields and cursor survive full core execution / complete return interpretation | Establish the continuous body and all intervening effects; local capture/consumer proofs alone do not suffice |
| CF10 | Saved count fields and 1<=L<=64 survive / next-full-block predicate | Universal u32 proof, satisfiable premise and 64 boundary cases; other modes remain outside the claim |
| CF11 | Direct scalar SP census is bounded / access completeness | Extend to overlaps, paired/computed/alias accesses and frame-base changes |
| CF12 | These are process-local interfaces / architecture scope | Require explicit digest/cache writes, a known Mach/IOKit emission and matching consumer before assigning a transport role |

| Impact | Additional opportunity / unresolved pattern | Required next evidence |
| --- | --- | --- |
| High | Selector2 now identifies a concrete core entry | Recover A361B0 message decoding, round/schedule operations, state update and all output writes |
| High | Ambient frame dependencies still stop retained identity paths | Recover real caller producers or prove the relevant dependencies unused on a continuous path |
| High | Conditional return has exact full-block/remainder targets | Recover actual pointer/count updates at BAE8D0 and C9F804, then join complete core returns |
| High | Digest/cache and driver transport remain separate | Establish actual digest/cache publication and join bytes to existing Mach/IOKit request producers/consumers |
| Medium | 320-byte scratch matches an 80-u32 extent | Verify actual indexing, initialization and lifetime before identifying a message schedule |
| Medium | Selector1 and other-value branches remain unclassified | Recover their full core/status contracts and native admitted selector set |
| Low | Four frame offsets have heterogeneous global uses | Expand alias/overlap analysis while retaining path-specific field meanings |

Reproduction uses the pinned Python/Z3 environment of the preceding reports. Run `recover_daemon_compression_frame.py`, `prove_daemon_compression_frame.py`, `probe_daemon_compression_frame.py` and `validate_daemon_compression_frame.py` in that order. The validator rebuilds source obligations, matches both SMT forms, reruns all 716 isolated cases, checks original code/table bytes and independent ordered byte ledgers, then audits retained journals. Time is O(text bytes + retained visits/effects + new visits/effects + solver resources); memory includes loaded artifact bytes, retained output journals, the largest decoded retained journal, one private mapping and solver expressions. Solver queries have a 30-second limit; no polynomial SMT bound is claimed.

QG1: factual technical scope. QG2: CF1-CF12 and falsification probes. QG3: copy/frame/selector/return/next-block increment covered; full objective remains incomplete. QG4: explicit byte extents, signed indices, modulo widths, modeled dispatch counts and bounded predicates. QG5: source-local identities, exhaustive byte-domain dispatch, retained frontiers, fixture premises and native continuity remain distinct. QG6: original source/fixups, live IDB bytes, rebuilt proofs, fresh A64 cases and retained effect inspection support scoped claims. QG7: impact-ranked additional evidence table provided.
