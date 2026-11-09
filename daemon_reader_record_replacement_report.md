# N19 first-match lookup, position-preserving replacement and retirement

The N19 constructed-record path now has a source-composed lookup and matched-replacement contract. Lookup decodes the first four bytes of each candidate record, compares the encoded identifier exactly, publishes the first matched node or NULL at chain exhaustion, and returns a raw status. The matched candidate is explicitly joined through the N19 output cell to replacement's OLD pointer. Replacement repairs the appropriate neighboring links and container endpoints, conditionally releases the old buffer, releases the old node, clears its scratch pointer, and returns to the saved-end reader-loop continuation. [LR1-LR10]

Both ordinary insertion outcomes now have a conditional actual back edge: the earlier absent-result append and the matched-result replacement. Each completed iteration advances the logical cursor by at least 10 B under the preceding fit/admission contract. This does not prove a complete native parser, termination of callees or cyclic searches, object ownership, hardware authentication, or daemon-kext delivery. The u64 reader's complete raw-value transform remains unresolved. The full cross-layer goal remains active.

No target execution, target emulation, FairPlay request, native release or IDB mutation occurred. Original-file and retained evidence references suffice; no new IDA query was necessary.

## Primary evidence and coverage

Original thin daemon: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are unslid original VAs. Hexadecimal offsets/constants have `0x` prefixes; byte extents and counts are decimal unless explicitly hexadecimal. BE32 denotes big-endian wire decoding; frame and node integer loads/stores follow the captured little-endian instruction set. Integer operations have explicit u32/u64 widths.

- [Source ranges, bank bytes, original fixups and initializer references](triage_evidence/daemon_reader_record_replacement_source.json), [extractor](triage_evidence/recover_daemon_reader_record_replacement.py).
- [Queries, translations and results](triage_evidence/daemon_reader_record_replacement_checks.json), [validator](triage_evidence/validate_daemon_reader_record_replacement.py).
- [Preservation seal](triage_evidence/daemon_reader_record_replacement_delivery.json), [scoped quality gates](triage_evidence/daemon_reader_record_replacement_quality_gates.json), [independent publication auditor](triage_evidence/verify_daemon_reader_record_replacement_publication.py).
- Adjacent [N19 typed payloads and append](daemon_reader_record_payloads_report.md), [admission/allocation/header reconstruction](daemon_reader_record_headers_report.md), [earlier constructor lookup and word codec](daemon_constructor_lookup_report.md), [bank-origin projections](daemon_constructor_bank_origins_report.md), [additional initializer root references](daemon_builder_owner_join_report.md).

| Evidence | Exact scope |
|---|---|
| Fresh capture | 27 branch-terminated ranges; 1278 instructions / 5112 B, including two release-call boundaries |
| Original dispatch metadata | 35 pointer records; 37 fragment/index/modifier matches |
| Full instruction coverage | Every new instruction except BRAA/BLRAA; 1249 distinct translated PCs, 1821 translated instances, 1707 SSA definitions |
| Prior source recapture | Eight lookup/decoder ranges; generic preparation and word decoder are byte-identical to the earlier helper |
| Key-origin join | All 19 literal-tail register outputs compared with the complete actual 386-instruction preparer state |
| Source/solver certificate | 39 new UNSAT queries; 32 replayed decoder seed/round UNSAT queries; one abstract SAT mutation counterexample |
| Release-target banks | Two original 256-byte bank pairs; all 512 abstract byte-input cases select `_free` under the stated roots |
| Integrity controls | Six changed-source/ledger controls rejected against freshly recaptured evidence; these do not test native behavior |

No captured range writes SP. The two BLRAA boundaries are not executed: post-call models preserve SP and X19-X29, make caller-saved registers fresh, and require the designated frame/list cells to retain their stated values. Preservation of memory owners is a separate premise from register preservation.

Historical JSON evidence may reside in `.json.zst` archives after the external storage migration. Current capture, seal and audit tools read both forms without restoring or overwriting archived files. Manifest sizes and hashes identify decoded logical content; historical Markdown JSON paths are resolved logically and are not all physically present as literal filenames. The already-recorded unavailable historical SDK header remains distinct from archive resolution.

## First-match lookup and its N19 caller

The shared post-payload block `0x1005c635c` clears K+`0xde8`/u64 and supplies CTX, the encoded preceding word HRAW, and that temporary output-cell address to `0x1006fd1b8`. The helper saves continuation table[`0x1308`] at K+`0x7060`, HRAW/u32 at K+`0xaa5c`, and OUT=K+`0xde8` at K+`0xaa60`. Its original saved continuation is `0x1007c4d4c`, IA modifier `0x068f`. NULL CTX selects the early mediator with raw W6=`0x74c29d88`; lookup itself does not write OUT on that arm. N19 had already cleared the cell. [LR2-LR4]

For non-NULL CTX, LINK initially equals CTX. The helper at `0x100697188` loads CAND=[LINK+0], stages it at K+`0xaa68`, and selects candidate decoding or exhaustion. On a mismatch, LINK becomes the candidate node; the next load therefore follows CAND.next at +0.

| Source | Recovered contract |
|---|---|
| `0x100697198` | CAND=[LINK]; LINK is CTX initially and the previous candidate thereafter |
| `0x100914e54` | BUF=[CAND+0x18] |
| `0x100914e6c..0x100914e78` | Encoded word offset X4=`0x661a590b302baf96`, meaning offset 0 |
| `0x100914e80` | Dispatch to preparer with W8=`0x8c3f`, return selector W16=`0xc8` |
| `0x1006f6bf0` | Complete 386-instruction preparation; X1/BUF, X4/offset and W16/return selector preserved |
| `0x100800004` | Four-byte address-masked word decoder |
| `0x100615a1c` | Exact u32 comparison of decoded W4 with saved HRAW |
| `0x1005bb1b0` | Reload phase and advance through candidate.next after mismatch |
| `0x100914a10` | Store candidate or zero through saved OUT and publish raw status |
| `0x1006c5c2c` | Authenticated transfer through the saved continuation |

All nineteen preparer literal-tail register outputs match the initial-key assumptions used by the 32 replayed seed/round lemmas. The freshly translated merge includes the fourth mask-word delta `0x5353535353535353`. For j=0..3 and A=BUF+j:

```text
D = BE32(BUF[j] XOR m(BUF+j), j=0..3) XOR 0x8b3dc651
match iff D == HRAW
```

The N19 header writer supplies clear identifier HRAW XOR `0x8b3dc651`; the decoder's second XOR therefore recovers the same HRAW representation. This identifies the equality key, without assigning application-specific meaning to its value. The search checks the first four decoded identifier bytes; no candidate tag or complete candidate-extent validation is established by this lookup path. Each candidate buffer must be readable for the required bytes and address-mask computation. The preparer's other eager context reads remain explicit valid-memory premises.

| Source outcome | Raw W6 | Exact output effect |
|---|---|---|
| NULL CTX | `0x74c29d88` | No lookup OUT write |
| Chain exhausted | `0x74c29ded` | *OUT=NULL/u64 |
| Identifier match | `0x8b3dc651` | *OUT=first matched CAND/u64 |

On a finite stable acyclic chain with readable nodes/buffers, the one-step contracts imply first-match behavior by induction: exhaustion returns NULL; equality returns immediately; inequality advances exactly one link. Search time is O(k) and scalar auxiliary space O(1) for k examined candidates. Termination for cyclic or concurrently modified chains is not established. Existing duplicate identifiers after the first match remain in the chain. [LR3-LR5]

The new joined query follows the actual decoded candidate through comparison, publication at K+`0xde8`, saved return, raw-status selection, and replacement. It reloads the same CAND as OLD under the documented stable/disjoint frame premises. It does not substitute an unrelated success marker or unrelated OLD pointer.

## N19 result selection and local splice

N19's signed raw-status split and exact gates retain this complete u32 partition:

| Raw status | Selected path |
|---|---|
| `0x8b3dc651` | Matched replacement at `0x10076e3a8` |
| `0x74c29ded` | Established append at `0x100853de0` |
| All other values | Recorded cleanup frontier |

These names describe local source effects, not public error codes. The reconstructed private register/stack interfaces are not recovered public C prototypes.

Replacement first loads OLD from K+`0xde8`, NODE from K+`0x5440`, PREV=OLD.prev and NEXT=OLD.next. It stores NODE.prev=PREV and NODE.next=NEXT, then repairs the appropriate links/endpoints:

| Condition | Source | Effect |
|---|---|---|
| Always | `0x10076e3d0`, `0x10076e3d8` | NODE.prev=PREV; NODE.next=NEXT, in that order |
| PREV!=NULL | `0x1004ea80c` | PREV.next=NODE |
| NEXT!=NULL | `0x1006efc24` | NEXT.prev=NODE |
| PREV=NULL | `0x1008cb958` | CTX.head=NODE |
| NEXT=NULL | `0x1006bb374` | CTX.tail=NODE |

All four actual source paths are stitched independently through their next/head/tail branches to retirement: singleton, head, tail and middle. Each performs the two NODE link stores plus exactly two applicable neighbor/endpoint stores. Intervening reloads of NODE.next/prev are bound to their prior stores under stable disjoint ownership. Ordinary loads/stores and STP establish neither atomicity nor synchronization. [LR4-LR7]

A separate array model composes the source-derived stores in their actual order over aligned u64 word cells, a disjoint 16 B head/tail projection, and 32 B nodes with coherent initial links/endpoints. It proves all four positions, preservation of NODE+`0x10` and NODE+`0x18` word cells, and unchanged word cells outside the conditional write set. It excludes byte-memory overlap, native allocator effects, concurrency and a complete CTX object type. A SAT mutation query demonstrates that omitting the tail-endpoint update is not equivalent in that abstract model; no native request or fault fixture is constructed.

This is position-preserving replacement. A found key does not move its record to the tail. With initially unique identifiers and the established absent-key append, these local contracts preserve uniqueness; no claim removes pre-existing later duplicates.

```text
before:  PREV <-> OLD  <-> NEXT
                   |
                   +-- old buffer

after:   PREV <-> NODE <-> NEXT
                   |
                   +-- newly constructed buffer

PREV=NULL updates CTX.head; NEXT=NULL updates CTX.tail.
Old-owner retirement occurs after the link repairs.
```

## Release interfaces and normal-return composition

`0x1006cc840` reloads OLD from K+`0xde8` and OLD_BUF=[OLD+`0x18`]. NULL OLD_BUF skips its release; non-NULL OLD_BUF enters `0x1006c7710`. Both branches then enter `0x1008b3144` to release OLD. The NULL-buffer arm is a source-defined helper branch, not evidence that a stable successful identifier decode can read an absent buffer. [LR5-LR9]

| Release | Frame bank roots | Bank key / index addition | Original call |
|---|---|---|---|
| OLD_BUF | K+0x600=`0x100e99a00`; K+0x5f8=`0x100f4e390` | `0xd7` / `0xcb7c` | `0x1006c7788`, X0=OLD_BUF |
| OLD | K+0x870=`0x100e99700`; K+0x868=`0x100f4e190` | `0x56` / `0xcbf4` | `0x1008b31b8`, X0=OLD |

The original bank bytes yield constants `0x8c` and `0x14` respectively for every u8 selector input. Both therefore select index `0xcc08`, slot `0x10109ff30`, the original `libSystem/_free` authenticated binding with IA modifier `0x46a2`. The controller-dependent selector arithmetic is translated with arbitrary controller inputs. The initializer root references are recaptured separately: two prior projections for +0x870/+0x868 and sixteen retained root-field instances for +0x600/+0x5f8. They do not establish native reaching definitions at these later calls.

After a normal OLD_BUF release, the source reloads OLD and clears OLD+`0x18`/u64 before node release. After a normal OLD release, it clears K+`0xde8`/u64. The clear concerns the saved old-node scratch cell; NODE remains linked. No native release, allocator ownership, actual deallocation or heap-lifetime transition was observed or executed.

At each modeled call boundary, SP and X19-X29 are preserved while caller-saved registers are fresh. Designated frame/list cells must remain valid and stable as separate owner/callee premises. This avoids carrying transient caller-saved values through a release without justification. The preceding reports retain the primary normal-call ABI reference; public allocator semantics and native execution are not inferred from this register model alone.

## Replacement back edge and bounded ordinary-record progress

Both OLD_BUF-present and OLD_BUF-NULL component routes produce W19=`0x9467` and W20=`0x3599` before/through OLD release. Its normal return clears the saved OLD pointer, supplies X9=K+`0x5000`, and dispatches table[`0x9467`] -> `0x1009a1808`, IA modifier `0xe01c`. This is the same post-insertion continuation established for append.

That continuation sets:

```text
X8  = u64[K+0xdb8]             # saved fitting end E
W19 = u32[K+0x631c]            # encoded total input extent
W12 = 0xb350
table[0x3599] -> 0x1004ddaec    # original IA modifier0x47da
```

The earlier source producer supplies E=C+10+P, where C is the current byte cursor and P the decoded u32 payload extent. Total extent S is u32, C<S and E<=S on the admitted path. The fresh geometry query proves no u64 offset wrap, E>C, and E-C>=10 B. Therefore both completed ordinary insertion outcomes use the actual C_next=E back edge. Native pointer arithmetic and validity of the saved-end reaching definition remain premises. [LR2,LR4,LR6,LR8-LR10]

A bounded mathematical consequence follows for completed ordinary iterations beginning at C0=0:

```text
C(n+1) = C(n) + 10 B + P(n),  P(n)>=0 B
C(n) >= n * 10 B
C(n) <= S
n <= floor(S / 10 B)
S <= 4294967295 B  =>  n <= 429496729 completed ordinary iterations
```

These are exact integer bounds, without measurement error. They bound completed ordinary-record iterations only. Special early-return arms may stop earlier; nonreturning native callees, invalid owners and cyclic/nonterminating context searches are outside this progress theorem. No global parser or native termination proof is claimed.

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent results | Stress test / falsification probe |
|---|---|---|---|
| LR1 | Exact pinned daemon build and original fixup catalog | Every VA, instruction and dispatch/import identity | Rehash executable and recapture instructions/fixups; changed build invalidates transferred addresses |
| LR2 | N19 caller and shared lookup use the recorded K/frame epoch with stable reaching cells | Key/output/continuation join, OLD publication and saved-end back edge | Resolve aliases and intervening writes to de8,7060,aa5c,aa60,aa68,5440,8760,db8 and631c; equal offsets alone are insufficient |
| LR3 | Candidate nodes/buffers and all eager preparer context reads are valid | Four-byte identifier decode and actual key state | Verify readable node+0x18 and buffer bytes plus full preparer footprint; no candidate type/full-extent check is inferred |
| LR4 | Pinned canonical codec cuts, source literal keys and caller phases compose | Decoded identifier equality and source path stitching | Recheck all19 literal-tail outputs,32 seed/round lemmas and fourth-word5353 delta; generic helper sharing alone is insufficient |
| LR5 | Finite stable acyclic chain, stable identifiers and disjoint OUT/frame | First-match search and its termination | Establish list/owner invariants and lack of mutation; later duplicate keys remain after a first-match replacement |
| LR6 | OLD,NODE,non-NULL neighbors and the CTX head/tail projection are valid/disjoint with coherent initial links | Position-preserving splice and protected NODE fields | Verify reciprocal links/endpoints, alignment and nonwrapping owners; the word-cell model does not prove native byte-memory validity |
| LR7 | Intervening reloads observe the just-written NODE links; no concurrency/alias interference | Four stitched source paths and their retirement join | Resolve aliases/locks and node lifetime; ordinary writes do not establish atomic publication |
| LR8 | Release bank roots/controllers/table have the recorded roles at this epoch | `_free` dispatch and post-call control | Check initializer references and later reaching definitions; exhaustive bank bytes do not prove current mutable native roots |
| LR9 | Releases return normally, preserve SP/X19-X29 and designated frame/list owners, with distinct live OLD/OLD_BUF/NODE as applicable | Buffer clear, OLD release, scratch clear and back edge | Establish allocation lineage, actual call identity/effects and completion; allocator effects are excluded from the splice model |
| LR10 | Earlier admission/fit produces stable E and original authentication metadata describes intended continuations | Minimum10 B progress, completed-iteration bound and conditional control joins | Recheck saved end and original target/key/diversity; native PAC, endpoint rights, authorization, delivery and daemon-kext pairing remain unproved |

## Reproduction, complexity and bounded continuation

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_reader_record_replacement.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_reader_record_replacement.py
```

Lookup takes O(k) time and O(1) scalar space under LR3-LR5. For a fixed context with M initial nodes and R completed ordinary insertions, stable first-match traversal examines at most sum(i=0..R-1)(M+i)=R*M+R*(R-1)/2 candidates when every insertion appends. Replacement keeps the node count fixed. Thus a conditional aggregate upper bound is O(R*(M+R)+sum(P)) source work, excluding native callee costs; it is not a measured runtime or an external reachability claim. The local replacement uses constant many source operations; native allocator/callee costs are unknown. Static extraction costs O(B+F+I+512+H) time/space for image bytes B, fixups F, selected instructions I and referenced evidence H. Query construction repeats finite projections. QF_BV/QF_AUFBV solver cost has no claimed polynomial bound. Each query has a 15 s timeout and 20 s subprocess limit; unknown/timeouts are rejected. Publication checking is O(total logical artifact bytes+links), with O(manifest+largest JSON) memory. All dimensional calculations concern bytes and exact integer widths.

- High: recover the full u64 reader raw-value transform and join it to the established N19 writer representation; this remains a local typed-reconstruction gap.
- High: establish CTX ownership, input/output-pair relationships and the caller's complete operation/transport lineage to build-matched daemon/kext interfaces.
- High: recover non-ordinary return/status and cleanup paths without importing ordinary-path invariants into unrelated epochs.
- Medium: prove reaching definitions for shared bank roots, saved frame cells and allocator/list ownership before promoting the source contracts to native behavior.
- Medium: determine the governing synchronization/owner protocol for shared context mutation and repeated lookup.
- Low: retain caller-specific encodings and epoch-specific scratch roles when naming shared helpers; no IDB renames are made.

QG1: Pass. The technical investigation requires no normative conclusion.

QG2: Pass for LR1-LR10. Assumptions, dependencies and falsification probes are explicit.

QG3: Pass for first-match lookup, matched-candidate publication, four-position replacement, normal-return retirement and the actual replacement back edge. Global parser/native transport closure remains active.

QG4: Pass. Endianness, u32/u64/128-bit geometry, byte extents, exact completed-iteration bound, normal-call cuts and computational limits are explicit.

QG5: Pass for bounded claims. Logical artifacts, eager-read validity, raw statuses, source versus word-cell models, NULL-buffer fallback and native owner/callee effects remain distinct.

QG6: Pass. Fresh original source/fixups/banks, full non-control instruction coverage, literal-key joins,39 new and32 replayed UNSAT queries support the claims. The SAT mutation is abstract; memory supplies guidance rather than a semantic premise.

QG7: Pass for the finite high/medium/low continuation list. The full cross-layer goal remains active and is not marked complete.
