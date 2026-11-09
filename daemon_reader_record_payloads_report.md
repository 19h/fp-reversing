# N19 typed payloads, address-aware span copying and append back edge

The N19 path following header reconstruction now has an exact selected type/extent partition. Reader tag `0xd0ee` admits a 4 B payload, `0xc31c` admits 8 B, and `0x1742` selects a variable-length span. The span route decodes the previously opaque count cell and copies encoded bytes with separate source-address and destination-address masks. The scalar and span routes converge on a context lookup. Its two distinguished raw results select append or replacement staging. Both append arms supply the actual cursor back edge to the earlier reader loop. [RP1-RP10]

This is a conditional source certificate. Full lookup behavior, replacement completion, retirement/cleanup, the u64 reader's raw-value transform, native object ownership, hardware authentication and successful daemon-kext exchange remain unproved. The full interface investigation remains active.

No target code was executed or emulated, no FairPlay request was sent and no IDB was modified. Original-file references suffice; no new IDA query was necessary.

## Primary evidence and coverage

Original thin daemon: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are unslid original virtual addresses. Offsets, selectors and constants below are hexadecimal with `0x` prefixes; extents and counts are decimal unless stated otherwise. B denotes bytes. u16/u32/u64 operations have the stated modular width; BE32/BE64 denote big-endian wire values.

- [Source ranges, original fixups and liveness](triage_evidence/daemon_reader_record_payloads_source.json), [extractor](triage_evidence/recover_daemon_reader_record_payloads.py).
- [Exact queries, translations and results](triage_evidence/daemon_reader_record_payloads_checks.json), [validator](triage_evidence/validate_daemon_reader_record_payloads.py).
- [Preservation seal](triage_evidence/daemon_reader_record_payloads_delivery.json), [scoped gates](triage_evidence/daemon_reader_record_payloads_quality_gates.json), [publication auditor](triage_evidence/verify_daemon_reader_record_payloads_publication.py).
- Earlier [admission/allocation/header joins](daemon_reader_record_headers_report.md), [value staging and source-span provenance](daemon_reader_value_consumers_report.md), [generic eight-byte writer](daemon_typed_scalar_report.md), [common word writer](daemon_header_codec_report.md).

| Evidence | Scope |
|---|---|
| New capture | 31 fragments: 27 branch-terminated ranges and four explicit half-open cuts; 820 instructions / 3280 B |
| Original authenticated table records | 36 records; 41 fragment/index/modifier matches, plus three writer-return joins |
| Prior byte recapture | Six ranges, including the full 746-instruction u64 writer, the word/tag writers and N19 header continuations |
| Additional preservation gap | 152 B between count-prefix and count-save cuts; no X8/W8 write, call or control transfer |
| Translation | Every non-BRAA instruction in the new capture, plus the full prior u64 helper and overlapping mask components; 1520 distinct PCs, 1709 instances, 1648 SSA definitions |
| Solver certificate | 51 new UNSAT queries, 72 replayed u64 seed/round/selection UNSAT queries; one abstract SAT mask counterexample |
| Integrity controls | Six changed-source/ledger controls rejected by fresh-source comparison; these are evidence checks, not native behavioral tests |

No captured new range writes SP. Named loads remain explicit frame/owner/cache premises; complete alias analysis or native initialization does not follow from instruction coverage.

## Selected type and scalar interfaces

The shared writer setup caches the sign-extended saved u16 tag at K+`0x970`. Under low32 phase `0x6cf4`, K+`0x928` contains `0xffffd0ee`, K+`0x930` contains `0xa630`, K+`0x900` contains `0x1c10`, and K+`0x908` contains `0xaeb8`. The router `0x1004a0f64` and upper split `0x1007996e8` use signed comparisons; the following exact comparisons produce this table over all 65536 u16 tags and all u32 extents P. [RP1-RP4]

| Reader tag T | Wire tag T XOR 0x4799 | Accepted P | Selected writer path |
|---|---|---|---|
| `0xd0ee` | `0x9777` | Exactly 4 B | `0x1005c3574 -> 0x10053ea88 -> 0x100615004 -> 0x100546c90` |
| `0xc31c` | `0x8485` | Exactly 8 B | `0x1006072c8 -> 0x10053f020 -> 0x1005a2c2c` |
| `0x1742` | `0x50db` | Variable; earlier allocation bound P<=0xfffffff5 still applies | `0x1004b9ce0`, zero bypass or span-copy setup |
| Every other u16 | Other wire tags | No selected payload route | Recorded cleanup frontier |

These checks occur after allocation/header construction on the selected path. They are not a claim of validation before every native memory access. Invalid-tag branches assign raw W6=`0x74c29d88`; wrong scalar extents assign `0x74c29d8f`. These assignments also execute on matching branches; raw assignment alone does not establish an externally returned error.

For u32, `0x10053ea88` supplies buffer-pointer cell NODE+`0x18`, encoded writer offset `0x71134a47fbd9f0b7+10`, and return selector `0x2a5`. The common word caller supplies F=VAL32 XOR `0x01263f51`. The source-recaptured generic writer therefore emits, before its address mask, BE32(VAL32 XOR `0x8b3dc651`). The prior reader/value-staging contract supplies VAL32 in this representation; composing those contracts preserves the decoded u32 wire payload under their frame and key premises.

For u64, `0x10053f020` supplies:

| Operand | N19 source value |
|---|---|
| X1 | K+`0xa628`, saved raw64 operand cell |
| X14 | K+`0x5440`, node-pointer cell |
| X16 | `0x80915f9a168f26e3`, scalar pre-XOR |
| W0 | `0x1351`, writer return selector |
| Dispatch | `0x7d2d -> 0x1005a2c2c`, IA modifier `0x14ad` |

This caller differs from the earlier constructor caller even though it shares the same writer. For j=0..7 and A=REC+10+j, the full helper with source-justified mask cuts proves:

```text
wire64 = RAW64 XOR 0xfa039b7ca50c772e
REC[10+j] = BE64_byte(wire64,j) XOR m(A)
```

The constant follows from `0x80915f9a168f26e3 XOR 0x7a92c4e6b38351cd = 0xfa039b7ca50c772e`. The byte-7 helper mask delta `0x6464646464646464` is retained by the replayed generic lemmas. The earlier u64 reader result was staged as raw X9; its complete input-to-RAW64 transform remains unknown. This increment establishes the writer's output in terms of RAW64, without claiming the missing reader inverse. [RP3-RP5]

Original return slots `0x2a5` (IA `0xa918`), `0x1351` (IA `0xd08c`) and span return `0x37fd` (IA `0x8388`) all target `0x1005c635c`. Header key registers and the word writer's residual scalar key have source liveness checks across the selected N19 continuations.

## Span count and encoded-byte transfer

The record-allocation prefix `0x1004d617c..0x1004d6234` and save at `0x1004d62d0` establish:

```text
Q = zero_extend64(P) + 0x1376253dadee7b93
u64[K+0xa630] = Q
```

The intervening 152 B preserve X8, which holds Q; no allocation call intervenes before its save. This is an additive representation. The span gate loads the low u32 of Q and its arithmetic reduces to P XOR `0xadee7b93`. It selects `0xcafd -> 0x1005c635c` for P=0; nonzero P selects `0xcadc -> 0x1007fd5e4`. That setup removes the XOR, supplies countdown P in X16, REC through NODE+`0x18`, and source SPAN from K+`0x57a0`. The earlier value-staging contract links SPAN to the original span payload address under its own epoch and ownership premises. [RP2-RP6]

The loop at `0x100791cfc` operates for countdown n=P,P-1,...,1. Define i=n-1, A=SPAN+i, D=REC+10+i, and m as the canonical address-indexed mask established by the earlier codec reports. Its exact byte relation is:

```text
i = n - 1
REC[10+i] = SPAN[i] XOR m(A) XOR m(D)
n = i
repeat if n != 0; otherwise return through table[0x37fd]
```

Both source and destination mask seeds reduce to:

```text
s = ROR64(address & ~7,8) + 0x622c5d3364e5d59f
x = s XOR 0xa7bebfcf1750d389
y = s XOR 0xb6dc5654307e7f72
```

Each uses the seven canonical rotate/add/XOR rounds documented in the [generic codec report](daemon_typed_scalar_report.md). Two new universal seed queries and fourteen arbitrary-state round queries cover the actual interleaved source and destination calculations. The source seventh-round word has a uniform XOR `0x7878787878787878`; the final literal byte XOR `0x78` cancels it. Omitting that delta would give an incorrect transfer equation.

Consequently decoding at D yields exactly the clear byte decoded at A. The operation preserves decoded bytes while adapting their storage to a different address. It does not establish byte equality of the encoded buffers. A single abstract SAT query rejects unconditional raw-copy equivalence for independent unequal mask bytes; it is not a target fixture and does not imply that every distinct address pair has different masks. Equal masks can coincide.

Source liveness establishes that the loop preserves its source/destination bases, return selector and fixed keys. Under 1<=n<=P, source index i is in [0,P-1] and destination offset is in [10,P+9], within the earlier P+10 B requested record extent. Countdown strictly decreases. Under valid stable disjoint owners, P nonzero iterations perform P byte reads and P byte writes and terminate. Time is O(P), auxiliary scalar state is O(1), and the record allocation occupies P+10 B. Physical pointer validity, nonwrapping native mappings and source lifetime remain premises. [RP4-RP7]

## Lookup result, ordered append and actual cursor back edge

At `0x1005c635c`, the shared successful-payload continuation clears the 8 B temporary cell K+`0xde8`, loads CTX from K+`0x8760` and the encoded identifier HRAW from K+`0xa618`. It enters `0x1006fd1b8`, which saves:

| Cell | Width | Value |
|---|---|---|
| K+0x7060 | 8 B | Original table[0x1308] continuation, target `0x1007c4d4c`, IA modifier `0x068f` |
| K+0xaa5c | 4 B | HRAW |
| K+0xaa60 | 8 B | Address K+0xde8 |

NULL CTX takes the early saved-return path with raw marker `0x74c29d88`. Non-NULL CTX enters `0x100697188` through the established dispatch chain. Its complete search and output-production contract is not newly proved here. The saved return and subsequent status tree are proved for an arbitrary raw u32 STATUS, with this exact partition: [RP2,RP7-RP9]

| Raw STATUS | Selected source effects |
|---|---|
| `0x8b3dc651` | Replacement staging at `0x10076e3a8` |
| `0x74c29ded` | Append gate at `0x100853de0` |
| Every other u32 | Recorded cleanup frontier |

The names describe local source effects and do not assign public error meanings. A raw marker does not establish actual lookup success or native validity of its output pointer.

The append gate loads CTX.tail at +8 and NODE from K+`0x5440`. Its two paths have these ordered effects:

| Case | Source | Exact stores / reads |
|---|---|---|
| Loaded tail T1=NULL | `0x10071e7f0` | CTX.head=NODE; CTX.tail=NODE via STP |
| Loaded tail T1!=NULL | `0x10090064c` | *T1=NODE; T2=CTX.tail; NODE.prev=T2; CTX.tail=NODE |

The nonempty interpretation as a consistent doubly-linked append requires valid disjoint owners, stable tail and the prior zeroed NODE.next field. T2 is a reload after the first write; T1=T2 is a separate stability premise. STP and ordinary stores establish neither atomic publication nor locking. The first two CTX words have head/tail roles on this path; a complete global CTX type and its relationship to the separately allocated 16 B output pair remain unknown.

Both append arms supply W20=`0x3599` and X9=K+`0x5000` to table[`0x9467`] -> `0x1009a1808`. That continuation supplies the exact earlier loop interface:

```text
X8  = u64[K+0xdb8]             # previously saved fitting record end E
W19 = u32[K+0x631c]            # encoded total input extent
W12 = 0xb350
table[0x3599] -> 0x1004ddaec    # original IA modifier0x47da
```

Thus the actual append back edge uses C_next=E=C+10+P under the preceding saved-end/epoch contract. Combining the earlier u32 total-extent admission and fit predicate proves C_next>C without u64 offset wrap and C_next<=S. The next iteration either continues on C_next<S or takes the established exhausted-input arm on equality. This is a selected append-path progress theorem, not a complete parser invariant or a replacement-path termination proof. [RP2,RP6-RP9]

The replacement staging frontier copies OLD.prev and OLD.next into NODE and branches according to whether OLD.prev is NULL. OLD is loaded from K+`0xde8`; its validity is an explicit premise. Subsequent neighboring-link repairs, old-node retirement and the replacement back edge remain open. No failed-allocation cleanup dereference or fault reproduction was evaluated.

```text
header completion
  -> exact u32 / u64 / span route
  -> common post-payload context lookup
       -> absent raw result -> empty/nonempty append -> cursor=record_end -> reader loop
       -> found raw result  -> copy old links -> replacement fixup frontier
       -> other raw result -> cleanup frontier
```

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent result | Stress test / falsification probe |
|---|---|---|---|
| RP1 | Pinned original daemon build and fixup catalog | All VAs, bytes and authenticated slot joins | Rehash executable, recapture ranges/fixups; any changed build invalidates address reuse |
| RP2 | Selected source producers and consumers share the stated K/frame epoch, with stable reaching cells | Type caches, scalar/span operands, lookup context/key and saved-end back edge | Resolve intervening aliases and upstream frame provenance; matching offsets alone are insufficient |
| RP3 | Earlier header helpers supply and preserve the recorded key state | Generic scalar helper composition | Recapture literal groups, residual word key and new N19 header/type-path liveness; hardware authentication remains separate |
| RP4 | The selected tag and P derive from the earlier reader/admission contracts | Typed reconstruction and bounds interpretation | Recheck persistent tag, canonical reader keys, exact 4/8 B gates and P+10 admission; arbitrary external reachability is not inferred |
| RP5 | RAW64 is the staged full u64 operand; its reader transform is unknown | Output is BE64(RAW64 XOR fa039b7ca50c772e) before address masking | Recover the complete u64 reader seed/merge transform before claiming a full u64 round trip |
| RP6 | Count-prefix input W23=27f2 and saved Q/span/end cells retain their source values | Additive count, copy countdown and C_next=E | Check predecessor phase and the X8-preservation gap, low32 load, span producer and end-store reaching definitions |
| RP7 | NODE, REC, CTX, SPAN, frame and relevant source/destination extents are valid, stable and appropriately disjoint | Byte-memory transfer, append interpretation and termination | Establish allocator/owner/lifetime and native mappings; logical offset bounds do not prove physical validity |
| RP8 | Lookup return STATUS and its output cell satisfy the stated component premises | Replacement/append selection and use of OLD | Recover full search/output/status contract; raw status alone does not prove a valid found pointer or an absent-key condition |
| RP9 | CTX.tail is stable across the ordered append stores and reload | Consistent doubly-linked append | Verify locking/ownership and T1=T2; retain both reads if aliases or concurrency can change the field |
| RP10 | Original authentication metadata describes intended continuations | Conditional table/return maps | Re-decode target/key/diversity; native PAC, rights, peer identity, delivery and daemon-kext pairing remain unproved |

## Verification, bounded continuation and quality gates

Reproduction uses static extraction and scalar bit-vector solving only:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_reader_record_payloads.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_reader_record_payloads.py
```

Extraction/translation costs O(I+R) time/space for captured instructions I and pointer records R, with finite recapture/liveness scans. The seven-round mask calculation has constant scalar cost per copied byte. Solver construction repeats finite projections; no polynomial bound is claimed for QF_BV solving. Each query has a 15 s timeout and 20 s subprocess limit; unknown/timeouts are rejected. Publication audit costs O(total artifact bytes+links), with O(manifest+largest JSON) memory. No physical measurements occur.

- High: complete context lookup status/output production, replacement link repairs/retirement and the replacement cursor back edge. This is the remaining local insertion path.
- High: recover the u64 reader's complete raw-value transform and join it to the now-proved N19 u64 writer representation.
- High: connect the private caller, CTX owner and input/output pairs to build-matched transport endpoints and selector26/RPC502/700 exchanges.
- Medium: establish frame/heap separation and tail stability or the governing lock/lifetime contract before promoting ordered source stores to native list consistency.
- Low: retain epoch-specific scratch types; shared helper addresses do not make the two constructor callers' tag/scalar encodings identical.

The prior publication's unavailable MacOSX27.0 SDK header citation remains explicitly recorded in the manifest. This increment depends on original daemon bytes and pinned codec evidence, without substituting the differing installed SDK header.

QG1: Pass. Technical source and model statements require no normative conclusion.

QG2: Pass for RP1-RP10. Dependencies and falsification probes are explicit.

QG3: Pass for typed payloads, recoding, lookup handoff, append and its actual back edge. Full lookup, replacement, cleanup, u64 reader transform and cross-layer closure remain active.

QG4: Pass. Byte extents, signed u16 ordering, exact u32/u64 arithmetic, additive count, endianness, complexity and logical/native bounds are explicit.

QG5: Pass for bounded claims. Caller-specific scalar encodings, mask deltas, arbitrary raw status, tail reloads and source-model versus native evidence remain distinct.

QG6: Pass. Original source recaptures, full non-BRAA coverage, original fixups/liveness, 51 new and 72 replayed UNSAT queries support the claims. The SAT query is abstract and creates no native witness. Memory supplies guidance, not a semantic premise.

QG7: Pass for the finite high/medium/low continuation list. No complete-parser or full-goal achievement is claimed.
