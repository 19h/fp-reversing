# Marker dispatch and the 872-byte allocation boundary

Original daemon instructions conditionally connect a byte-marker dispatch to `_malloc(872)` at `0x100C116B0`. The coherent binary-marker candidate has incoming `W8=0x621B` at analyst cutpoint `0x100A035F0`; the allocator receives internal phase `0x471C`. Marker zero takes a separate path to a lazy rwlock check with callback `0x100B280C8`. Native entry, marker address/producer, allocation initialization, registry publication and correspondence to the previously recovered destruction object remain **unknown**. The full daemon/kext/deeper-interface investigation remains active. [CR1-CR12]

Primary evidence is the original thin ARM64e image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, its original chained fixups and read-only database `fairplayd`, target `6b117c693e3b`. The [contracts](triage_evidence/daemon_object_creation_contracts.json), [source proofs](triage_evidence/daemon_object_creation_proofs.json), [A64 cases](triage_evidence/daemon_object_creation_replays.json), [fresh checks](triage_evidence/daemon_object_creation_checks.json), [preservation](triage_evidence/daemon_object_creation_preservation.json), and [scoped gates](triage_evidence/daemon_object_creation_quality_gates.json) contain reproducible artifacts. Prior [destruction](daemon_object_consumers_report.md) and [rwlock lifecycle](daemon_mode471c_lifecycle_report.md) evidence remains sealed.

| Assumption | Dependent result | Stress test / falsification probe |
|---|---|---|
| CR1: Exact thin-image identity and original chained-fixup membership | All addresses, banks and dispatch edges | Rehash source; decode original format-12 words/imports; compare 456 fresh IDB bytes |
| CR2: `A035F0` is an analyst cutpoint, with declared incoming registers/frame | Conditional fragment composition | Establish its actual predecessor and incoming state; no continuous native caller is claimed |
| CR3: Marker 0/1 is a candidate protocol, not an established invariant | Unique coherent candidate among seven marker-zero authenticated slots | Exhaust all 256 byte values; retain aliases 0x20/0x21 and additional metadata-compatible 0xE0 |
| CR4: Marker contents remain unchanged between the two reads on the zero route | Tested zero-marker path to the lazy gate | Identify synchronization/other writers; model interleaving or change the second read independently |
| CR5: Saved roots, table pointer and readable controller owners have the stated contents | `_malloc` resolution and private composition | Restore roots with original instructions, prove frame offsets, exhaust every bank input byte; native frame provenance unknown |
| CR6: Frame, marker, controller, cell and allocation owners are disjoint in private cases | Read/write and pointer-save assertions | Use two frame placements/backings plus four fresh cases; unknown private reads are rejected; native aliasing unknown |
| CR7: `_malloc` may return NULL or a valid 872-byte owner; ABI-preserved GPRs/SP survive | Allocation-result dispatch | Exercise both outcomes, clobber X1-X17/NZCV and preserve X18-X29/SP; no native allocator executes |
| CR8: Phase Q is an internal state value | Arithmetic and control partitions | Prove all u32 Q / u64 return equations; do not equate Q=471C with an external API selector |
| CR9: Authenticated table words are used through logical fixup tokens | Candidate edge identity | Check IA key, address-diversity zero and exact modifier; hardware authentication remains unknown |
| CR10: Same physical code can carry distinct incoming callback state | Zero-route interpretation | Compare X19=B280C8 here with the earlier removal-phase callback; do not import the earlier continuation wholesale |
| CR11: NULL-path stores are local state, not a proved final return | Raw failure marker and saved zero | Stop at 987C84; establish subsequent status/result consumers before naming a returned error |
| CR12: Matching allocation/destruction sizes do not establish object identity | Bounded link to earlier 872-byte overwrite/free | Trace returned pointer through initialization and publication into a registry object consumed by removal |

For u32 arithmetic modulo 2^32, incoming S=`W8`, and byte m loaded at `0x100A03650`, the original source computes:

```text
B = u32(S + 0x354D)
L = u32(B + 0xEFFC4FF6) & 0x10035FBD
H = u32(B + 0x5BF03876) & 0xA40F773D
I = B | u32(m * u32(L + H - 0x8DA5))
target = TABLE[sign_extend32(I)], modifier IA/0xE9B9
W8=L; W9=H; TABLE=0x101039EF0
```

All seven original IA/E9B9/ad=0 slots at or above TABLE form the marker-zero candidate set. Requiring both m=0 and m=1 to select members of that set yields one candidate; this is a bounded metadata-consistency constraint, not proof of a native caller. [CR2,CR3,CR9]

| Marker-zero index B | Incoming S | L | H/Q | Marker-one index | Both metadata-compatible |
|---|---|---|---|---|---|
| 9768 | 621B | 471C | 471C | 97FB | Yes |
| 978F | 6242 | 4785 | 5005 | 9FEF | No |
| 97DF | 6292 | 4795 | 5015 | 9FDF | No |
| 97E8 | 629B | 479C | 501C | 9FFB | No |
| 97F1 | 62A4 | 47A5 | 5025 | 9FF5 | No |
| 97FB | 62AE | 47B1 | 5031 | 9FFF | No |
| C3DE | 8E91 | 11394 | 7414 | FBDF | No |

Values in this and subsequent mapping tables are hexadecimal unless a byte/count is explicitly decimal. For S=621B, I=`0x9768 | u32(m*0x93)`. The five byte values whose selected original slots have IA/E9B9/ad=0 metadata are:

| Marker byte | Index | Original slot | Target |
|---|---|---|---|
| 00, 20 | 9768 | 0x101085A30 | 0x1009C5844 |
| 01, 21 | 97FB | 0x101085EC8 | 0x100C11650 |
| E0 | 97E8 | 0x101085E30 | 0x100A05AE0 |

The remaining 251 byte values select absent fixups or differently authenticated original words. The exhaustive cases stop before executing that dispatch. Metadata agreement alone does not establish hardware PAC success or a semantically valid continuation for 20/21/E0. [CR3,CR9]

```text
analyst cutpoint A035F0, incoming W8=621B
  save frame fields -> A03650 reads marker
  |
  +-- 0 -> 9C5844 -> ABE63C (second marker read, held at 0)
  |         -> 9C1404 -> 64FFBC: load saved-X4 cell; X19=B280C8
  |                        +-- cell=0 -> 97290C creator frontier
  |                        +-- cell!=0 -> 933C2C acquisition frontier
  |
  +-- 1 -> C11650 -> C116B0: malloc(872)
                          +-- NULL -> CB2BA8 -> 987C84 frontier
                          +-- non-NULL -> 6534BC -> 6534E8 frontier

separate proven cutpoint 9F735C, low32(X0)=471C:
  9F7368 writes marker=1 -> table[97FB] -> C11650
  X9 preserves full X0; earlier path into 9F735C remains unknown
```

The `A035F0` fragment stores incoming X4 at SP+26C0. The later load is `0x10064FFCC`, followed by dereference `0x10064FFD0`. The zero route selects X19 from original slot `0x10103DE38`, index07E9, target `0x100B280C8`, IA/56F7. Its later invocation is not established here. The retained removal execution enters the same lazy gate with W22=0817 and loads callback `0x100B353A4` from slot `0x10103DFA8`. W22=40C7 belongs to a separate source-proof fixture; it was incorrectly described here as executed removal state before the [predecessor investigation](daemon_creation_predecessors_report.md) checked the actual source journal. The new source proof covers all u64 cell values while retaining W22=07E9. These incoming-state distinctions prevent treating shared code as one recovered function contract. [CR4,CR6,CR10]

Original `0x1009F7368` writes a byte value 1 through X15. Its table index is `u32(W0+0x50DF)`, so selecting index97FB requires low32(X0)=471C. `0x1009F7370` preserves the full X0 in X9. Only the incoming phase requirement and forward source effects are proved; the marker's native storage address, prior owner, and path into this setter are unknown. Six literal `MOV X17,#E9B9; BRAA` pairs are retained in the original-text census. Computed modifiers and alternative branch sequences are excluded. IDA reports a single data xref into C11650 from slot101085EC8 and no direct xref to the slot; absence of static xrefs does not exclude dynamic callers. [CR2,CR8,CR9]

| Saved frame offset | Source restoration/use | Declared private value or role |
|---|---|---|
| +2A88 | A0366C -> X28 | Readable u32 controller owner |
| +2A90 | A03670 -> X23 | Second readable u32 controller owner |
| +2978 | A03674 -> X24 | 0x100FC4230 |
| +2980 | A03678 -> X25 | 0x101031FA0 |
| +2990 | A0367C -> X14 | 0x100F4E390 right byte bank |
| +2998 | C11678 -> X10 | 0x100E99A00 left byte bank |
| +29A0 | C116B4 -> X30 | TABLE after the modeled malloc return |
| +2970 | 9C585C -> X13 | Opaque private 0/FF backing; unconsumed before zero-route frontier |
| +26C0 | A03610 stores X4; 64FFCC loads it | Pointer to readable 8-byte cell |

Under these roots, the allocation dispatch reduces to table indexCC0D for all 256 possible low-byte bank inputs. Original slot `0x10109FF58`, word `0xC0086AA40000008C`, is an authenticated import of `_malloc` from `/usr/lib/libSystem.B.dylib`, IA/6AA4/ad=0, import ordinal140 and addend0. Source `0x100C116A8` supplies W0=0x368, requesting **872 bytes**. The aligned literal `MOV W0/X0,#872` census has one match in the original text; computed allocation sizes are excluded. [CR1,CR5,CR7]

The allocator prologue produces W19=`u32(Q-0x2745)` and W20=`u32(Q+0x3934)`. For return pointer R, the post-call index is:

```text
f = ((u32(Q-0x2745) XOR (R==0)) & 1)
J = u32(Q+0x3934) XOR (56*f)
```

For Q=471C, W19=1FD7 and W20=8050:

| Outcome | Index / slot | Target / IA modifier | Verified local effect |
|---|---|---|---|
| R!=0 | 8068 / 0x10107A230 | 0x1006534BC / D254 | C116B8 saves R at SP+2C08; 6534BC saves R at SP+2A68 |
| R=0 | 8050 / 0x10107A170 | 0x100CB2BA8 / D254 | Writes raw74C29F35 at SP+3554 and SP+2F94, zero at SP+3580, byte0 at SP+30E7 |

Success cases stop before `0x1006534E8` reads SP+3620, whose native producer is unknown. None of the 1,024 successful/failed allocation cases writes into the candidate object payload before its frontier. The NULL path next selects slot101049DA8, index1FD7, IA/1B02, target987C84, where this increment stops. Raw74C29F35 XOR8B3DC651 equals u32FFFF5964, signed32 -42652; an error name and final returned result remain unknown. [CR7,CR11]

Two rejected shortcuts are retained as falsification evidence. Choosing S=62AE merely to select the allocator with marker0 supplies Q=5031; NULL and non-NULL result slots then carry IA/30A0 and IA/0B49, rather than required D254. The logical edge is rejected before execution in both cases. Also, adjacent non-NULL selectors at the previously recovered A59BB4 entry have different original PAC metadata: selector471C selects4730/BB7D, whereas471D selects4731/F964,471B selects4737/00D6 and471E selects4732/A97C. Neither arbitrary phase forcing nor numeric selector adjacency establishes a valid constructor API. [CR8,CR9]

No new incoming/outgoing Mach right, message ID, IOKit selector, or Mach emission location is established. The byte marker, saved frame, callback, local result fields and malloc boundary are process-local interfaces. Their link to the historical RAX trace and to kext request processing is unknown. Equal 872-byte allocation and overwrite extents are a candidate data-flow relation; object identity requires pointer continuity through publication. [CR12]

Validation covers 10 original spans,160 original fixups,256 bank inputs,256 marker bytes,seven phase candidates,six literal discriminator/branch pairs,15 source-proof pairs/30 persisted UNSAT queries,15 freshly rebuilt obligations and105 lifted instructions. Independent Unicorn execution covers1,294 persisted private cases and100,000 source visits; the checker recomputes every case, then checks four additional cases/286 visits. The two instruction engines are the source bitvector lift and Unicorn; replaying a case again is a freshness check, not a third engine. Three fresh IDB ranges cover456 raw bytes and106 display rows, including four undecoded single-byte rows. Original raw bytes are authoritative; IDA function boundaries and display rows do not establish semantic ownership. No native target, allocator, PAC or IPC executes, and no IDB is mutated.

Reproduce with the pinned local Python/Z3 environment:

```sh
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_object_creation.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_object_creation.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/replay_daemon_object_creation.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_object_creation.py
```

Complexity is O(original text bytes + fixups + cases*source visits + solver resources) time and O(largest evidence JSON + one private emulator map) space. Each solver query has a30 s timeout. Bitvector identities are universally quantified by counterexample exclusion; private execution is finite. Bytes, bits and instruction counts have distinct units; no timing or native performance claim is made.

| Impact | Bounded continuation | Evidence that would resolve it |
|---|---|---|
| High | Actual A035F0 predecessor and marker owner | Continuous source path producing W8=621B,X15 and saved roots, without changing internal phase to force allocation |
| High | Allocation initialization and registry publication | Native/source pointer continuity from C116B8/6534BC through object field writes into the earlier key/payload arrays |
| High | Marker/lock ordering | Identify all writers and the actual lock/once owner covering both marker reads and allocation/publication |
| Medium | Callback B280C8 and possible reset semantics | Establish its invocation and actual pointer owners before interpreting the three zero stores |
| Medium | Constructor-to-request association | Trace actual callers to Mach/MIG/IOKit records and corroborate with historical trace PCs; numeric phase alone is insufficient |
| Low | Alternative marker aliases | Establish whether20/21/E0 are reachable native states and whether their continuations have coherent saved frames |

QG1 passes for factual source analysis. QG2 is covered by CR1-CR12 and their falsification probes. QG3 passes for this bounded increment; the full objective remains active. QG4 covers u8/u32/u64 modular arithmetic,872-byte extent and explicit complexity/solver bounds. QG5 distinguishes internal phase, stable-marker premises, callback identity, local failure fields, candidate object identity and native gaps. QG6 uses pinned original bytes/fixups,read-only IDB outputs,source proofs and finite A64 cases with separate provenance. QG7 retains the impact-bounded continuations above. Machine-readable scoped gates are issued after semantic checks and preservation pass.
