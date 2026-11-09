# Daemon IOKit error normalization and returning cleanup

The three former IOKit error frontiers call the same internal adapter `0x100422A60`, which normalizes a signed 32-bit status and writes its XOR-encoded result through a destination pointer. All 68 preceding error-frontier cases now complete selected source cleanup and outer result publication. The shared routine's decoded output lies in the inclusive interval -49998 through -42001 and is idempotent under repeated normalization. These are original-source and private-model conclusions; native API behavior, synchronization-object lifetime and the upstream interpretation of the result remain unknown. [DE1-DE12]

[Original contracts](triage_evidence/daemon_iokit_errors_contracts.json), [retained profiles](triage_evidence/daemon_iokit_errors_profiles.json), [independent checks](triage_evidence/daemon_iokit_errors_checks.json), [source proofs](triage_evidence/daemon_iokit_errors_proofs.json), [current IDB windows](triage_evidence/daemon_iokit_errors_live_ida.json), [preservation](triage_evidence/daemon_iokit_errors_preservation.json) and [scoped gates](triage_evidence/daemon_iokit_errors_quality_gates.json) retain evidence. The [synchronization report](daemon_iokit_sync_report.md) supplies the selected full-entry/acquisition/common-cleanup contract; its prior error boundaries are extended here. The full interface objective remains active.

```text
IOMainPort nonzero ---------------------+
                                      |
GetMatchingServices nonzero -----------+--> status adapter
                                      |      -> write encoded result at F+60
Open nonzero -> release service -------+      -> return
                (saved status retained)         |
                                                +-- main/matching -> common cleanup
                                                +-- Open -> release iterator
                                                             -> common cleanup
common cleanup -> shared once -> conditional unlock
               -> publish raw result at input+4 -> outer return
```

F is SP after the outer 0x130-byte allocation. The error record R=F+0xA8 is 8-byte aligned. B denotes bytes. All arithmetic is exact modular u32/u64; comparisons on status use signed two's-complement int32 unless explicitly unsigned. Addresses are preferred file virtual addresses.

## Assumption register

| ID | Assumption or bound | Dependent result | Stress test or falsification probe |
| --- | --- | --- | --- |
| DE1 | Pinned daemon images and current IDB identify this build | Addresses, original source and imports | Rehash originals; compare 579 current IDB rows and 13 original spans |
| DE2 | Selected full entry has the preceding 0x5784/09 input/state premises; Open path has a nonzero returned service | Full compositions | Preserve prior source/epoch prefixes; vary external statuses and trace other entry/state branches separately |
| DE3 | IOKit and pthread results/effects are the explicit frozen private summaries | Finite source execution and returning cleanup | Compare exact formal arguments/output provenance; native errors, blocking and ownership effects remain unknown |
| DE4 | Original banks/fixups provide the declared internal targets | Three adapter calls and internal status routing | Exhaust all 256 inputs for four banks; independently decode 85 original fixups; native authentication remains unproved |
| DE5 | Local record/destination/frame/controller cells do not interfere and record is 8-byte aligned | Caller/callee codecs and indirect result store | Quantify arbitrary aligned record addresses in source proofs; vary two private placements; trace native aliases before composition |
| DE6 | Primary/fallback pointer fixtures remain stable, and once state is explicit | Source-selected write-lock/unlock and callback composition | Retain all 20 preceding pointer/once controls; trace actual cell writers and runtime lifetime separately |
| DE7 | Error adapter is entered with decoded control 0x952A | Closed status dispatcher | Prove all three caller record layouts and callee decoding; different controls may select other fragments |
| DE8 | Status is an arbitrary u32 interpreted as signed int32 within the adapter | Universal normalization formula | Source-derived SMT obligations cover all 2^32 words; finite cases include boundaries, all positive 1..99 and deterministic random words |
| DE9 | External calls return; source guards are stable and PAC/RETAB are explicitly abstracted without source-byte changes | Selected returns and restored integer registers/SP | Source byte checks and private restoration checks; native faults, authentication and nonreturning calls remain unknown |
| DE10 | Prior notes are conditional leads, not current/native proof | Comparison with earlier findings | Preserve six note texts/hashes; independently lift current bytes and execute full selected predecessors |
| DE11 | Decoded code means `raw XOR 0x8B3DC651` algebraically | Compact normalized representation and idempotence | Trace upstream consumers before assigning semantic error names or assuming every caller applies this decoder |
| DE12 | Scope covers the three selected error origins, adapter and returning cleanup | Role and lifecycle claims | Recover upstream outer-entry callers, other adapter controls/callers and native lock initialization before claiming complete lifecycle |

## Compact routine semantics

Let s be signed32(status_u32), M=0x8B3DC651, and C(s) the algebraically decoded result. The source-derived contract is:

```text
C(s) = -42600 - s,   if 1 <= s <= 99
       s,            if -49998 <= s <= -42001
       -42600,       otherwise

*destination_u32 = u32(C(s)) XOR M
```

This algorithm uses O(1) time and O(1) auxiliary space. The source implements it through obfuscated arithmetic and authenticated table branches; no machine instruction sequence was replaced by this formula during private execution. [DE4,DE7-DE9]

| Input class | Decoded output | Raw stored output | Exact u32-domain cardinality |
| --- | --- | --- | ---: |
| Signed 1..99 | -42600-s | `u32(-42600-s) XOR M` | 99 |
| Signed -49998..-42001 | s | `status_u32 XOR M` | 7998 |
| All other values | -42600 | 0x74C29FC9 | 4294959199 |

The interval count is `-42001 - (-49998) + 1 = 7998`; the complement is `2^32 - 99 - 7998 = 4294959199`. The three classes sum to 4294967296. These cardinalities describe the adapter's all-u32 mathematical domain. Status zero is in its default class, but all three selected IOKit error callers enter only after a nonzero-status predicate; isolated zero cases do not establish a native zero-status adapter call. [DE2,DE8]

Every decoded output lies in the 7998-code negative interval. Positive inputs map to codes -42601..-42699 already present in that interval, and the default -42600 is also present. Consequently C(C(s))=C(s), and the decoded mapping projects all u32 inputs onto this interval. Separate source-derived SMT obligations verify the interval and idempotence. This supports a status-normalization role; POSIX/IOKit/FairPlay error-name assignments remain unknown. [DE8,DE11]

For positive 1..99, the prior expression `(s+0x67) XOR 0x74C29FAE` equals the raw formula above. Its range restriction is retained. The earlier negative-window and positive-result notes agree with the current universal source proof and full selected compositions. [DE10]

## Call sites, record ABI and result flow

| Origin | Error fragment | Call PC | Original call slot / modifier | Returning continuation |
| --- | --- | --- | --- | --- |
| IOMainPort nonzero | 0x10062FB74 | 0x10062FC68 | 0x1010A1490 / IA 0xD3F1 | Common cleanup 0x100383B00 |
| IOServiceGetMatchingServices nonzero | 0x100318CC0 | 0x100318D98 | Same slot / modifier | Common cleanup 0x100383B00 |
| IOServiceOpen nonzero | 0x1004BDB24 | 0x1004BDC5C | Same slot / modifier | Iterator release 0x100483C6C, then common cleanup |

All three calls pass X0=R and resolve to 0x100422A60. Their distinct exhaustive bank rules produce the same index 0xCEB4 and same authenticated slot. The adapter's dispatcher root independently resolves to table 0x101039EF0. [DE4]

The source-derived status selectors compose through these independently decoded original routes. They are local table indices, not Mach message identifiers. [DE4,DE7]

| Index | Original slot | Target | IA discriminator |
| --- | --- | --- | --- |
| 0xB4F0 | 0x101094670 | 0x10011959C, nonpositive split | 0x6607 |
| 0x952A | 0x101084840 | 0x1001DDC64, negative/large split | 0x6607 |
| 0x94E0 | 0x1010845F0 | 0x1002CB160, positive result | 0x6607 |
| 0x6C14 | 0x10106FF90 | 0x100202E14, 256 split | 0x36BD |
| 0x6C4C | 0x101070150 | 0x1000D44AC, -42000 split | 0x36BD |
| 0x8201 | 0x10107AEF8 | 0x10013B168, store default | 0x36BD |
| 0x1E29 | 0x101049038 | 0x10004E43C, prepare default | 0xF547 |
| 0x3D3A | 0x1010588C0 | 0x10003B414, -49998 split | 0xF547 |
| 0x1E25 | 0x101049018 | 0x10013B168, store selected word | 0xF547 |

| Error-record offset | Type / width | Source value |
| --- | --- | --- |
| +0 | Pointer u64 / 8 B | Address F+0x60, the outer raw-result cell |
| +8 | Encoded status u32 / 4 B | `u32((status_u32 XOR M) - K)` |
| +0x0C | Encoded control u32 / 4 B | `u32(0x952A + K)` |

The shared key is `K=u32((low32(R) XOR 0x8515CFBD)*0xC7F6DCA7)`. Source-derived caller prekeys are equal to the callee prekey under the record-alignment premise. All 16 record bytes are initialized by original caller stores in composed cases. Isolated records use explicit fixture provenance. [DE5,DE7]

Open's status survives the intervening service-release API call through the source-saved value `W27=u32(status_u32+0x6C3D1923)`. The error caller decodes this arithmetic form into the shared record; it does not use the service-release return as the Open status. Source proofs cover arbitrary u32 status, not only sampled low values. [DE3,DE8]

The adapter allocates 16 B, updates controller cells, decodes status/control, and branches through the original shared dispatcher. Final store/return fragment `0x10013B168` loads the full destination pointer from `[X0]`, stores W10 through it, restores SP by 16 B and returns to the original caller. The later common cleanup reloads the same F+0x60 result; `0x100336FCC` publishes it at outer input+4. All 224 composed cases restore outer X19-X29 and SP. [DE5,DE9]

For adapter SP H after its 16 B allocation and source-loaded controller values A/B, let `D=u64(A+B+(H+8))`, `m=0x0A5CD4CF`, and `t=0x73D046208EAED1A6`. Source stores at 0x100422AA8/0x100422AAC write:

```text
[0x1010C52D8] = u64((D*m) XOR t)
[0x1010C4670] = u64((D XOR t)*m)
```

These controller writes execute as original source; the model supplies no API write to the result cell. [DE3-DE5]

## Cleanup, ownership requests and existing result channels

| Error origin | Requested IOKit operations on selected returning path | Excluded from this source path |
| --- | --- | --- |
| MainPort | MainPort call, status adapter, common synchronization cleanup | Dictionary construction, iterator/service operations, metadata queries |
| MatchingServices | MatchingServices call, status adapter, common synchronization cleanup | Iterator read/release, service Open, metadata queries |
| Open | Open, service release, status adapter, iterator release, common synchronization cleanup | Metadata selectors 22/23 |

These are exact source call sequences, not native reference-count or ownership-transfer proof. Matching failure's unproduced iterator cell is not read on this path. Open failure still requests release of the returned service before normalizing the saved Open status, then requests iterator release after normalization. API failure-output ownership and actual resource effects require separate native evidence. [DE2,DE3,DE9]

The same algebraic decoder clarifies earlier raw source words without assigning upstream semantics:

| Existing source result | Raw word | `signed32(raw XOR M)` | Bound |
| --- | --- | ---: | --- |
| Initial outer result | 0x8B3DC651 | 0 | Default selected-entry word |
| Null dictionary / generic normalized default | 0x74C29FC9 | -42600 | Distinct source producers, same raw output |
| Zero IteratorNext result | 0x74C29C07 | -42410 | Does not distinguish exhaustion from invalid iterator |

The shared adapter normalization, outer publication and earlier wire-scalar XOR convention now have an exact algebraic connection. Actual consumer decoding and semantic error labels remain unknown. [DE11]

## Verification

The 224 full-entry profiles include all 68 preceding stopped error cases, 24 preceding return controls, and 132 added cases spanning 22 status boundaries, three error origins and two placements. Placement also varies completed-once state in the added cases; the original 20 pointer/once controls remain among the preceding controls. All 92 preceding instruction/read/write/edge/API prefixes are retained exactly.

The 748 isolated profiles cover 374 distinct u32 values at two record placements: zero, every positive 1..99, the explicit boundary set, and 256 deterministic random words. All 972 profiles undergo independent source-byte and read/write epoch reconstruction; 16 full-entry and 16 isolated profiles are freshly replayed. The 200 adapter calls return and preserve their source-produced result through outer publication; the other 24 full cases retain the preceding returning behavior.

Twenty-nine original/simplified proof pairs cover 440 lifted instructions across declared source phases, including an all-u32 composed formula, output interval and idempotence. Thirteen original spans, four exhaustive banks, 85 independently decoded fixups, six preserved prior notes and 579 current IDB instruction rows provide separate provenance. The existing typed IOKit/pthread contracts remain frozen dependencies; no new external call model is introduced.

| Checked class | Count |
| --- | ---: |
| Full / isolated source instruction visits | 312977 / 173368 |
| MainPort / matching / Open error returns | 68 / 76 / 56 |
| Isolated positive / passthrough / default cases | 198 / 8 / 542 |
| Former error frontiers closed | 68 |
| Fresh replays | 32 |

Native daemon, IOKit, pthread, Mach and hardware PAC operations do not execute. Source selected returns, private primitive/API effects and native applicability remain distinct. Preservation covers 2543 preceding artifacts, with 2537 unchanged and exactly six designated existing report/index edits; all three original supplied inputs retain their hashes.

## Bounded continuation opportunities

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High | Original callers of 0x1004601D0 and consumers of input+4 | Trigger, record ownership, actual result decoder and error semantics |
| High | Writers of primary/fallback cells 0x1010C8240 / 0x1010B9638 | Native lock construction, replacement and lifetime |
| High | Other controls and incoming calls to 0x100422A60 | Whether the proven status map is shared by other architectural interfaces |
| Medium | Other source emitters/consumers of -49998..-42001 and -42600 | Internal error namespace boundaries and intentional collision classes |
| Medium | State-byte09/0A and connection-cell writers | Cache reinitialization, failure recovery and retained connection semantics |
| Medium | Native observation of API error outputs and releases | Ownership effects beyond source-requested operations |

No additional incoming/outgoing Mach port, right disposition or emission location is established here. Local status controls, keys, controller cells and result pointers are daemon-internal interfaces.

## Quality gates and reproduction

QG1: factual analysis. QG2: DE1-DE12 include dependent results and falsification probes. QG3: the three selected error continuations, shared status map and returning cleanup are covered; full objective incomplete. QG4: widths, byte extents, modular/signed arithmetic, exact cardinalities and complexity are explicit. QG5: nonzero caller guard versus isolated zero, source versus native ownership, saved Open versus release status, and algebraic versus semantic decoding are distinguished. QG6: original bytes, fixups, current IDB, preserved leads, source proofs and finite evidence have separate provenance. QG7: bounded continuations have impact labels. Scoped gates are issued after verification and preservation checks pass.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_iokit_errors.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_iokit_errors.py
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_iokit_errors.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_iokit_errors.py
```
