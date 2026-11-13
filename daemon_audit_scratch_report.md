# Daemon audit-token scratch component and PID-extraction boundary

The continuation selected by the [notification-failure report](daemon_notification_failure_report.md) reaches an audit-token preparation component. Its saved pointer is locally defined: `0x1007019b0` saves entry X26 into S+`0x9b8`. All 84 retained contexts preserve that definition and stop at `0x1006e6148`, before reading the undefined eight-byte scratch cursor at S+`0x16d0`. The entry X26 value is a declared caller fixture; its native origin remains unknown. [AS1-AS4]

Separate, explicitly declared component entries establish a 1,056 B scratch reservation, a complete u64 pointer-null gate, cursor restoration on null, and a source-first 32 B copy followed by a pending `audit_token_to_au32` call requesting only PID output. These entries do not fill the retained cursor or close the earlier provider gap. [AS2-AS5]

```text
Retained notification-failure caller boundary: 0x1006cdaf8
  -> saved X26 from S+0x9b8
  -> 0x1006e6114: three continuation/view stores
  -> STOP at 0x1006e6148: undefined u64 cursor, S+0x16d0

Separate component, pointer and cursor supplied explicitly:
  R = u64(S + 0xc070 + cursor); cursor += 0x420
  saved pointer == 0
    -> 0x10079af48: cursor -= 0x420; W28 = 0x74c29d88
    -> saved continuation 0x1006f7720 (STOP)
  saved pointer != 0
    -> 0x100810154: initialize output pointer/status cells
    -> 0x1008101d0: local copy(source, R, 32)
    -> STOP at 0x100810240: audit_token_to_au32(..., PID_out, ...)
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| AS-A1 | The pinned original daemon and unchanged parent receipts identify the source. Every address claim depends on this identity. | Rehash source, generator, auditor and dependencies; compare original instructions and decode original format-12 pointer words. Matching native build/provider/task identity remains unknown. |
| AS-A2 | Retained boundary state is reconstructed from the parent registers, flags, SP, defined private fixtures and ordered private writes. Retained suffix claims depend on that state. | Check exact register/flag/SP equality and equality of every reconstructed defined private byte; fail before any undefined private read. Preserve all eight undefined cursor bytes in every one of 84 contexts. The parent provider cut remains explicit. |
| AS-A3 | Separate component cases have a stable SP, readable token fixtures, declared cursor and source-compatible table/bank roots. Conditional component execution depends on these premises. | Check two placements, two controller pairs, two cursors, null and all eight source alignments; invert backing/token patterns and replay independently. No native caller admission follows. |
| AS-A4 | Address equations use modular u64 arithmetic; cells in the symbolic source interface denote separate declared inputs. Pointer/view equations depend on this model. | Prove reservation/restoration for arbitrary u64 SP/cursor; keep valid native bounds, alignment, readability, ownership and overlap unknown. Finite copy fixtures have disjoint source/destination regions. |
| AS-A5 | Authenticated edges are interpreted using the original normalized target and exact IA diversity. Local control flow depends on those exact slots. | Decode eight original words and compare each replayed authenticated edge; separately retain saved-continuation provenance. No hardware authentication executes. |
| AS-A6 | Current Darwin arm64e declarations identify the by-value audit-token call arrangement. The PID-output interpretation depends on this ABI comparison. | Compile exact size/type assertions and a matching nine-argument call to assembly. Historical SDK and runtime libbsm identity remain unknown; the API never executes. |
| AS-A7 | The whole-text census is syntactic, within its stated direct-SP scope. Candidate counts depend on that scope. | Decode all aligned words whose base-field bits equal 31 and inspect fixed-immediate SP overlaps. Computed aliases, register indexing, other sections and equality of different SP epochs remain excluded. |
| AS-A8 | Only the owned increment is published. Preservation and publication claims depend on the exact delta. | Check logical manifest/input preservation, archive round trips, explicit staged/committed paths, and raw/typed/decoded-payload path hygiene. |

## Reservation, views and null restoration

At `0x1006cdaf8`, retained W19=`0x79ea` yields W8=`0x6cf4`, continuation index W11=`0x5e`, and branch index `0x2895`. X0 receives the u64 value stored at S+`0x9b8`; X9=S+`0xf0c`; X10=S+`0x7820`. The original branch reaches `0x1006e6114`. The saved pointer is an eight-byte value, and its later comparison tests all 64 bits. [AS2-AS4]

Let U be the separate entry cursor and R=`u64(S+0xc070+U)`. The reservation component performs five stores before its null-dependent branch. [AS2-AS4]

| Cell | Width | Original writer | Value |
| --- | --- | --- | --- |
| S+`0x4ec8` | 8 B | `0x1006e6134` | Saved continuation `0x1006f7720`, loaded from table index `0x5e` |
| S+`0xa7f8` | 8 B | `0x1006e6140` | S+`0x7820` |
| S+`0xa800` | 8 B | `0x1006e6144` | S+`0xf0c` |
| S+`0xa808` | 8 B | `0x1006e615c` | R+`0x20` |
| S+`0x16d0` | 8 B | `0x1006e6164` | `u64(U+0x420)` |

The retained contexts execute only the first three stores before the undefined-cursor stop. Separate component controls execute all five. The increment `0x420` equals 1,056 B; it describes local cursor bookkeeping, not an allocator call or a proven native arena extent. W23 becomes `0x86a`; the null selector reduces exactly to index `0x6a27` for X0=0, otherwise `0x6a1f`. [AS2-AS4]

The null body at `0x10079af48` subtracts `0x420`, stores the cursor at `0x10079af50`, sets W28=`0x74c29d88`, reloads the saved continuation and branches to `0x1006f7720`. Modular restoration is proved for every u64 U. It does not clear the saved view cells. There is no allocation/free or Mach operation in this branch. [AS2-AS4]

## Nonnull copy and BSM call interface

The nonnull body clears the u64 output-pointer cell S+`0x7820` at `0x100810158` and initializes the u32 status cell S+`0xf0c` to `0x8b3dc651` at `0x100810164`. It then selects the local helper using two 256-byte banks. For every selector byte x, `x XOR right[left[x] XOR 0x78] == 0xa1`; index `0xcb12+0xa1` is `0xcbb3`. The original target is `0x10046f89c`, not an imported memcpy symbol. [AS2-AS4]

Call `0x1008101d0` supplies X0=saved pointer, X1=R and X2=32. The helper loads from X0 and stores through X1. Eight additional byte-addressed source proofs retain 32 arbitrary byte variables and verify all 256 input bits at the destination, once-only reads/writes of each byte, payload-independent control, exact original branch order and return to `0x1008101d4`. They cover every source alignment modulo 8 with an aligned, disjoint destination. Broader lengths, overlap behavior and all destination alignments are outside this increment's copy proof. [AS2, AS4]

After the copy, the second bank identity is `x XOR right[left[x] XOR 0xf3] == 0x43`; index `0xcc7f+0x43` is `0xccc2`. Its original auth-bind names `libbsm/_audit_token_to_au32`. The source uses different controller mixes for the two selections: `u32(((C0 XOR C1) XOR 0xa6)*0x0a5cd4cf)` for the copy and `u32(((C1-C0) XOR 0xa6)*0x0a5cd4cf)` for BSM. Source proofs cover both byte-bank addresses, index expressions and call registers for all u32 controller values; the exhaustive bank identities then fix the targets. [AS2-AS4]

| API parameter | Machine location | Established value |
| --- | --- | --- |
| By-value `audit_token_t` | X0, indirect ABI carrier | R, holding the copied 32 B |
| `auid`, `euid`, `egid`, `ruid`, `rgid` output pointers | X1..X5 | NULL |
| `pid` output pointer | X6 | S+`0x571c`, a 4 B signed `pid_t` under the compared SDK |
| `asid` output pointer | X7 | NULL |
| `tid` output pointer | 8 B stack slot at SP | NULL, stored at `0x100810214` |
| Pending import | `0x100810240` | Original slot `0x1010a0500`; IA diversity `0xdc55` |

The current SDK compile verifies `sizeof(audit_token_t)==32`, four-byte token words and signed four-byte `pid_t`, plus the complete void-return prototype. Generated arm64e assembly passes the token indirectly and puts the ninth pointer on the stack, matching the recovered call shape. This does not substitute an implementation for libbsm. The component does not initialize S+`0x571c` before the import; the PID value and all later PID consumers remain unknown here. A PID is a process identifier, not a time, count, port name or port right. [AS4-AS5]

## Exact slots and conditional continuation

| Role | Index | Original slot | Normalized target | IA diversity |
| --- | --- | --- | --- | --- |
| Reservation entry | `0x2895` | `0x10104e398` | `0x1006e6114` | `0xafb5` |
| Saved continuation | `0x5e` | `0x10103a1e0` | `0x1006f7720` | `0xb335` |
| Nonnull branch | `0x6a1f` | `0x10106efe8` | `0x100810154` | `0xb6fd` |
| Null restoration | `0x6a27` | `0x10106f028` | `0x10079af48` | `0xb6fd` |
| Source-first copy | `0xcbb3` | `0x10109fc88` | `0x10046f89c` | `0x34a1` |
| PID-extraction import | `0xccc2` | `0x1010a0500` | `libbsm/_audit_token_to_au32` | `0xdc55` |
| Conditional equal-result continuation | `0xa424` | `0x10108c010` | `0x1006936f0` | `0x4113` |
| Conditional other-result continuation | `0x7a10` | `0x101076f70` | `0x100709868` | `0x4113` |

An additional separate source slice classifies `0x1006f7720`: conditional on S+`0x9d0`=`0x6cf4`, W28=`0x8b3dc651` selects index `0xa424`; every other u32 result selects `0x7a10`. Therefore the null component's W28=`0x74c29d88` would take the latter branch under that extra phase premise. The retained contexts do not establish this phase cell or reach that gate; no new continuous caller-to-IOKit path is claimed. Modifier equality alone is not target evidence. [AS2-AS4]

## Direct-access census and emission accounting

The original text is 14,849,960 B: 3,712,490 aligned instruction words. The census decodes 355,213 words with base-field bits 9:5 equal to 31, then examines explicit fixed-immediate SP operands and overlapping widths. It retains 1,648 accesses overlapping S+`0x9b8` (365 stores), and 956 overlapping S+`0x16d0` (496 stores), with no unclassified nearby widths. These are candidates across different SP epochs. Their number precludes treating a numeric stack offset as a global field identity or unique reaching definition. The one reaching definition claimed here is supported by the ordered retained write ledgers. [AS2, AS4]

The new source traces contain one local copy call on each nonnull component path and stop before BSM. They contain no Mach send/receive, IOKit call or port-right operation. No incoming/outgoing port identity, port-right disposition, port creation or message-emission location is established by this increment. Token contents, environment-helper readiness and scratch views do not themselves establish a daemon-kext transaction. [AS2-AS4]

## Provenance and verification

| ID | Primary evidence and role |
| --- | --- |
| AS1 | Original thin daemon SHA256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred virtual addresses throughout. |
| AS2 | [Extractor](triage_evidence/recover_daemon_audit_scratch.py) and [checks](triage_evidence/daemon_audit_scratch_checks.json.zst): original source/fixups/banks, direct-SP census, retained-state reconstruction, component traces and eight source obligations. |
| AS3 | Unchanged [notification-failure evidence](triage_evidence/daemon_notification_failure_checks.json.zst) and [audit](triage_evidence/daemon_notification_failure_audit.json.zst), including the separate provider cut and caller-boundary state. |
| AS4 | [Independent auditor](triage_evidence/audit_daemon_audit_scratch.py) and [audit](triage_evidence/daemon_audit_scratch_audit.json.zst): byte-addressed instruction/effect replay, reconstructed-state equality, eight symbolic copy proofs and compile-only ABI comparison. |
| AS5 | Current Darwin SDK `bsm/libbsm.h` and generated arm64e assembly, with exact source, assembly and relative-header SHA256 values retained in AS4. Historical SDK/runtime implementation pairing is unknown. |
| AS6 | [Publication verifier](triage_evidence/verify_daemon_audit_scratch_publication.py): exact owned delta, source/receipt pins, manifest and original-input preservation, archive round trips and raw/typed/decoded-payload path hygiene. |

The 72 component cases cover two SP placements, two controller pairs, two cursor values and nine pointer classes (null plus all eight byte alignments). Together with 84 retained contexts they record 14,632 original source visits, 3,852 reads, 2,636 writes and 364 logical edges. Independent replay adds alternate backing/token patterns for every component: 228 lifts check 27,080 visits, 873,856 register values including SP, 27,308 NZCV values, 27,552 read bytes, 14,560 write bytes and 516 authenticated edges against original pointer words. All pass. [AS2-AS4]

Eight nonvacuous source equations and eight arbitrary-token copy queries are UNSAT. The copy slices contain 43 original visits for source alignment zero and 86 for each other alignment. The current SDK compile succeeds. Exact bytes, finite replay, full-width algebra and ABI comparison retain distinct scopes; none is a native transaction observation. [AS2-AS5]

The fixed component and 32 B copy use O(1) work and scratch bookkeeping per invocation. Extraction/auditing use O(N+C*(I+E)+Q) time/space in text words N, case instruction visits I, recorded effects E and query count Q; solver resources are separate, with a 30 s/query limit. Large JSON is archived with zstd level 22 and exact decompression checks. [AS2, AS4, AS6]

## Bounded continuation

| Impact | Open question | Evidence required |
| --- | --- | --- |
| High | Cursor producer and arena validity | Same-SP-epoch reaching definition of S+`0x16d0`, original reservation nesting, bounds and all intervening overlapping writes; keep the retained cursor undefined until then. |
| High | Native entry X26/token origin | Admission and lifetime chain to the saved X26, readable 32 B backing and original request identity; copied token shape alone does not prove a kernel-authenticated source. |
| High | BSM return and PID consumers | Source continuation from `0x100810244`, PID-cell definition/lifetime and full local result/control equations under an explicitly declared API contract. |
| High | Daemon-kext transaction join | Matching-build task/connection/provider, selectors, buffers, ordered send/return observations and request identity. |
| Medium | Saved-continuation phase | Same-epoch producer/preservation for S+`0x9d0`; the conditional complete result gate must remain separate until joined. |
| Medium | Scratch nesting across earlier reservation | Compare 128 B and 1,056 B reservations using exact cursor epochs and view lifetimes; numerical reuse of the cursor offset is insufficient. |
| Low | Shared audit preparation pattern | Compare this source-first copy/PID-only contract with RPC502 and XPC bridge evidence before assigning a common higher-level policy. |

## Scoped quality gates

**QG1** passes for factual source analysis. **QG2** passes with AS-A1..AS-A8. **QG3** passes for this increment's routine roles, source data/control flow, ABI, environmental boundary and emission accounting; the full goal remains active.

**QG4** passes with exact byte extents, modular u32/u64 operations and explicit complexity. **QG5** passes within scope: the retained cursor is undefined, separate component premises remain separate, and native token ownership/PID value remain unknown. **QG6** passes with original bytes/fixups, sixteen checked queries, independent instruction/effect replay and current SDK primary declarations. **QG7** passes with the impact-ranked continuation table. No native API, IPC, allocation/free, hardware PAC or IDB mutation executes. [AS1-AS6]
