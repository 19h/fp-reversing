# FPSD1200 environment dependencies, seed material and certificate input

The original continuation expands one `arc4random` result into 624 u32 state words, combines two further random results with clock fields, and depends on initialized arena and self-text-window state. Composing retained startup bytes or retained provider state lets the original application code consume all 756 bytes of the reference CoreFP certificate and reach another process-local atomic gate. One explicit scalar continuation reaches `malloc(1219)` at `0x100346714`. No new Mach emission, port-right producer or IOKit call is reached. [FX1-FX8]

This report continues the [pool/application-word analysis](fpsd1200_arena_report.md). It completes one static/private increment; the full daemon-kext-deeper investigation remains active. Previously published finite cases retain their original scope.

## Assumption register

| ID | Assumption / dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FX1 | The pinned thin daemon and matching live IDA spans identify this source. Every instruction/address attribution depends on this identity. | Rehash the thin image, all 594 source spans, 820 original rebases and 29 bind records. Distinguish the IDA input-file metadata hash from selected-byte equality. |
| FX2 | Frozen admission, libbsm identity, CF/Security and once/lock fixtures supply the declared preceding environment. All continuations depend on these premises. | Independently replay original visits, API events, token copies, exact selected library body and callback returns. Native credentials, PAC, library pairing and synchronization remain unknown. |
| FX3 | Explicit private mappings, scalar CASAL semantics and imported API results define a bounded machine. Continuations beyond those boundaries depend on the corresponding fixtures. | Retain pre-execution atomic/import guards; compare GP31/SP/NZCV, old/expected/desired values and terminal state. Do not extrapolate acquire/release or concurrent behavior. |
| FX4 | Random u32 values and a 12-byte timeval output are explicit fixtures; retained Darwin timeval layout is the ABI premise. Seed/material results depend on those values and layout. | Check all 624 seed words for three distinct first seeds, every material word, source operand widths and untouched four-byte padding. Native entropy, wall clock and random distribution remain unknown. |
| FX5 | Startup composition copies retained source-written globals and owned bytes with definedness masks; provider composition copies its declared snapshot fields. Environment results depend on this artificial join. | Reconstruct all 246729 startup global stores independently, compare 31 final spans/2761 bytes, check owner read/write journals and final masks. Native temporal continuity and ownership lifetime are not established. |
| FX6 | Application words and the 756-byte OOL object are controlled input fixtures. Input-consumption conclusions depend on those bytes and counts. | Compare synthetic input with the pinned public DER, request+52 values1/2 and request+56 values0/1/2/3/4; check every OOL read against actual memory. Certificate trust, full authentication and enum names remain unknown. |
| FX7 | Task-local port names, error formatter writes and imported retirement calls do not establish native right movement or message delivery. IPC conclusions preserve that boundary. | Separate incoming port arguments, reply-buffer construction, OOL retirement and actual send/right producers. Match native receive/send and connection lifetime in separate evidence. |
| FX8 | Nineteen finite profiles and one local arithmetic certificate bound the result. Fragment roles do not define complete C functions or arbitrary-state semantics. | Replay 7245815 original instruction visits, exhaustive bank identities and terminal state; retain all unpaired bank observations and stop-before-read guards. Other states, malformed payloads and later constructors remain separate work. |

## Primary provenance [FX1-FX3,FX8]

| Object | Identity / coverage |
| --- | --- |
| Original daemon arm64e slice | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base `0x100000000` |
| Read-only live IDA | Input metadata SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`; all 594 selected code spans match the thin image. The different whole-file hashes remain explicit. |
| Source catalog | 28519 distinct daemon instructions including five guard sites; 114076 bytes. These flattened spans are not asserted function boundaries. |
| Pointer and lookup evidence | 820 rebases, 29 bind records; 17 exhaustive adjacent-bank identities covering 4352 inputs, 14344 observed pair uses and 615 unpaired reads |
| Reference public certificate | Retained [DER](triage_evidence/corefp_fppineboard_certificate.der), 756 bytes, SHA-256 `a0caace76b0db1214f92e89225458e5040d3b92837c03270274ea1a1b359e2de`; extraction provenance in [CoreFP client paths](corefp_client_paths_report.md) |
| Retained context inputs | [Startup profiles](triage_evidence/rpc502_startup_profiles.json.zst), initialized_worker case; [provider snapshots](triage_evidence/daemon_object_initialization_context.json.zst), snapshot0; prior [entropy/ABI contracts](triage_evidence/daemon_entropy_return_contracts.json.zst) |

New artifacts: [source, events and profiles](triage_evidence/fpsd1200_context_checks.json.zst), [fresh IDA readback](triage_evidence/fpsd1200_context_ida_readback.json.zst), [producer](triage_evidence/recover_fpsd1200_context.py), [independent replay/oracles](triage_evidence/audit_fpsd1200_context.py), [exact publication audit](triage_evidence/verify_fpsd1200_context_publication.py). The operation-specific IDA knowledge-store search produced no matching fact. No IDB mutation or native target execution occurred.

## Random-result consumers and clock material [FX1-FX4,FX8]

| Original site / storage | Established local role |
| --- | --- |
| `0x100630448` | Imported zero-argument `arc4random`; first explicit u32 result E1 |
| `0x10063044c` | `STR W0,[X28]`, X28=`0x1010c784c`; writes initial state word |
| `0x10052deec` loop | Generates the remaining 623 u32 words through `0x1010c8208` |
| `0x100405a74` | Imported `gettimeofday(Q+16,NULL)`; explicit result0 and 12-byte output |
| `0x100405a78` / `0x100405aa0` | Read low32 seconds and u32 microseconds from Q+16 and Q+24 |
| `0x100405a9c` / `0x100405ab0` | Store encoded seconds and microseconds at Q+8 and Q+4 |
| `0x100405af4` / `0x100405b20` | Second `arc4random` result E2; store encoded value at Q+12 |
| `0x100405b68` / `0x100405b88` | Third result E3; store encoded value at Q+0 |

All recurrence operations are modulo 2^32:

```text
mt[0] = E1
for i = 1..623:
    mt[i] = 0x6c078965 * (mt[i-1] XOR (mt[i-1] >> 30)) + i
```

This is the standard MT19937 seed recurrence, independently checked against all 624 words in eight snapshots, including E1=0, `0xffffffff` and `0x12345678`. The earlier [entropy-return analysis](daemon_entropy_return_report.md) establishes the same recurrence in another source clone and retains primary libc++/SDK context. The new result joins this clone to FPSD1200; it does not establish a dynamically called libc++ engine, native random distribution or use as a cryptographic primitive. The compact recurrence costs O(624) time and O(624) words of state.

For K=`0xfc564818`, the source arithmetic satisfies, for every u32 x:

```text
x - ((x << 1) AND 0xf8ac9030) + 0xfc564818 = x XOR K

Q+0  = E3 XOR K
Q+4  = microseconds XOR K
Q+8  = low32(seconds) XOR K
Q+12 = E2 XOR K
```

The equality has a retained UNSAT counterexample query. It proves this arithmetic identity only; the source constants, phase-dependent shift and material ordering are checked separately by source replay. This codec differs from the earlier [seed-material report](daemon_seed_material_report.md); its phase constants must not be substituted here.

The sampled clock fields are 1710000000 s and 123456 microseconds, with E1/E2/E3=`0x12345678`/`0x9abcdef0`/`0x0fedcba9`. These are declared values, not measurements. The retained timeval contract has an eight-byte seconds field, a four-byte microseconds field and four padding bytes, total 16 bytes/alignment 8. The fixture writes 12 bytes, padding stays A5, and original code consumes only the stated u32 fields. Raw X1-X7 remnants in zero-argument random API events are register observations, not additional arguments.

## Readiness, arena ownership and self-text context [FX3-FX5,FX8]

| Original source / dependency | Controlled contrast and result |
| --- | --- |
| `0x10047ab28` | Sets X21=0 before readiness-dependent allocation |
| `0x10047ab44` / global `0x1010c5798` | Reads readiness byte; selected phase compares it with low8(`0x4cc+0x8335`)=1 |
| `0x1006303f0` then `0x10049d978` | With readiness0, source publishes the NULL seed base locally; the harness stops before a four-byte read at effective address4 |
| `0x10062826c` | Readiness1 without an initialized descriptor stops before `LDR X15,[X22,#8]` |
| Descriptor `0x1010b5ef0` and eight retained owners | Composed source-written descriptor/owner state supplies a nonnull arena result; every subsequently consumed owner byte is defined |
| `0x10049d9c4..0x10049da00` | Uses encoded window globals; missing globals stop before the computed self-text read |
| `0x1010c6800` | Encodes window mask as `(length-1) XOR 0xfff0c012a7a730ec` |
| `0x1010ca2a8` | Encodes window base as `base XOR 0x12af5504870a589f` |

The [startup analysis](rpc502_startup_report.md) already records the source readiness store at `0x10046c750`. Here, the read is linked to this operation's allocator path. A Boolean readiness patch alone is insufficient: descriptor, owner contents and encoded text-window fields form separate dependencies. The guarded addresses are incomplete-private-environment results; no native fault or vulnerability is asserted.

Provider snapshot0 supplies a 32768-byte window based at `0x100a22058`. The complete retained startup global overlay supplies its own coupled window fields. All 3538 new self-text reads are checked against original image bytes; a window dependency is established, while its complete algorithmic purpose remains unknown.

| Retained startup owner | Extent / initially defined bytes |
| --- | --- |
| `0x5000000000` | 90000 / 3522 bytes |
| `0x5000017000`, `0x5000019000`, `0x500001d000`, `0x500001f000` | 200 / 8 bytes each |
| `0x500001b000` | 960 / 960 bytes |
| `0x5000021000` | 58 / 58 bytes |
| `0x5000023000` | 101 / 101 bytes |

These are private owner identities retained from the earlier source journal. Total extent is 91919 bytes, initially defined 4673 bytes. The independent audit reconstructs the final global overlay from 246729 ordered source-store events into 31 contiguous spans totaling 2761 bytes. It checks 1343 new owner reads, 3995 new owner stores, byte-knownness updates and terminal owner bytes/masks. Snapshot composition does not establish continuous native startup, real allocator ownership, pointer authentication or thread-safe publication.

```text
FPSD1200 admitted + selected pool slot
  |
  +-- request+56 bit 1 clear --> status 8 --> slot marker restored
  |
  +-- request+56 bit 1 set
        |
        +-- cold state --> random/clock material
        |                   |
        |                   +-- readiness / arena / self-text dependencies
        |                   +-- explicit later scalar gate --> input parse
        |
        +-- retained provider/startup state -----------------> input parse
                                                              |
                         synthetic first bytes --------------> error -42018
                         retained 756-byte DER --------------> atomic guard
                                                                |
                                            explicit model ----> malloc(1219)
```

Arrows describe the retained compositions and sampled paths, not a complete native state machine. The entry still depends on the preceding explicit admission, identity, allocation and lock fixtures.

## Externally controlled input and certificate continuation [FX3,FX5,FX6,FX8]

At `0x10037aaa4..0x10037aab8`, original code loads the wrapper's payload+40 copy of request+56, masks it with 2 and compares against the selected phase value 0. Equality selects the status 8 route; inequality continues. Thus the recovered local predicate tests bit 1, rather than equality with a complete operation enum. The independent replay checks both the loaded address and comparison operands. Values 0,1,4 select the original status 8 return; values 2 and 3 continue in these cases. This does not assign semantics to other bits or prove phase invariance across arbitrary native states.

The first OOL reads are byte loads at `0x100315ae8` and `0x10022cb78`, offsets0 and1. Synthetic bytes 00/01 lead to application status `0xffff5bde` (signed32 -42018) after exactly two OOL reads. The retained public DER instead produces 2305 read events covering every offset 0..755. The journal retains all load sites, sizes, values and repeated accesses. This establishes input consumption and further parsing; a complete DER parser reconstruction, trust decision and successful authentication are not established.

The reference CoreFP wire uses request+52=2, request+56=2 and matching OOL counts756 at+40/+60. The cases named word3 deliberately alter +56; they are not the reference client's wire. A separate +52=1 countercase reaches the same guarded source site with the retained DER. Similar endpoints do not establish semantic equivalence of the two application words.

| Retained cases (19 total) | Endpoint / original visits per case |
| --- | --- |
| entropy_boundary | Before first random API result; 19229 |
| time_boundary, seed_zero_time_boundary, seed_max_time_boundary | Before clock API result; 28618 each |
| second_entropy_boundary | Before second random result; 28650 |
| cold_seed_base_guard | Before read at address4; 29077 |
| readiness_only_guard | Before missing descriptor read; 19776 |
| arena_without_window | Before missing self-text read; 33709 |
| arena_with_window_gate | Before `CASAL` at `0x100543cc0`; 379222 |
| arena_with_window_return | Scalar gate fixture, synthetic OOL; status -42018; 827645 |
| provider_word2_der, startup_word2_der, startup_word3_der_gate, word52_1_reference | Before `CASAL` at `0x100466d54`, all 756 input bytes read; 1039908 each |
| provider_word3_synthetic | Synthetic OOL, status -42018; 461911 |
| startup_word3_der_allocator | Two scalar fixtures at `0x100466d54`; before `malloc(1219)`; 1145043 |
| word56_0, word56_1, word56_4 | Original status 8 returns; 18689 each |

Both newly encountered CASAL sites use global `0x1010b5de0`, old/expected=`0x5d96`, desired=`0xa94ef`. The exact source forms are `CASAL W12,W14,[X13]` at `0x100543cc0` and `CASAL W11,W1,[X15]` at `0x100466d54`. Three explicit scalar operations execute across the matrix: one at the former site and two visits to the latter site. Five profiles stop before a later atomic operation. These observations do not establish a native lock implementation or contention behavior.

The final `malloc` import at `0x100346714` receives X0=`0x4c3`=1219 bytes. That site is already associated with the embedded root-CA constructor in the [startup report](rpc502_startup_report.md). This new run joins the OOL/certificate continuation to its allocation boundary. Construction beyond that allocation, native memory return, chain validation and subsequent provider/IOKit calls remain unknown.

## Error cleanup, incoming ports and emission boundary [FX3,FX6,FX7]

All five complete returns use the original 36-byte simple error reply. The application carrier decodes `0x8b3dc659 XOR 0x8b3dc651`=8 or `0x74c29d8f XOR 0x8b3dc651`=`0xffff5bde`. Reply+32 is a status field in this simple layout; it must not be interpreted as such in the earlier 212-byte complex layout.

At `0x100633cb4`, original code restores selected slot0's u32 marker from `0x4577df4a` to `0x4577df49` before each completed error return. This is a local rollback observation; allocation lifetime and a native free are not inferred. No slot-owner read or protected output-region write occurs in these cases.

| Interface location | Established contract / emission distinction |
| --- | --- |
| Incoming stub call `0x10000467c` | The application's incoming port argument is request local name+12; inherited from the [FPSD1200 ABI](fpsd1200_contract_report.md) |
| Demux `0x100004b8c..0x100004ba0` | Reply destination is request remote name+8, reply local name 0, reply ID 1300. These are buffer fields, not a send event. |
| Retirement call `0x10000468c` | On the five completed returns, imported `mig_deallocate(input_address,756)` is recorded; no native release executes. |
| Source `0x100004690..0x100004694` | Original stub clears request OOL address/count after the retirement call. |
| Earlier complex-reply port cell at reply+44 | Still no new output name/right producer. These error routes do not establish a successful complex reply. |
| New continuation endpoints | No new Mach send, connection open, IOKit invocation or right emission was reached. Native endpoint identity and daemon-kext transaction remain unknown. |

## Validation, reproducibility and bounded continuations

The independent auditor imports the frozen arena auditor, never this increment's producer. It reconstructs the declared environment separately, replays every original instruction byte/event and checks all retained GP/SP/NZCV checkpoints, source/global/owner writes, OOL and self-text reads, selected library execution, terminal registers, stack, private, pool and owner bytes. Only the inherited instruction budget is increased to 4000000. The matrix contains 7245454 daemon and 361 library visits, 190 original token-copy calls, 16 modeled random results and eight 624-word seed snapshots. No case ends at the instruction budget or an engine error. [FX1-FX8]

Using an environment with the retained Unicorn, Capstone, Z3 and cache-reader dependencies:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$Z3_PYTHONPATH:triage_evidence" \
  Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/audit_fpsd1200_context.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$Z3_PYTHONPATH:triage_evidence" \
  Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/verify_fpsd1200_context_publication.py
```

The replay costs O(B+F+C*K+R+256*N) time and O(B+F+R) transient space: B is mapped image/evidence size, F is fixup material, C is profiles, K is per-profile machine setup, R is original visits/events, and N is bank identities. Solver cost is separate. All byte counts and modular arithmetic are exact; there is no sampled measurement uncertainty or native timing claim.

| Impact | Bounded next question / falsification target |
| --- | --- |
| High | Continue the source-linked 1219-byte root-CA constructor and certificate-validation return; locate the first actual successful output/provider/IOKit producer. A matching allocation site alone does not close that interface. |
| High | Establish native initialization continuity for readiness, descriptor, owners, cache pointer and self-text window, then match the inbound audit context with receive/send and connection records. |
| Medium | Recover the complete local DER consumer and failure-status semantics; distinguish format rejection, signature/trust decision and environmental failure with source-backed return paths. |
| Medium | Recover later slot-field consumers and marker lifetime; the current rollback gives a state transition but no complete session/client identity. |
| Low | Compare phase-specific seed/material clones structurally; shared recurrence and different codecs do not establish identical whole-function roles. |

**QG1** Pass: factual source/interface analysis; no normative conclusion is required.

**QG2** Pass for this increment: FX1-FX8 enumerate premises, dependent results and falsification probes.

**QG3** Pass for this increment: obfuscated fragment roles, incoming/outgoing port boundaries and data/control/environment context are reported; the full goal remains active.

**QG4** Pass: exact byte extents, u32/u64 arithmetic, signed32 errors, ABI fields and algorithmic complexity are explicit and replayable.

**QG5** Pass for this increment: cold versus composed state, synthetic versus DER input, status versus descriptors, repeated atomic visits and native versus private effects remain distinct. Native completion remains unknown.

**QG6** Pass: pinned source/fixup/library/context/certificate provenance, fresh read-only IDA span checks, independent event replay and one local UNSAT certificate support the bounded claims.

**QG7** Pass: impact-ranked continuation questions are bounded by their explicit evidence gaps.
