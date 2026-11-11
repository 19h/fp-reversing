# AES configuration routing and command emission

Original AppleS8000 AES source now supplies complete scalar operation/selector partitions and bounded command-record contracts beyond the earlier configuration-entry frontier. Selected command emission records a payload u32 in a software ring, advances its cursor, then re-reads that payload location for a version-selected MMIO store. Equal recorded/emitted values require a stable source buffer. These are source/ABI results under declared object, call and register-snapshot premises. No device access, actual key material, successful hardware transaction or daemon/kext pairing is established. [AC1-AC8]

```text
outer command -> hardware quantum -> _configureAES(provider,command,0)
  -> operation partition -> selected key-metadata pointer
  -> selector high-bit handling -> selector partition
  -> path-specific state/size/helper gates [not all closed]
  -> command header + declared payload/IV records
  -> _space_available(byte_count): status snapshot
  -> _push_command(buffer,byte_count)
       -> separate status snapshot / cold-handler boundary
       -> for each u32: software trace -> cursor update -> MMIO store
  -> OSSynchronizeIO on the ordinary IV-command continuation

native configuration acceptance, completion and DMA continuity: unknown
```

Evidence: [original source and certificates](triage_evidence/aes_configuration_commands_checks.json.zst), [extractor/lifter](triage_evidence/recover_aes_configuration_commands.py), [independent scalar and byte-memory interpreter](triage_evidence/audit_aes_configuration_packets.py), and [publication auditor](triage_evidence/verify_aes_configuration_commands_publication.py). Context: [provider admission](aes_provider_admission_report.md), [DMA preparation](aes_dma_preparation_report.md), [quantum binding](aes_quantum_binding_report.md), and [buffer construction](buffer_construction_flow_report.md). Existing construction evidence already conditionally publishes 81920 B of metadata; actual backing and live epoch identity remain open.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| AC1 | The pinned collection, compiler bounds, exact symbols and original pointer chains identify this build. | Rehash and independently decode all eight spans / three slots; remap other builds. |
| AC2 | Provider, command, selected key metadata, private frames and source buffers have valid, compatible extents and nominal dispatch. Cross-read value equality additionally assumes stable source bytes. | Match native classes, allocations, offsets, ownership, nonaliasing and lifetime; retained symbolic cells do not prove those properties. |
| AC3 | Scalar source forests begin with the declared inputs and stop at their recorded frontiers. Recognized selectors still have later gates. | Reproduce coverage/disjointness and all 24 scalar-feasibility checks; inspect post-frontier state/size/helper branches before claiming complete admission. |
| AC4 | Cross-cut composition assumes ordinary ABI-preserving returns and the stated field effects. | Match callee effects, exceptions, authentication and synchronization; source argument packing alone is not a completed helper operation. |
| AC5 | Register reads use declared snapshots; MMIO semantics and native FIFO occupancy are unknown. | Match hardware/register mapping and concurrent writers; separate each repeated status read and cold-handler boundary. |
| AC6 | Width-header units are inferred only on the recognized 128/192/256 domain from exact consumed byte counts. | Recheck the bits-to-bytes relation and its SAT premise control; other headers follow distinct/unproved admission paths. |
| AC7 | Current trace addressing requires incoming cursor <=255 and a valid provider prefix. The next cursor is bounded independently. | Match the cursor initializer, every writer, provider extent and synchronization before applying the local ring invariant to native state. |
| AC8 | Payloads are symbolic or declared test bytes; only static instruction semantics are evaluated. | Obtain matched native daemon/kext/provider request, device acceptance and completion evidence before an end-to-end claim. No native MMIO, key extraction, barrier, IPC or IDB mutation occurs here. |

## Primary bodies and interfaces

Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Six complete compiler-bounded bodies plus two exact 16 B import stubs retain 1308 instructions / 5232 code bytes. Existing complete configuration/quantum captures match the original bytes. IDA was not needed for this increment. [AC1,AC8]

| Exact source interface | Original half-open range | Instructions |
| --- | --- | --- |
| `AppleS8000AESAccelerator::_configureAES(IOAESAcceleratorCommand*,unsigned)` | `0xfffffe0009d4fcf8..0xfffffe0009d5070c` | 645 |
| `_push_command_key(unsigned,unsigned,u8*,u8*,bool)` | `0xfffffe0009d507c4..0xfffffe0009d50914` | 84 |
| `_push_command_dsb(u8 const*,u8 const*)` | `0xfffffe0009d50914..0xfffffe0009d50980` | 27 |
| `_space_available(unsigned)` | `0xfffffe0009d51dfc..0xfffffe0009d51e38` | 15 |
| `_push_command(void*,unsigned)` | `0xfffffe0009d51e38..0xfffffe0009d51f3c` | 65 |
| `performAESQuantum(IOAESAcceleratorCommand*)` | `0xfffffe0009d50a28..0xfffffe0009d51168` | 464 |
| Synchronization / copy import stubs | `0xfffffe0009d52af4..0xfffffe0009d52b04` / `0xfffffe0009d52c94..0xfffffe0009d52ca4` | 4 / 4 |

| Original slot | Exact nominal target | Role |
| --- | --- | --- |
| `0xfffffe00082fe588` | `0xfffffe000be82c2c`, `_OSSynchronizeIO` | Stub called after ordinary IV packet emission |
| `0xfffffe00082fe658` | `0xfffffe000c647f10`, `_memcpy` / `_memmove` exact aliases | Copy-helper identity; neither alias alone proves overlap policy for every caller |
| `0xfffffe0007f3fdb0` | `0xfffffe000c51e1d4`, `IOCommandGate::commandSleep(void*,unsigned)` | Nominal gate +0x200 used by configuration retry sites |

All three are authenticated format-8 pointers with verified original chain membership. Actual receiver class, authentication and register effects remain premises. [AC1,AC2,AC4,AC5]

## Scalar operation and selector partitions

The quantum source calls configuration at `0xfffffe0009d50d4c` with X0=provider, X1=outer command and W2=0. Configuration saves these as X19, X21 and X20, then reads the command's u32 operation at +0x40. The complete selected scalar forest admits operations 0..5, or operation 6 only when the **raw** selected key+0x24 word equals 3102. Other operation values reach raw-error preparation. This prefix result requires valid declared field reads; it does not prove later configuration success. [AC2,AC3]

| Operation | W24 operation field | W25 operation field | Additional prefix condition |
| --- | --- | --- | --- |
| 0 | 0x00010000 | 0x00100000 | None |
| 1 | 0x00010000 | 0 | None |
| 2 | 0 | 0x00100000 | None |
| 3 | 0 | 0 | None |
| 4 / 5 | 0x00020000 | 0x00100000 | None |
| 6 | 0 | 0 | Raw key+0x24 ==3102 |

At the common key path, source retains the original u32 selector word, clears its high bit in memory when set, and dispatches on the low 31 bits. The following table is a complete recognition partition of that normalized scalar value, with all other values selecting the unsupported-selector frontier. [AC3]

| Normalized selector | Original frontier | Next source role / unresolved gate |
| --- | --- | --- |
| 0 | `0xfffffe0009d50048` | Width header and inline 32 B scratch staging; high-bit extension path separate |
| 1000 | `0xfffffe0009d500c4` | Provider+0x1d5 / +0x1f0 state-dependent path |
| 1001 | `0xfffffe0009d4fe00` | Provider+0x1d6 / +0x1f4 state-dependent path |
| 2000 | `0xfffffe0009d500a4` | Provider+0x1d4 / +0x1ec state-dependent path |
| 2001 | `0xfffffe0009d500e4` | Length/high-bit, bounded-copy and auxiliary command path |
| 3000 / 3100 | `0xfffffe0009d4ff74` | Selected slot 2 / 3, size gate and `_push_command_dsb` path |
| 3102 | `0xfffffe0009d4feb4` | Requires operation 6, further metadata checks and `_distribute_dkey` boundary |
| 4000..4003 | `0xfffffe0009d4fe4c` | Direct selector-derived flag fields |
| All other low-31-bit values | `0xfffffe0009d500fc` | Unsupported-selector error preparation |

Recognition is distinct from the generic provider's earlier key-table lookup. Original selectors 2100..2999 can be remapped to another key-data pointer; configuration reloads the selected pointer from command+0x48. A sample-state selector such as 2201 therefore cannot be compared directly with this lower recognition table without establishing its table-entry result. The generic provider and hardware recognition gates also have different numeric ranges; complete key policy remains unproved. [AC2-AC4]

The source contains nine literal preparations of u32 `0xe00002c2` for diagnostic/error returns and a separate raw-success publication at `0xfffffe0009d503c8`. The report does not assert termination or complete return coverage through every helper, wait loop, cold handler and canary path. [AC3,AC4]

## Width headers and record layouts

For the ordinary selector-0 path, the first u32 at the **selected** key pointer controls the size flag: 192 selects `0x00400000`, 256 selects `0x00800000`, and the local default selects zero. The key-command helper decodes header bits 22..23 as 16, 24 or 32 payload bytes for codes 0, 1 or 2. Code 3 reaches a diagnostic boundary. [AC3,AC6]

| Recognized width header | Size bits | Consumed payload | Exact relation |
| --- | --- | --- | --- |
| 128 | 0 | 16 B | 16 B * 8 bit/B =128 bit |
| 192 | 1 | 24 B | 24 B * 8 bit/B =192 bit |
| 256 | 2 | 32 B | 32 B * 8 bit/B =256 bit |

This proves the source unit relation on the stated domain; it does not establish actual key provenance or a completed cryptographic operation. The source first stages 32 B from selected-key+4, then the helper consumes the selected prefix. Other first-word values are not covered by the width-unit interpretation; the retained SAT control demonstrates why that premise is needed. [AC2,AC4,AC6,AC8]

| Record/interface | Ordered byte layout | Emission contract |
| --- | --- | --- |
| Ordinary IV command, 20 B | u32 header; 16 B IV, or 16 zero bytes when IV pointer is NULL | `_push_command(provider,frame+0x18,20)` at `0xfffffe0009d503c0` |
| DSB helper record, 36 B | u32 `0x30000000`; first 16 B source; second 16 B source | `_push_command` call at `0xfffffe0009d50960` |
| Extended key-command record, 68 B | u32 command; u32 auxiliary word; 12 zero bytes; 16 B extension; 32 B staged payload | Call path through `0xfffffe0009d508f4`; extra-pointer and FIFO predicates apply |
| Ordinary key command | u32 command, followed by 16/24/32 B payload | Two `_push_command` requests after a combined-size precheck; intervening snapshots remain distinct |
| Direct routed header | u32 command only | Selected when command bits 24..26 are nonzero and the tested status bit permits continuation |

The 20 B header contains `((channel32&3)<<26)`, selected route flags and `0x20000000`; its preserved base field is explicitly masked before insertion. The common key-command header ORs selected width/extension/channel/kind/operation fields and `(slot32&255)<<18`. These equations retain overlapping-bit OR semantics; no undocumented hardware field names or injective encoding are inferred. The quantum's third argument 0 selects the ordinary `0x10000000` channel contribution; other low32 values select `0x18000000` in that local cut. [AC2-AC4]

The independent byte-memory interpreter begins with poisoned frame bytes and declared patterned source bytes. It checks full record coverage, zero padding, unaligned vector-copy offsets and little-endian word order. This independently qualifies the fixed-cell symbolic lift; it does not supply native buffer extents or evaluate device effects. [AC2,AC4,AC8]

## FIFO admission, trace ring and MMIO word flow

`_space_available(N)` first requires `N&3==0`; the other arm reaches a cold-handler boundary. For a declared u32 status snapshot S read from u64[provider+0x178]+0x24, the selected source computes:

```text
requested_words = N >> 2
status_words    = (S >> 8) & 255
available       = requested_words + status_words <= 128
```

The u32 addition cannot overflow for any u32 N. Interpreting `status_words` as FIFO occupancy is an inference from this method and its callers; a hardware register specification or matched live observation is absent. `_push_command` separately checks alignment and calls `_space_available` again. Insufficient space reaches another cold-handler boundary, not a recovered false return from the void emitter. Native FIFO timing and atomic multi-call reservation remain unknown. [AC4,AC5]

Selected configuration retry paths publish provider+0x150=1, request a register-bit update, then invoke nominal gate+0x200 through provider+0x1c8 with event pointer provider+0x150 and raw flags 2. Source retries after the call; its result is not a proved configuration-success result. Actual sleep, gate ownership, wakeup producer and device-progress guarantees remain open. [AC2,AC4,AC5]

For positive aligned N, the emitter initializes u64 word index i=0 and remaining words=N/4. One source iteration has the following order:

```text
u32 traced_word = buffer[i]   // first read at buffer + 4*i
trace[old_cursor] = {u32 2, u32 traced_word}
cursor = (old_cursor < 255) ? old_cursor+1 : 0
u32 emitted_word = buffer[i]  // separate payload read
MMIO[(version == 0) ? 0x100 : 0x200] = emitted_word
i = i+1; remaining = remaining-1
```

The trace store precedes the cursor update and the MMIO store. The trace payload load at `0xfffffe0009d51ed8` and emitted-word load at `0xfffffe0009d51efc` are separate observations. Their values coincide under stable source bytes; buffer mutation or aliasing is outside that equality claim. Optional diagnostic logging may read the same buffer location earlier. The next cursor lies in 0..255 for every incoming u32 cursor; valid **current** trace addressing still requires old_cursor<=255. Under that premise, each 8 B record starts at provider+0x1fc+8*cursor and ends no later than provider+0x9fc. The cursor itself occupies +0x9fc..+0xa00. This explains a required 2560 B provider prefix for these fields; it is not a proof of native allocation size or cursor initialization. [AC2,AC5,AC7]

The loop-step and byte-offset bounds are proved under their counter premises. Original source is captured, including the actual register-store instruction; the analysis never performs that device store. No whole-loop native transaction, hardware acceptance, key installation, cryptographic output or completion event is demonstrated. The synchronization import is identified as OSSynchronizeIO, but its native effect is unexecuted. [AC4,AC5,AC8]

## Validation and bounded continuation

Fifty-six UNSAT obligations cover three complete scalar forests and 25 straight-line cuts / 104 lifted instructions. The forests retain 24 feasible declared scalar paths, with independent coverage/disjointness checks. One SAT width-domain control is separate. The publication audit rechecks these results and 43 prior DMA UNSAT certificates, original bytes/bounds/symbols/fixups, original-input preservation, the exact artifact delta and scrubbed paths, including decoded archives and commit metadata.

| Independent interpreter cases | Count |
| --- | --- |
| Operation / selector / size routing | 39 / 4100 / 12 |
| Extended / IV / inline / DSB / trace byte layouts | 8 / 32 / 6 / 2 / 4 |

Reproduce with `PYTHONPATH="triage_evidence${Z3_PYTHONPATH:+:$Z3_PYTHONPATH}" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/recover_aes_configuration_commands.py --verify`, then run the independent interpreter and publication auditor with the same environment. Source/path construction is O(B+I+P) time/space for collection bytes B, instructions I and retained path visits P; finite interpretation is O(cases*visits) time and O(code+private bytes) space. SMT cost is separate; each observation limit is 15 s. Sizes and widths are exact integers; no timing or throughput is inferred.

| Impact | Remaining evidence | Purpose |
| --- | --- | --- |
| High | Actual selected key-table entry, metadata owner and post-prefix gates | Joins the obfuscated caller's selector to the complete lower configuration contract. |
| High | Device register mapping/status semantics and live command acceptance | Separates static packing/FIFO predicates from hardware effects and output. |
| High | Current trace-cursor initializer, all writers and provider allocation extent | Establishes the native ring invariant and valid logging prefix. |
| High | DMA/configuration/interrupt completion in one descriptor/job epoch | Joins prepared ranges, submission and returned result to the daemon request. |
| Medium | Complete retry sleep/wakeup and ordinary/cold return behavior | Establishes progress, error propagation and resource lifetime. |
| Medium | Native buffer backing versus existing 81920 B metadata publication | Resolves constructor and current descriptor/command identity without duplicating conditional metadata proofs. |

**QG1**: Descriptive source, ABI and control/data-flow analysis requires no normative judgment.

**QG2**: AC1-AC8 identify assumptions, dependencies and falsification probes.

**QG3**: The scalar partitions, selected record builders, FIFO predicate, trace/emitter flow and synchronization/sleep interfaces are covered for this increment. Full configuration/native/cross-layer recovery remains active.

**QG4**: u32/u64/u128 widths, little-endian byte order, exact record extents, bits-to-bytes relation, unsigned arithmetic and complexity are reproducible.

**QG5**: Recognition versus admission, original versus remapped metadata, logical versus native extent, repeated status/payload snapshots, current versus next cursor, packet construction versus hardware completion and normal versus cold paths remain distinct.

**QG6**: Original collection bytes, compiler bounds, exact nlist definitions, authenticated chains, source/SMT certificates and an independent byte-memory/scalar interpreter supply primary provenance.

**QG7**: The impact-ranked continuation table bounds the architectural expansion; scoped passage is not native key installation, hardware completion or daemon/kext pairing.

## Trace lifetime and conditional wakeup

The [trace/wakeup report](aes_trace_wakeup_report.md) establishes source class/request size 2560 B, eight literal cursor stores and their local transition contracts. It resolves the conditional interrupt producer for the same configuration wait event P+0x150, including byte-wide publication/clear, control-bit handling, eight sleep sites and nominal wakeup arguments. Native zeroing, closed writer sets, serialization and matching gate/workloop epochs remain unknown (TW1-TW8).
