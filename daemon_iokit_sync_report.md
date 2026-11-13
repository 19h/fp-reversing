# Daemon IOKit acquisition, cleanup and outer return

Follow-up: The [network gate report](daemon_network_gate_report.md) composes the shared acquisition and cleanup adapters into a retained network-record caller. Original callback effects, equal fallback argument addresses, cache-control wrap and separate object-layout frontiers are independently checked; native lock validity and ownership remain unknown.

Related caller: The [network record report](daemon_network_record_report.md) reaches acquisition adapter 0x10043e280 and the same once control/callback tuple from a conditional process-path/network-record context. Its captured pointer is zero and its once call remains pending. The earlier callback/lock fixtures are not composed into these new cases; native initialization and cross-layer identity remain unknown.

The selected daemon entry at `0x1004601D0` reaches the previously established class-matching, service-open and metadata-query sequence through an acquisition adapter. The former unknown SP+0x50 cleanup value is now source-derived: it holds the address `0x1010C8240`, whose contents supply the primary synchronization pointer. Acquisition captures that pointer before its adapter call; common cleanup reads the cell again. Both adapters call `pthread_once` with the same control and callback, then conditionally call `pthread_rwlock_wrlock` or `pthread_rwlock_unlock`. These are source and private-model results; native synchronization, pointer lifetime and concurrent mutation remain unknown. [DS1-DS12]

[Original source contracts](triage_evidence/daemon_iokit_sync_contracts.json), [retained cases](triage_evidence/daemon_iokit_sync_profiles.json), [independent byte and replay checks](triage_evidence/daemon_iokit_sync_checks.json), [source proofs](triage_evidence/daemon_iokit_sync_proofs.json), [live IDB source](triage_evidence/daemon_iokit_sync_live_ida.json), [SDK signature assertions](triage_evidence/daemon_iokit_sync_sdk.c), [preservation](triage_evidence/daemon_iokit_sync_preservation.json) and [scoped gates](triage_evidence/daemon_iokit_sync_quality_gates.json) retain the evidence. The [class-matching report](daemon_iokit_class_report.md) remains the preceding evidence boundary. The full interface objective remains active.

```text
outer entry 0x1004601D0
  selected input phase 5784, state byte 09
    -> save &primary at F+50; capture primary in acquire record
    -> acquire adapter 0x10043E280
         pthread_once(&control, callback)
         primary != 0 ? primary : fallback
         selected != 0 -> pthread_rwlock_wrlock(selected)
    -> reread state byte; selected 09 continuation
    -> MainPort -> class dictionary -> iterator -> Open(type 0)
         -> queries 22/23 -> encoded state -> object releases
    -> common cleanup 0x100383B00
         reread primary through saved &primary
         cleanup adapter 0x1004423F8
           pthread_once(&same_control, same_callback)
           fresh primary != 0 ? fresh primary : fallback
           selected != 0 -> pthread_rwlock_unlock(selected)
    -> publish F+60 raw u32 at input+4
    -> guard check, restore registers/SP, outer return

callback 0x10040EBD4
  -> source controller writes
  -> local record containing &fallback -> 0x10044FC34 [single RET]
  -> guard check and return
```

The matching/Open/MainPort error continuations remain separate stop boundaries. Their cleanup and return behavior is unknown in this increment. All addresses are preferred file virtual addresses. F is SP after the outer 0x130-byte frame allocation; R=F+0xA8 is an 8-byte-aligned reused local record. B denotes bytes. Arithmetic below is modular u32/u64; no floating-point calculation or physical measurement is involved.

## Assumption register

| ID | Assumption or bound | Dependent result | Stress test or falsification probe |
| --- | --- | --- | --- |
| DS1 | Pinned daemon thin/universal images and current daemon IDB identify the inspected build | All address and import claims | Rehash originals; compare 161 live IDB instruction rows with original bytes |
| DS2 | Input selector is 0x5784 and initial state byte is 09 | Selected full entry and class/query composition | Change input/state independently and recover every newly selected source fragment; no universal entry coverage claimed |
| DS3 | Primary/fallback pointer contents are explicit stable private fixtures | Primitive argument selection in finite runs | Trace original writers and readers; observe authorized runtime initialization and synchronization before assigning native identities |
| DS4 | Primary cell is Mach-O `__common` zerofill storage, not file-backed data | Unknown runtime value; private BSS fixture required | Parse original segment/section extents and flags; a different image or runtime store invalidates a file-initial-value inference |
| DS5 | R is 8-byte aligned | Acquisition caller/callee key equivalence | SMT quantifies arbitrary aligned R; remove alignment and inspect counterexamples |
| DS6 | Original fixups and exhaustive byte-bank rules retain their stated targets | Internal edges, globals, imports and callback identity | Decode original format12 words; vary all 256 bank inputs; hardware PAC remains outside this proof |
| DS7 | Once control is modeled as completed or not completed; first incomplete call invokes the original callback once | Callback/no-callback compositions | Vary completed state; check second call skips callback; native once state, blocking and recursion remain unknown |
| DS8 | Callback entry SP is privately placed 0x100 bytes below the once caller SP | Source callback stack/controller values | Preserve source frame effects; vary outer placement; native pthread implementation stack placement is unknown |
| DS9 | Primitive models return int32 zero, write no target memory and clobber caller-saved registers | Finite returning paths | Source proof covers arbitrary write-lock return word for its next dispatch; native errors, waits and synchronization effects remain unknown |
| DS10 | Existing IOKit summaries preserve their formal arguments and declared outputs | Prior class/object/query semantic composition | Compare all 664 preceding source sequences and formal call arguments; do not equate unused registers or earlier controller epochs |
| DS11 | Guard fixtures are stable; PAC/RETAB/PACIZA are explicitly abstracted without changing source bytes | Source-selected return and ABI restoration | Native authentication or guard failure requires separate evidence; compare original instruction bytes and restored registers/SP |
| DS12 | Evidence is bounded to selected entry, common cleanup and declared error frontiers | Scope of routine-role assignments | Recover stopped error paths, upstream callers and global writers before claiming complete lifecycle or native reachability |

## Source and ABI mappings

| Interface or cell | Exact location | Established function |
| --- | --- | --- |
| Outer entry / input | `0x1004601D0`; input X0 | Reads encoded u32 selector at input+0; publishes raw u32 result at input+4 |
| Actual outer controller | `0x1010B8E48` | Full predecessor resolves X22 here; earlier partial-entry controller fixtures remain conditional |
| Primary pointer cell | `0x1010C8240` | Address saved at `0x1003CCFE4`; contents captured at `0x1003CCFE8` |
| Acquisition adapter | `0x10043E280`; call `0x1003CD07C` | Decodes control 0x593D and captured pointer, calls once and conditional write-lock |
| Shared once control / callback | `0x1010B8CD0` / `0x10040EBD4` | Identical X0/X1 at both once calls; callback pointer passes source PACIZA |
| Acquisition once | `0x10043E508` | Bind slot `0x10109FE80`, IA discriminator 0x8489, `pthread_once` |
| Write-lock | `0x100361DF4` | Bind slot `0x1010A0A00`, IA 0x4C4D; X0 is selected nonzero pointer |
| Fallback pointer cell | `0x1010B9638` | Read if primary is zero; original file-initial rebase points to `0x1010B7478`; runtime contents/object validity unknown |
| Common cleanup | `0x100383B00` | Loads saved cell address then fresh primary contents at `0x100383B04` |
| Cleanup adapter | `0x1004423F8`; call `0x100383BA0` | Decodes control 0xA293 and fresh pointer, calls once and conditional unlock |
| Cleanup once | `0x100442650` | Same once bind slot, discriminator, control and callback |
| Unlock | `0x100208EFC` | Bind slot `0x1010A0D78`, IA 0x5431; X0 is selected nonzero pointer |
| Callback leaf | `0x10044FC34`; call `0x10040EE2C` | Original single RET; no record read or lock-object creation in this leaf |
| Outer publication / return | `0x100336FCC` / `0x100337004` | `STR W11,[X19,#4]`; guard check; restore X19-X29 and SP; RETAB |

The primary cell lies in `__DATA` virtual extent beginning `0x1010B4000`, size 98304 B, with file-backed size 81920 B ending at `0x1010C8000`. Its containing `__common` section has zerofill type 1. This identifies storage layout, not its value when the selected routine runs. No IDB filler byte or private fixture is promoted to a native value. [DS1,DS3,DS4]

The actual full predecessor resolves `0x1010B8E48` through bank key 0x81, additive 0x823, constant 0x48, pool index 0x86B, slot `0x1010A5CB8`, and bias `0xFFFFFFFFC51978D5`. This refines the earlier partial-entry X22 fixture `0x1010B7D48`; only the full-source value is assigned to this predecessor. The primary cell resolves through key 0x6C, additive -0x13 (-19 decimal), constant 0x87, pool index 0x74, slot `0x1010A1D00`, and bias `0xFFFFFFFF858BECD2`. Both rules check all 256 possible byte-bank inputs. [DS6]

## Local records and control flow

| Record epoch | Offset +0 | Offset +4 | Offset +8 | Access width |
| --- | --- | --- | --- | --- |
| Acquisition R | `u32(0x593D XOR Ka)` | Unspecified padding | Captured primary pointer u64 | 4 B + 8 B |
| Cleanup R | Fresh primary pointer u64 spans +0..+7 | Part of pointer | `u32(0xA293 - Kc)` | 8 B + 4 B |
| Callback SP+0x10 | Encoded control u32 | Unspecified padding | Address of fallback cell u64 | Leaf does not read record |
| Outer input | Encoded selector u32 | Published raw result u32 | Outside established input extent | 8 B total accessed |

For low32(R)=r, acquisition's caller key is

```text
Ka = u32(((u32(2*(r & 0x0E82E2D8) - r + 0xF17D1D24))
          XOR 0x6903B1AE) * 0x316F29C1)
```

Its callee computes the equivalent key using

```text
u32(((u32(r - 2*(r & 0x202F5694) + 0xA02F5694))
     XOR 0x3851FA1E) * 0x316F29C1)
```

The source-derived prekeys are equal under R mod 8=0. Cleanup's shared key is `Kc=u32((r XOR 0xEAAE0AC9)*0x7398180B)`. Source decoding recovers the control and full pointer separately; these local phase values are not Mach message IDs. [DS5,DS6]

The outer selector decodes as `u32(MEM32[input] - u32((low32(input) XOR 0x966E5812)*0x592E2F77))`. The selected 0x5784/09 path enters acquisition with phase 0x597A. A post-acquisition state-byte reread selects `0x100461C30` for byte09; the helper return word is not this predicate. Acquisition's nonzero captured-primary dispatch index is 0x593D; zero selects 0x5F67 and the fallback reader. The write-lock postreturn index is 0x593C independently of arbitrary W0, reaching its original restore/return epilogue. [DS2,DS9]

Both adapters choose primary when nonzero, otherwise fallback, and omit their primitive if both are zero. The two source pointer reads occur at different times. The finite cases keep cells stable; they do not establish equality under concurrent native mutation or valid matching acquisition/unlock of a native lock. [DS3,DS7,DS9]

## Callback and result channel

For the callback's actual source SP H and source-loaded controller words A/B, let `D=u64((A XOR B)+(H+8))`, `M=0x0A5CD4CF`, and `T=0x73D046208EAED1A6`. Original stores at `0x10040ECFC` and `0x10040ED00` write:

```text
[0x1010C5088] = u64(D*M + 0x673E3A80075F02C6)
[0x1010C4670] = u64((D XOR T)*M)
```

The callback then passes a source-built record containing the address of the fallback cell to the original single-RET leaf. The selected callback writes neither primary nor fallback pointer storage. Its observable source effects establish controller updates and local-record preparation; a native lock initializer role is unknown. [DS3,DS6-DS8]

The cleanup adapter updates two controller cells before record decoding. For its SP H, loaded A/B and the same M/T, it stores `u64(((A-(H+8)+B) XOR T)*M)` to both `0x1010B6738` and `0x1010C4670`. These writes and callback writes execute as original source instructions in the private guest. They are not fabricated API outputs. [DS6-DS9]

The outer result begins as raw 0x8B3DC651. The selected zero-service path stores 0x74C29C07; null matching dictionary stores 0x74C29FC9. Common cleanup returns to `0x100336FCC`, which publishes the selected raw word to input+4. Native semantic normalization and the upstream consumer of this record remain unknown. Treating this raw channel as an ordinary int32 success code requires additional caller evidence. [DS2,DS10-DS12]

## Validation and limits

The case set contains 684 profiles: all 664 preceding class cases plus 20 pointer-selection/once-state controls across two outer frame placements. Every retained source instruction and read/write epoch is independently reconstructed from original file bytes, decoded fixups, explicit fixtures and API writes. Thirty selected cases are freshly rerun. All 664 preceding original class/object/query instruction sequences remain embedded; formal IOKit call arguments and declared outputs are compared. Full-entry controller reads, unused scratch registers and previously unknown stack bytes are not equated with earlier partial-entry epochs.

Fifteen original/simplified SMT proof pairs cover 131 lifted instructions. Fourteen original spans, 80 independently decoded original fixups and seven current IDB windows with 161 original-byte matches retain source provenance. Installed arm64e SDK syntax checking verifies three pthread signatures, 8 B pointers and 4 B int returns. The 684 generated cases contain 1175922 source instruction visits. Native daemon, pthread, IOKit, Mach, hardware PAC and kernel operations do not execute. Exact counts, result/frontier distributions and independent audit totals are recorded in the checks file.

The successful common-cleanup cases restore X19-X29 and outer SP, retain the source guard check and publish the source result. Error frontiers remain stopped. The complexity of producers and verifiers is stated in their source docstrings; arithmetic uses fixed-width bit vectors, byte extents and explicit unsigned comparisons.

| Verified case or epoch class | Count | Evidence boundary |
| --- | ---: | --- |
| Outer result publication and ABI return | 616 | Private primitive/API summaries; original returning source |
| MainPort / matching / Open error frontiers | 24 / 32 / 12 | Stop before error continuation |
| Acquisition once / cleanup once | 684 / 616 | Same control/callback arguments; modeled once state |
| Source callback invocations | 674 | Original callback executes; private caller-stack placement |
| Write-lock / unlock summaries | 676 / 608 | Stable primary/fallback fixtures; native synchronization unknown |
| Read / write epochs audited | 253656 / 82402 | Independently reconstructed source memory epochs |
| API output writes audited | 3796 | Explicit external-output provenance |
| Timed record/string snapshots checked | 2896 | Captures checked at their original source visit |

Preservation checks cover 2496 preceding artifacts, with 2490 unchanged and exactly six designated existing report/index edits. All three original supplied inputs retain their recorded size and SHA-256.

## Bounded continuation opportunities

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High | Original writers and incoming references to `0x1010C8240` and `0x1010B9638` | Native synchronization-object construction, replacement and lifetime |
| High | MainPort/matching/Open error continuations and their original return paths | Whether error paths converge on the same fresh-pointer cleanup and result publication |
| High | Callers of outer entry and consumers of input+4 | Trigger, input-record ownership and raw-result normalization |
| Medium | State-byte09/0A writers and lock-cell epoch relations | Cache initialization ordering and which native mutation constraints preserve pointer selection |
| Medium | Callback's incoming references and once-control initialization | Whether the observed controller/RET callback has additional callers or build-dependent initialization roles |
| Medium | Existing query22/23 provider implementations | Native getter values and relation of encoded capability bit08 to actual protocol behavior |
| Low | Equality between default result 0x8B3DC651 and prior scalar mask constants | Candidate encoding convention; equality alone supplies no semantic normalization |

No additional incoming/outgoing Mach port, right disposition or emission location is established here. The sequence retains the earlier IOKit port/value contracts; synchronization pointers, once controls, local phases and callback addresses are process-local interfaces.

## Quality gates

QG1: factual technical analysis. QG2: DS1-DS12 include dependent results and falsification probes. QG3: selected entry/acquisition/common-cleanup/return covered; full interface goal incomplete. QG4: widths, byte extents, modular arithmetic, alignment and reproduction are explicit. QG5: captured/fresh pointers, file/runtime state, callback/primitive effects, raw/normalized status and error frontiers are distinguished. QG6: original bytes, fixups, IDB, SDK, source proofs and finite profiles have separate provenance. QG7: bounded continuation opportunities have impact labels. The scoped gate record is issued only after the corresponding checks and preservation checks pass.

Reproduce with the pinned Python environment and existing frozen dependencies:

```sh
export PYTHONPATH="triage_evidence:$Z3_PYTHONPATH"
export Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR"
"$PYTHON" -P triage_evidence/probe_daemon_iokit_sync.py
"$PYTHON" -P triage_evidence/recover_daemon_iokit_sync.py
"$PYTHON" -P triage_evidence/prove_daemon_iokit_sync.py
"$PYTHON" -P triage_evidence/validate_daemon_iokit_sync.py
```
