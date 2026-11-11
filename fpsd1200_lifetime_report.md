# FPSD1200 failed-watch cleanup, queue origin and slot-word provenance

After `kevent=-1`, original code calls `__error()` and proceeds to invalidate/release the CF endpoint, clear its slot field, restore the slot marker and return a36-byte reply with status -1. It does not read errno storage on this path. NULL and unmapped nonnull accessor-result controls have identical original instruction sequences and terminal state. Separately, the process-watch queue word joins the previously recovered descriptor initializer, and a diagnostic slot-word control is overwritten by original source. These are private source/ABI results; native queue/event/CF/VM effects and transport remain unverified. [FL1-FL8]

This continues the [CF endpoint report](fpsd1200_port_report.md). The full daemon/kext/deeper-interface investigation remains active.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FL1 | The pinned thin daemon and matching live IDA bytes identify this source. All address/instruction claims depend on this identity. | Rehash the thin image,853 selected spans,13 additional retained descriptor ranges,1138 rebases and38 bind records. Distinguish thin-image and whole-input metadata hashes. |
| FL2 | Frozen admission, libbsm, startup, certificate/arithmetic, VM, CF, PAC, atomic and lock models define the preceding private machine. All continuations depend on those premises. | Freshly replay every original visit, event, checkpoint, owner record and terminal CPU/memory comparison. Native initialization, credentials, library pairing, synchronization and successful FairPlay processing remain unknown. |
| FL3 | `__error()` supplies only a declared result; both tested results are unmapped and no errno memory is supplied. Failed-watch cleanup depends on this finite API model. | Compare results0 and `0x78000000`, confirm neither address is mapped, replay the complete original return and observe no pointer read. Native TLS implementation and arbitrary API behavior remain unknown. |
| FL4 | Descriptor setup and FPSD1200 are separately entered components joined through one four-byte field. Queue-origin conclusions depend on this explicit composition. | Independently replay original context initialization and fd0/fd7 setup, compare the actual source store, header bytes and later read/argument. Native temporal continuity and descriptor validity are not established. |
| FL5 | The watch call returns either0 or -1 without native event/errno effects. Success/failure conclusions apply to these cases. | Compare both full continuations and the all-u32 local carrier query. The query does not prove the complete dispatch predicate for arbitrary return values. |
| FL6 | An initial four-byte diagnostic stack seed is controlled in one profile. Slot-word overwrite findings depend on its exact placement and the original subsequent stores. | Compare original read/write journals, before/after byte masks, both successful sequences and full terminal state. A source-write mask records a write footprint; it is not transitive value-origin proof. |
| FL7 | CF/MIG/VM cleanup APIs remain record-only models, and the719-byte private owner remains mapped. Lifetime findings concern original requests and selected intervals. | Check CF invalidation/release, slot clearing/marker reset, input retirement and absence of a later VM cleanup call. Native retain counts, unmapping, eventual reclamation and later callbacks remain unknown. |
| FL8 | Four new FPSD1200 profiles, three retained descriptor components and two local full-domain arithmetic queries bound this increment. | Verify source, SDK signatures, independent CPU replay and data joins. Populated-slot process-event consumption, subsequent session operations and daemon/kext/deeper joins remain separate obligations. |

## Primary provenance [FL1,FL2,FL8]

| Object | Identity / extent |
| --- | --- |
| Original arm64e daemon | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base `0x100000000` |
| Live IDA metadata | Input SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`;853 matching source spans and13 additional original descriptor ranges |
| New source catalog |40637 distinct four-byte daemon instructions /162548 bytes |
| Retained queue producer | [Descriptor source profiles](triage_evidence/daemon_descriptor_source_profiles.json.zst), context initializer and `setup_fd0` / `setup_fd7`; independently replayed in this increment |
| Primary SDK | Eight installed headers; arm64e compile-only VM/CF/event checks plus `int *__error(void)` and four-byte `int` |
| IDA knowledge search | Returned MIG correspondence/table facts8/7; no direct process-watch, errno or lifetime evidence |

Evidence: [producer](triage_evidence/recover_fpsd1200_lifetime.py), [source and profiles](triage_evidence/fpsd1200_lifetime_checks.json.zst), [live IDA/SDK readback](triage_evidence/fpsd1200_lifetime_ida_readback.json.zst), [independent replay/oracles](triage_evidence/audit_fpsd1200_lifetime.py), [fresh replay receipt](triage_evidence/fpsd1200_lifetime_audit.json.zst) and [publication/data-join verifier](triage_evidence/verify_fpsd1200_lifetime_publication.py). No IDB mutation or native target/API execution occurs.

## Failed watch: return propagation and CF cleanup [FL2,FL3,FL5,FL7]

| Original location | Established data/control operation |
| --- | --- |
| `0x1003ae458` | One `EVFILT_PROC`, `EV_ADD|EV_ONESHOT`, `NOTE_EXIT` change for the signed audit PID; explicit result -1 |
| `0x1003ae464..0x1003ae46c` | Encodes the32-bit result in W22; observed `0x74c239ae` for -1 |
| `0x100493a58` | Zero-argument `__error()` accessor request; explicit result0 or unmapped `0x78000000` |
| `0x100493a5c..0x10054e848` | Original continuation enters CF cleanup and loads the stored CF object; no errno-object load occurs |
| `0x100474e6c` | `CFMachPortInvalidate(0x77001000)` request |
| `0x100474eb4` | `CFRelease(0x77001000)` request |
| `0x100474eb8` | Clears slot+0 with an original eight-byte zero store |
| `0x1004d8440` | Restores marker `0x4577df49` at slot+876 |
| `0x1004d8454` | Selected original CSEL propagates W22's encoded failure into W27 |
| `0x10061aa0c` | Stores raw carrier `0x74c239ae` into the adapter status field |
| `0x10000468c` | Record-only input `mig_deallocate` request for756 bytes; original stub returns36-byte status `0xffffffff` (signed32 -1) |

The original source release at `0x1003ae380` has already followed source insertion into the main default mode. Thus the failed watch occurs after source-registration requests. The cleanup interval does not call CFGetPort and does not publish the six output fields that follow the earlier count store; no success port descriptor is emitted in the36-byte error reply. CF invalidation's native consequences for registered sources are unknown.

For every u32 result r, the local source expression satisfies:

```text
carrier32 = r - ((r << 1) AND 0x167b8ca2) + 0x8b3dc651
          = r XOR 0x8b3dc651                      (mod 2^32)
```

The retained counterexample query is UNSAT. With r=`0xffffffff`, the carrier is `0x74c239ae`; original selected cleanup and the existing adapter/stub return -1. The pointer returned by `__error()` does not supply that status. The separate error controls with supplied errno bytes3/5 were exploratory locators; publication uses the stronger complete NULL/unmapped-result controls without any errno object.

```text
CF object -> slot association -> source registration -> local source release
                                                       |
                                             process-watch request
                                               /             \
                                          return0           return-1
                                             |                 |
                                     publish outputs       __error() call
                                     get raw name          no errno read
                                     reply212              invalidate/release
                                                           clear CF slot
                                                           restore marker
                                                           reply36, status-1
```

Both error profiles retain a source-filled719-byte private VM owner. The sole observed `vm_deallocate` call is the earlier preallocation call at `0x10049e114`; no later VM cleanup request appears in these intervals. This establishes an unresolved reclamation question, not a native leak. Input OOL retirement is separate from the output VM owner.

## Queue initializer-to-watch join [FL1,FL2,FL4,FL5]

| Interface | Original source / exact field |
| --- | --- |
| Descriptor creation | `kqueue()` call `0x1000968f4` in the retained setup component |
| Encoded publication | `STR W9,[X21,#0x48]` at `0x100096920`, header base `0x1010c4cd8`, address `0x1010c4d20` |
| Watch consumer | Four-byte read at `0x1003ae3d8` from the same address |
| Decoded API argument | `0x1003ae43c` produces W0; original `kevent` receives fd0 or fd7 according to the composed producer word |

| Descriptor bits | Producer word / LE bytes | Later watch argument |
| --- | --- | --- |
|0 | `0x060ed969` / `69d90e06` |0 |
|7 | `0x060ed970` / `70d90e06` |7 |

For every32-bit descriptor d, the original setup expression and selected watch-phase arithmetic satisfy:

```text
encoded = (d XOR 0x4eefd9fd) + ((d << 1) AND 0x9ddfb3fa) + 0xb71eff6c
        = d + 0x060ed969                         (mod 2^32)
decoded = encoded + 0xf9f0d0b3 + 0x55e4
        = d                                     (mod 2^32)
```

The complete composed counterexample query is UNSAT. The watch phase W24=`0x55e4` is a premise checked in CPU replay. This proves a shared scalar representation and the selected read/call dependency; it does not identify a native descriptor or establish continuous setup-to-session execution.

The prior descriptor0 value also equals the original image word. The retained `initialized_worker` startup journal contains246729 global source writes, none overlapping these four bytes. Therefore the previous FPSD1200 descriptor0 case did not establish execution of the kqueue initializer: that word was already present in the original image and survived the startup overlay. The new fd7 case explicitly composes a value produced by independently replayed original setup. Its successful API result remains declared.

The [descriptor-source report](daemon_descriptor_source_report.md) already separates this BSD descriptor from Mach port names and recovers its CFFileDescriptor callback `0x10044f23c`. Its SIGTERM registration call `0x100097b08` ignores the supplied result in the selected setup cases. FPSD1200's watch call `0x1003ae458` branches into the cleanup above when supplied -1. The two call-site contracts must remain distinct.

## Slot+400: original overwrite and value-origin boundary [FL2,FL6]

| Original dataflow / private cell | Established local contract |
| --- | --- |
| `0x1006219b8`, `[SP+0x9a0]` | Immediate upstream u32 load; selected address `0x70066570` |
| `0x1006219bc`, `[SP+0x818]` | Original u32 copy into `0x700663e8` |
| `0x1005a7330`, `[SP+0x818]` | Later successful-path u32 load from that copied cell |
| `0x1005a7340`, `[X12+0x190]` | Original copy into selected slot+400 |

The initial destination cell is diagnostic A5 in the ordinary case and explicitly `0x11223344` in the control. Original `0x1006219bc` overwrites both with `0xa5a5a5a5`. The later slot store, successful instruction sequence, terminal GP31/SP, stack, private backing, heap, certificate and VM state and reply agree between those profiles. The initial destination seed is therefore not the final value's producer in these cases.

The source-write knownness mask for the destination becomes `01010101`. This records its original write; it does not by itself prove that the copied upstream value had a semantic initializer. The fresh independent replay records exactly one upstream read per profile at `0x1006219b8`: four bytes `a5a5a5a5` from `0x70066570`, with knownness mask `00000000` and no original CPU write to that upstream cell. Thus this bounded fixture supplies diagnostic bytes at the copy chain's input. Native initialization and caller/environment continuity are unknown; no native uninitialized-read consequence is established. Slot+400 is not assigned a PID, protocol field or native object role here. Its complete semantic provenance and later populated-slot consumer remain unresolved.

## Finite cases and verification [FL1-FL8]

| Profile | Composed fd | Accessor result / initial diagnostic word | Original visits | Original reply |
| --- | ---: | --- | ---: | --- |
| `error_pointer_NULL` |0 |NULL; no errno object |10093130 |36 bytes, status -1 |
| `error_pointer_opaque` |0 |Unmapped `0x78000000`; no errno object |10093130 |36 bytes, status -1 |
| `queue7_success` |7 |Accessor not called; initial A5 word |10093981 |212 bytes, status0 |
| `slot_word_control` |7 |Accessor not called; initial `0x11223344` word |10093981 |212 bytes, status0 |

| Coverage | Exact extent |
| --- | --- |
| New FPSD1200 visits |40374222:40374146 daemon and76 selected-library visits |
| Separately replayed queue-origin components | Three: initializer22292 visits, fd0/fd7 setup307 each;22906 visits total |
| Import events / replies |192 /4:two success and two error replies |
| Private VM owners / original stores |4 /2876 stores,719 bytes per owner |
| Original output stores / staged output reads |528 /36 |
| Queue reads / slot-word reads / slot-word writes |4 /2 /4 |
| Errno-pointer reads |0; no errno storage is supplied |
| Upstream slot-word read / original write observations |4 /0; each read has a zero source-write mask |
| Public arithmetic |376 complete Montgomery calls,12 complete exponent sequences and eight signature-derived outputs; two independent public-signature relations |
| Input OOL reads |9284 |
| Byte-bank evidence |17 exhaustive identities /4352 inputs,17028 observed pair uses and140 unpaired reads |
| Local arithmetic queries | Two UNSAT counterexample queries; no complete-dispatch or native theorem |

The independent auditor never imports this producer. It replays all original instructions through frozen predecessor oracles and independently handles queue composition, accessor result/unmappedness, new GP31/SP/NZCV checkpoints and slot-word journals. It also freshly replays the retained initializer and both setup components with complete original CPU/read/write/API/RAM checks. Full earlier constructor/arithmetic/owner records and terminal state remain checked. The publication verifier pins that fresh receipt, compares the control pairs, joins actual queue/cleanup/status/output bytes and checks exact manifest ownership and original-input preservation. Receipt validation does not itself repeat instruction replay.

Substantial JSON is Zstandard ultra22 archived with exact decompression comparison. Analyst-path checks cover reports, source, decoded profiles, outer metadata and commit metadata; compressed Base64 alphabet coincidences are excluded only after their decoded profiles are checked.

```sh
env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/audit_fpsd1200_lifetime.py

env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_fpsd1200_lifetime_publication.py
```

New finite replay/observation costs O(B+F+V+E+L) for selected bytes, fixups, visits, events and active limb bytes, excluding integer/SMT costs. The retained descriptor replay additionally checks its explicit source journals and whole mutable snapshots linearly in their bytes. Peak storage includes two private worker machines, the aggregator and largest decoded profile. Byte extents, u32/64-bit pointer widths and signed32 status conversions are explicit; no native timing or whole-program complexity is inferred.

## Bounded continuation opportunities [FL2-FL8]

| Impact | Discriminating next evidence |
| --- | --- |
| High | Follow the process-event callback with a populated session slot and the actual stored PID/identity representation. The previously tested empty-slot callback does not establish session retirement. |
| High | Resolve native CF invalidation/source removal and VM-owner reclamation after failed watch registration; distinguish original requests, object retention and eventual effects. |
| High | Establish continuous startup-to-queue-to-request execution and native event/right/callback-send/client-copyout evidence. One source-produced field composition does not supply that continuity. |
| High | Follow returned-session operations into daemon provider, IOKit user client and deeper facilities with exact source/namespace pairing. Current cases reach no IOKit call. |
| Medium | Trace slot+400's upstream value and consumer semantics beyond the immediate copy chain; write-footprint knownness and diagnostic A5 do not assign field meaning. |
| Medium | Expand watch-result dispatch only with its actual local predicates and ABI premises; the carrier identity does not establish arbitrary-return branch semantics. |

**QG1** passes: factual source, ABI and finite-state analysis. **QG2** passes: FL1-FL8 state assumptions, dependent results and falsification probes. **QG3** passes for this increment; the full investigation remains active. **QG4** passes: byte extents, widths, signed statuses, exact counts and local modular arithmetic are explicit. **QG5** passes within scope: accessor call versus errno read, scalar composition versus native continuity, source writes versus value origin, and cleanup requests versus reclamation remain distinct. **QG6** passes: original source/fixups, live IDA, primary SDK, fresh independent replays and data joins supply provenance. **QG7** passes: bounded continuation questions carry impact labels.
