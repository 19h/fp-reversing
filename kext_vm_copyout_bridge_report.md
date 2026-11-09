# Original FairPlay kext caller to VM copyout/discard bridge

The original FairPlay constructor now consumes a copy object produced by original kernel copyin instructions, calls original VM copyout through its real adapter/stub, and resumes at its actual return address with complete CPU and memory state. The success branch installs the mapped address/extent in its child and reaches wiring. A declared allocation result 6 preserves the copy object; the resumed kext calls original discard, resumes again, requests staging cleanup and reaches destination-port release. Transport, allocation, byte-copy, lock, zero/free and logical PAC effects remain declared premises. Authentic daemon exchange, native mapping/ownership and hardware authentication remain unknown. [KB1-KB8]

Primary evidence: [original functions/ranges/adapter slots](triage_evidence/kext_vm_copyout_bridge_source.json), [eight component journals](triage_evidence/kext_vm_copyout_bridge_profiles.json), [independent replay and ABI checks](triage_evidence/kext_vm_copyout_bridge_checks.json). Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. References suffice; no new IDA access, IDB mutation or memory-store write occurs. The [historical zut trace analysis](zut_trace_report.md) remains separate evidence; this increment does not execute fairplayd or replace the failed-open capture.

## Original interfaces and emission sites

Anonymous `_fcHfFIGhsx` at `0xfffffe000a66a7e0` is treated as a constructor/request/reply materialization path under the selected warm/mode-1 fixture, not as an established source-level name. Twenty-three complete kernel bodies / 4492 instructions and fifteen kext ranges / 4492 instructions are recaptured. Every dynamic instruction visit is checked separately against the original collection. Captured ranges are not full kext function or branch coverage. [KB1,KB4]

| Original kext call site | Adapter or callee | Binding / observed contract |
|---|---|---|
| `0xfffffe000a60d61c` | `0xfffffe000a508e34` | Stub `0xfffffe000a69f474`, slot `0xfffffe000847c568`, `_vm_map_copyout` at `0xfffffe000bdd1574` |
| `0xfffffe000a6124c0` | `0xfffffe000a508e0c` | Stub `0xfffffe000a69f494`, slot `0xfffffe000847c578`, `_vm_map_wire` / `_vm_map_wire_external` at `0xfffffe000bdcfd6c`; stop before execution |
| `0xfffffe000a611790` | `0xfffffe000a508e24` | Stub `0xfffffe000a69f454`, slot `0xfffffe000847c558`, `_vm_map_copy_discard` at `0xfffffe000bdc6308` |
| `0xfffffe000a615ed4` | `0xfffffe000a508e4c` | Stub `0xfffffe000a69f304`, slot `0xfffffe000847c4b0`, `_kmem_free` / `_kmem_free_external` at `0xfffffe000bdc2f24`; adapter entry modeled |
| `0xfffffe000a615f2c` | `0xfffffe000bcd0448` | `_ipc_port_release_send`; stop at entry, X0 equals acquired destination-port pointer |

Copyout and discard execute both original adapter instructions and all four original stub instructions. The stub's `BRAA X16,X17` is interpreted as a logical tail edge after checking the original authenticated fixup, target and slot modifier. X16/X17 are therefore produced by the stub. This does not validate a hardware PAC signature. Wiring and staging-free bindings are statically recaptured; their bodies are not executed here. [KB1,KB5,KB7]

```text
original kernel copyin -> type3 object + modeled backing bytes
  -> eight explicit region imports into original FairPlay constructor
  -> declared internal reply 602 -> original reply parser -> copyout call
       +-> real adapter/stub -> original copyout, allocation model returns 0
       |    -> actual caller return -> child address/extent -> wire [stop]
       |
       +-> real adapter/stub -> original copyout, allocation model returns 6
            -> actual caller return -> discard call
            -> real adapter/stub -> original discard -> actual caller return
            -> staging-free model -> destination send-right release [stop]
```

## Data, frame and ownership contracts

All addresses R-relative below belong to private emulated RAM, R=`0x6500000000`; they are not observations of runtime kernel addresses. The producer's 48-byte type3 header holds backing R+0x78000 at +0, extent 4096 at +0x20, and type byte 3 at +0x2d. The backing pattern is `byte[j]=(17+37*j) mod 256`, for `0 <= j < 4096`. The zero-length second descriptor publishes NULL; its unused header allocation fixture retains its A5 canary. [KB2-KB4]

| Object / representation | Private address or extent | Meaning |
|---|---|---|
| Source map / thread / destination map | R+0x2a000 / R+0x2c000 / R+0x2e000 | Declared environmental objects |
| Reply copy object / backing | R+0x68000, 48 bytes / R+0x78000, 4096 bytes | Original header construction; modeled backing allocation/copy |
| Request copy identity | R+0xb8000 | Opaque model identity, distinct from reply object and zone metadata |
| Request staging | R+0x70000, 16384 bytes | Actual modeled allocation extent; original zero-fill after 29-byte filename copy |
| Child | R+0x22000, 152 bytes | Original fixed-record marker and mapped-buffer fields |
| Mapped reply address | R+0xa8000 | Declared allocation result; 4096 copied bytes, 16384-byte requested allocation/wire interval |
| Destination port pointer | R+0x83000 | Opaque successful host-special-port model result; not a Mach namespace name |

The initial producer-to-kext transition imports eight explicitly enumerated regions totaling 7296 bytes, plus all declared producer globals. This is not whole-RAM or whole-CPU continuity from a daemon. Import bytes equal both producer output and kext copyout-entry state. Imported regions are pairwise disjoint and disjoint from actual kext allocation extents, filename, output handle, request identity and mapped interval. The inherited staging A5 observation window extends beyond its 16384-byte allocation; that observation window is not a live allocation extent. Metadata tags are explicitly relocated away from the filename. [KB2,KB3]

From the kext copyout boundary onward, six call/return transfers preserve all 1048576 private RAM bytes, 31 general registers, SP, NZCV, 32 SIMD registers and declared globals; TPIDR_EL1 remains the same thread fixture. Copyout receives `(destination_map, FP-0x80, reply_copy)`, with FP=R+0xeff20 and output pointer R+0xefea0. Both copyout branches return to `0xfffffe000a60d620`; discard returns to `0xfffffe000a611794`. Actual callee-saved X18-X30/SP and low 64 bits of Q8-Q15 are checked. [KB3,KB5]

On success, the original copyout path requests backing release, zeroing and release of its 48-byte header. The modeled primitive copies the exact produced 4096 bytes to the declared mapped address. The original kext stores child+0x48=mapped address, +0x50 (u32)=4096, +0x58 (u64)=0 and +0x60 (u32)=0. It reaches wiring with `(destination_map, mapped, mapped+16384, 3, 0)`. Page shift 14 yields `ceil(4096/16384)*16384 = 16384 bytes`; logical extent and wire extent are distinct. Wiring success, access rights and physical mappings are unknown. [KB4-KB7]

With allocation result 6, original copyout returns 6 without consuming the header/backing. The kext then passes that exact copy pointer to original discard, which requests backing release of 4096 bytes and header zero/free of 48 bytes. After discard returns, original kext code reaches staging free `(staging_map,R+0x70000,16384)` and then `_ipc_port_release_send(R+0x83000)`. Staging free is a no-effect model; port release is not executed. Destination-map reference fixture 3 and the original thread-map fixture are restored at all three kernel returns. Native lifetime/reference balance remains unknown. [KB5-KB8]

Scratch+0x90 retains the reply pointer bits after successful consume or discard. Scratch+0x18 retains the destination pointer and +0x28 the distinct request-copy identity. Stale pointer bits are not evidence of continuing ownership or a leak. The cleanup order and target identities are established conditionally; no new Mach port emission, namespace conversion or right transfer is observed. [KB5-KB8]

## Transport premise and port provenance

The original request builder emits an 88-byte kernel-form RPC502 request: destination pointer, one request-copy descriptor of 29 bytes, NDR and CPU type/subtype/origin fields. The transport entry receives send extent 88 and receive capacity 400. Its declared successful 392-byte reply has ID602, two OOL descriptors `(reply_copy,4096)` and `(NULL,0)`, the fixed marker `0xbeefed02`, and matching inline counts. The original parser accepts this internal representation before the copyout call. [KB2,KB4,KB8]

The host-special-port model supplies destination pointer R+0x83000 for slot17. That same pointer appears in request destination, scratch+0x18 and the final release argument. This is conditional identity continuity across acquisition, emission and cleanup. Neither that pointer nor the reply copy pointer is a user-space Mach name. A genuine fairplayd-produced payload, namespace conversion, service/build pairing, daemon processing and authentic reply delivery are unknown; constructing this reply does not establish them. [KB2,KB4,KB8]

## Assumption register

| ID | Premise / dependent results | Stress test or falsification probe |
|---|---|---|
| KB1 | Pinned collection and normalized kext identify this build's code and fixups | Recapture every body/range/visited instruction and all four slots; verify deployed build pairing separately |
| KB2 | Selected normalized copyin input and declared reply represent a useful component contract | Join an authentic daemon-produced reply and actual namespace conversion; preserve synthetic marker/payload provenance |
| KB3 | Enumerated first imports and complete later CPU/RAM/global transfers define the epochs | Check every imported byte, disjoint live extent, six full transfers and real caller stack output pointer |
| KB4 | Warm mode1, filename length28, one nonempty type3 descriptor and page shift14 bound coverage | Extend mode700, second descriptor, other sizes, type2 and malformed replies using original producers |
| KB5 | Logical PAC and declared metadata/map/thread/zone prerequisites permit selected paths | Establish live metadata/global writers, native map identity and hardware authentication separately |
| KB6 | Allocation result0 or6 and primitive byte-copy/zero effects bound the branch experiment | Derive actual allocator/error/copy behavior; test real error propagation without treating injected6 as native exhaustion |
| KB7 | Release/free/lock/switch models establish requests and argument/order contracts | Execute or independently establish native mapping, wiring, allocator retirement and reference effects |
| KB8 | Eight components stop before wiring or destination release, leaving wider continuity unknown | Continue those original callees and authentic request/reply/error paths; do not infer full startup or round trip |

## Verification, quality gates and bounded continuation

Eight independent fresh CPU replays verify 5636 original instruction visits, 675 reads / 4238 bytes, 2401 writes / 19002 bytes, 31 API models, eight complete final RAM images / 8388608 bytes, 84 global records and all final SIMD states. Six full transfer images represent 6291456 bytes checked at call/return joins. Seven VM-effect patches total `4096 + (8+8+4096+8+48) + 48 = 8312 bytes`; five kext model effects total `8+8+29+8+392 = 445 bytes`. API clobbers are deterministic and checked separately from original instructions. These are finite conditional checks, not native coverage or performance measurements.

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kext_vm_copyout_bridge.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kext_vm_copyout_bridge.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kext_vm_copyout_bridge.py
```

Time is O(image + captured bytes + visits + RAM + effects); space is O(image + captured source + RAM + journals), with 1048576 private RAM bytes per component. Byte counts and address/page arithmetic are exact in the tested domain.

| Impact | Further interface evidence |
|---|---|
| High | Continue original wiring and destination release with exact returned state to establish their ABI and ownership requests |
| High | Replace declared RPC602 with authentic daemon reply/namespace conversion and verify matching service/build |
| High | Join second-descriptor, copy-error, wire-error and RPC700 cleanup paths using original callers |
| Medium | Recover boot/runtime destination-map, metadata and zone provenance; distinguish remaining environmental overlays from original object producers |

QG1: Factual technical analysis; no normative judgment required.
QG2: KB1-KB8 identify premises, dependent conclusions and falsification probes.
QG3: Scoped anonymous role, original call/emission sites, pointer/port identity, ABI, data/control/error/lifetime and reporting updates are covered. The full goal remains incomplete.
QG4: Explicit field widths, page arithmetic, byte counts, complexity and commands are reproducible.
QG5: First region import versus whole-state return continuity, actual allocation versus observation window, stale bits versus ownership, primitive effects versus original instructions and wiring/release frontiers versus completed effects are distinguished.
QG6: Original collection bytes/symbols/fixups and independent replay provide primary provenance for the scoped claims.
QG7: Impact-labelled continuation targets unresolved cross-layer transport, environmental and ownership contracts.

[Preservation](triage_evidence/kext_vm_copyout_bridge_delivery.json), [scoped gates](triage_evidence/kext_vm_copyout_bridge_quality_gates.json), [publication verifier](triage_evidence/verify_kext_vm_copyout_bridge_publication.py). The full goal remains active.
