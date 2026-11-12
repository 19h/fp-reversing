# Selector-21 core workspace, record and initial scalar admission

Subsequent payload evidence: the [selector-21 preparation report](versioned_core_preparation_report.md) follows mode 2 through a complete in-place block helper and encoded result, then stops before an undefined caller frame word. Mode 5 reaches an original allocation boundary with an explicit virtual-tail state fixture. Complete outer processing, native ownership and daemon/kext pairing remain unknown.

The original `_UeFdbi` wrapper at `0xfffffe000a5a2bac` marshals all ten provider arguments, requests a 16,384 B aligned workspace and a 4,096 B typed auxiliary allocation, and calls a separate protected entry at `0xfffffe000a5a5470`. Its address-dependent operation encoding normalizes to `0x3da4b356`. The initial entry gate explicitly admits the daemon's modes 2/5 and fixed word `0xb4d3a486`. This closes a static scalar-compatibility gap after the [daemon call-site join](daemon_postblock_dispatch_report.md); successful processing, native admission, Mach-right ownership and daemon/kext pairing remain unknown. [VE1-VE8]

```text
daemon pending IOConnectCallStructMethod(selector=21, 552 B)
  -> ucRunVersioned -> qtQQt -> _UeFdbi
       -> allocate workspace W / auxiliary A [modeled successful returns]
       -> marshal argument record R on wrapper stack
       -> protected entry 0xfffffe000a5a5470
            +-> initial mode/marker admission -> stop before processing
            +-> initial rejection -> count copyback / frees / decoded return
```

## Assumption register

| ID | Assumption and dependent results | Stress test or falsification probe |
| --- | --- | --- |
| VE-A1 | These exact daemon, normalized kext and original KC bytes define the comparison. All static joins depend on this build identity. | Hash all three inputs; compare every captured instruction between original KC and normalized image. A different build invalidates the address mapping. |
| VE-A2 | Ordinary AArch64 register/stack argument placement and successful pointer authentication. Adapter/core joins and guest returns depend on it. | Retain original authenticated pointer-chain records and call modifiers; native PAC rejection would falsify runtime reachability. Guest PAC and authenticated returns are abstracted. |
| VE-A3 | The two allocations succeed, are distinct, correctly aligned and backed, and do not alias the wrapper frame, count or other live objects. Workspace layout and replay continuation depend on it. | Private owners W/A are distinct; two placements and two backing patterns are checked. No native allocation success, failure behavior or owner lifetime is proved. |
| VE-A4 | The count pointer is readable/writable for 4 B; provider input/output spans and task are valid when later consumed. Count forwarding depends on the former premise. | Replays use count 512 and `0x10203040`; neither result proves native pointer validity or later payload access bounds. |
| VE-A5 | Source-local memory cells are distinct and their epochs agree. Symbolic cell lifts and record composition depend on it. | Reconstruct every guest read/write byte independently and check snapshots at their recorded visit; retain undefined-byte masks. Overlap/wraparound requires a different alias model. |
| VE-A6 | Entry global words remain stable between the source accesses except for captured source stores. Global-state equations and bank addresses depend on it. | Original and declared-noise global fixtures select the same constant banks. Concurrent native mutation and synchronization are unknown. |
| VE-A7 | Register-only allocator/free models obey the ordinary preserved-register contract. Complete private rejection returns depend on it. | Clobber X0-X17 and NZCV at every modeled call; verify restored X19-X29 and SP. No allocator/free memory effects are modeled. |
| VE-A8 | The earlier daemon fixtures describe conditional source-produced API words; they are not an observed native transaction. Daemon-to-core compatibility depends on that conditional provenance. | Keep prior receipt hashes fixed. A native capture with different fields or routing would falsify the proposed runtime join. |

## Allocation and authenticated call mapping

Every bank below is constant over all 256 possible byte indices. Original KC chained-pointer decoding independently confirms each selected normalized slot. These are static bindings, not authenticated native calls. [VE1-VE3]

| Wrapper call PC | Slot | Target / role | IA modifier | Source arguments |
| --- | --- | --- | --- | --- |
| `0xfffffe000a5a2d78` | `0xfffffe000847a8f8` | `0xfffffe000c4b9a08`, `_IOMallocAligned` / `_IOMallocAligned_external` | `0xca0c` | X0=16,384 B; X1=64 B alignment |
| `0xfffffe000a5a2e14` | `0xfffffe000847a7b8` | `0xfffffe000c4ba154`, `_IOMallocTypeImpl` | `0xd0c8` | X0=`0xfffffe000847bea0` |
| `0xfffffe000a5a2e68` | `0xfffffe000847a828` | `0xfffffe000a687ecc`, unsigned ordering guard | `0x4d6a` | X0=W+64; X1=W+16,384 |
| `0xfffffe000a5a2f50` | `0xfffffe000847a9e8` | `0xfffffe000a5a5470`, protected entry | `0x1e46` | X0=W |
| `0xfffffe000a5a2fe4` | `0xfffffe000847a878` | `0xfffffe000c4ba368`, `_IOFreeTypeImpl` | `0x4d6a` | X0=`0xfffffe000847ba60`; X1=A |
| `0xfffffe000a5a3030` | `0xfffffe000847a848` | `0xfffffe000c4b9a24`, `_IOFreeAligned` | `0x84ff` | X0=W; X1=16,384 B |

The typed allocation/free views are distinct static addresses. Both original 64 B records resolve name `site.AllocType`, flags `0xe4`, size 4,096 B and the same two static pointer fields. This comparison does not prove equality of runtime allocator bookkeeping. The ordering helper compares unsigned X0/X1, returns X0 when X0 <= X1 and traps otherwise; it does not clear the workspace. [VE2-VE3]

At dispatcher call `0xfffffe000a5a562c`, the same guard receives W+256 and W+16,384 through a separately recovered bank. Neither allocation, the ordering check, nor the initial scalar gate establishes initialization of a complete payload or workspace. [VE2,VE4]

## Marshalled records and actual field consumers

Let F be wrapper SP after its 256 B reservation, W its workspace allocation, A its typed auxiliary allocation, Q the mutable-count pointer, and R=F+`0x48`. The two original incoming stack arguments are output-B and Q at entry SP+0/+8. The wrapper copies the value at Q into R+`0x40`; the protected entry receives a pointer to this local record. [VE1,VE4-VE5]

| R offset / width | Source value | Selector-21 wire relationship |
| --- | --- | --- |
| `+0x00` / u64 | task argument | UserClient task field; no user Mach-name identity inferred |
| `+0x08` / u32 | mode | input+0; daemon modes 2/5 |
| `+0x0c` / u32 | marker | input+4; daemon `0xb4d3a486` |
| `+0x10` / u32 | generated scalar | input+8; preceding constructor's generated word |
| `+0x18` / u64 | input-A pointer | input+`0x0c`; optional 16 B daemon span |
| `+0x20` / u64 | input-B pointer | input+`0x20`; daemon processed 16 B block |
| `+0x28` / u32 | input count | input+`0x220`; daemon 16 |
| `+0x30` / u64 | output-A pointer | output+`0x0c` |
| `+0x38` / u64 | output-B pointer | output+`0x20` |
| `+0x40` / u32 | copied mutable count | *Q; UserClient normally seeds 512 |

The accessed argument-record extent is 68 B; 60 B are explicitly defined. Padding `[0x14,0x18)` and `[0x2c,0x30)` remains unspecified in the guest. Input/output payload bytes are not read in any retained prefix, including rejection returns. The scalar fixture `0xfedcba98` is a declared generated-word control, not a newly recovered daemon value. Initial scalar admission is independent of that scalar; later processing remains unknown. [VE4-VE6]

| W offset / width | Wrapper definition and role |
| --- | --- |
| `+0x00` / u32 | protected-entry result, read by wrapper after the call; not initialized by wrapper |
| `+0x08` / u64 | A |
| `+0x10` / u32 | address-keyed encoded operation |
| `+0x18` / u64 | A+4,096, exclusive end |
| `+0x20` / u64 | R |
| `+0x28` / u64 | W+16,384, exclusive end |
| `+0x30` / u64 | W+64, initial working pointer |

This wrapper's status is at W+0, and its argument-record pointer is at W+`0x20`. Do not substitute the other core2 wrappers' W+`0x14` / W+`0x28` conventions. The first payload-processing continuations stop outside this increment. [VE1,VE4]

## Operation key and global-state interfaces

All key arithmetic below is modulo 2^32. For p=low32(W), both source expressions reduce to:

```text
K = (p XOR 0x97099bc0) * 0xef54ff65
wrapper W[0x10] = K + 0x3da4b356
entry decoded_operation = W[0x10] - K = 0x3da4b356
```

The wrapper obtains the XOR constant through `0x92224700 XOR 0x052bdcc0`; the dispatcher uses `0x86d7342f XOR 0x11deafef`. Both reduce to `0x97099bc0`. The wrapper uses addition for this encoded operation, distinct from the XOR tag forms described for other wrappers. Source lifts prove the pack, decoder and composition separately. [VE4-VE5]

Three mutable u64 global cells participate. With M=`0x4d08a3fb` zero-extended to 64 bits and C=`0xa41a4d891208c018`, source updates are modulo 2^64:

| Phase | Cells and source equation |
| --- | --- |
| Wrapper | g=`*[0xfffffe000ccc7758]`, d=`*[0xfffffe000ccc32f8]`; t=(g+d) XOR (F+`0x90`); g'=(t*M) XOR C; d'=(t XOR C)*M |
| Protected entry | h=`*[0xfffffe000ccc3650]`, d=current shared cell; u=h XOR d XOR (F-`0x70`); h'=u*M-C; d'=(u XOR C)*M |

These are source state-update equations, not an assigned PRNG or concurrency protocol. The shared `0xfffffe000ccc32f8` cell is an architectural touch point between the wrapper and protected entry. No lock or native interleaving guarantee is inferred. [VE2,VE4-VE6]

## Exact initial scalar admission

The first mode comparison is unsigned u32 mode <=8. A 32-bit variable shift and mask `0x124` then select modes 2/5/8. Mask `0x90` selects the other admitted mode family, 4/7. The marker decision tree uses signed comparisons; its exact accepted sets below are proved over all u32 mode/marker pairs. [VE4-VE5]

| Mode | Marker set | Initial admitted continuation |
| --- | --- | --- |
| 2, 5, 8 | 23 values listed below | `0xfffffe000a5a5bf4` |
| 4, 7 | `0xc8584bc4`, `0x7a975b93`, `0x7184b44f` | `0xfffffe000a5a58a0` |
| Every other pair | none | rejection at `0xfffffe000a5a7290` |

The first family's complete marker set is:

```text
b4d3a486 c23729b3 d03b7ae1 fd029d6d 13f0ac06 14a96160
19967e25 2070d6b0 30a3976e 39b124b2 39c84ba4 39e897b5
3f5e9413 4653e2e2 525e5ba4 57e209d2 57e209d5 5b0895c9
5e5171e3 7184b44f 757ff287 7ed2ca46 7a975b93
```

For daemon modes 2/5 and marker `0xb4d3a486`, the original signed-comparison path is `0xfffffe000a5a5808 -> 0xfffffe000a5a5a70 -> 0xfffffe000a5a5b00 -> 0xfffffe000a5a5bd0`, followed by equality at `0xfffffe000a5a5be0` to `0xfffffe000a5a5bf4`. This gate has no native readiness, task authorization, input-content or successful-output meaning assigned to it. [VE1,VE4-VE6]

## Rejection, count and status channels

The initial entry error word is `0xce515b51`. Rejection stores W+0 and returns through the original 608 B dispatcher frame. The wrapper then copies its local R+`0x40` count to Q, retires the typed/workspace allocations, and returns W[0] XOR `0x31ae0066`, yielding `0xffff5b37` for this rejection. Its own frame is 256 B. The local count is unchanged on these rejection paths. No semantic error-code name is assigned. [VE1,VE4-VE6]

This is separate from the UserClient wrapper's outer IOReturn and structure status: under ordinary provider return, `ucRunVersioned` stores the provider result at output+`0x224` and returns outer zero. Only provider success copies the mutable count to output+`0x220`. Thus the core's unconditional local-to-Q copyback does not imply a UserClient count-field write on provider error. See [the exact provider ABI](versioned_request_abi_report.md). [VE7]

## Validation and provenance

| ID | Primary evidence and verification |
| --- | --- |
| VE1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext SHA256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Five source regions, 682 instructions / 2,728 B, no overlapping region instances. |
| VE2 | [Source extractor](triage_evidence/recover_versioned_core_entry.py): 15 exhaustive bank rules / 3,840 byte inputs, original selected chained pointers, ten pool pointer records and original typed-view pointer fields. |
| VE3 | Matching-KC exact allocator/free symbols and two original/normalized 64 B typed-view records retained in [checks](triage_evidence/versioned_core_entry_checks.json.zst). |
| VE4 | Fourteen source-derived Z3 obligations are freshly UNSAT. Fixed-cell/epoch premises and scalar-tree exclusions are explicit in the extractor; address-only loads excluded from the scalar predicate do not feed its comparisons. |
| VE5 | Eighty-six [private original-A64 replays](triage_evidence/versioned_core_entry_replays.json.zst): 43 mode/marker profiles in two placements, backing patterns, global fixtures and count fixtures. 43,582 instruction visits, 56,834 read bytes and 50,296 write bytes independently reconstructed. |
| VE6 | [Replay harness](triage_evidence/probe_versioned_core_entry.py): 58 admitted prefixes and 28 complete rejection returns, strict initialization checks, per-visit source-byte checks, epoch snapshots, preserved-register/SP checks, register-only heap models and zero modeled memory writes. |
| VE7 | Pinned [provider ABI](versioned_request_abi_report.md) source/check hashes and the preceding [daemon API join](daemon_postblock_dispatch_report.md) receipt. These preserve the cross-build/native pairing boundary. |
| VE8 | [Publication verifier](triage_evidence/verify_versioned_core_entry_publication.py): fresh source/proofs/replays, exact manifest delta, preserved original inputs, logical archive hashes and decoded path/hex/typed-payload hygiene. No live IDA was required or used. |

The daemon source hash remains `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Input files and IDBs remain unmodified. The guest executes original instructions under explicit models; it does not invoke native APIs. These counts contain no native allocation, IPC or cryptographic-processing execution. Complexity is O(B+I+256R) for extraction and O(C*(B+V+E)) for retained replays, plus solver cost capped at 30 s/query; each replay has a 2,000-instruction bound. [VE1-VE8]

## Bounded continuation

| Impact | Next investigation | Discriminating evidence |
| --- | --- | --- |
| High | Continue `0xfffffe000a5a5bf4` with the recognized daemon mode/marker. | Actual optional-span/generated-word/block consumption and count/result definitions after initial admission. |
| High | Trace caller connection initialization and coherent native admission. | Concrete right ownership, provider/task epoch and matching daemon/kext execution, beyond static compatibility. |
| Medium | Establish allocator failure/lifetime and global-state serialization contracts. | Real allocation behavior, type-view runtime links, synchronization and their caller premises. |
| Low | Compare other mode/marker families. | Whether initial partitions converge later; initial admission alone does not establish operation equivalence. |

No new Mach port, right transfer or emission PC is established. The previously recovered pending daemon emission boundary remains `0x100478a04`. The broader interface investigation remains active.

## Quality gates

- **QG1**: Pass. Factual interface analysis requires no normative content.
- **QG2**: Pass. VE-A1..VE-A8 identify dependencies and falsification probes.
- **QG3**: Pass for this increment. Workspace/record, scalar partition, global state, count/result and rejection cleanup are covered; complete processing and the full goal remain open.
- **QG4**: Pass. Byte extents, u32/u64 modular arithmetic, signed/unsigned predicates, replay bounds and complexity are explicit and reproducible.
- **QG5**: Pass. Entry admission, successful processing, core/provider/outer status, local/structure count and distinct core layouts remain separate. Native unknowns are explicit.
- **QG6**: Pass. Exact original/normalized bytes, source lifts, symbolic versus finite controls, modeled calls and prior receipt pins are distinguished.
- **QG7**: Pass. Impact-ranked continuation and global/allocator architectural touch points are bounded above.
