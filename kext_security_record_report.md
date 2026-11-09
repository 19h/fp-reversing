# FPAppSecurityInfo: allocation, reply capacity and typed release

Original type metadata identifies the record family as `site.FPAppSecurityInfo`, with a requested size of `0x98` (152 bytes). The protected allocation call selects view `0xfffffe000847bd60`; the previously recovered close suffix selects view `0xfffffe000847bc60`. Their original 64-byte contents are identical, including the type name, signature string, flags and size. The views have distinct addresses and potentially distinct initialized state. This establishes a shared static type description, not native object identity or allocator-zone equivalence. [SR1-SR8]

The original RPC502 client writes exactly 136 bytes to its first fixed-record output. The 152-byte allocation request has capacity for that record, with 16 bytes beyond the fixed wire span. Six component compositions transfer source-produced caller record bytes into the original reply-copy fragment and verify the final 136 bytes plus preserved suffix. Full allocation -> RPC -> owner publication -> page use -> close continuity remains unknown.

Evidence: [original views, functions, selectors and copy-store intervals](triage_evidence/kext_security_record_source.json), [private CPU cases and compositions](triage_evidence/kext_security_record_profiles.json), [independent checks](triage_evidence/kext_security_record_checks.json), [preservation](triage_evidence/kext_security_record_delivery.json), and [scoped gates](triage_evidence/kext_security_record_quality_gates.json). The [mapped-region cleanup report](kext_mapped_cleanup_report.md) retains the exact unwire/deallocation/free requests.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SR1 | Original collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` supplies code, metadata, names and format-8 fixups. | Rehash and recapture all ranges and pointers. Native daemon/kernel pairing remains unknown. |
| SR2 | Descriptor names and signature bytes describe a static type family. | Compare both original 64-byte views, string targets and `__kalloc_type` membership. Do not infer equal native zones/stats from equal file bytes. |
| SR3 | Private initialized-view fixtures provide a nonzero zone, statistics base, alternate-zone operand, CPU index and selected counter. | Test file-state heap, populated-zone and alternate-zone routes at CPU indices 0 and 3. Inspect original native initialization before assigning runtime values or grouping the two views. |
| SR4 | The conditional caller fragment starts with W20=`0xc96`, W22=`0x87`, declared banks/frame values, and a readable C. The native predecessor derivation of W20 is unknown. | Recover protected predecessor invariants. Original prologue fixes FP=SP+`0x2d0`; fixtures use that relation. Caller NULL/non-NULL branches are conditional results, not proof of native reachability. |
| SR5 | Lower allocator calls return a declared NULL/private pointer and preserve callee-saved registers while clobbering caller-saved registers/NZCV. | Independently check arguments, return registers and original return/control instructions. No allocator, OOM, allocation capacity, free, or native initialization effect is executed. |
| SR6 | Canary-backed private storage is explicitly 152 bytes; original metadata requests 152 bytes. | Derive request extent from the original descriptor/delegate and check all record writes. Canary preservation describes source stores under the model, not native allocator contents. |
| SR7 | Reply-copy entry is a component after successful validation, with first fixed-record input at SP+`0x54` and output at the declared record. | Recheck the five original stores and all 136 copied bytes. Reuse source-produced caller bytes in six compositions. Actual reply validation, transport, descriptor conversion and full caller continuity remain unestablished. |
| SR8 | C+`0x58`, X27/SP+`0x88`, C+`0x60` and owner+`0x2e8` transfers are component evidence across protected frame epochs. | Compose the complete original path and native lookup before equating the allocated, reply, owner-child and close records. |

The original inputs and IDBs were preserved. No live target/kernel execution, Mach operation, native allocation/free, hardware PAC or saved-memory write was performed. Original references were sufficient; no additional IDA query was required.

## Static type and record extents

| Property | Allocation view | Cleanup view |
| --- | --- | --- |
| Address | `0xfffffe000847bd60` | `0xfffffe000847bc60` |
| Owning section | FairPlayIOKit `__DATA_CONST,__kalloc_type` | Same section |
| File bytes +0 through +15 | Zero | Zero |
| Name pointer at +`0x10` | `0xfffffe0007936ff4` | Same |
| Name bytes | `site.FPAppSecurityInfo` | Same |
| Signature pointer at +`0x20` | `0xfffffe00079330d0` | Same |
| Signature bytes | `2222222221212222222` | Same; encoding semantics unassigned |
| Flags u32 at +`0x28` | `0x64` | `0x64` |
| Size u32 at +`0x2c` | `0x98` = 152 bytes | Same |

| Byte range within the requested 152-byte record | Established role |
| --- | --- |
| `[0x00,0x88)` | Fixed RPC502 first-record output span, 136 bytes |
| `[0x48,0x50)` | Mapped-address field after the normal mapping path replaces the reply value |
| `[0x50,0x54)` | u32 mapped extent after that replacement |
| `[0x58,0x60)` | Secondary pointer, cleared by initial caller stores and the mapped-reply path |
| `[0x60,0x64)` | Secondary u32 extent, explicitly cleared by the mapped-reply path |
| `[0x88,0x98)` | Outside the fixed RPC record; meaning and native initialization unknown |

The source caller's initial stores clear only the qwords at +`0x48` and +`0x58` in the inspected fragment. It does not clear the adjacent u32 lengths there. A later successful RPC copy overwrites the entire `[0,136)` span. The normal mapped-reply path subsequently installs the VM fields and clears the secondary pointer/extent. These operations occur at distinct source stages. [SR4-SR8]

```text
IOMallocTypeImpl(view BD60: FPAppSecurityInfo,152 bytes)
    -> lower allocator request [explicit return model]
    -> C+0x58 = returned pointer
    -> NULL: separate conditional continuation
    -> non-NULL: X27 = pointer; clear two pointer fields
         |
         +-- declared component transfer --> original RPC first-record copy
                                             writes [0,136)
                                             preserves [136,152)

later source staging/publication -> owner+0x2e8 [continuity unknown]
close child -> IOFreeTypeImpl(view BC60: same static type description)
```

## Exact call and lower allocator interfaces

The allocation call at `0xfffffe000a60ab2c` resolves through original table slot `0xfffffe000847a7b8` to exact `_IOMallocTypeImpl` at `0xfffffe000c4ba154`, modifier `0xd0c8`. The left/right banks `0xfffffe0007949ed0` / `0xfffffe000792fec0`, key `0x32`, collapse to byte `0xf9`, giving table index `0xf13`. The type-view selector uses banks `0xfffffe000792fcc0` / `0xfffffe00079391f0`, key `0x87`, collapsed byte `0xdf`, pool index `0x13c`; original slot `0xfffffe00084728e0` stores the view address biased by +12. Both identities check all 256 inputs and retain original pointer provenance. [SR1,SR4]

The original wrapper reads descriptor flags+`0x28`. For the original flags `0x64`, it selects raw W1=`0x8004` and tails to exact `_kalloc_type_impl` at `0xfffffe000bcfeb8c`. That implementation reads view+0. The following raw argument contracts are verified for the declared private states; flag-bit meanings are not assigned beyond their source operations. [SR3,SR5]

| Runtime-view branch | Original lower boundary | X0 | X1 | W2 / X3 |
| --- | --- | --- | --- | --- |
| view+0 is NULL; original flags/size | Call `0xfffffe000bcfec20` -> `0xfffffe000bcfe5b8` | Heap operand `0xfffffe0007f36938` | 152 bytes, derived from size word & `0xffffff` | W2=`0xd1004`; X3=0 |
| view+0 non-NULL; selected stats word+`0x1c` nonzero | Call `0xfffffe000bcfebdc` -> `0xfffffe000bd75c64` | view+0 zone operand | Unadjusted view+8 statistics base | W2=`0xd1004` |
| view+0 non-NULL; selected stats word+`0x1c` zero | Same call | Alternate operand loaded from view+`0x30` | Unadjusted view+8 statistics base | W2=`0xd1044` |

The statistics test reads `load32(stats_base + (load16(TPIDR_EL1+0x1b8) << 14) + 0x1c)`. The lower call still receives the unadjusted statistics base. This distinction is independently checked at private indices 0 and 3. The fixture labels describe the observed field use; they do not recover the complete native statistics type or CPU-state initialization.

The original file has a zero view prefix. This explains the file-state component route, not the live kernel's route: startup can populate runtime view fields. Likewise, the original identical descriptors do not prove that allocation and cleanup use identical zones after initialization.

Exact `_IOFreeTypeImpl` at `0xfffffe000c4ba368` tails to exact `_kfree_type_impl` at `0xfffffe000bcff010`. Its view+0 test selects the following boundary contracts. No lower release body executes. [SR1-SR3,SR5]

| Cleanup branch | Boundary | Arguments retained / derived |
| --- | --- | --- |
| view+0 NULL, original flags/size | Tail `0xfffffe000bcff050` -> `0xfffffe000bcfec48` | X0=heap operand `0xfffffe0007f36938`, X1=record argument, X2=152 bytes |
| view+0 non-NULL | Tail `0xfffffe000bcff01c` -> `0xfffffe000bd7a4b8` | X0=cleanup view `0xfffffe000847bc60`, X1=record argument; lower zone-release ABI beyond this entry is unknown here |

## Caller and reply-copy contract

Under the explicit caller seed W20=`0xc96`, a NULL return stores NULL at C+`0x58` and selects original slot index `0xc97`, target `0xfffffe000a608958`. A non-NULL return selects index `0xc96`, target `0xfffffe000a60ab74`, copies the pointer into X27, and reaches the two source pointer-clearing stores. The native producer of that control seed remains unknown. The caller tests do not infer allocation failure behavior on a running system. [SR4-SR6]

The original reply-copy fragment `0xfffffe000a5a21ec..0xfffffe000a5a2228` has five record stores:

| Store PC | Destination offset | Width |
| --- | --- | --- |
| `0xfffffe000a5a21fc` | `0x20` | 32 bytes |
| `0xfffffe000a5a2208` | `0x80` | 8 bytes |
| `0xfffffe000a5a2214` | `0x60` | 32 bytes |
| `0xfffffe000a5a221c` | `0x40` | 32 bytes |
| `0xfffffe000a5a2224` | `0x00` | 32 bytes |

Their union is exactly `[0,136)`; the sum is `4*32+8=136` bytes. Requested extent minus fixed-record extent is `152-136=16` bytes. Six compositions use the actual private non-NULL caller outputs, execute these original SIMD/GPR copy instructions and check every destination byte plus the untouched suffix. The source entry bypasses earlier RPC validation as an explicit component premise. No additional Mach right or IPC emission site is established. [SR6,SR7]

The following staging remains component evidence from the [cleanup report](kext_mapped_cleanup_report.md): X27 -> SP+`0x88` at `0xfffffe000a60ae48`; saved slot -> C+`0x60` at `0xfffffe000a6110d8`; C+`0x60` -> owner+`0x2e8` at `0xfffffe000a6165f8`. Establishing their common frame and owner epochs is the next lifetime join. [SR8]

## Validation and remaining interfaces

Four complete original functions and ten original slices retain 201 instructions, two exhaustive 256-input selectors, both 64-byte type views, original strings/fixups and five reply stores. Forty-two independently replayed cases execute 1636 original visits: 12 allocator components, 12 conditional caller components, 12 free-routing components and six allocation-output/reply-copy compositions. Replay verifies 518 reads / 3360 bytes, 174 writes / 1392 bytes, 72 logical PAC steps, 24 lower allocator return models and 42 final boundaries. The 24 modeled allocation requests divide equally across heap, selected-zone and alternate-zone paths. Free cases stop at four heap and eight zone boundaries. Caller cases divide into six NULL and six non-NULL branches. [SR1-SR8]

```sh
env PYTHONPATH=triage_evidence \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kext_security_record.py
env PYTHONPATH=triage_evidence \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kext_security_record.py
env PYTHONPATH=triage_evidence \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kext_security_record.py
```

Source recovery takes O(B+I+256K) time, where B is image bytes, I retained instructions and K selector banks. CPU recording/replay takes O(B+V+E) time and O(B+J) space, with V visits, E modeled events and J journals. Byte-extent checking is O(S+L), where S is the five stores and L the 152-byte requested record. No solver or unbounded execution is needed for this increment. The lower allocator return model supplies no memory effects.

| Impact | Unresolved interface | Discriminating next evidence |
| --- | --- | --- |
| High | Continuous pointer publication | Original protected execution connecting C+`0x58`, X27, saved slot, C+`0x60` and owner+`0x2e8` in one frame epoch |
| High | Caller control seed | Establish the native predecessor of W20=`0xc96`, instead of relying on the conditional component seed |
| High | Page-reader identity | Map the same FPAppSecurityInfo instance into page-decrypt callbacks and close token/registry lookup |
| Medium | Runtime type initialization | Recover startup writers of both views' zone/statistics/alternate fields and prove any relevant zone equivalence |
| Medium | Allocation/free effects | Extend original lower backends with explicit size classes, initialized contents and reference ownership before claiming native capacity or retirement |
| Low | Trailing 16 bytes | Identify writers/readers of `[0x88,0x98)`; no field semantics are assigned from capacity alone |

- QG1: Factual binary/type/ABI analysis; no normative conclusion required.
- QG2: SR1-SR8 register assumptions, dependent claims and falsification probes.
- QG3: Static type, requested extent, exact call bindings, local allocator/free interfaces, conditional caller and byte-copy composition covered; full goal remains incomplete.
- QG4: All offsets/extents are bytes; u16/u32/u64 reads, 24-bit size mask, frame relation, CPU stride and complexity are explicit. Original-word replay and byte oracle pass.
- QG5: Distinct views and runtime states, NULL/non-NULL results, both statistics branches, model contents and native gaps remain separated.
- QG6: Original code, symbols, metadata, fixups and source-produced bytes are verified independently. No native effect or reachability is inferred from private executions.
- QG7: Impact-labeled continuation is bounded to remaining identity, control, initialization and ownership interfaces.
