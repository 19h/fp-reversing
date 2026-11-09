# FairPlay mapped-region cleanup and close suffix

Original kernel-collection bytes establish a conditional mapped-region cleanup role inside `_oh70aLVr` (`0xfffffe000a5bff88`). The suffix loads a child record from owner+`0x2e8`, conditionally requests unwiring and deallocation for child+`0x48/+0x50`, conditionally deallocates child+`0x58/+0x60`, and requests `_IOFreeTypeImpl` for the child. These are source call requests. Native VM effects, successful registry lookup, the original caller's entry state, and a continuous constructor-to-close lifetime remain unknown. [MC1-MC8]

The [earlier VM report](kext_port_vm_report.md) establishes installation of a mapped reply address and u32 extent at reply record0+`0x48/+0x50`. The matching cleanup offsets now have original-source consumers. Their identity across the complete protected constructor, context publication, pager use and close invocation is conditional; matching offsets alone do not prove object identity. The broad interface investigation remains active.

Evidence: [original source, symbols, fixups and proofs](triage_evidence/kext_mapped_cleanup_source.json), [60 private suffix cases](triage_evidence/kext_mapped_cleanup_profiles.json), [independent checks](triage_evidence/kext_mapped_cleanup_checks.json), [preservation](triage_evidence/kext_mapped_cleanup_delivery.json), and [scoped quality gates](triage_evidence/kext_mapped_cleanup_quality_gates.json).

## Assumption register and provenance

| ID | Explicit premise / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| MC1 | Original collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` is the analyzed image. All static claims are image-specific. | Rehash the collection and compare captured bytes, nlist names and format-8 fixups; compare native kernel/kext UUIDs separately. Native pairing with the daemon is unknown. |
| MC2 | Normalized kext SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` supplies logical pointers. | Every captured kext code span and bank byte is compared with the original collection; pointer slots are checked against original chain metadata. Hardware PAC is not exercised. |
| MC3 | Private entry at `0xfffffe000a5c0d78` has the declared frame/banks, readable owner, W0=`0xcb262240`, W21=`0x1eb`, and source-compatible preserved registers. | Two isolated original CPU seed fragments verify W21=`0x1eb`, W22=`0x7a3`, including the optional predecessor seed calculation. Establish a continuous successful native lookup/tag path before asserting reachability. |
| MC4 | Owner+`0x2e8` is either NULL or points to a readable private child with the declared fields. | Cases vary NULL/non-NULL owner field, both region pointers and both u32 extents. Recover the constructor's exact object identity, allocation extent and native lifetime. |
| MC5 | `_kernel_map` and `_PAGE_SHIFT_CONST` are readable and hold the declared private values. | The source file contains page-shift value 0; runtime value is unknown. Cases/proofs use shifts 12, 14 and 16, respectively 4096, 16384 and 65536 bytes per page. Obtain runtime values before assigning a native range. |
| MC6 | Call models return 0 or 4, preserve AAPCS64 callee-saved registers, clobber caller-saved registers, and have no memory effects. | Replay verifies call arguments, targets, modifiers and clobbers. Thirty status pairs take identical paths. Native VM/release effects and arbitrary callee side effects are outside this contract. |
| MC7 | A64 u64 arithmetic wraps modulo 2^64; lengths are loaded as u32 and zero-extended. | Six source proofs quantify all u64 addresses/u32 extents for the three fixed page shifts. Finite cases include zero length, page crossing, u32 maximum and address wraparound. Other page shifts are unproved. |
| MC8 | Constructor staging and publication fragments are component identities. Their interblock control/alias continuity is unknown. | Check the recorded register/frame epochs at each transfer and compose the protected path before treating the reply destination, C+`0x60`, owner child and page-consumer record as one object. |

No IDA query was necessary for this increment: original collection bytes, symbols, fixups and supplied reference artifacts were sufficient for its bounded claims. No IDB, saved memory, original input, native task, Mach right or VM state was changed.

## Recovered calls and field contract

Let O be the private owner at suffix entry, R=`load64(O+0x2e8)`, A=`load64(R+0x48)`, N=`load32(R+0x50)`, B=`load64(R+0x58)` and M=`load32(R+0x60)`. S is the suffix SP. The record identity R is distinct from the earlier close wrapper's shared stack argument record at FP-`0x88`. [MC3,MC4]

| Role | Source address | Proven operation |
| --- | --- | --- |
| Select child | `0xfffffe000a5c0d8c` | X20=`load64(O+0x2e8)`; NULL bypasses the child cleanup |
| Guard primary | `0xfffffe000a5c0dcc` | Load R+`0x48`; NULL bypasses both primary calls |
| Unwire request | `0xfffffe000a5c0f7c` | `_kernel_vm_map_unwire(kernel_map, floor_page(A), ceil_page(A+N), 0)` |
| Primary deallocation request | `0xfffffe000a5c0fe8` | `_kernel_vm_deallocate(kernel_map, A, zero_extend64(N))` |
| Guard secondary | `0xfffffe000a5c1040` | Load R+`0x58`; NULL bypasses secondary deallocation |
| Secondary deallocation request | `0xfffffe000a5c10cc` | `_kernel_vm_deallocate(kernel_map, B, zero_extend64(M))`; no secondary unwire call in this suffix |
| Typed child free request | `0xfffffe000a5c1170` | `_IOFreeTypeImpl(0xfffffe000847bc60, R)` |
| Next unexamined owner continuation | `0xfffffe000a5c119c` | Stop boundary; remaining owner lifetime and wrapper result are unknown |

```text
O+0x2e8 -> R == NULL ---------------------------> owner continuation
            |
            +-- A != 0 -> unwire rounded range
            |             -> deallocate exact A,N
            |
            +-- B != 0 -> deallocate exact B,M
            |
            +-- IOFreeTypeImpl(type descriptor,R)
                          |
                          +--------------------> owner continuation
```

The calls' status returns are not tested in the inspected suffix. The primary deallocation reloads X0 from the kernel-map cell and reloads A/N after unwire. Deallocation returns are overwritten with the local control constant. No store clears the child fields or O+`0x2e8` before the typed-free request in the tested interval. This observation is limited to the interval; subsequent owner retirement or field clearing is unknown. The no-effect models preserve the input records by construction. [MC3-MC6]

## Exact table and import provenance

The table base is `0xfffffe0008472f20`; the constant pool base is `0xfffffe0008471f00`. Each selector identity checks all 256 byte inputs. A shared PAC discriminator is insufficient to identify a callee: the earlier request-copyin site also uses `0xdff5`. The bank roots and selected original pointer slot establish the unwire binding here. [MC1,MC2]

| Operation | Left / right byte-bank roots | Key; collapsed byte; index | Original slot -> logical target |
| --- | --- | --- | --- |
| Unwire | `0xfffffe0007949fd0` / `0xfffffe000792ffc0` | `ac`; `06`; `f88` | `0xfffffe000847ab60` -> `0xfffffe000a508e14`, IA diversity `dff5`, address-diversity 0 |
| Deallocate | `0xfffffe0007949dd0` / `0xfffffe000792fbc0` | `5c`; `d2`; `edd` | `0xfffffe000847a608` -> `0xfffffe000a508e1c`, IA diversity `8bbb`, address-diversity 0 |
| Typed free | Same as deallocate | `3e`; `54`; `f2b` | `0xfffffe000847a878` -> `0xfffffe000c4ba368` |
| Kernel-map cell | Same as deallocate | `5c`; `d2`; pool index `162` | `0xfffffe0008472a10`, target minus 4 -> `_kernel_map` cell `0xfffffe0007f860a8` |
| Page-shift cell | `0xfffffe000792fcc0` / `0xfffffe00079391f0` | `47`; `7b`; pool index `183` | `0xfffffe0008472b18` -> `_PAGE_SHIFT_CONST` `0xfffffe0007e6d9c0` |
| Type descriptor | Same as deallocate | `16`; `88`; pool index `bc` | `0xfffffe00084724e0`, target minus 8 -> `0xfffffe000847bc60`; exact type name unknown |

| Kext adapter / thunk | Original authenticated import | Matching-kernel target / continuation |
| --- | --- | --- |
| `_kernel_vm_map_unwire` `0xfffffe000a508e14` -> thunk `0xfffffe000a69f484` | Slot `0xfffffe000847c570`, IA diversity 0, address-diversity 1 | Exact `_vm_map_unwire` `0xfffffe000bdcfd5c`; sets X4=`0xfffffe0007e6b840` and tails to `0xfffffe000bdcf67c` |
| `_kernel_vm_deallocate` `0xfffffe000a508e1c` -> thunk `0xfffffe000a69f444` | Slot `0xfffffe000847c550`, IA diversity 0, address-diversity 1 | Exact `_vm_deallocate` `0xfffffe000be2d068`; tails to shared VM leaf `0xfffffe000bdc1ec0` |
| Exact `_IOFreeTypeImpl` `0xfffffe000c4ba368` | Direct selected original table target | Tails to `0xfffffe000bcff010`; lower free effects are not executed |

The mapped reply uses `vm_deallocate`, distinct from the `kmem_free` request-staging cleanup already recovered. The shared VM leaf checks null map, zero size, u64 addition carry and rounded end greater than start before its lower range operation. These original guard instructions are captured; their native operation is not executed here. [MC1,MC2,MC6]

## Range arithmetic, staging and publication boundaries

For the fixed tested page shifts p in {12,14,16}, define Q=`2^p` bytes and MASK=`~(Q-1)` as u64. Source proofs establish the following identities for every u64 A and u32 N under the local seed and load contracts. Additions are u64 modulo 2^64. [MC3,MC5,MC7]

```text
unwire_start = A & MASK
unwire_end   = (A + zero_extend64(N) + Q - 1) & MASK
dealloc_base = A
dealloc_size = zero_extend64(N)
```

An unaligned nonzero A with N=0 still requests the rounded unwire interval, whereas the subsequent deallocation receives size 0. A wrapped address-plus-length can yield an end below the start. These are argument-flow results; they do not establish accepted ranges, a native failure, or a vulnerability. The original lower deallocation leaf has separate overflow/size/range checks. The actual runtime page shift, map state and API results are unknown.

The constructor fragments provide the following partial object-publication chain. They do not establish that every transfer belongs to a single execution or that no intervening protected path changes a register or slot. [MC8]

| Source fragment | Local transfer / contract | Remaining dependency |
| --- | --- | --- |
| `0xfffffe000a60ab50` | Store allocation result X0 into C+`0x58` | Allocation success and predecessor reachability |
| `0xfffffe000a60ab78` | X27=X0 | Selected successor and preserved result |
| `0xfffffe000a60ae48` | SP+`0x88`=X27 | X27/frame epoch across intervening protected blocks |
| `0xfffffe000a6110d0..0xfffffe000a6110d8` | Reload C from SP+`0x1a8`; C+`0x60`=load64(SP+`0x88`) | Same C and saved-slot epoch |
| `0xfffffe000a61240c..0xfffffe000a612420` | Reply destination receives mapped address/extent and zeroed secondary fields | Previously established C+`0x58` identity and mapping-success path |
| `0xfffffe000a6165e4..0xfffffe000a6165fc` | Owner+`0x2e8`=load64(C+`0x60`); owner+`0x2f0`=0 if NULL, otherwise `0x98` | Owner provenance, protected predecessors, publication into live registry |
| `0xfffffe000a5c0d8c` | Close suffix loads owner+`0x2e8` | Same live owner and native close token/registry lookup |

A bounded scan checks 422089 aligned words in this normalized kext's A5-A6 segments and rechecks matching words against the original collection. It finds 14 unsigned-offset `STR Xn,[Xm/SP,#0x2e8]` encodings: seven use SP and seven use a general register. The catalog includes the constructor store at `0xfffffe000a6165f8`, other protected candidates and a zero store at `0xfffffe000a68d3c4`. General-register bases do not establish an owner type. This scan excludes STUR, STP, computed offsets, aliases and other encodings; it is not a complete writer census. [MC1,MC2,MC8]

## Validation, reproduction and limits

The source capture retains 16 ranges / 524 original instructions, six exhaustive selector identities with original pointer provenance, six SMT proofs and the 14 candidate stores. Sixty private CPU cases execute 11862 source visits. A separate executor rechecks every visited original word, 2538 reads, 60 writes, 450 logical authenticated edges, 162 API-model requests and 60 final boundaries. It verifies 42 unwire requests, 42 primary deallocation requests, 24 secondary deallocation requests and 54 typed record-free requests. Thirty 0/4 return-status pairs have identical source paths. The two isolated seed fragments check 13 additional source instructions. These are finite component witnesses plus bounded scalar proofs. [MC1-MC8]

Reproduction uses the supplied Python environment and the existing pinned Z3 runtime:

```sh
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
  Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kext_mapped_cleanup.py
env PYTHONPATH=triage_evidence \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kext_mapped_cleanup.py
env PYTHONPATH=triage_evidence \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kext_mapped_cleanup.py
```

Recovery takes O(B+I+256K+W), where B is image bytes read, I captured instructions, K selector banks and W scanned instruction words, plus timeout-bounded SMT solving. CPU recording/replay takes O(B+V+E) time and O(B+J) space, where V is visits, E modeled events and J retained journals. Publication validation takes O(total artifact bytes + links). No running daemon, native kernel code, Mach transaction, hardware PAC, allocation/free or mapping operation is exercised.

The supplied [zut trace](zut_trace_report.md) still ends with an unsuccessful UserClient open. It provides neither an observed mapped reply nor a close invocation. The private suffix cases do not extend that trace into a successful native transaction. No incoming/outgoing Mach port or additional IPC emission site is established by this increment.

## Bounded continuation and quality gates

| Impact | Remaining question / opportunity | Discriminating evidence |
| --- | --- | --- |
| High | Continuous record identity | Compose allocation -> C+`0x58` -> X27/SP+`0x88` -> C+`0x60` -> owner+`0x2e8` using actual protected control/frame epochs |
| High | Native close entry | Recover successful token/registry lookup, owner tag `0x42059342`, owner references and caller continuity before claiming a completed close |
| High | Page-consumer ownership | Correlate the record and mapped bytes with `EQlZPp` page callbacks and final close; establish synchronization and reuse epochs |
| Medium | Wire/unwire result handling | Follow original caller continuations and owner retirement around unsuccessful VM operations; current suffix only establishes ignored local returns |
| Medium | Descriptor and release extent | Resolve type descriptor `0xfffffe000847bc60`, allocation request and complete lower `_IOFreeTypeImpl` contract |
| Low | Writer census | Expand the explicitly bounded STR candidate scan to other encodings only where owner provenance warrants it |

- QG1: Factual source/ABI analysis; no normative conclusion required.
- QG2: MC1-MC8 register premises, dependent conclusions and falsification probes.
- QG3: Scoped suffix, selectors, imports, fields, arithmetic, publication candidates and validation covered. Full interface goal remains incomplete.
- QG4: Byte lengths, u32/u64 widths, modular arithmetic, page sizes and complexity are explicit; original-word replay and six proofs pass.
- QG5: NULL, zero-size, page-crossing, maximum u32, wraparound and nonzero-return cases are separated. Continuous/native lifetime is explicitly unknown.
- QG6: Original-file code, names, fixups and bank bytes are rechecked; private models and component claims are distinguished from native observations.
- QG7: Impact-labeled continuation is bounded to unresolved ownership, control and interface contracts.
