# Copyin policy selector, startup writer and environmental predicate

The original collection initializes cell `0xfffffe0007e6a01c` to u32 value2. Its exact boot-parameter binding is the original string `vm_map_cow_defeatured_enforce`, a24-byte argument record, and a startup callback. Original startup/parser execution in three private cases locates the indirect four-byte store at `0xfffffe000c5e4b38`. File initialization and private parser behavior do not attest the native runtime value. [CP1-CP4]

Original predicate helper `0xfffffe000bdc6bc8` and the small-copy prefix in `0xfffffe000bdd15a4` make matching decisions under the tested prerequisites. Nonzero selector values consult source-map or owner-associated object flags, with a thread-flag exception on one branch. Thus the preceding [outgoing OOL report](rpc502_reply_copyin_report.md) remains a conditional result: its explicitly supplied selector0 differs from file initialization2. This increment establishes the latter and exercises the additional predicate rather than treating the prior private premise as native state. [CP3-CP8]

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| CP1 | The hash-pinned collection is the intended static image | Initial data, startup records, references and instructions | Rehash and recapture originals; attest the loaded kernel/slide separately |
| CP2 | Original startup records describe the callback/argument binding | Boot-parameter identity and writer route | Check chained membership/targets and the actual startup dispatcher; native invocation is not executed here |
| CP3 | Private boot-record binding and test strings describe only the supplied parser fixtures | Absent/present parse behavior and four-byte writes | Compare actual boot-input binding and runtime value; no host configuration is read or changed |
| CP4 | Metadata, owner placement and object pointers satisfy the declared private geometry | Original owner lookup and associated-object paths | Validate native zones, multiplier, owner backlink and pointer lifetimes; private allocation validity is not native provenance |
| CP5 | Map/thread/associated flags and scalar V have the declared values without concurrent mutation | Local predicate and paired branch selection | Read their live writers/epochs; raw offsets remain authoritative and private semantic types are provisional |
| CP6 | Positive extent37, valid map interval/page shift14 and clear excluded option bits hold | Predicate/gate equivalence before buffer factory or range validation | Exercise other sizes, flags and boundary ranges; predicate0 alone does not guarantee a buffer outside this domain |
| CP7 | Logical PAC and a returning read-lock model apply | Parser callbacks, pointer reads and gate boundary | Test hardware authentication and actual locking separately; only the bound local callback target is followed |
| CP8 | Independent replay and the bounded direct-reference scan cover their stated domains | Finite counts, writer evidence and reference inventory | Rebuild both; indirect aliases, literal/GOT routes and arbitrary data flow are outside the scan's completeness claim |

Original image: `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. [Source recovery](triage_evidence/kernel_copyin_policy_source.json) retains10 compiler-bounded functions /1,399 instructions, original pointer records, initial bytes and bounded reference paths. Exact nlist names include `_kernel_task`, `_strlen` and `_strncmp`; names assigned to other helpers describe roles rather than exact symbols. [CP1,CP2]

## Startup identity and indirect writer ABI

```text
startup record 0xfffffe000cbec948
  +8  -> callback 0xfffffe000c6306e0 (authenticated original fixup)
  +16 -> argument record 0xfffffe000ca881c0
           +0  -> "vm_map_cow_defeatured_enforce"
           +8  -> policy cell 0xfffffe0007e6a01c
           +16 -> extent4; flags at+20/+21 are0
                     |
                     v
original callback -> original parser 0xfffffe000c5e48a4
                     -> indirect store at 0xfffffe000c5e4b38
```

| Binding | Original location | Evidence |
| --- | --- | --- |
| Parameter string | `0xfffffe000ca881a0` | Original NUL-terminated bytes; no nearest-symbol inference |
| Name / destination pointers | Argument+0 /+8 | Original format8 chain members resolve to the string and policy cell |
| Extent and flags | Argument+16 /+20 /+21 | u32 size4; flag bytes0/0 |
| Startup callback / argument | `0xfffffe000cbec950` /`...c958` | Original fixups resolve to callback and argument; callback discriminator `0x2abe` |
| Parser entry | `0xfffffe000c630724` -> `0xfffffe000c5e48a4` | X0=private boot text, X1=name, X2=policy cell, W3=4, W4=0 |
| Observed indirect write | `0xfffffe000c5e4b38` | Four bytes at the passed destination in each present-value case |

The parser fixtures start with value2. An unrelated private argument leaves2; matching integer values1 and2 produce those four-byte values. The callback's flag+20 is0, so its optional Boolean-normalization store is not selected. The original numeric parser calls its original character classifier at `0xfffffe000c5e4f50`; source PACIA/BLRAA use discriminator `0x0ba5`. The binding is checked and followed logically; hardware authentication is not executed. No actual startup dispatcher or host boot configuration is changed. [CP2,CP3,CP7]

## Local predicate and cross-object data flow

Define G as the selector u32, V as u32 at `0xfffffe0007f8b5f0`, S as source-map byte+`0xb3` bit1, and T as thread u16+`0x480` bit1. S is the same physical bit as source-map u32+`0xb0` bit25, which supplies VM-copyin option bit9. Original file V is0; its native value and semantic identity remain unestablished. [CP1,CP5]

Original owner lookup `0xfffffe000bd7e9c4` reads thread+`0x420`, validates its range, placement and zone tag3, verifies the object's backlink equals the thread, and returns object+`0x28`. Call the returned value R. The predicate compares R against null and exact `_kernel_task`; otherwise it loads/authenticates R+`0x28` and calls that pointer A. These raw relations are established; complete private types and ownership of R/A remain unknown. [CP4,CP5]

```text
thread+0x420 -> owner object -- backlink+0 must equal thread
                    |
                    +0x28 -> R -- compare null / kernel_task
                                |
                                +0x28 -> A (authenticated, modifier0x5ef8)
                                           |
                                           +0xb3 bit1

source-map+0xb3 bit1 -> fallback predicate
thread+0x480 bit1    -> exception on the A-based branch
```

The inspected helper's local decision is:

```text
if G == 0: return 0
if V > 18 or thread.owner_word != 0:
    R = original_owner_lookup(thread)  // requires valid owner metadata
    if R != 0 and R != kernel_task:
        A = authenticated_load_u64(R+0x28)  // stored zero returns zero
        if A != 0:
            return bit1(A.byte_at_0xb3) and not bit1(thread.u16_at_0x480)
return source_map != 0 ? bit1(source_map.byte_at_0xb3) : 0
```

The thread-bit exception does not apply to the source-map fallback branch. Values1 and2 are equivalent only for this helper's nonzero test; this does not assign whole-system meanings to those selector values. Invalid owner metadata can terminate before the returned decision and is not modeled as a successful lookup. [CP4,CP5]

For the positive small-copy domain in CP6, returned1 matches the copyin prefix's range-validation boundary at `0xfffffe000be3218c`; returned0 matches arrival at backing-allocation boundary `0xfffffe000bcfe5b8`. Neither boundary executes its VM/allocator operation. Other sizes/options/range failures can select different paths regardless of this helper. [CP6,CP7]

| Associated-object branch selected? | Selected bit | Thread bit T | Local decision when G!=0 |
| --- | ---: | ---: | ---: |
| No | S=0 | Either | 0 |
| No | S=1 | Either | 1 |
| Yes | A bit=0 | Either | 0 |
| Yes | A bit=1 | 0 | 1 |
| Yes | A bit=1 | 1 | 0 |

## Reference inventory and verification

The bounded scan examines725 instruction-marked sections across the original fileset entries:15,490,987 four-byte words, or61,963,948 bytes. A raw opcode decoder selects431 ADRP references to the relevant page; a register-width-aware local tracker follows at most32 instructions until control transfer. It finds seven four-byte read groups and no direct write group within that procedure. Arbitrary indirect aliases, literal/GOT paths and inter-block data flow are excluded. The proven indirect boot writer shows why this is not a no-writers or immutability proof. The cell is in original `__DATA_CONST,__const`; native protection epochs remain unknown. [CP1,CP8]

| Direct read PC | Local source context |
| --- | --- |
| `0xfffffe000bdc6bd0` | Reusable predicate's zero-selector branch |
| `0xfffffe000bdc6d38` | Comparison against1 |
| `0xfffffe000bdc6d50` | Comparison against1 |
| `0xfffffe000bdca3fc` | Nonzero-selector branch |
| `0xfffffe000bdcff20` | Comparison against1 |
| `0xfffffe000bdd1864` | Small-copy prefix's zero-selector branch |
| `0xfffffe000c2acac4` | Comparison against1 |

[Profiles](triage_evidence/kernel_copyin_policy_profiles.json) contain54 predicate/gate pairs plus three startup cases. The matrix varies G=0/1/2, source bit0/1 and nine declared owner/task/associated/thread contexts, including V=0/19. It executes64 original owner lookups using explicit private range/zone/backlink premises. Of54 gate components,42 reach buffer allocation and12 reach policy range validation. The G=2 subset yields12 and6, respectively, among its18 declared contexts; these counts do not estimate native frequencies. [CP4-CP8]

[Checks](triage_evidence/kernel_copyin_policy_checks.json) freshly reconstruct source/references and independently replay9,988 visits,1,755 reads /9,981 bytes,1,311 writes /9,802 bytes and111 final boundaries. Three original parser argument records and six logical instruction-authentication steps are checked. Twelve read-lock callbacks are modeled; startup parsing and owner lookup use original instructions. Every pair agrees with a separate predicate oracle; the two present-value cases execute the four-byte global store. No SMT or universal runtime equivalence claim is made. [CP7,CP8]

Reproduce in order:

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_copyin_policy.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_copyin_policy.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_copyin_policy.py
```

Time is O(instruction words + ADRP candidates*32 + source visits); retained space is O(collection metadata + captured paths/profiles + one private CPU map). No native target, IPC, VM, host boot operation, hardware PAC, IDB mutation or saved-memory update is performed. Original files remain preserved; the full investigation remains active. [CP1-CP8]

| Impact | Remaining bounded interface | Required evidence |
| --- | --- | --- |
| High | Actual small-copy selection | Attest runtime G/V, map/associated/thread flags and real reply extents together |
| High | Policy range validation and type2 completion | Continue the two distinct lookup frontiers with established native object provenance |
| Medium | Private type and lifecycle identities | Trace writers/owners of thread+`0x420`, R+`0x28`, map flags and thread+`0x480` |
| Medium | Complete control over the selector | Recover startup dispatch, actual input source, later indirect aliases and protection epochs |
| Low | Public-reference drift | Retained older VM source lacks this parameter name; native instructions govern the recovered predicate |

- QG1: Pass. Factual control/data-flow and environmental ABI analysis.
- QG2: Pass. CP1-CP8 identify assumptions, dependencies and falsification probes.
- QG3: Pass for selector initialization/writer and paired local predicate; native environment and transport remain open.
- QG4: Pass. u32/u16/byte fields,24-byte records, word/byte counts and algorithm bounds are explicit.
- QG5: Pass for scope. File/private/runtime values, source/associated branches, thread exception, owner validity and bounded references are separated.
- QG6: Pass. Original bytes, chained startup bindings, original parser stores, fresh scan/replay and independent oracle are retained.
- QG7: Pass. Impact-labeled continuation identifies immediate environmental and lookup gaps.

Publication checks: [preservation](triage_evidence/kernel_copyin_policy_delivery.json), [scoped gates](triage_evidence/kernel_copyin_policy_quality_gates.json).
