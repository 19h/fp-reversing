# Original early-main module-pointer signing and return

Current continuous CPU increment: The [continuous CPU report](kernel_cpu_initialization_execution_report.md) now executes the CPU initializer at this report's final boundary and returns before the scheduler-initializer BL. It preserves this complete 821831-visit prefix, all reads/writes and all 1058 prior page digests at the former frontier, with only five explicit initial system-register keys added.

The original main now calls the collection/fileset walker with the boot-produced root header, executes all 1845 segment-signer calls and 6362 nonzero pointer stores, and returns on its existing stack. This replaces one inherited no-RAM return model. Main then reaches the same nonzero timer return as the [boot-state logging handoff](kernel_boot_logging_handoff_report.md). The private case contains 821831 journal visits: 515187 preserved visits plus 306644 inserted walker/signer visits. Logical PAC, two other return models, declared startup fixtures and the two proved logging joins remain explicit premises. Module initializer invocation, native signing and matched FairPlay IPC remain unknown. [MP-A1-MP-A7]

```text
returned private boot image + unchanged startup fixtures
  -> main at c639a94: load root header into X0
  -> BL c47cce0, existing main SP and return PC
       root segments / 362 fileset children
         -> 1845 calls to c656ca4
         -> 6362 XPACI / PACIA(0x4a27) / pointer stores
              +-> six FairPlay initializer/terminator slots
       -> return to c639a9c, SP/callee-saved state preserved
  -> all 1029 prior registry callback returns
  -> both logging joins and 94 original ring-byte stores
  -> nonzero timer return at c639e40, before CPU-initializer BL

module-table pointer store -> callback invocation: still unestablished
```

Primary evidence is the original collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, [captured source/headers/tables](triage_evidence/kernel_main_pointer_signing_checks.json.zst), [complete audit and case](triage_evidence/kernel_main_pointer_signing_audit.json.zst), the [separate signing cases](kernel_initializer_pointer_signing_report.md) and the frozen boot-state logging case. The [recovery](triage_evidence/recover_kernel_main_pointer_signing.py), [producer](triage_evidence/probe_kernel_main_pointer_signing.py), [independent replay](triage_evidence/replay_kernel_main_pointer_signing.py), [audit](triage_evidence/audit_kernel_main_pointer_signing.py) and [delivery verifier](triage_evidence/verify_kernel_main_pointer_signing_delivery.py) reproduce this increment. No IDB was queried or changed; original inputs and predecessor evidence JSON remain unchanged. [MP-A1-MP-A3]

| Interface / source | Established custody |
| --- | --- |
| `0xfffffe000c639a90..0xfffffe000c639a98` | Original ADRP/load/BL forwards the word at `0xfffffe0007f8b528` in X0 |
| Root argument | `0xfffffe0007004000`, from the qualified boot-word initial precedence |
| Walker `0xfffffe000c47cce0..0xfffffe000c47ce2c` | Original 83-word collection/fileset traversal; exact original symbol unknown |
| Signer `0xfffffe000c656ca4..0xfffffe000c657040` | Original 231-word bounded signer; exact original symbol unknown |
| Direct-root / child calls | `0xfffffe000c47cd24` / `0xfffffe000c47cd8c`; selected segment in X0 |
| Walker entry / return indices | 23 / 306667, zero-based journal boundaries |
| Caller return | `0xfffffe000c639a9c`; original LR and stack, with no frame replacement |
| Walker entry / return SP | `0x65000eff40` in both snapshots |
| Later case boundary | `0xfffffe000c639e40`, before the CPU-initializer BL |

The source capture preserves 203 preceding bodies and adds the two exact previously recovered bodies: 205 functions, 17304 words, 69216 B. Both absent helper names remain unknown; the roles follow source and observed effects. Recovery rehashes the helper closures, all 363 root/fileset headers and all 674 eligible pointer tables against the boot-bound logical image. The signer's separately retained compiler-boundary exclusion remains qualified as described in the earlier report. [MP-A1-MP-A2]

No new initialization record or mid-execution memory repair supplies table contents. The unchanged main fixture records still give eight returned boot words precedence over inherited poison. The new producer maps and checks each table's original logical bytes before main, adds their storage to the tracked output domain and admits the original helper bodies. Its code hook bypasses the old leaf interception only for those bodies. XPACI and PACIA1716 retain the declared logical target identity while recording actual source operands and order; PACIBSP/AUTIBSP retain the existing logical projection. Native signature bits and writable-table permissions remain unknown. [MP-A2-MP-A4]

The independent parser reads the declared initial image, walks u32 command counts and u32 command sizes from header+32, selects root LC_SEGMENT_64 commands and follows LC_FILESET_ENTRY child-header pointers at command+8. Child fileset commands are not recursively followed. For each selected segment it reads nsects at +64 and 80 B section records from +72, admits low-byte section types 9/10, and processes each complete nonzero u64 pointer from section address/size at +32/+40. The parser derives the expected sequence without invoking the producer or signer. It then compares all actual signer arguments, nonprivate writes and strip/sign operands in order. This is a bounded parser over the pinned stable corpus, not malformed-image or concurrent-registry admission. [MP-A1-MP-A5]

| Checked effect | Count / extent |
| --- | ---: |
| Fileset children | 362 |
| Selected segment calls | 1845 |
| Eligible initializer/terminator tables | 674 |
| Complete nonzero pointer stores | 6362 / 50896 B |
| Explicit XPACI/PACIA operand events | 12724 |
| Helper private stack stores | 20941 |
| Callee allocation bound | 96 B below entry SP |
| Independent table/frame checks | 13072 |
| Full-case reads / writes | 192341 / 119550 |
| Final mapped pages | 1058 / 4333568 B |

Every nonzero pointer receives one XPACI, IA signing with X16=`0x4a27`, and one u64 store to its original slot. The independent oracle checks value custody and visit order for all 6362 triples. Walker return preserves SP, X19-X29, all 32 vector registers and the logical system map. Every helper private write stays inside the 96 B allocation bound; the complete 1048576 B private image outside that bound is unchanged at return. The complete later private image ultimately matches the frozen regression without masking. This finite frame result does not establish a native permission or authentication epoch. [MP-A3-MP-A5]

FairPlayIOKit's two 24 B tables receive their six actual stores during this main call. Ordinals are zero-based among the 6362 nonprivate table stores; visit indices refer to the complete new journal. All six store PCs are `0xfffffe000c656d98`.

| Table slot | Logical target | Original symbol | Ordinal | Visit |
| --- | --- | --- | ---: | ---: |
| `0xfffffe000846a5b0` | `0xfffffe000a5039a4` | `__GLOBAL__sub_I_FairPlayMemoryDescriptor.cpp` | 3482 | 182009 |
| `0xfffffe000846a5b8` | `0xfffffe000a504d58` | `__GLOBAL__sub_I_FairPlayIOKitUserClient.cpp` | 3483 | 182032 |
| `0xfffffe000846a5c0` | `0xfffffe000a50ac60` | `__GLOBAL__sub_I_FairPlayIOKit.cpp` | 3484 | 182055 |
| `0xfffffe000846a5c8` | `0xfffffe000a5039f8` | `__GLOBAL__D_a` | 3485 | 182104 |
| `0xfffffe000846a5d0` | `0xfffffe000a504dac` | `__GLOBAL__D_a` | 3486 | 182127 |
| `0xfffffe000846a5d8` | `0xfffffe000a50acb4` | `__GLOBAL__D_a` | 3487 | 182150 |

No module-table target is entered during the helper interval. The earlier metaclass argument/vtable source relations are rebuilt, but the FairPlay wrappers and OSMetaClass implementation are not newly invoked. Table signing and class registration remain distinct interfaces. [MP-A4-MP-A6]

Deleting only the contiguous new helper interval reproduces the entire preceding 515187-visit instruction stream and every preceding read/write event, including addresses, widths and bytes, after index translation. The 306644 helper visits also exactly match the instruction sequence from the separate pinned collection signer case. No claim of equality between their different caller register/stack fixtures follows. [MP-A3-MP-A5]

| Regression comparison | Result |
| --- | --- |
| Initial private bytes and all fixture records | Exact |
| Projected instruction/read/write streams | Exact, without value masks |
| Registry callbacks and logging/lookup journals | Exact after visit-index translation |
| Final private RAM, GPRs, SP, NZCV, vectors and system | Exact |
| All 300 preceding mapped-page digests | Exact |
| Additional 758 page digests | Exact unchanged boot-bound original pages |
| Complete final global intervals | Prior computed outputs plus unchanged original tables |
| Remaining API-result models | Two, down from three |

The vector-registration model is unchanged. The selector0e model at `0xfffffe000c620ec4` keeps X0-X6, return PC `0xfffffe000be83254` and result zero. Its recorded X7 changes from `0x091a2b3d5b25e3da` to `0x091a2b3cc663a929`. Because model count changes from three to two, its deterministic declared X1-X17 clobbers and NZCV also change; the audit retains both full register arrays and flags. These are model bookkeeping differences, not native wrapper effects. The concrete projected memory/control stream and complete final state still match. Native significance of the recorded X7 envelope remains unknown. [MP-A3-MP-A6]

The prior independent global formulas are rechecked on the frozen case; the new case is related to them through exact projected events, final old-page hashes and complete final-global comparison. Thus the two 47 B ring messages, 94 character callbacks, 1029 registry returns and exact 24000/2400 tick thresholds remain established under the same fixture premises. Six image-range words remain poisoned; empty/populated registry and native console limits remain those in the preceding report. [MP-A3-MP-A6]

Nine new nonvacuous QF_AUFBV obligations cover 27 instruction instances/PCs: caller header transfer, empty command return, root segment/fileset gates, child-header count, both signer argument/return sites, u32 command stepping and first-child remainder. Twenty-one retained signing/metaclass relations over 159 instruction instances/PCs and five retained logging relations are rebuilt. Opaque strip/IA/DA functions in the signing proofs establish data dependencies and modifiers; they do not establish cryptographic signatures or universal traversal termination. [MP-A1-MP-A5]

Independent replay checks all 821831 source visits, 192341 reads, 119550 writes, 12724 module PAC operand events, both new caller checkpoints, all signer entries, inherited callback/API journals, two logging joins, complete final private RAM and all 1058 final pages. It imports no new producer executor. Two NOP controls omit the scalar store at `0xfffffe000c656d98` or one unrolled store at `0xfffffe000c656e00`, retain identical declared inputs and stop at the walker return. Positive original pages are eagerly mapped before each control to align its page domain. Both controls retain the exact complete positive walker-return snapshot, including table bytes, but fail the independently parsed store count/order. This demonstrates why unchanged final logical bytes cannot certify signing-store execution. [MP-A3-MP-A5]

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_main_pointer_signing_checks.json` | `2a7b3e6d423c645dc3d35f5ee756e4023d67c92ec839f3f774d73b3a9fb0081e` |
| `kernel_main_pointer_signing_audit.json` | `febc7e70038bb417c33876f8a0522c606517a123130aee78f31804b196a0e073` |

No incoming/outgoing Mach right, message ID, port-emission site or matched daemon/provider/kext transaction is newly established. The new architectural evidence is the actual early-main call, frame return and source signing-store custody of FairPlay's class lifecycle pointers. The full interface goal remains active. [MP-A6-MP-A7]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| MP-A1: Pinned original source and metadata define this corpus | Roles, layouts and FairPlay identities | Rehash helper source, 363 headers and 674 tables; reject input/dependency drift |
| MP-A2: Qualified boot-word precedence and corrected image define initial main storage | Real root argument and table bytes | Preserve every preceding fixture; check original logical table bytes before main and source-produced header load |
| MP-A3: Declared private frame/system premises define the continuous case | Return, continuation and regression equivalence | Complete caller snapshots, exact projected journals, final private/global/page comparisons and fresh replay |
| MP-A4: PAC target identity bounds concrete execution; source proofs use opaque signing functions | Store target/modifier custody | Check every XPACI/IA operand/store triple and separate native keys/signatures; unknown |
| MP-A5: Stable finite command/section extents and architectural models bound the parser/proofs | Traversal and finite oracle | Independent parser, nine new/26 retained relations, full replay and two rejected source controls; malformed/concurrent admission unknown |
| MP-A6: Two inherited returns and uninvoked module targets bound lifecycle conclusions | Selector envelope and FairPlay registration limits | Preserve X7/clobber deltas; execute actual wrapper and initializer/constructor callers in separate composed cases |
| MP-A7: Private pointer signing does not establish native transport | Mach and full-goal limits | Recover actual right ownership, emission PCs, message/selector contracts and matched epochs; unknown |

| Impact | Bounded next work | Discriminating evidence |
| --- | --- | --- |
| High | Establish actual module initializer invocation and FairPlay class registration | Original caller, table-slot authentication, callback entry/return and OSMetaClass state |
| High | Continue main through CPU/Mach initialization | Original caller admission, per-CPU/system effects and phase-14 MIG callbacks |
| High | Recover image-range/registry producers and match daemon/provider/kext transport | Source writers, populated lookups, object/port identities and matching transaction evidence |
| Medium | Replace remaining vector-registration and selector models | Actual source inputs/effects, frame custody and register liveness |
| Medium | Qualify native PAC and table write permissions | Concrete signing/authentication outcome and writable lifecycle epoch |

Collection/source/table recovery and independent parsing are linear in their byte/record counts. Original traversal retains worst-case O(R + sum(C_i^2) + P + S) work for root commands R, child command counts C_i, complete pointer slots P and section records S. Journaling, relational comparison and replay are linear in visits, events and mapped/private bytes; retained host timelines sort O(J log J). Storage is linear in those retained data. SMT search is separate with a 30 s query limit. The 96 B allocation bound, 50896 B table domain and 4333568 B mapped domain are distinct; zero-slide boot hydration is inherited, not rerun as another 43400376-visit boot case.

**QG1**: Factual technical analysis; no normative content required. **QG2**: MP-A1-MP-A7 state dependencies and falsification probes. **QG3**: Actual caller/return, original table traversal/signing, FairPlay slot custody, complete continuation and Mach/lifecycle limits covered for this increment; full goal active. **QG4**: u32/u64 widths, source/visit counts, 80 B section records, 96 B allocation and logical byte domains explicit. **QG5**: Actual helper/model returns, original/synthetic frames, identity/native PAC, signed-table/callback invocation and X7/model-clobber deltas distinguished. **QG6**: Pinned source/records, independent parser, old-global formula recheck, relational comparison, full replay and mutations retained. **QG7**: Impact-ranked bounded continuation included.
