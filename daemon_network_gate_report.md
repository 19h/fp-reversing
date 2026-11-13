# Conditional network cache gate and synchronization composition

Follow-up representation recovery: The [context unseal report](daemon_context_unseal_report.md) identifies cell 0x1010c9298 as an arena-context reference that can be encoded or raw. Its selected branch reverses the reference codec and the 552-byte context sealing before publishing the raw address. The network-record substitution controls here remain separate probes; no object-identity or native-epoch join is retroactively inferred.

The previously stopped network-record caller reaches the same fallback write-lock argument and cleanup unlock argument, `0x1010b7478`, under explicit once/import return premises. The caller then tests a 32-bit control immediately before the network record and a separate 64-bit cache-pointer cell. This is a local source composition; native lock validity, successful acquisition, object ownership, concurrent behavior and daemon-kext delivery remain unknown. [NG1-NG4]

The gate selects `0x10048192c` exactly when the control is zero and the cache pointer is nonzero. Otherwise it increments the control modulo `2^32`, calls the shared cleanup adapter, and reaches either another acquisition call or a pointer-field consumer. The former neighbor sentinel is now an explicit control-state premise. The second cached pointer is a distinct cell; substituting the network-record address is a control probe, not evidence that the two objects are interchangeable. [NG3-NG5]

```text
Frozen pending pthread_once(control, callback)
  + once completion premise
  + optional original callback invocation with declared stack gap
  -> fallback cell -> pthread_rwlock_wrlock(0x1010b7478)
  + imported return premise -> caller at 0x1004f753c
  + two initializer-compatible roots and two cache-state premises
  -> control32 == 0 AND cached_pointer64 != 0 ?
       yes -> STOP at 0x10048192c before another undefined root
       no  -> control32 += 1 modulo 2^32
              -> shared cleanup -> pthread_once -> unlock(same address)
              -> original zero-return leaf
              -> STOP before next acquisition or cached-pointer +8 load
```

| Evidence | Primary artifact and exact scope |
| --- | --- |
| NG1 | Pinned thin daemon SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [source extractor](triage_evidence/recover_daemon_network_gate.py) retains original instruction bytes and fixup rows. |
| NG2 | [Frozen parent checks](triage_evidence/daemon_network_record_checks.json.zst), SHA-256 `64fc7eb0c7c84641109e9fd7512595118561f4d44cae33128d78bdb4ded064c0`; eight distinct caller contexts selected without changing the parent artifact. |
| NG3 | [New source receipts](triage_evidence/daemon_network_gate_checks.json.zst): callback, acquisition, cache gate and cleanup intervals; explicit boundary states, private definedness and image premises. |
| NG4 | [Independent auditor](triage_evidence/audit_daemon_network_gate.py) and [audit receipts](triage_evidence/daemon_network_gate_audit.json.zst): separate byte-addressed instruction lift, all register/flag/memory effects and interval joins. |
| NG5 | Four nonvacuous bit-vector counterexample queries are UNSAT; source-derived gate, counter wrap, callback updates and zero leaf. Concrete return controls use statuses 0 and 35. |
| NG6 | [Publication verifier](triage_evidence/verify_daemon_network_gate_publication.py): exact parent delta, original inputs, source/dependency/receipt hashes, archives, report links, raw/typed/decoded path hygiene. |

## Exact interfaces

Let `S` be the retained caller SP. All addresses below are preferred image VAs; ASLR and hardware pointer authentication are not executed.

| Site or cell | Source role | Width or extent |
| --- | --- | --- |
| `0x10043e508` | Acquisition `pthread_once(0x1010b8cd0, 0x10040ebd4)` | X0 control pointer, X1 callback pointer |
| `0x10040ebd4` | Once callback; updates obfuscation controllers and calls local `RET` leaf | 64 B own frame; declared 256 B invocation gap is a model premise |
| `0x1010b9638` | Fallback-pointer cell; original rebase target `0x1010b7478` | u64; file rebase is distinct from native writable state |
| `0x100361df4` | `pthread_rwlock_wrlock` with fallback pointer in X0 | Pointer64; imported result32 |
| `S+0x570` | Pointer to control cell `0x1010c5760` | u64; initializer writer `0x1004c2c0c` |
| `S+0x568` | Pointer to cache-pointer cell `0x1010c9298` | u64; initializer writer `0x1004c2f88` |
| `0x1010c5760` | Gate control, four bytes immediately before network record | u32 |
| `0x1010c9298` | Separate cached pointer tested for NULL | u64 |
| `0x1004f7574` | Authenticated gate branch, IA diversity `0x6507` | Index `0x9e4b` -> `0x10048192c`; `0x9e69` -> `0x10050fe9c` |
| `0x10050feb4` | Stores `u32(control + 1)` | Four bytes; `0xffffffff` wraps to zero |
| `0x10050ff50` | Calls cleanup adapter `0x1004423f8` with reused temporary | X0 = `S+0x10cb8`; IA diversity `0x6aa4` |
| `0x100442650` | Cleanup `pthread_once` with same control and callback | Cleanup completion modeled without a second callback invocation |
| `0x100208efc` | `pthread_rwlock_unlock` with same fallback argument | Pointer64; imported result32 |
| `0x10050ff98` | Calls `0x1000056c8`, `MOV W0,#0; RET` | Original local leaf; no scheduler or IPC call |
| `0x10080a464` | Next acquisition call, left pending | Source call boundary before executing another acquisition |
| `0x1005fadd4` | Pending `LDR X9,[X22,#8]` | Eight bytes at cached pointer +8; requires backing and object-layout evidence |

The gate predicate follows the original `CMP`, conditional `CCMP` and `CSET`. The nonmatching branch uses default NZCV `#4`, setting Z, so a nonzero control selects the increment/cleanup route regardless of the cache pointer. This establishes the exact Boolean predicate, rather than inferring it from two zero comparisons. [NG1,NG5]

The callback reads full u64 controllers A at `0x1010c5088` and B at `0x1010c4670`. With H its SP after reserving 64 B, D = `(A XOR B) + H + 8` modulo `2^64`. Stores at `0x10040ecfc` and `0x10040ed00` are respectively `D * 0x0a5cd4cf + 0x673e3a80075f02c6` and `(D XOR 0x73d046208eaed1a6) * 0x0a5cd4cf`, modulo `2^64`. Its temporary contains the *address of the fallback cell*, not the fallback target. The leaf at `0x10044fc34` is a single `RET`; this callback trace writes neither pointer cell and constructs no lock. The original stack-guard comparison and return execute in the private software model. [NG1,NG3-NG5]

## Controls, assumptions and limits

Each of eight frozen contexts is continued with callback omitted or invoked and import status 0 or 35, producing 32 acquisition cases. Four cache-state controls per acquisition produce 128 consumer cases. Status 35 is a synthetic return-register perturbation; no documented native return domain is inferred for it. The status controls preserve source PC sequences in paired cases; address agreement alone does not establish a successful native lock/unlock pair. The callback/cleanup controller writes remain carried through interval joins. [NG3-NG4]

| Control32 | Cached-pointer control | Observed source boundary per acquisition | Interpretation |
| --- | --- | --- | --- |
| 0 | NULL | `0x10080a464` | Increment to 1, cleanup and next acquisition call |
| 1 | NULL | `0x10080a464` | Increment to 2, cleanup and next acquisition call |
| 0 | Network-record address | `0x10048192c` | Descriptor route; stop before undefined `S+0x878` root |
| `0xffffffff` | Network-record address | `0x1005fadd4` | Wrap to 0, cleanup, then stop before pointer +8 read |

No consumer changes the known network-record prefix `[0x1010c5764,0x1010c576e)`. The final pointer control would demand bytes `[R+8,R+16)` from a record with only `[R,R+10)` established here. Six demanded bytes lie beyond that established prefix. This is a probe of an incompatible substitution; it is not a native out-of-bounds finding. [NG3-NG4]

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| NG-A1: Pinned source and logical fixups match this image | All local source roles | Verify SHA-256, visited words, original authenticated slot and diversity; fail on drift. |
| NG-A2: Parent receipt represents a retained private caller context | Caller composition | Exact parent index, register, flag, SP and defined-byte joins; no native reachability assertion. |
| NG-A3: Once completion and optional callback invocation obey the declared ABI/stack premises | Callback composition and acquisition continuation | Compare callback/no-callback profiles; verify callee-saved registers, exact SP restoration, guard, controller writes and every source effect. Native pthread stack layout remains unknown. |
| NG-A4: Imported routines return without modeled memory effects and preserve callee-saved state | Lock/cleanup continuation | Status 0/35 source-path controls and explicit return journals; native failure effects or concurrent mutations can invalidate the premise. |
| NG-A5: Two caller root cells equal the initializer-compatible values in a separate epoch | Cache gate | Twelve frozen initializer writer ledgers contain one exact eight-byte definition per cell and no later overlapping write. Preserve the pre-premise unknown-read cuts; epoch identity remains unknown. |
| NG-A6: Explicit control/pointer values are separate image-state probes | Gate outcomes and pointer-field frontier | Zero/nonzero and wrapping controls; never promote sentinel values or substituted pointer to native state. Actual cached object producer and layout remain unknown. |
| NG-A7: Logical PAC and private guard model suffice for this source interpretation | Authenticated paths and callback return | Independent fixup/diversity and register/effect replay; hardware authentication and native guard state remain unknown. |

The source receipts and independent replay cover 32 acquisitions, 16 original callback executions and 128 consumers: 528 intervals, 78,416 source visits, 15,616 reads, 4,080 writes and 2,000 logical edges. Independent checks compare 2,526,208 register values, 78,944 NZCV states, 81,216 read bytes, 17,440 written bytes and 1,744 original authenticated edges. Four new source obligations are freshly checked and stored queries are replayed. SDK compilation checks the current arm64e `pthread_once`, `pthread_rwlock_wrlock` and `pthread_rwlock_unlock` prototypes only; it executes no target routine and proves no historical object initialization. Complexity is O(receipt bytes + cases * (source visits + effects) + source/query size) time and space, with a 30 s solver limit per query. Arithmetic widths, byte intervals and separate invocation gaps are explicit. [NG3-NG6]

Decoded checks SHA-256: `734dab1b800e9c528a2073b9c093d9fe481565308f48b72ea9af178764561884`. Decoded audit SHA-256: `7d8a3ea103a5b8a5775d30e895a4f8061e27d0ba10fa7f874d927d183409aad5`.

## Bounded continuation and quality gates

| Impact | Next evidence | Purpose |
| --- | --- | --- |
| High | Producer and decoded layout of `0x1010c9298` | Establish the cached object before following pointer +8 or substituting a known record. |
| High | Original root and image-state definitions for the `0x10048192c` route | Continue descriptor consumption without manufacturing an object pointer. |
| Medium | Native or separately recovered fallback-lock initialization and once implementation | Distinguish address pairing from valid lock lifetime, ownership and concurrency. |
| Medium | Definition/use census of control `0x1010c5760` | Determine the counter protocol and whether wrap is naturally reachable; no finite control demonstrates native wrap. |
| Low | Correlated native transport evidence after admission | Associate later IOKit/Mach operations; this increment emits no message and establishes no new port name. |

**QG1** passes: factual source/interface analysis. **QG2** passes: NG-A1-NG-A7 identify dependencies and falsification probes. **QG3** passes for this bounded increment: callback, acquisition, cache gate, cleanup and next boundaries are reported; the full investigation remains active. **QG4** passes: u32/u64 arithmetic, half-open byte ranges, stack extents, ABI widths and complexity are explicit. **QG5** passes: null/populated/wrapping controls and status variations are separated; unknown object backing, native epochs and concurrency remain explicit. **QG6** passes after source, receipt, independent replay, SDK and publication checks. **QG7** passes: impact-ranked opportunities and incompatible pointer-substitution limits are bounded above.
