# Retirement diagnostic routing and panic argument contracts

The two previously unresolved retirement error callees prepare diagnostic arguments and call the original `_panic` target. The zone diagnostic reports the pointer and `zalloc.c:732`. The class diagnostic distinguishes a regular zone, a typed zone, and a heap mismatch; its typed route first publishes a flag and zone pointer to diagnostic globals. Native panic execution, termination and concurrent metadata changes remain unknown. [KE1-KE7]

This extends the [small retirement dispatch](kernel_retirement_dispatch_report.md), [metadata query](kernel_retirement_query_report.md), [allocator boundaries](kernel_allocator_boundary_report.md) and [selected MixedData retirement](mixed_data_retirement_report.md). Error format text establishes diagnostic intent and machine operands. It does not establish a successful retirement, a recoverable error status, or the actual lifetime of the supplied allocation. No additional Mach endpoint or right emission is established.

## Original evidence and claims

Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized predecessor kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. No new IDA observation was needed.

| Complete original callee | Exclusive interval | SHA-256 |
| --- | --- | --- |
| Class diagnostic, 68 instructions / 272 B | 0xfffffe000c62d430..0xfffffe000c62d540 | 747ed7f9aa6d34f2b864fddf77c350d5c9d3a854fbbbd4fe91a03f299a0b7c09 |
| Zone diagnostic, 12 instructions / 48 B | 0xfffffe000c6336f8..0xfffffe000c633728 | efb3000a1d7860b802dd2eb3671844e61e199eaa7ede9d9922379adb3af89e7c |

Both bodies lack exact original symbols. Original nlist records identify `0xfffffe000c62a2b0` as `_panic`. The 80 captured words contain five direct calls: four to `_panic` and one from the class diagnostic to the zone diagnostic. Neither body has a return instruction. This is a bounded source inventory; native nonreturn behavior is not inferred solely from that inventory or symbol.

| Claim | Established source contract | Dependencies |
| --- | --- | --- |
| KE1 | Both complete callees and their original diagnostic literals are pinned, including four _panic call sites | KE-A1-A2 |
| KE2 | The zone diagnostic places Z, its source filename and line 732 in three stack slots before calling _panic | KE-A1-A3 |
| KE3 | The class diagnostic repeats the exact zone interval check and indexes flag/name data from query-derived IDs | KE-A1-A4 |
| KE4 | A coherent flag snapshot selects typed, regular, named-heap or invalid-name heap diagnostics with exact format/argument correspondence | KE-A1-A5 |
| KE5 | The typed route stores u8 1 and u64 Z to two diagnostic globals before its _panic call | KE-A1-A5 |
| KE6 | Two explicitly modeled changes between the flag reads separate first-read mask/type decisions from reloaded class decisions | KE-A1-A6; no native interleaving is observed |
| KE7 | Fifteen nonvacuous obligations cover 80 new and five reused source locations, including dispatch-to-diagnostic joins; five predecessor formulas and a changed-store control replay | KE-A1-A7 |

Evidence: [extractor](triage_evidence/recover_kernel_retirement_diagnostics.py), [instruction audit](triage_evidence/audit_kernel_retirement_diagnostics.py), [delivery verifier](triage_evidence/verify_kernel_retirement_diagnostics_delivery.py), [capture](triage_evidence/kernel_retirement_diagnostics_checks.json.zst), [proofs](triage_evidence/kernel_retirement_diagnostics_audit.json.zst). Decoded capture SHA-256: `6dcd5c0912c7d6ddf346dda4746f5f5b55411b9279b18b1d1e3180e34237efc9`. Decoded audit SHA-256: `3cd8a3d4c466c3877a6668991634020cb658c8807452d9bf111053b0b2ff48ac`.

## Inputs and zone diagnostic

The dispatch class-error call at `0xfffffe000bcfee58` supplies X0=selected heap H, X1=recovered base P, X2=original request N and X3=zone Z. Its three-word argument producer is recaptured and linked into all four valid-zone class-diagnostic routes. The geometry-error call at `0xfffffe000bcfeeac` supplies X0=Z; its two-word producer is linked into the complete zone diagnostic.

The zone diagnostic allocates a 48 B frame and requests `_panic` at `0xfffffe000c633724`, with X0 pointing to the original format `zone %p isn't in the zone_array @%s:%d` at `0xfffffe0007053148`.

| Slot relative to call-time SP | Eight-byte machine value |
| --- | --- |
| +0 | Original Z |
| +8 | Pointer `0xfffffe000705316f`, literal `zalloc.c` |
| +16 | Zero-extended 732 (`0x2dc`); the format's integer line operand |

This producer accepts any raw u64 Z in the declared stack domain. It does not dereference Z. The class diagnostic independently allocates a 64 B frame and repeats `B <= Z < B+132480`, B=`0xfffffe000caeb480`. An invalid Z is forwarded to the same zone diagnostic; the nested call's stack is 112 B below the class diagnostic's incoming SP. The formula proves that linked nested argument production, without assuming a return from `_panic`.

## Zone flags and diagnostic names

For the preceding query's `Z=B+192*i`, i is ten bits and the guard admits exactly i<690. The class diagnostic computes `(((Z-B)*0x01555556) >> 32)=i`, then reads u32 flags at `0xfffffe0007e6a7a0+4*i`. This is a different instruction spelling of the preceding dispatch's equivalent table index.

It reads the full u8 requested-heap class K at H+0x10, then obtains its diagnostic name pointer from `0xfffffe0007e66f08+8*K`. This first name lookup has no local K<=4 test. The proof declares a valid 256-entry read window for the full u8 domain; only the following five original file entries are decoded as initialization evidence. No native larger-table extent or initialized K is inferred. [KE-A3-A4]

| Original table index | Chained-pointer target | NUL-terminated literal |
| --- | --- | --- |
| 0 | 0xfffffe00070eb2c9 | Empty string |
| 1 | 0xfffffe000704c1fa | `early.` |
| 2 | 0xfffffe000704c201 | `data.` |
| 3 | 0xfffffe000704c207 | `data_shared.` |
| 4 | 0xfffffe00070eb2c9 | Empty string |

Each format-8 pointer's chain membership is checked before its target literal is read. These file targets remain separate from the runtime name pointers used symbolically by the source proofs.

Let F1 be the first flag read at `0xfffffe000c62d478`. Bit 11 selects the typed-zone diagnostic immediately. Otherwise the routine retains `M=F1 AND 0x700`, reloads the same u32 flag cell at `0xfffffe000c62d494` as F2, and extracts `C2=(F2 >> 8) AND 7`. The reloaded class chooses either a table name for C2<=4 or the literal `invalid` at `0xfffffe0007053178`. M then chooses the regular format when zero and the heap-mismatch format when nonzero.

| Stable snapshot, F1=F2 | Diagnostic |
| --- | --- |
| F1 bit 11 set | Typed-zone format |
| Bit 11 clear, class 0 | Regular-zone format; table entry 0 supplies its name prefix |
| Bit 11 clear, class 1..4 | Heap-mismatch format; name comes from that class's table entry |
| Bit 11 clear, class 5..7 | Heap-mismatch format; name pointer is the `invalid` literal |

The invalid-name block's conditional branch to the regular formatter is not taken under a stable snapshot: C2>4 implies M!=0. Two additional source obligations introduce an explicit hypothetical word replacement between the reads. They establish that M still reflects F1 while C2 reflects F2, and that M=0 with C2>4 reaches the regular formatter with `invalid` as its prefix. The receipt records both interventions as external hypotheses, not source stores or observed concurrent operations. Native synchronization, writer existence, likelihood and reachability of that interleaving remain unknown. [KE-A5-A6]

## Class formats, stack operands and global stores

Original format literals are:

| Kind / address | Original format text |
| --- | --- |
| Regular / 0xfffffe000704c70f | `kfree: addr %p, size %zd found in regular zone '%s%s' @%s:%d` |
| Typed / 0xfffffe000704c6c0 | `kfree: addr %p found in kalloc type zone '%s'but being freed to %s heap @%s:%d` |
| Heap / 0xfffffe000704c74c | `kfree: addr %p, size %zd found in heap %s* instead of %s* @%s:%d` |

Let ZNAME=u64[Z+0x10], HNAME=the requested heap's name pointer, and CNAME=the selected zone-class name pointer or `invalid`. The routine supplies the following eight-byte stack slots; all values are source machine operands. Native string dereferencing and formatting by `_panic` are outside the proof.

| Kind / _panic call site | +0 | +8 | +16 | +24 | +32 | +40 |
| --- | --- | --- | --- | --- | --- | --- |
| Regular / 0xfffffe000c62d4d0 | P | N | CNAME | ZNAME | `kalloc.c` pointer | 2769 (`0xad1`) |
| Typed / 0xfffffe000c62d50c | P | ZNAME | HNAME | `kalloc.c` pointer | 2764 (`0xacc`) | Not an argument |
| Heap / 0xfffffe000c62d53c | P | N | CNAME | HNAME | `kalloc.c` pointer | 2772 (`0xad4`) |

The `kalloc.c` pointer is `0xfffffe000704c2bc`. N remains the original u64 request operand; no element-extent substitution occurs in these diagnostic arguments. The strings provide primary binary evidence for the diagnostic roles without identifying a live allocation or proving its heap membership.

| Typed-route store | Source site | Established effect before _panic |
| --- | --- | --- |
| u8 at 0xfffffe000cadd714 | 0xfffffe000c62d4dc | Value 1 |
| u64 at 0xfffffe000cadd718 | 0xfffffe000c62d4e4 | Original zone Z |

The two globals have zero original file bytes; their current values and external consumers remain unknown. The regular and heap-format paths preserve them within the declared memory domain. No atomic operation or synchronization is established for these two separate stores.

```text
dispatch class-error call(H,P,N,Z)
              |
         zone interval ------ rejected --> zone diagnostic(Z)
              |                                  |
           admitted                              v
              |                         _panic(format,Z,file,732)
         first flag F1
              |
        bit 11 set -----> diagnostic globals ---> typed _panic
              |
        bit 11 clear
              v
       retain mask from F1
       reload class from F2
              |
       choose table/invalid name
              |
        mask zero / nonzero
             /          \
      regular _panic   heap _panic
```

## Verification and assumptions

Fifteen source counterexample obligations are UNSAT with nonvacuous premises; two explicitly declare a metadata intervention. They cover all 80 new instruction locations and five reused dispatch locations, with 412 instruction instances and 397 linked-edge obligations. Five predecessor formulas recheck the dispatch error operands and query-derived index guard. Changing the typed diagnostic's u8 store to NOP yields a SAT counterexample from an initially zero diagnostic flag. The original and altered formulas replay independently in a fresh audit reconstruction.

The model uses exact fixed-width arithmetic and one little-endian byte array per state, with defined read aliases and explicit memory transitions. PACIBSP is a conditional identity envelope; this increment stops before every external `_panic` call executes. The direct class-to-zone diagnostic call is linked as source rather than modeled as an ordinary returning callee. No recovery through a hypothetical `_panic` return is proved.

Extraction is O(B+I+S+C) time/space for image bytes, instructions, symbol records and selected chain work. Formula construction is O(I+Q) time/space for instruction instances and expression-DAG nodes; solver search is separate with a 30 s per-query timeout. Widths and literal byte counts are exact, with no numerical approximation. The delivery verifier rebuilds receipts, compares canonical formula ASTs, replays the negative control, checks original inputs and exact publication custody, and checks decoded archives for analyst paths.

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| KE-A1: source identity | Pinned collection, compiler bounds and predecessor captures supply these bytes. All claims depend on identity. | Recapture both complete bodies, caller spans, literals, original _panic symbol and five pointer chains. |
| KE-A2: instruction model | Fixed-width operations, byte-array loads/stores, flags, vararg cells and linked edges model the selected source. All proofs depend on the model. | Rebuild/re-solve canonical formulas, reject the altered store, and compare another instruction engine. |
| KE-A3: declared storage | Stack and declared heap, zone, flag/name windows and diagnostic globals are valid, nonwrapping and disjoint where accessed. KE2-KE6 are conditional on those domains. | Check actual address mappings, aliases and the requested-heap class. A full u8 name index needs its own valid read; five file entries alone do not validate all 256 cases. |
| KE-A4: query and initialization epoch | Z has the stated query-derived record geometry when applying the flag/name indexing proof. File literals/fixups do not establish current name pointers or initialized classes. KE3-KE5 use this distinction. | Match Z/ID/flags, H+0x10, table pointers and label pointers in one allocation/retirement epoch. |
| KE-A5: coherent snapshot | The ordinary route partition uses equal first/reloaded flag words and stable heap/zone/name data. KE4-KE5 use this storage epoch. | Inspect writers, locking and matched reads. A changed flag word invalidates the coherent route partition. |
| KE-A6: explicit environment probe | KE6 allows a hypothetical independent flag word between the two source reads. This is a declared intervention, not a discovered writer or native trace. | Establish an actual ordered writer/read epoch independently, or retain this result solely as a conditional dependency test. |
| KE-A7: execution boundary | PAC and address validity are assumptions; source _panic requests do not prove native execution, termination, allocator ownership or daemon identity. KE7 and broader interpretations use this boundary. | Verify native call/termination and allocator/daemon correlation independently; do not infer them from missing local return instructions. |

## Bounded continuation

| Impact | Next evidence | Remaining question |
| --- | --- | --- |
| High | Zone-tail reclassification and normal/full-cache retirement paths | Whether the element reaches a matching actual release/reuse epoch |
| High | Matched daemon request, userclient record and kernel allocation identity | Which daemon transaction owns these paths |
| Medium | Producers/readers of the class flags, name pointers and diagnostic globals | Initialized values, synchronization and diagnostic consumers |
| Medium | Independent native _panic/termination evidence | Whether the source request is realized and how the system terminates |
| Low | Extend reciprocal indexing beyond query-derived record starts | Behavior for arbitrary raw addresses inside the interval |

## Scoped quality gates

- **QG1**: Factual diagnostic, control-flow and machine-ABI claims only.
- **QG2**: KE-A1-KE-A7 identify dependencies and falsification probes.
- **QG3**: Both complete callees, all diagnostic routes, five call sites, literals/name fixups, global stores and dispatch joins are covered. The full interface goal remains active.
- **QG4**: 68+12=80 words; 80*4 B=320 B; frames are 64/48 B, nested depth 112 B; stack argument slots are 8 B; u8/u32/u64 widths and complexity are explicit.
- **QG5**: Original file values versus runtime values, stable versus hypothesized changed flags, source _panic requests versus native termination, and missing local returns versus a proved nonreturn contract remain distinct.
- **QG6**: Original bodies/literals/fixups and _panic symbol accompany 15 source proofs, five predecessor rechecks, canonical reconstruction and an altered-source SAT control.
- **QG7**: Ranked continuation covers deeper retirement, transaction identity, initialization/synchronization, diagnostic consumers, native termination and raw indexing scope.
