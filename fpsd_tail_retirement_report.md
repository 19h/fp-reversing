# FPSD process-event tail cleanup frontiers

The process-event callback treats slot+888 and slot+880 as distinct cleanup inputs. With nonzero +888 it first zeroes object+24, then reaches an object+0 read before any observed pool reset or session CF cleanup request. With zero +888 and nonzero +880 it performs the52 pool stores and session CF invalidation/release requests before reaching an object+108 read. Nine independently replayed profiles stop before consuming any opaque object bytes. Native object type, allocation extent, ownership and a source-produced publication-to-retirement lifetime remain unknown. [FT1-FT8]

This extends the [process-event analysis](fpsd1200_process_report.md) and the [selected-session analysis](fpsd1202_session_report.md). The broader daemon/kext/deeper interface investigation remains active.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FT1 | The pinned thin daemon image identifies the instruction implementation. All addresses and source expressions depend on it. | Rehash the image,39 source spans and original fixup words; compare the retained whole-code IDA hash. Distinguish current locator results from a new byte readback, which failed. |
| FT2 | The frozen successful FPSD1200 pool and descriptor callback setup define a declared source composition. | Independently reconstruct entry RAM, pool, mask and CPU; pin the predecessor payload and successful receipt. The10093981-visit session prefix is not freshly replayed. Native temporal continuity is unknown. |
| FT3 | Nonzero tails, marker4d and moved-slot variants are explicit controls. | Check every patch and mask change; vary each tail independently, PID, marker and slot index. No source-produced valid object is supplied. |
| FT4 | Diagnostic A5 backing only makes the pre-read original store observable. | Reject every read from that backing and stop at the code hook before the first object-read instruction. Its65536-byte mapping is not a native allocation-size claim. |
| FT5 | Inherited process-event, CF, PAC and synchronization models define external effects. | Recompute all95 API contracts, original journals, complete CPU checkpoints and final mutable RAM. No native event, CF, Mach, VM or IOKit operation executes. |
| FT6 | Null-selector equations depend on observed local CPU phases. | Check full source checkpoints and independently lift original instruction bytes; rerun two retained and two independently lifted all-u64-pointer queries. Object validity and ownership are outside these theorems. |
| FT7 | Publication windows are static local source facts, without a proven common object identity. | Retain the three marker4d table references; recover reaching definitions of X26, header, index and pointer values before claiming a lifetime join. |
| FT8 | Nine bounded callback profiles define the observed order and stopping conditions. | Compare null, each tail, both tails, mismatched PID, inactive marker, marker4d and slot1 controls. Keep instructions beyond each stop, concurrency and native ownership unresolved. |

## Provenance and reproducibility [FT1-FT8]

| Primary evidence | Identity / extent |
| --- | --- |
| Thin arm64e daemon | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| IDA input metadata | SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7` |
| Retained whole-code IDA extent | `0x100001058..0x100e2ac40`,14851048 bytes; SHA-256 `1463b16f028bda1abb76d52edcf5236c3bd11bbece4a7a6b46f8029ff511236b` |
| Current source catalog |39 spans,3617 distinct instructions, including pending-read instructions and five static additional intervals |
| Fresh callback replay |37834 instruction visits,4608 reads,4084 writes,95 modeled external calls |
| Original format12 records |99 rebases and11 bindings independently decoded; seven explicit pointer records |
| Fresh SDK validation | Four retained header hashes checked against installed headers; arm64e compile-only ABI assertions repeated successfully |

Artifacts: [producer](triage_evidence/recover_fpsd_tail_retirement.py), [profiles/source/proofs](triage_evidence/fpsd_tail_retirement_checks.json.zst), [reference provenance](triage_evidence/fpsd_tail_retirement_reference.json.zst), [independent auditor](triage_evidence/audit_fpsd_tail_retirement.py), [successful audit receipt](triage_evidence/fpsd_tail_retirement_audit.json.zst) and [publication verifier](triage_evidence/verify_fpsd_tail_retirement_publication.py).

The fresh read-only IDA locator completed and returned function extents and three noncode references to `sub_1009B7D10`. The subsequent requested byte readback failed after the bridge disconnected; no new live instruction/data-byte attestation is claimed. All39 source spans lie inside the retained IDA-attested whole-code extent, whose current source-image hash was independently recomputed. Data pointer words are checked against original fixups, without a new live IDA data-byte comparison. No IDB edits were requested.

## Incoming event and field contracts [FT2-FT5,FT8]

The inherited descriptor callback is `0x10044f23c`. The declared event has filter-5 and ident `0x17161514`; original code compares the encoded PID field and eligibility marker before reaching these tails. The successful predecessor supplies a50-slot pool with896-byte stride, private CF reference `0x77001000` and marker `0x4577df4b`. Tail controls patch only pointer cells and their defined masks. The diagnostic backing is A5-filled; +880 points to `0x78000000`, +888 to `0x78001000`. These addresses are private model values, not native pointers or port names.

| Slot field | Width | Established use |
| --- | --- | --- |
|+0|8 bytes|Session CF reference consumed by inherited cleanup calls|
|+140|4 bytes|Encoded PID matching, established by the predecessor|
|+876|4 bytes|Eligibility marker and retirement value `0x4577df49`|
|+880|8 bytes|Second cleanup pointer; first pending object access is +108/u32|
|+888|8 bytes|First cleanup pointer; original store to object+24 precedes pending +0/u64 read|

These are process-event profiles, not MIG request/reply profiles. They emit no new Mach name, port-right descriptor, Mach send, IOKit request, VM request or free request in the observed intervals. The CF reference is an opaque private model value. No native right ownership follows from it.

## Original selector equations and exact targets [FT1,FT6]

Original `0x10022de34` loads slot+888 into X20. At `0x1003ce728..0x1003ce754`, the freshly checked W19 phase is `0x9686`. For a64-bit pointer p, the resulting u32 table index is:

```text
tail888_index = 0x9686 XOR (0x47 * [p == 0])

tail880_index = 0x6ad8 XOR (0x2d * [p != 0])
```

The +880 expression comes from `0x100265248..0x100265274`, with freshly checked W19=`0x6ad8` and pre-add W8=`0x2d34`. All arithmetic is modulo2^32. At `0x1003ce750`, the checkpoint precedes EOR: W8 is47 for null and0 for nonnull; it is not yet the final index. Both retained counterexample queries and both independent source lifts are UNSAT over allu64 pointers under these phases.

| Field / condition | Index | Original word address | Decoded target |
| --- | --- | --- | --- |
|+888 null|96c1|`0x1010854f8`|`0x10025bc54`|
|+888 nonnull|9686|`0x101085320`|`0x100406d5c`|
|+880 null|6ad8|`0x10106f5b0`|`0x100353458`|
|+880 nonnull|6af5|`0x10106f698`|`0x1001faa0c`|

Word addresses are table base `0x101039ef0` plus8*index. These proofs establish pointer null selection, not validity, type, ownership or native PAC behavior.

## Cleanup order and bounded profiles [FT3-FT5,FT8]

```text
matching eligible process event
              |
          load +888
              |
     nonzero--+----------------zero
        |                       |
 store object+24 = 0       52 pool stores and
        |                 CF invalidate/release
 STOP before read +0            |
                            load +880
                                |
                       zero-----+-----nonzero
                        |                 |
                  original return   STOP before read +108
```

The diagram summarizes local observed order; the52 stores occur across the checked reset sequence rather than at one instruction. With nonzero +888, `0x100406d60 STR XZR,[X20,#0x18]` writes eight zero bytes. Replay stops before `0x100406d64 LDR X15,[X20]`; following `0x100406d68 LDR W8,[X20,#8]` is static evidence only and is not executed. The store requires access through byte31, which does not establish object allocation size.

With zero +888 and nonzero +880, replay stops before `0x1001faa20 LDR W11,[X11,#0x6c]`. The pending access would end at byte111; it is not consumed and supplies no object-size theorem. By that boundary, the session's original CF invalidation at `0x10025e648`, release at `0x10025e6a4` and reference clear at `0x10025e6ac` have occurred in the model. The marker is49 and the +880 pointer remains retained. This is partial local order, without a native race, leak or ownership conclusion.

| Case | Visits | Boundary | Object stores | Pool stores | Session CF calls | Final marker suffix | Final CF reference |
| --- | ---: | --- | ---: | ---: | --- | --- | --- |
|null_tails|7088|Original return|0|52|Invalidate, release|49|0|
|tail880|5205|Before +108/u32 read|0|52|Invalidate, release|49|0|
|tail888|3057|Before +0/u64 read|1|0|None|4b|77001000|
|both|3057|Before +0/u64 read|1|0|None|4b|77001000|
|different_PID|4045|Original return|0|0|None|4b|77001000|
|inactive_marker|3999|Original return|0|0|None|49|77001000|
|marker4d|3057|Before +0/u64 read|1|0|None|4d|77001000|
|index1_both|3089|Before +0/u64 read|1|0|None|4b|77001000|
|index1_tail880|5237|Before +108/u32 read|0|52|Invalidate, release|49|0|

Marker suffixes abbreviate `0x4577dfXX`; CF references are hexadecimal. The PID mismatch control uses ident15. Marker49 and marker4d are explicit controls. Slot1 shifts addresses by896 bytes and adds32 original visits in the paired profiles. Null/+880 cases load tails in order888 then880; nonzero888 cases have not yet loaded880; PID/marker rejection cases load neither. No profile reads opaque object bytes. The stopped instruction is catalogued but excluded from original instruction visits.

## Static publication and clearing windows [FT1,FT7]

| Original source | Local source fact | Unresolved reaching definition / join |
| --- | --- | --- |
|`0x100735e50`|Stores X8 to `MEM64[H] + 896*I + 888`, where H=`MEM64[SP+0x448]`, I=`MEM64[SP+0x62d0]`|Header identity, index bounds, X8 producer and actual lifetime|
|`0x1009b7d24`|Stores marker `0x4577df4d` at X26+876|X26 identity and incoming state|
|`0x1009b7d28..0x1009b7d2c`|Loads X8 from SP+0x4c0 and stores it at X26+880|Pointer producer, object initialization and native ownership|
|`0x1003e50b0`|Clears +880 using a header from SP+0x940 and indexed X20|Not reached before the present opaque-read stops; completion and common object identity unknown|

Three original table records point to `0x1009b7d10`: `0x101047868` (index1b2f, discriminator1dbb), `0x10105e7f8` (index4921, discriminator1b2d) and `0x101088808` (index9d23, discriminator2458). The fresh IDA locator confirms these noncode references. A table reference and reused branch discriminator do not identify the executed predecessor. No publication-to-retirement join is claimed.

## Validation and bounded continuations [FT1-FT8]

The independent auditor reconstructs all nine entries without importing the new producer. It checks607 complete CPU frames,37834 original instruction visits,4608 reads,4084 writes,95 declared external ABI/effect contracts,21970944 final mutable-RAM bytes and589824 bytes each of pool, defined mask and diagnostic backing. Checkpoints include357 process points and33 tail points. The source extent, seven pointer records,99 rebases and11 bindings are recomputed. Four SDK header hashes and compile-only assertions pass. The retained prefix is pinned; no native target or target API executes.

Reproduction uses the configured `$PYTHON` and Z3 environment to run the producer, independent auditor and publication verifier. Scripts document time/space costs; replay is linear in retained visits/journals and checked state, with local solver cost separate. Evidence JSON and the manifest are zstd ultra22 archives, exactly byte-compared after decompression. Owned text and decoded typed RAM are checked for analyst-path literals. The original three input files remain preserved.

| Impact | Further question / discriminating evidence |
| --- | --- |
|High|Recover source-produced +888 and +880 objects, their initializer writes and matching cleanup entry. This replaces diagnostic pointers and permits field/type interpretation beyond the first read.|
|High|Resolve X26 and SP+0x4c0 reaching definitions at marker4d publication; join them to the actual896-byte session slot and callback epoch.|
|High|Connect object provenance to matched daemon/kext/provider request lineage, endpoint ownership and deeper interfaces; the present local retirement order supplies no cross-layer transaction join.|
|Medium|Trace the static +880 clear through the original object cleanup only after its input contract is established. Distinguish CF requests from completed native right teardown.|
|Medium|Recover the +888 publisher header/index provenance and caller, using exact source dataflow rather than branch-discriminator reuse.|
|Low|Repeat live IDA byte comparisons when the bridge reconnects. Retained whole-code attestation already covers the present instruction windows, while new data-word comparison remains absent.|

## Quality gates

- **QG1**: Factual source, ABI and lifetime analysis requires no normative premise.
- **QG2**: FT1-FT8 state assumptions, dependencies and falsification probes.
- **QG3**: Routine roles, incoming event, outgoing CF requests, exact instruction locations, data/control flow and cross-layer boundaries are covered within the bounded scope.
- **QG4**: Byte widths,896-byte stride, u32 arithmetic and all replay totals are reproducible; diagnostic mapping extent is distinguished from object size.
- **QG5**: Stopped reads, static following instructions, private controls, CF ordering and unresolved publication identities remain explicit.
- **QG6**: Original source/fixups, retained IDA whole-code attestation, completed fresh locator, SDK headers and independent replay/solvers support the claims; failed new byte readback is disclosed.
- **QG7**: Impact-ranked continuations preserve unresolved source-produced lifetimes and native/cross-layer joins. The full goal remains active.
