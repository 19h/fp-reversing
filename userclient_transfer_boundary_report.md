# Selector26 transfer and return boundary

The recovered core return composes with the task-aware provider and UserClient handler: after a normal core return, the provider requests copy-back before propagating that status, regardless of the low32 status or reported copy counts. The handler then publishes the first12 descriptor bytes only when the low32 provider status is zero. Four earlier descriptor/allocation/preparation failures produce the same local adapter value, `0xffff5bd4`, through different cleanup sequences. These are conditional source contracts; successful byte transfer, native object ownership and a successful fairplayd transaction remain unknown.

## Evidence and claim register

The [extractor](triage_evidence/recover_userclient_transfer_boundary.py), [instruction audit](triage_evidence/audit_userclient_transfer_boundary.py) and [delivery verifier](triage_evidence/verify_userclient_transfer_boundary_delivery.py) accompany reproducible [checks](triage_evidence/userclient_transfer_boundary_checks.json.zst) and [proofs](triage_evidence/userclient_transfer_boundary_audit.json.zst). Primary evidence is the original kernel collection and normalized kext, supplemented by the associated C and previously pinned [selector26 ABI](interface_abi_report.md), [task flow](context_descriptor_task_flow_report.md), [command dispatch](userclient_command_dispatch_report.md) and [guarded core return](userclient_caller_return_report.md).

| Claim | Established result | Dependencies |
| --- | --- | --- |
| TB1 | Selector26's nominal method record and provider slot select the captured handler/provider | TB-A1, TB-A2 |
| TB2 | Handler forwards address64, zero-extended extent32, stored state and stored task; provider copies using low32 extent while forwarding incoming X2 to the core | TB-A1-TB-A4 |
| TB3 | Every normal provider path uses the recovered descriptor lifecycle; four early failure classes return the same local value | TB-A1-TB-A5 |
| TB4 | Core return precedes copy-out, completion and release requests; reported copy counts cannot change the selected status path | TB-A1-TB-A5 |
| TB5 | Low32 provider success writes exactly descriptor bytes0..11; low32 failure logs and writes no output descriptor bytes | TB-A1-TB-A6 |
| TB6 | Prior guarded core result ZE64(raw32 XOR0x31ae0066) survives provider and handler; status alone does not establish successful data transfer | TB-A1-TB-A7 |
| TB7 | 191 source instructions,189 normally modeled locations,23 nonvacuous UNSAT queries, two predecessor rechecks and an altered-copy-extent SAT control support this increment | TB-A1-TB-A7 |

Normalized kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. All191 handler/provider words and12 import-veneer words match both images. Eight original chained bindings establish collection targets and nominal selector/provider pointers. No live IDA access was necessary for these reference-supported obligations.

## Route, argument widths and external bindings

| Boundary | Exact source | Contract |
| --- | --- | --- |
| Selector26 method | Index25; slot `0xfffffe000846b838` -> record `0xfffffe000846b710` | Flags3; input16 B; output16 B; handler `0xfffffe000a504034` |
| Nominal provider route | Vtable symbol `0xfffffe000846b8c0` +16+0xa20 -> slot `0xfffffe000846c2f0` | Target `0xfffffe000a505198`; original diversity0x3499 |
| Handler call | `0xfffffe000a50408c` | X0=provider from UserClient+0xd8; X1=descriptor.address64; W2=descriptor.extent32; X3=state from+0xe8; X4=task from+0xe0 |
| Task descriptor request | `0xfffffe000a5051d4` | withAddressRange(address,ZE64(N),3,task), N=low32(incoming X2) |
| Kernel buffer request | `0xfffffe000a505250` | inTaskWithOptions(kernel_task,0x13,ZE64(N),alignment) |
| Buffer address query | `0xfffffe000a5052bc`, virtual+0x308 | Receiver=kernel buffer descriptor; result retained in X24=K |
| Provider -> core | `0xfffffe000a5052fc` | X0=K; X1=incoming provider X2; X2=per-client state |

The original handler pointer field at record+8, `0xfffffe000846b718`, separately resolves to `0xfffffe000a504034`. Its original chained record is checked alongside the method-record pointer and nominal provider-method pointer.

The native provider saves incoming X2 in X22 but separately narrows W2 into W20. Thus the core's X1 preserves the incoming64-bit lane while descriptors and copies use ZE64(low32(X2)). A separate arbitrary-high32 proof establishes that distinction. At the recovered UserClient call, W2 was loaded from the descriptor and therefore X2 is already zero-extended. The [core size theorem](userclient_caller_return_report.md) also consumes only low32(X1). These width facts do not establish which direct callers outside this nominal route exist.

| Role | Original slot | Collection target / exact symbol |
| --- | --- | --- |
| Task descriptor factory | `0xfffffe000847c420` | `0xfffffe000c53a934`, IOMemoryDescriptor::withAddressRange |
| Buffer factory | `0xfffffe000847c428` | `0xfffffe000c526070`, IOBufferMemoryDescriptor::inTaskWithOptions |
| Error logging | `0xfffffe000847c398` | `0xfffffe000c4babac`, _IOLog |
| Kernel task global | `0xfffffe000847c608` | `0xfffffe0007f8b0a0`, _kernel_task |
| Page-shift global | `0xfffffe000847c5b0` | `0xfffffe0007e6d9c0`, _PAGE_SHIFT_CONST |

Exact mangled names, original pointer words, chain membership and authentication metadata are preserved in checks. Virtual offsets name structural call roles corroborated by the associated C and prior ABI report. They do not identify a live descriptor subclass or authenticate its vtable.

The alignment argument is precisely `SE64(1u32 << (runtime_PAGE_SHIFT_CONST &31))`, because the source performs a32-bit variable LSL followed by SXTW. The audit quantifies over every32-bit shift value. Positive page alignment therefore requires the environmental value separately; no arbitrary runtime value is substituted into a native allocation claim.

## Copy requests, cleanup and status ordering

Let D be the task memory descriptor, B the kernel buffer descriptor, K its queried byte pointer, A the user virtual address, N the low32 extent, C the per-client state, and T the task. After successful factory/prepare results, the source sequence is:

```text
D = withAddressRange(A, N, 3, T)
  -> D.prepare(0)
  -> B = inTaskWithOptions(kernel_task, 0x13, N, alignment)
  -> B.prepare(0)
  -> K = call_virtual(B, 0x308)
  -> call_virtual(D, 0x208, 0, K, N)    copy-in request
  -> r = PRnut72j9(K, incoming_X2, C)
  -> call_virtual(D, 0x210, 0, K, N)    copy-out request
  -> B.complete(0) -> B.release()
  -> D.complete(0) -> D.release()
  -> return r
```

Copy-in and copy-out call PCs are `0xfffffe000a5052ec` and `0xfffffe000a505344`. The core result is saved at `0xfffffe000a505300`, survives subsequent ordinary callee register havoc in callee-saved X21, and returns at `0xfffffe000a5053d8`. Neither copy's result is compared with N or converted into a new status. The audit leaves both reported counts arbitrary, including a nonvacuous case N>0 with both counts<N and nonzero core status. The exact same copy-out request and retained return remain selected. This establishes request/status behavior; it does not establish initialized bytes after a short read or copied bytes after a short write.

| First failing result | Subsequent descriptor calls | Local return |
| --- | --- | --- |
| Task factory returns null | None | 0xffff5bd4 |
| Task prepare returns low32 nonzero | D.release | 0xffff5bd4 |
| Buffer factory returns null | D.complete(0), D.release | 0xffff5bd4 |
| Buffer prepare returns low32 nonzero | B.release, D.complete(0), D.release | 0xffff5bd4 |
| All preceding results accepted; core returns normally | Copy-out, B.complete(0), B.release, D.complete(0), D.release | Exact core X0 |

Complete/release call PCs are respectively `0xfffffe000a505380`, `0xfffffe000a505398`, `0xfffffe000a5053bc`, `0xfffffe000a5053d4`. Their opaque normal return values cannot replace X21. These are emitted lifecycle calls; reference counts, ownership transfer and native reclamation are not inferred.

## Handler output and core-result composition

At `0xfffffe000a504094`, CBZ W0 examines only the provider result's low32 bits. The success path writes the input address64 at output+0 and input extent32 at output+8, using stores `0xfffffe000a5040b0` and `0xfffffe000a5040b8`. It does not write bytes12..15. The failure path logs at `0xfffffe000a5040a4` and performs no output-descriptor store. Both paths retain the exact provider X0 in X21 and return it. Proof cases cover separate input/output descriptors and exact pointer equality, under stable packet/private-frame premises. Partially overlapping descriptors, framework initialization of untouched bytes and final framework output behavior remain unknown.

The provider's returned status and bytes written into A are distinct channels: core byte modifications may be copied toward task memory before the handler decides whether to publish the small descriptor. Thus absence of a handler descriptor write does not establish absence of an earlier data-transfer request. Successful or complete write-back remains conditional on the descriptor operation.

The predecessor [core-return proof](userclient_caller_return_report.md) establishes, for its selected cleanup paths and equal canaries:

```text
core_X0 = ZE64(raw_status32 XOR 0x31ae0066)
provider_X0 = core_X0                     ordinary descriptor-call returns
handler_X0 = provider_X0
handler descriptor publication iff raw_status32 == 0x31ae0066
```

Two predecessor queries are re-solved: the low32 original size codec and ordinary equal-canary raw-status decode. The new core-to-handler formulas compose that status theorem through the handler return; the provider's independent full64 status-preservation theorem supplies the middle equality. Full controller reachability and effects of every command body remain outside this composition.

| Raw core value | Decoded external32 value | Meaning established here |
| --- | --- | --- |
| 0x31ae0066 | 0x00000000 | Enables the handler's12-byte descriptor publication |
| 0xce515bb2 | 0xffff5bd4 | Numerically equals all four local adapter failure returns |
| 0xce515bb7 | 0xffff5bd1 | Arithmetic decode of the prior unsupported-command raw value |

These are exact u32 XOR calculations, not IOReturn enum assignments or claims that every listed raw value reaches every cleanup path. In particular, receiving0xffff5bd4 does not distinguish the adapter's four early failures from a core path that returns the matching decoded value. No rollback, all-or-nothing transfer, successful pairing or new Mach message/right follows from the status alone. Existing Mach endpoint/emission contracts remain in [the port report](mach_ports_report.md).

## Reproduction, assumptions and limits

Decoded checks SHA-256: `89f850dedac819421be0b9819ab7c543840928fa39f4f11e3bc5de092e678559`. Decoded audit SHA-256: `a4cdec71195b81d3908e4d9dd40bc61857864e6a834324b1f343d86c26004d64`. The verifier rebuilds source custody, reconstructs and re-solves all23 frozen queries, rechecks two predecessor formulas, checks report/manifest linkage and scrubs owned physical and decoded files. Exact counts: five provider paths, four handler cases,189 distinct proved instruction locations and1,726 proof instruction instances.

The other two of191 function instructions are authentication-failure BRKs at `0xfffffe000a505320` and `0xfffffe000a505364`. The normal-path model treats AUTDA/XPACD as already authenticated canonical pointer operations and PACIBSP/RETAB as structural boundaries. The conditional normal dispatch premise supplies this abstraction; the solver does not establish PAC validity, trap avoidance or a native return. No mutation is made to an IDB or original input.

One negative control changes the original copy-out extent instruction at `0xfffffe000a505338` from `MOV X3,X20` to `MOV X3,#0`. The independent operand-level model then finds a SAT counterexample with N>0 to the expected extent. This is an evidence-sensitivity control on analysis bytes, not a patch to the target image or a native experiment.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| TB-A1: Pinned images, original fixups, compiler boundaries and predecessor receipts | TB1-TB7 | Fresh191-word/12-veneer-word comparison, eight original bindings, exact receipt hashes and prior-query replay; altered-copy-extent counterexample |
| TB-A2: Nominal selector/provider binding and successfully authenticated ordinary dispatch | TB1-TB7 | Original method record,0xa20 slot/diversity and both authentication-trap locations; bind actual object vtables/PAC separately |
| TB-A3: AArch64 widths, variable-shift masking, signed extension and private-stack load/store semantics | TB2-TB7 | Arbitrary64-bit incoming X2, arbitrary32-bit shift, exact call operands, callee-saved registers X19..X29 and restored SP |
| TB-A4: Accessible stable receiver/packet fields and queried K; valid private frame separate from modeled objects | TB2-TB7 | Every abstract load has an independently checked source address; recover native mapping results, object identity, field writers and alias epochs |
| TB-A5: Each invoked callee returns normally and preserves private-frame storage and callee-saved registers; its volatile result is otherwise arbitrary | TB3, TB4, TB6, TB7 | Four failure classes, arbitrary copy counts and completion/release returns; native exceptions, blocking and heap/descriptor effects remain unknown |
| TB-A6: Input packet remains stable across the provider; descriptors are separate or exactly equal, with accessible12-byte output | TB5-TB7 | Four alias/status cases and exact store widths; examine concurrent mutation, partial overlap and framework initialization of trailing bytes |
| TB-A7: Prior selected core cleanup premise includes retained storage/phase and equal canaries; actual daemon/provider correlation remains unknown | TB6, TB7 | Re-solve the original size/status formulas; establish complete modifying command bodies, live input/output bytes/counts, context and selector/message pairing |

## Bounded continuation and cost

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Actual read/write counts and before/after task/kernel bytes during one successful exchange | Distinguish emitted requests from complete transfer; bind provider/core/daemon byte identity |
| High | Second command body and writers of protected staging bytes | Identify the processing results visible through the proved core copy-back |
| High | Lifecycle call trace with raw core status and external return | Resolve the identical0xffff5bd4 values across adapter/core layers |
| High | Auxiliary-pointer/extent producer | Connect the independent optional data-retirement channel to an actual command result |
| Medium | Native descriptor vtables, task references, PAC and mapping lifetime | Establish environmental and ownership premises behind virtual call roles |
| Medium | Handler/framework packet aliasing, trailing-word initialization and concurrency | Determine final16-byte output semantics and stability guarantees |

The adapter and handler each contain a bounded number of instructions/calls: local O(1) work and O(1) private state, excluding opaque callees and byte-transfer costs. The two requested transfers each have N B extent; actual transfer cost/content is not proved. Combined selected core cleanup remains O(k+N) for k stable list nodes, as documented by its predecessor. Extraction is O(B+I) time/space for consumed image bytes B and selected instructions I; proof construction is O(I+query DAG), with SMT search separate and a30 s/query bound. Counts/statuses are u32, addresses and preserved return lanes u64; all extents/alignment are bytes.

## Quality gates

- **QG1**: Claims are factual control/data/ABI/lifecycle analysis.
- **QG2**: TB-A1-TB-A7 enumerate dependencies and falsification probes.
- **QG3**: This increment covers selector/provider custody, arguments, failure paths, copy/count/status order, handler output and prior core-result composition; the full goal remains active.
- **QG4**: Narrowing, zero/sign extension, shift masking, byte widths, exact XOR mappings and complexity are explicit.
- **QG5**: Requests/actual bytes, provider64/core-low32 widths, descriptor/payload writes, local/core error origins and PAC/model boundaries remain distinct.
- **QG6**: Dual-image words, original fixups/symbols,23 nonvacuous source formulas, two predecessor rechecks and the SAT mutation control support the stated scope.
- **QG7**: Ranked continuation includes native transfer counts, modifying commands, ambiguous status provenance, auxiliary allocation, task/descriptor lifetime and packet concurrency.
