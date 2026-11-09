# Original constructor request VM-copy construction and queue handoff

The original FairPlayIOKit constructor now calls the real adapter, authenticated stub, exported `_vm_map_copyin` wrapper and common VM-copy factory before constructing its RPC request. Four continuous private CPU executions produce a complete 48-byte type3 object backed by 29 staged string bytes, return to the actual kext caller at `0xfffffe000a60b784`, then pass that object through original RPC502/700 preparation and queue insertion. The previous whole-call `vm_map_copyin_model` is absent from these cases.

Raw backing/header allocation and the lower map byte-copy primitive remain contracts. Native allocation, VM access/protection/map switching, class19 zone creation, PAC authentication, descriptor delivery and daemon processing remain unknown. This supplies a source-produced request copy object for the next connection to the [receiver descriptor frontier](kernel_request_receive_report.md); that receiver continuation is not executed here. The [ZUT trace](zut_trace_report.md) remains separate historical failed-open evidence.

## Primary evidence and composition

Original KC SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Addresses below are unslid logical KC addresses. Exact compiler-bounded functions, nlist names, adapter/stub bytes and authenticated chained pointer records are independently recaptured.

| Artifact | Contents |
| --- | --- |
| [Source](triage_evidence/kernel_request_copyin_source.json) | 132 complete kernel functions / 18407 instructions; nine additions / 2741 instructions; 13 copyin-role instructions; actual adapter/stub/slot/export binding |
| [Profiles](triage_evidence/kernel_request_copyin_profiles.json) | Four original caller/VM factory/RPC queue executions; complete RAM, CPU, effect and object journals |
| [Checks](triage_evidence/kernel_request_copyin_checks.json) | Independent context/before-image, object/backing/caller/packet/queue oracles, fresh CPU replay and two scalar proofs |
| [Preservation](triage_evidence/kernel_request_copyin_delivery.json) | Prior 6330 artifact hashes and six owned reporting changes |
| [Quality gates](triage_evidence/kernel_request_copyin_quality_gates.json) | QG1-QG7 and exact scope boundaries |
| [Prior manifest](triage_evidence/kernel_request_copyin_prior_manifest.json) | SHA-256 `ae0854b4ae47c37d61ec5c6b44fffaf7e2dd824bd0febf037f6bfe9a3204ea6b` |

```text
original kext constructor -> staged C string including NUL
   -> original adapter/stub -> exported vm_map_copyin -> common factory
       -> original size/range/policy selection
       -> raw backing allocation [contract]
       -> lower map byte copy [contract, exact staged bytes]
       -> raw header allocation [contract]
       -> original complete type3 header construction/signing/publication
   -> actual original kext return -> original descriptor packing
   -> original RPC preparation/right copyin/send/queue/linkage
   -> STOP before common receive
```

The source environment comes from the preceding [request-path analysis](kernel_rpc_request_report.md). Four selected environment outputs are freshly replayed. Map observations, raw copy storage, type cells and allocator-view identity are then declared before entering the original constructor. No packet or object replacement occurs at the VM call/return or RPC boundary. Their complete intermediate states are checked independently.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| VC1 | Original KC and preserved environment artifacts identify the intended source. All address/function claims depend on this. | Rehash, recapture complete bodies, nlist records, chained slot and every visited instruction; verify live build identity separately. |
| VC2 | The inherited thread/owner/task/host/port/zone/cache epoch and source-produced environment remain valid private premises. Queue-path results depend on these prior contracts. | Freshly replay the four selected environment producers; compare full origin RAM/globals, sender records, rights, queue and accounting. Native context/registration/cache provenance remains unknown. |
| VC3 | Two disjoint 1024-byte map observation records with declared bounds, shift 14, reference 3 and clear source flag select the recorded VM path. | Independently reconstruct maps and typed cells, preserve original policy value 2, execute source range/predicate selection. Native map allocation, protection and lifetime are unknown. |
| VC4 | Raw 48-byte header and 29-byte backing storage are returned by the lower allocators; a declared class19 allocator-view pair is used. Object creation depends on these contracts. | Check exact allocator arguments, raw before bytes, guards and original full header stores. Class19 creation caller/native view is unknown; the original 192-byte file record is zero. |
| VC5 | The lower map-copy primitive succeeds and copies the staged 29 bytes. Backing data depends on this effect. | Derive source/destination/count from live registers; independently compare source bytes and before/after effect. Native map switching, access checks, faults and physical backing remain unknown. |
| VC6 | Logical code/data/return PAC follows original pointers and modifiers. Pointer/control-flow claims depend on this model. | Recapture exact instructions, stub slot/address modifier and full CPU frames. Hardware PAC validity remains unknown. |
| VC7 | The supplied 28-byte patterned C string, mode502/700 and fresh/prebound reply variants bound finite execution. | Preserve the string including NUL; compare complete headers/backing, actual return and queue packet. Other lengths, policy contexts, failures and entry-list paths remain outside these four executions. |
| VC8 | Remaining constructor/transport primitive contracts retain their stated outcomes. Composition does not establish a native round trip. | Check dependency hashes, primitive arguments/volatile clobbers and independently replay complete states. Execute descriptor copyout and daemon reception with the produced object next; native effects remain unknown. |

## Actual API binding and routine roles

| Original location | Identity or recovered role | Established contract |
| --- | --- | --- |
| `0xfffffe000a60b780` | Original constructor call instruction | Logical authenticated call to adapter; actual return at `...a60b784` |
| `0xfffffe000a508e2c` | Kext VM-copyin adapter | Original instructions reach stub `0xfffffe000a69f464` |
| `0xfffffe000a69f464` | Original four-instruction authenticated stub | Loads slot `0xfffffe000847c560`; `BRAA X16,X17` uses slot as modifier |
| `0xfffffe000847c560` | Original format8 authenticated fixup | Address diversity1, diversity0, key0; target `0xfffffe000bdd1594` |
| `0xfffffe000bdd1594` | Exact exported `_vm_map_copyin` | Original wrapper takes `(map,source,extent,destroy,copy_out)` |
| `0xfffffe000bdd15a4` | Common VM-copy factory | Original range, page, small-copy and policy selection; type3 construction |
| `0xfffffe000bdd16c8` | Small-copy extent gate | Compares extent to 32768 bytes; current extent 29 selects the small route under supplied flags/ranges |
| `0xfffffe000bdd1864` | Read copyin-policy selector | Original file value 2 is retained, not replaced by 0 |
| `0xfffffe000bdd1e94` | Backing allocation call | `(descriptor 0xfffffe0007f8bfb0,29,0,0)`; raw storage contract |
| `0xfffffe000bdd1eb4` | Lower map byte-copy call | `(source_map,staging,backing,29,1)`; exact byte effect contract |
| `0xfffffe000bdd1ef8` | Header allocation call | `(class19_view,class19_statistics,4,...)`; first three arguments are established |
| `0xfffffe000bdd1f24` | Sign backing pointer | Logical `PACDA X17,X16`, discriminator `0xb7af` |
| `0xfffffe000bdd1f38` | Publish copy object | Original store to the actual caller-supplied output address |

Names are exact only where nlist identity is stated. Capturing 132 complete bodies does not mean all their branches execute. In particular, the lower map-copy body and generic predicate helper are captured; the former remains modeled, and the common factory executes its own inlined policy path.

The actual call arguments are `(ipc_map,staging,29,0,&copy_result)`. Destroy is 0, so the original successful factory publishes the object without requesting source-range removal. The staging allocation therefore remains distinct from the new backing allocation. The actual caller resumes with X0=0, original SP and X18-X29 preserved, then reads the published object and packs it into the original request descriptor. [VC2-VC8]

## Type3 representation and byte provenance

All R-relative addresses below are private model coordinates, R=`0x6500000000`. The input is the declared pattern `byte[j]=0x21+(j mod90)` for 0 <= j <28, followed by NUL. These are synthetic caller bytes, not an observed native pathname or authenticated FairPlay payload.

| Object/field | Private value or extent | Producer/provenance |
| --- | --- | --- |
| Kernel map / source ipc map | R+`0x84000` / R+`0x85000`;1024-byte observations | Declared map context, both in type16 metadata page |
| Current thread map | thread+`0x428` ->kernel map | Explicit pre-constructor context |
| Staging / allocation extent | R+`0x70000`;16384 bytes | Original constructor with inherited staging-allocation/byte-copy contracts |
| Copy object | R+`0x88010`;48 bytes | Declared raw storage; every header byte is source-constructed |
| Backing | R+`0x8c000`;29 bytes | Declared raw allocation; lower copy uses exact original staging bytes |
| Header+`0x00` u64 | Backing pointer | Original signed-pointer store |
| Header+`0x08` through+`0x1f` | Zero | Original stores |
| Header+`0x20` u64 | 29 | Original extent store |
| Header+`0x28` through+`0x2f` | Zero except type byte | Original stores; type3 at+`0x2d`; selected byte+`0x2e` is 0 |
| RPC descriptor pointer | Produced copy object | Original caller packs it; original RPC preparation signs it with discriminator `0x5d4f` |
| Header/backing guards | `0xa5` | Preserved outside the declared48-byte and 29-byte observations |

The old opaque copy identity R+`0x86000` shares a16-KiB type-metadata page with the map fixtures. It is not reused as a type19 object. The source-produced header now occupies a separate type19 page, while both maps share a consistent type16 page. The backing and C-string observations are also disjoint. This establishes private fixture consistency, not native allocation validity. [VC3,VC4]

## Cross-layer result and ownership boundary

| Property | Result in all four cases |
| --- | --- |
| Request ID / source host slot | RPC502/slot17 or RPC700/slot34, as before |
| Kernel send extent / receive capacity | 88 /400 bytes |
| Published VM object / logical extent | Source-produced type3 object /29 bytes |
| Queued descriptor/body | Prior complete packet with only the copy-pointer identity changed to the produced object |
| Destination refs / send rights | 5 /2 at common receive frontier |
| Reply refs / send-once rights | 2 /1 at common receive frontier |
| Queue count / task send counter | 1 /1 |
| Whole-call `vm_map_copyin_model` | No invocation |
| New lower VM contracts per case | One backing allocation, one header allocation, one map byte-copy effect |
| Endpoint | Before common receive at `0xfffffe000bcc83b4` |

The complete queued kmsg is reconstructed independently from the prior source-produced request with the new descriptor pointer. Destination/reply/turnstile records and task send accounting remain byte-for-byte equal to the corresponding prior result. The current thread's declared map pointer is the expected additional context difference. Complete header/backing bytes remain intact at the actual caller return, RPC handoff and final queue frontier.

The constructor owns a staging allocation while the VM-copy object references a separate backing allocation. Source destroy=0 does not consume the staging range. The object is then held in the queued request. Consumption, descriptor-copyout failures, backing/header retirement and daemon-visible mapping have not executed here. No new Mach-message emission site is introduced: the established send call remains `0xfffffe000bcf5ba8`. [VC4,VC5,VC8]

Four VM snapshots per case cover adapter entry, factory publication, actual kext return and RPC entry:16 full CPU/RAM handoffs. The inherited constructor-to-RPC snapshot adds four independently checked boundary snapshots. All these transitions retain original CPU/RAM state; no returned VM object or queued packet is supplied by an import at those boundaries.

## Validation and reproduction

Four continuous cases execute 26506 original instructions: two fresh-reply cases at 6697 each and two prebound-reply cases at 6556 each. Independent fresh CPU replay checks 10414 writes / 81142 bytes, 3624 reads / 21860 bytes, 66 primitive models, 36 VM ABI/object frames, 16 VM full-state handoffs and four complete final RAM images / 4194304 bytes. Fresh environment replay contributes 314 separate original visits and four further full final RAM images. These counts are finite conditional validation, not native coverage or performance measurements.

Two scalar UNSAT checks cover (1) unsigned32 `length+1` without wrap for 0 <= length <=32767 and (2) 14-bit page rounding containing the original interval for 1 <= extent <=32768 within the declared private arena. They establish arithmetic within stated domains; only length28/extent 29 executes through the full caller here.

```sh
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_request_copyin.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_request_copyin.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_request_copyin.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/seal_kernel_request_copyin.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/verify_kernel_request_copyin_publication.py
```

Recovery/CPU validation take O(image bytes + source visits + copied RAM bytes + journal effects) time and O(image bytes + one CPU RAM map + journals) working space. Each private RAM image is 1048576 bytes. Addresses, widths, counts and byte sizes are exact. Native timing, error rates and physical ownership remain unknown.

## Bounded remaining evidence

| Impact | Question | Resolving evidence |
| --- | --- | --- |
| High | Can the receiver convert this exact request copy object into the daemon's address space? | Transfer this complete queued state into the original receiver path, then execute descriptor VM copyout and user-message construction. |
| High | What creates class19's real allocator view and storage? | Recover its original creation caller and native epoch; the generic startup catalog lacks an established class19 specification. The current raw allocation pair is explicit. |
| High | Does the lower map byte-copy primitive enforce the intended map/protection semantics? | Execute or independently establish its map-switch, access/fault and cleanup contracts with source-derived state. Current byte copying is a model. |
| Medium | What changes for larger extents or policy flags selecting entry-list copies? | Join source-produced map/store entries and actual caller branches; the small-copy result does not generalize to type2. |
| Medium | What retires the request backing/header and staging allocation after send or reply failure? | Continue ownership through original receiver/copyout/reply/cleanup paths without interpreting stale pointer bits as ownership. |
| Low | Are native host registration and task/daemon identities paired to this static build? | Establish registration writers, namespaces and deployed identity independently of private coordinates and the failed-open ZUT capture. |

## Quality gates

- QG1: Technical source/ABI/data-flow analysis; no normative conclusion required.
- QG2: VC1-VC8 identify assumptions, dependent conclusions and concrete falsification probes.
- QG3: Actual producing API/binding, VM object representation, byte provenance, caller return, descriptor forwarding, queue/right state and respective report updates are covered within this increment. The full goal remains active.
- QG4: Exact widths, byte extents, header fields, arithmetic domains, complexity and reproduction commands are recorded.
- QG5: Whole API execution versus lower primitive contracts, original policy2 versus runtime state, disjoint type pages, staging versus backing ownership and queued object versus delivered user memory are distinguished.
- QG6: Original complete bodies, nlist records, chained slot,13 instruction roles, every visited instruction, fresh environment states and independent CPU/object/packet effects are checked against primary local bytes.
- QG7: Impact-labeled continuation targets class19 creation, lower VM semantics, exact receiver descriptor conversion, lifecycle and actual endpoint identity; native exchange remains unknown.
