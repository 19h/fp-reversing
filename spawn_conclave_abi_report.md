# Spawn descriptor ABI, Conclave serialization and bounded receiver evidence

The original user-space spawn path serializes the Conclave identifier as a size/address pair at descriptor+0x80/+0x88: extent 128 B followed by the pointer from private attribute+0xf8. Launchd's attribute preparation and subsequent `posix_spawnp` call use the same handle address. Cached libc binds through an original shared stub to libkernel; the normal and optional-filter paths reach BSD syscall 244. The captured kernel requests a copy of the full 144 B descriptor, but its 209 direct SP-relative loads contain no read overlapping the copied Conclave pair [CP1-CP4]. [Original capture](triage_evidence/spawn_conclave_abi_source.json), [checks](triage_evidence/spawn_conclave_abi_checks.json).

The complete descriptor-taking helper consumes a different pair, descriptor+0x30/+0x38, for MAC-policy extensions. Named original setter/getter exports establish those nested 144 B records as MAC extensions. Their own+0x80/+0x88 data-pointer/length fields are distinct from the outer Conclave pair. The receiver census is bounded: arbitrary aliases, other callees, other images and whole-kernel non-use remain unknown. Native spawning, Conclave effects and effective FairPlay job identity are not established.

This extends the [job/endpoint factory lineage](job_factory_lineage_report.md), [launch frontier](endpoint_job_lifecycle_report.md) and [Exclaves control boundary](exclaves_notification_contract_report.md). The separate control trap returns 46 in the captured collection; that fact does not determine this BSD spawn path's behavior.

## Identities and scope

Launchd SHA-256 is `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`; slice UUIDs are `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71` and `62af2b7d-327e-334a-a1d7-83777efc3c12`. Cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`; original library UUIDs, exports, shared-stub pointer chain and used cache-file hashes are retained. Kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` [CP1,CP6].

Capture contains 22 complete compiler-bounded bodies: eight launchd bodies across two slices, ten cached bodies and four kernel bodies, totaling 6938 instructions/27752 B. Nine selected launchd words require byte-checked LLVM decoding. Both slices' 4894 fixups independently match `dyld_info`. Private labels remain analytical; empty kernel nlist results are not treated as original names.

```text
J.identifier -> copied attribute string (128 B buffer)
  -> launchd work record: attribute handle at SP+0x38
  -> posix_spawnp -> shared stub -> posix_spawn
     -> descriptor[8] = {128, attribute.identifier_pointer}
     -> normal or optional-filter syscall path
        -> BSD244 -> request descriptor copy-in (144 B)
           +-> direct SP-relative reads: pairs0..7
           +-> Conclave pair8: no overlapping direct SP-relative load
           +-> descriptor helper consumes pair3 (MAC extensions)

selected caller cleanup -> attribute destroy -> clear/free frontiers
```

Each edge is conditional on the captured control path and valid initialized objects. A requested copy-in is distinct from observed native byte continuity or a successful process launch.

## Launchd handle and ownership lineage

| Role | arm64e | arm64e.x1 | Selected effect |
|---|---|---|---|
| Launch core | `0x10001ee14` | `0x10001e76c` | Prepare work record, attributes, argv/environment and conditional spawnp call |
| Work-record initialization | `0x100013e98` | `0x100013b8c` | Zero 2888 B; initialize attribute handle at+0 and file-actions handle at+8 |
| Attribute preparation | `0x10002369c` | `0x100022f58` | If J+0x570 is nonnull, call Conclave setter with the attribute-handle address |
| Work-record cleanup | `0x100013f14` | `0x100013c08` | Attribute destroy, file-actions destroy and additional selected cleanup |

The launch core initializes the record rooted at SP+0x38 before attribute preparation. It passes that address in X1 to preparation and later in X3 to `_posix_spawnp`; file actions are supplied from the record's+8 handle. Spawnp emission sites remain `0x10001f7c0` / `0x10001f118`, with a local PID-output address and path/argv/environment arguments. Selected post-call code checks status and a positive PID. No actual executable admission, PID creation or native FairPlay invocation follows from these call sites [CP1,CP2].

The cached attribute initializer requests 256 B through a runtime allocator table, publishes the returned pointer through the opaque handle, initializes fields and zeroes the tail containing+0xf8. The Conclave setter, recovered previously, stores a separately allocated 128 B string buffer at+0xf8. Thus the job's identifier and attribute string are separate ownership stages. The destroy routine clears+0xf8 before a conditional runtime free call and finally clears the outer handle. Missing callbacks, allocation failure, earlier cleanup branches and actual free effects remain dependencies [CP2,CP5].

## User-space descriptor and filter path

| Cached role | Original address |
|---|---|
| libc `_posix_spawnp` | `0x1805d7908` |
| libkernel `_posix_spawn` | `0x18054eee8` |
| BSD veneer `___posix_spawn` | `0x18054f12c` |
| Attribute initialization / destruction | `0x18054ea78` / `0x18054f158` |
| Conclave attribute setter | `0x18055edbc` |
| Optional filter body, original name `__posix_spawn_with_filter` | `0x180557f2c` |
| Late libkernel initializer | `0x180557930` |
| MAC-policy getter / setter | `0x18054ebe8` / `0x18054ecbc` |

Both recorded spawnp-to-spawn call sites use shared stub `0x18806df00`. Its original authenticated cache pointer at `0x1e2104108` resolves exactly to `_posix_spawn`. Path-search branches and error continuations are retained as complete code, but their complete environment/filesystem policy is not newly interpreted [CP1,CP5].

The public wrapper prepares nine size/address pairs. For nonnull admitted sources, the selected fields are:

| Pair / descriptor offset | Source | Size field in captured producer |
|---|---|---|
| 0 / +0x00 | Attribute object | 256 B |
| 1 / +0x10 | File-actions object | 8+1040*n B, selected positive count n |
| 2 / +0x20 | Private attribute+0xc8 | 8+24*n B on its admitted count path; complete semantic role not assigned here |
| 3 / +0x30 | Private attribute+0xd0, MAC-extension array | 8+144*n B on its admitted count path |
| 4 / +0x40 | Private attribute+0xd8 | 48 B |
| 5 / +0x50 | Private attribute+0xe0 | 88 B |
| 6 / +0x60 | Private attribute+0xe8 | 340 B |
| 7 / +0x70 | Private attribute+0xf0 | 1024 B |
| 8 / +0x80 | Private attribute+0xf8, Conclave string | 128 B |

The table describes source instructions and selected admitted branches. It is not a native request fixture or a complete validation predicate. The private 256 B object is distinct from the public 8 B opaque handle. These pairs refer to caller memory; they do not inline the Conclave string or represent Mach message port descriptors [CP2,CP3].

The filter cell at `0x1eb065e68`, originally named `_posix_spawn_with_filter`, is zero in the captured file. The late initializer can store a signed pointer to the filter body after a selected version>=3 / byte+0x0a==1 gate. The public wrapper uses nonnull state as the filter gate and calls the captured body directly. Native initialization and effective filtering remain unknown; file-default zero is not a live observation [CP5].

The filter body copies all 144 descriptor bytes to its local record, including a 16 B load/store of the final pair. It also copies the attribute object to local storage and replaces the local descriptor's attribute pointer while preserving the extended pair. Its file/environment processing and string/allocator callbacks are additional prerequisites. Selected terminal code calls the same BSD veneer with the local descriptor. This establishes conditional descriptor preservation, not native filter selection or complete filter semantics.

The BSD veneer loads X16=244, executes SVC 0x80 and routes the carry-error path through `_cerror`. The public wrapper's selected return path reads the result/TLS errno and restores its saved errno value. Cancellation callbacks, every early arithmetic-error path and effective TLS state are not newly proved. These are BSD/errno contracts, separate from Mach status46 in the Exclaves control interface.

## Kernel ingress and bounded Conclave read census

| Original kernel role | Address | Selected contract |
|---|---|---|
| BSD244 handler | `0xfffffe000c2a2b4c` | Five-argument spawn implementation; complete 2556-instruction body |
| Argument munger | `0xfffffe000bf0875c` | Five u32 inputs widened to five 64-bit slots |
| Named `_copyin` entry | `0xfffffe000be76e18` | Original nlist binding; lower memory/backend effects remain dependencies |
| Descriptor-taking helper | `0xfffffe000c2a5450` | MAC-extension array/payload copy and selected cleanup |

The original sysent row and name pointer bind BSD244 to the handler. Its retained metadata records five arguments and 20 u32 argument bytes. The munger expands 20 B to 40 B. In the handler's native-width argument record, offsets0/8/16/24/32 carry the PID-output pointer, path pointer, descriptor pointer, argv and environment respectively [CP1,CP3].

The selected descriptor paths request 144 B directly or 72 B followed by nine vector zero-extension operations, producing the same nine-pair 144 B local layout. The compatibility association is inferred from 32-bit to 64-bit field widening; actual runtime selection remains unknown. The descriptor's local frame base is SP+0x250. Its final pair therefore occupies SP+0x2d0 through SP+0x2df inclusive.

If the base-attribute pair is present, the kernel requests 200 B from the attribute-object address into a separate local record. That base copy excludes private attribute+0xf8: the Conclave pointer begins at 248 B, beyond the 200 B extent. Other pointed records use their separate descriptor pairs. Thus the last descriptor pair is the identified user-space route for the string, rather than the copied base-attribute prefix [CP2,CP3].

The reproducible receiver census establishes:

- All 209 literal SP-relative load instructions are width-checked, including paired and narrow loads. None overlaps [SP+0x2d0,SP+0x2e0).
- Two literal address formations produce SP+0x250: the descriptor copy-in destination and the descriptor-helper argument.
- The helper's four recorded direct reads through its incoming descriptor aliases select offset+0x30, including the+0x38 address member of that pair.
- A nested load at helper `0xfffffe000c2a5640` uses inner MAC-extension record+0x80/+0x88. Its base is computed from the separately copied extension array; it is not a direct read of the outer Conclave pair.

This is bounded negative evidence, not a whole-kernel absence proof. Register aliases, other callee access, stack inspection, effective code changes and other images remain outside this census. The source marks `whole_kernel_nonuse_proved=false`. Native effect of the Conclave attribute remains unknown [CP4].

## Distinct nested MAC-extension contract

The named getter and setter access private attribute+0xd0. Their stride calculation, bounded policy-name copy and data-pointer/length stores establish this reconstruction:

| Nested MAC-extension field | Offset / capacity |
|---|---|
| Policy-name field | +0,128 B |
| Caller data address | +128,8 B |
| Caller data extent | +136,8 B |
| Record stride | 144 B |
| Array prefix | 8 B; capacity/count words |

The setter stores the caller's data pointer/extent; its array growth does not establish a private copy of that payload. The getter recovers those two fields after a policy-name match. The original kernel helper separately requests a copy of the array, computes the aggregate payload extent, allocates a flat buffer, and issues one copy-in per selected record. It replaces each copied data pointer with an offset into the flat buffer. On its successful suffix, the helper publishes array pointer, flat-buffer pointer and total extent into a 24 B output record. Allocation, bounds, user-memory stability, callbacks and later policy consumption remain dependencies [CP2,CP3].

The outer descriptor is 144 B, and each MAC-extension element is also 144 B. Those equal sizes do not imply type identity. Their+0x80/+0x88 fields have different roles and bases. This distinction is necessary when interpreting offset searches and explains why a nested field hit is insufficient evidence of Conclave consumption.

## Applicability, assumptions and further interfaces

The current FairPlay plist remains byte-identical to SHA-256 `ca21543400f3ead9e96d2434f968184b6acd2e1e3de57322ca3da663831eae3c` and does not declare `_Conclave`. Effective overrides, actual launch inputs, initialized filter state and native job identity remain unknown. The report therefore establishes a generic launchd-to-spawn interface and its receiver evidence; a FairPlay-specific Conclave effect is unproved [CP1,CP5].

| ID | Assumption / dependent result | Stress test / falsification probe | Remaining boundary |
|---|---|---|---|
| CP1 | Captured launchd/cache/kernel bindings describe the applicable path | Pin identities; compare both slices, two shared-stub bindings, original sysent/name and munger | Runtime slice, reexports/interposition and effective kernel image unknown |
| CP2 | Initialized handles and borrowed pointers retain one object epoch | Join SP+0x38 setup/use/cleanup, private 256 B initialization, Conclave copy and clear/free frontiers; distinguish MAC borrowed data | Allocation, callbacks, concurrent changes and native lifetime/balance unknown |
| CP3 | Copy-in/backend operations obey the required data contract | Preserve exact argument/descriptor/base/auxiliary extents, status continuations, width conversion and MAC output publication | Native memory validity, byte continuity, policy admission and successful spawn unknown |
| CP4 | Receiver census is used only within its locator domain | Recompute every 209 direct SP load span and selected helper reads; preserve nested-record base provenance | Arbitrary aliases/callees, other images and whole-kernel non-use unknown |
| CP5 | Effective configuration selects the recorded normal/filter path | Separate file-default zero from late version/flag publication; rehash FairPlay plist and absent key | Initializer input, filter file/environment processing, effective job inputs and Conclave use unknown |
| CP6 | Reconstructed geometry and scalar models match only their stated operations | Fresh recapture/decoding, 4894 fixups, compiled SDK/geometry, scalar identities and altered-evidence rejection | Canonical private types, hardware PAC/x1 semantics and whole-goal completion unknown |

| Impact | Remaining interface question | Concrete anchor |
|---|---|---|
| High | Any additional Conclave receiver access | Extend beyond the literal SP/helper census with explicit alias and callee analysis; preserve the final-pair interval and separate base-attribute prefix |
| High | Effective FairPlay launch correspondence | Bind the initialized handle, actual path/argv/environment and effective job record to one native launch epoch |
| High | Filter initialization and selection | Trace the producer of late-initializer version/byte+0x0a and the effective filter cell; default zero is insufficient |
| Medium | MAC-extension policy consumer | Follow the helper's 24 B output and pointer-to-offset representation into the actual policy consumer |
| Medium | Ownership and syscall-result completion | Bind user buffers, copy-in success, PID publication, attribute cleanup and error/cancellation state |
| Low | Wider ABI variants | Extend packing checks to matching alternate images without treating a field offset or equal record size as type identity |

## Validation and quality gates

Fresh source recapture matches the saved capture. Validation covers complete contiguous bytes/decodes, 123 selected instruction occurrences, two original spawnp bindings, the 209-load census, 19 SDK assertions in one arm64 compilation, three full-domain scalar proofs and six rejected evidence alterations. The proofs cover admitted-count size formulas and zero-extended 32-bit lane packing. They do not execute target records, construct native requests or prove whole-kernel non-use. [Recovery](triage_evidence/recover_spawn_conclave_abi.py), [validator](triage_evidence/validate_spawn_conclave_abi.py), [delivery](triage_evidence/spawn_conclave_abi_delivery.json), [quality gates](triage_evidence/spawn_conclave_abi_quality_gates.json).

Capture/census is O(B+F+I+L) time/space for original bytes B, fixups F, selected instructions I and locator records L. Scalar size/offset operations are O(1). Selected MAC array/payload preparation is O(n+S) in admitted element count n and copied payload bytes S, excluding allocator, memory and policy/backend costs. No recovered target execution, emulation, SVC, spawn, IPC, service/port change or IDB mutation occurs.

QG1: Descriptive interface analysis requires no normative premise.

QG2: CP1-CP6 record assumptions, dependent results, falsification probes and unknowns.

QG3: Handle production/use/cleanup, normal/filter serialization, descriptor and syscall geometry, kernel copy-in, bounded read evidence and distinct MAC records are covered; the full objective remains active.

QG4: Public handle 8 B, private attribute 256 B, descriptor 144/72 B, native/compat argument 40/20 B, Conclave buffer 128 B, base copy 200 B and code 6938*4=27752 B remain distinct. Reconstructed types are not claimed as canonical private SDK types.

QG5: Serialization differs from native consumption; direct-read absence differs from whole-kernel absence; outer descriptor and nested MAC records have separate bases; file-default filter state differs from initialized state.

QG6: Original bytes, exports, pointer chains, named copyin, sysent/name, current plist, primary SDK and checked scalar identities supply provenance. Runtime effects remain unknown.

QG7: Remaining questions have bounded anchors and impact labels. Native spawning, FairPlay/Conclave attribution and complete interface coverage remain unproved.
