# Kernel collection bindings, special ports, and protected RPC callers

The original matching kernel collection resolves 415 of the extracted kext's 417 external pointer values directly to exact symbols. Subsequent [native bias recovery](kext_port_vm_report.md) binds the remaining two to `_kernel_map` and `_ipc_kernel_map` after explicit four-byte adjustments. Native protected-dispatcher slices resolve calls to `host_priv_self`, `host_get_special_port`, RPC502, and RPC700. Under the recovered local protocol, the special-port selector is 17 when the request word at `+0x24` equals 1, otherwise 34. Current launchd reports an active native `com.apple.unfreed` endpoint on slot17. The kernel port-object identity, process-selected executable slice, and complete object-alias/control-flow chain remain unknown.

## Build provenance and assumptions

| Artifact | Current verified identity |
| --- | --- |
| Collection | `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`; SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Embedded kernel | UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84` |
| Embedded/extracted FairPlayIOKit | UUID `227f9df7-645d-39b8-b74a-685303d16b4b`; extracted SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Collection base | `0xfffffe0007004000`, unslid |

Current read-only `sysctl -n kern.uuid` and `kmutil showloaded -b com.apple.driver.FairPlayIOKit` checks also match these UUIDs; the loaded driver reports version 72.19.0. See [live identity snapshot](triage_evidence/current_kernel_identity.json). This identifies the current running build, without attesting the historical emulator run, native slot contents, or runtime memory integrity.

The read-only resolver scans 362 fileset entries and 504,045 nlist records. Four kext sections match raw bytes, including all `__text` and `__auth_stubs`. The other eight match after original collection chained fixups are decoded: **all 12 file-backed sections match**, with no remaining differences. All 795 stored pointer occurrences for the 417 candidate values agree with their original raw/decoded collection locations. This includes section-wide evidence beyond a UUID comparison.

The collection contains 1,036,413 decoded chained entries, using format 8 with cache level 0. An 8-byte pointer can begin in the final four bytes of a page; the walker constrains its start to that page and full width to its file-backed segment. The original chain membership, raw word, target, diversity, address-diversity flag and key are retained per relevant pointer. Apple's primary [fixup-chain representation](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h#L206) defines this format. Neither stripping the stored encoding nor decoding its metadata validates native pointer authentication.

| Assumption | Dependent claims | Stress test / falsification probe |
| --- | --- | --- |
| K1: source/collection images are stable and preserve the observed unslid layout | Binding identities and target addresses | Rerun complete section normalization and per-slot comparisons; mismatches fail the claimed correspondence |
| K2: the common dispatcher frame contains the initialized table/bank pointers | Four local target reductions | Reconstruct each predecessor or capture native frame/register values; arbitrary entry into fragments is outside this contract |
| K3: the host lookup follows the inspected non-null allocation predecessor; the RPC operation branch has W11=`0x8ea` | Word==1 selection and RPC variant mapping | Exercise another predecessor/control state; target reductions remain separately checked, while variant selection is conditional |
| K4: normal callee-saved state and stable read-only bank/table memory hold | Register persistence across the local calls | Capture native state or prove caller/callee preservation; no whole-program race or PAC claim |
| K5: public XNU API semantics explain conventional host/port types | Meaning of kernel host handle and returned send reference | Match target kernel implementation/revision; actual native pointer values and port contents remain runtime observations |

The [resolver output](triage_evidence/kernel_collection_interfaces.json) contains exact symbols and segment ownership separately. Symbol matches include data/metaclass objects, not only executable functions. Values `0xfffffe0007efa634` and `0xfffffe0007f860ac` do not directly equal nlist symbols. The [subsequent native adjustment proof](triage_evidence/kext_port_vm_contracts.json) establishes that each is four bytes above an exact pointer-cell symbol: `_ipc_kernel_map` and `_kernel_map`, respectively. The original raw/decoded pointers and direct-symbol count remain unchanged; no nearest symbol was substituted as an exact function identity.

## Recovered kernel bindings

| Role | Actual collection symbol address | Protected table slot | Core2 index |
| --- | --- | --- | --- |
| `host_priv_self` | `0xfffffe000bcf27ac` | `0xfffffe000847ac10` | `0xf9e` |
| `host_get_special_port` | `0xfffffe000bcf258c` | `0xfffffe000847ac88` | `0xfad` |
| `ipc_port_release_send` | `0xfffffe000bcd0448` | `0xfffffe000847a7a8` | `0xf11` |
| `IOMallocAligned` | `0xfffffe000c4b9a08` | `0xfffffe000847a8f8` and another pool | `0xf3b` for the listed slot |
| `IOMallocTypeImpl` | `0xfffffe000c4ba154` | `0xfffffe000847a7b8` and another pool | `0xf13` for the listed slot |
| `IOFreeTypeImpl` | `0xfffffe000c4ba368` | `0xfffffe000847a878` and another pool | `0xf2b` for the listed slot |

The table base is `0xfffffe0008472f20`. The special-port entries are real callable addresses in the kernel collection. Earlier synthetic UNDEF addresses such as `0xfffffe000cccf700` remain IDA import placeholders and must not be treated as those implementations.

## Native special-port acquisition

| Native event | Site / established data flow |
| --- | --- |
| Obtain kernel privileged-host handle | Indirect call at `0xfffffe000a60ac04` -> `host_priv_self` |
| Choose selector | `0xfffffe000a60ac10` compares request u32 with recovered comparison value 1; `...ac14` selects 17 or34 |
| Prepare output and node | `...acac`: X3=`X28+0x18`; `...acb0`: W1=`0xffffffff` (-1) |
| Obtain special-port reference | Indirect call at `...acb8` -> `host_get_special_port`; X0 is the previous host-handle result, not overwritten by intervening calculations |
| Test status | Predicate ending `...ad04`/`...ad08` is exactly status==0 under the declared local state |
| Forward acquired field on success | `...ad58` reads `[X28+0x18]`; `...ada0` stores it at another argument record's `+8` |

The common native shape is:

```text
host_priv_self() -> kernel host_priv_t handle
                         |
host_get_special_port(handle, -1, selector, &context_field_18)
                                      selector = word24 == 1 ? 17 : 34
                         |
                   status == 0 path
                         |
              copy context_field_18 into another call record
```

The comparison value 1 follows the non-null predecessor protocol: the branch slot for `0xfffffe000a60ab74` has index `0xc96`; preceding state arithmetic gives incoming W23=`0x3e785138`, W22=`0x448`, W20=`0x43f`, and W26=1. This is a conditional source reduction, not proof that every native execution reaches that predecessor.

The source uses two different status encodings for the selector branches. Both reduce to a zero-status test. Z3 returned `unsat` for the negation of that equivalence over all 32-bit statuses in each branch. [Proof result](triage_evidence/special_port_contract_proof.json) and [queries](triage_evidence/host_port_status_selector17.smt2).

Primary [XNU host implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/host.c#L1306) distinguishes the kernel `host_priv_t` handle from an `ipc_port_t` send reference; `host_priv_self` returns `&realhost`, while special-port lookup copies a send reference into the output. Its success return does not alone establish a non-null or live endpoint. This is reference-source context; effective slot contents and this kernel's complete lifetime behavior were not observed.

Current read-only `launchctl print system/com.apple.fairplayd` reports the native job running and its `com.apple.unfreed` endpoint active with host-special port17. The actual job plist declares slot17 for that service and slot31 for `com.apple.arcade.fpsd`; both endpoints are active in the snapshot. The native job runs as `_fpsd`, with `DYLD_PAGEIN_LINKING=0`, from `/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd`. That executable has exactly the IDB-recorded universal-file hash. Its arm64e slice is exactly the zut thin image; which slice the live process selected remains unknown. See [job/file evidence](triage_evidence/native_fairplayd_services.json) and [live launchctl snapshot](triage_evidence/native_fairplayd_launchctl.txt).

| Service | Declared host slot | Live launchctl-reported endpoint value | Live state |
| --- | ---: | --- | --- |
| `com.apple.unfreed` | 17 | `0x2603` | active, managed |
| `com.apple.arcade.fpsd` | 31 | `0x2503` | active, managed |
| `com.apple.fairplayd` | none declared | `0xfad0b` | active, managed |
| `com.apple.fpsd` | none declared | `0x1262f3` | active, managed |
| `com.apple.fpsd.sim` | none declared | `0x125893` | active, managed |
| `com.apple.fairplayd.xpc` | none declared | `0x11a7df` | active, managed |

These are snapshot values printed by launchctl, not kernel pointer identities or established daemon-local port names. They must not be equated with the emulator's guest names. A read-only scan of system LaunchDaemons plists found no declared slot34 and no plist-read errors; it does not cover every possible runtime or programmatic registration. Slot34 purpose/reachability and the request word's relationship to UserClient virtual mode remain unknown. The native launchd publication evidence strengthens the slot17 association but does not prove that a captured kext lookup returned that particular port object or that an RPC round trip executed.

## Protected RPC callers and local argument ABI

| Operation | Protected indirect caller | Selected table slot / callee | Actual Mach emission |
| --- | --- | --- | --- |
| RPC502 | `0xfffffe000a60b8a8` | `0xfffffe000847aa90` -> `0xfffffe000a5a2064` | `0xfffffe000a5a20f8` |
| RPC700 | `0xfffffe000a60d3bc` | `0xfffffe000847ace8` -> `0xfffffe000a5a22d4` | `0xfffffe000a5a2368` |

The byte-selector identities were checked over all 256 possible indices:

```text
x xor right[left[x] xor key] = constant

host_priv_self:       key 0x3e -> 0x54; index 0xf4a + 0x54 = 0xf9e
host_get_special:     key 0x32 -> 0xf9; index 0xeb4 + 0xf9 = 0xfad
RPC502:               key 0x98 -> 0x95; index 0xed9 + 0x95 = 0xf6e
RPC700:               key 0x32 -> 0xf9; index 0xec0 + 0xf9 = 0xfb9
```

The bank pointers and original table entries are independently read, rather than inferred from the PAC discriminator alone. A discriminator search produced other calls with the same immediate; those are not assigned these targets without a bank/table proof.

The predecessor at `0xfffffe000a60b7f8` loads X0 from `[X28+0x18]`, X1 from+`0x28`, X3/X4 from request-record+`0x10`/+`0x18`, W5 from request-record+`0x20`, and an inline output pointer from context+`0x98`. The two RPC call blocks preserve these input registers, compute W2 from a saved 32-bit word plus1, and pass the remaining output pointers through X6/X7 and four stack slots. X0 is a kernel port object here, not a task-local numeric name.

Under dispatcher W11=`0x8ea`, the request word at+`0x24` chooses the RPC variant: equality to1 selects block `0xfffffe000a60b820`/RPC502; other values select `0xfffffe000a60d334`/RPC700. This is the same word tested by the nearby host lookup when the declared common protocol holds. The receiver for RPC700 remains unknown; no matching ID700 server stub was found in the five inspected daemon tables. The subsequent [full callback routing recovery](daemon_receive_interface_report.md) additionally proves that700 falls outside every recovered callback range and returns locally without a reply send; this does not identify the actual alternate endpoint.

Local offsets tie acquisition output and RPC input to a `+0x18` field. The [subsequent scratch/cleanup recovery](kext_port_vm_report.md) separates the argument record from the typed scratch arena and proves a local post-RPC rejection route to `_ipc_port_release_send` at `0xfffffe000a615f2c`, loading that scratch field. Complete SSA/object identity across every predecessor, overwrite, publication and close path remains to be proved before claiming an end-to-end lifetime or total reference balance. The UserClient's per-client state pointer, the protected dispatcher frame, and the dispatcher-owned scratch arena remain distinct objects.

## Verification and outstanding work

```sh
python3 triage_evidence/resolve_kernel_collection_interfaces.py
python3 triage_evidence/prove_special_port_contracts.py
python3 triage_evidence/verify_interface_contracts.py
```

The resolver has O(B+N+F log F+P*G) time and O(B+N+F+P) space, with binary bytes B, nlist records N, decoded fixups F, pointer candidates P, and segments G. The four byte identities require 1,024 finite evaluations covering their complete 8-bit input domains. The two status equivalences use complete 32-bit SMT queries. Source-to-formula translation is manually audited against retained native instructions; these are not native execution or PAC-authentication checks.

| Impact | Newly established opportunity / remaining question |
| --- | --- |
| High | Exact kernel symbols and original fixup metadata now support resolving protected calls that the kext-only IDB leaves outside its segments |
| High | Slot17/34 acquisition and RPC502/700 caller sites replace earlier absence of local call-site evidence |
| High | Native launchd reports slot17 active for the exact universal daemon image; cross-block object identity and an actual RPC round trip remain the next proof obligations |
| Medium | Slot34 and the request word's origin may distinguish another environment or facility; meaning is unknown |
| Medium | The same PAC discriminator occurs at different calls, so discriminator equality is only a search aid |

QG1 factual analysis. QG2 assumptions/probes explicit. QG3 this increment covers original collection bindings, port lookup ABI, local RPC invocation and scope limits; the broad goal remains active. QG4 byte widths, unsigned arithmetic, indices and complexity are explicit. QG5 chain normalization, page-straddling pointers, namespace distinctions and conditional reachability are addressed. QG6 original collection symbols/bytes, extracted bytes, live snapshots, proof artifacts and reference source are distinguished. QG7 bounded findings listed above.
