# FPSD1200 VM certificate output and shared-callback port-construction boundary

The original FPSD1200 path reads the staged output OOL address/count, calls `vm_deallocate`, requests a new 719-byte VM allocation, copies the embedded daemon leaf DER into that private allocation and writes count 719 into the staged output. It then reaches `CFMachPortCreate` through the existing shared-callback helper. These are original source effects under explicit private VM return/pointer models. The output OOL address and returned-name cells remain unpublished at the subsequent CF boundary captured here; no native VM change, CF object, raw port right or completed successful reply is established. [VM1-VM8]

This continues the [certificate/inline-output report](fpsd1200_certificate_report.md), which already establishes the supplied CoreFP leaf public-exponent result in reply[68,196). The full daemon/kext/deeper-interface investigation remains active.

## Assumption register

| ID | Assumption / dependent results | Stress test / falsification probe |
| --- | --- | --- |
| VM1 | The pinned daemon slice, selected library and live IDA readback identify this source. Every address/fragment role depends on that identity. | Rehash selected source bytes and original pointer fixups; preserve thin-image versus whole-input hashes. Compare live IDA selected spans without mutating the IDB. |
| VM2 | Frozen admission, Security/CF, PID, startup, random/clock, PAC, pool/lock and scalar-atomic models supply the predecessor. All finite continuations depend on these premises. | Independently replay every original instruction, import event, CPU checkpoint, arithmetic record and terminal memory state. Native credentials, startup continuity and concurrency remain unknown. |
| VM3 | `vm_deallocate` is record-only with explicit return 0; target-task name 0x6600 is an explicit imported-data fixture. Control beyond the old boundary depends on that contract. | Verify actual three-argument values and immediate W0 overwrite; preserve the earlier unexecuted-call boundary. No native address validity, VM ownership or deallocation result follows from this model. |
| VM4 | VM allocation success supplies a disjoint private zero-filled 719-byte owner and writes its pointer into the original address temporary; failure 3 supplies no owner/pointer store. Allocation/output observations depend on these explicit effects. | Compare success/failure profiles, every original owner write/read and untouched backing bytes. Recheck API argument widths and flags against current SDK compilation. Native VM allocation is not exercised. |
| VM5 | The initial OOL output address is diagnostic A5 fill or zero; the stub-defined count is zero. Preallocation-address conclusions depend on those chosen inputs. | Change only the initial reply address, preserve original wrapper marshalling and inspect original staged-field loads/API arguments. Caller/receive-buffer initializedness and native cleanup behavior remain unknown. |
| VM6 | Certificate construction, typed limb codecs and private owner knownness have the retained meanings. DER/output claims depend on these byte representations. | Check every constructor store, full arithmetic result and exponent sequence; compare the VM owner byte-for-byte with independently recovered DER and track source write order. API-defined zero bytes are distinguished from CPU-written bytes. |
| VM7 | A staged count, private VM pointer, CF construction request and raw Mach right are distinct objects/effects. IPC/output interpretations depend on that distinction. | Monitor all output cells and exact helper arguments/context; trace CF-object return, raw-name extraction, registration and native emission separately. Shared callback identity alone does not prove live delivery. |
| VM8 | The finite matrix, independent replay/oracles and exact publication checks delimit this increment. Selected flattened fragments do not define complete C-function prototypes. | Reproduce all retained cases, matching source/fixup/bank checks and the pinned audit receipt. The receipt is evidence of completed replay, not a new replay when rehashed. Retain impact-ranked unresolved interfaces. |

## Provenance and retained interfaces [VM1,VM2,VM6,VM8]

| Primary object | Identity / relationship |
| --- | --- |
| Daemon arm64e slice | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base `0x100000000` |
| Live IDA metadata | Whole-input SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`; selected source-byte agreement is checked separately |
| Embedded daemon leaf | Original XOR-encoded source `0x100ee87f0`,723-byte constructor extent, four-byte prefix and 719-byte DER; DER SHA-256 `d43ca892b364466d885a38418b11469c2634ddcfe493ff3beda2f022edde4102` |
| Shared callback/helper | [Daemon receive analysis](daemon_receive_interface_report.md): helper `0x100001f50`, CF call `0x100001f8c`, callback `0x100425f78` |
| Framework receive context | [Installed-cache CF analysis](cf_receive_report.md): callback/receive/source contracts; actual native version, object identity and registration history remain separate premises |
| Current SDK | VM allocation/deallocation declarations, `VM_FLAGS_ANYWHERE`, task-self data and `CFMachPortContext`/create/callback declarations; compile-only arm64e width/layout/prototype checks |

Evidence: [source and finite profiles](triage_evidence/fpsd1200_vm_checks.json.zst), [live IDA/SDK attestation](triage_evidence/fpsd1200_vm_ida_readback.json.zst), [fresh replay receipt](triage_evidence/fpsd1200_vm_audit.json.zst), [producer](triage_evidence/recover_fpsd1200_vm.py), [independent auditor](triage_evidence/audit_fpsd1200_vm.py) and [publication verifier](triage_evidence/verify_fpsd1200_vm_publication.py). The IDA knowledge query returned an unrelated cross-version MIG correspondence; it supplies no evidence for this VM continuation. No IDB mutation or native target/API execution occurs.

## Preallocation output-cell reads and VM APIs [VM2-VM5,VM7]

The original wrapper packs its 14 arguments into a 104-byte staged payload P. Its OOL output-address cell P+72 copies the initial reply+28 value; P+80 copies the count scratch initially zeroed by the stub. The [request/reply contract](fpsd1200_contract_report.md) already distinguishes these reads from protected-output production. This continuation identifies their actual consumers.

| Original source | Actual data flow |
| --- | --- |
| `0x100400bc8`, `LDR X20,[X8]` | Reads eight bytes at P+72 into X20 |
| `0x100475dd4`, `LDR W2,[X1]` | Reads four bytes at P+80 into W2 |
| `0x10049e0f8`, `LDR W0,[X28]` | Reads explicit task-self u32 fixture 0x6600 |
| `0x10049e10c`, `MOV X1,X20` | Supplies the earlier staged address as VM deallocation argument1 |
| `0x10049e114` | Calls imported `vm_deallocate` with target task, staged address and old count |
| `0x10049e118`, `LDR W0,[X28]` | Immediately replaces the API's returned W0 with task-self data |
| `0x10049e170`, `ADD X1,SP,#0x4d0` | Supplies the original stack address temporary for allocation output |
| `0x10049e174`, `MOV W3,#1` | Supplies flags 1, independently equal to current SDK `VM_FLAGS_ANYWHERE` |
| `0x10049e17c` | Calls imported `vm_allocate` with extent 719 |

The immediate W0 load syntactically kills the deallocation return before any source instruction can inspect it. That local statement is independent of the modeled return's numerical value; it does not constrain native API memory effects or caller-clobbered state. The finite private model preserves other registers and memory.

| Imported API | SDK argument contract | Captured selected values |
| --- | --- | --- |
| `vm_deallocate` | `vm_map_t`, `vm_address_t`, `vm_size_t` | `0x6600`, initial staged address, `0` |
| `vm_allocate` | `vm_map_t`, `vm_address_t*`, `vm_size_t`, `int` | `0x6600`, original eight-byte stack temporary, `719`, `1` |

Compile checks establish four-byte port names and eight-byte VM addresses/sizes. X3..X7 on the deallocation call and X4..X7 on allocation are captured remnants outside those API argument contracts. The stack temporary is separate from P+72: writing the API result there does not publish the OOL address into the staged output.

## Original leaf-copy and count production [VM4,VM6,VM7]

On explicit allocation success, the model supplies private address `0x76000000` and initializes its 719 bytes to zero. This is an API fixture, not a CPU-store journal or observed native allocation. Original code subsequently overwrites every byte exactly once with the complete recovered DER. The private 1 MiB mapping is instrumentation capacity; its bytes beyond the 719-byte owner remain A5 backing fill.

| Copy source site | Stores per successful allocation | Original destination offsets |
| --- | ---: | --- |
| `0x10048d95c` | 7 one-byte stores | Leading executed tail-copy stores, descending718..712 |
| `0x100633d64` | 89 one-byte stores | Eight interleaved descending lanes, with the following seven PCs |
| `0x100633d70` | 89 | Same complete source-driven copy |
| `0x100633d7c` | 89 | Same complete source-driven copy |
| `0x100633d90` | 89 | Same complete source-driven copy |
| `0x100633da4` | 89 | Same complete source-driven copy |
| `0x100633db4` | 89 | Same complete source-driven copy |
| `0x100633dd0` | 89 | Same complete source-driven copy |
| `0x100633ddc` | 89 | Same complete source-driven copy |

The exact count is7+8*89=719 stores/bytes, with no duplicate destination offset. Final owner bytes match the 719-byte DER exactly, excluding the constructor's four-byte local prefix and its residual four-byte tail outside DER. This is copying of the existing embedded certificate, not a new signing operation.

Original `STR W10,[X1]` at `0x100543d3c` writes 719 to P+80. Original `free` at `0x1004a9ac8` retires the temporary723-byte certificate owner after copying. Root and AAA were already retired at their retained source sites. At the captured CF boundary, P+72 still holds the initial address and the returned-name cell P+100 still holds diagnostic seed bytes. Those uncommitted fields prevent interpreting the partial state as a completed successful reply or a native disclosure.

## Shared-callback CF construction request [VM2,VM7]

After certificate copy/count production, original code enters the already recovered helper `0x100001f50`. Its source zeros the complete 40-byte `CFMachPortContext` and a one-byte Boolean, constructs the logical callback pointer `0x100425f78`, and calls `CFMachPortCreate` at `0x100001f8c`.

| Argument/context field | Captured value | Established meaning |
| --- | --- | --- |
| X0 allocator | `0` | Null/default allocator argument |
| X1 callout | `0x100425f78` | Shared daemon Mach callback; PAC operation is explicitly bypassed in private execution |
| X2 context | Pointer to source-defined40-byte stack record | Version 0, info 0, retain 0, release 0, copyDescription 0 |
| X3 shouldFreeInfo | Pointer to source-defined zero Boolean | In/out API flag cell; no returned flag is modeled |
| API return | Unknown | No CF object or raw Mach name is supplied at this boundary |

The current SDK establishes context offsets0,8,16,24,32 and callback prototype `(CFMachPortRef, void*, CFIndex, void*)`. The helper returns a CF object when the API succeeds; a raw port-name producer requires a later extraction/ownership trace. Existing [framework receive analysis](cf_receive_report.md) and [daemon registration analysis](daemon_registration_report.md) describe shared-callback source/receive contracts, while [created-port analysis](created_port_report.md) concerns a separate registration/arcade route. Shared helper/callback addresses do not equate their service identity or traffic.

```text
staged prior OOL address/count -- vm_deallocate boundary/model
                                      |
                            vm_allocate(719, ANYWHERE)
                                      |
                        private owner receives leaf DER
                                      |
                          staged count 719; free temp
                                      |
                            shared CFMachPort helper
                                      |
                      CFMachPortCreate request [stop]
                                      |
                   CF object, raw name, registration unknown
```

## Allocation failure and Mach-role separation [VM3-VM7]

With the same inputs and explicit allocation return3, no VM owner or pointer output is supplied. Original code retires the temporary leaf at `0x1004a9ac8`, restores the selected pool marker to `0x4577df49`, returns application status `0xffff5bd4` (signed32 -42028), and formats a 36-byte error reply. Original input retirement reaches `mig_deallocate` at `0x10000468c` with the 756-byte input extent. The earlier 128 inline result stores have already occurred, but those bytes lie outside this36-byte reply format. No CF construction request occurs on this failure continuation.

This error equals the earlier first-certificate-allocation NULL status; equality of scalar status does not establish a shared high-level error name or a native failure. The staged104-byte payload remains byte-identical to its entry state in this case, including count 0, while the inline result remains separately produced. All three certificate owners are retired in the private API journal.

| Object / role | Original producer or consumer | Current evidence limit |
| --- | --- | --- |
| Incoming application name | Request+12, retained MIG call at `0x10000467c` | Fixture0x1400, without native right identity |
| Reply destination | Retained request+8/header formatting | Fixture0x6400, without a new message send |
| VM target-task argument | Imported task-self reads at `0x10049e0f8` and `0x10049e118` | Explicit u32 name 0x6600; no object/namespace identity |
| Private OOL backing | VM pointer-output fixture at `0x10049e17c`, followed by original 719-byte copy | Defined private certificate bytes; no native VM mapping |
| Staged OOL count | Original store at `0x100543d3c` |719 on success; address publication still pending |
| CF port-construction request | Original API call at `0x100001f8c` | Shared callback/context established; API result unexecuted |
| Returned Mach-name cell | Staged P+100 | Retains seed bytes at the captured success boundary |
| Daemon reply emission | Existing callback send at `0x100035184`, documented separately | Not reached by these continuations; no new native emission observed |

The existing [CF source analysis](cf_receive_report.md) resolves its selected cached `CFMachPortCreate` body as receive-right allocation, send-right insertion and CF-object creation. That is retained library-specific source evidence, not a new runtime observation or proof that this daemon uses that exact native library instance. This turn establishes the original daemon-to-API edge and its local data, while native right creation/emission locations remain outside the executed private continuation.

## Finite matrix, source coverage and reproduction [VM1-VM8]

| Profile | Initial staged OOL address | Allocation result model | Original visits | Endpoint |
| --- | --- | --- | ---: | --- |
| `allocation_success` | `0xa5a5a5a5a5a5a5a5` |0 plus private owner/pointer output |10092649 | Unexecuted `CFMachPortCreate` |
| `allocation_failure` | Same A5 seed |3 without owner/pointer output |10089151 | Original 36-byte error reply, status `0xffff5bd4` |
| `zero_address_success` |0 |0 plus the same private owner contract |10092649 | Same original instruction sequence and CF boundary as the first profile |

The initial-address control changes the actual staged load and the deallocation address argument; it does not remove the deallocation call or change the original instruction sequence. Allocation success/failure holds that address premise fixed. All cases retain the same explicit task-self name and deallocation return model. The earlier [certificate report](fpsd1200_certificate_report.md) preserves the stop-before-VM control; this increment does not replace it with a completed native call.

| Coverage | Exact extent / boundary |
| --- | --- |
| Original instruction visits |30274449:30274392 daemon and 57 selected-library visits |
| Original source catalog |843 spans,39665 distinct four-byte instructions /158660 bytes; full76-byte helper is additionally source/IDA checked |
| Original pointer records |1124 rebases and 30 bind records, independently decoded |
| Import events / returned replies |120 / one 36-byte error return; no completed212-byte reply |
| VM owners / CPU stores / CPU reads | Two 719-byte private owners /1438 one-byte stores /0 reads |
| Inline result / staged count stores |384 original inline stores and two original count stores,386 monitored output stores total |
| Staged output-cell reads |13, including original wrapper copy-back on the error return |
| Public arithmetic |282 full Montgomery calls, nine complete exponent sequences; two independent public certificate-signature relations |
| External DER reads |6963 events; retained exact reference input and extension bytes |
| Adjacent-bank checks |17 exhaustive identities,4352 byte inputs,12746 observed pair uses;105 unpaired reads remain observations |
| SDK compile | Five primary headers; arm64e VM widths/prototypes/flags and 40-byte CF context layout; compile-only exit0 |

| Selected bind | Original slot / encoded word | Recovered import |
| --- | --- | --- |
| VM allocation | `0x10109ffe8` / `0xc008a49900000088` | `libSystem/_vm_allocate`, authenticated IA, discriminator `0xa499` |
| VM deallocation | `0x1010a00f8` / `0xc008389300000083` | `libSystem/_vm_deallocate`, authenticated IA, discriminator `0x3893` |
| CF construction | `0x1010b1c40` / `0xc0090000000000ae` | `CoreFoundation/_CFMachPortCreate`, authenticated IA with address diversity |

The independent auditor never imports the VM producer. It replays original bytes through the frozen predecessor oracle and independently handles VM owner creation, pointer-cell writes, knownness, owner read/write journals, output-cell reads and CPU checkpoints. It compares all earlier constructor/arithmetic records and terminal registers, stack, globals, private backing and retained owner contents. The scalar atomic/PAC/API models remain explicit; successful replay is not native API or hardware validation.

The publication verifier additionally joins every VM store to the recovered DER, every inline result store to the checked public-exponent result, all staged output changes to their original locations, and the CF request to its source-defined callback/context. It checks exact manifest ownership, original input preservation, pinned source/dependency/auditor/receipt hashes and analyst-path absence. Substantial JSON is archived using Zstandard ultra22 and exact decompression comparison. Rehashing the fresh-replay receipt does not itself perform another instruction replay.

```sh
env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/audit_fpsd1200_vm.py

env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_fpsd1200_vm_publication.py
```

Finite replay/observer work is O(B+F+V+E+L) for selected source bytes B, fixups F, original visits V, recorded events E and active limb bytes L, excluding big-integer arithmetic costs. A 719-byte copy has719 CPU stores:7+8*89. Modular arithmetic uses explicit32-bit limb and 64-bit address widths. Replay memory is bounded by the private image/owners and one decoded profile; publication hashing adds O(manifest entries + owned bytes) work. These are instrumentation/evidence bounds, not native target timing or whole-program complexity claims.

## Bounded continuation opportunities [VM2-VM8]

| Impact | Question / next discriminating evidence |
| --- | --- |
| High | Continue the original CF-object return, raw-name extraction, slot association, source registration and output-address publication under separately declared object/port contracts. The current stop supplies neither a CF object nor a raw right. |
| High | Recover actual publication of P+72 and P+100, remaining scalar/deallocation fields, final status and successful client parsing; keep locally produced certificate/inline bytes distinct from complete transport delivery. |
| High | Join native daemon initialization, library instance, credentials, task/port namespace and request/reply evidence to the kext/provider interfaces. The task-self scalar and shared callback do not establish those identities. |
| Medium | Resolve existing-output initialization/lifetime and native VM result handling independently of diagnostic initial fill. The zero-address case tests one local dependency without proving caller or receiver semantics. |
| Medium | Compare the selected CF creation path with the retained named registration and arcade helper callers; establish service identity from object/name data, not shared source addresses. |
| Low | Extend the selected byte-copy fragment's size/aliasing contract beyond this complete 719-byte DER copy; the current evidence does not define a general memcpy prototype. |

**QG1** passes: factual source, ABI and finite-state observations. **QG2** passes: VM1-VM8 declare assumptions, dependent conclusions and falsification probes. **QG3** passes for this increment; the complete multi-level investigation remains active. **QG4** passes: widths, byte extents, signed32 status, exact store counts, modular arithmetic and finite cost are explicit. **QG5** passes within scope: failure versus partial success, API-created versus CPU-written bytes, seeded versus published outputs and native versus private effects remain distinct. **QG6** passes: original bytes/fixups, independently recovered DER, live IDA, primary SDK compilation and fresh replay/oracles supply separate provenance. **QG7** passes: bounded continuation questions carry explicit impact labels.
