# Original startup, constructor and hardware-AES boundary

Original `cmam7f` execution now supplies the constructor's table, mask and locks without setting the protected bridge's warm byte. A memory-preserving caller transition to original `fcHfFIGhsx` reaches lazy `IOAESAccelerator` discovery and then `_performHWAESOnGlobalBuffer`. Execution stops before the nominal provider's `performAES` body. Four alternative discovery/descriptor/hardware-result models return `0xffff5bea` before either daemon RPC. This establishes an original-instruction startup/constructor composition under explicit external API premises; native execution, hardware success and the complete daemon exchange remain unknown. [HB1-HB8]

```text
cmam7f original startup
  -> table[512 B], base, mask=255, locks, ready=1, bridge-warm=0
  -> original return 0
  -> declared caller transition preserving RAM/BSS/FP/resource state
fcHfFIGhsx original entry
  -> FPAESParameters[104 B]
  -> serviceMatching("IOAESAccelerator", NULL)
  -> waitForService(dictionary, {0 s, 1 ns})
  -> retain -> descriptor(81920 B) -> prepare -> getBytesNoCopy
  -> copy IV[16 B] and data[32 B]
  -> _performHWAESOnGlobalBuffer -> performAES entry [STOP]
                                      |
                   modeled result 4 --+--> cleanup -> return 0xffff5bea

No host-special-port acquisition, RPC502 or RPC700 occurs in these cases.
```

The [source capture](triage_evidence/kext_startup_hardware_bridge_source.json) contains seven original ranges / 2015 instructions, nine original pointer slots, two typed views and the local SDK timespec declaration hash. [Profiles](triage_evidence/kext_startup_hardware_bridge_profiles.json) retain one original startup/constructor composition and four exact startup-produced forks. [Independent replay and oracles](triage_evidence/kext_startup_hardware_bridge_checks.json), [preservation](triage_evidence/kext_startup_hardware_bridge_delivery.json) and [quality gates](triage_evidence/kext_startup_hardware_bridge_quality_gates.json) distinguish source behavior from modeled effects. No IDB was required or modified. The [RAX trace report](zut_trace_report.md) remains a separate historical run ending with failed UserClient open; these private CPU compositions do not extend that trace.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| HB1 | The preserved kernel collection supplies the analyzed kext and nominal kernel/provider implementations. All source and pointer bindings depend on this image. | Rehash the original collection and normalized kext; recapture every covered instruction and all nine raw chained pointers. A runtime UUID/slot mismatch invalidates application to that runtime. |
| HB2 | A caller invokes the constructor after startup returns, retaining its memory and resource epoch. The composition is an explicit caller model, not a recovered native caller sequence. | Replay the original startup afresh; compare RAM, BSS, scalar/FP state and resource snapshot at the transition. Capture the native caller and its allocator/stack epoch to establish runtime continuity. |
| HB3 | Kernel task/map objects, page shift 14, filename and disjoint private allocator results are environmental fixtures. Allocation/alignment and observed residue depend on them. | Inspect actual runtime globals and allocator lifetimes; vary these premises in a separately owned experiment. The source rounding formula is covered by the earlier constructor report. |
| HB4 | Matching dictionary, service, descriptor, retain, prepare and buffer-address results are declared API outcomes. Positive discovery is conditional. | Compare real registry class, runtime vptr and API outcomes with the nominal slots. Original waiter ownership/release operations are not executed by the API model. |
| HB5 | Logical PAC operations retain decoded pointers and source modifiers; no hardware authentication is performed. All indirect continuations are conditional on authentic pointers. | Check original slot, format, key, diversity and address-diversity, then match actual runtime vptr/PAC state. A discriminator alone does not establish the callee. |
| HB6 | The same caller SP is reused after startup; source-produced stack bytes are retained. The finite error-output value depends on this epoch. | Independently replay the last startup writer and constructor read/store; change caller stack epoch to test whether the value changes. No native user-visible disclosure is established. |
| HB7 | The hardware-error variant supplies result 4 without executing AES. This proves only the original nonzero-result continuation. | Obtain authentic provider completion/result and output bytes. No successful AES result or cryptographic output is supplied in this increment. |
| HB8 | The historical RAX trace, analyzed daemon and collection are distinct evidence epochs; native pairing remains unknown. | Match runtime UUID/build, credentials, registry identity, ports and message payloads in one captured exchange. Reusing numeric port names across tasks/epochs is insufficient. |

## Initialization flags and resource epoch

| Cell | Established role | Source writer / current state |
| --- | --- | --- |
| `0xfffffe000cccea88` | Protected table/subsystem ready byte | Startup stores 1 at `0xfffffe000a627d10`, after the 512 table bytes. |
| `0xfffffe000ccca078` | Protected bridge warm byte | Startup stores 0 at `0xfffffe000a607218`; remains 0 through every current boundary. |
| `0xfffffe000ccceb00` | Exact nlist `gAESAccelatorProviderInitialized` | `_initKernelAESHW` reads bit 0; successful modeled discovery/prepare stores 1 at `0xfffffe000a5081a8`. |
| `0xfffffe000ccceb08` | Exact nlist `gAESAcceleratorProvider` | Non-NULL modeled wait result stored at `0xfffffe000a508084`. |
| `0xfffffe000ccceb10` | Exact nlist `gAESAcceleratorIOBMD` | Allocator result stored at `0xfffffe000a5080dc`, including NULL. |
| `0xfffffe000ccc7848` | Obfuscated global `_T68NEoIlLOBwWkdF06PuGk48xiiehGZrfj`: hardware buffer address in this path | `getBytesNoCopy()` result stored at `0xfffffe000a508178`. This establishes the observed role, not every use of the global. |

These are separate readiness predicates. A successful startup return does not set either hardware-initialized or bridge-warm state. The earlier [provider initializer report](kext_provider_initialize_report.md) already establishes table construction and its consumer bound; the present composition retains those actual bytes. Its startup prefix contains 6866591 original source visits and 21 external API models. Four branches restore byte-identical 1 MiB private RAM and 65536 B BSS, FP state, allocator cursor and six distinct lock objects from this source-produced snapshot. They do not reconstruct a guessed table or owner. [HB1-HB5]

The constructor obtains the startup lock modeled at `0x6500082200`, published through cell `0xfffffe000cccda78` in the prior initializer evidence. Its lock call returns to `0xfffffe000a5b421c`. The positive AES boundary still holds this lock; each four-error continuation unlocks it before return, with unlock returning to `0xfffffe000a5bfe88`. These are model ownership checks on original operation requests; native exclusion and reference balance remain unknown.

## Discovery and exact nominal bindings

All addresses below are original collection VAs. Virtual offsets are relative to nominal vptrs, not vtable symbols. `IOAESAccelerator` vptr is `0xfffffe0008588380`; `IOBufferMemoryDescriptor` vptr is `0xfffffe0007f85d80`. Runtime object identity is a premise. [HB1, HB4, HB5]

| Original call / slot | Exact target and contract |
| --- | --- |
| Call `0xfffffe000a508070`; import slot `0xfffffe000847c458` | `0xfffffe000c4ece88`, `IOService::serviceMatching(char const*, OSDictionary*)`; literal at `0xfffffe000790ba3c`, second argument NULL. |
| Call `0xfffffe000a508078`; slot `0xfffffe000847c450` | `0xfffffe000c4eb5d8`, `IOService::waitForService(OSDictionary*, mach_timespec*)`; timeout bytes `0000000001000000`. |
| Provider vptr+0x20; slot `0xfffffe00085883a0` | `0xfffffe000c445200`, `OSObject::retain() const`; original auth diversity `0x2e4a`. |
| Import slot `0xfffffe000847c428` | `0xfffffe000c526070`, `IOBufferMemoryDescriptor::inTaskWithOptions(task*, unsigned int, unsigned long, unsigned long)`; task=`kernel_task`, options `0x13`, capacity 81920 B, alignment 16384 B under shift 14. |
| Descriptor vptr+0x218; slot `0xfffffe0007f85f98` | `0xfffffe000c5353b4`, `IOGeneralMemoryDescriptor::prepare(unsigned int)`; argument 0, diversity `0xf5b3`. |
| Descriptor vptr+0x308; slot `0xfffffe0007f86088` | `0xfffffe000c524b60`, `IOBufferMemoryDescriptor::getBytesNoCopy()`; diversity `0xf4f4`. |
| Provider vptr+0x890; slot `0xfffffe0008588c10` | `0xfffffe000abff358`, exact `IOAESAccelerator::performAES(...)`; diversity `0x17dc`. Execution stops before its body except the declared nonzero-result model. |
| Import slot `0xfffffe000847c608` | Exact `_kernel_task` cell `0xfffffe0007f8b0a0`; runtime object is modeled. |
| Import slot `0xfffffe000847c5b0` | Exact `_PAGE_SHIFT_CONST` cell `0xfffffe0007e6d9c0`; original file word 0, explicit runtime fixture 14. |

The seven function slots have original chained-pointer format 8, auth=1, key=0/IA, address-diversity=1. The two data-cell pointers are unauthenticated. Four data-pointer `AUTDA X16,X17` steps at `0xfffffe000a508094`, `0xfffffe000a5080f0`, `0xfffffe000a50815c` and `0xfffffe000a5084c4` are separately recorded as logical operations; they are not hardware PAC evidence.

The timeout is `{u32 tv_sec=0, i32 tv_nsec=1}`: `0 s * 10^9 ns/s + 1 ns = 1 ns`. Original waiter instructions `0xfffffe000c4eb5f0..0xfffffe000c4eb604` load the two 32-bit words, sign-extend nanoseconds and calculate the internal nanosecond argument. This independently reuses the [cold-init timeout conclusion](kext_cold_init_report.md), with no new SDK compilation. The original waiter also requests releases for the dictionary and a non-NULL result; those operations are outside the modeled call and do not establish live reference ownership.

## Actual global-buffer AES handoff

This constructor path uses `_performHWAESOnGlobalBuffer` at `0xfffffe000a508484`, with provider call at `0xfffffe000a5084f0`. It does not use the separate copied-descriptor `_performHWAES` wrapper. Original protected execution copies 16 B from `FPAESParameters+0x12` to its IV frame and 32 B into the global buffer. Disjoint private `memcpy` effects are checked against source bytes at each independent replay call boundary. See the earlier [four-wrapper AES ABI](kext_aes_handoff_report.md) for the static family.

| ABI location | Observed value at `performAES` entry |
| --- | --- |
| X0 | Modeled nominal provider object |
| X1, X2 | Same modeled memory descriptor, input and output |
| X3 | 32 B |
| X4 | Private IV pointer; 16 zero bytes in the retained cases |
| W5 | 0 |
| X6 | Private opaque `IOAESKeyData*`; contents/meaning remain unknown |
| X7 | Offset A = 0 |
| SP+0 | Offset B = 0, 64-bit |
| SP+8 | Completion callback NULL |
| SP+16 | Completion context NULL |
| LR | `0xfffffe000a5084f4` |

The all-zero IV is an observation for these source/fixture inputs; it is not a universal cryptographic contract. No AES result 0, output ciphertext/plaintext, native device operation or successful context token is produced. [HB3-HB7]

## Five independently replayed cases

| Variant | Original source visits | Outcome | Final hardware flag / provider / descriptor / buffer |
| --- | --- | --- | --- |
| Original startup + nominal discovery | 6869363 = 6866591 startup + 2772 constructor | Stops before `performAES`; caller output remains eight `a5` bytes | 1 / non-NULL / non-NULL / non-NULL |
| Absent service | 2809 constructor visits from exact startup snapshot | Original constructor returns `0xffff5bea` | 0 / NULL / NULL / NULL |
| Descriptor NULL | 2838 | Same constructor result | 0 / non-NULL / NULL / NULL |
| Prepare result 4 | 2880 | Same constructor result | 0 / non-NULL / non-NULL / NULL |
| Hardware method result 4 | 4013 | Same constructor result after declared external error | 1 / non-NULL / non-NULL / non-NULL |

Total: 6881903 original source visits. Every case retains ready=1, bridge-warm=0 and registry head NULL. These prefixes do not allocate/publish `KBCryptShared`, a `KBCrypt` owner or an `FPAppSecurityInfo` child. Each error continuation requests typed release of the 104 B parameters, arena release and aligned frame release. Freed memory is retained by no-effect models; native deallocation/retention is unknown. Hardware-initialized remains 1 after the modeled hardware error, while bridge-warm remains 0: initialization and operation success are distinct predicates.

## Constructor status and output are distinct channels

The source error epilogue is unconditional with respect to its subsequent status test:

```text
0xfffffe000a66ab54  LDR W27, [X20,#0x14]  ; encoded status
0xfffffe000a66ab58  LDR W8,  [SP,#0x48]   ; 32-bit output slot
0xfffffe000a66ab5c  LDR X9,  [SP,#0x38]   ; caller output pointer
0xfffffe000a66ab60  STR X8,  [X9]         ; zero-extended 32-bit word, 8 B store
```

In this retained stack epoch, the slot is `initial_SP-0x88`. Startup's store at `0xfffffe000a5a3998`, source visit index 51, writes `0xfffffe000794a0d0` there. No constructor-phase write overlaps the four bytes read at `0xfffffe000a66ab58` on any current path. All four failure returns therefore store `d0a0940700000000` to the caller output location while returning u32 `0xffff5bea` (signed i32 -42006). This is source-produced stack residue copied through a local kernel-side ABI under HB2/HB6. It is not a generated context token; native stack reuse, callers' handling of failed outputs and any user-visible propagation remain unknown. The earlier unchanged output canaries were measured before this epilogue and do not contradict this later write.

## Reproduction and evidence bounds

Run the three producers/validator sequentially with the existing pinned environment:

```sh
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kext_startup_hardware_bridge.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kext_startup_hardware_bridge.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kext_startup_hardware_bridge.py
```

No new SMT query is used; Z3 remains an import dependency of frozen utilities. Complexity is O(source visits + effects + image bytes), with O(unique PCs + retained critical effects + fixed private RAM) space. Each fresh replay decodes/compares original code, independently executes source instructions and verifies five streaming event fingerprints, declared API arguments/clobbers, source-byte copy models, final RAM/BSS, all tracked flag/output reads/writes and lock states. Source fingerprints do not substitute for native IOKit, hardware authentication or IPC execution. No original input, IDB or memory file is modified. The historical RAX producer executable/configuration and matching native daemon/kext/hardware epoch remain unknown.

| Independent replay check | Count |
| --- | --- |
| Original source visits | 6881903 |
| Source read / write events | 1067034 / 286965 |
| Logical authenticated indirect edges / recorded indirect calls | 254092 / 2793 |
| Declared external API models | 87 |
| Explicit model memory effects / written bytes | 13 / 164 B |
| Source-byte memcpy checks | 4 |
| Logical data authentication steps / other logical PAC steps | 11 / 107 |
| Parent critical effects / bridge effects / bridge reads | 167 / 21 / 29 |
| Original wrapper returns / final boundaries | 5 / 5 |
| Source-produced startup snapshot / memory-preserving caller transition | 1 / 1 |

The read/write and indirect-edge/call categories have their explicit stream definitions in the frozen replay code; the call stream covers recorded authenticated indirect calls, not every direct `BL`. The four component forks count constructor visits only; the startup prefix is counted once.

## Bounded continuation

| Impact | Remaining interface question | Evidence needed to resolve it |
| --- | --- | --- |
| High | Hardware preparation is a predecessor of the RPC bridge; bypassing its warm byte loses provenance. | Continue the exact source-produced state through an authentic provider result/output contract, then trace the bridge-warm store and original RPC caller. |
| High | Actual provider object and command-gate/queue ownership are unestablished. | Match live class/vptr to the pinned nominal slots and recover documented/native descriptor and completion ownership. |
| High | Constructor success, token publication and page/close identity remain disconnected from this hardware frontier. | Track one original owner/child identity through success output, registry insertion, page consumer and retirement; keep native effects separate. |
| Medium | Error status can coexist with an output write; the current output contains retained stack bytes. | Recover each source caller's status guard and output consumption, then establish its native stack epoch before drawing propagation conclusions. |
| Medium | Six startup lock objects survive, and hardware preflight retains one. | Recover complete serialization and lifecycle requests across hardware success/failure and provider teardown; no native lock-balance claim follows from this prefix. |
| Low | The timespec's 1 ns can be misread as 1 s. | Preserve the raw eight bytes and original kernel conversion in all later environment models. |

## Quality gates

- QG1: Factual source, ABI and evidence analysis; no normative conclusion required.
- QG2: HB1-HB8 list premises, dependent claims and explicit falsification probes.
- QG3: This increment covers source-produced startup/constructor continuity, discovery bindings, active-lock boundary and four error/output continuations. The broad interface objective remains active and incomplete.
- QG4: Fixed-width loads/stores, byte extents, signed status and dimensional timeout calculation are explicit; no timing measurement or hardware error bound is inferred.
- QG5: Ready/hardware/warm flags, retained-stack output versus token, frontiers versus complete returns, and source/API/native epochs are distinguished. Unknown continuations are not asserted as established.
- QG6: Original file hashes, source words, raw chained slots, exact nlist names, SDK hash, source-produced snapshots and independent replay/oracles support the scoped claims.
- QG7: The continuation table bounds additional questions and labels their impact.
