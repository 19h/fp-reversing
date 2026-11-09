# FairPlayIOKit to IOAESAccelerator: descriptor and command handoff

Four kext wrappers call the descriptor overload of `IOAESAccelerator::performAES` through provider vptr +0x890. Original instructions establish eight register arguments and three stack arguments, including the completion fields omitted from the supplied decompilation. Matching IOCryptoAcceleratorFamily source builds a command carrier and routes queued work through a command gate. Separately, byte-bank recovery identifies one actual cleanup call site at `0xfffffe000a6227b4`.

[Original contracts](triage_evidence/kext_aes_handoff_contracts.json), [retained wrapper profiles](triage_evidence/kext_aes_handoff_profiles.json), [distinct fresh replays](triage_evidence/kext_aes_handoff_replays.json), [independent checks](triage_evidence/kext_aes_handoff_checks.json), and [local proofs](triage_evidence/kext_aes_handoff_proofs.json) support this increment. It extends the [descriptor lifecycle](kext_buffer_report.md) and [cold initialization](kext_cold_init_report.md) reports. Source addresses are unslid; modeled object addresses are private fixtures. All structure offsets are bytes. Native provider execution, key-data contents and accepted operations remain unproved.

```
kext wrappers
  -> nominal IOAESAccelerator::performAES
       +-- immediate branch, conditional
       `-- queued branch
            -> IOCommandPool::getCommand(true)
            -> command fields: descriptors, length, IV, operation,
               opaque key-data pointer, offsets, callback, context
            -> IOCommandGate::runAction(action, command, 0, 0, 0)
                 -> queue processing
                 -> callback absent: commandSleep(command, 0)
                 -> completion: complete both descriptor roles
                      +-- callback present: return command, invoke callback
                      `-- callback absent: commandWakeup(command, false)
```

This diagram describes static source interfaces and conditional branches. Provider implementation, command processing, waits, callbacks and descriptor effects are not executed. The kext fixtures execute original wrapper instructions under explicit result models. No additional daemon Mach port identity or message emission is established in the examined paths.

## Source identity and bounds

| Source | Verified identity / coverage |
| --- | --- |
| Normalized kext | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original kernel collection | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Compiler function catalogs | 450 starts for FairPlayIOKit; 106 for IOCryptoAcceleratorFamily |
| Recovered fileset functions | 6 kext functions, including the cleanup caller; 7 IOCryptoAcceleratorFamily functions |
| Further kernel bodies | `withBytes`, the unnamed buffer target, command-gate `runAction`, command-pool `getCommand` |
| Associated C | Original SHA-256 `dfb28b99b293db95a78a5d2dd20f6fcf1a95f1a53245b99a090370e7a3327f08`; cleanup-caller excerpt pinned at lines 189217-189240 |

Compiler bounds come from each original fileset's `LC_FUNCTION_STARTS`, independently of IDA fragment labels. Exact original bytes match all six normalized-kext functions. Thirteen fileset functions, four kernel functions and fifteen nominal vtable slots are checked. Fourteen slots have exact symbols; the remaining buffer target has an SDK-correlated method role, as distinguished below. All source results depend on H1; execution results also depend on H2-H5.

## Provider method and complete call ABI

The nominal provider vtable symbol is `__ZTV16IOAESAccelerator` at `0xfffffe0008588370`; its vptr is symbol +16. Slot `0xfffffe0008588c10` (+0x890) points to `0xfffffe000abff358`, exact symbol:

```
__ZN16IOAESAccelerator10performAESEP18IOMemoryDescriptorS1_yP7IOAESIV14IOAESOperationP12IOAESKeyDatayyPFvPviES7_
```

The included `AppleS8000AESAccelerator` nominal vtable uses the same +0x890 target. This identifies an inherited method in that candidate class; it does not identify the runtime object returned by service matching. Original format-8 pointer-chain membership, authentication metadata and diversity `0x17dc` are verified for both entries. Hardware PAC acceptance remains unknown.

| Position | Machine location at provider call | Role |
| --- | --- | --- |
| Implicit receiver | X0 | Provider pointer |
| 1 | X1 | Input `IOMemoryDescriptor *` |
| 2 | X2 | Output `IOMemoryDescriptor *` |
| 3 | X3 | u64 length value L |
| 4 | X4 | `IOAESIV *`, opaque |
| 5 | Low32 of X5 | `IOAESOperation`; original provider stores/uses a 32-bit operation |
| 6 | X6 | `IOAESKeyData *`, opaque contents |
| 7 | X7 | u64 offset A |
| 8 | `[SP+0]`, 8 bytes | u64 offset B |
| 9 | `[SP+8]`, 8 bytes | Completion function pointer, type `void (*)(void *, int)` |
| 10 | `[SP+16]`, 8 bytes | Completion context pointer |

The provider's prologue loads the three stack words from the incoming stack. Offset roles A/B follow their association with the two descriptor roles in the command carrier; their downstream interpretation and native range constraints are not completely recovered here. The copied wrapper ties L to the byte counts of `withBytes` and the SDK-correlated `readBytes` call. Other wrappers forward their numeric length as shown below.

## Four wrapper mappings

Let P be the provider global `0xfffffe000ccceb08`, D the descriptor global `0xfffffe000ccceb10`, and A0..A7 the wrapper's incoming X0..X7. `u32(x)` denotes truncation to 32 bits, followed by zero-extension where placed in X registers.

| Wrapper / provider call | Provider X1, X2 | X3 length | X4 / X5 / X6 | X7 / stack offset B / callback / context |
| --- | --- | --- | --- | --- |
| `performHWAES`, entry `0xfffffe000a5081b0`, call `0xfffffe000a508290` | Temporary descriptor T, T | `u32(A4)` | A1 / A5 / A0 | 0 / 0 / 0 / 0 |
| `performHWAESOnBuffer`, entry `0xfffffe000a5083d8`, call `0xfffffe000a508440` | D, D | `u32(A2)` | A1 / A3 / A0 | 0 / 0 / 0 / 0 |
| `performHWAESOnGlobalBuffer`, entry `0xfffffe000a508484`, call `0xfffffe000a5084f0` | D, D | `u32(A2)` | A1 / `u32(A3) XOR 1` / A0 | 0 / 0 / 0 / 0 |
| `performAESonIOMD`, entry `0xfffffe000a508534`, call `0xfffffe000a50859c` | A0, A1 | A2, full64 | A3 / A4 / A5 | A6 / A7 / 0 / 0 |

Every call obtains X0 from P. X5 is copied at full register width in three wrappers, while the provider consumes its operation as 32 bits. The global-buffer wrapper explicitly writes W5, so it zero-extends the XOR result. XOR 1 toggles bit 0 and preserves other low32 bits; it is not a general logical negation.

The supplied C body presents `performHWAES` with five parameters, the two shared-buffer helpers with none, and `performAESonIOMD` with two. Original use of incoming registers establishes six, four and eight arguments respectively for these examined call contracts. The complete public mangled name of `performAESonIOMD` corroborates the eight-argument form. No key or IV bytes are reconstructed; only opaque pointer movement is established.

The copied wrapper tests P for null and calls initialization only when P is null. The other three wrappers directly load the provider, and the two shared-buffer wrappers directly load D. No wrapper readiness-byte read occurs in the fresh runs. These are local source preconditions; valid native global-state combinations and caller synchronization remain unknown.

## Temporary descriptor and copy-out lifecycle

`performHWAES` passes A2, `u32(A4)`, direction 3 and contiguous flag false to `IOBufferMemoryDescriptor::withBytes`. Stub `0xfffffe000a69f204`, slot `0xfffffe000847c430`, resolves exactly to `0xfffffe000c526570`, symbol `__ZN24IOBufferMemoryDescriptor9withBytesEPKvmjb`. The model records these arguments without allocating native memory or copying A2.

| Outcome in the original wrapper | Requested sequence after the initial status check | Raw wrapper X0 |
| --- | --- | --- |
| Initialization result -40, declared model | No temporary descriptor request | `0xffffffd8` |
| Temporary descriptor null | `withBytes` only | `0xffffffd8` |
| Provider returns nonzero W0 | Provider, release T | `0xffffffea` |
| Provider W0 = 0; prepare returns nonzero W0 | Provider, prepare(0), release T | `0xffffffea` |
| Prepare W0 = 0; copy count differs from requested count | Provider, prepare(0), copy-out, complete(0), release T | `0xffffffea` |
| Copy count exactly matches | Provider, prepare(0), copy-out, complete(0), release T | 0 |

All rows include `withBytes` where applicable. Provider calls precede the wrapper's own prepare/copy-out/complete sequence. This does not assert that the provider lacks its own preparation: its retained source has preparation and completion paths for both descriptor roles, even when the caller supplies the same descriptor twice.

The copy-out call uses T, offset 0, destination A3 and count `u32(A4)`. Nominal buffer vptr +0x208 resolves to `0xfffffe000c5361d4`, but this target has **no exact symbol** in the matching source symbol tables. An arm64e compile-only SDK probe of `IOMemoryDescriptor::readBytes` emits virtual offset 520 (`0x208`) and PAC diversity 64512 (`0xfc00`), matching the original call. Its method role is therefore SDK-correlated rather than an exact-symbol identification. Original code compares the full64 returned count against the zero-extended requested count.

The wrapper ignores declared nonzero completion and release returns. These observations concern source control flow under result models; no physical preparation, copied output, successful crypto, native release or accepted protected operation is established. Raw `0xffffffea` and `0xffffffd8` mean signed32 -22 and -40; they are not sign-extended negative u64 values.

## Provider command carrier and queued completion

The following is a partial source-established command layout, not a complete original C structure. Provider policy checks and key-data internals are not emulated.

| Command offset | Width | Source-established value or use |
| --- | --- | --- |
| +0x10, +0x18 | 8 each | Queue-link fields written by `_queueLocked` |
| +0x20, +0x28 | 8 each | Input/output descriptor pointers |
| +0x30 | 8 | Length L |
| +0x38 | 8 | IV pointer |
| +0x40 | 4 | Operation |
| +0x48 | 8 | Opaque key-data pointer selected by provider source |
| +0x50, +0x58 | 8 each | Offset A/B |
| +0x60 | 8 | Provider-derived per-operation value; complete meaning unknown |
| +0x68 | 8 | Initially zero; full progress/state meaning unknown |
| +0x78 | 4 | Completion status consumed by waiter/callback paths |
| +0x80 | 8 | Completion function pointer |
| +0x88 | 8 | Completion context pointer |

The provider loads a pool through its +0xf8 field and invokes nominal `IOCommandPool::getCommand(true)` at vptr +0x148. It packs the command and tail-dispatches through the gate at provider+0xb8. The `runAction` call receives the action pointer from provider+0xf0, command as its first argument and three zero argument slots. Exact runtime action registration and object identity remain unproved.

| Nominal class / virtual offset | Exact method | Target |
| --- | --- | --- |
| IOCommandPool +0x148 | `getCommand(bool)` | `0xfffffe000c51ff48` |
| IOCommandPool +0x150 | `returnCommand(IOCommand *)` | `0xfffffe000c51fe7c` |
| IOCommandGate +0x1e8 | `runAction(...)` | `0xfffffe000c51e408` |
| IOCommandGate +0x200 | `commandSleep(void *, unsigned int)` | `0xfffffe000c51e1d4` |
| IOCommandGate +0x208 | `commandWakeup(void *, bool)` | `0xfffffe000c51e19c` |
| IOAESAccelerator +0x8b8 | `performImmediateAES(IOAESAcceleratorCommand *)` | `0xfffffe000abfd29c` |
| IOAESAccelerator +0x8d0 | `_queueLocked(IOAESAcceleratorCommand *)` | `0xfffffe000abfd2d8` |
| IOAESAccelerator +0x8d8 | `_startCommand()` | `0xfffffe000abfd4bc` |

Original `_queueLocked` distinguishes immediate and queued paths. On its queued path, callback +0x80 nonnull permits an asynchronous zero return; callback null reaches `commandSleep(command, 0)`, then loads status +0x78 and returns the command to its pool after a successful wait. Thus null callback fields select waiting behavior on that queued path; they do not prove a native wait occurs for every operation.

Original `_completeAES` at `0xfffffe000abfd598` requests `complete(0)` for both descriptor roles. For a nonnull callback, it saves status, context and callback before returning the command to the pool, then tail-calls the saved function with context in X0 and status in low32 of X1. For a null callback it tail-calls `commandWakeup(command, false)`. No native callback, wait, wake, pool return or descriptor completion is executed in this increment.

## A confirmed obfuscated cleanup caller

The original compiler-bounded function `0xfffffe000a62259c..0xfffffe000a6229c8` contains an indirect call at `0xfffffe000a6227b4` to `cleanupKernelAESHW`. Three exhaustive byte-bank identities establish the table base, the preceding assertion target and the cleanup target independently of the changing byte input.

| Selection | Byte-bank XOR key | Constant for all 256 inputs | Selected slot / result |
| --- | --- | --- | --- |
| Table-base selection | `0xac` | `0x06` | Pool index `0x33`, slot `0xfffffe0008472098`; loaded value minus 12 gives `0xfffffe0008472f20` |
| Preceding assertion | `0xb4` | `0x6e` | Table index `0xf21`, slot `0xfffffe000847a828`, target `0xfffffe000a687ecc` |
| Cleanup selection | `0x32` | `0xf9` | Table index `0xf81`, slot `0xfffffe000847ab28`, target `0xfffffe000a5085e0` |

The cleanup left/right bank pointers come from pool offsets +0xb70/+0xa10; source-loaded addresses are `0xfffffe0007949ed0` and `0xfffffe000792fec0`. The original cleanup slot is an authenticated format-8 entry with diversity `0xed6d`, matching the call modifier. The bounds helper compares unsigned X0 and X1, returns if X0 <= X1, and otherwise executes `BRK #1`. It does not change X27, which holds the recovered table base. The caller passes `(object + 0x40) mod 2^64` and its supplied limit to that helper. A legitimate native object, entry record, returning assertion or eventual cleanup invocation has not been observed.

The supplied C already calls `cleanupKernelAESHW()` in this adapter, despite its surrounding xref metadata saying `None`. Original machine-code selection now independently corroborates that call. The remainder of the adapter and its incoming callers are not fully recovered; no destructor or object-class name is assigned.

## Reference census and remaining candidates

The direct B/BL scan covers 422089 aligned words in the original executable segment. Its only direct reference to the five wrapper/cleanup targets is a tail branch at `0xfffffe000a50a010` into `performAESonIOMD`; no direct cleanup branch is found. Nine aligned qword matches consist of four data-constant pointer candidates and five linkedit metadata words. Linkedit matches do not establish runtime caller pointers.

Six executable sites load modifier `0xed6d` immediately before an indirect call:

| Modifier instruction | Following call | Current result |
| --- | --- | --- |
| `0xfffffe000a60db4c` | `0xfffffe000a60db50` | Target unresolved |
| `0xfffffe000a6227b0` | `0xfffffe000a6227b4` | Cleanup target resolved above |
| `0xfffffe000a6825cc` | `0xfffffe000a6825d0` | Target unresolved |
| `0xfffffe000a6968f0` | `0xfffffe000a6968f4` | Target unresolved |
| `0xfffffe000a698164` | `0xfffffe000a698168` | Target unresolved |
| `0xfffffe000a698254` | `0xfffffe000a698258` | Target unresolved |

The bounded original table range `0xfffffe0008470000..0xfffffe000847c000` contains four authenticated entries with that diversity, targeting `0xfffffe000a5086a0`, `0xfffffe000a6674d0`, `0xfffffe000a5a962c` and `0xfffffe000a5085e0`. Diversity alone therefore does not distinguish cleanup. Five candidate sites remain unresolved; this census is not an exhaustive recovery of all indirect transfers or aliases.

## Verification and reproduction

| Check | Result |
| --- | --- |
| Fresh wrapper cases | 85, 6643 original instruction visits |
| Provider call records | 80: 64 same-descriptor records, 16 separate-descriptor records |
| Stack arguments | 1920 bytes checked against preceding original source writes |
| Temporary descriptor requests | 36 |
| Preparation / copy-out / completion / release requests | 28 / 24 / 24 / 32, explicitly modeled |
| Wrapper return classes | 40 zero, 40 signed32 -22, 5 signed32 -40 |
| Nonzero X0 with zero W0 cases | 16; verifies low32 status consumption under declared results |
| Local proofs | 3 unsatisfiable counterexample queries: XOR bit flip, length zero-extension, status fold |
| Cleanup dispatch identities | 3 banks, all 768 byte inputs verified |
| Native provider execution / accepted operation | None / unproved |

The verification command used before publication is below. Published outputs remain frozen; independent reproduction requires a separate copy of the source/evidence tree.

```
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kext_aes_handoff.py
```

The verifier re-reads original function bounds, bytes, symbols, slots and headers, rechecks the word proofs and byte-bank identities, and runs newly created wrapper cases. Cost is O(B + C*I + E + N) time and retained space for source bytes B, cases C, bounded per-case instructions I, events E and scanned symbols N, plus compiler and solver-dependent fixed-word work. Provider argument values, including opaque invalid-as-native pointer sentinels, are ABI fixtures; APIs do not dereference or accept them.

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| H1 | Pinned source builds and original fileset compiler catalogs identify these routines | All addresses, methods and source mappings | Rehash originals; compare exact function bytes, bounds, symbols and chain membership |
| H2 | Objects, globals and input values are declared private fixtures | Wrapper argument and control-flow executions | Guard all non-stack reads; reject any dereference of opaque key/IV/data; compare fresh source replay |
| H3 | External results model factory, provider, prepare, copy-out, complete, release, initialization and log calls | Resource sequences and return classes | Null/error/full-count/mismatched-count/nonzero-return cases; never infer native acceptance or effects |
| H4 | PAC is abstracted in private wrapper runs | Conditional control flow only | Preserve original tags/targets as provenance; actual receiver identity and authentication require separate evidence |
| H5 | Local lift preserves source word widths and shifts | Three word identities and wide-status interpretation | Pin instructions, recheck SMT, test high64 inputs and full64 count mismatches |
| H6 | Vtable classes and provider-derived fields are nominal source bindings | Provider/pool/gate and partial command contracts | Recover actual object constructors, registration and runtime vptrs before assigning native object state |
| H7 | Installed SDK is corroborating context, not an exact historical private SDK | +0x208 `readBytes` role | Recompile pinned headers; compare offset/signature diversity; keep original target symbol explicitly unknown |
| H8 | Source banks/table entries remain pinned and the preceding assertion returns | One cleanup target selection | All 256 inputs per bank; exact source pool loads, base construction and assertion body; entry/native reachability remains unknown |
| H9 | Provider source paths are inspected without hardware execution | Conditional queued sleep/wakeup and callback ordering | Trace action registration, immediate/queued predecessors and completion producer; do not infer an actual wait or callback |

## Bounded continuation

| Impact | Next investigation | Contract resolved |
| --- | --- | --- |
| High | Recover incoming record producers and callers of `0xfffffe000a62259c` | Entry reachability and eventual AES cleanup after partial initialization |
| High | Resolve the other five modifier sites through their original byte-bank context | Remaining cleanup/other adapter associations |
| High | Bind provider+0xf0 action registration and command-gate ownership | Exact queue dispatch and serialization route |
| High | Trace cached data-buffer consumers and command offset consumers | Byte extents and end-to-end buffer data flow |
| Medium | Recover prepare/complete pairing across immediate, queued and caller layers | Descriptor ownership/counting invariants |
| Medium | Identify the unnamed +0x208 target from additional matching primary symbols/source | Strengthen the SDK-correlated method label |

## Scoped quality gates

QG1 passes for factual analysis. QG2 passes with H1-H9, dependent results and falsification probes. QG3 passes for wrapper/provider ABI, partial command/completion and one cleanup caller; the broad goal remains active and incomplete. QG4 passes for explicit widths, register/stack locations, exact byte counts and complexity. QG5 passes with modeled/native effects, nominal/actual receivers, exact-symbol/SDK-correlated methods, resolved/unresolved references and local/native reachability separated. QG6 passes through original bytes, compiler bounds, symbols, slots, 85 fresh cases, three local proofs and exhaustive bank checks. QG7 passes with impact-labeled continuation. [Machine-readable gates](triage_evidence/kext_aes_handoff_quality_gates.json), [source readback](triage_evidence/kext_aes_handoff_source_identity.json) and [prior-artifact preservation](triage_evidence/kext_aes_handoff_preservation.json) cover delivery.
