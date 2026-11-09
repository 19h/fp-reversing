# Daemon RPC502 application boundary: private ABI, filename scan and audit PID gate

The application entry at `0x100422d48` scans the received filename as a NUL-terminated string, copies the audit token into a private record and enters a protected dispatcher using operation tag `0xbc84919b`. The recovered protected route extracts the audit PID and continues only when that PID is zero. A nonzero PID takes a local early-return path whose decoded u32 result is `0xffff5bbf` (-42049).

This supplies an application-side predicate compatible with the [kernel request's zero audit template](kernel_user_copyout_report.md). It does not establish complete service access, authorization or native delivery. Filename scanning precedes this predicate and is not bounded by the incoming OOL count in the inspected wrapper.

## Provenance, tool availability and assumption register

Analysis date: 2026-11-01. Original daemon thin image: `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Its exact relationship to the IDB-recorded universal image is retained in the [corpus identity report](zut_trace_report.md).

Current connection discovery listed only the kext database. The previously connected daemon target `6b117c693e3b` was absent from that response; no new daemon decompilation was received. The pending orchestration was terminated and analysis continued from original bytes. [Connection visibility](triage_evidence/rpc502_ida_availability.json) does not establish that the IDB file is missing or that any IDA/daemon process is closed. No target code was executed, and no IDB was modified.

[Native contracts](triage_evidence/daemon_rpc502_contracts.json) retain 18 ranges, 17 exhaustive byte-bank reductions, 13 branch slots, 33 independently checked original fixup/import words and four SMT queries. Four prior shared-core source hashes were refreshed against the original thin image. The long setup range's 129 stores were checked for preservation of the routing words and frame root; prior notes were locators, not fresh live proof.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| D1: original image, fixups and read-only tables are the intended build | Static call targets and routing | Recheck image/range hashes, raw fixup words, imports and every selected table. Runtime rebases/PAC are separate. |
| D2: filename points to readable memory through a terminating NUL | Scan completes and enters the private dispatcher | Test empty, unterminated, boundary-ending and null/zero-length cases in an isolated model or authorized native observation. The received count alone is not this precondition. |
| D3: inherited registers, stack records and globals obey the declared nonaliasing protocol | Cross-fragment argument identities, dispatcher tag and early-return status | Trace all predecessors and stores; perturb aliasing, stack alignment or saved frame words. Branch fragments are not standalone functions. |
| D4: imported stack-check and standard callees preserve the custom protocol expected by this code | X0/X1 and caller record survive through protected setup | Inspect matching implementations or native registers. Ordinary caller-saved-register rules do not alone prove the stack-check's custom preservation contract. |
| D5: runtime libbsm implements the documented API | The extracted output is the audit PID | Match the runtime library or inspect it. Exact import identity, current SDK declaration, pinned reference implementation and a compile-only ABI probe are retained; runtime library execution is not tested. |
| D6: received audit bytes are initialized, intact and supplied through the installed CF receive path | Kernel zero-token correspondence and native reachability | Establish receive options/capacity/allocation/status handling and capture an actual exchange. The previous synthetic trailer witness remains a separate gap. |
| D7: the recovered nonzero-PID route preserves the helper scratch and valid return frames | Outer stack adjustment 0 and decoded status -42049 | Trace writes/aliases through copies, libbsm and core setup; observe a return. Unmodeled scratch corruption invalidates this local composition. |

## Public application-call ABI and private argument record

MIG502 emits the direct application call at `0x1000051f8`. The source-image caller and callee agree on 13 arguments:

| Incoming location | Value |
| --- | --- |
| W0 | Receiving-service task-local name, from request+0x0c |
| X1 | Received OOL filename address |
| W2 | Received u32 OOL extent, checked against its repeated length by the stub |
| X3 / X4 / X5 | CPU type / CPU subtype / origin scalar values |
| X6 | Pointer to the stub's 32-byte audit-token copy |
| X7 | Fixed reply record0 destination, 136 bytes |
| Entry SP+0 | Fixed reply record1 destination, 172 bytes |
| Entry SP+8 / +16 | OOL0 address-output pointer / count-output pointer |
| Entry SP+24 / +32 | OOL1 address-output pointer / count-output pointer |

Let S be the wrapper's SP after its 0x150-byte prologue, R=S+0x28, U=S+0xa0 and F=S+0xc0. F is the encoded protected control record, U an auxiliary local state object, and R the private application-argument record. The separate frame-extent slot is S+0xb0. These objects and the incoming Mach message are not merged into one type.

| R offset | Width, bytes | Established role |
| --- | ---: | --- |
| +0 | 4 | Receiving-service numeric name |
| +8 | 8 | Original filename pointer |
| +0x10 | 8 | CPU type |
| +0x18 | 8 | CPU subtype |
| +0x20 | 8 | Origin |
| +0x28 | 32 | Audit token copied by value |
| +0x48 | 8 | Fixed record0 destination |
| +0x50 | 8 | Fixed record1 destination |
| +0x58 / +0x60 | 8 / 4 | OOL0 result address / count |
| +0x68 / +0x70 | 8 / 4 | OOL1 result address / count |

This partial view is 0x78 bytes including alignment padding. The incoming W2 extent is not stored in R. The wrapper overwrites W2 with 32 for the audit-copy call before any recovered use of that incoming extent. Consequently the private record passes a string pointer without that transport bound.

## Filename scan before audit policy

At `0x100422edc`, the entry loads the first byte through X1 without a preceding local null/count check. A nonzero byte enters `0x10008a958`, which pre-increments a separate pointer X11 and reads one byte per iteration until NUL. An empty string goes directly to common construction. Both routes reduce W28 to `0x35ec001d`; they do not select different operation tags here.

```text
received filename pointer
       |
       +-- first byte 0 -----------------------+
       |                                     |
       +-- scan subsequent bytes until NUL ---+
                                             |
                                    build R and copy audit
                                             |
                                    protected RPC502 operation
                                             |
                                    extract PID and test zero
```

For a readable string containing L non-NUL bytes, the scan reads L+1 bytes and takes O(L+1) time, O(1) additional scan space. It is not a bounded `strnlen` using the supplied extent. The ordinary kext constructor's proven filename-plus-NUL payload satisfies this precondition under its own assumptions; that does not establish it for every possible Mach sender.

The refreshed MIG stub checks complex/count/size/type and repeated extent, then the trailer. It has no explicit filename-address/NUL guard before calling this entry. A zero descriptor extent with repeated extent0 can satisfy those local structural comparisons while the application's first-byte read still requires a readable pointer. Service availability, valid trailer delivery, framework filtering and native reachability of such a malformed request remain unknown. This is a static precondition/ordering finding, not an observed native fault or service-access result.

## Audit-copy helper and protected control record

Call `0x100023938` resolves through original slot `0x10109fc88` to local helper `0x10046f89c`, with IA discriminator `0x34a1`. It receives `(source_audit,R+0x28,32)`. Native loads from X0 and stores through X1 establish the copy direction; it is not assigned the imported `memcpy` name.

For the aligned 32-byte call used here, the helper follows four 8-byte load/store pairs at `0x10046fa50`..`...fa6c`, then returns. The stub audit temporary and private destination are 16-byte aligned under the standard entry-SP condition. Complete general overlap and arbitrary-length semantics are outside this scoped copy contract.

At `0x100023a74`, the wrapper calls `0x10065ffd8`; its nested call at `0x10066022c` resolves to `0x10061a2d0`. Original pointer words and PAC discriminators `0xea64` / `0xedd6` are retained independently from their successful runtime authentication.

With x=`low32(F)` and p=`(x xor 0xeaae0ac9)*0x7398180b mod 2^32`, the wrapper supplies:

```text
F+0x00 = U xor 0x1c0b9f7ce10f2255
F+0x08 = p xor 0x00006cf4
F+0x0c = p xor 0xbc84919b
F+0x10 = R
F+0x18 = encoded result written by the protected core
```

The child dispatcher reduces its first index to 0x6cf4 and the operation word to 0xbc84919b under D3/D4. This uses the same shared root as a prior 61471 analysis, with a distinct operation word. The previous 61471 path's later choices are not reused without recomputing these comparisons.

| Protected stage | Selected index | Target |
| --- | --- | --- |
| First shared entry | 0x6cf4 | `0x1004c244c` |
| Preserved root setup | 0x8061 | `0x100610388` |
| Signed comparison with 0xd5525452 | 0xb31b | `0x1005283ac` |
| Equality boundary | 0x6567 | `0x100524a58` |
| Exact operation-tag equality | 0x6295 | `0x1006126c4` |
| Nonnull private-record route | 0xbe65 | `0x1007fc57c` |

The 0x1004c24a4..0x1004c3638 setup is straight-line through its final branch and does not overwrite the protected routing words; all 129 stores were checked. Its final load at `0x1004c3620` obtains R from the saved F+0x10. The records therefore remain linked by native loads, subject to the declared nonaliasing/preservation assumptions.

## Recovered audit PID predicate and early return

The operation leaf loads filename, CPU/subtype/origin and fixed-record pointers from R. It copies R's audit value into two internal temporaries, then calls imported `libbsm/_audit_token_to_au32` at **`0x1007fc754`**. The original auth-bind is slot `0x1010a0500`, IA discriminator `0xdc55`.

The call supplies a copied token through X0, null output pointers through X1..X5 and X7, one nonnull output at X6 and a null final stack argument. The current SDK declaration and [pinned OpenBSM implementation](https://github.com/openbsm/openbsm/blob/696ec806a1d8fe5494a447343d2f78bb7414a8ef/libbsm/bsm_wrappers.c#L470) identify X6 as the PID-output pointer. The reference writes token word 5 to that output; it is not the exact runtime libbsm binary. A compile-only [ABI probe](triage_evidence/rpc502_audit_abi_probe.c) with the current SDK independently produces this register/stack arrangement, retained in [assembly](triage_evidence/rpc502_audit_abi_probe.s).

The output word is initialized to 0 at protected SP+0x4620. The arithmetic at `0x1007fc758`..`...fc784` reduces exactly to:

```text
PID == 0 -> index 0x5bcc -> 0x1005c18c8 -> thread/QoS processing
PID != 0 -> index 0x28fc -> 0x100528dd8 -> early return
```

The full 32-bit predicate is checked with SMT, including negative bit patterns and INT32_MIN. No UID/GID output is requested in this API call. This is a recovered local PID-zero predicate, not a complete eight-word kernel-token comparison or proof that no later checks exist.

On the nonzero-PID route, `0x100528ddc` writes encoded value `0x74c29dee` to F+0x18 and returns through the protected frames. Under D7, the helper's scratch restoration makes the outer dynamic stack adjustment 0. The outer wrapper reads the encoded word and XORs `0x8b3dc651` at `0x100023ad4`, yielding `0xffff5bbf`, signed -42049. Its symbolic business error name is unknown; it is not assigned a POSIX/Mach error label.

Under D5/D6, the kernel transport's eight zero audit words yield PID 0 and satisfy this necessary local predicate. Conversely a conventional user sender with nonzero audit PID selects the early return after filename scanning. Neither statement establishes acquisition of a service send right, installed framework delivery, complete authorization or a successful context construction.

## Output publication and thread scheduling interface

After the protected adapter returns, the wrapper copies its local OOL address/count results to the four incoming output pointers at `0x100023a94`/`...3a9c`/`...3aa8`/`...3ab0`, before decoding and returning status. Those outputs are not established as initialized/useful on every error route. The generated MIG caller uses only the error reply on nonzero status; it builds the 384-byte complex success reply and copies OOL counts only on status 0. This status-dependent serialization matters when interpreting incidental error-path stores.

Successful incoming OOL lifetime, complete fixed-record construction and output VM allocation/deallocation remain unknown. The local wrapper scan/copy does not establish that protected callees leave the incoming mapping untouched.

| Scheduling event after PID 0 | Native call | Exact original import / observed arguments |
| --- | --- | --- |
| Current thread identity | `0x1005c195c` | `_pthread_self` |
| Query current QoS | `0x1005c19ac` | `_pthread_get_qos_class_np(thread,&class,&relative_priority)` |
| Query result 0 | Index0xca27 -> `0x100579c6c` | Continues to scheduling-class request |
| Query failure | Index0x6ac2 -> `0x1005be85c` | Joins with a zero scheduling-change flag; later environment processing is documented below |
| Request class change | `0x100579cd4` | `_pthread_set_qos_class_self_np(0x21,0)` |

The current SDK names 0x21 `QOS_CLASS_USER_INTERACTIVE`. The [environment continuation report](rpc502_environment_report.md) establishes return-dependent handling: the common join stores a byte indicating whether the setter returned zero; query failure also joins with zero. The actual scheduling change and complete restoration of prior class/relative priority remain unknown. This is an external scheduling interface in the protected operation, distinct from Mach voucher/importance propagation.

That continuation also establishes CPU/origin marshalling, a guarded binary global, `_csr_get_active_config` at `0x100616094`, and `_bootpolicy_get_security_mode` at `0x1004cfe24`. The latter consumes values from two imported data cells whose original import-table addends cancel native adjustments. The CSR indicator is 2 on getter failure, otherwise `((u32_config & 0xffffffef) != 0)`. Its final policy use remains unknown. Ten finite Unicorn fixtures explicitly bypass PAC and model selected imports; they do not establish a native RPC exchange, actual environment values or complete authorization.

## Reproduction, bounded findings and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_daemon_rpc502.py
clang -target arm64e-apple-macos13.0 -std=c11 -fsyntax-only \
  triage_evidence/rpc502_private_layouts.c
clang -target arm64e-apple-macos13.0 \
  -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
  -S -O2 -Wno-deprecated-declarations triage_evidence/rpc502_audit_abi_probe.c \
  -o triage_evidence/rpc502_audit_abi_probe.s
```

The first compile attempt lacked an explicit sysroot and could not find `bsm/libbsm.h`; the command above succeeds with the current SDK. It is ABI compilation, not target execution. Source/header identities are in the [source manifest](triage_evidence/daemon_rpc502_audit_sources.json). Extraction is O(B+F+D) time/space for binary bytes B, fixups F and retained instructions D, plus constant-size exhaustive selector checks and solver-dependent proof cost. Private record assertions describe only the recovered 120-byte prefix.

| Impact | Additional finding / remaining interface |
| --- | --- |
| High | Native application code supplies a PID-zero predicate compatible with the kernel audit template. Complete service access and downstream policy remain unknown. |
| High | Filename scanning precedes this predicate and discards the transport's explicit length bound at the private-record boundary. Malformed-message reachability is unverified. |
| High | The operation-specific private record/control tag connects generated MIG502 to shared protected core code; intermediate IDA fragments must not be treated as independent routines. |
| Medium | OOL result stores occur before status return, while MIG serialization is status-dependent. Error-path stores alone are not valid-output or disclosure proof. |
| Medium | PID-zero processing queries and requests pthread QoS; class restoration is a concrete remaining lifecycle requirement. |
| Medium | Fresh daemon IDA knowledge/decompilation was unavailable through the current connection; original-byte recovery proceeded with explicit provenance. |

QG1 factual technical scope. QG2 D1-D7 and probes explicit. QG3 this increment covers RPC502's private ABI, scan ordering, protected route, local audit predicate, return code and scheduling edges; the full original objective remains active. QG4 widths, signed comparisons, modulo arithmetic, layouts and complexity are explicit. QG5 empty/nonempty scans, caller/receiver identities, ABI/public-source/runtime boundaries and status-dependent outputs are separated. QG6 original ranges/fixups, refreshed prior hashes, exhaustive bank checks, SMT, pinned reference source and compile-only ABI evidence remain distinct. QG7 bounded impact-labeled findings and continuation requirements are listed above.

## BootPolicy backend continuation (2026-11-01)

[bootpolicy_backend_report.md](bootpolicy_backend_report.md) follows the environment dependency through the original installed-cache library and matching kernel BootPolicy user client to the SEP endpoint. It establishes default-value pointer identity, root-volume/registry and local-policy inputs, command0x11 framing, additional Mach emission sites, entitlement/command guards and the daemon's three-way result-marker partition. This increment performs no target execution. Actual runtime library selection, environment values, full context policy, QoS restoration and output ownership remain unknown.

## Protected support/CoreKE continuation (2026-11-01)

[rpc502_runtime_report.md](rpc502_runtime_report.md) follows the common environment-marker route into two lazy rwlock objects, a VMM inquiry and dynamic CoreKE resolution. It recovers exact dlsym/export mappings and a call boundary with two u32 values plus a 64-bit record address. On the alternate VMM-positive finite route, processing reaches a constructed sidecar open. [rpc502_sidecar_report.md](rpc502_sidecar_report.md) then traces policy markers through a mutable global into a byte scan start, explains skipped synthetic prefix bytes, and establishes open-result routing to fstat/errno, including descriptor zero. Split-halving and valid native file framing remain unresolved. These results do not establish complete request rejection/acceptance, CoreKE execution, QoS restoration or successful output ownership.

[rpc502_mapping_report.md](rpc502_mapping_report.md) follows the selected file path through fstat status gating, full64-bit mapping/allocation size transfer, result publication, descending copy and a BE32 parser boundary. It establishes unmap/close after allocation failure, descriptor invalidation despite modeled close failure, and a late saved-class/relative0 scheduling request on selected error exits. Early-failure descriptor ownership, complete framing/parser semantics, all scheduling exits and successful reply ownership remain open.
