# FPSD1200 certificate chain, inline output and task-map cleanup

The original FPSD1200 path consumes the reference CoreFP certificate, constructs embedded Root and FairPlay AAA certificates, and executes public-exponent arithmetic matching their signature relationships. A later exponentiation uses the supplied CoreFP leaf's public modulus and a source-built representative beginning `00 66 64 70 63 00 00 00 01`. Original byte stores at `0x1002212a0` export its complete 128-byte result into the inline reply region. The subsequent continuation constructs the embedded fairplayd leaf and reaches imported `vm_deallocate` at `0x10049e114`. No native message emission, output-port right or completed protected operation is established. [FV1-FV8]

This extends the [seed/environment continuation](fpsd1200_context_report.md). Four new profiles preserve the earlier original admission and identity prefix. The investigation remains active; the recovered output is local data production before an unexecuted VM API, not an observed completed reply.

## Assumption register

| ID | Assumption / dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FV1 | The pinned thin daemon, selected library body and matching live IDA code identify this source. All recovered addresses and fragment roles depend on this identity. | Rehash the thin image, all 832 source spans, 1113 rebases and 28 bind records; compare cache/export identity. Keep IDA whole-input metadata distinct from thin-image identity. |
| FV2 | Frozen Security/CF, PID, once/lock, pool and composed startup fixtures supply the declared predecessor. Every finite continuation depends on those premises. | Independently replay all original visits, API events, callback returns and terminal CPU/memory state. Native credentials, PAC, startup continuity and concurrency remain unknown. |
| FV3 | Each certificate allocation is a disjoint private owner with initially undefined bytes, or NULL. Constructor and ownership observations depend on that contract. | Verify every descending XOR-copy and ascending shift store, each consumed byte's knownness, retirement ordering and untouched backing bytes. Compare the first-allocation NULL return. Native allocation/free behavior is not inferred. |
| FV4 | The retained integer/argument codecs correctly interpret the actual selected arithmetic records. Public-key and output roles depend on those record views. | Check source-known header/limb/context bytes, complete call/return checkpoints, all 251 full Montgomery products and every exponent sequence. Compare actual moduli/signatures with independently parsed public DER. No unrestricted routine-equivalence theorem is asserted. |
| FV5 | The reference words2/2, matching counts756 and retained public certificate are explicit input fixtures. External-data conclusions depend on those exact bytes. | Rehash the DER, inspect its extension boundaries and every OOL read, preserve all request/header bytes and retain unchanged earlier countercases. Complete extension semantics, other application words and malformed-input behavior remain unknown. |
| FV6 | CASAL handling models scalar single-thread compare/store semantics. Optional `mach_task_self_` data is a supplied u32 name. Later continuations depend on those explicit fixtures. | Retain matched stop-before-instruction/data cases, compare GP31/SP/NZCV and old/expected/desired values, and verify the original VM-call arguments. Native atomic ordering and task/port object identity are unknown. |
| FV7 | Inline result bytes, preserved OOL/port seeds, task-local names and an API-call boundary are distinct objects/effects. Output and IPC interpretations depend on that distinction. | Match all 128 output stores to the computed result; monitor other output cells and actual import boundaries. Recover native right producers, VM ownership and completed receive/send independently. |
| FV8 | Four finite profiles, arithmetic oracles and exact publication checks delimit this increment. Fragment names are not complete C-function prototypes. | Replay 30103606 original visits, recheck all 4352 bank inputs, retain unpaired observations and preserved predecessors. Audit receipts pin the exact replay inputs and program; publication checks do not replace a fresh replay. |

## Primary provenance [FV1-FV4,FV8]

| Object | Identity / coverage |
| --- | --- |
| Original daemon arm64e slice | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base `0x100000000` |
| Read-only live IDA | Input metadata SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`; all 832 selected source spans match the thin image. Differing whole-file hashes remain explicit. |
| Source catalog | 39379 distinct daemon instructions / 157516 bytes, including two guard sites; these flattened spans do not define C-function boundaries |
| Pointer and lookup evidence | 1113 rebases, 28 bind records, 17 exhaustive adjacent-bank identities, 4352 inputs, 13112 observed pair uses and 138 unpaired reads |
| Retained inputs | Reference [CoreFP public DER](triage_evidence/corefp_fppineboard_certificate.der), source-written startup snapshot and prior [Root/AAA/leaf extracts](rpc502_policy_report.md); original source bytes remain authoritative |
| ABI context | Current SDK `mach_task_self_` declaration, `vm_deallocate` prototype and VM-map Mach type definitions; compile-only arm64e checks establish port32/address64/size64 types |

New evidence: [source/profiles](triage_evidence/fpsd1200_certificate_checks.json.zst), [IDA and SDK attestation](triage_evidence/fpsd1200_certificate_ida_readback.json.zst), [independent audit receipt](triage_evidence/fpsd1200_certificate_audit.json.zst), [producer](triage_evidence/recover_fpsd1200_certificate.py), [independent replay/oracles](triage_evidence/audit_fpsd1200_certificate.py), [publication verifier](triage_evidence/verify_fpsd1200_certificate_publication.py). The relevant IDA knowledge-store query returned no matching fact. No IDB mutation or native target/API execution occurred.

## Actual certificate constructors and lifetime [FV2-FV5]

All observed allocations use imported `malloc` at `0x100346714`. Original descending stores at `0x1003f0e5c` copy the full selected array XOR `0x98`, including a four-byte prefix. Original ascending stores at `0x10030980c` then move bytes[4,N) to[0,N-4). The last four bytes retain their earlier tail values. Those residual bytes are outside the DER object. The local prefix meanings remain unknown.

| Constructed object | Encoded source / allocated extent | Prefix4 / DER extent | DER SHA-256 |
| --- | --- | --- | --- |
| Apple Root CA | `0x100e9eee0` / 1219 bytes | `00000000` / 1215 bytes | `b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024` |
| Apple FairPlay AAA Certification Authority | `0x100ff63a0` / 893 bytes | `01000003` / 889 bytes | `b091ab656e40fe664326e3a0c6018d0f3275a8aa2c397e071aa8493bd61b2cf7` |
| `fairplayd.3333AF100127AF0003AF000001` | `0x100ee87f0` / 723 bytes | `01000007` / 719 bytes | `d43ca892b364466d885a38418b11469c2634ddcfe493ff3beda2f022edde4102` |

The selected intermediate is AAA. The earlier [RPC502 startup report](rpc502_startup_report.md) also identified a 1035-byte Key Services constructor at this shared source site; its observed branch must not be substituted for this one. The earlier [public hierarchy inventory](rpc502_auth_report.md) and [AAA continuation](rpc502_policy_report.md) supply independent source-extract context.

For owner extent N, the constructor makes N+(N-4)=2N-4 one-byte stores and defines every owner byte. Across the matrix, all 15532 such stores and 25507 owner reads are checked. No owner is consumed before source definition or after its recorded retirement. `free` at `0x100582efc` retires AAA and `0x1005ada28` retires Root in each nonnull path. These are recorded API effects; physical private bytes remain available for terminal checking. The later own-leaf allocation is still live at the captured VM boundary.

If the first certificate `malloc` returns NULL, original code returns application status `0xffff5bd4` (signed32 -42028), restores selected slot0's marker to `0x4577df49`, and reaches original MIG input retirement. No certificate owner or arithmetic call is created in that case. This is an allocation-failure continuation, not a native fault claim or a semantic error-name assignment.

## Arithmetic and actual public keys [FV1-FV5]

The [prior Montgomery analysis](rpc502_rsa_report.md) identifies selected square entry `0x100539ea0` and product entry `0x10094593c`. This increment joins those entries to FPSD1200 and checks every actual call and return, rather than inheriting their role from names alone.

| Selected arithmetic representation | Established retained codec |
| --- | --- |
| Integer header+0 | Raw u32 capacity in limbs |
| Header+4 | Signed count=`int32(stored-0x693be708 mod2^32)` |
| Header+8 | Pointer64 to active encoded u32 limbs |
| Limb j | Little-endian u32 XOR `0xada56e3c`; least-significant limb first |
| Square arguments | Context pointer+0, output integer+16, operand+24, modulus+32; selected extent40 bytes |
| Product arguments | Context+0, modulus+8, output+16, left+24, right+40; selected extent48 bytes |
| Context+0 / +8 / +16 | Pointers to radix/precomputation integers; u32 low-limb inverse parameter |

For n active modulus limbs, R=2^(32n). Every complete call satisfies `T=A*B*R^-1 mod N`. The audit checks actual source-known inputs/output and `-N[0]^-1 mod2^32`, not just selected inner rows. Entry/return SP and all recorded CPU checkpoints agree.

| Exponent group | Actual modulus | Calls / precomputation squares | Established input/result relationship |
| --- | --- | --- | --- |
| AAA certificate under Root | 2048-bit Root public modulus | 32 / 11 | Actual representative is AAA's raw signature; final result equals its SHA-1 DigestInfo encoded block |
| Reference CoreFP leaf under AAA | 1024-bit AAA public modulus | 31 / 10 | Actual representative is the retained leaf's raw signature; final result equals its SHA-1 DigestInfo encoded block |
| Later source-built representative | 1024-bit supplied CoreFP leaf modulus | 31 / 10 | Exact input/output and full exponent order match exponent65537; protocol semantics remain unknown |

The first profile contains the first two groups; each later nonnull profile contains all three. Thus 251 complete arithmetic calls and eight full exponent sequences are retained. Different call counts follow the actual modulus widths and precomputation lengths. They are not evidence of missing calls.

Each sequence performs log2(32n) precomputation squares, converts with R^2, runs the actual public-exponent square/product sequence, and converts out of Montgomery form. The full source order and each result are checked independently against integer modular arithmetic. Mathematical signature equality does not establish native trust-anchor, date, revocation, credentials or successful protected-operation policy.

## Inline result and peer-extension reads [FV4,FV5,FV7]

The third representative begins `00 66 64 70 63 00 00 00 01`: a zero byte, ASCII `fdpc`, then `00000001`. Its field meanings are unknown. The prefix is not the `00 02` prefix of a PKCS#1 v1.5 encryption block; no standard padding or protocol-version interpretation is assigned.

After the final conversion out of Montgomery form, all 128 original stores at `0x1002212a0` (`STRB W25,[X17,W26,UXTW]`) write reply+195 down to reply+68, one byte at a time. The resulting ascending 128-byte region equals the complete big-endian result `S^65537 mod N` under the supplied CoreFP leaf modulus. Both later nonnull profiles reproduce the same bytes. The independent replay checks actual stores and terminal memory; publication adds the explicit join between that output and the independently checked integer result.

```text
reference CoreFP DER -- Root/AAA public-signature checks
           |
           +-- supplied leaf modulus N
                         |
source-built S ----------+--> S^65537 mod N --> reply[68,196)
                                                128 bytes
                                                   |
                                      own-leaf construction
                                                   |
                                      task-self data read
                                                   |
                                      vm_deallocate boundary
                                      (implementation unexecuted)
```

All 104 bytes of the staged protected payload remain identical to their entry values in every case. In particular, its output OOL address, count and name cells remain seeded. The produced inline bytes do not establish an OOL owner, port producer or completed reply.

The later profiles also read 16 additional bytes from the peer certificate after the earlier full DER parse. These lie inside the 20-byte extension OCTET STRING beginning at DER offset589, associated with raw OID bytes `2a864886f76364070102`. Complete OCTET contents are `0000000200000004294e5e300000000483705b57`. The table records bytes and source consumers; their protocol semantics remain unknown.

| DER offsets, inclusive | Bytes | Original additional read PCs |
| --- | --- | --- |
| 589..592 | `00000002` | `0x1003f47e8`, `0x1003f47f0`, `0x1003f47f8`, `0x1003f4820` |
| 593..596 | `00000004` | `0x1003f969c`, `0x1003f96a0`, `0x1003f96b4`, `0x1003f96dc` |
| 597..600 | `294e5e30` | Earlier DER reads only; absent from these additional16 reads |
| 601..604 | `00000004` | `0x10061cb8c`, `0x10061cba0`, `0x10061cbb4`, `0x10061cbf4` |
| 605..608 | `83705b57` | `0x100493738`, `0x10049374c`, `0x10049375c`, `0x10049379c` |

## Atomic, task-map and Mach boundaries [FV2,FV6,FV7]

The new atomic site `0x100482d98` is `CASAL W14,W11,[X15]`, opcode bytes `ebfdee88`. At address `0x1010b5de0`, observed old and expected values are `0x5d96`, desired value `0xa94ef`. The matched guard stops before this instruction. Six later modeled visits across three profiles apply only its scalar compare/store result; source code restores the old value between repeated visits. Native acquire/release ordering and contention are not tested.

| Interface object | Original location | Established role / limit |
| --- | --- | --- |
| Incoming application name | Request+12, consumed by the retained MIG prefix at `0x10000467c` | Fixture name `0x1400`; object/right identity is not supplied by this number |
| Reply destination | Request+8, retained header formatter | Fixture remote name `0x6400`; a buffer field, without observed send |
| `mach_task_self_` data | Original imported slot `0x1010a39c8`; `LDR W0,[X28]` at `0x10049e0f8` | Optional explicit u32 fixture `0x6600`; guard stops before the read when missing |
| `vm_deallocate` call | Original indirect call at `0x10049e114`; imported bind slot `0x1010a00f8` | First three argument registers identify target task, address and size; API implementation is unexecuted |
| Input MIG retirement on NULL return | `mig_deallocate` at `0x10000468c` | Original OOL input address and756-byte count; record-only import result, without host release |
| Native Mach emission | Unknown for the unexecuted VM continuation | No Mach message, trap, returned port right or native VM change is observed |

The current SDK declares `mach_port_t mach_task_self_` and `vm_deallocate(vm_map_t, vm_address_t, vm_size_t)`. Compile-only arm64e checks establish four-byte port names and eight-byte address/size arguments. The call's actual first three arguments are:

| Argument | Captured value | Provenance |
| --- | --- | --- |
| target_task, X0/u32 | `0x6600` | Explicit imported task-self data fixture |
| address, X1 | `0xa5a5a5a5a5a5a5a5` | Equal to preserved staged output-address seed at payload+72 |
| size, X2 | `0` | Original source-selected call argument |

X3..X7 are captured register remnants, outside this three-argument API contract. The invalid-looking seed and zero size are observations of this finite fixture; no native validation result or allocation ownership is inferred. Normalized import-data address `0x6000000800` is private harness placement, not a native binding address. The bind record's authenticated pointer metadata and PAC bypass remain explicit in evidence.

## Finite matrix and verification [FV1-FV8]

| Case | Original visits | Arithmetic calls | Inline stores | Terminal observation |
| --- | ---: | ---: | ---: | --- |
| `reference_atomic_guard` | 8758037 | 63 | 0 | Before new CASAL at `0x100482d98` |
| `reference_task_data_guard` | 10088919 | 94 | 128 | Before missing task-self data at `0x10049e0f8` |
| `reference_Mach_boundary` | 10088927 | 94 | 128 | At unexecuted `vm_deallocate` import selected by `0x10049e114` |
| `first_certificate_NULL` | 1167723 | 0 | 0 | Original36-byte error reply; status `0xffff5bd4` |

The total is 30103606 original instruction visits: 30103530 daemon and76 selected-library visits. The audit checks 141 import events,72 retained admission checkpoints,15532 constructor stores,240784 active arithmetic bytes,251 full Montgomery outputs, eight full exponent sequences and six signature-derived exponent results. Two public certificate-signature relations are independently verified. No final profile ends on an instruction-budget or engine-error boundary. Earlier application-word1 countercases remain preserved; this matrix does not assert their equivalence to this word2 continuation.

The fresh independent replay completed successfully before publication. Its receipt pins the exact auditor, logical evidence, IDA/SDK readback, source image and dependency hashes. Publication checks rehash those inputs, compare the exact manifest delta and original inputs, join inline stores to arithmetic results, and inspect owned content and commit metadata for analyst paths. A receipt records that execution; checking the receipt alone is not a new instruction replay. All substantial new JSON is archived using Zstandard ultra22 with exact round-trip verification.

From a prepared environment, use the existing retained source/cache inputs and a Python environment containing Unicorn, Capstone and Z3:

```sh
env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/audit_fpsd1200_certificate.py

env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_fpsd1200_certificate_publication.py
```

Producer/replay cost is O(B+F+V+E+L) for selected source bytes B, fixups F, finite visits V, recorded events E and active limb bytes L, excluding integer multiplication/inversion cost. For modulus width b, the recorded exponent oracle uses O(log65537) modular operations per sequence plus the retained precomputation; integer multiplication cost depends on the interpreter's big-integer implementation. Live replay state is bounded by the private mapped image/owners and one decoded profile. This is a finite evidence bound, not a worst-case target-runtime bound.

## Bounded continuation opportunities [FV5-FV8]

| Impact | Question / next evidence |
| --- | --- |
| High | Recover the source origin of the output OOL address/count and their owner before interpreting the VM call. The current seed-preserving path supplies neither an allocation nor a VM result. |
| High | Continue past the VM API only under an explicit argument/result contract; recover subsequent status, slot handling, output-name producer and actual native receive/send separately. |
| Medium | Trace the20-byte peer extension and source-built `fdpc` representative into exact local field producers/consumers. Raw grouping and exponent arithmetic do not establish field semantics. |
| Medium | Establish native initialization, trust policy, credentials, task/right identity and atomic concurrency independently of these composed startup fixtures. |
| Low | Compare the shared certificate constructor's other selectors and lifetimes against the retained Key Services branch; avoid inferring a complete routine prototype from flattened shared fragments. |

**QG1** passes: factual interface and arithmetic observations. **QG2** passes: FV1-FV8 declare premises, dependent claims and probes. **QG3** passes for this bounded increment; the full investigation remains active. **QG4** passes: byte widths, signed32 status, limb/radix arithmetic, source order and finite cost are explicit. **QG5** passes: incomplete replies, preserved seeds, API boundaries and native effects are distinguished. **QG6** passes: original source, public DER, read-only live IDA, SDK compilation and independent replay/oracles supply separate primary provenance. **QG7** passes: impact-ranked continuation questions are bounded and explicit.
