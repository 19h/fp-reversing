# RPC502 response ABI and kext output handoff

The original daemon response continuation and kext post-transport parser have matching successful layouts: 384 user bytes become a 392-byte internal representation with two 16-byte OOL descriptors, fixed records of 136 and 172 bytes, and two repeated u32 lengths. A separate 36-byte user / 44-byte internal form carries a nonzero application error. The user-to-kernel conversion in this increment is a declared byte-transfer fixture; native conversion and a complete FairPlay transaction remain unknown. [RP1-RP4]

The kext commits its six output values only after all successful-reply guards. Its argument 11 is an OOL-address output, despite the supplied decompilation's `NDR_record_t *` type. Successful output processing requests no message destruction in this stub. Rejection requests destruction; actual descriptor retirement is outside the private execution. [RP1,RP4-RP7]

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| RP1 | The hash-pinned daemon and collection are the intended static images | Instruction addresses, guards, field layouts and inferred roles | Rehash both original images and recapture every inspected instruction; verify runtime UUID/module pairing separately |
| RP2 | The application returns the declared status and has written the declared outputs | Response-continuation cases, including four complex outputs | Join a real application execution to these output locations; these fixtures do not establish application success |
| RP3 | Imported `_NDR_record` has the declared eight bytes | Exact NDR serialization in the private cases | Resolve the actual library binding and compare bytes; the private pointer at `0x1010b1e10` is explicitly substituted |
| RP4 | A completed receive supplies the modeled 64-bit internal header and unchanged body | Seven producer/consumer compositions | Recover and execute native reply copyin/descriptor conversion and transport delivery; names, rights, copy objects and pointer authentication are unresolved here |
| RP5 | The post-call frame and registers agree with the original prologue and AAPCS64 | Output destination identities and transport-status handling | Compare live registers/frame or execute a joined original caller; output pointers are private, valid and disjoint in these cases |
| RP6 | Cleanup requests return normally without touching the disjoint caller outputs | Final private parser boundaries and unchanged outputs on rejection | Recover cleanup effects and aliases; the destruction call is modeled and does not retire native OOL memory |
| RP7 | Original straight-line stores and tested guards describe the inspected stub only | Local output commit boundary and fields not checked by this stub | Review preceding transport validation and alternate callers; absence of a stub check is not absence of a system-level check |
| RP8 | Independent replay and the separate byte oracle apply to the finite declared cases | Verification counts and exact copied bytes | Rebuild source capture, replay all original reads/writes, substitute independent input patterns; finite cases are not universal native-path proofs |

## Evidence and recovered interface

Primary evidence is the original machine code in `/Users/___/Downloads/zut/fairplayd.arm64e` (SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`) and `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho` (SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`). [Source capture](triage_evidence/rpc502_reply_bridge_source.json) retains 332 instructions across five spans, 14 exact instruction-role checks, three original authenticated thunks and their logical fixup targets. Authenticated thunk execution is not performed. The supplied [decompilation](com.apple.driver.FairPlayIOKit.c) at line 129688 corroborates the structure but overlays request and response stack variables. [RP1,RP5]

```text
request502 -> demux header initialization -> application call (not executed)
                                             |
                                  declared status and outputs
                                             |
                       original response continuation at 0x1000051fc
                         /                                  \
              status != 0                              status == 0
             simple36, ID602                       complex384, ID602
                         \                                  /
                          declared internal representation
                                             |
                     original kext parser at ...a5a20fc
                         /                                  \
              rejection/error                         validated success
              destroy request                    records + OOL outputs
```

| Component | Original site / interval | Established local role |
| --- | --- | --- |
| Daemon demux prefix | `0x100005274`-`0x100005298` | Reply bits = incoming bits &31; size36; destination = incoming remote name; local/voucher=0; ID=request ID+100 modulo 2^32 |
| Application call boundary | `0x1000051f8` -> `0x100422d48` | Status and fixed/OOL output ABI; application is not executed in this increment |
| Error serialization | `0x100005200`-`0x100005214` | Store u32 error at+32 and NDR8 at+24; retain simple size36 |
| Success serialization | `0x100005228`-`0x100005260` | Copy output counts into descriptor extents; write NDR; set complex bit, size384 and count2 |
| Kext post-transport parser | `0xfffffe000a5a20fc`-`...a5a229c` | Classify transport result, validate reply, copy outputs or request destruction |

The descriptor flags were initialized before the application call at `0x1000051a0` and `0x1000051a8`. The response-continuation fixtures preserve that initialization and supply explicit application output bytes. The demux prefix is executed separately on a private request. Its exact produced header becomes the response fixture; later application execution and intervening framework state are not thereby joined. [RP2,RP3,RP8]

## Successful reply and caller output ABI

All offsets are in bytes from the relevant message base. The 8-byte header-width difference is a representation distinction, not evidence that native IPC uses a raw insertion operation. [RP1,RP4]

| Field | User offset | Internal offset | Extent / value |
| --- | --- | --- | --- |
| Descriptor count | `0x18` | `0x20` | 4 bytes; value2 |
| OOL0 address | `0x1c` | `0x24` | 8 bytes |
| OOL0 flags / extent | `0x24` / `0x28` | `0x2c` / `0x30` | 4 bytes each; producer flags `0x01000101` |
| OOL1 address | `0x2c` | `0x34` | 8 bytes |
| OOL1 flags / extent | `0x34` / `0x38` | `0x3c` / `0x40` | 4 bytes each; producer flags `0x01000101` |
| NDR | `0x3c` | `0x44` | 8 bytes |
| Fixed record0 | `0x44` | `0x4c` | 136 bytes |
| Fixed record1 | `0xcc` | `0xd4` | 172 bytes |
| Repeated lengths0/1 | `0x178` / `0x17c` | `0x180` / `0x184` | 4 bytes each |
| Inline total | 384 | 392 | Excludes OOL payload and trailer |

Arithmetic: user `24+4+2*16+8+136+172+2*4 = 384` bytes; internal `32+4+2*16+8+136+172+2*4 = 392` bytes. The previously recovered receive capacity is `392+8 = 400` bytes including a minimal trailer. See [kernel transport](kernel_rpc_transport_report.md). All counts are u32; address values are 64-bit words. [RP1,RP4]

| Kext argument | Entry location | Successful value / source |
| --- | --- | --- |
| 7 | X6, saved in X21 | Pointer to caller record0; receives internal `[0x4c,0xd4)` |
| 8 | X7, saved in X20 | Pointer to caller record1; receives internal `[0xd4,0x180)` |
| 9 | Entry SP+0; frame X29+`0x10` | OOL0 address output pointer; receives u64 at internal+`0x24` |
| 10 | Entry SP+8; frame X29+`0x18` | OOL0 count output pointer; receives u32 at internal+`0x30` |
| 11 | Entry SP+16; frame X29+`0x20` | OOL1 address output pointer; receives u64 at internal+`0x34` |
| 12 | Entry SP+24; frame X29+`0x28` | OOL1 count output pointer; receives u32 at internal+`0x40` |

Here entry SP denotes the function's SP before its `0x1e0`-byte allocation; X29 is the established frame pointer. Argument11's `NDR_record_t *` in the decompilation is misleading: the stack slot named `v36` held request NDR before transport but contains response descriptor1's address afterward. A descriptive raw-word type is `uint64_t *ool1_out`; the caller's ultimate copy-object type requires the transport and consumer contracts. The actual reply NDR at internal+`0x44` is not copied to that output. [RP1,RP4,RP5]

Record0 stores occur at `...a5a21fc`-`...a5a2224`. Record1 stores occur at `...a5a2238`-`...a5a2270`; its unaligned 16-byte store at output+`0x9c` ends at byte172 and overlaps the preceding vector store. OOL0 address/count are stored at `...a5a2278`/`...a5a227c`; OOL1 at `...a5a2284`/`...a5a2288`. The independent byte oracle checks the complete resulting records and both pairs. These parser slices never fetch bytes from either returned OOL address. Payload schema, application meaning and downstream release timing remain unknown in this increment. [RP5,RP7,RP8]

## Error channels and acceptance boundary

Transport status W0 is tested before reply inspection. For nonzero status the stub returns that same u32. Values `0x10000002`, `0x10000003` and `0x10000010` call thunk `...a69f384`; other nonzero values call `...a69f364`. Original slots identify these as `_mig_put_reply_port` and `_mig_dealloc_reply_port`, respectively; both are BTI/RET in this image. The matched transport's actual thread-bound receive endpoint has a separate lifetime. [RP1,RP5,RP6]

| Condition after transport result0 | Result u32 / signed interpretation | Destruction requested |
| --- | --- | --- |
| Reply ID71 | `0xfffffecc` / -308 | Yes |
| Other ID except602 | `0xfffffed3` / -301 | Yes |
| Simple602; size44, remote64=0, nonzero error32 at+`0x28` | Same application error bits | Yes |
| Other simple602, including error0 | `0xfffffed4` / -300 | Yes |
| Complex602; all guards below pass | 0 | No |
| Complex602; any guard fails | `0xfffffed4` / -300 | Yes |

Successful complex guards are: descriptor count2; internal size392; null remote64 field; both descriptor type bytes1; descriptor0 extent equals repeated0; descriptor1 extent equals repeated1. This stub does not compare local/voucher fields, NDR bytes, other descriptor flag bytes, OOL addresses, or fixed-record contents. No semantic acceptance by a downstream consumer follows from these local checks. [RP1,RP7]

Every rejection after transport success converges on `...a5a2294`, with a destruction call at `...a5a2298` passing the internal message base. The target is `0xfffffe000bcf5ea4`, which conditionally processes complex descriptors, a non-null/non-sentinel remote object and complex-body cleanup. This increment captures that code but models its effects. There are no caller-output stores before the successful guard sequence completes; all 21 tested nonzero-result cases preserve the disjoint private outputs. This does not specify aliasing behavior or whether outputs are useful after any error. [RP5-RP8]

| Kext thunk | Original slot | Logical target | Role |
| --- | --- | --- | --- |
| `0xfffffe000a69f314` | `0xfffffe000847c4b8` | `0xfffffe000bcf5ea4` | Kernel message destruction request |
| `0xfffffe000a69f364` | `0xfffffe000847c4e0` | `0xfffffe000bcf5f24` | `_mig_dealloc_reply_port`, no-op |
| `0xfffffe000a69f384` | `0xfffffe000847c4f0` | `0xfffffe000bcf5f2c` | `_mig_put_reply_port`, no-op |

The original [kernel transport report](kernel_rpc_transport_report.md) supplies exact symbol provenance for the no-op targets. Pointer normalization here does not authenticate either thunk on hardware. [RP1,RP6]

## Validation, bounded continuation and quality gates

[Profiles](triage_evidence/rpc502_reply_bridge_profiles.json) contain 36 cases / 1,071 original instruction visits: one demux prefix, seven response completions and 28 kext consumers. Four emitted complex replies use count pairs `(0,0)`, `(1,37)`, `(4096,8192)` and `(UINT32_MAX,UINT32_MAX)` with opaque address words; no corresponding OOL allocation is made. Three application errors use -300, -309 and5. Seven declared user/internal transfers preserve exact body bytes; 15 field variants and six transport-status cases separate local guards from untouched fields. [RP2,RP4,RP8]

[Checks](triage_evidence/rpc502_reply_bridge_checks.json) freshly recapture the source, independently replay all 1,071 visits, 502 reads / 3,349 bytes, 337 writes / 2,524 bytes, 36 final boundaries and 21 declared cleanup/no-op models. A separately implemented ABI oracle checks return values, destruction requests, unchanged outputs on error, exact record copies and packed OOL outputs. Seven parser cases return0; 21 preserve outputs with a nonzero result; 15 request destruction. Finite CPU evidence and source inspection are identified separately. No SMT theorem or native application success is claimed. [RP6,RP8]

Reproduction, from the extracted directory, in order:

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_reply_bridge.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_reply_bridge.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_reply_bridge.py
```

All scripts operate on original-file reads and private CPU state. Capture is O(captured bytes); generation/replay is O(cases * instruction visits), with O(private RAM + retained journals) space. No host Mach send, kernel invocation, native OOL operation, IDB mutation or memory-store update is performed. The full interface investigation remains active. [RP1-RP8]

| Impact | Remaining interface / bounded opportunity | Evidence needed |
| --- | --- | --- |
| High | Native reply copyin and descriptor-object handoff | Join daemon VM regions to kernel copy objects, bit37 pointer handling and final parser header state |
| High | Actual successful application output | Reach application status0 from independently established inputs; compare all fixed/OOL outputs without supplying them as fixtures |
| High | Caller prototype and downstream ownership | Trace the six outputs past this stub and identify each release/retention site; preserve the argument11 type correction |
| Medium | Layer-local validation boundary | Separate fields validated by Mach transport from this generated stub and later semantic consumers |
| Medium | Build pairing | Attest daemon, cache and collection identities together before treating static compatibility as runtime interoperability |
| Low | Historical trace coverage | Search the annotated RAX trace for an actual reply602 and distinguish it from startup-only or failed-emulation events |

- QG1: Pass. Factual static and private-model interface analysis.
- QG2: Pass. RP1-RP8 identify dependencies and falsification probes.
- QG3: Pass for this response-ABI increment. Native conversion, actual application success and the full objective remain open.
- QG4: Pass. Byte layouts, arithmetic, u32/u64 widths, finite counts and reproduction complexity are explicit.
- QG5: Pass for scope. Transport, simple and complex replies; opaque fields; overlapping vector stores; copy-object ownership and disjoint-output assumptions are separated.
- QG6: Pass. Original hashes/bytes/fixup targets, decompilation limitations, fresh replay and independent byte oracle are retained.
- QG7: Pass. Impact-labeled continuation is bounded to the reply chain and its immediate consumers.

Publication checks: [preservation](triage_evidence/rpc502_reply_bridge_delivery.json), [scoped gates](triage_evidence/rpc502_reply_bridge_quality_gates.json).
