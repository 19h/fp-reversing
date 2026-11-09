# Source-produced no-senders packet through original kernel send preparation

The source-produced ID70 packet now passes through original send-only preparation, right-copyin, trailer setup and common send control, then resumes its original notification caller. All four message-storage layouts complete. The helper's optional output marks successful kernel right-copyin before queueing; it remains1 in tested later-error cases. A queue result 0x10000003 takes a different cleanup/status route from preparation result 0x10000003. Allocation, byte copying, keyed-hash results, validation/tag helper, locks, queueing and retirement effects remain explicit models. Native delivery, right consumption and authentication remain unknown. [NS1-NS8]

Evidence: [ten complete routines /1503 instructions and separate opaque keyed-hash bytes](triage_evidence/kernel_notification_send_source.json), [52 private CPU components](triage_evidence/kernel_notification_send_profiles.json), [fresh producer/replays, state oracles and three scalar proofs](triage_evidence/kernel_notification_send_checks.json). Collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Original files suffice; no new IDA access, IDB/memory-store mutation or native target/IPC occurs. Captured bodies do not imply all-branch execution; allocator/buffer-free bodies remain unexecuted.

## Original call chain and relation to FairPlay

| Site or entry | Local contract |
|---|---|
| `0xfffffe000bcd0598` -> `0xfffffe000bcf55dc` | Source notification caller supplies `(packet,44,0x50001,0,NULL)` |
| `0xfffffe000bcf561c` -> `0xfffffe000bcc68c4` | Prepare kernel message, using caller-local kmsg output pointer |
| `0xfffffe000bcc6944` -> `0xfffffe000bcc24a4` | Allocation request `(44,0,0,1)` in the valid noncomplex cases; result modeled |
| `0xfffffe000bcf562c` -> `0xfffffe000bcc6b10` | Kernel-form right/header copyin |
| `0xfffffe000bcc6bc0` -> `0xfffffe000bcc9718` | Destination pointer and disposition18; selected MOVE_SEND_ONCE branch |
| `0xfffffe000bcc6d2c` -> `0xfffffe000bcc4194` | Original trailer/canonical-input construction |
| `0xfffffe000bcf5684` -> `0xfffffe000bcc7040` | Common send `(kmsg,effective_options,timeout)` |
| `0xfffffe000bcc724c` -> `0xfffffe000bcc7c34` | Queue request `(destination+0x28,kmsg,options,timeout)`; result modeled |
| `0xfffffe000bcf563c` -> `0xfffffe000bcc2974` | Buffer-free request following right-copyin failure |
| `0xfffffe000bcf5698` -> `0xfffffe000bcc2c40` | Wrapper destruction request `(kmsg,0)` after propagated send error |
| `0xfffffe000bcd059c` | Actual helper return into notification caller; original branch/epilogue executes to its caller return |

The [FairPlay kernel RPC route](kernel_rpc_transport_report.md) uses the same preparation, right-copyin and send entries at original call sites `0xfffffe000bcf5a48`, `0xfffffe000bcf5b40` and `0xfffffe000bcf5ba8`. All three BL instructions and the complete original common-RPC range are recaptured. Shared implementation does not establish a shared destination, protocol or process. RPC request/reply setup and its thread reply endpoint remain distinct from this send-only notification. [NS1,NS6,NS8]

```text
original last-send caller -> source-built ID70 packet
  -> original send-only wrapper
       -> original preparation + declared allocation/byte copy
       -> original kernel right-copyin, disposition18
       -> original trailer inputs + opaque keyed-hash results
       -> original common send + declared preflight/queue outcome
       -> original stage-specific cleanup requests
  -> actual notification caller return -> original outer epilogue
```

## Exact source state and explicit environmental epochs

The [notification producer](kernel_send_right_lifecycle_report.md) is replayed afresh. Every new component restores its complete 1048576-byte RAM image, all 31 GP registers, SP, NZCV, SIMD registers and declared globals at the send-helper boundary. Explicit overlays then provide the allocator's initialized kmsg/storage pointers, observation buffers, destination receiver identity, thread flag epoch and optional output canary. Two globals supply a distinct kernel-space identity and a zero send-policy byte. Controlled size/options/output-pointer and target-state variants are recorded separately. Thus producer state is exact before declared initialization/ABI substitutions; this is not wholly unchanged-memory native continuity. [NS2,NS3]

The original packet is 44 bytes with a 32-byte kernel-form header: destination disposition18, pre-send header size 0, destination kernel pointer, NULL reply, voucher0, ID70, original NDR and make-send count7. Its bytes remain unchanged by preparation, except for the explicitly substituted NULL-destination probe. Preparation copies the explicit 44 bytes and stores 44 at internal header+4 at `0xfffffe000bcc69f0`. The source size 0 is therefore not the normalized internal size. These are kernel pointer/right inputs; they are not task-local port names or arbitrary user-message namespace inputs. [NS3,NS4]

Let K be the declared kmsg pointer, H an external header buffer and D an external body buffer. The class is kmsg+0x3f bits 6..7:

| Class | Header | Body / trailer | Original byte-copy plan |
|---|---|---|---|
| 0 | K+0x40 | Header+32 / header+44 | One 44-byte copy |
| 1 | K+0x40 | D / D+12 | Header 32 bytes, then body 12 bytes |
| 2 | H | H+32 / H+44 | One 44-byte copy |
| 3 | H | D / D+12 | Header 32 bytes, then body 12 bytes |

Allocator layout is a premise. The 1024-byte kmsg and 256-byte external observation windows are private observation extents, not established native allocation/zone sizes. Logical authenticated pointer loads execute around external buffers; hardware PAC does not. Selected disposition18 returns from the original right-copyin helper without additional destination send/send-once/object counter stores before common send. This is a move-existing-right interface; actual consumption by queue/destructor remains outside the modeled leaves. [NS2-NS5]

## Optional output, status and cleanup stages

The wrapper clears a non-NULL X4 u32 output at entry and sets it to 1 at `0xfffffe000bcf564c` only after preparation and kernel right-copyin return zero. Queueing follows later. The original notification caller always passes NULL; non-NULL output tests are explicit ABI variants. This supplies concrete semantics for the send-only `message_moved` input previously modeled in the [IORPC report](iorpc_remote_report.md): the local signal marks the copyin milestone and does not attest queue delivery. It does not establish an actual one-way FairPlay/IORPC caller. [NS3,NS5,NS8]

| Declared condition / stage | Helper status | Optional output | Original cleanup request |
|---|---|---|---|
| Send extent31, below kernel header minimum32 | 0x1000000e | 0 | No allocation/copy/send |
| Allocation returns NULL | 0x1000000d | 0 | No copied kmsg to free |
| Copied header has NULL destination | 0x10000003 | 0 | Buffer-free request at `...bcf563c` |
| Queue returns 0 | 0 | 1 | No destruction request in this path |
| Queue returns5 | 5 | 1 | Wrapper requests destruction `(kmsg,0)` |
| Queue returns 0x10000003 | 0 | 1 | Common send drops destination object reference and requests destruction `(kmsg,1)` |
| Queue returns 0x10000004, 0x10000007 or0x1000000d | Same raw code | 1 | Failure helper, then wrapper destruction `(kmsg,0)` |
| Target inactive at common send | 0 | 1 if supplied | Unlock request, original object-reference drop, destruction `(kmsg,1)`; no queue request |

Queue-error output 1 is explicitly checked for codes 5 and 0x10000003, alongside successful output cases. The inactive-target fixtures use the original NULL output argument. Their target-state substitution occurs after packet construction; this is a conditional local state epoch, not an observed concurrent transition. Allocation NULL and short/NULL-destination inputs are branch probes, not proof of native allocator failure or a real sender producing those arguments. Native allocator waiting/guarantees and those prerequisites remain unknown. [NS2,NS5-NS8]

For the tested ordinary receiver branch, failure-helper classification uses `n=u32(status-0x10000003)`, `n<=10` and bitmap 0x413. An all-u32 proof establishes exactly the set `{0x10000003,0x10000004,0x10000007,0x1000000d}`. Cleanup flags0/1 and raw status values are reported as observed call arguments; a complete destruction-mode/return-code taxonomy is not assigned. Destruction/failure callbacks are no-effect models. The original reference decrement is distinguished from native send-once consumption and allocator retirement. [NS5-NS7]

All 52 components reach original return site `0xfffffe000bcd059c` and execute the notification caller's branch/epilogue. The caller does not inspect the helper result in this suffix or restore the cleared no-senders request. These selected injected failures do not establish a native leak, failure reachability or complete reference imbalance. [NS6-NS8]

## Option/thread and authentication context

The wrapper always clears option bit 37 before preparation. For thread word+0xc8 bit 11 clear, its common-send options are `cleared_options | ((~(raw_options>>1)) & 0x40000)`. For bit 11 set, it also clears option bit 18. Common send then tests thread bit 10: when set, it clears option bit 16, sets bit 4 and clears thread bit 10. No broader flag names or external-control provenance are assigned. Two all-input bit-vector proofs cover the retained64-bit option/16-bit thread formulas; original CPU cases cover all four selected flag combinations. [NS4,NS5]

| Thread flags, raw options 0x50001 | Wrapper common-send options | Queue options |
|---|---|---|
| 0 | 0x50001 | 0x50001 |
| 0x400 | 0x50001 | 0x40011 |
| 0x800 | 0x10001 | 0x10001 |
| 0xc00 | 0x10001 | 0x11 |

Setting raw bit 37 in the paired option variants leaves these outputs unchanged. Receiver identity, zero policy byte and thread word are explicit environmental fixtures; actual native producers/control remain unknown. [NS2,NS4]

Trailer setup writes the original 68-byte kernel template, then supplies a 36-byte canonical masked header/count and that 68-byte trailer to the previously identified PACGA-based keyed hash at `0xfffffe000bc9d90c`. Its180 source bytes and five PACGA sites are retained separately from the 1503 complete-function instructions. Runtime key/hash values are unknown. Both returns are modeled as `0x123456789abcdef0`; original code stores the second result's high32 bits, 0x12345678, at kmsg+0x38. A separate message tag/validation helper is also modeled. Exact inputs and a synthetic signature field do not establish native authentication. [NS1,NS6,NS7]

## Assumption register and verification

| ID | Premise / dependent claims | Stress test or falsification probe |
|---|---|---|
| NS1 | Pinned collection, prior raw keyed-hash record and original RPC edges identify this build | Recapture all bodies, visited words, table/template and three shared BL sites; match deployed build separately |
| NS2 | Allocator layout, receiver/kernel-space identities, thread flags and zero policy byte define private epochs | Recover native initialization, actual allocation sizes/guarantees, receiver association and policy/flag writers |
| NS3 | Exact producer state precedes the explicitly recorded RAM/ABI substitutions | Reconstruct every overlay from source bytes and compare CPU/globals; preserve actual versus variant notification arguments |
| NS4 | Noncomplex44-byte packet and four class layouts bound copy/normalization coverage | Extend descriptor-bearing packets, arbitrary sizes and actual allocator-created storage without conflating user/kernel representations |
| NS5 | Raw queue/preflight results and selected target states exercise stage-specific control | Establish actual callback effects, failure prerequisites, concurrency and final ownership; output 1 alone is insufficient |
| NS6 | Keyed hashes, tag/validation, queue and free/destroy effects remain opaque models | Recover real key/tag verification, queue transfer, right consumption and allocator retirement |
| NS7 | Logical PAC and lock models permit local original instruction execution | Verify hardware authentication and native synchronization independently; private LSE/reference writes are not native effects |
| NS8 | Shared FairPlay/IORPC transport code and caller return do not establish authentic peer or full lifetime | Join native daemon registration, task namespace conversion, request/reply/error and close paths |

Fifty-two fresh CPU replays verify 17201 original instruction visits, 4691 reads /32856 bytes, 3608 writes /26955 bytes, 417 API models, 332 entry/return frames, 52 complete RAM images /54525952 bytes, 416 global records and all final SIMD/system states. Sixty-five independently reconstructed byte-copy calls transfer 2068 bytes. Eighty-six keyed-hash input records are checked. The source notification producer has a separate fresh replay; its visits are not included in the 17201 total. All final source-port bytes and input packet bytes are checked independently of the modeled queue/destructor effects.

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_notification_send.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_notification_send.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_notification_send.py
```

Recovery/replay time is O(image + source + visits + RAM + effects), space O(image + source + RAM + journals). Each RAM image is 1048576 bytes; all stated counts/arithmetic are exact finite observations. Three fixed-width scalar solver queries have no claimed general polynomial runtime bound.

| Impact | Further interface evidence |
|---|---|
| High | Actual kmsg allocation/layout and waiting/failure guarantees; replace initialized-object and NULL-return premises |
| High | Continue queue, failure/destructor and send-once consumption; establish native ownership beyond request arguments |
| High | Authentic FairPlay/daemon request/reply and actual one-way IORPC caller/output integration |
| Medium | Hardware keyed-hash/tag verification, receiver/thread/policy writers and descriptor-bearing storage variants |

QG1: Factual technical analysis; no normative judgment required.
QG2: NS1-NS8 register premises, dependent claims and falsification probes.
QG3: Scoped source packet, shared interfaces, normalization, rights, options, output/status, cleanup and original caller return are covered; the full goal remains incomplete.
QG4: Header/body/trailer widths, storage plans, bit formulas, counts, commands and complexity are reproducible.
QG5: Original arguments versus ABI variants, preparation output versus delivery, stage-dependent equal codes, original counter writes versus modeled retirement, and synthetic signature versus authentication are distinguished.
QG6: Original bytes, source producer, exact overlays/frames, keyed-hash input capture, scalar queries and independent CPU/effect replay provide primary provenance.
QG7: Impact-labelled continuation targets unresolved allocation, queue/rights, authentication, environmental and authentic cross-layer contracts.

[Preservation](triage_evidence/kernel_notification_send_delivery.json), [scoped gates](triage_evidence/kernel_notification_send_quality_gates.json), [publication verifier](triage_evidence/verify_kernel_notification_send_publication.py). The full goal remains active.
