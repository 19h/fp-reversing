# Source-produced request through descriptor copyout and user-message packing

Eight private receiver executions now consume the exact queued requests and type3 copy objects produced by the original FairPlayIOKit constructor path. Original descriptor validation, common VM copyout, header consumption, descriptor/header/trailer packing and receive return execute through status 0. Independent byte oracles verify an 80-byte user-form request, an 8- or 68-byte trailer, and 29 out-of-line string bytes. No replacement request, copy object or backing payload is imported at the descriptor boundary.

VM allocation, user byte-copy effects, raw retirement, receiver context and logical PAC remain explicit contracts. Native task address spaces/protections, scheduling, allocator effects, daemon entry and a complete FairPlay exchange remain unknown. The [ZUT capture](zut_trace_report.md) still supplies historical failed-open evidence, not a captured successful request exchange.

## Evidence and composition boundary

Original KC SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Addresses below are unslid logical KC addresses. The four [constructor/VM-copy/request producers](kernel_request_copyin_report.md) are freshly replayed, then complete final RAM/globals supply the receiver setup. The source packet, copy header/backing, sender thread and reply linkage survive setup byte-for-byte. Receiver task/namespace/map/loan context remains a separate explicit epoch.

| Artifact | Contents |
| --- | --- |
| [Source](triage_evidence/kernel_request_delivery_source.json) | 148 complete kernel functions / 20412 instructions; sixteen additional captured bodies / 2005 instructions; nine delivery-role instructions |
| [Profiles](triage_evidence/kernel_request_delivery_profiles.json) | Four source receiver-loan constructors and eight original descriptor/user-delivery cases |
| [Checks](triage_evidence/kernel_request_delivery_checks.json) | Independent before-image, user-wire/trailer/OOL, object/ownership/order oracles, fresh CPU replay and two scalar packing proofs |
| [Preservation](triage_evidence/kernel_request_delivery_delivery.json) | Prior 6343 artifact hashes and six owned reporting changes |
| [Quality gates](triage_evidence/kernel_request_delivery_quality_gates.json) | QG1-QG7 and exact conditional evidence scope |
| [Prior manifest](triage_evidence/kernel_request_delivery_prior_manifest.json) | SHA-256 `11b3492bf8951bc695fd337bdc267d240ae473c1732670897198dd9db8c6aec8` |

```text
original constructor -> VM-copy factory -> actual caller -> original RPC queue
                                   |
                     exact complete queued-state transfer
                                   |
     receiver context + source loan -> original lookup/dequeue/header names
                                   |
             original descriptor validator accepts produced type3 object
                                   |
             original common copyout -> VM allocation [contract]
                                   |
          backing 29 -> receiver OOL region [user-byte-copy contract]
                                   |
             original header clear/zero -> raw retirement [contract]
                                   |
             original descriptor/header/trailer packing
                                   |
       user message80 + trailer8/68 [user-byte-copy contract]
                                   |
             original kmsg256 zero -> raw retirement [contract]
                                   |
                     original receive C frontend returns0
```

Captured source combines prior datasets; all 148 bodies are recaptured, but not all branches or captured bodies execute. The public `_vm_map_copyout` wrapper is captured for its identity relationship; the actual descriptor path calls the common implementation directly. The resulting user bytes remain private emulated observations, not a native userspace delivery or scheduler/trap event.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| UD1 | Original KC and preserved producer artifacts identify the target source. All address/semantic claims depend on this. | Recapture hash, compiler bounds, nlist records, roles and every visited instruction. Live build pairing remains unknown. |
| UD2 | The four original constructor/request producers retain their inherited primitive/environment contracts. End-to-end source byte provenance depends on these contracts. | Freshly replay each producer; compare full transferred RAM/globals and exact packet/copy/backing preservation. Native backing and host registration remain unknown. |
| UD3 | Separate receiver task/owner/SMR/namespace/map context and explicit source-loan publication represent a consistent private epoch. | Independently reconstruct every before image, type cell, table entry, map range and source loan. Native task identity, registration and scheduler causality remain unknown. |
| UD4 | Class19's declared allocator view has element extent48 in addition to its inherited identity/statistics pair. Copy-header zero/free ABI depends on this. | Compare48-byte source construction, original zeroing and raw-free arguments; recover the actual zone-creation writer. Native class19 creation remains unknown. |
| UD5 | VM allocation returns the declared aligned 16384-byte receiver range; two lower user-copy operations succeed with exact source bytes. User/OOL observations depend on these contracts. | Check map bounds/alignment, register and stack arguments, copied bytes and guards independently. Native allocation, page contents, access/protection checks, faults and address-space switching remain unknown. |
| UD6 | Keyed hashes and raw turnstile/backing/header/kmsg retirement return the declared outcomes. Integrity and cleanup reachability depend on these contracts. | Verify hash inputs, raw before records, reference/state changes, original zeroing and release order. Actual allocator reclamation is not executed. |
| UD7 | Logical data/return PAC tracks original operands without cryptographic authentication. | Recapture instructions, pointers/modifiers and full CPU states. Hardware PAC acceptance remains unknown. |
| UD8 | Four producer families times two accepted capacities bound execution: map64, one type1 descriptor containing a type3 object of extent 29, and no voucher. | Reproduce all cases and two packing proofs. Other extents/types/maps, failures, concurrency, framework hooks and daemon processing remain unknown. |

## Original interfaces and callsites

Descriptions below are recovered roles unless an exact nlist identity is stated. All field widths and values refer to this pinned source and supplied context.

| Original location | Interface / source effect | Established result |
| --- | --- | --- |
| `0xfffffe000bcc5564` | Descriptor copyout | Continues the prior [receiver frontier](kernel_request_receive_report.md) with the produced object |
| `0xfffffe000bcc5698` -> `0xfffffe000bdd148c` | Original VM-copy validator | Range/type-class19 check; type3 extent 29 equals descriptor extent 29; returns true |
| `0xfffffe000bcc56e8` -> `0xfffffe000bdcb374` | Common VM copyout | `(receiver_map,&address,produced_copy,29,1)` |
| `0xfffffe000bdcbbb0` | Type3 copyout helper | Original copy, consume and ownership sequencing |
| `0xfffffe000bdc76b4` | Lower VM allocation boundary | Requested extent 16384, register options0; stack u32 words `(3,7,1)` |
| `0xfffffe000be7798c` | Lower user-byte-copy boundary | First copies 29 backing bytes to OOL; later copies 88/148 packed bytes to inline buffer |
| `0xfffffe000bcfec48` | Backing retirement boundary | `(descriptor 0xfffffe0007f8bfb0,backing,29)` after original header pointer clear |
| `0xfffffe000bd74fcc` | Raw zone retirement boundary | Class19 header48 and class24 kmsg256 after original zeroing; destination turnstile also retired separately |
| `0xfffffe000bcc55b4` / `...55b8` | Descriptor result stores | Original code replaces copy pointer with receiver VA and writes extent 29 |
| `0xfffffe000bcdcf9c` -> `0xfffffe000bcc62d0` | Final put-to-user/packing routine | Original scalar packing, trailer selection and byte-copy request |
| `0xfffffe000bcc663c` | Header name narrowing | Original vector narrowing packs translated names into 32-bit user fields |
| Original receive frontend return | Preserved C caller return | X0=0, SP restored; no native user-return/trap execution |

No whole descriptor validator, VM-copyout implementation, message-packing routine, header-zeroing helper or kmsg-zeroing helper is replaced by a success model. Lower VM allocation and user-byte-copy operations remain contracts. Source code calls the common copyout target used by exact exported `_vm_map_copyout` at `0xfffffe000bdd1574`; the exported wrapper itself is not entered in these cases. [UD4-UD8]

## Exact user-form message and out-of-line data

R=`0x6500000000` is the private arena base. The inline buffer is R+`0x1000`; declared receiver OOL VA is R+`0x4000`, a 16384-byte observation aligned to 16384 bytes. Receiver map bounds `[R,R+1048576)` contain both. These coordinates stand in for task virtual addresses in one private CPU map; actual task address-space separation/protection is not emulated by these byte effects.

The original constructor input is the synthetic 28-byte C-string pattern `byte[j]=0x21+(j mod90)`, followed by NUL. The OOL region's first 29 bytes exactly equal that producer input. Remaining observation bytes and its guard remain `0xa5`; this is not evidence that native VM allocation initializes pages that way. The inline buffer is independently reconstructed in full:

| User-message offset | Width, bytes | Value / provenance |
| --- | ---: | --- |
| `0x00` | 4 | Header bits `0x80001112` |
| `0x04` | 4 | Inline size 80 |
| `0x08` | 4 | Reply send-once name `0x207` from original receiver namespace publication |
| `0x0c` | 4 | Service receive name `0x303` for502 or `0x403` for 700 |
| `0x10` | 4 | Voucher name 0 |
| `0x14` | 4 | Request ID 502 or 700 |
| `0x18` | 4 | Descriptor count 1 |
| `0x1c` | 8 | Declared receiver OOL address R+`0x4000` |
| `0x24` | 4 | Packed descriptor flags `0x01000101` |
| `0x28` | 4 | Descriptor extent 29 |
| `0x2c` | 8 | Original NDR bytes `0000000001000000` |
| `0x34` | 4 | Repeated extent 29, preserved from constructor |
| `0x38` | 8 | Supplied CPU type `0x0100000c` |
| `0x40` | 8 | Supplied CPU subtype 0 |
| `0x48` | 8 | Supplied origin scalar 1 |

Both port names are private namespace values, not native or ZUT endpoint identities. Receiver reply-right publication is not a reply-message send. No new Mach-message emission site is introduced: the source request send remains `0xfffffe000bcf5ba8`.

The 16-byte memory descriptor retains its width for the supplied map64 context. The 32-byte internal header contracts to 24 bytes, so 88 internal bytes become 80 user bytes. Original packing narrows translated namespace names; it does not truncate raw kernel port pointers into names. Descriptor flags change from `0x01000100` to `0x01000101`: the source packer rebuilds the deallocate byte from its copy-method byte. [UD3,UD5,UD8]

| Receive configuration | Inline bytes | Trailer bytes | Total copied bytes | Scope |
| --- | ---: | ---: | ---: | --- |
| Options 2, capacity 88 | 80 | 8 | 88 | Kernel receive/packing succeeds; full audit prefix is not delivered |
| Options `0x07000002`, capacity 148 | 80 | 68 | 148 | Complete source kernel trailer, including 32-byte audit token, is delivered |

The extended trailer has type 0, advertised extent 68, sequence 0, security words `(0,1)` and eight zero audit words. Its context/remainder fields are zero in the supplied epoch. The audit bytes originate in the producer's original null-task kernel template, not the constructor's separate origin scalar or an observed initiating user identity. The full delivered trailer is checked byte-for-byte.

The [installed CF receive path](cf_receive_report.md) previously established capacity 3072 and option selection for a 68-byte map64 trailer. The capacity 148 case here is the exact required message-plus-trailer extent for this 80-byte request. No CF hook or daemon code executes in this increment. In particular, the successful 8-byte-trailer kernel case must not be treated as proof that the daemon's audit-dependent MIG path accepts it. [UD2,UD5,UD8]

## Ownership and cleanup at the C return

Original code clears the copy header's backing pointer before requesting backing release. It then executes all 48 header-zeroing bytes before raw header retirement. The two user-byte-copy contracts run in order: backing 29 ->receiver OOL region, then packed inline/trailer 88 or148 ->receiver buffer. Original kmsg cleanup subsequently executes all 256 zeroing bytes before its raw retirement.

| State at return | Established private result |
| --- | --- |
| Destination object refs / send rights | 3 /1; sender RPC hold remains outstanding |
| Reply refs / send-once count | 2 /1; reply right remains in receiver namespace |
| Queue head / count / sequence | NULL /0 /1 |
| Reply linkage state / union | 4 /NULL; sender owner and binding preserved |
| Destination send turnstile | Original 96-byte zeroing before raw retirement contract |
| Receiver turnstile loan | Preserved source-constructed loan and explicit thread publication |
| Type3 header | 48 zero bytes before raw retirement contract |
| Copy backing observation | Original 29 bytes remain physically visible in the private map after release request; ownership is not inferred from those bytes |
| Kmsg | 256 zero bytes before raw retirement contract |
| Receiver thread's stored kmsg pointer | Stale pointer bits remain; pointee observation is zeroed |
| Receiver map/current-map field | Declared map preserved; reference 3 restored/preserved |
| User/OOL observations | Exact packed message/trailer and 29 source string bytes; guards preserved |

These are intermediate ownership results. The sender has not received a daemon reply. Native allocation/free, VM persistence, protection and reference concurrency remain unknown. No leak, native use-after-free or completed request/reply lifecycle is inferred from retained pointer or byte observations. [UD2-UD8]

## Validation and reproduction

Four freshly replayed constructor/request producers contribute 26506 original visits. Four receiver-loan constructors and eight delivery executions contribute 20916 visits: four 54-instruction loan constructors, four 2580-instruction minimal-trailer paths and four 2595-instruction extended-trailer paths. Independent receiver replay checks 5012 writes / 28924 bytes, 5036 reads / 32624 bytes, 76 declared primitive calls, 112 descriptor/VM/user-delivery ABI frames and 12582912 final RAM bytes. The inherited receiver joins add 24 full CPU/RAM handoffs; descriptor validation/VM/packing add 32 further full-state handoffs. Fresh producer counts are retained separately.

Independent complete wire/trailer/OOL oracles cover all eight cases. Complete port/namespace/thread/loan/map/accounting records and globals are checked against their source-based expectations. Sixteen header/kmsg zeroing-before-retirement checks cover 48 and 256 bytes per case. The 24 independently reconstructed primitive patches total `8*(8+29)+4*(88+148) = 1240 bytes`: one allocation-output write plus two user-byte-copy effects per case. Original source performs the zeroing; those writes are not primitive patches.

Two scalar UNSAT queries check descriptor-flag deallocate-byte reconstruction across all 32-bit flag words and lossless narrowing of translated namespace names restricted to u32 values. They do not generalize the finite VM/capacity/context executions to arbitrary native inputs.

```sh
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_request_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_request_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_request_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/seal_kernel_request_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/verify_kernel_request_delivery_publication.py
```

Recovery/CPU validation cost is O(image bytes + source visits + copied RAM bytes + journal effects) time and O(image bytes + one CPU RAM map + journals) working space. Each private RAM image is 1048576 bytes. Addresses, widths, counts and byte arithmetic are exact. Native timing, error probabilities, memory ownership and physical page state remain unknown.

## Bounded remaining evidence

| Impact | Question | Resolving evidence |
| --- | --- | --- |
| High | Does this exact packed request enter the intended daemon MIG handler and application path? | Transfer these produced user bytes, OOL bytes and full extended trailer through the source-pinned daemon receive/dispatch path. Keep framework callbacks and actual namespace identity explicit. |
| High | What creates the actual class19 zone/view and provides matching map/backing provenance? | Recover original initialization/allocation writers and matched runtime state. Current view element size and raw storage are declared premises. |
| High | What do the lower VM/user-copy primitives enforce? | Establish native map/protection/fault/context-switch behavior or execute original implementations with source-derived state. The present byte effects cannot attest it. |
| Medium | How do body-copy or allocation failures affect published reply rights and partially converted messages? | Continue original error/cleanup/packing paths with explicit outcomes and ownership ledgers. Current cases all use successful lower contracts. |
| Medium | How does the daemon reply return through the outstanding kernel RPC and release remaining holds? | Produce the response from the daemon path, then join reply emission, kernel receive/copyout and actual kext continuation. |
| Low | Which other descriptors, map widths, vectors, extents and audit paths apply? | Recover source partitions and appropriate producer contexts independently; current type1/type3/map64 cases do not cover them. |

## Quality gates

- QG1: Technical source/IPC/ABI analysis; no normative conclusion required.
- QG2: UD1-UD8 identify assumptions, dependent results and concrete falsification probes.
- QG3: Produced-object validation, descriptor conversion, exact user/OOL/trailer bytes, namespace/right state, cleanup order, original return and respective reporting updates are covered. The full interface goal remains active.
- QG4: Exact byte counts, widths, allocation rounding, patch totals, arithmetic domains, complexity and executable reproduction are recorded.
- QG5: Internal88 versus user80 bytes, minimal versus full audit trailer, private byte effects versus native task mappings, stale bytes versus ownership and C return versus actual daemon delivery are reconciled explicitly.
- QG6: Original complete bodies, exact nlist records, nine instruction roles, every visited instruction, fresh producer states and independent CPU/wire/object/effect oracles provide primary provenance.
- QG7: Impact-labeled continuation targets exact daemon consumption, zone/map provenance, lower VM semantics, error/ownership paths and reply completion; native exchange remains unknown.
