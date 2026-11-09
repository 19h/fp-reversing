# Queued FairPlayIOKit requests through receiver namespace publication

The original queued RPC502/700 requests now execute through the original receive frontend, encoded namespace lookup, fast dequeue, receive-results processing and reply-right namespace publication. Eight accepted-capacity cases reach the original descriptor-copyout entry at `0xfffffe000bcc5564`. Two one-byte-short `MACH_RCV_LARGE` cases retain the original queued request and stop before receive-results processing with status `0x10004004`. No replacement packet is imported.

This joins the [constructor-to-queue evidence](kernel_rpc_request_report.md) to the existing [reply-namespace component analysis](kernel_reply_namespace_report.md). The sender and receiver are separate explicit CPU/task epochs. Descriptor VM conversion, user-buffer delivery, daemon parsing and a native exchange remain unknown. The [ZUT runtime trace](zut_trace_report.md) still ends after an unsuccessful UserClient open; these private executions do not establish a captured RPC exchange.

## Evidence and scope

Original KC SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. All code addresses are unslid logical KC addresses. Four original request producers are freshly replayed before consuming their complete final RAM/global states. The queued kmsg, both service ports, sender thread, bound reply and existing linkage are unchanged by receiver setup. Their exact preservation is independently checked.

| Artifact | Contents |
| --- | --- |
| [Source](triage_evidence/kernel_request_receive_source.json) | 123 recaptured complete kernel functions / 15666 instructions; 19 receive-role instructions; no claim of additional recovered function bodies |
| [Profiles](triage_evidence/kernel_request_receive_profiles.json) | Four original receiver-loan constructors and ten original receive executions; full RAM, CPU, object and effect journals |
| [Checks](triage_evidence/kernel_request_receive_checks.json) | Independent context/before-image plans, full object/packet/namespace/queue oracles, fresh CPU replays and two scalar proofs |
| [Preservation](triage_evidence/kernel_request_receive_delivery.json) | Prior 6317 artifact hashes and six owned reporting changes |
| [Quality gates](triage_evidence/kernel_request_receive_quality_gates.json) | QG1-QG7 for this connection and its explicit boundaries |
| [Prior manifest](triage_evidence/kernel_request_receive_prior_manifest.json) | SHA-256 `2fba86f2eed615d72c05ed939562336de7be68d6f24e2c6dfa0e9e3623b5b68c` |

```text
original constructor/request producer -> actual queued kmsg and reply linkage
                                              |
                         exact complete RAM/global state transfer
                                              |
            original receiver turnstile allocation -> explicit thread loan
                                              |
              original receive frontend and encoded receive-right lookup
                                  /                           \
              capacity 88 or 148 bytes                capacity 87 bytes
                       |                            options RCV_LARGE
              original fast dequeue                          |
                       |                            queue stays intact
              receive-results processing             status 0x10004004
                       |
              original header namespace publication
                       |
              reply name 0x207; service name 0x303 or 0x403
                       |
              STOP before descriptor copyout; user buffer unchanged
```

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RQ1 | The original KC and previous request producers identify the target source. All code and packet claims depend on this. | Verify original hash, complete compiler-bounded bodies/nlist records, every visited instruction and fresh request-producer replays. Live build correspondence is unknown. |
| RQ2 | A separately supplied receiver thread/task/owner/map/SMR context may consume the queued state. All receiver executions depend on this explicit epoch. | Check complete transferred RAM/globals, disjoint context/type regions, every ordered before image and preserved sender/queue state. Native scheduler causality and task identity are unknown. |
| RQ3 | Receiver task namespace contains the original source-initialized service receive entry and a declared free entry2. Reply publication depends on this namespace epoch. | Execute original encoded lookup, generation validation, free-entry allocation and publication; independently reconstruct the full table/global state. Actual daemon registration and native names are unknown. |
| RQ4 | Raw zeroed receiver-turnstile storage is available and the original allocator result is published to thread+0x30. Receive-results cleanup depends on this loan context. | Execute original allocator/initialization; compare the complete96-byte record and guard. The thread-loan publication is explicit; its native lifecycle producer is unknown. |
| RQ5 | The inherited request allocation/cache, staging/VM-copy, copy/hash/tag/preflight and PAC premises hold for the producer snapshot. End-to-end source composition depends on these prior contracts. | Freshly replay all four request producers and verify their dependency hashes. Source/native VM-copy backing and authentication remain unknown. |
| RQ6 | Repeated keyed-hash calls return the declared value and raw send-turnstile retirement reports success. Integrity checks and final linkage cleanup depend on these contracts. | Audit exact hash input bytes, arguments, clobbers and returned field; execute original zeroing before retirement. Native keyed hashing and allocator retirement remain unknown. |
| RQ7 | Logical PAC follows original pointer/control operands without cryptographic authentication. Pointer interpretation depends on this model. | Recapture exact instructions and verify registers/modifiers, return flow and full CPU states. Native PAC acceptance is unknown. |
| RQ8 | Ten finite receive cases and two bounded scalar proofs establish only their stated domains. | Reproduce all cases, the accepted/short-capacity boundary and complete state oracles. Non-NULL vouchers, alternate map layouts, concurrency, other rights, descriptor VM effects and daemon delivery remain unknown. |

## Routine and interface boundaries

Descriptions are recovered roles. They are not asserted as original symbol names where the original nlist is empty. Complete bodies were already present in the source set; the new evidence is their composition with the actual constructor-produced request.

| Original location | Role and ABI | Evidence in these cases |
| --- | --- | --- |
| `0xfffffe000bd682cc` | Allocate/initialize receiver turnstile; returns object in X0 | Original class28 initializer consumes declared raw96-byte storage |
| `0xfffffe000bcdd4e4` | Receive frontend `(buffer,0,options,0,0,capacity,0,receive_name)` | Source task-space accessor, encoded namespace lookup and receiver-field setup |
| `0xfffffe000bcc8cf4` | Receive-right lookup; calls encoded translation at `0xfffffe000bcd2cc0` | Original service entry lookup and temporary object retain |
| `0xfffffe000bcdd6d0` | Common receive call | `(service+0x10,0,2,receiver_thread,1)` |
| `0xfffffe000bcc8514` | Receive queue fast path and capacity selection | Original ring integrity checks, size/trailer calculation and accepted/short partition |
| `0xfffffe000bcc86e4` | Queue-head update | Accepted cases set head NULL |
| `0xfffffe000bcc86e8` | Clear removed element ring pointers | Accepted cases clear both original kmsg links |
| `0xfffffe000bcc86f8` | Queue-count store | Accepted count1 ->0 |
| `0xfffffe000bcc8758` | Receive sequence increment | Sequence0 ->1; old sequence0 saved to receiver |
| `0xfffffe000bcc87b0` | Publish received kmsg to thread+0x3b8 | Original logical PAC discriminator `0x33ff` |
| `0xfffffe000bcc87d4` | Task receive-accounting increment | One event for each accepted request; none for short-buffer cases |
| `0xfffffe000bcdd708` | Tail branch from frontend into results processing | Original CPU/stack/SIMD state retained; no scheduler continuation is supplied |
| `0xfffffe000bcdce04` | Release temporary receive object hold | Accepted cases release the namespace-lookup retain |
| `0xfffffe000bcdcf28` | Original header copyout call | `(kmsg,receiver_space,receiver_map,options)` |
| `0xfffffe000bcd5b90` | Publish reply right in receiver namespace | Original send-once publication yields name `0x207` |
| `0xfffffe000bcc5564` | Descriptor copyout entry | Execution stops with `(descriptor_pointer,1,space,map,options)` |

The fast path does not require a scheduler block in these cases. That does not establish a native context switch or exclude other scheduling paths. The receiver turnstile loan remains present and unchanged; the separate destination send turnstile is completed, zeroed and passed to the modeled raw-retirement boundary in accepted cases. [RQ2, RQ4, RQ6]

## Size, direction and namespace contracts

The original size helper at `0xfffffe000bcc4bb4` computes 80 user-message bytes from the 88-byte internal kernel request: the kernel header loses 8 bytes, and the single type1 descriptor remains 16 bytes under the supplied map state. The original trailer-size helper computes 8 bytes for options2 and 68 bytes for options `0x07000002`. Thus accepted capacities are exactly 88 and 148 bytes. The user packet itself has not been copied or fully converted at the stopping boundary.

| Request family | Source host slot | Service receive name in supplied receiver namespace | Accepted capacities / options | Published reply name |
| --- | ---: | --- | --- | --- |
| RPC502, fresh or prebound sender reply | 17 | `0x303` | 88 bytes /2;148 bytes /`0x07000002` | `0x207` |
| RPC700, fresh or prebound sender reply | 34 | `0x403` | 88 bytes /2;148 bytes /`0x07000002` | `0x207` |
| RPC502 or700, fresh sender reply, short-buffer control | 17 or34 | `0x303` or `0x403` | 87 bytes /6 (`RCV_LARGE`) | No publication before the results boundary |

These names are private model namespace values. They do not identify native ports or the ZUT guest port names. The incoming service request uses the source-created service receive right; the request's reply object becomes a send-once right in the receiver namespace. Publishing that right is not a reply-message emission. The existing original request send call remains `0xfffffe000bcf5ba8`; no additional Mach-message emission executes here. [RQ2, RQ3, RQ5]

## Complete-state results and remaining ownership

| State | Queued request producer | Accepted-capacity descriptor frontier | Short-buffer pre-results frontier |
| --- | --- | --- | --- |
| Destination object refs / send rights | 5 /2 | 3 /1 | 6 /2; lookup hold remains outstanding |
| Queue head / count / sequence | Original kmsg /1 /0 | NULL /0 /1 | Original kmsg /1 /0 |
| Kmsg ring pointers | Self-linked | Both NULL | Self-linked, unchanged |
| Header bits | `0x80111211` | `0x80001112` | Original bytes, unchanged |
| Internal header size | 88 bytes | Still 88 bytes; user-header contraction not yet performed | 88 bytes |
| Internal remote/local fields | Service object / reply object | Reply name `0x207` / service receive name | Original pointers |
| Descriptor and remaining request body | Original constructor-produced bytes | Preserved byte-for-byte | Preserved byte-for-byte |
| Reply object refs / send-once count | 2 /1 | 2 /1 | 2 /1 |
| Reply linkage state / destination union | 1 /service object | 4 /NULL | 1 /service object |
| Reply owner and sender binding | Original sender thread / bound reply | Preserved | Preserved |
| Reply diagnostic word+0x60 | 0 | 4242 from explicitly supplied receiver BSD-process context | 0 |
| Destination send turnstile | Primary hold1 | Original96-byte zeroing then modeled raw retirement | Preserved |
| Receiver turnstile loan | Original allocator result, explicit publication | Preserved, still owned by receiver context | Preserved |
| Recipient free entry2 | Declared free entry | Original reply object and bits `0x04840001`; generated name `0x207` | Remains free |
| Receiver status / received-kmsg field | Unset | 0 /original kmsg | `0x10004004` /NULL |
| Receiver required-size word+0x3a8 | 0 | 0 | 80 bytes |
| Receive-accounting events | 0 | 1 | 0 |
| User observation buffer | 8192 bytes of `0xa5` | Unchanged | Unchanged |

The three remaining destination references in accepted cases include the outstanding sender RPC hold. They are intermediate ownership values, not a completed lifecycle. Likewise, publishing the reply name before descriptor conversion does not establish daemon-visible delivery or final disposition after any later error. The short-buffer cases stop before dropping the receive-lookup hold; their reference count6 is intentional evidence of the stopping location. [RQ2-RQ8]

Three complete intermediate CPU/RAM snapshots per accepted case verify original frontend-tail, receive-results entry and header-copyout entry continuity. The two control cases retain one frontend-tail snapshot each and stop before results. All 14 final RAM images and 26 intermediate handoffs are checked independently. Sender-thread bytes, the unselected service port, receiver loan and user buffer have independent preservation checks.

The initial receiver setup lacked a turnstile loan. Source receive-results processing then selected port-side loan completion without a corresponding port-side loan in that artificial epoch. That rejected setup is not evidence of native reachability or a native defect. The final setup executes the original loan constructor first and explicitly publishes its result to thread+0x30. Native creation and publication of that thread-owned context remain unknown. [RQ2, RQ4]

## Validation and reproduction

The four freshly replayed request producers contribute 25786 original instruction visits. Four receiver-loan constructors and ten receive cases contribute 17816 visits: four 54-instruction constructors, four 2037-instruction minimal-capacity paths, four 2045-instruction extended-capacity paths and two 636-instruction short-buffer controls. Fresh independent receiver replay checks 3210 writes / 22544 bytes, 4310 reads / 27612 bytes, 32 declared primitive calls, 142 complete ABI/object frames and 14680064 final RAM bytes. Producer replay totals are recorded separately in the checks artifact.

Independent complete-record oracles reconstruct the service port, reply port, kmsg, receiver namespace, receiver thread, task receive counter and receiver loan for all ten cases. The namespace table/global state is reconstructed separately. Eight final destination-turnstile releases execute original lock destruction and full 96-byte zeroing before the raw-retirement contract. Actual raw-storage lifetime and native retirement remain unproved.

The two scalar UNSAT checks cover: (1) one type1 descriptor's user-size transformation `S-8-16+16 = S-8`, minimum result44 bytes and nonwrapping trailer addition for 52 <= S <= `0xffffffc3` and trailer 8 or 68 bytes; (2) generated name `(index<<8)|7` preserves its index and low generation byte for 0 <= index <= `0xffffff`. These arithmetic domains do not generalize CPU reachability beyond the finite receiver contexts.

```sh
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_request_receive.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_request_receive.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_request_receive.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/seal_kernel_request_receive.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/verify_kernel_request_receive_publication.py
```

Recovery and CPU validation take O(image bytes + source visits + copied RAM bytes + journal effects) time and O(image bytes + one CPU RAM map + journals) working space. Each private RAM image is 1048576 bytes. Addresses, counts and byte sizes are exact; no native timing, probability, scheduler behavior or numerical error bound is inferred. Scripts and dependency hashes record the environment-specific Python, image-reader and proof inputs.

## Bounded follow-up evidence

| Impact | Architectural question | Evidence that resolves it |
| --- | --- | --- |
| High | Does the actual host-special-port registration connect this source service object to the daemon's receive namespace? | Recover the original registration writer and establish port/receive-right lifetime and matched target identity. Current service names are fixtures. |
| High | What backs the constructor's internal type1 VM-copy pointer? | Join original staging/VM-copy construction to its actual object representation, then execute descriptor copyout with that producer state. The current pointer is opaque. |
| High | How does the converted request enter fairplayd's MIG dispatcher? | Complete descriptor conversion and user-message copyout, then transfer the resulting80-byte request into the source-pinned daemon receive path. Current user memory remains unchanged. |
| Medium | Which original lifecycle creates and publishes the receiver thread's turnstile loan? | Identify the allocation/publication producer and carry its state into the frontend without the explicit publication fixture. |
| Medium | How do later descriptor/copyout errors affect the already published reply right and outstanding RPC holds? | Execute original failure/rollback and reply paths with source-derived VM state; maintain distinct send-right, object-reference and turnstile ledgers. |
| Low | What varies under other map limits, vouchers, receive options and port sets? | Derive source partitions and bounded contexts independently; do not infer coverage from the present type1/no-voucher/direct-port cases. |

## Quality gates

- QG1: Technical source/interface analysis; no normative conclusion required.
- QG2: RQ1-RQ8 identify assumptions, dependencies and concrete falsification probes.
- QG3: Actual queued-request consumption, incoming service/right context, reply namespace publication, source control/data/ownership effects and respective report updates are covered. The full interface goal remains active.
- QG4: Exact byte counts, object layouts, unsigned arithmetic domains, complexity and executable reproduction are recorded; finite CPU and scalar proof scopes are distinct.
- QG5: Short-buffer preservation versus outstanding lookup retain, internal88-byte header versus projected80-byte user message, source loan construction versus explicit publication and namespace publication versus daemon delivery are reconciled.
- QG6: Original complete bodies, exact symbol records,19 role instructions, every visited instruction, fresh producer states and independent fresh CPU effects are checked against primary local bytes.
- QG7: Impact-labeled follow-up questions and resolving evidence are bounded above; native registration, thread context, descriptor VM backing, scheduler causality, user delivery and authentic FairPlay round trip remain unknown.
