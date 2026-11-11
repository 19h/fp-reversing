# FPSD1200 CF endpoint, process-exit registration and complete reply construction

The original FPSD1200 continuation stores its CF endpoint in the selected pool slot, creates and registers a main-run-loop source, requests a one-shot process-exit watch for the audit PID, publishes all seven staged output fields and constructs a 212-byte, zero-status reply. These results depend on explicit private CF, default-mode and `kevent` models. Two NULL controls return 36-byte errors; `kevent=-1` instead reaches an unexecuted errno accessor. No native right creation, message transmission or kext call is established. [FP1-FP8]

This continues the [VM/output analysis](fpsd1200_vm_report.md). The full daemon/kext/deeper-interface investigation remains active. Earlier profiles retain their original stop boundaries.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FP1 | The pinned thin daemon and matching live IDA bytes identify this source. All instruction and address claims depend on that identity. | Rehash the daemon, all 854 source spans, 1140 original rebases and 38 bind records. Keep the IDA whole-input metadata hash distinct from thin-image identity. |
| FP2 | Frozen startup, admission, libbsm, certificate, arithmetic, VM, PAC, atomic and import models define the preceding private machine. All continuations depend on those premises. | Freshly replay every original visit and event; compare prior ownership/knownness, registers, stack, globals, certificates and arithmetic records. Native initialization, authentication, library pairing and concurrency remain unknown. |
| FP3 | CF objects and the imported default-mode object are opaque fixture identities. CF continuation and slot association depend on those identities and declared API results. | Compare port/source NULL controls and a stop-before-mode-data control. No synthetic CF object layout is mapped; native allocation, retain counts, scheduling and rights remain unknown. |
| FP4 | A single explicit `kevent` result is supplied without errno or queue effects. Successful output continuation depends on return0. | Withhold the result, then compare0 with -1; retain the resulting boundary at `__error()`. Do not equate composed descriptor0 with a valid native kqueue. |
| FP5 | The source receives audit bytes00..1f and the retained reference request/DER. PID and output values depend on those inputs. | Check the original libbsm/token-copy path, signed PID load, all event bytes and the full-domain sign-extension codec query. Actual process identity and native credential decisions remain unknown. |
| FP6 | CFGetPort supplies a u32 fixture name in a private namespace. Name publication and reply construction depend on that result. | Join CF slot storage/read, GetPort argument/result, phase checkpoint and original output store; prove the selected-phase codec for all u32 inputs. Native send/receive rights, namespace equality and kernel copyout remain unknown. |
| FP7 | Imported release/invalidate/VM/MIG cleanup calls are record-only models. Lifetime findings concern observed requests and retained private ownership. | Inspect every cleanup call and all source stores on success/failure. Native deallocation, later callbacks and eventual reclamation require separate evidence. |
| FP8 | Six finite profiles and two local full-domain arithmetic checks delimit this increment. Selected flattened fragments do not define complete functions or arbitrary-state semantics. | Independently replay all profiles, source/import/checkpoint journals and mathematical joins; preserve unpaired bank reads and unexecuted boundaries. Native transport, client acceptance and deeper interfaces remain separate obligations. |

## Provenance and reproducible evidence [FP1,FP2,FP8]

| Object | Identity / extent |
| --- | --- |
| Original arm64e daemon | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base `0x100000000` |
| Read-only live IDA | Input metadata SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`; all 854 selected source spans match the thin image |
| Original source catalog | 40645 distinct four-byte instructions including one unretired mode guard:162580 bytes |
| Reference client input | [CoreFP DER](triage_evidence/corefp_fppineboard_certificate.der),756 bytes; request words+52=2,+56=2 and matching OOL counts756 |
| Primary ABI context | Seven installed SDK headers; compile-only arm64e checks for VM/CF widths and signatures, CF context40 and `struct kevent`32 with exact member offsets/constants |
| Earlier knowledge | IDA fact6 supplies shared-callback/wrapper context only; it supplies no direct evidence for this endpoint continuation |

Artifacts: [producer](triage_evidence/recover_fpsd1200_port.py), [source/profiles](triage_evidence/fpsd1200_port_checks.json.zst), [live IDA/SDK readback](triage_evidence/fpsd1200_port_ida_readback.json.zst), [independent replay/oracles](triage_evidence/audit_fpsd1200_port.py), [fresh replay receipt](triage_evidence/fpsd1200_port_audit.json.zst) and [publication/data-join verifier](triage_evidence/verify_fpsd1200_port_publication.py). No IDB mutation or native target/API execution occurs.

## CF endpoint and source sequence [FP2-FP4,FP6]

| Original location | Established operation / arguments |
| --- | --- |
| `0x100001f8c` | `CFMachPortCreate(NULL,0x100425f78,context,&shouldFreeInfo)`; context40 and Boolean are source-defined zero |
| `0x100624eb4` | `STR X0,[X23]` writes the returned CF object, including NULL, into selected slot0+0; comparison with NULL follows at `0x100624eb8` |
| `0x1005236b0` | `CFMachPortCreateRunLoopSource(NULL,CFPort,0)` |
| `0x1003ae28c` | Zero-argument `CFRunLoopGetMain()`; remaining register values are not extra API arguments |
| `0x1003ae314` | Loads the imported `kCFRunLoopDefaultMode` object pointer; this read is guarded when its data is withheld |
| `0x1003ae330` | `CFRunLoopAddSource(mainRunLoop,source,defaultMode)` |
| `0x1003ae380` | `CFRelease(source)` request after source registration |
| `0x1003ae458` | `kevent(queueFD,&change,1,NULL,0,NULL)` |
| `0x1005a73f8` / `0x1005a7410` | Reads the defined CF object from slot0+0, then calls `CFMachPortGetPort(CFPort)` |
| `0x1005a7458` | Original store publishes the raw name at staged P+100 |

The opaque fixture identities are CFPort=`0x77001000`, source=`0x77002000`, run loop=`0x77003000` and default mode=`0x77004000`. They are unmapped handles with no modeled object internals. CFGetPort returns name `0x6800`; this return does not itself allocate or transfer a native right. The selected continuation does not execute `mach_port_insert_right`.

```text
original CF create request
  -> store CF object in selected slot
  -> create source -> obtain main loop -> load default mode
  -> add source -> release local source reference
  -> request audit-PID exit watch
       +-- return -1 -> __error() boundary
       +-- return  0 -> publish OOL/scalars -> get raw name
                         -> original wrapper -> 212-byte reply buffer
```

The shared callback is the previously recovered daemon receive callback. The [arcade created-port path](created_port_report.md) has different callers and an explicit insert-right sequence; its endpoint identity and right operations are not transferred to this FPSD1200 path. The [CF receive analysis](cf_receive_report.md) preserves separate installed-cache implementation evidence. Current opaque models do not establish that library's native pairing or actual CF behavior.

## Process-exit event and queue dependency [FP2,FP4,FP5]

The event is entirely source-defined before the imported call. SDK compilation checks `sizeof(struct kevent)==32` and the following layout:

| Offset / width (bytes) | Member | Selected value / ABI meaning |
| --- | --- | --- |
|0 /8 | `ident` | `0x17161514` =387323156, signed audit PID extended to64 bits |
|8 /2 | `filter` | -5, `EVFILT_PROC` |
|10 /2 | `flags` | `0x0011`, `EV_ADD | EV_ONESHOT` |
|12 /4 | `fflags` | `0x80000000`, `NOTE_EXIT` |
|16 /8 | `data` |0 |
|24 /8 | `udata` |NULL |

The exact event bytes are `1415161700000000fbff11000000008000000000000000000000000000000000`. The call has six ABI arguments: queueFD0, change pointer,1,NULL,0,NULL. There is no output event list or timeout object. Raw X6/X7 remnants are not arguments.

At `0x1003ae384`, `LDRSW X8,[SP,#0x714]` loads the copied audit PID. The following source arithmetic through `0x1003ae3b4` preserves its sign extension; `0x1003ae3c4` stores event.ident. For signed32 PID p, x=signextend64(p), K=`0x863abc041240df58` and M=`0x0c7578082481beb0`:

```text
((x - ((x << 1) AND M) + K) XOR K) mod 2^64 = x
M = (2*K) mod 2^64
```

A retained UNSAT counterexample query covers every32-bit PID bit pattern. It proves the codec, not that the fixture PID names a live process. The source stores filter/flags/fflags at `0x1003ae3c8`, zero udata at `0x1003ae3cc` and zero data at `0x1003ae3d0`.

At `0x1003ae3d8`, the queue-word read is four bytes `69d90e06` from `0x1010c4d20`, context base `0x1010c4cd8`+72. The selected continuation combines this encoded word with phase values and yields W0=0 at `0x1003ae43c`. This is a dependency on composed initialized context, not evidence that descriptor0 is a native kqueue. With return -1, original code reaches `libSystem/___error` at call site `0x100493a58`; its pointer result and errno data are deliberately absent. No final error code or rollback is inferred for that unfinished branch.

## Seven staged outputs and original wire construction [FP2-FP4,FP6]

P is the wrapper's104-byte payload at private address `0x70077e48` in this fixture. All seven output fields below have original source stores on the successful path; no protected-output tuple is injected.

| P offset / width (bytes) | Original producer | Selected final value | Original reply placement |
| --- | --- | --- | --- |
|72 /8 | `0x100624c70` | `0x76000000`, private VM owner | OOL descriptor address at+28 |
|80 /4 | `0x100543d3c` |719 | OOL size+40 and repeated count+196 |
|84 /4 | `0x100624c68` |1 | OOL descriptor deallocate byte+36 |
|88 /4 | `0x1005a7378` |76 | u32+200 |
|92 /4 | `0x1005a7394` |9 | u32+204 |
|96 /4 | `0x1005a73ac` |0 | u32+208 |
|100 /4 | `0x1005a7458` | `0x6800`, CFGetPort fixture result | Port descriptor name+44 |

The prior original inline producer `0x1002212a0` supplies reply[68,196):128 bytes equal to the complete public-exponent result under the supplied CoreFP leaf modulus. The VM owner contains the719-byte embedded daemon leaf DER with every byte defined. Its SHA-256 is `d43ca892b364466d885a38418b11469c2634ddcfe493ff3beda2f022edde4102`. The wrapper at `0x100007f34..0x100007f60` copies the staged fields into its result cells; original MIG code constructs the212-byte complex reply with two descriptors, message ID1300 and application status0. Raw carrier `0x8b3dc651` and zero delta produce that status through the retained adapter.

The raw-name arithmetic at `0x1005a7414..0x1005a7458` is identity for every u32 input under the observed phase W19=`0x25d1`. With x the GetPort result, K=`0xf3fcefb6` and arithmetic modulo2^32:

```text
y = (x XOR K) + 0x0c03104a + ((x << 1) AND (0x25d1 XOR 0xe7f9fabd))
y = x
```

The publication verifier independently checks an UNSAT counterexample query and joins the phase checkpoint, source operands, API result and final store. This local proof has a phase premise; it does not assert arbitrary dispatcher-state equivalence. The three scalar values76/9/0 are established, while their protocol field names remain unknown.

| Port-like value | Established role / boundary |
| --- | --- |
| `0x1400` | Incoming request's local-name fixture |
| `0x6400` | Reply destination carried in the original constructed header |
| `0x6600` | Explicit task-self-name fixture used by VM calls |
| `0x77001000` | Opaque CF object identity stored in the pool; not a raw Mach name |
| `0x6800` | Modeled CFGetPort raw result, originally stored and placed in outgoing descriptor with disposition19/type0 |

Original input `mig_deallocate` at `0x10000468c` records retirement of the756-byte incoming OOL object. Entry is the MIG demultiplexer `0x100004b80`, so this experiment returns a reply buffer without executing the enclosing callback send. The separately recovered send site `0x100035184` remains the transport touch point; it is not reached here. A received client descriptor's disposition17 requires kernel delivery/conversion from the outgoing19. Actual transmission, right copyout and [CoreFP client acceptance](corefp_client_paths_report.md) remain unknown.

## Pool association, retained representative and failure lifetime [FP2,FP3,FP7]

| Selected slot field / source | Established effect |
| --- | --- |
|+0 / `0x100624eb4` | Stores the CF result; successful GetPort path reads this defined field |
|+404..531 /128 stores at `0x100552948` | Descending byte stores retain the exact third exponentiation input representative XOR `0x98` |
|+400 / `0x1005a7340` | Copies diagnostic A5 bytes into this field on success; its semantic origin/role is unknown |
|+876 / `0x1005a7350` | Advances selected marker `0x4577df4a` to `0x4577df4b` on success |
| NULL-result failures | Restore marker `0x4577df49` and return status `0xffff5b38` (signed32 -42184) |

The retained representative decodes to the exact128-byte arithmetic input beginning `00 66 64 70 63 00 00 00 01`; the inline reply contains its exponentiation result, not this stored input. Every retained-representative store is joined independently to the original arithmetic record. Nearby bytes and the whole896-byte slot are not assigned complete structure semantics.

If source creation returns NULL after nonnull port creation, original calls `CFMachPortInvalidate` at `0x100474e6c` and `CFRelease` at `0x100474eb4` consume the CF object, then original store `0x100474eb8` clears slot+0 before the36-byte error reply. Port creation returning NULL does not reach source creation. Both paths have already allocated and filled the private719-byte VM owner, but neither observed failure interval requests another VM deallocation. The owner remains mapped in the model. This bounds an unresolved native cleanup/lifetime question; it does not establish a native leak. Source release after successful registration is a recorded request, without a modeled CF retain-count consequence.

## Finite controls and verification [FP1-FP8]

| Profile | Original visits | Terminal boundary / reply |
| --- | ---: | --- |
| `CF_port_NULL` |10092802 | Original36-byte reply, status -42184 |
| `CF_source_NULL` |10092917 | Invalidate/release requests, original36-byte reply, status -42184 |
| `default_mode_guard` |10092776 | Before imported mode read `0x1003ae314` |
| `kevent_boundary` |10092858 | Before `kevent` implementation/result |
| `endpoint_success` |10093981 | Original212-byte zero-status reply |
| `kevent_error` |10092917 | Before `__error()` implementation/result |

| Coverage | Exact extent |
| --- | --- |
| Original instruction visits |60558251:60558137 daemon and114 selected-library visits |
| Imports / completed replies |265 /3:one212-byte success and two36-byte errors |
| Private VM owners / original copy stores |6 /4314, each owner719 bytes |
| Protected output stores / staged output reads |780 /33 |
| Input OOL reads |13926 |
| Mode reads / guarded read / queue-word reads |3 /1 /3 |
| Public arithmetic |564 complete Montgomery calls;18 complete exponent sequences,12 signature-derived outputs and two public-signature relations |
| Byte-bank checks |17 exhaustive identities /4352 inputs;25521 observed pair uses and210 unpaired reads |
| Local SMT checks | One retained all-PID query checked by the independent auditor; one selected-phase all-name query checked by the publication verifier |

The independent auditor does not import this producer. It replays the original instructions through the frozen predecessor oracle, independently checks all new GP31/SP/NZCV checkpoints, mode and queue reads, CF arguments/results, source-defined context and complete event record, and compares all retained earlier owner/arithmetic/terminal state. CFCreate and later cleanup events bypass only the predecessor's obsolete stop-only assertion; ordinary source and event replay remains active. Both production and replay use two operating-system worker processes with separate private machines.

The publication verifier checks exact manifest ownership and preserved inputs, source/dependency/auditor/receipt hashes, all seven output joins, descriptor bytes, failure cleanup sequences, CF object-to-name flow, retained representative and local name codec. It validates the pinned fresh-replay receipt without repeating instruction replay. Substantial JSON is Zstandard ultra22 archived with exact decompression comparison. All owned files and commit metadata undergo analyst-path checks. Compressed profiles are decoded and checked separately from their outer metadata, so accidental alphabet runs in compressed Base64 text are not classified as path strings.

```sh
env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/audit_fpsd1200_port.py

env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_fpsd1200_port_publication.py
```

Finite observation/replay work is O(B+F+V+E+L) for selected source bytes B, fixups F, visits V, events E and active limb bytes L, excluding big-integer arithmetic and SMT costs. Storage is bounded by two private worker machines plus the aggregator and largest decoded profile; publication adds O(manifest entries + owned bytes) hashing work. Widths are explicitly u32/64-bit address/signed32 status; event extents and offsets are bytes. These bounds do not describe native target timing or whole-program complexity.

## Bounded continuation opportunities [FP2-FP8]

| Impact | Discriminating next evidence |
| --- | --- |
| High | Follow the `kevent=-1` errno read and original cleanup path, with separately declared errno/pointer models. Resolve the selected queue word's initializer and actual queue ownership. |
| High | Follow process-exit event consumption into slot retirement, CF invalidation and VM reclamation; distinguish requested cleanup from actual lifetime. |
| High | Join native daemon initialization, request receive, CF/right creation, callback reply send and client copyout. Object fixtures and a complete original reply buffer leave this transport obligation open. |
| High | Join subsequent use of the returned session endpoint to daemon provider, IOKit user client and deeper interfaces using exact source and namespace evidence. This FPSD1200 path reaches no IOKit call. |
| Medium | Resolve the stored128-byte representative, scalar76/9/0 fields and slot+400 provenance through actual producers/consumers. Do not infer semantics from prefixes or A5 fill. |
| Medium | Compare the shared CF helper's distinct callers and service identities without merging their right-insertion or protocol contracts. |

**QG1** passes: factual source, ABI and finite-state observations. **QG2** passes: FP1-FP8 state assumptions, dependent results and falsification probes. **QG3** passes for this increment; the broader investigation remains active. **QG4** passes: byte extents, ABI widths, signed statuses, arithmetic identities and finite cost bounds are explicit. **QG5** passes within scope: successful construction, NULL errors, unexecuted errno boundary, retained private owners and native delivery are distinguished. **QG6** passes: original bytes/fixups, fresh live IDA, installed primary SDK, independent replay and arithmetic/data joins supply provenance. **QG7** passes: bounded continuation questions carry impact labels.
