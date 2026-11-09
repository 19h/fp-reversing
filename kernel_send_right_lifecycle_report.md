# Host-slot send-reference acquisition, release and no-senders notification

Original host-special-port acquisition and send-reference release now have checked counter, output and notification contracts. Three original acquisition/release pairs restore both selected counters. The prior FairPlay release frontier also executes the original release body and returns to its actual kext continuation after an explicit source-produced port-object import. A last-send component constructs a 44-byte no-senders notification; an inactive notification destination instead takes original send-once cleanup. Native host-slot contents, notification delivery, final retirement and authentic FairPlay lifetime balance remain unknown. [SR1-SR8]

Primary evidence: [eight complete routines / 455 instructions and original descriptors](triage_evidence/kernel_send_right_lifecycle_source.json), [22 private CPU components](triage_evidence/kernel_send_right_lifecycle_profiles.json), [fresh replay, packet oracles and three bit-vector proofs](triage_evidence/kernel_send_right_lifecycle_checks.json). Collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Original references suffice; no new IDA access, target execution, native IPC, hardware authentication or memory-store update occurs.

## Original entry points and ownership fields

| Entry or site | Established local role |
|---|---|
| `0xfffffe000bcf27ac`, exact `_host_priv_self` | Returns original global address `0xfffffe000cad0238` |
| `0xfffffe000bcf258c`, exact `_host_get_special_port` | Selected global slot lookup, original host-lock atomics, reference-copy call and output publication |
| `0xfffffe000bcd00bc`, anonymous | Copy-send helper inferred from caller and exact two-counter increments |
| `0xfffffe000bcd0448`, exact `_ipc_port_release_send` | Send-count decrement, object-reference decrement, last-send handling |
| `0xfffffe000bcc8f4c`, anonymous | Extract/clear ordinary-port no-senders request and return make-send count; also captures other-kind branches |
| `0xfffffe000bcce494`, anonymous | Send-once count decrement and reference drop on selected inactive-target branch |
| `0xfffffe000bcc922c`, anonymous | Last-object-reference dispatch; captured, not entered in the retirement-frontier case |
| `0xfffffe000bcc90a0`, anonymous | Other-kind callback and reference-drop continuation; captured, unexecuted |

| Port-relative field | Width | Selected meaning and source evidence |
|---|---|---|
| +0 | u8 | Port-kind index into original 40-byte descriptor table |
| +1, low three bits | u8 field | Predicate separating selected usable/inactive branches; broader flag names unknown |
| +4 | u32 | Object-reference counter, updated with original LSE atomics |
| +0x14 | Address | Port-lock argument; lock implementation modeled |
| +0x50 | u64 pointer | Ordinary-port no-senders request, logically authenticated and cleared on extraction |
| +0x84 | u32 | Make-send count returned with extracted request |
| +0x88 | u32 | Send-right counter |
| +0x8c | u32 | Send-once counter on the selected cleanup path |

The original descriptor at `0xfffffe0007e62b98` names kind1 `port`; its flags contain bit0x20, checked by the ordinary no-senders extractor. Thirteen original descriptors/names are retained. The header fields and kind1 fixture are premises, not an observed host-slot allocation or proof that arbitrary byte images are valid ports. Metadata extent/class guards execute before the modeled port lock. [SR1-SR3,SR7]

## Host acquisition and paired release

Original slot selection uses global table base `0xfffffe000cad0248`. Slot17 and slot34 cells are therefore `0xfffffe000cad02d0` and `0xfffffe000cad0358`. The selected fixtures place distinct port pointers in them; native cell contents and initialization remain unknown. The original host lock at global+8 is acquired with CASA and released with CASL using a declared thread token at thread+0x518 and zero lock-policy word. No host-lock slow path or concurrent behavior is established. [SR2-SR4]

Three paired components preserve the exact acquired component's RAM/globals into a separate release call. Their call registers are initialized for that separate call; they are not claimed as uninterrupted caller CPU continuity. For initial counters `(object_refs,send_refs)`:

| Declared acquisition | After original copy-send | After original release |
|---|---|---|
| Slot17, (3,2) | (4,3), output=port17 | (3,2) |
| Slot34, (5,1) | (6,2), output=port34 | (5,1) |
| Slot17, (3,0xfffffffe) | (4,0xffffffff) | (3,0xfffffffe) |

The empty slot returns status0 and publishes NULL. Slot0 and slot37 return4 without changing the A5 output canary. For the u32 selector interpretation, the original guard accepts exactly 1 through36 inclusive; one bit-vector query proves this equivalence over all u32 values. This establishes the local guard, not registration, authorization or service identity. Release of NULL or all-ones dead sentinel returns before port dereference/lock. [SR3,SR4]

Send-count growth is unsigned 32-bit. Original code loads a u32 into X8, adds1 in 64 bits, stores the low32 bits, then tests the shifted sign-extension identity `(X8 << 31) >>signed 31 == X8`. This retains 33 bits, so crossing 0x7fffffff is accepted. The guard rejects old send count0xffffffff, after its low32 store wraps to0. A second all-u32 proof establishes acceptance exactly for old counts0 through0xfffffffe. A finite crossing case produces0x80000000 successfully. [SR4,SR5]

Object-reference acquisition uses the separate biased u32 guard `(old + 0xf0000001) mod 2^32 > 0xf0000001`, equivalent to `1 <= old <= 0x0ffffffe`; the third all-u32 proof establishes this. Send-right and object-reference counters therefore have different checks. The injected send-underflow, object-underflow and send-overflow cases stop before original failure handlers. Their post-arithmetic stores are recorded; they do not establish a native failure trigger. The overflowing acquisition never resumes its host caller, so that component's host-lock word remains the declared token rather than being reported as released. [SR4-SR7]

## No-senders notification and outgoing endpoint

```text
original release_send(port)
  -> send count remains nonzero -> unlock -> object ref decrement -> return
  -> last send
       -> ordinary request absent -> unlock -> object ref decrement -> return
       -> ordinary request present -> extract pointer/count, clear port+0x50
            -> unlock -> object ref decrement
            +-> usable target -> build ID70 packet -> kernel send helper [stop]
            +-> inactive target -> original send-once release -> return
```

The selected last-send fixture has object references3, send rights1, request pointer N, and make-send count7. Original code changes source counters to (2,0), clears source+0x50, and constructs this kernel-form message. [SR3,SR5,SR6]

| Offset | Width | Exact selected packet value |
|---|---|---|
| 0 | u32 | Bits18, conventional `MACH_MSG_TYPE_MOVE_SEND_ONCE` destination disposition |
| 4 | u32 | Size field0 at this pre-send boundary |
| 8 | u64 | N, copied from the source port's no-senders request |
| 16 | u64 | Reply pointer0 |
| 24 | u32 | Voucher field0 |
| 28 | u32 | ID70, conventional `MACH_NOTIFY_NO_SENDERS` |
| 32 | 8 bytes | Original NDR `0000000001000000` |
| 40 | u32 | Make-send count7 |

Original call site `0xfffffe000bcd0598` reaches helper entry `0xfffffe000bcf55dc` with `(packet,44,0x50001,0,NULL)`. The 44-byte explicit argument and zero pre-send header-size field are distinct. The helper body and transport do not execute. Current local SDK definitions independently establish 18 and `0100 + 006 = 70`; their paths/hashes/lines are retained. Those SDK definitions corroborate conventional names, not the running kernel revision. [SR1,SR5,SR6]

N is a kernel pointer, not an observed user-space Mach name. It is distinct from the FairPlay RPC502 destination. The active-target component leaves N's own send-once count/reference untouched at the send boundary; subsequent conversion or consumption is unknown. With an inactive N fixture, original code instead enters `0xfffffe000bcce494`, changes N's send-once count1->0 and object references2->1, and returns without constructing the notification packet. A last object-reference fixture stops at `0xfffffe000bcc922c` after decrement to0; no allocator retirement is claimed. [SR5-SR8]

## Actual FairPlay caller continuation with explicit object import

The [previous bridge](kext_vm_copyout_bridge_report.md) ended at original `_ipc_port_release_send` with the acquired destination pointer and actual return PC `0xfffffe000a615f30`. This component restores that exact RAM base, GP/SP/NZCV/SIMD state and existing globals. Its opaque zero-filled port placeholder is then replaced by the exact 144-byte port image produced by the slot17 acquisition component. Three two-byte metadata tags and declared arena/metadata globals are explicit environmental overlays. Thus the CPU caller state is preserved, while the port/environment initialization epoch is declared; this is not a wholly unchanged-memory handoff or a real host-slot publisher. [SR2,SR3,SR7]

Original release executes on imported counters (4,3), returns them to (3,2), preserves callee-saved state, and returns to the actual kext address. The caller continuation is not executed. This closes the release-body ABI for the selected caller/object premises. It does not prove that the declared transport preserved a real endpoint's counters, that all native retains/releases balance, or that the endpoint belongs to the inspected fairplayd instance. [SR3,SR7,SR8]

## Assumption register

| ID | Premise / dependent results | Stress test or falsification probe |
|---|---|---|
| SR1 | Pinned collection/descriptors and separately versioned SDK describe the retained code/conventional names | Recapture all bodies, visited words, descriptor names and SDK lines; verify deployed build separately |
| SR2 | Host cells, thread token, arena/zone tags and port headers are declared environmental objects | Recover real initialization/registration writers and actual runtime object/slot provenance |
| SR3 | Separate full-memory component transfers and the explicit acquired-object import define the epochs | Compare every byte/global and exact caller registers; keep the port/metadata overlays visible |
| SR4 | Scalar selector/counter guards are interpreted with original widths and modular arithmetic | Three all-u32 proof queries plus upper-limit, signed-crossing, invalid-selector and underflow probes |
| SR5 | Ordinary kind1, one request, count7 and the selected target state bound notification coverage | Exercise other descriptor kinds, high-word callback results, request registration and concurrent final-send transitions |
| SR6 | Original packet construction establishes a pre-send interface, not native delivery | Continue original send helper, conversion, queueing and receiving namespace; retain explicit size/disposition ownership |
| SR7 | Port locks and PAC remain logical models; LSE counter/host-lock instructions execute in private memory | Establish real locking, concurrency, authentication, allocation and retirement separately |
| SR8 | Scoped acquisition/release/notification components do not establish authentic FairPlay lifetime balance | Join actual host registration, daemon request/reply activity, counter changes through transport and complete close/retirement paths |

Twenty-two fresh CPU replays verify 1445 original instruction visits, 323 reads /1956 bytes, 226 writes /1656 bytes, 32 lock models, 22 complete final RAM images /23068672 bytes, 137 global records and all final SIMD/system states. Three 1048576-byte acquisition-to-release RAM transfers and one prior-kext RAM base are checked separately. There are no modeled counter or packet-memory effects: original instructions perform those writes. Seventeen components return, including the actual kext caller return; one reaches notification send and four stop at retirement/failure frontiers.

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_send_right_lifecycle.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_send_right_lifecycle.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_send_right_lifecycle.py
```

Recovery/replay is O(image + source + visits + RAM + globals) time and O(image + source + RAM + journals) space; each RAM image is 1048576 bytes. Three solver queries use fixed-width 32/64-bit formulas, with solver runtime not assigned a general polynomial bound. Counts and arithmetic above are exact finite observations.

| Impact | Further interface evidence |
|---|---|
| High | Actual host-slot registration and initial port construction; replace declared endpoint identity and counters |
| High | Continue no-senders send helper and receiving conversion; establish actual right consumption/delivery |
| High | Join native transport-side reference changes and complete FairPlay error/close lifetime |
| Medium | Other-kind callback, last-object-reference dispatch, queue/zone retirement and lock slow paths |

QG1: Factual technical analysis; no normative judgment required.
QG2: SR1-SR8 register premises, dependent claims and falsification probes.
QG3: Scoped acquisition, cleanup, notification emission/frontier, pointer/rights/ABI, environment and report updates are covered; the full goal remains incomplete.
QG4: Explicit widths, modular guards, packet offsets/size, byte counts, commands and complexity are reproducible.
QG5: Send versus object versus send-once counts, unsigned growth versus signed crossing, request extraction versus delivery, separate calls versus explicit imported caller state, and unfinished versus released lock epochs are distinguished.
QG6: Original bytes, symbols, descriptors, constants, separately hashed SDK definitions, solver queries and independent CPU replay provide primary provenance.
QG7: Impact-labelled continuation remains bounded to unresolved registration, transport, ownership, notification and retirement interfaces.

[Preservation](triage_evidence/kernel_send_right_lifecycle_delivery.json), [scoped gates](triage_evidence/kernel_send_right_lifecycle_quality_gates.json), [publication verifier](triage_evidence/verify_kernel_send_right_lifecycle_publication.py). The full goal remains active.
