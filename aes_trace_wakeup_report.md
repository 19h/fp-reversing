# AES software trace, allocation geometry and interrupt wakeup

Original AppleS8000 AES source identifies eight software-ring cursor stores and a conditional interrupt-to-configuration wakeup interface. Class metadata and the class allocator both request 2560 B, exactly the prefix required by the ring and cursor. This resolves the earlier source-size question; native allocation, initial bytes, alias closure, serialization and progress remain unknown. [TW1-TW8]

```text
class metadata size 2560 B + typed allocation request 2560 B
  -> typed wrapper(view,2560) -> lower backend(view,raw flags 4)
  -> actual zeroing / construction / native object epoch [unknown]

P+0x1fc: 256 records of {u32 tag,u32 payload}
P+0x9fc: u32 cursor; local record updates keep NEXT cursor in 0..255
  -> startup / state changes / command words / completion records

configuration retry: wait byte P+0x150=1; register control bit 0 requested
  -> gate sleep(event=P+0x150,raw flags=2)
interrupt: enabled bit + status mask + status bit 0 + wait-byte bit
  -> clear register control bit 0 -> clear wait byte
  -> gate wakeup(event=P+0x150,raw boolean=0)
  -> status bit 5 can select _completeAES after wakeup returns

native interrupt delivery, matching wait epoch and completed device work: unknown
```

Primary artifacts: [source/certificates](triage_evidence/aes_trace_wakeup_checks.json.zst), [extractor/lifter](triage_evidence/recover_aes_trace_wakeup.py), [independent integer/byte-memory interpreter](triage_evidence/audit_aes_trace_wakeup.py), [publication audit](triage_evidence/verify_aes_trace_wakeup_publication.py). Context: [configuration/emitter](aes_configuration_commands_report.md), [quantum binding](aes_quantum_binding_report.md), [carrier allocation precedent](aes_carrier_initialization_report.md).

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| TW1 | The pinned collection, fileset UUID, compiler boundaries, symbols and original pointer chains identify this build. | Rehash and independently decode the spans, full text census, view, constant and eight slots; remap other builds. |
| TW2 | P denotes a compatible provider with live writable storage, compatible nominal dispatch and nonaliasing declared fields. | Match native allocation, receiver, lifetime, metaclass and field ownership; file metadata alone cannot supply a live object. |
| TW3 | The typed allocation request and separately versioned raw-4 flag meaning are distinguished from actual returned memory. | Establish the runtime type-view/zone binding, backend zeroing, failure handling and intervening constructor effects before assigning an initial cursor value. |
| TW4 | Current ring addressing assumes cursor<=255; an inductive lifetime invariant additionally needs a bounded initial cursor and closure over all writers. | Match initialization and alias/indirect/bulk writes, including callers outside this fileset. The census covers literal +0x9fc memory operands only. |
| TW5 | Record composition is serial with stable owner fields and payloads over the declared source cuts. | Match locking/workloop ownership and concurrent producers. Separate source reads and ordinary load/store updates do not reserve slots atomically. |
| TW6 | Interrupt register/field reads use declared snapshots; writes have source instruction meaning only. | Match real mapping, register semantics, interrupt delivery and interleavings. No MMIO or interrupt executes here. |
| TW7 | Sleep/wakeup nominal receiver, authentication, ABI-preserving returns and event epoch match. | Establish actual gate/workloop identity, sleep registration, wake scheduling and retry progress; equal event addresses alone do not prove a delivered wakeup. |
| TW8 | Only original-source semantics, SMT obligations and private finite byte arrays are evaluated. | Obtain a matched native daemon/kext/provider transaction, job identity and output/completion evidence before an end-to-end claim. |

## Source and allocation geometry

Collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; AppleS8000AES fileset UUID is `0dcd56c8-3f0e-372b-9b43-a32d0a11df8b`. Nineteen retained spans contain 2107 instructions / 8428 B: fifteen complete compiler-bounded bodies and four exact 16 B import stubs. IDA was unnecessary because the original references suffice. [TW1,TW8]

| Original source | Evidence |
| --- | --- |
| `AppleS8000AESAccelerator::MetaClass` C1 / C2 | `0xfffffe0009d4e560` / `0xfffffe0009d4e6a4`: W3=0xa00 before nominal OSMetaClass constructor |
| `MetaClass::alloc()` | `0xfffffe0009d4e6e4..0xfffffe0009d4e6f0`: X0=view, W1=0xa00 before typed-new stub call |
| `AppleS8000AESAccelerator_ktv` | `0xfffffe00082fe4e8`; low24(u32[view+0x2c])=0xa00; original name pointer identifies `site.AppleS8000AESAccelerator` |
| Typed-new import | Slot `0xfffffe00082fe580` -> `0xfffffe000c4458c4`, `_OSObject_typed_operator_new` |
| Typed-wrapper branch | Request 2560<=view size 2560 selects backend call `0xfffffe000c44590c`; raw W1=4 |
| Derived constructors | Typed C1/C2 and default C1/C2 call the nominal base constructor and publish the derived vptr; their local stores do not explicitly initialize +0x9fc |

The raw-4 request matches `Z_ZERO` in the separately versioned [pinned Apple zalloc.h](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/zalloc.h#L466), whose captured SHA-256 is `3a7bcfed6b5062574a33ac59e15dd97fc8c8a80cc45b37c67f52f5f112c739d9`. This reuses retained primary provenance from the carrier report; source-revision identity with this collection is unproved. The request supports a zero-initialization explanation, conditional on actual backend behavior and subsequent preservation. It does not establish cursor=0 in native memory. [TW2-TW4]

The exact geometry is:

```text
ring bytes       = 256 * 8 B = 2048 B
ring end offset  = 0x1fc + 0x800 = 0x9fc
cursor end       = 0x9fc + 4 B = 0xa00 = 2560 B
class/view request                          = 2560 B
```

The prior private 0xa00-byte provider reservation therefore matches source class/request metadata. This adds provenance to its size; it does not convert earlier private-object replays into native execution or prove actual allocation capacity. [TW2,TW3]

## Cursor census and record meanings

The entire original `__text` range `0xfffffe0009d4e540..0xfffffe0009d52ab4` decodes to 4445 instructions / 17780 B. Its SHA-256 is `6640f7216f19121372903b36283bd38521d2282a19e84979c7ec2060f028bdc9`. A complete literal-memory-operand census finds seven loads and eight stores at displacement +0x9fc, all in four methods. There is no literal cursor-reset store among these hits. This is not alias/indirect/bulk-writer closure. [TW1,TW4]

Each source record is little-endian `{u32 tag,u32 payload}` at `P+0x1fc+8*old_cursor`. The following are source marker/payload meanings, not hardware event-code definitions. Startup markers precede the later superclass-start result and do not establish successful service publication. [TW2,TW4-TW6]

| Source record | Tag | Payload | Cursor-store location |
| --- | --- | --- | --- |
| First startup marker | 1 | 1 | `0xfffffe0009d4f464` |
| Second startup marker | 1 | 2, from original 8 B constant `0xfffffe000771c5f8` | `0xfffffe0009d4f4b0` |
| State-change enable arm | 1 | 1 | `0xfffffe0009d4f9fc` |
| State-change disable arm | 1 | 3 | `0xfffffe0009d4fa4c` |
| Common state-change continuation | 1 | 2 after enable / 4 after disable | `0xfffffe0009d4fbbc` |
| Completion status sample | 3 | Low byte of register-base+0x30 sample, after bits 8..15 test zero | `0xfffffe0009d515e0` |
| Completion progress field | 4 | u32[P+0x164] read at the record site | `0xfffffe0009d517c8` |
| Command word | 2 | Payload word read for the software record | `0xfffffe0009d51eec` |

All eight local updates implement:

```text
next = (old_cursor < 255) ? old_cursor+1 : 0
```

For every incoming u32, next lies in 0..255. Under old_cursor<=255, the current 8 B record lies within `[P+0x1fc,P+0x9fc)`. A bounded initial cursor plus serialized applications of these updates preserves that range by induction. A valid next cursor does not retroactively validate an out-of-range current store. Native initialization and writer closure are still needed. [TW4,TW5]

The cursor sequences use ordinary loads/stores. The full-canvas interpreter checks preservation outside each 8 B record and 4 B cursor field for every valid cursor, but it does not establish multiwriter atomicity, record ordering across CPUs or absence of lost records. Command tracing and the later device store retain their separately observed payload reads from the preceding report. [TW5,TW6]

## Configuration wait and interrupt wakeup

All eight configuration sleep call sites use nominal gate+0x200, event P+0x150 and raw flags 2. Their wait publication is one byte, not a u32-wide reset. The representative continuation publishes byte 1, reads register-base+0x1c, sets bit 0 and then packs the sleep arguments. Calls and register reads remain distinct observations. [TW2,TW6,TW7]

| Wait-byte store | Sleep call |
| --- | --- |
| `0xfffffe0009d4feec` | `0xfffffe0009d4ff28` |
| `0xfffffe0009d4ffa8` | `0xfffffe0009d4ffe8` |
| `0xfffffe0009d50228` | `0xfffffe0009d50268` |
| `0xfffffe0009d502b4` | `0xfffffe0009d502f4` |
| `0xfffffe0009d50334` | `0xfffffe0009d50370` |
| `0xfffffe0009d5044c` | `0xfffffe0009d5048c` |
| `0xfffffe0009d505d4` | `0xfffffe0009d50610` |
| `0xfffffe0009d506bc` | `0xfffffe0009d506fc` |

For `_interruptOccurred`, let E be byte[P+0x1f8], W be byte[P+0x150], V be u32[P+0x128], and S be the sampled u32 at register-base+0x18. The complete selected source forest has seven feasible paths and these frontiers. [TW6,TW7]

```text
mask     = (V < 2) ? 0x0001ffde : 0x0003efde
active   = (E & 1) != 0
admitted = active && ((S & mask) == 0)
wake     = admitted && ((S & 1) != 0) && ((W & 1) != 0)
```

| Predicate | Source frontier / effect |
| --- | --- |
| !active | Cold-handler call boundary `0xfffffe0009d4f62c` |
| active | Read S and write it back to register-base+0x18 before the mask test |
| active && (S&mask)!=0 | Diagnostic call path at `0xfffffe0009d4f630` |
| admitted && (S&1)!=0 | Read register-base+0x1c, clear bit 0 and write the result back |
| wake | Clear byte[P+0x150]; prepare nominal gate wakeup |
| admitted && !wake && (S&0x20)==0 | Ordinary return continuation `0xfffffe0009d4f5f8` |
| admitted && !wake && (S&0x20)!=0 | Completion continuation `0xfffffe0009d4f608` |

At `0xfffffe0009d4f5f0`, the wakeup call uses X0=u64[P+0x1c8], X1=P+0x150 and W2=0. Original vtable slot `0xfffffe0007f3fdb8` at nominal gate+0x208 resolves to `0xfffffe000c51e19c`, `IOCommandGate::commandWakeup(void*,bool)`, with diversity 0xf36c. The original wrapper loads gate+0x30 and forwards to that receiver's virtual +0x1b8 slot; actual workloop identity and wake effects remain unknown. The paired sleep slot `0xfffffe0007f3fdb0` resolves to `IOCommandGate::commandSleep(void*,unsigned)`. [TW1,TW2,TW7]

After a returning wakeup, source reuses saved S and tests bit 5 at `0xfffffe0009d4f5f4`; the set arm tail-branches to `_completeAES` at `0xfffffe0009d4f628`. Thus a single admitted snapshot can request wakeup and subsequently enter completion. The completion method has its own repeated register-base+0x30 reads and waits for bits 8..15 to clear before its status record; this is a separate snapshot/loop, with termination unproved. There is no established mapping from these markers to an authenticated daemon request or finished cryptographic output. [TW6-TW8]

## Validation and bounded continuation

Sixty-eight new UNSAT certificates cover 43 straight-line pieces / 183 lifted instructions plus the complete selected interrupt forest. Seven declared-snapshot paths are SAT-feasible; two SAT controls show why bounded initialization and the full wake predicate are needed. Source provenance retains nineteen spans, eight original pointer slots and the complete 4445-instruction literal census. The independent interpreter checks 12288 full 2560 B ring canvases and 4480 interrupt snapshots. All payload bytes and registers are declared private test data. [TW1-TW8]

Reproduce the generator with `--verify`, then run the independent interpreter and publication auditor under the documented dependency environment. Extraction and path expression construction are O(B+I+P) time/space for collection bytes B, decoded instructions I and path visits P; finite interpretation is O(cases*visits+compared bytes) time and O(code+private bytes) space. SMT cost is separate, with a 15 s observation limit per query. Counts, byte extents, masks and u32/u64 widths are exact; no timing measurement is inferred.

| Impact | Remaining evidence | Purpose |
| --- | --- | --- |
| High | Runtime view/zone/backend, constructor preservation and provider lifetime | Establishes actual 2560 B backing and the initial cursor. |
| High | Alias/indirect/bulk writer closure and gate/workloop serialization | Turns local cursor transitions into a native lifetime invariant. |
| High | Authentic sleep registration, interrupt snapshot and gate/workloop epoch | Establishes whether a wakeup reaches the corresponding wait and permits retry. |
| High | Same-job DMA/configuration/completion and daemon result | Connects source markers to actual end-to-end behavior. |
| Medium | Register mapping/semantics and completion-loop progress | Distinguishes source writeback/tests from accepted device effects. |
| Low | Marker collection/export and overwrite history | Determines whether this internal ring is recoverable as diagnostic evidence. |

**QG1**: Descriptive source/ABI analysis requires no normative judgment.

**QG2**: TW1-TW8 enumerate dependent results and falsification probes.

**QG3**: Allocation geometry, the literal cursor census, all eight local record updates, eight configuration sleep arguments and selected interrupt/wakeup flow are covered. The broader interface goal remains active.

**QG4**: Geometry, little-endian layouts, u32/u64 masks, source counts and algorithmic complexity are reproducible.

**QG5**: Metadata/request size, actual backing/initialization, current/next cursor, local/closed writer sets, source snapshots, ABI calls and native progress remain distinct.

**QG6**: Original bytes/bounds/symbols/chains, retained versioned primary flag provenance, SMT certificates and independent integer/byte-memory interpretation support the scoped claims.

**QG7**: The impact-ranked table bounds further architectural work; native completion and daemon/kext pairing remain unknown.

## Registration and physical mutex continuation

The [event-registration report](aes_event_registration_report.md) extends the nominal gate/workloop handoff with identical wait/wake hash expressions, source table globals and the input-2 registration abort predicate. It distinguishes cleared owner/depth bookkeeping from the physical mutex word, proves the action-0x10 no-block path for non-waiting registration results and checks all eight configuration sleep returns through their first X0/W0 overwrite. Native table initialization, ownership, membership and scheduler progress remain unknown (ER1-ER8).
