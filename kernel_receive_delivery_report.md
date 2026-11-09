# Receive completion, destination names and private copyout contract

Original receive selection, user receive-results, header conversion,
destination-name conversion and simple-message packing now execute in one
private CPU. The destination conversion reads a u32 receive name from port+0x34
after receiver-space matching. Packing writes that name into the 24-byte user
header. Kernel object pointers are replaced by converted-name representations
before the header's vector narrowing operation.

The selected success path copies a 36-byte simple reply plus its requested
trailer through a declared private copyout model. For split storage, the first
copy contains the 24-byte user header and the second contains inline body and
trailer. If the modeled second copy fails, the successful header prefix remains
in the private user buffer while the returned size fields are zero. Error
reporting and prior copy effects are therefore distinct state channels.

This does not establish native user delivery. Original bytes execute for the
receive/results/header/destination/packing bodies, with explicit private object
preconditions, a modeled caller handover, logical PAC and helper models. The
copyout model declares every private destination write; native copyout, rights,
object validation, allocator effects and hardware authentication do not execute.
The earlier [receive/dequeue report](kernel_queue_receive_report.md) establishes
the upstream selector contract. The broad investigation remains active.

## Primary evidence and reproduction

All addresses are unslid VAs in the original collection with SHA-256
`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.
Offsets/constants are hexadecimal; byte extents and counts are decimal.
Compiler bounds use LC_FUNCTION_STARTS. Semantic role names are distinguished
from exact nlist matches in the captured symbol results.

| Artifact | Content |
| --- | --- |
| [Source](triage_evidence/kernel_receive_delivery_source.json) | Seven functions, 1,451 unique instructions and original symbol lookup |
| [Profiles](triage_evidence/kernel_receive_delivery_profiles.json) | 240 original-source runs, caller handovers, argument cuts and declared copyout effects |
| [Proofs](triage_evidence/kernel_receive_delivery_proofs.json) | Fifteen obligations and 30 original/simplified SMT files |
| [Independent checks](triage_evidence/kernel_receive_delivery_checks.json) | Source/proof rebuild, fresh CPU replay, independent wire oracle and SDK compilation |
| [Preservation](triage_evidence/kernel_receive_delivery_delivery.json) | Prior artifact preservation and six allowed existing-file changes |
| [Quality gates](triage_evidence/kernel_receive_delivery_quality_gates.json) | Scoped QG1-QG7 and native-evidence boundaries |

From this directory:

```sh
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_receive_delivery.py
```

Time is O(source/artifact bytes + visits/effects + compiler/solver resources);
space is O(collection metadata + one private CPU map + largest profile + DAGs).
Fresh replay does not reuse the probe executor; it shares Unicorn as the ISA
engine. Source bytes, all reads/writes, API register arguments/clobbers, caller
handover, function-entry cuts and private-copy payloads are checked independently.

## Source path and declared handover

```text
source-produced single-message queue links/count/sequence
   -> original common receive + dequeue
   -> declared caller handover: X0=NULL or optional result pointer; PC=user receive-results
   -> original user receive-results BCDCC7C
      -> receive-object reference release
      -> original header conversion BCC4E98
         -> original signature body with modeled object/hash checks
         -> original receiver-name conversion BCCA164
         -> source header rebuilt with converted names
      -> original packing BCC62D0
         -> private copyout model, one or two calls
         -> source result/error update and cleanup requests
   -> result record + private user buffer + function result
```

The seed fixtures and source-write prefix come from the verified queue-send
profiles. Only single-message enqueue seeds are selected, so the received head
is the original reply M. Queue links/count/sequence are retained; destination
receiver metadata and new thread/space/map/buffer frames are explicit additions.
In particular port type, name, receiver-space pointer, counts and context are
private preconditions, not values observed in a native FairPlay exchange.

The first phase executes common receive with the same options/capacity used by
completion. On return, an explicit handover changes X0 to zero for the 3,072-byte cases, matching the ordinary helper, or an optional
private 40-byte result-record pointer for exact-capacity cases. It sets PC to
BCDCC7C while preserving other registers and SP. This
models the caller boundary; the actual intervening user receive-helper frame is
not executed. Receive itself publishes the message/state/sequence consumed by
completion. No receive, header, destination-name or packing callback substitutes
for those original bodies.

The message is the existing simple reply fixture: kernel size 44, ID 4901,
eight NDR bytes and a zero u32 result. Its generic-dispatch origin and VM operation
are not executed here. This is not an RPC502 complex/OOL request execution;
that distinct 88-to-80-byte contract remains in the
[kernel user-copyout report](kernel_user_copyout_report.md).

## Receiving context and destination conversion

| Source-derived input | Private precondition / role |
| --- | --- |
| Current-task-like helper result+0x318 | Logical receiving-space pointer S; DA context discriminator 0x8280 |
| Thread R+0x428 | Logical map pointer; DA context discriminator 0x9E54 |
| Thread R+0x398 | Receive object D, with separately held object reference |
| Thread R+0x3A0 / +0x3A4 / +0x3B8 | Source-published receive status / sequence / message |
| R+0x378 / +0x380 | Private primary buffer / NULL auxiliary buffer |
| R+0x388 / +0x38C | Primary capacity / zero auxiliary capacity |
| Space S+0x48 | Non-NULL logical live-space marker; original native validity unknown |
| Destination D+0x48 | Logical receiver-space pointer equal to S, DA discriminator 0x97F6 |
| D+1 low three bits | Class 1 in these cases; matching branch permits classes 1/2 |
| D+0x34 | u32 receive name, fixture values 0x123 and 0x87654321 |
| D+0x78 | u64 receiver context, fixture 0x123456789ABCDEF0 |

The normal header path uses a NULL local/reply object and voucher, and internal
remote disposition 18. It locks D, checks the receiving space's non-NULL marker,
then calls BCCA164 with `(S,D,18,&local_name_output)` at BCC52C4. The latter
checks port class and receiver-space identity, decrements u32(D+0x8C), reads
u32(D+0x34), executes the ordinary unlock-like body BCCF39C, decrements u32(D+4),
and stores the name through its u32 output pointer.

The source conversion derives a pre-existing receive name; it does not allocate
or prove a native namespace entry in these cases. Alternate receiver-space,
inactive-port, voucher and non-NULL reply-object branches remain outside the
execution set. Symbolic checks cover all type bytes, pointer equality, u32
name words and decrement arithmetic at fixed disjoint placements.

Receive-results first decrements the receive object's reference at BCDCE04.
Destination conversion decrements another message-associated reference at
BCCA2C0. The private D+4 count is seeded to 3, producing 3 -> 2 -> 1; its
send-once count is seeded to 1, producing 1 -> 0. Native ownership/acquisition of
these seeded references is not established. Underflow/last-reference branches
are captured but not executed in this set.

## Header rebuilding and user representation

At BCC53A4-BCC53C4 the source rebuilds header bits from dispositions and retained
flags. At BCC53C8-BCC53DC it loads the two u32 names from scratch storage,
widens ordinary names with zero extension and widens the UINT32_MAX sentinel to
UINT64_MAX, then replaces the two kernel pointer-width header fields.
All-name-word widening has a symbolic obligation.

Packing subsequently uses XTN at BCC663C to narrow those converted fields.
The source order establishes why this is name packing rather than object-pointer
truncation. Original vector loads/narrowing/stores execute in every case and
have a byte-array proof with an explicit SIMD-lane rule.

| User simple-reply offset | Width, bytes | Source-derived value in these cases |
| --- | --- | --- |
| +0 | 4 | Bits 0x1200 |
| +4 | 4 | Inline size 36 |
| +8 | 4 | Remote/reply name 0 |
| +0x0C | 4 | Local/receive name read from D+0x34 |
| +0x10 | 4 | Voucher name 0 |
| +0x14 | 4 | Message ID 4901 |
| +0x18 | 8 | NDR bytes 00 00 00 00 01 00 00 00 |
| +0x20 | 4 | Fixture result 0 |

The current SDK checks the 24-byte user header, these name offsets, 36-byte
simple-reply layout, audit trailer layout and MACH_RCV_INVALID_DATA=0x10004008.
Private views remain reconstructed types, not original header provenance.

## Trailer, capacity and copyout request ABI

Three receive selectors execute: default 0 requests 8 bytes, audit selector 3
requests 52, and AV selector 7 requests 68 on the seeded 64-bit map. Capacities
are either the exact inline+trailer requirement or 3,072 bytes. The selector and
completion use the same capacity/options, so the normal receive gate admits
the complete packet in these cases; no truncated-trailer path executes here.

| Packet contract | Default | Audit | AV |
| --- | ---: | ---: | ---: |
| User inline bytes | 36 | 36 | 36 |
| Requested/delivered trailer bytes on success | 8 | 52 | 68 |
| Complete private packet bytes | 44 | 88 | 104 |

The original trailer writer stores requested extent, the source-published old
queue sequence UINT32_MAX, the receiver context at trailer+52 for this map,
and zero remainder. It preserves audit bytes +20..51. Their zero fixture value
comes from the kernel template; it does not establish an initiating user's
identity. A byte-array proof covers all 256 audit bits and all sequence/context
words through the writer.

| Storage bit 6 | Source copyout requests at BE7798C |
| --- | --- |
| Clear, classes 0/2 | `(packed_header, user_buffer, 36+trailer_extent)` |
| Set, classes 1/3 | First `(packed_header,user_buffer,24)`; then `(split_body,user_buffer+24,12+trailer_extent)` |

All four storage classes execute. The copyout model records source/destination,
length, source bytes, prior destination bytes and return value. A successful
model copies into a bounded private buffer; a failure model performs no writes.
Replay recomputes the source bytes from its own CPU memory and checks every
declared effect. Native copyout may have additional partial-fault behavior;
the clean failure model is an explicit premise.

The scalar packing capacity/truncation algebra is symbolically checked over
u32 words, including its branch comparisons. Its broader interpretation requires
representable inline+trailer arithmetic and a valid original message; those
lemmas do not establish native reachability of a particular truncated packet.

## Failure, result record and cleanup boundaries

| Modeled copy outcome | Function result | Internal result sizes | Private user-buffer effect |
| --- | --- | --- | --- |
| Complete success | 0 | Inline 36, requested trailer, auxiliary 0 | Complete packet |
| First copy fails | 0x10004008 | All three sizes zero | No model write |
| Split second copy fails | 0x10004008 | All three sizes zero | Previously copied 24-byte header remains |

The thread receive status remains success: dequeue completed before conversion
and copyout. The final function result is a later channel. Original name/right
counter consumption also precedes copyout and is not undone on these failures.
This is a source/control-flow observation under the declared callback model;
it is not evidence of a native leak or final object-lifetime violation.

The original internal result record is 40 bytes:

| Offset | Width, bytes | Observed role |
| --- | --- | --- |
| +0 / +4 / +8 | 4 each | Inline / trailer / auxiliary sizes |
| +0x0C | 4 | Receiver-name/error field; zero on these normal paths |
| +0x10 | 4 | Sequence |
| +0x14 | 4 | Reserved bytes, zero in these runs |
| +0x18 | 8 | Receiver context |
| +0x20 | 8 | Packed metadata; zero for these message fixtures |

All 240 records are captured while the original receive-results frame is live,
immediately before its epilogue. In 120 cases a non-NULL entry argument causes
the original 40-byte copy to the optional output record. The 120 ordinary-NULL
cases leave that optional destination untouched. A byte-array proof covers all
320 input bits of the non-NULL copy. Sequence/context remain in the internal
record when copy failure clears size fields; they do not prove packet delivery.

Packing requests message-buffer cleanup, an allocator-view check and a zone-free
operation before returning. Those operations remain explicit models. The private
allocator view and size 0x100 are fixtures, not recovered original allocation
sizes. The source's cleanup requests and function return are established; native
deallocation, lifetime and downstream ownership are unknown.

## Validation, assumptions and continuation

The 240 cases cover four storage classes, three trailer selectors, two receive
names, exact or 3,072-byte capacity, ordinary-NULL/optional-result callers, and
first/second-copy outcomes. The set contains 96 complete private packet copies,
96 first-copy failures and 48 split second-copy failures. The independent oracle
checks the entire 4,096-byte private user window, including untouched bytes,
the internal and optional result records, queue depletion, object/send-once
counters, original entry arguments and private copy effects.

Fifteen obligations and 30 saved SMT forms pass. Original receive/header/name/
packing bodies are distinguished from declared helper models. Native admission,
scheduling, full daemon-request provenance and user delivery remain unestablished.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| RD1 | Original collection and unslid mapping identify this compiler epoch | Rehash bytes and independently recover mappings/bounds |
| RD2 | Verified single-message queue seed supplies the reply links/count/sequence | Replay producer and compare native queue/message identity |
| RD3 | Added thread, space, map, port name/context and reference counts are valid private premises | Verify real namespace membership, task/map/thread ownership and held references |
| RD4 | The explicit caller handover models the function-entry boundary | Execute the full intervening caller and match registers, SP and native event order |
| RD5 | Simple reply, NULL local/reply object and voucher describe this execution set | Execute non-NULL reply/voucher, inactive/foreign-space and complex/OOL paths |
| RD6 | Logical PAC preserves fixture pointers; arbitrary hash outputs match fixture tag bytes | Attest native keys, genuine objects and authentic signatures |
| RD7 | Locks, observers, object checks, task access and allocator callbacks have declared effects | Recover/execute their bodies with full state and concurrent context |
| RD8 | Successful private copyout writes all bytes; failed model writes none | Measure native partial-fault effects and real user-buffer validity |
| RD9 | Receiver map is 64-bit and capacities/options agree across receive and packing | Establish actual map, complete option word, buffer allocation and capacity provenance |
| RD10 | Current SDK/private views corroborate layouts without matching runtime-build attestation | Match native source revision/UUID and original private types |
| RD11 | Optional result-record cases model a separate caller precondition; ordinary helper uses NULL | Identify genuine non-NULL callers and their record lifetime/consumers |
| RD12 | Fresh replay shares Unicorn; passing results establish source/model consistency | Cross-check another ISA engine and native daemon-visible bytes |

| Impact | Further evidence | Interface question |
| --- | --- | --- |
| High | Complex RPC502/OOL descriptor conversion and receiver mapping coupled to packing | How does the kext's native 88-byte request become the daemon's 80-byte request and borrowed data? |
| High | Full caller/scheduler and actual object/namespace provenance | Which private preconditions hold in a real exchange? |
| High | Native copyout and installed framework/MIG consumers | Which bytes, rights and status reach fairplayd under success and partial failure? |
| Medium | Voucher/reply-object, inactive/foreign-space and last-reference paths | How do alternative right/name and lifetime contracts differ? |
| Medium | Observer, object-check, allocator and copyout helper bodies | Which effects are hidden by the remaining models? |
| Low | Matching original symbols/private headers | Which descriptive roles can become exact names/types? |

QG1: Factual technical analysis requires no normative conclusion.
QG2: RD1-RD12 identify dependencies and explicit falsification probes.
QG3: Selected receive completion, destination-name conversion, simple packing,
trailer, error and result-record contracts are covered; the full goal remains active.
QG4: Widths, offsets, byte extents, modular arithmetic, complexity, SDK assertions
and exact reproduction are explicit.
QG5: Kernel pointers versus converted names, receive state versus copyout result,
ordinary NULL versus optional result callers, and partial bytes versus zero size
reports are distinguished. Unexecuted ownership/lifetime branches remain explicit.
QG6: Original bytes, source-state prefix, independent wire oracle/replay, rebuilt
SMT, SDK checks and artifact hashes support the scoped claims.
QG7: The impact table bounds complex/OOL, namespace, native transport and helper work.
