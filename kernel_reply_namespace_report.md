# Original reply-right namespace creation and produced-name lookup

Original header copyout now executes its namespace admission check, free-entry allocation, generation update and send-once publication. The resulting reply names resolve back to the same reply object through original generic right translation. Wrong-right and changed-generation probes return17 and15, respectively. This replaces the whole reply-state, name/entry-output, publication and space-lock models used in the earlier complex receive bridge for the selected ordinary-port path.

The components stop before original descriptor copyout. Their inputs retain explicit namespace, typed-object, source-container and internal-header representation premises. They do not execute the original transport between the kext constructor and this header component, actual user copyout, native IPC or a complete FairPlay exchange. In particular, RPC700's actual recipient remains unknown.

## Provenance and assumption register

Primary KC SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Addresses are preferred VAs; offsets, capacities and record extents are bytes, little-endian. Original inputs, IDBs and memory stores are unchanged. Original KC and existing evidence suffice; no new IDA query was needed.

| Artifact | Evidence |
| --- | --- |
| [Source](triage_evidence/kernel_reply_namespace_source.json) | 91 complete functions /12562 instructions, 16 new instruction roles, exact symbols, selected type-policy bytes and class22 validation source |
| [Profiles](triage_evidence/kernel_reply_namespace_profiles.json) | Original preparation/header/lookup components, exact RAM origins, overlay before images, namespace ABI frames and source reads/writes |
| [Checks](triage_evidence/kernel_reply_namespace_checks.json) | Independent complete-record/ownership/name oracles, source recapture, fresh producer/CPU replay and scalar proofs |
| [Recovery](triage_evidence/recover_kernel_reply_namespace.py), [probe](triage_evidence/probe_kernel_reply_namespace.py) | Original source capture and explicit component construction |
| [Replay](triage_evidence/replay_kernel_reply_namespace.py), [validator](triage_evidence/validate_kernel_reply_namespace.py) | Independent executor and semantic checks; no probe executor import |
| [Delivery](triage_evidence/kernel_reply_namespace_delivery.json), [quality gates](triage_evidence/kernel_reply_namespace_quality_gates.json) | Prior preservation, owned reporting changes and scoped gates |

The [preceding receive/copyout report](kernel_receive_copyout_report.md) supplies the preserved RAM/global starting epoch. The [original kext constructor report](kext_constructor_request_report.md) supplies separate source-produced RPC502/700 packet fields. The [complex receive bridge](rpc502_receive_bridge_report.md) previously modeled reply name/entry creation and namespace publication; its descriptor/daemon components remain separately scoped. The [namespace report](kernel_namespace_report.md) supplies the encoded-table and generic right-translation context, and the [zone startup report](kernel_zone_startup_report.md) supplies the eight explicitly transferred class22 validation bytes.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| RN1 | The pinned KC, compiler bounds, logical fixups and exact nlist records identify this source epoch. All instruction-level claims depend on it. | Rehash and recapture complete bodies, roles, selected policy bytes and every executed word. |
| RN2 | The private encoded table, free-list head, free entry, counters, owner/task and SMR records satisfy the selected source contracts. | Recover original namespace initialization/growth/free-list writers and a native task's complete table/domain epoch. No real task-local numeric endpoint is inferred from the fixture. |
| RN3 | The parent receive-results RAM/global epoch and explicit fresh reply storage support separate new calls. | Establish actual caller stacks, object allocation, native event ordering and original ownership across the transition. Exact byte transfer does not establish an uninterrupted runtime event. |
| RN4 | The original no-senders kmsg container and original constructor's packet fields are imported into a declared internal RPC representation. Header results depend on this representation. | Execute actual kext constructor -> transport allocation/copyin/send -> recipient receive, preserving all memory/CPU/ownership transitions. The size/disposition/object-pointer overlay is not a transport execution. |
| RN5 | Logical PAC preserves declared pointers and keyed validation returns its declared value. | Establish actual signed entries/objects, hardware authentication and keyed hashes. Source PAC modifiers and hash inputs are verified, but hardware/key validity is unknown. |
| RN6 | Exactly eight class22 validation bytes from startup case1 supplement the retained class24 epoch. | Join complete native zone/cache/page creation, allocation and reclamation. Matching arithmetic fields and typed metadata do not prove a genuine native allocation. |
| RN7 | Free-entry generation bits, cached two-bit seed and selected ordinary type1 port/policy describe this execution set. | Recover real generation initialization/recycling, random-cache refill, special kernel-reply kind11 and nonzero policy/ancillary branches. Cached bit extraction is not entropy-quality evidence. |
| RN8 | Descriptor count1, inline storage class0 and the RPC502/700 schemas bound the header component. | Continue original descriptor/VM conversion, user packing/framework dispatch and application/reply handling. RPC700 destination identity and a native round trip remain unknown. |

## Routine roles and interface coverage

Eleven additions contribute1099 instructions. Complete source capture does not imply all branches execute. Namespace growth is an entry stop; random-cache refill branches are captured while the retained rollover consumes cached bits.

| Address | Instructions | Recovered role / coverage |
| --- | ---: | --- |
| 0xfffffe000bccffa4 | 70 | Create a send reference under original typed checks/lock; two calls supply separate destination holds |
| 0xfffffe000bccc258 | 29 | Validate class22, lock reply object, mark state access and return state/associated pointer in X0/X1 |
| 0xfffffe000bcbc0f0 | 88 | Pop free entry, update generation/seed, sign/store object, return name and entry via output pointers |
| 0xfffffe000bcbbff4 | 63 | Namespace capacity/free-chain admission check; selected calls read without consuming entries |
| 0xfffffe000bcbc3a8 | 443 | Namespace growth body; captured, stopped before entry |
| 0xfffffe000bcd5b90 | 165 | Publish selected send/send-once right metadata, unlock object and update namespace index bounds |
| 0xfffffe000bd0af50 | 24 | Exact `_lck_ticket_lock`; uncontended space-lock path executes |
| 0xfffffe000bd0b348 | 28 | Exact `_lck_ticket_unlock`; normal release/preemption path executes |
| 0xfffffe000bccb384 | 79 | Associated-task/type-policy decision used during publication; selected ordinary type1 path |
| 0xfffffe000be57f8c | 76 | Cached bit extraction and refill body; retained rollover extracts two cached bits |
| 0xfffffe000bcc92e4 | 34 | Generic requested-right translation through actual namespace lookup; success retains lock without an extra reference |

Other role names are descriptive, not recovered original symbols. Existing bodies execute original port initialization, make-send-once, header conversion, typed ticket acquisition, SMR lookup/revalidation and port unlock. [RN1-RN8]

## Source imports and call sequence

The starting full RAM/globals come from the preceding successful receive-results component, after original kmsg zeroing and modeled raw retirement. New calls preserve this state except for independently recorded namespace/owner/type/seed/fresh-storage fixtures. The reply object is declared at private address0x6500080070. Its within-16-KiB-page offset112 matches the source-derived class22 page-start adjustment; this remains conditional allocation metadata. [RN2,RN3,RN6]

Original source performs two destination send creations, reply-object initialization, reply unlock and make-send-once before header conversion. The destination starts with reference1/send0, reaches reference3/send2 and finishes header conversion at reference2/send1. This retains a caller-side send hold while the message-owned send hold is consumed. The reply starts with reference1 after initialization and reaches reference2/send-once1 before header copyout.

The packet's separate original constructor cases are1 for RPC502 and17 for RPC700. Both are freshly replayed. The source-produced56 bytes after the32-byte header, voucher field and message ID are retained. A declared representation overlay sets internal bits0x80001211, message size88, destinationPORT and local/reply objectREPLY. The inline256-byte kmsg container is imported separately from the preceding original sender. No joined constructor/transport/send execution is asserted. [RN4]

```text
separate original kext constructor -> source packet fields
                                      |
parent receive-results RAM + explicit namespace/storage/type fixtures
  -> original destination send creation, twice
  -> original reply init -> unlock -> make-send-once
  -> declared internal RPC header + source packet fields/container
  -> original header copyout
       space lock -> admission -> reply-state lock
       -> entry allocation/generation -> temporary reply retain
       -> publication/unlock -> destination translation
       -> space unlock -> temporary reply release
       -> STOP before original descriptor copyout
              |
              +== full RAM/globals; separate lookup calls ==>
                    original generic right translation
                     +-> matching right/name -> object returned locked
                     +-> wrong right -> return17, unlock
                     +-> changed generation -> return15, unlock
```

These are internal namespace and object boundaries. They add no Mach message emission. The generated reply name will occupy the user request's remote/reply field after later packing; the service receive name remains a separate local field. Actual numeric native names are unknown. [RN2-RN5,RN8]

## Admission and free-entry allocation

The declared token is TABLE|5, TABLE=`0x400000100000`, yielding a1024-byte table capacity and24-byte entries. Original0xfffffe000bcbbff4 derives `q=floor(capacity/24)` using a reciprocal multiply, then uses `floor(7*q/8)` as the selected counter threshold. For1024 bytes, q=42 and the threshold is36. A request for one slot passes the scalar threshold at counter35 and fails at36. Native wraparound/noncanonical counter epochs are outside these admissible counter fixtures.

Admission also walks the requested free-chain extent. The slot must be nonzero and its full24 bytes must fit. Index41 ends at1008 bytes and fits; index42 ends at1032 bytes and reaches the original trap prefix. An empty head or the counter36 threshold reaches the original growth helper with the space lock held. No growth, slot consumption, right publication, lock release or completed receive is inferred from those stops.

Actual allocation at0xfffffe000bcbc0f0 reads the head index at table+0x0c, follows that slot's next index at entry+0x0c, publishes the next head, decrements space+0x18 and updates entry+8. It then logically signs/stores REPLY into entry+0 with modifier derived from the entry address and discriminator0xf444. The output ABI is `(space,object,u32 *name,entry **entry)`, returning X0=0 on the selected path. The allocator writes both outputs itself; no name or entry-output model remains. [RN2,RN5,RN7]

## Generation, seed and produced names

Let B be the previous u32 entry word, s=(B>>24)&3 and g=B>>26. Original arithmetic computes `delta=((B<<2)&0x0c000000)+0x04000000`, equivalently `(s+1)<<26`. Thus the six generation bits advance by1+s positions. This is not a universal increment-by-one rule.

Without carry, the new word is B+delta. Carry occurs exactly when g+s+1>=64. On the retained carry path, original code asks0xfffffe000be57f8c for two cached bits from space+0x1c. Cache0x35 supplies bits1 then0, assembled into result2; the cache becomes0x0d, and the allocator uses2<<24 as the new word. No refill or entropy acquisition executes.

The source name expression is `u32(index<<8 | new_word>>24 |3)`. Its low two bits are forced to3; generation bits come from the upper six bits of the entry word. Publication subsequently adds right bit18 and one user reference, leaving generation/seed bits intact.

| Fixture | Index / previous word | New word before rights | Produced reply name | Meaning |
| --- | --- | --- | --- | --- |
| RPC502 ordinary | 2 /0 | 0x04000000 | 0x207 | Seed0, generation step1 |
| RPC700 ordinary | 5 /0x02000000 | 0x0e000000 | 0x50f | Seed2, generation step3 |
| RPC502 rollover | 2 /0xfc000000 | 0x02000000 | 0x203 | Carry; two cached seed bits consumed |
| RPC502 table edge | 41 /0xf8000000 | 0xfc000000 | 0x29ff | Last fitting tested free slot |
| RPC502 counter edge | 2 /0, counter35 | 0x04000000 | 0x207 | Last passing tested threshold counter for one requested slot |

The earlier complex bridge's modeled name0x203 remains a private fixture. The rollover component shows one conditional original allocator state that produces it; it does not establish that the earlier bridge represented this native allocation history. [RN2,RN7]

## Publication, reference transfer and header fields

Original header conversion increments the reply object's reference count2->3 at0xfffffe000bcc51b0 before calling publication at0xfffffe000bcc5214. Publication's ordinary type1/send-once branch preserves send-once1, unlocks the port and stores `new_word |0x00040001` into entry+8 at0xfffffe000bcd5d50. The selected type-policy halfword at0xfffffe0007e62ba0 has bit0x200 set; the executed policy helper therefore contributes no additional bit23 to this entry.

The entry now contains the logically signed reply object, send-once right bit18, one user reference and the source-produced generation/seed bits. Trailing entry bytes16..23 retain their declared canaries. Namespace+0x70/+0x74 become the allocated minimum/maximum index. Header conversion later releases its temporary reply reference3->2. The existing send-once reference is represented by the new namespace entry; the selected path does not create a second send-once count. These are conditional count/field effects, not a total native lifetime proof. [RN2-RN7]

| Stage | Destination object refs / send refs | Reply object refs / send-once refs |
| --- | --- | --- |
| Parent epoch / fresh initialized reply | 1 /0 | 1 /0 |
| Two original send creations / make-send-once | 3 /2 | 2 /1 |
| Header temporary reply retain and publication | 3 /2 | 3 /1 |
| Header finishes namespace conversion | 2 /1 | 2 /1 |
| Successful generic lookup | 2 /1 | 2 /1; reply lock held |
| Original lookup unlock | 2 /1 | 2 /1; lock released |

At the descriptor-copyout boundary, original code has rebuilt the pointer-width header as follows. This is still an88-byte internal message;80-byte user packing is a later stage, not executed by these components.

| Header field | Width | Source-produced value |
| --- | ---: | --- |
| Bits | 4 | 0x80001112 |
| Message size | 4 | 88 bytes |
| Remote/reply slot | 8 | Allocator-produced reply name, zero-extended |
| Local/destination slot | 8 | Declared service receive name0x303, zero-extended |
| Voucher | 4 | 0 |
| Message ID | 4 | Original constructor's502 or700 |
| Remaining body | 56 | Exact original constructor bytes after its32-byte header |

The source reply name replaces an object pointer through namespace conversion before later narrowing to the user header. No pointer truncation is used to invent a Mach name. The five completed header components release their space/object locks and return preemption nesting to0 before the descriptor boundary. The three unsuccessful prefixes retain the space lock/nesting1 and unchanged entry/right/header state; they are unfinished control paths, not completed failures or native resource leaks. [RN3-RN8]

## Produced-name lookup and ownership

Each successful header state supplies its complete RAM/globals to four separate original generic-translation components. Only output canaries are reset; entry/object/count fields are not repaired. The valid case requests right index2, so the wrapper checks entry bit16+2=18. The underlying original SMR lookup authenticates the encoded table/object, takes the actual typed ticket lock, reloads the table and checks identity, generation and nonempty rights.

| Lookup input | Original result | Output / lock / references |
| --- | --- | --- |
| Produced name, requested right2 | 0 | Writes REPLY, leaves reply locked/nesting1, reference2 unchanged |
| Same name, requested right0 | 17 | Output canary unchanged; releases lock, nesting0; reference2 unchanged |
| Produced name XOR4, requested right2 | 15 | Generation mismatch; output unchanged; releases lock, nesting0; reference2 unchanged |
| Original unlock after valid lookup | No status interpretation assigned | Releases held ticket, nesting0; reference2/send-once1 unchanged |

The valid lookup adds no reference. The separate original unlock confirms the transfer of lock ownership to the caller. These components do not consume the send-once right or send a reply. Native SMR reclamation, hardware memory ordering, actual namespace permissions and the receiving task's identity remain unknown. [RN2,RN3,RN5,RN7]

## Independent validation and reproduction

Independent validation passes for48 preparation/header components and20 produced-name lookup/unlock components:68 complete RAM replays,11226 original instruction visits and four scalar proofs. It recaptures91 complete function bodies /12562 instructions and16 added role words. Fresh replays verify the preceding receive-results component, two original kext packet producers and original class22 zone-startup case1.

Independent input plans check80 private and16 global overlay before images, all48 full port/reply/space/entry/header/global expectations, eight packet/import boundaries, five actual namespace publications and three held growth/trap prefixes. Twenty lookup components verify name/right/generation, unchanged references, exact output and lock/nesting contracts. Source frames independently locate allocation outputs before publication and the temporary reply retain.

Fresh CPU replay checks1841 writes /12206 bytes,2578 reads /15433 bytes,68 final1-MiB RAM images /71303168 bytes and1224 global ranges. It checks87 namespace ABI/record frames,29 logical data signatures,101 logical data authentications and429 logical return-PAC steps. All16 API models are the two opaque keyed-hash results per header component; namespace allocation, entry outputs, publication, locks and cached seed extraction execute original instructions. The independent executor shares Unicorn's ISA implementation; complete-record, byte and arithmetic oracles provide separate semantic checks, not cross-engine verification.

Four counterexample queries are UNSAT: the generation delta equals one plus the retained two-bit seed; carry matches the six-bit generation plus that stride; generated names revalidate their24-bit index and six generation bits; and the reciprocal gives floor(capacity/24) for all decoded capacities through268419072 bytes. The first two cover every u32 entry word; the name proof assumes index<=0xffffff. The capacity proof writes C=24q+r with q>=0 and0<=r<24 and proves `q*2^32 <= C*0x0aaaaaab < (q+1)*2^32` across the same capacity domain. The original UMULL product fits u64 in this domain. These scalar results do not prove valid native entries, randomness, reachability, locking progress or object lifetime.

```sh
cd /Users/___/dev/dylex/extracted

env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_reply_namespace.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_reply_namespace.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_reply_namespace.py
```

Expected validation output is four UNSAT proof records, eight family summaries and `all_checks_pass:true`. Recovery is O(image+source) time/space. Execution/replay is O(image+visits+RAM+effects) time and O(image+RAM+journals) space; the four scalar solver queries have separate solver cost. No native contention, allocation, RPC or receive-time bound follows.

## Bounded expansion and quality gates

| Impact | Further evidence | Interface resolved |
| --- | --- | --- |
| High | Original transport/copyin/send/receive from the source-produced kext request | Replace the imported internal representation and establish actual caller/data/ownership continuity |
| High | Original descriptor/VM conversion from this produced header state | Connect the new namespace output to OOL payload and final daemon bytes |
| High | Native task namespace initialization, growth, recycling and complete zone/SMR epochs | Replace free-list, counter, type and allocation premises |
| High | Actual kernel-special-reply kind11 binding/completion | Extend the ordinary type1 reply-object result to the transport's thread-bound reply endpoint |
| Medium | Generation cache refill and real state writers | Establish complete seed provenance without inferring entropy from cached bits |
| Medium | Nonzero type-policy/associated-task and ancillary branches | Extend publication flags and lifetime handling beyond the selected ordinary path |
| Medium | RPC700 recipient registration and dispatch | Identify its actual receiving facility independently of compatible packet shape |
| Low | Private type/symbol corroboration | Refine descriptive routine names while preserving exact instruction provenance |

QG1: All conclusions are descriptive technical analysis; no normative conclusion is required.

QG2: RN1-RN8 identify assumptions, dependent results and falsification probes.

QG3: This increment covers original reply-state, admission, entry allocation/generation/signing, right publication, reference transfer, header names, space/object locks and produced-name translation. New message emission, native recipient identity and full transport completion are not claimed.

QG4: Byte capacities/entry extents and fixed-width arithmetic are explicit. Counter35/36 and slot41/42 probes check the selected boundaries; generation, name and capacity domains are recorded. No native timing or physical-unit result is asserted.

QG5: Packet/container imports, ordinary versus special reply objects, cached seed versus randomness, namespace move versus temporary retain and held prefixes versus completed calls are distinguished. Unknown native behavior and unexecuted branches remain explicit.

QG6: Primary KC bodies/symbols/policy/role words and every visited instruction are recaptured; fresh source producers, exact overlay origins, complete records and source-backed name/lookup oracles pass. Pinned reference sources are not substituted for native implementation identity.

QG7: The impact table bounds remaining transport, descriptor, namespace, allocator and special-reply interfaces. The full interface-investigation goal remains active.
