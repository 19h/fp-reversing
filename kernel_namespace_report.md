# Kernel namespaces, receive references and special-reply linkage

The matching kernel resolves receive names through an authenticated encoded table and24-byte capability entries. It locks the candidate object, reloads the table, revalidates object identity, rights and generation, then returns a locked object without adding a reference. The receive wrapper adds its own object reference before unlocking; a matching decrement occurs in receive-results processing. Generic send/right translation has a different contract: successful translation returns the object locked, without that extra reference.

Special-reply linkage also has two distinct holds: a destination object reference and a send-turnstile primary reference. A paired private link/unlink fixture restores both counters. User special-reply replacement clears/releases the previous thread binding before new allocation; kernel unbinding reaches port destruction. These contracts explain additional lifetime boundaries beneath the daemon and kext paths. Actual port identities, namespace contents, lock/concurrency behavior, PAC validity and a successful FairPlay exchange remain unknown.

## Provenance and assumption register

Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; kernel UUID: `9b65bd6e-027b-34d1-a22b-ac03dccffc84`. The original `_version` identifies Darwin27.2.0, `xnu-13432.41.4~3/RELEASE_ARM64_T6041`. All addresses are unslid. [Native contracts](triage_evidence/kernel_namespace_contracts.json) retain23 compiler-bounded original ranges,24 instruction checks, exact available nlist matches, six full-domain arithmetic proofs and a compiled partial layout. Conventional names for stripped functions below are source-correlated roles, not invented original symbols.

[Private profiles](triage_evidence/kernel_namespace_profiles.json) retain93 cases, original code-page hashes, seeds, native writes, helper models, PAC bypasses, stage snapshots and stops. [237 explicit checks](triage_evidence/kernel_namespace_profile_checks.json) cover every profile. Unicorn2.1.4 uses UC_CPU_ARM64_MAX to support the original LSE instructions; its default CPU stopped at LDADD before that explicit configuration. Atomic counter instructions execute in private memory. PAC, object locks, allocation/initialization, guard disposition, task context and deeper turnstile operations are modeled. The receive-reference pair enters a native release slice in a second synthetic phase; it does not execute a queue receive or message delivery.

No native target, host IPC, kernel allocation, lock, scheduling callback, synchronization operation or target syscall was executed. Original binaries, IDBs and analysis inputs remain unchanged.

| ID | Assumption / basis | Dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| N1 | Supplied collection is relevant to the analyzed images | Cross-layer linkage | Match loaded module identities, slides, bytes and live task mode | Static identity confirmed; runtime pairing unknown |
| N2 | Original compiler ranges and AArch64 field/width rules describe these operations | Native coordinates, masks and counter arithmetic | Recheck source bytes, compiler starts, partial layout and proof formulas | Confirmed for inspected operations |
| N3 | Pinned XNU source supplies conventional private names/types | Namespace, SMR, turnstile and state terminology | Match exact target revision or recover every implementation independently | Retained; reference differences from other increments remain applicable |
| N4 | Explicit private SMR/zone/lock/PAC/object seeds describe only their stated fixtures | Local executions and injected post-lock table changes | Stop on unknown code/data; attest native object provenance, locking, barriers and PAC separately | Retained; native concurrency and reachability unproved |
| N5 | Selected capability-bit states and reference seeds isolate local predicates | Rights/last-reference cases | Verify namespace construction invariants and real allocator/reference contracts; a nonnull object with synthetic dead-name bits is not a validated namespace state | Retained; bit-level fixtures are not native-state claims |
| N6 | Returning guard/task/turnstile models isolate control flow | Guard suppression, diagnostic PID and linkage cleanup | Recover guard disposition, task context, workloop and full turnstile effects; observe native behavior | Retained; actual external effects unknown |
| N7 | The recovered common receive caller follows its normal object-reference contract | Receive acquisition/release correspondence | Verify queue/block/continuation/error paths and actual installed CF reception | Compatible static path established; native exchange unknown |

The [primary-source inventory](triage_evidence/kernel_namespace_references.json) records exact URLs/hashes at commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`. The target's exact source revision is unknown. Native evidence remains authoritative where that reference differs.

## Name-to-object path

```text
Mach2 receive name
  -> 0xfffffe000bcc8cf4  receive-name wrapper
       -> 0xfffffe000bcd2cc0  namespace lookup
            table acquire -> candidate object lock -> table/object recheck
            -> rights and generation checks -> locked object, no extra ref
       -> object ref +1 -> unlock -> publish receive object
  -> 0xfffffe000bcdd4e4  user receive setup / common queue receive
  -> 0xfffffe000bcdcc7c  receive results
       -> selected reply-link completion -> object ref -1
       -> later message namespace/VM copyout

SYNC_WAIT boosting name
  -> 0xfffffe000bcc92e4  generic right translation
       -> same namespace lookup -> requested-right bit check
       -> locked object, no extra ref
  -> caller retain/unlock -> reply linkage -> caller release
```

The wrapper/helper coordinates are linked by original BL instructions and the [Mach2 handler report](kernel_dispatch_report.md). The [reference lookup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_right.c#L109) explains the conventional `ipc_right_lookup_read` role. Native behavior is more specific than treating a numeric port name as an address.

| Native field | Width / stride | Use |
| --- | --- | --- |
| Name index | u32 name >>8 | Select capability entry |
| Entry | 24 bytes | Object pointer+0; capability bits+8; remaining fields retained as opaque here |
| Space+0x48 | u64 encoded array token, authenticated | Current entry-table allocation base/extent |
| Entry bits16..20 | Mask0x001f0000 | Nonempty capability-type field |
| Entry bits26..31 | Mask0xfc000000 | Six generation bits |
| Name low8 | Compared against `(entry_bits >>24 &0xfc) |3` | Generation plus required low-two-bit pattern |

The original entry sequence computes `index*24+24` and requires it not exceed the decoded byte capacity before the first entry access. Index0 is rejected immediately: names0..255 clear both output parameters and return15. For every u32 name, the complete first-entry extent is at most `0x18000000=402653184` bytes; this arithmetic does not overflow u64. The six generation bits and the two fixed low bits are proved equivalent to the native shifted32-bit comparison. A matching index alone is insufficient: names0x32c/0x32d/0x32e fail when0x32f matches the retained entry's generation.

The allocation-token decoder has two native forms. Let T be the authenticated token and P=`1<<46`:

| T bit46 | Decoded base | Capacity, bytes |
| --- | --- | --- |
| 0 | `(T & ~0x3fff) | P` | `(T &0x3fff) <<14` |
| 1 | `T & ~0x1f` | `((T &0x10) |0x20) << (T &0xf)` |

These are numeric target formulas, independently corroborated by the reference [typed allocation-array interface](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/kalloc.h#L990). The token is not a plain table address. Both decoded bases are32-byte aligned; the maximum capacity under these formulas is268419072 bytes. The private cases exercise both forms. This neither validates the token's PAC nor proves that every bit pattern represents a real allocator result.

## Protected lookup, revalidation and outputs

For nonzero index, native lookup increments thread+0x1c8, loads CPU index from thread+0x1b8, publishes the domain sequence from `0xfffffe000caac348` into a per-CPU slot addressed through `0xfffffe000caac350` with128-byte stride, then executes DMB ISH. The [reference SMR enter/leave](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/smr.c#L676) disables/enables preemption around the protected read. The native counter/slot operations corroborate that role; thread+0x1c8 is not treated as an arbitrary recursive SMR nesting allowance.

After reading/authenticating a nonnull entry object, lookup calls the lock-allow-invalid wrapper `0xfffffe000bcca438`. Its underlying lock operation is a separate helper, not a proved nonblocking try-lock. If locking returns true, lookup reloads/authenticates space+0x48, recomputes the entry address, reloads the object and requires it to equal the locked object. It then checks nonempty type bits and the generation comparison. There is no local retry loop in this lookup range. A latency bound for the opaque lock helper is unknown.

| Condition | Native status / action | Caller outputs |
| --- | --- | --- |
| Index0 | 15, before protected section | Explicitly writes bits0/object0 |
| First or reloaded table token null | 16 | Otherwise unchanged; unlocks when an object was already locked |
| Out-of-bounds first entry, null object, failed lock | 15 | Unchanged |
| Reloaded object changed, no type bits or generation mismatch | 15, after unlock | Unchanged |
| Revalidation succeeds | 0; object stays locked | Writes original capability bits and object pointer |

For entered paths, native code stores zero to the selected CPU slot with STLR, decrements the preemption counter and may call `0xfffffe000be8663c` when the decrement reaches zero and the current CPU-associated pending-work byte has bit2. Private cases preserve an initial counter2, exercise CPU slot1 at+128, and observe the selected pending-work call. They do not verify concurrent reclamation or memory ordering on hardware.

The private post-lock mutations test termination, growth with the same object, growth with a different object, object replacement, rights clearing and generation change. Growth with the same object succeeds; the other changed/invalid cases return16 or15 and release the modeled lock. These are explicit interleaving probes, not observed races or defect demonstrations. Most failures leave caller outputs unchanged; receive and translation wrappers initialize their own local lookup outputs and guard their use by status.

The lock-allow-invalid wrapper performs arena extent and metadata checks around its underlying lock. The inspected metadata mask first accepts classes0x16/0x17; after a successful lock, a nonzero object type byte requires class0x16 and zero requires class0x17. Private port-shaped and port-set-shaped fixtures pass; wrong metadata reaches fail-stop validation helpers. This establishes native guards, not forgeability or complete object validity. Full lock algorithms, hardware tagging and zone state remain separate.

## Rights, guard policy and receive-reference balance

| Interface | Admission after successful lookup | Object-reference effect | Lock on success |
| --- | --- | --- | --- |
| Receive-name wrapper `0xfffffe000bcc8cf4` | Capability mask0x000a0000 nonzero: RECEIVE bit17 or PORT_SET bit19 | Atomic +1 at object+4, then publishes object | Released before return |
| Generic translation `0xfffffe000bcc92e4` | Right selector0..4 and corresponding entry bit16+selector set | No additional object retain in this wrapper | Remains held |

The [receive wrapper reference](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_mqueue.c#L1367) and [generic translator](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_object.c#L256) supply conventional labels. Native masks, widths and reference operations are independently retained. The generic right-bit predicate is proved for all u32 capability words and selectors0..4. Synthetic bit combinations do not override namespace-construction invariants, particularly for dead-name states.

Receive lookup maps its lower-level failures to0x10004002. For a successfully looked-up object without RECEIVE/PORT_SET, it unlocks and may call guard helper `0xfffffe000c629ba0` with `(name,0,0x80000)`. Entry bit21 (`EX_RECEIVE` in the reference) suppresses that particular guard callback, while the receive still fails. It is not an admission exemption. Guard termination/exception behavior is modeled as returning in the fixtures and remains unknown natively.

Native reference increment uses a biased guard. For old u32 count R, the ordinary branch requires `(R+0xf0000001) mod2^32 >0xf0000001`, proved equivalent to `0<R<0x0fffffff`. A zero-old-count fixture reaches the failure helper after the atomic increment; it is not a valid acquired reference. Initial absolute counts remain allocator/object-contract inputs.

The successful user receive helper stores the retained object at thread+0x398 and calls common queue receive. In `0xfffffe000bcdcc7c`, receive-results processing loads that object, performs selected special-reply/turnstile completion and then decrements object+4 at `0xfffffe000bcdce04`. Old count0 takes an underflow boundary; old count1 reaches last-reference cleanup. Later message/header/OOL copyout follows this release. The paired fixture observes object count2 ->3 in receive-name lookup ->2 in the native release slice. It does not execute an actual wait or prove every continuation/error path.

This retained receive object, the message's destination/reply references and the protected FairPlay caller's destination send right are distinct ownership scopes. The reference is not extended merely because thread storage was populated. The [kernel transport report](kernel_rpc_transport_report.md) separately accounts for COPY_SEND, MAKE_SEND_ONCE and temporary caller retains.

## User and kernel special-reply bindings

| Contract | User special-reply trap | Kernel special-reply helper |
| --- | --- | --- |
| Native entry | `0xfffffe000bcf8ca0`, original Mach index50 | `0xfffffe000bcf8e14` |
| Thread binding | +0x450, authenticated pointer | +0x3f0, direct pointer load/store in inspected range |
| Creation | Calls `0xfffffe000bccd000` with current space, label0x10b, context0, flags1 and name/object outputs | Allocates and initializes special reply object against a dedicated space; initializer final argument1 |
| New binding | Atomic object ref+1; stores pointer; PAC-signs owner thread at port+0x40 | Same thread-hold increment/owner publication, then drops local initialization reference |
| Replacement / unbind | Clear field; adjust with flags4; decrement old object reference | Clear field; adjust with flags4; lock again; destroy port |
| Result | New namespace name; allocation failure returns0 | Status0 after creation |

The native user path clears the previous binding at `...bcf8cec` before attempting allocation at `...bcf8d64`. It clears the old owner through the adjust helper and decrements old object+4 at `...bcf8d0c`. Thus modeled allocation failure leaves thread+0x450 null; it does not restore the old binding. A synthetic last-reference case enters the old object's cleanup boundary. No old-user-path call to port destruction is present here; namespace-held capabilities and remaining references are separate. Their complete retirement is unknown.

User allocation flags1 select SEND|RECEIVE capability bits0x30000 inside the allocator wrapper, whereas the ordinary mach_reply_port call's flags0 select RECEIVE0x20000. The actual entry publication and initial object-count semantics remain deeper allocator contracts. With explicit initial-ref1 models, new user binding ends at count2; kernel creation increments then drops its local reference and ends at count1. Those fixture counts are not asserted as real initial/final runtime counts.

Kernel teardown `0xfffffe000bcf837c` clears thread+0x3f0, adjusts/unlinks, locks again and tail-branches at `...bcf83cc` to destruction `0xfffffe000bccdbb4`. Both kernel-unbind fixtures stop before destruction executes. The [thread-IPC reference](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ipc_tt.c#L1425) corroborates the user-release/kernel-destroy distinction. Full port destruction, namespace entry removal, notifications and waiter wakeup remain open.

Library `__task_reply_port` at0x1ed83e8f4 instead holds the u32 name returned by ordinary mach_reply_port, as recorded in [user_trap_interface_report.md](user_trap_interface_report.md). It is not established as either thread special-reply object. Kext context+0x18 is a destination object in another accounting scope.

## Destination linkage, turnstiles and state union

`0xfffffe000bccef30` first prepares the destination's send turnstile through `0xfffffe000bcced98`, then validates/locks the special-reply object. For type byte0x0b, sync state0 and null inheritor, it increments destination+4, signs/stores the destination at reply+0x58 and sets state1 in reply flags+0x10. If the object is not special, the state already disallows linkage or the inheritor is nonnull, it completes the temporary turnstile reference instead of installing a new link. These ordering and object-validity preconditions are retained separately.

| Reply field / state | Native representation | Conventional interpretation |
| --- | --- | --- |
| Owner thread | +0x40, PAC discriminator0xf4d6 | Bound caller thread |
| Sync state | Flags+0x10 bits12..14 | State values below |
| Bootstrap check-in | Same flags, bit15 | Set by selected link call; cleared by adjust flag0x20 |
| Inheritor union | +0x58 | Destination port, knote or stashed turnstile according to state |
| Diagnostic PID | +0x60 | Set on selected PORT -> NO_LINKAGE transition; cleared on NO_LINKAGE -> ANY |

| State | Reference name | Union meaning / selected cleanup |
| --- | --- | --- |
| 0 | ANY | Unlinked and linkage allowed; UNLINK_THREAD can still clear owner |
| 1 | PORT | Destination pointer; unlink clears union and releases object plus send-turnstile holds |
| 2 | WORKLOOP_KNOTE | Knote pointer; selected unlink clears union |
| 3 | WORKLOOP_STASH | Held turnstile pointer; selected unlink clears union and calls turnstile deallocation |
| 4 | NO_LINKAGE | Linkage disabled until reset; ALLOW_SYNC_LINKAGE returns it to0 |
| 5 | RCV_THREAD | Additional receive-thread state; selected unlink transitions to4; complete push policy remains open |

The state names are from the pinned [port header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_port.h#L246); masks/transitions are native. The union has distinct PAC discriminators: destination0xa1c0, knote0x824a and stashed turnstile0xfb21. Source-correlated type/state does not substitute for authenticating its actual runtime value.

The [link reference](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_port.c#L1857) corroborates the separate turnstile hold. Native prepare reads destination+0x70 and increments turnstile+0x58. Native completion at `0xfffffe000bcceadc` decrements that primary count; zero enters turnstile completion/cleanup/deallocation helpers. The fixture set exercises existing counts1/2 and the zero-initial-count allocation path with explicit helper models. Full turnstile inheritor propagation and scheduling effects remain unknown.

```text
Paired private fixture; initial destination ref5, turnstile primary count1

ANY/null -- link --> PORT/destination -- UNLINK_THREAD --> NO_LINKAGE/null
             |                               |
             +-- object ref5 ->6              +-- ref6 ->5
             +-- turnstile count1 ->2         +-- count2 ->1
                                             +-- owner cleared

PORT/destination -- ALLOW_SYNC_LINKAGE --> ANY/null
                      same reference releases; owner preserved
```

Adjust helper `0xfffffe000bcce5b8` uses flag4 for owner unlink and flag1 for allowing linkage. Selected PORT -> NO_LINKAGE stores PID4242 only because that is the explicit process-helper seed in the fixture. Native calls include exact `_get_bsdtask_info` and `_proc_pid`; the actual runtime PID is unknown. A nonzero stashed-turnstile case reaches deallocation; populated workloop/knote admission and every state combination are not established.

A group-tracking path consults destination+0x12 bit0, current thread+0x298 and thread+0xc8 bit13. It may invoke `0xfffffe000be81ebc` and set thread bit13. This is an architectural performance-controller touch point, not evidence that FairPlay triggered a live callout or any measured scheduling effect.

## Bounded findings and continuation

| Impact | Established distinction / unresolved boundary | Next evidence |
| --- | --- | --- |
| High | Numeric name resolves through task-space index/generation/PAC/object checks | Recover real namespace entries for published services and match their objects to kext host-special-port acquisitions |
| High | Lookup lock ownership differs from receive-object reference ownership | Complete queue/continuation/error paths, installed CF reception and actual object accounting |
| High | User binding release and kernel binding destruction have different lifetimes | Follow namespace capability retirement, port destruction, notifications, death, replacement and thread termination |
| High | Destination object and turnstile references are distinct and balance on selected paths | Extend all reply states, send failures, bootstrap and workloop paths; match actual kext/daemon transitions |
| Medium | Post-lock table reload rejects changed identity; protected reads include preemption/SMR barriers | Recover writer/growth/reclamation algorithms and complete lock primitives; private interleavings do not prove native concurrency |
| Medium | EX_RECEIVE suppresses one guard call while admission still fails | Recover guard policy/termination, actual task flags and receiver error handling |
| Medium | Allocation tokens, pointer PAC and state-specific unions shape kernel ABI | Recover allocator encoding/metadata, authenticators, initialization and callback ABI; do not infer runtime integrity from static words |
| Medium | Reply linkage touches turnstile inheritance, diagnostic PID and group tracking | Establish complete workloop/knote/performance-controller inputs and effects |
| Low | Most lookup failures preserve outputs while index0 clears them | Retain status-dominated use in caller models and test additional output aliases |

## Reproduction and quality gates

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_kernel_namespace.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_kernel_namespace_delivery.py
```

Recovery and evidence validation use O(B+I+N+E) time/space for image bytes, selected instructions, nlists and retained evidence; solver complexity is separate. The local namespace algorithm has constant arithmetic/table accesses and no local retry loop, excluding opaque lock, reclamation and pending-work costs. Each private profile has a30000-instruction limit and explicitly mapped storage. No latency, throughput or native concurrency bound is inferred.

[Quality gates](triage_evidence/kernel_namespace_quality_gates.json) pass for this increment: N1-N7 expose assumptions/probes, numeric fields and partial layouts are reproducible, original/reference/native/model provenance remains separate, all93 profiles have explicit checks, and remaining interfaces are impact-labeled. The full daemon/kext/deeper-interface objective remains active and incomplete.
