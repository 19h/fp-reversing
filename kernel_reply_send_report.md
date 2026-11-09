# Kernel generated-reply send, trailer and cleanup

The original kernel caller at `0xFFFFFE000BCC7040` consumes the generic
kernel-object dispatcher's returned message, initializes a kernel trailer,
constructs an integrity tag, obtains the returned message's destination and
requests queue send. Error handling distinguishes ordinary messages from
generated replies. A cleanup path requests destruction and then returns zero;
the queue status and the caller's return value are distinct channels.

This is a source-correlated send role, not an exact recovered nlist name.
The earlier [VM receiver](kernel_vm_mig_report.md) establishes the registry,
receiver and reply construction. Here the dispatcher return is an explicit
private model; a continuous VM request-to-reply-send execution is unknown.
No native kernel, Mach IPC, queue, hardware PAC or integrity check executed.

## Primary provenance and reproducibility

All addresses are unslid VAs in the original kernel collection with SHA-256
`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.
Offsets and addresses are hexadecimal; byte extents and case counts are decimal.
Evidence comes from original bytes, LC_FUNCTION_STARTS and decoded original
format-8 chain membership. Original nlist names are not established for these
roles. Fresh IDA queries were unnecessary; no IDB or saved memory changed.

| Artifact | Content |
| --- | --- |
| [Source](triage_evidence/kernel_reply_send_source.json) | Eleven function captures, 1,982 unique instructions, trailer template, per-word hash decoding |
| [Profiles](triage_evidence/kernel_reply_send_profiles.json) | 138 private CPU cases and complete source read/write/helper journals |
| [Proofs](triage_evidence/kernel_reply_send_proofs.json) | Fourteen original/simplified SMT pairs, assumptions encoded in their queries |
| [Checks](triage_evidence/kernel_reply_send_checks.json) | Fresh independent CPU replay, rebuilt source/proofs and reconstructed SDK layout |
| [Preservation](triage_evidence/kernel_reply_send_delivery.json) | Prior-manifest preservation and six allowed existing-file changes |
| [Quality gates](triage_evidence/kernel_reply_send_quality_gates.json) | Scoped QG1-QG7 and explicit native-evidence limits |

Reproduce from this directory using the existing local interpreter and solver:

```sh
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_reply_send.py
```

The validator rebuilds the source capture and obligations, resolves both saved
SMT forms, compiles reconstructed layouts for arm64e and replays every case in
a fresh CPU. It does not import the probe executor. The CPU engine is shared,
so this is independent journal reconstruction, not an independent ISA engine.
Time is O(source/artifact bytes + visits + solver/compiler resources); space is
O(collection metadata + one private map + largest profile + solver DAGs).

## Caller interfaces and outgoing request location

```text
post-dispatch route A/B entry (private frame)
   -> generic dispatcher (modeled return)
      +-> NULL -> return 0
      +-> reply message -> header/trailer selection
           -> kernel-template copy -> two hash calls (modeled returns)
           -> destination lock (modeled)
           -> destination/status gates
              +-> queue-send request at BCC724C (modeled)
              +-> error suffix
                   -> optional failure helper
                   -> conditional counter decrement/destruction request
                   -> cleanup clears status -> return 0
```

| Source site | Interface and width | Established scope |
| --- | --- | --- |
| BCC7340 / BCC73A8 | Dispatcher BCF4154: X0=input destination object, X1=request message | Components start at BCC7338 / BCC73A0; dispatcher output is NULL or a distinct private reply pointer |
| BCC7348 | Returned X0 becomes current message X19 | Subsequent reads use returned storage, not the old request fixture |
| BCC73F8 / BCC748C | Trailer initializer BCC4194: X0=reply, X1=0 | NULL-task initialization is executed from original source |
| BCC7404 / BCC7498 | Lock helper BCCC128: X0=destination object | Lock effects are modeled |
| BCC717C | Preflight BCC0F9C: X0=current message, X1=effective options | Route A reaches this after reply construction; route B does not repeat it in the selected component |
| BCC724C | Queue helper BCC7C34 | Original source emission-request boundary; actual enqueue/delivery unknown |
| BCC7280 | Failure helper BCC1CEC: X0=current message | Selected status family; helper effects modeled |
| BCC74D4 | Last-reference helper BCC922C: X0=destination | Requested only when source decrement observes old count 1 |
| BCC72D8 | Destroy helper BCC2C40: X0=current message, W1=1 | Caller request established; full destruction/lifetime effects unknown |

The queue request has the following exact register mapping:

| Register | Source at BCC723C-BCC7248 | Meaning established here |
| --- | --- | --- |
| X0 | destination + 0x28 | Embedded queue-related object address |
| X1 | current message X19 | Returned reply pointer |
| X2 | inherited X21 | Effective options, full 64-bit register |
| X3 | inherited X22 | Third inherited scalar, full 64-bit register; original private typedef unknown |

The destination is loaded as a u64 object pointer from kernel header+8. It is
not a user-space u32 Mach port name. The prior receiver constructs outgoing
header+8 from the incoming header's local-object field at +0x10. This increment
establishes where the caller requests send; it does not establish native right
transfer, namespace translation, receiver wakeup or final user copyout.

The full caller reads TPIDR_EL1. When thread+0xC8 bit 0x400 is set, source
BCC7074-BCC7080 rewrites options to `(options & ~0x10000) | 0x10` and clears
that thread flag. The rewrite has an all-word symbolic obligation. These
upstream instructions and route-selection predicates are not executed in the
post-dispatch profiles. Destination low-three-bit classes 0 and 3 are modeled;
classes 1/2 and nested kernel-object dispatch remain outside the case set.

## Storage, trailer and integrity metadata

Let M be the current message pointer, C=`u8(M+0x3F)>>6`, H the kernel header,
B the split body pointer, and L the u32 message size. Pointer arithmetic is
64-bit modulo arithmetic; subtractions below occur in u32 before extension.

| Condition | Original storage rule |
| --- | --- |
| C=0 or 1 | H=M+0x40 |
| C=2 or 3 | H=logical pointer at M+0xE8; AUTDA modifier has top 16 bits 0x289D and low 48 bits of M+0xE8 |
| Storage bit 6 clear | Trailer=H+zero_extend(L) |
| Storage bit 6 set, simple message | B=pointer at M+0xF0; trailer=B+zero_extend(u32(L-32)) |
| Storage bit 6 set, complex message | Prefix=u32(36+16*descriptor_count); trailer=B+zero_extend(u32(L-prefix)) |

The four storage classes are exercised with a simple 44-byte kernel reply.
The complex prefix arithmetic is symbolically checked; malformed extents and
native allocation validity are not established by the arithmetic identity.
AUTDA steps in the CPU are explicit logical pointer passthroughs.

For the caller's NULL-task argument, BCC422C-BCC4244 copies 64 bytes from
`0xFFFFFE0007010A68` and zeroes the final u32, producing this 68-byte trailer:

| Trailer offset | Width | Template content |
| --- | --- | --- |
| +0 | 4 | Type 0 |
| +4 | 4 | Advertised extent 8 |
| +8 | 4 | Sequence 0 |
| +0x0C | 8 | Security-token words (0,1) |
| +0x14 | 32 | Eight zero audit-token words |
| +0x34 | 16 | Zero remainder |

The 68-byte copied/hashed extent is distinct from its advertised extent 8.
This kernel template does not establish the original requester's identity.
The [copyout analysis](kernel_user_copyout_report.md) previously encountered
the same template. A byte-array proof establishes all copied bytes and that
unrelated byte addresses remain unchanged by this bounded copy fragment.

The initializer constructs 36 canonical bytes: a copy of the 32-byte kernel
header with its first u32 masked by `0x80001F1F`, followed by a u32 descriptor
count (zero for a simple message). It then makes these calls:

| Site | Buffer / length | Seed | Mode |
| --- | --- | --- | --- |
| BCC42BC | Canonical header / 36 bytes | `(M & 0x0000FFFFFFFFFFFF) | 0x3409000000000000` | 0 |
| BCC42D0 | Trailer / 68 bytes | First call's full u64 result | 1 |
| BCC42D8 | Store at M+0x38 / 4 bytes | High 32 bits of second result | Store, not another call |

The callee at BC9D90C is a PACGA-based buffer fold. Its executable body has
five static PACGA sites and returns at BC9D9A0. The compiler-bounded interval
contains one undecoded word after that return; this does not make the executed
algorithm family unknown. Native hardware keys and tag values are unknown.
The probes supply two explicitly arbitrary hash returns; their stored word
`0xFEDCBA98` is model-derived and has no native validity claim.

A separate routine at BCC222C rebuilds the canonical inputs, calls the same
fold at BCC234C/BCC2360, compares its high result word against M+0x38 at
BCC2364-BCC2370, and takes a diagnostic path on mismatch. This verifier is
statically captured, not executed. Preflight BCC0F9C is a different routine;
its modeled return zero is not evidence of integrity acceptance.

## Failure status, counter and caller return

The suffix computes `delta=u32(status-0x10000003)`, bounds it by 10 and tests
mask 0x413. The exact helper-selected set is:

| Status | Failure helper requested | Cleanup when ordinary mode=0 | Cleanup when reply mode!=0 |
| --- | --- | --- | --- |
| 0 | No | No | No |
| 5 | No | No | Yes |
| 0x10000003 | Yes | Yes | Yes |
| 0x10000004 | Yes | No | Yes |
| 0x10000007 | Yes | No | Yes |
| 0x1000000D | Yes | No | Yes |

For all u32 statuses and mode words, the suffix cleanup predicate is
`status==0x10000003 || (status!=0 && mode!=0)`. Generated replies set mode 1.
In the selected inactive-destination cases, the caller supplies 0x10000003
without requesting queue send. Ordinary-message mode is tested separately
from BCC7254; its upstream send operation is not executed.

Cleanup performs a release atomic decrement of the u32 at destination+4
(BCC72C0). Old count 1 selects the last-reference helper; old count 2 does
not. Old count zero selects a diagnostic path outside the profiles. It then
requests destruction with flag 1 and executes `MOV W24,0` at BCC72DC before
returning through BCC72E0. Consequently all generated-reply cases here return
zero, including modeled send failures. Ordinary mode with nonzero status
other than 0x10000003 retains the status. The symbolic proof checks the reset
and direct-return fragments separately before selecting by the cleanup
predicate. It is not a proof of opaque helpers' ownership effects.

## Validation and assumption register

The 138 cases comprise two NULL replies, 112 non-NULL replies across two
routes/four storage classes/two initial counters, and 24 cleanup components.
Independent replay checks 16,520 original instruction visits. There are 96
queue request models, 224 hash return models, 108 destruction requests and
54 last-reference requests. All 14 rebuilt obligations and both saved forms
(28 SMT files) resolve UNSAT. The reconstructed SDK layout compiles for
arm64e; this is not original-header provenance or runtime attestation.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RS1 | Original collection and unslid address mapping identify this source; all claims depend on this epoch | Rehash original bytes and independently decode load commands/chains |
| RS2 | Private component frames represent selected post-dispatch states; source handover/cleanup depend on them | Execute upstream route selection with genuine kernel objects and thread state |
| RS3 | Dispatcher returns a distinct valid reply pointer or NULL; old-request independence is conditional | Capture real dispatcher return, allocation extents and old/new aliases |
| RS4 | Helper callbacks have declared returns and no hidden memory effects; case outcomes depend on these models | Execute helper bodies with complete storage, locking and ownership state |
| RS5 | Logical PAC passthrough preserves fixture targets; storage resolution is conditional | Attest native pointer authentication, discriminators and matching runtime epoch |
| RS6 | Hash outputs are arbitrary model words; only source input/tag propagation follows | Obtain genuine native outputs under known keys/context; no validity inferred here |
| RS7 | Selected destination classes and counters 1/2 are valid private states; case coverage is finite | Cover classes 1/2, old count zero, races, nested dispatch and alternate queue paths |
| RS8 | The fresh replay shares Unicorn but reconstructs the journal independently; replay confirms consistency | Cross-check with another ISA implementation and native observations |

## Bounded continuation and quality gates

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High | Queue helper, wakeup/dequeue and user copyout source continuity | Whether this request produces a receiver-visible reply and how destination rights terminate |
| High | Real generic-dispatch allocation/return and source-only caller join | Continuous receiver-to-send flow without a substituted dispatcher result |
| High | Matched daemon/cache/kernel epoch and authenticated object/port provenance | Which architectural contracts apply to one real environment |
| Medium | Failure/destroy/reference helper bodies and alternate port classes | Ownership, nested dispatch and error-state distinctions hidden by callbacks |
| Medium | Sequence/audit/trailer transformation during receive/copyout | Which metadata survives into the final user representation |
| Low | Exact original names or matching private headers | Replace source-correlated labels without changing the measured ABI |

QG1: Factual technical analysis requires no normative conclusion.
QG2: RS1-RS8 identify dependencies and explicit falsification probes.
QG3: This increment covers reply handover, queue-request ABI, trailer/tag
flow and caller cleanup; the broader multi-layer investigation remains active.
QG4: Widths, offsets, u32 wrap, byte extents, SDK assertions and reproduction
are explicit; no physical-unit calculation is involved.
QG5: The cleanup status reset, ordinary/reply modes, hash/preflight distinction,
trailing decode gap and modeled/native boundaries are resolved explicitly.
QG6: Original bytes, regenerated captures, independent journals and SMT hashes
support the bounded claims; source-role names and model values stay qualified.
QG7: The impact table bounds further architectural and ownership questions.
