# Kernel receiver for VM message 4801

The original collection registers a non-NULL receiver for message 4801 at
`0xFFFFFE000BD8B18C`. Its accepted request reaches the same VM leaf,
`0xFFFFFE000BDC1EC0`, identified on the available cache's trap -12 path.
The receiver has a five-pointer internal ABI and communicates its result
through reply storage. It validates the kernel message representation,
handles remote-object sentinels, invokes a conversion helper when required,
passes full-width address/size to the VM leaf and calls a release-like helper.

The available-cache request and this kernel contract are structurally
consistent after the 24-to-32-byte header change. This does not establish
continuous user-wire delivery, native namespace conversion, the daemon's
actual runtime version or a native reply emission. The broad investigation
remains active. No native kernel, VM, release, IPC or PAC operation executed.

## Primary evidence and reproduction

The original kernel collection SHA-256 is
`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.
Addresses are unslid VAs. Offsets/constants are hexadecimal unless stated;
counts and byte extents are decimal. Original function bounds use
LC_FUNCTION_STARTS; tables/pointers use independently decoded original
format-8 chain membership. Native runtime table contents are not attested.

This extends the [VM cache/kernel interface report](daemon_vm_cleanup_report.md),
[kernel dispatcher](kernel_dispatch_report.md), and
[kernel/user message representation](kernel_user_copyout_report.md).
Original files suffice: no new IDA query, IDB change or saved-analysis-memory
change was performed. No new observation was taken from the RAX trace.

Evidence: [original tables/functions and hash model](triage_evidence/kernel_vm_mig_source.json),
[173 private source profiles](triage_evidence/kernel_vm_mig_profiles.json),
[ten original/simplified proof pairs](triage_evidence/kernel_vm_mig_proofs.json),
[fresh independent replay](triage_evidence/kernel_vm_mig_checks.json),
and [reconstructed SDK/layout probe](triage_evidence/kernel_vm_mig_sdk.c).

From `/Users/___/dev/dylex/extracted`, apply this prefix in order:

```text
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
 Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
 /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/<script>

recover_kernel_vm_mig.py
probe_kernel_vm_mig.py
prove_kernel_vm_mig.py
validate_kernel_vm_mig.py
```

The SDK probe compiles without linking/execution to
[LLVM IR](triage_evidence/kernel_vm_mig_sdk.ll). Reconstructed private types
are not original declarations, and the installed SDK is not a matched runtime.

## Registration, selection and dispatch

| Record | Source-established location and value |
| --- | --- |
| Subsystem registry | 20 original pointers starting FFFFFE000CA87018 |
| VM subsystem, registry index 0 | FFFFFE0007E68088; IDs 4800 inclusive to 4830 exclusive |
| VM selector pointer | Slot FFFFFE0007E68088 -> FFFFFE000BD8B33C; IA diversity 0423, addrdiv 0 |
| Routine array | FFFFFE0007E680A8, stride 32 bytes |
| 4801 routine, array index 1 | FFFFFE0007E680C8 |
| 4801 stub pointer | Slot FFFFFE0007E680D0 -> FFFFFE000BD8B18C; IA diversity 3A83, addrdiv 0 |
| 4801 row metadata | Arity word +10=5; word +14=0; reply descriptor parameter +18=0; reply inline capacity +1C=44 bytes |
| Registry initializer | FFFFFE000C62A46C |
| Initialized dispatch table | FFFFFE0007E5CAB8; 1,031 slots, 24 bytes per slot |
| 4801 initialized entry | Slot index 677, address FFFFFE0007E60A30; initial policy word FFFFFFFF |

The VM selector reads the kernel message ID at header+1C. For every u32 ID,
its original range predicate accepts exactly 4800..4829. For in-range IDs,
the selected pointer slot is
`FFFFFE0007E680A8 + 32*(ID-4800) + 8`. Its signed-offset check selects the
ordinary address for this range. Range membership does not establish a
non-NULL implementation: ID 4824 has a NULL pointer and is skipped by the
initializer. The other 29 VM rows have non-NULL stubs.

The initializer walks all 20 subsystems and copies each non-NULL routine
into the hash table. Under the explicit original-file/empty-table premise,
the independent model and original-source execution agree on all 358 entries,
maximum probe count 91 and final counter word 390 (358+32). These are private
pre-startup model results, not measurements of the running kernel table.

| Hash-entry offset | Width, bytes | Initialized role |
| --- | ---: | --- |
| +00 | 4 | Message ID |
| +04 | 4 | Policy index/word, initially FFFFFFFF |
| +08 | 8 | Copied logical stub pointer |
| +10 | 4 | Reply inline capacity |
| +14 | 4 | Reply descriptor parameter |

Registration uses signed division arithmetic on the recorded positive IDs;
lookup uses widened unsigned multiply/shift/remainder arithmetic. The source
constant 7F218557 and shift 41 yield the unsigned quotient by 1,031 for all
u32 IDs. Separate source-BV and integer-bound proofs establish this relation.
The runtime lookup advances its u32 candidate before recomputing the remainder;
it must not be generalized to unbounded integer arithmetic at u32 wraparound.

The dispatcher at FFFFFE000BCF4154 reads this table and, when the selected
entry and intervening policy permit, calls the stub at FFFFFE000BCF4830:

| Register | Five-pointer stub argument | Original setup |
| --- | --- | --- |
| X0 | Kernel input header | MOV X0,X22 at ...4818 |
| X1 | Input body | MOV X1,X26 at ...481C |
| X2 | Trailer/end pointer | MOV X2,X27 at ...4820 |
| X3 | Kernel reply header | LDR X3,[SP,#20] at ...4824 |
| X4 | Reply body | MOV X4,X25 at ...4828 |

The selected function pointer comes from hash-entry+8, with IA diversity
3A83. The helper at FFFFFE000BCC2104 constructs X27 as the end of the
message body for the original storage class. The VM stub does not read
through X2 in the bounded cases; it is not an audit-token argument to the
VM leaf. Complete native trailer bounds and originating sender identity
remain outside this result.

The dispatcher also reads entry+4 and may consult a task-related bitmap
and an authenticated callback at FFFFFE0007E665C8 before calling the stub.
Function FFFFFE000C2C45A0 can write the policy word after a matching lookup
when its first u32 argument is 2. Its caller permissions and native setters
are unknown. Registration/lookup success alone does not prove policy admission.

## Request validation, conversion and lifetime boundary

```text
registered 4801 -> kernel dispatcher lookup/policy -> five-pointer call
    |
    +-> complex bit set OR kernel msgh_size != 56
    |      -> NDR + MIG_BAD_ARGUMENTS (-304) through reply-header pointer
    |
    +-> accepted kernel header
           -> remote-object pointer at input-header+08
           -> NULL / all-ones sentinel: converted argument = 0
           -> other pointer, byte[0] == 24: converted argument = 0
           -> otherwise conversion helper(pointer,0,0)
           -> VM leaf(converted, body.address64, body.size64)
           -> store low32(return) through reply-body pointer
           -> release-like helper(converted)
           -> copy NDR through reply-body pointer; return
```

The exact header checks are ...BD8B190..BD8B1A0. The pointer-sentinel
predicate uses `(pointer+1) >= 2` as an unsigned u64 comparison, excluding
exactly 0 and FFFFFFFFFFFFFFFF. The byte-24 branch is at ...BD8B21C..224;
its original symbolic object-type name is unknown. These are internal
kernel object pointers, not user-space numeric Mach port names.

The conversion call is ...BD8B234 -> FFFFFE000BCFAE94. Its detailed native
policy/reference behavior is not modeled by the receiver cases. Original
source captures show additional object-byte checks, a task-like flag test,
authenticated pointer loads and further helper calls. The resulting object
type/ownership is inferred as map-like from its VM consumer; an original
private type declaration has not been recovered.

The VM call at ...BD8B1D8 directly targets FFFFFE000BDC1EC0. Original
nlist names `_mach_vm_deallocate` and `_mach_vm_deallocate_external` both
identify wrapper FFFFFE000BE2D060, whose branch reaches this same leaf.
This joins the VM MIG receiver and fast-trap handler at the implementation
interface. It does not attest which path a native daemon request took.

The receiver loads address/size as two u64 words from body+08/+10. It does
not read the preceding eight request NDR bytes in these bounded cases.
After the VM call, `STR W0,[X20,#8]` at ...BD8B1DC stores the result before
the release-like call ...BD8B1E4 -> FFFFFE000BDCADE0. Thus caller-clobbered
registers from release do not replace the stored result. The helper's captured
body includes a NULL branch and an atomic decrement at object+88 on its
non-NULL route; allocation checks/finalization and native lifetime effects
remain unexecuted.

The stub's final X0 is not its MIG result channel. Accepted cases place
NDR/result at X4+00/+08; bad-header cases use X3+20/+28. Joined and separate
reply-body fixtures distinguish the two producers. Whenever conversion,
VM or release calls occur in the 102 receiver cases, they are explicit
callbacks rather than native calls.

## User and kernel message representations

| Field / extent | User representation | Kernel representation |
| --- | --- | --- |
| Header extent | 24 bytes | 32 bytes |
| Remote | u32 name at +08 | u64 object pointer at +08 |
| Local/reply | u32 name at +0C | u64 object pointer at +10 |
| Voucher | u32 at +10 | u32 at +18 |
| Message ID | u32 at +14 | u32 at +1C |
| VM address | u64 at request+20 | u64 at request+28 |
| VM size | u64 at request+28 | u64 at request+30 |
| Request inline extent | 48 bytes | 56 bytes |
| Normal reply inline extent | 36 bytes | 44 bytes |
| Result word | reply+20 | reply+28 |

Offsets in this table are hexadecimal; extents are decimal. The cache's
44-byte user receive capacity is separate from the kernel's 44-byte inline
reply extent, despite equal numbers. Natural C structure tail padding must
also be kept separate from the 44-byte inline field extent; the SDK probe
uses a byte-header extent type to avoid implying otherwise.

The generic dispatcher builds the kernel reply at ...BCF4760..4794:
size=44; bits=`(input_bits>>8)&31`; remote-object field=input local-object
field; local-object and voucher fields=0; ID=`u32(input_ID+100)`; NDR copied
from the original constant; result initially 0. For input ID 4801 the reply
ID is 4901. The receiver then overwrites the result/body through its selected
output pointer. No native port transfer or kernel reply send was executed.

This is a source-established correspondence of framing and body fields.
The actual user copyin/inflation, object-right translation, complete dispatcher
policy/storage trajectory and subsequent kernel reply emission are not a new
continuous trace here. In particular, supplying a raw 48-byte user header
directly to the 56-byte kernel-stub interface is a representation mismatch,
not evidence that a valid user request is rejected during native delivery.

## Assumptions and verification

| ID | Premise / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| KM1 | Pinned original collection, function starts and chain membership identify this receiver and registry. | Rehash collection, rebuild all 20 subsystem records, decode pointer words and match 993 captured instructions. Preserve absent original names as absent. |
| KM2 | Empty original-file hash/counter bytes define a private pre-startup state. | Execute the original initializer and compare all 1,031 entries, 358 insertions, maximum probe and counter against the independent table model. Runtime execution/content remains unattested. |
| KM3 | Selector and lookup profiles are component entries, not a full message receive trace. | Exercise all 30 VM IDs plus boundary/raw-bit cases; preserve NULL entry 4824; derive lookup fixtures from initializer output. |
| KM4 | Private RAM is explicitly zero-filled, and header/body/port/reply cells have the stated valid extents. | Joined/separate output fixtures, NULL/sentinel/byte-24/normal pointers, malformed sizes, complex bit, full-width payloads and fresh read/write replay. Native extents/ownership remain unknown. |
| KM5 | Conversion/VM/release returns and caller-clobbered registers/NZCV are explicit models; X18..X29 are preserved. | Verify all callback arguments, post-registers and result-before-release ordering. Actual reference acquisition, validation and finalization remain unexecuted. |
| KM6 | Local symbolic cells are fixed, valid and disjoint; PAC is logical. | Rebuild source expressions/SMT; pin original slots/key/diversity and the five-pointer call. Native pointer authentication is not established. |
| KM7 | Kernel object pointers, user port names and the two header representations are distinct. | Compare offsets/widths and framing explicitly; inspect actual inflation/namespace conversion before claiming continuous user-wire delivery. |
| KM8 | Registration, framing and shared implementation do not establish policy admission, native execution or final reply transfer. | Recover dispatcher bitmap/callback state, upstream caller path, downstream send and matched runtime/native rights separately. |

Ten original/simplified proof pairs solve UNSAT. They cover all u32 selector
IDs, in-range pointer offsets, source hash arithmetic and integer quotient
bounds, all u64 sentinel pointers, VM argument/result bits, reply field bits
and the five-pointer dispatch interface. Both forms of 20 SMT files are
rebuilt, read back and solved independently. These are scoped source/ABI
proofs, not a proof of native environmental preconditions.

The 173 private cases comprise one initializer, 35 selector cases, 35 hash
lookup cases and 102 stub cases (90 accepted headers, 12 bad headers).
Independent fresh CPU replay verifies 35,844 source visits, 5,155 reads,
2,722 writes, 181 logical PAC steps and all 173 final register/flag/stack
boundaries. It checks 36 conversion models, 90 VM models and 90 release
models. The initializer accounts for 29,363 visits. All source bytes and
read/write effects are checked against the original image or explicit fixtures.

Accepted stub cases preserve all 128 address/size bits into the VM call
and store a four-byte result. Bad-header cases invoke none of the modeled
helpers. Neither received NDR bytes nor trailer bytes are read by these
bounded stub cases. This is a statement about this receiver's source accesses,
not a claim that upstream normalization or authorization is absent.

SDK compilation verifies reconstructed routine/hash strides 32/24, private
kernel/user headers 32/24, kernel request 56, inline reply field extent 44,
and the installed SDK's MIG_BAD_ARGUMENTS=-304 definition. It does not
recover the original private typedefs or native allocation sizes.

Capture/initialization/replay costs O(collection bytes + fixups + routines
+ probes + source visits); space is O(collection metadata + one private
CPU map + journals). Solver expression DAGs and compiler resources are
additional. Byte widths and modular equations are exact; no native timing
or performance estimate is inferred from the probe count.

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| high | Connect user wire input to this internal kernel representation. | Original copyin/inflation and namespace conversion, actual object extents and a source-continuous receive path. |
| high | Complete kernel reply ownership and emission. | Dispatcher caller/return path, reply object/right consumption, send/release sites and actual header deflation. |
| high | Establish dispatcher and converter admission conditions. | Policy-word setter callers, task bitmap/callback state, port-object checks, reference acquisition and native rights provenance. |
| medium | Continue non-NULL release/finalization. | Allocation-type checks, atomic reference transitions, final-reference tail and required locks. |
| medium | Join this source interface to the daemon's actual environment. | Matched loaded cache/kernel identities, actual task/reply names and valid ownership. Symbol/interface correspondence alone is insufficient. |

QG1: Pass; factual source, ABI, registry and lifetime-boundary analysis requires no normative judgment.

QG2: Pass for this increment; KM1-KM8 identify premises, dependencies and falsification probes.

QG3: Pass for this increment; original registration, selector/hash routing, receiver validation, conversion/VM/release call ABI and reply construction are covered. The broad objective remains incomplete.

QG4: Pass; offsets, byte extents, integer widths, modular equations, reproduction, finite counts and complexity are explicit.

QG5: Pass within scope; NULL table entry, component versus continuous paths, user names versus kernel pointers, reply channels, helper models and native policy gaps are separated.

QG6: Pass; original bytes/nlist/chains, full private initializer comparison, rebuilt SMT, SDK compile and independent read/write/register replay support the scoped claims.

QG7: Pass; impact-labeled continuations cover input representation, reply emission, admission, lifetime and native runtime joins.

Publication evidence: [preservation](triage_evidence/kernel_vm_mig_delivery.json)
and [quality gates](triage_evidence/kernel_vm_mig_quality_gates.json).
