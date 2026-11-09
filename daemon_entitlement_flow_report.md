# Two entitlement adapters, token ABI and persistent frame-state flow

The first entitlement result is now joined to the next original caller
stages. Both caller destinations reach audit PID extraction and a second
Security-framework adapter. The Boolean-true result from
`com.apple.private.fpsd.client` first ORs bit 0x2 into a frame-state word;
the other recovered results enter the common stage directly. That state is
subsequently consumed after the second adapter's marker-0x31 return.

The second adapter queries `fairplay-client` at 0x1002382E8, using the same
32 token bytes through a new copy chain. Its result schema and final policy
use remain unknown. The string-NULL model returns marker 0x31 and, in the
first-query-true context, continues to a 32-byte malloc request. Neither
entitlement results nor allocation effects are observed natively.

This extends the [first result-consumer report](daemon_entitlement_result_report.md).
The original files suffice; no new IDA query or IDB mutation was performed.
The RAX trace remains historical transport evidence. All new API-result
cases below are explicit private models, not observations from that trace.

## Provenance and reproducibility

Original daemon: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
Source addresses are unslid VAs. The [contracts](triage_evidence/daemon_entitlement_flow_contracts.json)
retain original spans, used fixup/import words, exhaustive byte banks,
copy-helper bodies, record and output ledgers, SDK paths/hashes and compiler
arguments. The three profile groups retain all original instruction visits,
reads/writes, logical edges and explicit API events:

| Profile group | Cases | Declared continuation |
| --- | ---: | --- |
| [Caller continuations](triage_evidence/daemon_entitlement_flow_profiles.json) | 28 | First query's previous seven models, four contexts each; stop before the next unmodeled API |
| [PID-output continuations](triage_evidence/daemon_entitlement_flow_audit_profiles.json) | 12 | First query NULL, Boolean false or Boolean true; declared PID word 0, 1, 80000000 or FFFFFFFF |
| [Second string/task stages](triage_evidence/daemon_entitlement_flow_string_profiles.json) | 12 | First query Boolean true; second string NULL, string non-NULL, or string/task non-NULL; four contexts each |

Run from `/Users/___/dev/dylex/extracted`, applying this prefix to each
script in the order shown:

```text
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
 Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
 /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/<script>

probe_daemon_entitlement_flow.py
probe_daemon_entitlement_audit.py
probe_daemon_secondary_identity.py
recover_daemon_entitlement_flow.py
prove_daemon_entitlement_flow.py
validate_daemon_entitlement_flow.py
```

No native target, framework, allocation, IPC or Mach-right operation is
executed by these scripts. Original writable-file/BSS backing, initial
private cells and imported allocator words remain declared environment
premises. Existing allocator-word models are reused consistently by the
second adapter; they are not recovered native values.

## First result: conditional state update and common rejoin

Let F be the protected-core frame and R=F+0x10CB8. In this private placement,
F=0x680004F230 and R=0x680005FEE8. Those are harness addresses, not native
fixed addresses. Frame offsets below are hexadecimal bytes; sizes are
decimal bytes unless identified otherwise.

```text
first query: com.apple.private.fpsd.client
  |
  +-- flag=1, marker=5C --> 0x1004B3E6C
  |                         F+9B8 := 4061
  |                         u32(F+6ADC) |= 2 @ 0x1004B3EA0
  |                         BRAA @ 0x1004B3EB0
  |                             |
  +-- other recovered returns --+--> 0x1004B4F2C
                                      copy token32
                                      audit_token_to_au32 @ 0x1004B503C
                                      construct fairplay-client string
                                      copy token32 again
                                      rebuild record at R
                                      BLRAA @ 0x1004B52B4
                                        -> 0x100013F0C
```

For arbitrary saved index I=u32(F+0x998) and prior state C=u32(F+0x6ADC),
the alternate block has the exact u32 equations:

```text
T = (I + 0x01D89966) AND 0xFE276BEF
u32(F+0x9B8) := T                 @ 0x1004B3E94
u32(F+0x6ADC) := C OR (T-0x405F) @ 0x1004B3EA0
```

In the source-established context I=0x3B0B, T=0x4061 and T-0x405F=2.
For every prior C, the new word is C OR 2 and is nonzero. No clearing of
other bits is implied. The next load selects slot 0x101057748, IA/EB1C,
addrdiv=0, target 0x1004B4F2C. The direct path already has saved phase
u32(F+0x9B8)=0x4061. The common block computes
`W25=(phase+0x29D31A4A) AND 0xD62CF57E`, giving 0x502A for that phase.
These equations are universally proved over their local u32 inputs; native
invocation and frame validity remain separate premises.

The direct path does not execute this OR writer. In the finite retained
context its prior state is zero. That observation is not generalized to
every native invocation or to a statement that a false/missing entitlement
clears state. The first marker/flag predicate retains its recovered polarity;
the two destinations do not represent two immediate terminal outcomes.

## PID interface and token-copy lineage

| Source call PC | Interface/target | Original slot | IA discriminator | Source/destination or arguments |
| --- | --- | --- | --- | --- |
| 0x1004B4FD4 | Private copy helper 0x10046F89C | 0x10109FC88 | 34A1 | F+C080 -> F+C0C0, 32 bytes |
| 0x1004B503C | libbsm audit_token_to_au32 | 0x1010A0500 | DC55 | token at F+C0C0; PID output at F+5D5C |
| 0x1004B5214 | Private copy helper 0x10046F89C | 0x10109FC88 | 34A1 | F+C080 -> F+C0E0, 32 bytes |
| 0x1004B52B4 | Second adapter 0x100013F0C | 0x1010A0BB0 | 7441 | X0=R |
| 0x100062298 | Private copy helper 0x10046F89C | 0x10109FC88 | 34A1 | F+C0E0 -> second child SP+78, 32 bytes |

The [earlier handover](daemon_mig_handover_report.md) and
[first consumer](daemon_record40_consumer_report.md) establish the preceding
token copies and its first Security task argument. Three new all-256-bit
copy identities cover the actual source paths above. Fresh replay checks
80 token-argument instances across the 52 profiles. Identical bytes establish
data lineage; they do not prove that the original input came from a live
authenticated Mach sender.

The current installed SDK's `bsm/libbsm.h` declares audit_token_to_au32 with
an audit_token_t by value followed by eight output pointers. The source and
the compile-only [C probe](triage_evidence/daemon_entitlement_flow_sdk.c)
agree on its arm64e lowering; the [assembly](triage_evidence/daemon_entitlement_flow_sdk.s)
retains the indirect aggregate and pointer placement. Static assertions
check audit_token_t=32 bytes and pid_t=4 bytes.

| ABI location at 0x1004B503C | Value/meaning |
| --- | --- |
| X0 | Pointer to the 32-byte by-value token argument copy |
| X1..X5 | NULL audit/effective/real UID/GID output pointers |
| X6 | PID-output pointer F+0x5D5C |
| X7 | NULL audit-session-output pointer |
| [SP] | NULL final output pointer; source store at 0x1004B5010 |

The PID destination is source-undefined before the call. Its physical backing
bytes are not an input PID or a source initialization. Each PID model records
an explicit four-byte output effect with a zero prior-definedness mask at
the actual API epoch. Fresh replay changes unrelated backing patterns and
checks only the defined prior bytes before applying that effect. The API is
void; its modeled X0 after return is merely part of the declared register
clobber state, not a status result.

No current profile reads that PID-output word before its final boundary.
The sampled PID bit patterns therefore do not yet establish a PID admission
predicate. The [RPC502 path](daemon_rpc502_report.md) uses the same import
slot at a different call site and has a separately proved PID-zero test;
that test is not transferred to this operation. No fixed internal audit-token
word layout or native libbsm parsing implementation is assumed here.

## Second key, record epoch and Security calls

Source decodes 16 original bytes at 0x100FD4A3C into the complete ASCII
string `fairplay-client` plus NUL at F+0x1033E. For byte j!=1 the equation
is u8(9*encoded[j]-0x41); byte 1 is
u8(9*encoded[1]+0x502A-0x6B). The literal is not a bootstrap endpoint.

R is reused with a different layout before call 0x1004B52B4. The new builder
performs 28 bytes of field writes; padding and the status byte are not
initialized as a complete new C object. In particular, old source bytes in
the new status position do not establish a valid second-adapter result.

| R offset | First adapter's interpretation | Second adapter's source-established interpretation |
| --- | --- | --- |
| +00 | First key-string pointer | Token pointer F+C0E0, eight-byte field |
| +08 | One-byte first result marker | Encoded u32 control word |
| +10 | Separate first-flag pointer | Workspace/output pointer F+1280, eight-byte field; complete output type unknown |
| +18 | Encoded u32 first selector | Second adapter's one-byte result marker |
| +20 | First token pointer | Second key-string pointer F+1033E, eight-byte field |

With `K(R)=u32((low32(R) XOR 0x7A9247F6)*0x31B6B333)`, the second builder
stores `u32(R+8)=(phase+0x6B30) XOR K(R)`. The callee recovers
`W20=u32(R+8) XOR K(R)=phase+0x6B30`. The retained phase 0x4061 therefore
selects 0xAB91. In the private placement, K=0xDBFDDAFA and the raw field is
0xDBFD716B. A source-lifted address-key identity, a separate post-key decode
lemma, and a codec-composition theorem prove the relationship. The first
combined solver query timed out; the published decomposed obligations all
return UNSAT. No runtime key fixture or PC intervention replaces the source
MUL in the CPU profiles.

The second child allocates a 0x140-byte frame. Its actual shared roots include
0x1010B7D48 and 0x1010C4670; source issues eight-byte writes at 0x100014040
and 0x100014044 before the key decode. This is a new source context for those
cells, not evidence that earlier rwlock/startup fixtures should be relabeled.
Native initialization, synchronization and the meaning of this evolving
shared state remain unknown.

| Call PC | Interface and exact original binding | Bounded argument evidence |
| --- | --- | --- |
| 0x1000141C4 | CFStringCreateWithCStringNoCopy; slot 0x1010A0598, IA/D471 | allocator model, fairplay-client CString, W2=600 ASCII encoding, contents-deallocator model |
| 0x1000622E8 | SecTaskCreateWithAuditToken; slot 0x1010A0330, IA/2A84 | allocator model; token by-value copy at second child SP+78 |
| 0x1002382E8 | SecTaskCopyValueForEntitlement; slot 0x10109FFA0, IA/FE9E | second task object, second key object, error-output pointer second child SP+98 |

The last call's error cell is source-zeroed at 0x10001408C. Its private
address is 0x680004F188; the task and key are distinct opaque model identities
from the first query's task/key objects. The second query itself is unmodeled
and unexecuted. Its accepted CF type, value interpretation, cleanup and later
result/state updates remain unknown.

## Second string-NULL result and subsequent state consumer

For a NULL result at 0x1000141C4, the original branch selects
0x100067240, which writes marker 0x31 at R+0x18 and returns. The caller
reads this position at 0x1004B52B8 and compares against 0x31. For every marker
byte, its retained-phase table index is 0x406B if equal and 0x4061 otherwise.
The observed equality path reaches 0x1005AA0C8, which tests u32(F+0x6ADC).

| State tested after marker 31 | Index | Original slot / IA discriminator | Target |
| --- | --- | --- | --- |
| zero | 502F | 0x101062068 / 364B | 0x1005750A0 |
| nonzero | 502A | 0x101062040 / 364B | 0x1008017B8 |

Both slots have addrdiv=0. The all-u32 local predicate is proved independently
of the API models. The four second-string-NULL profiles start with the first
query's Boolean-true result, retain state=2, follow the nonzero destination,
and reach malloc(32) at 0x100570148. They stop before that import. The
state-zero destination is statically established but not followed in those
four profiles. No immediate final error, fallback success or native allocation
outcome is inferred from marker 0x31 alone.

## Verification and assumption register

[Independent checks](triage_evidence/daemon_entitlement_flow_checks.json)
pass for 52 profiles and 44,860 source instruction visits: 9,484 reads,
3,088 source writes, 828 logical edges, 428 declared API transitions and
76 separate API-output effects. The latter include 24 four-byte PID outputs
over 96 previously undefined bytes. All 1,264 unique visited source opcodes
match the original image. All 52 first-query prefixes match their frozen
predecessor journals, including the four unmodeled-type frontiers.

Eighteen [source proof pairs](triage_evidence/daemon_entitlement_flow_proofs.json)
produce 36 independently parsed/solved UNSAT files. These cover arbitrary
u32 state/index/phase inputs, three arbitrary 256-bit token payloads at the
recorded copy placements, all address words for local ABI/record equations,
the complete second literal, all second string references and all marker
bytes. Universal statements are local to their explicit premises; finite
profiles do not prove native reachability or all ABI/environment states.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| EF1 | Pinned source VA mapping, bytes and original fixup/import tables identify the target. | Rehash original image; decode used slot words/import ordinals independently; reject opcode or binding mismatches. |
| EF2 | The preceding selector-8BB2 entry/frame, source-generated private cells and declared file/BSS/controller/allocator state define these contexts. Native values are unknown. | Preserve all 52 predecessor source journals; vary backing/controller contexts; establish live initialization separately before native claims. |
| EF3 | Local proof memory cells are readable/writable at the declared placements; modular addresses alone do not establish native ownership or extent. | Rebuild original-instruction equations; strict-stop on unknown private reads/owners; verify each copy/record byte and boundary in a fresh CPU. |
| EF4 | First entitlement results, PID words and second constructor objects are declared models; query-2 results are not modeled. | Retain strict frontiers; inspect every API event/epoch; sample signed PID bit patterns and NULL constructors; do not infer native feasibility or token parsing from them. |
| EF5 | API models preserve X18..X29 and vary X0..X17/NZCV; complete vector/ABI clobber coverage is not claimed. | Independently verify preserved registers, stack and every recorded argument/effect with different undefined-byte backing; widen models before stronger ABI claims. |
| EF6 | PAC edges are logical resolutions of actual loaded slots/targets/modifiers; native PAC key state is unknown. | Check original IA/addrdiv/diversity words and source-loaded targets; hardware authentication success remains outside the evidence. |
| EF7 | Installed MacOSX27.2 SDK declarations justify this compile-only PID ABI probe, without runtime-version equivalence. | Recompile the pinned probe and verify header/assembly hashes; match exact target framework/libbsm versions before implementation claims. |
| EF8 | Token byte equality and reused record addresses have epoch-specific meanings; authenticated sender and final policy meaning are unknown. | Join the original receive trailer bounds/copies, follow both state destinations and query-2 outputs continuously, and distinguish first/second marker/control fields. |

Probe/recovery/replay time is O(total source visits + artifact bytes), with
O(one private CPU map + journals) space. Local BV proof cost adds solver
resources and expression-DAG storage. Extents are bytes; integer equations
are u8/u32/u64 modular arithmetic. No physical-unit or native timing estimate
is asserted.

## Bounded continuation and quality gates

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| high | Recover fairplay-client query result types, result marker and output workspace. | Original consumer after 0x1002382E8, explicit value/error/type models, and the return join to the state word. |
| high | Follow state-zero and state-nonzero destinations after marker 31. | Source-continuous cases covering first-query true/false/NULL with second-query constructor/result combinations; final output provenance. |
| high | Establish authenticated token origin for this operation. | Original receive trailer bounds and the complete source copy lineage; matching bytes alone are insufficient. |
| medium | Link frame bit 0x2 and later state/record outputs to the object-allocation path. | Epoch-specific consumers and eventual ownership/status publication, without interpreting malloc requests as successful allocations. |
| medium | Determine Security/libbsm framework-internal IPC and runtime identity. | Matching implementation and transport evidence; API imports alone do not establish incoming/outgoing Mach ports or emitted rights. |
| medium | Establish initialization/synchronization of shared root 0x1010B7D48 and 0x1010C4670. | Actual native writers and ordered 32/64-bit uses; preserve distinctions from earlier source contexts. |

No new incoming/outgoing Mach port, emission site or right disposition is
established. The [port report](mach_ports_report.md) retains the established
transport contracts; both recovered names here are entitlement keys.

QG1: Pass for factual source/interface analysis; no normative judgment is required.

QG2: Pass for this increment; EF1-EF8 enumerate assumptions, dependent results and falsification probes.

QG3: Pass for this increment; both first-result destinations, state writer/rejoin, PID ABI, token lineage, second record/key/query interface and bounded marker return are covered. The complete interface objective remains active and incomplete.

QG4: Pass; widths, modular arithmetic, byte extents, exact counts, reproduction commands and complexity are explicit.

QG5: Pass within scope; two record epochs/markers, two Security objects, state-preserving OR versus clearing, undefined PID input bytes, NULL constructor continuation and unresolved native effects are distinguished.

QG6: Pass; original bytes/fixups, installed primary SDK declarations, three exhaustive 256-input banks, 36 SMT readbacks and fresh A64 replay support the scoped claims.

QG7: Pass; impact-labeled opportunities cover query results, state consumption, authenticated provenance, ownership and deeper IPC.

Publication evidence: [preservation](triage_evidence/daemon_entitlement_flow_delivery.json)
and [scoped quality gates](triage_evidence/daemon_entitlement_flow_quality_gates.json).
