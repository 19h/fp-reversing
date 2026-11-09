# fairplay-client String parser and integer-output contract

The String branch converts into a 32-byte ASCII buffer, calls strtol with
base 10, then tests whether the returned end pointer is non-NULL and points
to NUL. On that local path it writes low32(returned_long) to the four-byte
output slot and selects marker 0x32. The recovered post-parser decision
does not test digit progress, errno or signed-32 range. Other recovered
String-conversion/end-pointer/end-byte outcomes select marker 0x31.

These are source-level caller semantics under explicit library models.
Eleven pure host-libc reference vectors were measured separately and used
as model returns; their runtime has not been matched to the daemon's library.
No native FairPlay daemon/framework/IPC operation was executed. The reference
measurements are not native entitlement values, sender admission or final
authorization observations.

## Primary evidence and reproduction

This extends the [second-result report](daemon_secondary_result_report.md)
and [two-adapter flow](daemon_entitlement_flow_report.md). Original daemon:
`/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
Addresses below are unslid source VAs. Original files suffice; no new IDA
query, database change or analysis-memory write was performed.

Evidence: [host reference vectors](triage_evidence/daemon_secondary_string_reference.json),
[32 private profiles](triage_evidence/daemon_secondary_string_profiles.json),
[original contracts and ledgers](triage_evidence/daemon_secondary_string_contracts.json),
[seven source proof pairs](triage_evidence/daemon_secondary_string_proofs.json),
and [independent checks](triage_evidence/daemon_secondary_string_checks.json).
The annotated RAX trace remains historical transport evidence; it did not
produce these declared CFString/strtol outcomes.

From `/Users/___/dev/dylex/extracted`, apply this prefix to each script below:

```text
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
 Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
 /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/<script>

capture_daemon_secondary_string_reference.py
probe_daemon_secondary_string.py
recover_daemon_secondary_string.py
prove_daemon_secondary_string.py
validate_daemon_secondary_string.py
```

The capture script alone invokes host strtol on fixed owned buffers through
ctypes. Validation remeasures those vectors. dladdr identifies the host symbol
in `/usr/lib/system/libsystem_c.dylib`; OS/kernel/architecture metadata is
recorded. No matching-daemon-runtime claim is made. The other target calls
are private CPU events with explicitly supplied results/effects.

The pinned installed MacOSX27.2 SDK `_stdlib.h`, CFString.h, sys/errno.h and
`usr/share/man/man3/strtol.3` supply primary declarations/documentation; paths
and hashes are retained. The manual describes the end pointer, no-conversion
and range-error conventions. Its historical standard description does not
establish the exact loaded target implementation. A compile-only
[C probe](triage_evidence/daemon_secondary_string_sdk.c) and
[LLVM output](triage_evidence/daemon_secondary_string_sdk.ll) verify eight-byte
long/pointer types, base 10 and the 32-byte ASCII conversion ABI.

## Exact call and output interfaces

Let F be the protected-core frame, R=F+0x10CB8 its second-query record, S the
second child SP and FP its frame pointer. In the retained private placement:
F=0x680004F230, R=0x680005FEE8, S=0x680004F0F0 and
FP=0x680004F220. These are harness addresses, not native fixed placements.
Offsets, markers, indices and masks are hexadecimal unless explicitly decimal;
ordinary byte extents and parser base are decimal.

| Source call PC | Original binding | Arguments |
| --- | --- | --- |
| 0x10014C658 | CFStringGetCString; slot 0x1010A12A8, IA/7208, addrdiv=0 | X0=String ref; X1=FP-0x80; X2=32 bytes; X3=0x600 ASCII encoding |
| 0x10000A2E8 | strtol; slot 0x1010A0320, IA/887B, addrdiv=0 | X0=FP-0x80; X1=FP-0x90, address of char* output; W2=10 |

The strtol discriminator 887B also occurs on CFBooleanGetValue at a different
slot. Exact source-loaded slot/import provenance identifies strtol here.
Discriminator matching alone is insufficient.

The conversion buffer is 0x680004F1A0; the end-pointer output cell is
0x680004F190. The numeric destination is loaded from R+0x10 at 0x10003B2C4
and saved at S+0x18. In this context it points to F+0x1280=0x68000504B0.
The forwarding theorem covers arbitrary output-pointer words in the retained
relative frame layout; actual readable/writable extents remain premises.

```text
CFStringGetCString(ref, buffer, 32, ASCII)
  return zero -------------------------------+--> cleanup, marker 31
  return nonzero                            |
    strtol(buffer, &end, 10)                 |
      end == NULL --------------------------+
      end != NULL, *end != NUL --------------+
      end != NULL, *end == NUL
        u32(*output) := low32(returned_long) @ 0x100073FDC
        marker := 32
        cleanup -> R+18 marker write @ 0x100067240
        caller state |= 8 -> next private bridge/CoreML-named key
```

The CF conversion return is compared as W0 against zero at 0x10014C668.
The theorem covers all u32 words; the modeled CF Boolean returns are 0/1.
The parser returns a 64-bit long. That return is preserved across both local
post-parser guards, which inspect only end-pointer/byte information. STR W0
then stores exactly the low 32 bits; no local signed-32 range predicate is
inserted between those guards and the store.

| Local predicate | True index / target | False index / target |
| --- | --- | --- |
| CF conversion return nonzero | 596E / 0x10000A278 | 5946 / 0x1000746D0 |
| end pointer non-NULL | A9D6 / 0x1000094E4 | A9A3 / 0x1000746D0 |
| byte at end pointer is NUL | 1F1E / 0x100073FC0 | 1F11 / 0x1000746D0 |

Contracts retain the six exact original target slots and IA diversities.
The end-byte test's obfuscated u32 arithmetic is equivalent to byte==0 for
all 256 byte values, not just ASCII digits or the sampled suffixes.

## Separate host reference and modeled caller outcomes

Each reference row below is a measurement of host strtol, followed by a
private source witness using its returned word/end offset. The target errno
cell is not modeled from the host measurement. The local source decision
does not read errno; no assertion is made about later unrelated error-state
consumers or about native target library equivalence.

| ASCII input | Host returned long, decimal | End offset, bytes | Host errno | Modeled marker | Four-byte output, hex |
| --- | ---: | ---: | ---: | --- | --- |
| empty | 0 | 0 | 22 | 32 | 00000000 |
| 0 | 0 | 1 | 0 | 32 | 00000000 |
| 17 | 17 | 2 | 0 | 32 | 00000011 |
| -1 | -1 | 2 | 0 | 32 | FFFFFFFF |
| 17x | 17 | 2 | 0 | 31 | not written |
| space followed by +17 | 17 | 4 | 0 | 32 | 00000011 |
| 2147483648 | 2147483648 | 10 | 0 | 32 | 80000000 |
| 4294967296 | 4294967296 | 10 | 0 | 32 | 00000000 |
| 9223372036854775807 | 9223372036854775807 | 19 | 0 | 32 | FFFFFFFF |
| 9223372036854775808 | 9223372036854775807 | 19 | 34 | 32 | FFFFFFFF |
| abc | 0 | 0 | 22 | 31 | not written |

SDK sys/errno.h identifies 22 as EINVAL and 34 as ERANGE. The empty reference
has end==buffer and buffer[0]==NUL; the caller therefore takes its NUL branch
without a separate end!=buffer/digit-progress comparison. The long-overflow
reference has a NUL end byte and a clamped long return. Its reference errno
does not participate in the modeled local decision. These are representation
and control-flow observations, not a claimed native exploit or final-policy
outcome.

For every row, the store's representation equation is
`output_bits32 = returned_bits64 mod 2^32`. Thus 4294967296 maps to zero and
the positive long maximum maps to FFFFFFFF. This differs from the neighboring
CFNumber path's explicit signed32 conversion request and Boolean conversion
status. How the eventual caller interprets/uses these stored bits remains
unknown; the present traces do not consume that numeric output before their
final boundaries.

The matrix also includes four modeled CF conversion failures, four strict
strtol-call frontiers and two counterfactual NULL end-pointer cases. The NULL
cases test the source guard; their native feasibility is not established.
CF conversion failure is modeled without output writes, not as a universal
failure-buffer guarantee. Successful conversion models write only their
NUL-inclusive prefixes, all within the requested 32 bytes.

## State, record epochs and exact proof limits

Eighteen marker-32 cases follow the previously established OR-0x8 writer
and reach the `FairPlay-CoreML-Client` string-construction frontier at
0x10033376C. Ten marker-31 cases split according to the retained earlier
state: five stop before an unavailable borrowed-owner write and five stop
before malloc(32). Four cases stop before strtol itself. Final operation
status, native owner extents and native admission remain unknown.

The String buffer at 0x680004F1A0 previously held other source data and later
becomes the next Boolean adapter's record in the successful continuation.
The end pointer is consumed before that later reuse. Neither that shared
address nor surviving bytes establish one global C object type or an
asynchronous lifetime contract. All source/profile and API-output effects
remain ordered by their actual instruction epochs.

The output theorem uses a byte-addressed Z3 array. It quantifies all 64-bit
long/output-pointer words while requiring the eight-byte pointer-input cell
and four-byte output store to be disjoint from the later eight-byte control
slot. This controls aliasing across the store and subsequent table load.
The retained CPU placements satisfy those conditions. Native address validity
and other cross-record aliases remain separate requirements. The other local
proofs use explicit readable cells and fixed relative, disjoint frame offsets.

Seven original/simplified proof pairs solve UNSAT. In addition, 256 isolated
fresh A64 byte-gate cases cover every possible input byte over 4,096 original
instruction visits and preserve the supplied 64-bit parser return. The 32
continuous profile replays check 64,490 visits, 13,909 reads, 4,218 source
writes, 1,289 logical edges, 684 declared API transitions and 148 separate
API-output effects. All 2,238 unique source instructions match original bytes.
All 32 earlier prefixes and 20 available deeper String prefixes match frozen
predecessors. Reference vectors are remeasured separately during validation.

## Assumption register and bounded continuation

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SS1 | Pinned source mapping/bytes and original fixup/import tables identify the target. | Rehash image; independently decode exact slots; reject opcode or binding mismatches. |
| SS2 | Retained source entry/frame state and declared controller, writable-image/BSS and allocator data define these private contexts. | Preserve predecessor journals; vary backing/controller contexts; establish native initialization independently. |
| SS3 | CFString refs, conversion result and supplied ASCII bytes are declared API models, not native entitlement contents. | Retain conversion-failure and strict-parser frontiers; inspect every output mask/epoch; do not assume native value feasibility. |
| SS4 | Host-libc measurements justify only the reference rows. Runtime, locale extensions and implementation equivalence to the daemon remain unestablished. | Record host image/OS metadata; remeasure fixed ASCII vectors; match target runtime before native parser claims. |
| SS5 | End-pointer dereference/output writes require readable/writable owners; the output theorem also requires explicit control-cell non-aliasing. | Exhaust all 256 byte values; solve the byte-array theorem; stop before unknown owners; analyze native extents/aliases separately. |
| SS6 | API models preserve X18..X29 and vary X0..X17/NZCV; full vector/ABI clobber coverage is not claimed. | Fresh CPU replay with different undefined-byte backing checks arguments, stack and all effects; widen clobbers before broader ABI claims. |
| SS7 | Buffer, end cell, integer output and later records have epoch-specific roles. | Compare source journals and reused addresses; verify NUL prefix, exact four/eight-byte effects and consumption before reuse. |
| SS8 | PAC is logically resolved; authenticated token origin, native entitlement values, final policy and framework IPC remain unknown. | Verify loaded target/modifier pairs and source copies; recover actual receive-trailer/runtime transport provenance independently. |

Probe/recovery/replay cost is O(total source visits + artifact bytes + total
reference-string bytes + 256*16); space is O(one private CPU map + journals).
BV proofs add solver resources and expression-DAG storage. Byte extents and
fixed-width modular equations are exact; no native timing or physical-unit
estimate is asserted.

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| high | Follow the CoreML-named Boolean adapter and private bridge return. | Actual constructor/query/result-channel source joins and subsequent state consumers; the name alone does not establish CoreML framework activity. |
| high | Establish use/interpretation of the four-byte numeric result. | A source-continuous read of its owner after later queries and final status/object publication. |
| high | Complete borrowed-output-owner and cross-record alias contracts. | Original caller/MIG field construction, readable/writable extents and object lifetime constraints. |
| medium | Match the target C/framework runtime and authenticated sender provenance. | Exact implementation identities, receive-trailer bounds and deeper transport evidence. |

No new incoming/outgoing Mach port, emission site or right disposition is
established; the named keys are not bootstrap endpoints.

QG1: Pass for factual source/interface analysis; no normative judgment is required.

QG2: Pass for this increment; SS1-SS8 enumerate dependencies and falsification probes.

QG3: Pass for this increment; String conversion, parser ABI/guards, narrowing/output, marker/state continuation and reference boundaries are covered. The full goal remains active and incomplete.

QG4: Pass; byte extents, eight/four-byte widths, decimal base, exact modulo equation, counts and complexity are explicit and reproducible.

QG5: Pass within scope; library references versus target observations, errno versus end-byte decisions, scalar payload versus marker, alias premises and record epochs are separated.

QG6: Pass; original bytes/fixups, primary installed SDK/manual, remeasured host reference, 14 SMT readbacks and independent A64 checks support the scoped claims.

QG7: Pass; impact-labeled continuations cover the next adapter, numeric use, owners/aliases and deeper runtime/IPC provenance.

Publication evidence: [preservation](triage_evidence/daemon_secondary_string_delivery.json)
and [scoped quality gates](triage_evidence/daemon_secondary_string_quality_gates.json).
