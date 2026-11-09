# Packed-carrier reset, control producers and common preparer ABI

Two sample-processing builders call the same preparer at `0xfffffe000a621118`. A separate complete routine at `0xfffffe000a62309c` resets 95 bytes within a 104-byte accessed extent, including both leading control bytes. Local source fragments independently assign control pairs `0/1` and `1/1`. These are upstream evidence for the operation-byte domain discussed in [the transfer report](sample_transfer_report.md); the domain of every carrier reaching a provider call remains **unknown**.

The supplied [zut capture](zut_trace_report.md) stops after an unsuccessful UserClient open. The private source executions below do not add observed daemon/kext transactions to that capture. No new Mach emission, port-right transfer, accepted request, provider execution or cryptographic result is established. The broad interface objective remains active and incomplete.

[Original contracts](triage_evidence/carrier_control_contracts.json), [retained source cases](triage_evidence/carrier_control_profiles.json), [distinct fresh replays](triage_evidence/carrier_control_replays.json), [independent checks](triage_evidence/carrier_control_checks.json) and [four local proofs](triage_evidence/carrier_control_proofs.json) retain the evidence. Original inputs, all IDBs, external `dump.md` and all published predecessors remain preserved.

## Assumption register and evidence boundaries

| ID | Assumption / explicit scope | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| CC1 | Original KC and normalized-kext identities define the inspected build; equivalence to the historical trace's host kext is unknown | All source addresses and recovered ABI fields | Verify both complete hashes, compiler-start bounds, exact bytes and fileset UUID; establish the historical host build separately |
| CC2 | AArch64 little-endian loads/stores and the decoded instruction widths apply | Byte footprints, `0x0100` interpretation, u32/u64 codec | Check retained raw bytes and fresh original-instruction output; do not substitute C annotation types for instructions |
| CC3 | Private fixture pointers, input bytes and entry registers describe the declared local contexts | All finite executions, pointer/selector arguments | Reconstruct actual predecessors, source-defined bytes and ownership before claiming native entry reachability; vary private placement, alignment and fill independently |
| CC4 | PAC operations are abstracted in private execution | Calls/returns within reset and wrapper prefixes | Check original authenticated slots and modifiers; authenticated native execution is not established by stripped private branches |
| CC5 | The declared carrier has 104 accessible bytes | Complete reset footprint and preserved gaps | Check every carrier write and final byte; establish actual allocation/type bounds separately. Minimum accessed extent does not prove `sizeof` or native allocation extent |
| CC6 | The first parent's stack-probe call returns with the expected SP; later source SP pivots are separate contexts | First entry-frame formula only | Inspect/verify the actual probe and all reaching SP definitions; the SMT query proves conditional arithmetic, not the probe's runtime contract |
| CC7 | Bank operands and saved frame pointers have the specified source/fixture values at the inspected calls | Two common-preparer call bindings and parent-to-carrier candidate links | Exhaust all 256 bank inputs, verify original chained pointers, then resolve aliases, intervening callees and dispatch predecessors. Literal stores alone do not prove reaching definitions |
| CC8 | Each reported control assignment is interpreted at its stated source boundary | Connection to the previous operation-argument equality proof | Establish all later writes and the exact carrier passed to the coordinator. Local assignments do not prove a global `{0,1}` invariant or enum semantics |

No native Mach, IOKit, credential, allocation, mapping, synchronization, provider, target-file or crypto API executes. The full preparer body is source-pinned but only its entry prefix and three bounded control-store fragments execute. Opaque carrier data has no recovered key or plaintext interpretation. CC1-CC8 qualify all results below.

## Primary sources and recovered routine roles

| Original source | Verified role / boundary |
| --- | --- |
| Normalized kext, SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Independent original-byte comparison for four complete functions and ten bounded spans |
| Original KC, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Compiler function starts, original bytes, exact symbols and chained-pointer membership |
| `0xfffffe000a62309c..0xfffffe000a623314` | Complete packed-carrier reset; reads `H = *(u64 *)X0`, clears selected ranges |
| `0xfffffe000a687d64..0xfffffe000a687ecc` | Complete pure fill helper; invoked with value 0 and lengths 16, 16 and 32 by this reset |
| `0xfffffe000a67c54c..0xfffffe000a67cae8` | Related wrapper; executed only through the return from its reset call at `0xfffffe000a67c804` |
| `0xfffffe000a621118..0xfffffe000a62259c` | Common preparer for both sample-processing builders; partial entry-record ABI and local control stores recovered |

These role descriptions are analytical labels. No IDB function is renamed. The supplied C corroborates the reset and related wrapper, with exact excerpt line ranges and full C hash retained in the contracts. Binary instructions govern widths and effects.

## Complete reset footprint

The reset loads its carrier pointer with `LDR X23,[X0]` at `0xfffffe000a62319c`. The following stores and pure-helper calls account for every carrier write in all 48 complete reset executions, including 24 related-wrapper prefixes.

| Carrier offset, hexadecimal | Count, bytes | Source action |
| --- | ---: | --- |
| `+0x00` | 2 | `STRH WZR,[X23]` at `0xfffffe000a6231a0`; clears control bytes 0 and 1 |
| `+0x02` | 16 | Original fill call `0xfffffe000a623244`, value32 = 0 |
| `+0x12` | 16 | Original fill call `0xfffffe000a623298`, value32 = 0 |
| `+0x24` | 4 | Original `STR WZR` at `0xfffffe000a62329c` |
| `+0x28` | 16 | Original `STP XZR,XZR` at `0xfffffe000a6232a0` |
| `+0x38` | 1 | Original `STRB WZR` at `0xfffffe000a6232a4` |
| `+0x39` | 32 | Original fill call `0xfffffe000a6232ec`, value32 = 0 |
| `+0x60` | 8 | Original `STR XZR` at `0xfffffe000a6232f0` |

The disjoint union is:

```text
H+[0x00,0x22): 34 bytes cleared
H+[0x22,0x24):  2 bytes preserved
H+[0x24,0x59): 53 bytes cleared
H+[0x59,0x60):  7 bytes preserved
H+[0x60,0x68):  8 bytes cleared

cleared = 34 + 53 + 8 = 95 bytes
gaps    =  2 +  7     =  9 bytes
extent  = 95 +  9     = 104 bytes
```

The reset therefore extends beyond the 89-byte minimum read extent previously established for the sample coordinator. It does not prove a 104-byte allocation or structure size. The field at `+0x60`, both gaps and the region's complete native type remain unknown. The reset is not a contiguous 104-byte zero fill. CC3-CC5 apply.

All three fill call targets are independently constant across 256 byte-bank inputs and resolve through original slot `0xfffffe000847a670` to `0xfffffe000a687d64`. Original pure-helper instructions execute in the private guest; memory effects are not supplied by a memset model.

## Two builders converge on one preparer

The immediately preceding preparer calls in the two builder contexts resolve as follows. The additive and resulting index are unsigned integer table indices; the addresses are unslid.

| Caller site | Left bank | Right bank | Key | Additive | Constant | Index | Original slot | Target |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0xfffffe000a64b21c` | `0xfffffe0007949fd0` | `0xfffffe000792ffc0` | `0x37` | `0xed4` | `0x3a` | `0xf0e` | `0xfffffe000847a790` | `0xfffffe000a621118` |
| `0xfffffe000a68f418` | `0xfffffe0007949dd0` | `0xfffffe000792fbc0` | `0x5c` | `0xe3c` | `0xd2` | `0xf0e` | `0xfffffe000847a790` | `0xfffffe000a621118` |

Eight separately checked original pool bindings support the bank pointers used by these calls, the reset and the related wrapper. The branch modifier at both builder calls is `0x085d`; it is retained with the source instructions. Target resolution does not establish native PAC success. CC4 and CC7 apply.

The first preparer builder writes `H = FP - 0xe8` to its record `+0x18` at `0xfffffe000a64b1bc`. The second stores its returned pointer X0 at preparer-record `+0x18` via `STP X24,X0,[X19,#0x10]` at `0xfffffe000a68f3c4`. Its X28 also receives X0 at `0xfffffe000a68f338`. These carrier candidates correspond to the respective pointer forms later supplied at coordinator-record `+0x20` in [the earlier builder report](sample_caller_report.md). Complete reaching paths, callee preservation and object identity across every intervening branch remain unknown.

## Partial preparer-record ABI

Let P be the preparer's input record pointer and K its address-derived key. Original entry instructions form:

```text
K64 = (P XOR 0xe10934e57abbf985) * 0xded29631 mod 2^64
selector32 = record.u32[0x30] XOR low32(K64)
```

Two local SMT queries establish equivalence to the original AND/shift/subtract/add/XOR expression, at full64 and low32 widths. They prove algebraic identities for every 64-bit P, without proving valid object addresses or input reachability.

| Offset | Width, bytes | Inspected use |
| --- | ---: | --- |
| `+0x00` | 8 | Opaque source pointer saved in X21 |
| `+0x08` | 8 | Saved pointer |
| `+0x10` | 8 | Saved pointer |
| `+0x18` | 8 | Packed carrier pointer H, loaded explicitly at `0xfffffe000a621490` |
| `+0x24` | 4 | Output status on inspected return at `0xfffffe000a621740` |
| `+0x28` | 8 | Context pointer; context +`0x100` is the entry guard's first argument |
| `+0x30` | 4 | Encoded selector, decoded to W26 |
| `+0x38` | 8 | Guard limit, entry guard's second argument |

The complete preparer record schema and the source object's semantic type are unknown. This is a partial internal ABI, separate from the coordinator's 96-byte record and its different key formula. Twenty-four fresh entry prefixes vary four record placements and six selectors, including bit31-set and all-ones values. Each stops before `BLRAA` at `0xfffffe000a621338`, checking both guard arguments and the decoded W26; no deeper processing executes.

## Source-defined control assignments

| Original fragment | Declared carrier register / relation | Effects at the stopping boundary | Remaining qualification |
| --- | --- | --- | --- |
| Reset `0xfffffe000a62309c` | `H = *input_record` | `H[0]=0`, `H[1]=0`; complete footprint above | Local complete reset; ultimate consumer association unknown |
| `0xfffffe000a69d954..0xfffffe000a69d978` | Incoming X0; copied to X28 | `H[0]=1`, `H[1]=1`, `H[0x38]=0`; u32 fields `+0x24=0`, `+0x28=0x1000`, `+0x2c=0` | Post-dispatch pointer fixture; allocation success, later writes and coordinator reachability unknown |
| `0xfffffe000a69825c..0xfffffe000a698278` | `H=FP-0xe8`, body SP+`0x568` under the stated frame | `H[0]=0`, `H[1]=1`, with the same `+0x24/+0x28/+0x2c/+0x38` values | Stack-local carrier candidate; linkage to the second coordinator carrier is not established |
| `0xfffffe000a621490..0xfffffe000a6214a0` | `H=*(X19+0x18)` | `H[1]=0`, preserving H[0] in this fragment | Local preparer fragment only |
| `0xfffffe000a621a78..0xfffffe000a621a8c` | X2 | `H[1]=3`, preserving H[0] in this fragment | Local preparer fragment only |
| `0xfffffe000a6221c4..0xfffffe000a6221cc` | X26 | `H[0]=0`, stores incoming W11 at `+0x2c` | Local preparer fragment only; upstream X26 association is conditional |

Little-endian `STURH W8,[FP,#-0xe8]` with W8=`0x0100` produces the pair `0/1`; it does not set operation byte0 to 1. The heap fragment uses two separate `STRB` instructions and produces `1/1`. Neither assignment identifies the meaning of the provider's operation enum.

For the exact H[0] values set by these fragments, the [previous transfer contract](sample_transfer_report.md) gives equal provider argument values for the direct and buffered paths: byte0=0 gives 1 on both; byte0=1 gives 0 on both. This conditional composition remains separate from proving that all later consumers receive these exact bytes. No native defect or provider interpretation follows from the earlier non-Boolean arithmetic examples. CC7-CC8 apply.

## Entry-frame arithmetic and SP changes

| Parent compiler start | FP relative to entry SP | Body SP relative to entry SP | FP minus body SP | `FP-0xe8` relative to initial body SP |
| --- | --- | --- | --- | --- |
| `0xfffffe000a635208` | `-0x10` | `-0x10f0` | `0x10e0` | `+0xff8` |
| `0xfffffe000a6890dc` | `-0x10` | `-0x660` | `0x650` | `+0x568` |

Two SMT queries verify this arithmetic modulo 2^64. The first result assumes the stack-probe SP contract (CC6). The earlier first-builder fixture used a declared FP=SP+`0x1100`; it was explicitly a local fixture and is not changed or retroactively described as an entry-derived frame.

The source census covers 72913 decoded instructions in both parent compiler envelopes. It records literal ADD/SUB/MOV/LDP instructions naming SP or FP as their first operand, including eight `MOV SP,X8` instructions: three in the first envelope and five in the second. The retained census is not a general alias/reaching-definition analysis; pre/post-indexed stores also change SP in prologues. A constant translation from every later SP-relative address to the initial body frame is not established. The `+0x568` stack object must not be equated with the second builder's X28 carrier solely because both appear in the same compiler envelope.

## Verification and reproducibility

The producer and fresh verifier each execute 192 distinct cases and 22422 original instruction visits. The fresh verifier checks 19968 final carrier bytes, all ordered carrier writes, all retained source bytes, original chained pointers, six exhaustive banks (1536 inputs), eight pool bindings and four SMT queries. Forty-eight full reset cases account for 4560 written bytes and 432 preserved gap bytes. Forty-eight local `0/1` or `1/1` cases account for 720 carrier-written bytes. No fixture reads undefined private data.

The reset/alignment and local fragments use eight carrier placements and three fill patterns. Stack-producer SP values retain 16-byte alignment; its eight placements do not claim eight different ABI-valid carrier alignments. Other reset/heap alignments are local memory stress fixtures, without native alignment-admissibility claims.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_carrier_control.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_carrier_control.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_carrier_control.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_carrier_control.py
```

These commands regenerate this increment's artifacts. For a new investigation, preserve published outputs and use a distinct output copy. Source extraction costs O(B+I+256R+chain work); finite replay costs O(C*(B+V+E)), with C cases, B mapped source bytes, V instruction visits and E retained events. Solver cost is separate. No algorithm here claims exhaustive recovery of the obfuscated CFG.

## Bounded continuation

| Impact | Further question / opportunity | Evidence needed |
| --- | --- | --- |
| High | Establish the complete first-byte domain at the actual AES-wrapper boundary | Trace the preparer's successful returns, all subsequent carrier writes and the coordinator's exact pointer; retain dispatch predicates and byte epochs |
| High | Connect preparer-record `+0x18` to coordinator-record `+0x20` across real predecessors | Resolve stack pivots, returned-pointer origin and callee preservation in both builder contexts |
| High | Relate historical daemon startup to an actual kext transaction | Match host kext identity and effective calling-task identity; the supplied trace's null connection remains the observation boundary |
| Medium | Recover carrier `+0x60` and the two preserved gaps | Identify consumers and independently establish allocation/type extents |
| Medium | Determine the semantic relationship between `0/1` and `1/1` producer variants | Follow source-only control predicates and lifecycle/context changes; operation enum names remain unknown |
| Low | Find a build-matched private type definition | Match the actual fileset/version before assigning field or enum names from external headers |

## Scoped quality gates

| Gate | Result / evidence |
| --- | --- |
| QG1 | Pass: factual source/ABI analysis; no normative premise is required |
| QG2 | Pass: CC1-CC8 specify dependencies and falsification probes |
| QG3 | Pass for this increment: reset, common preparer, producer controls, partial record ABI and frame qualifications covered; full objective remains active |
| QG4 | Pass: byte counts, half-open ranges, u32/u64 widths, modulo arithmetic and finite complexity specified |
| QG5 | Pass: reset footprint/sizeof, local assignment/global invariant, candidate pointer/native identity, SP arithmetic/reaching definitions and argument value/enum meaning remain distinct |
| QG6 | Pass: original bytes/compiler envelopes/chained pointers, preserved C excerpts, 192 fresh cases and four local proofs support the scoped claims |
| QG7 | Pass: impact-labeled continuation table bounds the additional questions |

[Final source identity](triage_evidence/carrier_control_source_identity.json), [baseline preservation](triage_evidence/carrier_control_preservation.json) and [machine-readable quality gates](triage_evidence/carrier_control_quality_gates.json) retain delivery checks. No acceptance, native reachability, crypto behavior or completion of the broad goal is asserted.
