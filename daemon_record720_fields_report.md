# Certificate callback fields, name workspace and startup-state interface

The declared 720-byte allocation route now reaches version, serial, TBS, algorithm, issuer, subject, key and signature callbacks. Its partial callback user record contains source-defined length/pointer pairs; its separate caller-frame workspace contains serial bytes, rendered names and three encoded digests. The populated-name path reaches a new CASAL acquisition of the existing shared gate at `0x1010B5DE0`, then consumes readiness byte `0x1010C5798`. Readiness zero reaches source cleanup and owner release; readiness one stops before an unavailable saved-frame word. Native caller reachability, complete issuer/trust policy, registry publication and a new daemon/kext transaction remain unknown. [CF1-CF13]

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [original source and current IDB bytes](triage_evidence/daemon_record720_fields_source.json), [source equations](triage_evidence/daemon_record720_fields_proofs.json), [18 fresh original-instruction cases](triage_evidence/daemon_record720_fields_profiles.json), [independent checks](triage_evidence/daemon_record720_fields_checks.json), [preservation](triage_evidence/daemon_record720_fields_delivery.json), [quality gates](triage_evidence/daemon_record720_fields_quality_gates.json).

This extends the [allocation/fingerprint convergence](daemon_record720_fingerprint_report.md). The [initialized RPC502 worker](rpc502_startup_report.md) and [frame-entry recovery](daemon_frame_entry_report.md) already establish a source writer for the readiness byte and other uses of the shared gate. The [worker issuer-policy report](rpc502_auth_report.md) retains the distinct Key Services literal and its own conditional policy evidence. The new FairPlay literal and call sites below do not redefine that older path.

## Source-continuous sequence

```text
declared allocation-phase entry -> malloc(720) model -> initializer
  -> private control 0x7A3A -> root/schema parser
       root fingerprint -> TBS record -> version -> serial -> OID/name pairs
       validity callbacks -> RSA-key fingerprint -> TBS digest -> signature
       |
       +-- empty names: before missing byte at Q+0x20, 0x100610BD0
       |
       `-- rendered names: source literal comparison
             -> 0x100503D18 CASAL, shared gate 0x1010B5DE0
             -> before readiness load at 0x10048D694
                  readiness unavailable: retain that frontier
                  readiness = 0: restore gate -> parser error -> free(P)
                  readiness = 1: before missing saved register word, 0x100633F04
```

All cases begin at the same original allocation-phase entry and execute their predecessors. Additional runtime cells are explicit declarations; no internal branch, callback record, result, input pointer or instruction is patched to reach a successor. Logical pointer authentication and modeled allocator behavior remain separate from native execution. [CF2-CF5]

## Partial callback user record

Let C be callback X0, I the parsed item supplied through X1, and Q the work-record pointer at C+0x60. All cases derive these pointers from original frame instructions. The item representation and the field-name interpretation are corroborated by the earlier source schema and independently parsed input bytes. This is a partial accessed view, not a recovered complete native type. [CF4,CF6]

| C offset / width | Established field / representation | Source publication |
| --- | --- | --- |
| +0 / u32 | TBS complete TLV length XOR 0x8B3DC651 | `0x10044F7A8`, from I+0x10 |
| +8 / u64 | TBS TLV start address | `0x10044F7B0`, from I+0x18 |
| +0x10 / u32 | Version byte + 0x428BF564, modulo 2^32 | `0x100161C0C` |
| +0x18 / u32 | Inner algorithm OID content length XOR 0x8B3DC651 | `0x1004150F4`, from I+4 |
| +0x20 / u64 | Inner algorithm OID content address | `0x1004150FC`, from I+8 |
| +0x28 / u32 | Issuer Name content length XOR 0x8B3DC651 | `0x100413258`, from I+4 |
| +0x30 / u64 | Issuer Name content address | `0x100413260`, from I+8 |
| +0x38 / u32 | Subject Name content length XOR 0x8B3DC651 | `0x10000CD3C`, from I+4 |
| +0x40 / u64 | Subject Name content address | `0x10000CD44`, from I+8 |
| +0x60 / u64 | Separate caller-frame workspace Q | Established in the preceding increment |

Other fields, padding and complete ownership/prototype semantics remain unknown. The direct pair setters are proved for arbitrary u32 field values and u64 pointer bits under their source cell/layout premises. They copy pointers; they do not copy the pointed-to TLV bytes or extend their native lifetime. All 162 new field publications match the actual fresh input spans. [CF6,CF7]

The version callback at `0x10041F768` admits the one-byte path iff decoded item content length equals one. Its local branch uses index 0x84D1 for that case and 0x7918 otherwise; the latter reaches the generic return with raw u32 error 0xFFFF5BDE. The admitted byte is represented additively at C+0x10. This is not a claim that every one-byte version is accepted by the enclosing parser or later policy. [CF6,CF8]

The serial callback at `0x10040F1D4` has a source-local length partition `decoded_length > 20`. Its selected copy path writes encoded length to Q+0x18 and encodes each active serial byte XOR 0x98 into the region starting Q+4. The concrete serial has one byte, 0x01, emitted as 0x99. A complete 20-byte native type and all INTEGER-validity rules are not inferred from this local guard. [CF6,CF8]

## Caller-frame workspace and name formatting

| Q offset / span | Established use in these cases | Boundary |
| --- | --- | --- |
| +0 / u32 | Encoded root TLV total | Earlier fingerprint contract |
| +4 / active serial bytes | Serial bytes XOR 0x98 | One active byte in this increment; 20-byte local limit recovered |
| +0x18 / u32 | Serial content length XOR 0x8B3DC651 | Original copy at `0x1000ABD64` |
| +0x1C / u32 | Raw rendered issuer-name byte count | Populated case: 11 |
| +0x20 / text | Rendered issuer string, including terminator | `/CN=Fixture` plus NUL in populated cases |
| +0xE8 / u32 | Raw rendered subject-name byte count | Populated case: 11 |
| +0xEC / text | Rendered subject string, including terminator | Same supplied Name in these fixtures |
| +0x468 / 20 bytes | RSA-public-key encoding digest, XOR 0x98 | SHA-1 of the inner encoded key span |
| +0x598 / 20 bytes | TBS digest, XOR 0x98 | SHA-1 under the supplied algorithm OID in this corpus |
| +0x5EC / 20 bytes | Complete root digest, XOR 0x98 | Last byte ends at Q+0x600 |

The two name count cells are separated by 0xCC = 204 bytes: four count bytes plus a 200-byte character region. This describes the accessed layout and local capacity contract; it does not prove complete native allocation or all-path safety. The source attribute callback at `0x10044FDC0` reaches helper `0x10043AA3C`. Its recovered u32 guard at `0x10043AB00` is exactly:

```text
u32(current_count + decoded_attribute_length + 1) < 201
```

The addition wraps modulo 2^32. Under separately established nonwrapping counts, this permits a combined count including the terminator of at most 200 bytes. No universal nonwrapping invariant or native memory-safety conclusion is claimed here. Source `0x10044FE1C` reads the current raw count; item+4 supplies the encoded attribute length. All 20 populated issuer/subject workspace records match their source-derived `/CN=Fixture` bytes. [CF4,CF6,CF8]

Original bytes at `0x100F780D0`, 94 bytes including the terminator, decode by XOR 0x11 to:

```text
/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple FairPlay Certification Authority
```

The signed/unsigned byte loads at `0x100610BD0` and `0x100610BD4` compare equal iff `rendered_byte == (literal_byte XOR 0x11)`. The proof covers all 65,536 byte pairs, including signed-load high bits. The populated-name fixture compares `/`, `C`, then `N`; the third byte differs from the decoded literal's `=`. That path nevertheless continues to the shared gate. The complete issuer-selection policy and meaning of the mismatch continuation remain unknown; it is not labeled authentication success or whole-operation rejection. [CF6,CF9]

For the empty-name fixture, the raw count is source-defined as zero, but the byte at Q+0x20 has no source write or declared input definition in this allocation-phase state. Execution stops before `0x100610BD0` reads it. This is an exact missing-data boundary in the declared state, not evidence that a native caller supplies an uninitialized object, or a native vulnerability. The earlier whole-worker fixtures have different predecessor and stack declarations. [CF2,CF4,CF10]

## Atomic acquisition and readiness

The populated-name continuation executes original `CASAL W11,W12,[X21]` at `0x100503D18`, with X21=`0x1010B5DE0`, expected W11=0x5D96 and desired W12=0xA94EF. The original image's initial four bytes at that address are `96 5D 00 00`. The new cases explicitly declare the current word equal to that image initial value; image initialization does not establish the current state of a native process. [CF3,CF5,CF11]

| Step | Site | Source/private effect |
| --- | --- | --- |
| Compare-and-swap | `0x100503D18` | Read 0x5D96, store 0xA94EF, return old word in W11 |
| Retry on mismatch | `0x100503D1C..0x100503D34` | Observed phase selects the original CASAL block again when the comparison fails |
| Matched successor | `0x10048D690` | Proceed to readiness read |
| Readiness byte | `0x10048D694` | Read u8 at `0x1010C5798` |
| Byte equals one | `0x10048D698..0x10048D6C0` | Index 0x3820 |
| Any other byte | Same range | Index 0x3831 |
| Readiness-zero cleanup | `0x100634280` | Plain STR restores gate word 0x5D96 |
| Owner release after that error | `0x1001C6100` | Request `_free(P)` through the existing control-0xBBB3 contract |

The readiness partition is proved for all 256 byte values under the recovered source phase. Ten fresh paths execute the matched CASAL transition. Twelve isolated original-instruction MAX-CPU checks cover matching and nonmatching words at two addresses; they compare actual memory/register results with the u32 CAS reference and check preserved NZCV. These are single-thread private execution results. Native authentication, ordering, contention, fairness and scheduling remain unknown. The restoration is an ordinary STR, without an invented store-release property. [CF5,CF11]

The source readiness writer `0x10046C750` belongs to the already recovered startup/frame-entry continuation. Thus the allocation/certificate route consumes an established startup-state interface; no complete native initialization sequence is composed here. Eight new named cases preserve the unavailable readiness byte. The readiness-zero baseline restores the gate, releases P and stops before outer F+0x24F8. The readiness-one baseline retains the acquired gate and stops before `LDR X24,[SP,#0x2E8]` at `0x100633F04`, whose restored register word is unavailable. A pointer use of that word is unproved; the [spill/restore report](daemon_record720_spill_report.md) establishes the subsequent bounded symbolic data flow. The stopped state is not a completed native invocation or evidence of a native lock leak. [CF2,CF10-CF12]

## Evidence coverage and assumptions

There are 18 fresh source-continuous cases and 5,750,409 retained original-instruction visits. Sixteen extend the two earlier certificate-shaped payloads across baseline, frame/allocation/input relocations, prior-runtime variation, two scalar-state variations and alternate backing. Two additional named baselines declare readiness zero or one. Thirteen additional aligned runtime u64 cells are retained explicitly in each context; the atomic word is a separate declared u32. The original 720-byte object receives only its 75 initialization stores in every case; no new certificate-field or digest store is assigned to that heap object. [CF3,CF4,CF12]

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| CF1 | Preferred addresses refer to the identified source and corresponding IDB slice. | Rehash the image and original inputs; compare nine current raw IDB windows totaling 2304 bytes. |
| CF2 | Allocation-phase entry and original header fragments are component handovers, with conditional native continuity. | Match all 18 old prefixes exactly; recover actual original callers and saved frame producers before claiming native reachability. |
| CF3 | Additional runtime u64 values, atomic u32 and optional readiness byte are explicit declarations. | Retain all bytes and origins; vary scalar state, compare the original atomic image initializer and separate missing from declared values. |
| CF4 | Frame, input span and modeled heap owners are distinct; only tracked definitions may be read. | Independently replay effective addresses/effects, vary owners, invalidate P on free, and preserve missing-byte/pointer frontiers. |
| CF5 | MAX CPU supplies instruction capability; pointer authentication and allocation remain explicit models. | Match default-CPU prefixes before new operations; check source slots/modifiers, isolated CASAL effects and native behavior separately. |
| CF6 | Source-local cell/layout/phase premises apply; pointer-bit identities do not establish arbitrary aliasing or native lifetimes. | Check actual item/user/work pointers and widths; derive separate contracts before composing overlapping cells. |
| CF7 | Field names refer to the retained source schema and exact independently parsed bytes. | Compare TBS/OID/Name spans and setters; do not extend this partial view to every certificate mode or complete native type. |
| CF8 | Length/encoding theorems are local predicates. Complete parser grammar and nonwrapping invariants remain unknown. | Retain modular u32 addition, unsigned comparisons and all-byte codecs; establish upstream constraints before broader bounds claims. |
| CF9 | Literal identity and local byte equality are separate from full issuer selection and authentication. | Trace complete mismatch/match successors and later signature/trust decisions with source-backed predecessors. |
| CF10 | Missing workspace/saved-frame definitions are limitations of these declared states. | Recover their actual producers; do not seed unavailable bytes or infer a native initialization defect from private stops. |
| CF11 | Atomic microchecks and full paths are single-thread private execution. | Check mismatch retry and matched transition independently; native scheduling/ordering and source-successful release paths require separate evidence. |
| CF12 | Only the readiness-zero baseline completes this particular error/release path. Other cases stop before unavailable data. | Preserve every terminal instruction, owner mask and gate state; do not treat a stopped acquired state as a returned native call. |
| CF13 | No new Mach/IOKit emission is established on the inspected visits. | Inspect every original edge/import; continue actual successors and join destination/right provenance before extending transport claims. |

## Bounded continuation targets

| Impact | Evidence target | Interface question |
| --- | --- | --- |
| High | Producer of saved `[SP+0x2E8]` before `0x100633F04` | Which caller/save epoch supplies the restored register word? |
| High | Complete FairPlay-literal mismatch/match successors with source-backed state | How does this allocation route select issuer records relative to the distinct RPC502 Key Services path? |
| Medium | Native/source predecessor for the empty-name workspace bytes | Which initialization/caller contract defines Q+0x20 before that read? |
| Medium | Further users and releases of gate word `0x1010B5DE0` | Which operations share acquisition, readiness and ordinary restoration contracts? |
| Low | Remaining C fields and formatter modes | Which partial metadata fields can receive stable types without conflating temporary epochs? |

## Verification

Thirteen source obligations and 26 exact SMT artifacts pass. The independent checker replays every fresh case, matches original opcode/fixup bytes, checks the earlier default-CPU prefix, reconstructs nine metadata publications per case, compares 54 standard SHA-1 outputs at original store epochs, and audits names, owner writes, CASAL effects and stopped reads. Final counts and per-case mappings are retained in the linked check artifact. The complete objective remains active.

```sh
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/capture_daemon_record720_fields.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_record720_fields.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_record720_fields.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_record720_fields.py
python3 triage_evidence/seal_daemon_record720_fields.py
```

Complexity is O(profile/source bytes + visits + effects + solver resources) time, O(profiles + largest decoded case + decoder cache) space. All addresses/extents are in bytes; scalar widths, signed-byte reads, endianness and modular arithmetic are explicit. No native target/framework, allocator, Mach/IOKit, hardware PAC or concurrent synchronization operation executes. Original source files, supplied analysis inputs, previous evidence and IDBs remain preserved.

QG1: Factual technical analysis. QG2: CF1-CF13 retain dependent assumptions and falsification probes. QG3: This increment covers callback fields, workspace, atomic/readiness joins and exact remaining frontiers; full goal incomplete. QG4: u8/u32/u64, signed-byte handling, modular bounds, byte geometry and complexity explicit. QG5: Native versus private, metadata versus trust, caller frame versus heap, missing data versus completed calls remain distinct. QG6: Current source/IDB, original pointer words, source lifts, independent instruction replay and byte/digest oracles provide provenance. QG7: Impact-ranked continuation targets are bounded above.
