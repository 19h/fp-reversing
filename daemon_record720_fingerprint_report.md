# Allocation route, root fingerprint and caller-owned output ABI

The private control **0x7A3A** route now connects the declared 720-byte allocation to the same root callback and encoded SHA-1 operation previously recovered from the RPC502 supplemental-file worker. The digest covers the root TLV, including its header. Its destination is a caller-frame work record, reached through callback argument X0+0x60. The inspected error paths release the 720-byte allocation without copying this digest into it. This establishes convergence of internal interfaces; native input reachability, successful certificate authentication, registry publication and a new daemon-to-kext transaction remain unknown. [F1-F12]

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [source and live-IDB capture](triage_evidence/daemon_record720_fingerprint_source.json), [source equations](triage_evidence/daemon_record720_fingerprint_proofs.json), [fresh source-continuous cases](triage_evidence/daemon_record720_fingerprint_profiles.json), [independent replay and digest checks](triage_evidence/daemon_record720_fingerprint_checks.json), [preservation](triage_evidence/daemon_record720_fingerprint_delivery.json) and [scoped gates](triage_evidence/daemon_record720_fingerprint_quality_gates.json).

The [previous release/reader report](daemon_record720_release_report.md) stopped before the callback's unavailable runtime state. The earlier [RPC502 certificate report](rpc502_certificate_report.md) independently identified the callback through whole-worker fixtures. Their original cases remain frozen. This increment establishes their correspondence and extends the allocation route under explicit additional runtime declarations.

## Interface convergence

```text
fresh 12-byte header components -> U:u64 and D:u32
  -> declared allocation entry 0x100BADFC0
  -> malloc(720) model -> original initializer
  -> private control 0x7A3A -> source parser/cursor route
  -> original schema root at 0x1010389A0
  -> 0x100478EF4 BLRAAZ -> 0x10040F7A4
       X0 = callback user record C
       X1 = parsed-item record I
       C+0x60 -> caller-frame work record Q
       I+0x10 -> encoded total -> Q+0
       I+0x18 -> root start -> digest input
       digest initializer -> source SHA-1 -> bytes XOR 0x98
       digest destination Q+0x5EC, length 20 bytes
       normal callback return W0=0
  -> selected invalid structure: error -> control 0xBBB3 -> free(P)
  -> certificate-shaped structure: next callback, unavailable state

retained RPC502 worker -> supplemental-file body -> same schema/callback
                                                   same digest writers
```

All transfers above execute original instructions in private CPUs, except explicitly modeled allocation/release and logical pointer authentication. The fresh input producer fragments remain component handovers. This diagram does not supply missing native caller continuity. [F2-F5]

| Interface / site | Established contract | Boundary |
| --- | --- | --- |
| `0x100478EF4` | IA modifier-zero callback through original `0x1010389A8` to `0x10040F7A4`; X0=C, X1=I | Hardware PAC success unknown |
| `0x1004AB0DC` | Store caller-frame pointer Q at C+0x60/u64 | C and Q are source-derived frame records |
| `0x10040F8E8` | Load Q from C+0x60 | The callback's first argument has an accessed extent of at least 104 bytes |
| `0x10040F8E0`, `0x10040F8EC` | Read I+0x10/u32 and copy its encoded root-total value to Q+0 | This is a length representation, not a Mach name |
| `0x10040F9E4` | Original slot `0x1010A0170` -> `0x10045C4F0`, IA diversity 0xA88B, address diversity 0 | Initialize the selected temporary digest context |
| `0x1000ABAA0..0x1000ABAA8` | Read C+0x60, add 0x5EC, retain digest-output address | Minimum work-record accessed extent: 0x600 = 1536 bytes |
| `0x1000C69B8`, `0x1000C69E8`, `0x1000C6A00`, `0x1000C6A04` | Emit twenty encoded digest bytes over five word iterations | Captured before callback return and later frame reuse |
| `0x100478EF8` | Caller resumes with W0=0 in all 88 root cases | Callback completion is distinct from whole-parser success |

The frame-relative relationships in these cases are I=C+0x1F8, Q=C-0x6F0 and digest destination Q+0x5EC=C-0x104. An outer-SP-only offset was falsified by the prior-runtime variant: it shifts C, I and Q by an additional 0xF0 bytes through the existing adapter. The record-relative relationships still hold. They are finite observations, not a universal native frame layout. [F4,F6]

The retained whole-worker fixtures use a different callback call site and a differently positioned workspace. Both original call instructions are `BLRAAZ X8`; the original descriptor supplies the common target. The preservation verifier independently checks the original instruction words and all 23 retained worker root-call records:

| Route | Callback emission | Parsed item | Workspace through C+0x60 |
| --- | --- | --- | --- |
| New allocation-phase cases | `0x100478EF4` | I=C+0x1F8 | Q=C-0x6F0 |
| Retained RPC502 worker cases | `0x100924554` | I=C+0x1F8 | Q=C+0x248 |

The common ABI is the pointer field at C+0x60; it does not require the same surrounding frame layout. The allocation call at `0x100BAE048` is absent from the retained worker instruction pool. Consequently, the shared callback and same-input digests do not establish that the retained worker executes the new allocation prefix. [F2,F4,F12]

## Digest-initializer record and runtime cells

For the temporary record address R, all scalar arithmetic wraps modulo 2^32:

```text
K(R) = u32((low32(R) XOR 0xF9D49974) * 0xDA51A827)
```

The source caller at `0x10040F8F0..0x10040F954` supplies:

| Offset | Width | Source representation |
| --- | --- | --- |
| R+0 | u32 input | K XOR 0xB308 |
| R+8 | u32 input | K XOR 0x7EFD0A1C |
| R+0x10 | u64 input | R-0x64: temporary digest context |

The caller identity is proved for eight-byte-aligned R. The callee key identity at `0x10045C53C..0x10045C570` covers arbitrary u64 address bits. The decoder composes using that separately proved key: control becomes 0xB308; `((raw[R+8] XOR K) & 0x1FF) XOR 0x1E` becomes algorithm mode 2. Source stores reset the two u32 counters at context+0x40 and +0x44, initially set output size at +0x5C to zero, and set mode at +0x60 to 2. The selected continuation sets size to 20 and initializes the five encoded state words. [F6-F8]

The complete writer identity is independently lifted from original instructions: an arbitrary u32 state word, represented XOR 0xF4F92DF7, produces its four big-endian bytes XOR 0x98 at the checked offsets. Independent `hashlib.sha1` computations match the actual twenty source stores for each retained root span. This supports the SHA-1 operation on these paths; it does not establish authentication. [F7,F8]

Four exhaustive 256-input byte-bank checks recover the callback state cell `0x1010B7E78`, shared cell `0x1010C4670`, initializer target and dispatch-table base. The callback state update has the following all-u64 source identity. Let X and Y be the incoming u64 contents of those two cells and S the callback SP at the recovered update:

```text
t = u64((Y-X) XOR (S+0x58))
M = 0x0A5CD4CF
K = 0x73D046208EAED1A6
store64(0x1010B7E78) = u64(t*M + K)
store64(0x1010C4670) = u64((t XOR K)*M)
```

The source caller tests the returned u32 through an obfuscated subtraction. The all-u32 proof establishes that its zero predicate is exactly W0==0. With this caller phase, zero selects index `0x8F9C XOR 0x46A5 = 0xC939`; nonzero selects 0x8F9C. This remains an internal dispatch contract. No port, entitlement or IOKit-selector role is assigned to either runtime cell. [F5,F9]

## Payload coverage, output epoch and ownership

Fourteen payloads each have eight variants: baseline, frame relocation, allocation relocation, input relocation, prior-runtime variant, release-state all ones, callback-state cells all ones and alternate physical/volatile backing. These are baseline plus individual variations, not a complete Cartesian experiment. The 112 cases retain 5,941,232 original source visits. The three additional declared u64 runtime cells are `0x1010B7E78`, `0x1010B9230` and `0x1010B69D0`. Their native producers and values are unknown. [F2,F3,F10]

| Payload group | Payloads | Root digest cases | Retained boundary |
| --- | --- | --- | --- |
| Empty root, one INTEGER, empty root with trailing INTEGER | 3 | 24 | Owner release, then unavailable saved frame field |
| Root with 63, 64, 65, 127, 128 or 129 zero content bytes | 6 | 48 | Same inspected error/release path |
| Two synthetic certificate-shaped records, empty or populated names | 2 | 16 | Before `0x10041F770` reads unavailable u64 state `0x1010C5320` |
| INTEGER, OCTET STRING and high-tag controls | 3 | 0 | No root callback; inspected error/release path |

The empty-root-with-trailing-INTEGER case declares five input bytes but hashes only its two-byte root `30 00`. All 88 root callbacks return zero, including fixtures whose enclosing structure subsequently fails. The two certificate-shaped records contain synthetic key material and zero signatures. Their 375-byte and 412-byte root digests are independently compared with the earlier whole-worker evidence for the same bytes. No signature/trust acceptance follows. [F7,F8,F11]

The digest sink is twenty bytes at Q+0x5EC. The first and last stores establish the half-open range `[Q+0x5EC,Q+0x600)`. All byte comparisons use that live callback epoch. Subsequent stack cleanup can overwrite the context, user record and digest; terminal stack contents are not substituted for these source stores. Borrowed input reads are checked against their declared bytes and extents; no source write overlaps the borrowed span. [F4,F7]

Every new case performs only the original 75 initialization writes into P's 720-byte extent. The 96 error/release cases then request `_free(P)` at `0x1001C6100` and stop before the undefined eight-byte read at outer F+0x24F8. The 16 certificate-shaped cases stop before the next unavailable runtime state and keep P live with exactly the initializer's 161 defined bytes. Neither result proves that a later successful parser path cannot populate P+0x238. The registry value->P linkage and publication remain unknown. [F4,F10-F12]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| F1 | Addresses refer to the identified thin source and corresponding arm64e IDB slice. All source results depend on this identity. | Rehash source and original inputs; compare five current IDB ranges, 3920 raw bytes, without normalization. |
| F2 | Entry remains the declared allocation-phase state, with explicit input-component handovers. Reachability is conditional. | Rebuild original input fragments and compare retained prefixes; recover the full native caller and actual input producer separately. |
| F3 | Added runtime scalars have declared values; native initialization is unknown. Continuation depends on their availability. | Test zero/all-ones variants; source-local state and key identities quantify arbitrary bits; do not resume a frozen old frontier by modifying it. |
| F4 | Private frame, borrowed input and modeled heap owners are distinct; only source-defined bytes may be read. Ownership findings depend on this model. | Independently replay all effects and actual effective addresses; vary owners separately; stop before undefined/unowned reads and invalidate P at modeled free. |
| F5 | Authenticated transfers are logical operations checked against original fixups. Call-target conclusions do not prove hardware authentication. | Recheck pointer words, IA key, diversity and source modifiers; compatible native PAC observation is separate. |
| F6 | Caller initializer record R is eight-byte aligned. Caller-key equivalence depends on this premise. | Explicit SMT alignment premise and per-call snapshots; unrestricted decoder-key proof is separate. Outer-SP-only geometry already fails the runtime variant. |
| F7 | Root mode starts at cursor zero; digest observations concern exact supplied spans and source-store epochs. | Compare raw item total/start, input contents, return order, writer PCs and standard digest; trailing-byte and multi-block fixtures discriminate span choices. |
| F8 | SHA-1 naming follows the earlier source evidence and refreshed standard-output comparisons. It is not a universal implementation or authentication proof. | Recompute independent digests and same-input worker oracles; extend message/state domains or inspect signature/trust decisions separately. |
| F9 | Source-local memory cells/records obey the declared nonaliasing and source phase. Formal scalar identities are not arbitrary overlapping-memory theorems. | Check concrete effective addresses and aligned records; derive additional alias-sensitive contracts before composing an overlapping layout. |
| F10 | 112 fixtures and eight individual variants are finite; unavailable next state remains unavailable. | Retain every configuration and exact terminal instruction; no full state-space or all-path claim. |
| F11 | Synthetic certificate-shaped bytes do not authenticate. Structural progression is separate from parser and policy success. | Inspect subsequent signature/trust/atomic outcomes under original callers and authenticated reference data. |
| F12 | No-new-emission statement covers only inspected visits/API targets. Full daemon/kext linkage remains incomplete. | Continue actual source successors and compare destination/right/descriptor provenance at the established Mach/IOKit emission sites. |

## Bounded continuation context

| Impact | Finding / next evidence target |
| --- | --- |
| High | The two routes share the root callback and digest writers. Trace a source-successful parser return before assigning digest storage to the 720-byte object or registry payload. |
| High | Next certificate callback stops at `0x10041F770`/`0x1010C5320`. Recover that state producer or compose its separately verified source-local contract without inventing native state. |
| Medium | C+0x60 distinguishes caller-frame digest workspace from P. Maintain these owner identities through return, cleanup and registry operations. |
| Medium | Callback zero return coexists with later structural error. Track callback status and enclosing parser status as separate ABI epochs. |
| Low | Context-relative geometry survives the tested dynamic stack displacement; global outer-F offsets do not. Prefer source-derived pointers when recording further interfaces. |

## Verification and reproduction

Ten rebuilt source obligations and twenty exact SMT artifacts pass. Five fresh live-IDB windows match original file bytes. Independent replay checks 5,825,912 ordinary A64 instructions, 143,096 writes, 266,024 reads and all 112 cases. It matches 48 frozen release prefixes and 88 live root digests, refreshes 43 earlier worker digest oracles, and matches the two complete synthetic root inputs across routes in 16 fresh variants. The [check artifact](triage_evidence/daemon_record720_fingerprint_checks.json) records final counts and per-case digest/span/destination mappings; preservation separately checks the two source callback sites and 23 retained worker root calls.

```sh
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/capture_daemon_record720_fingerprint.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_record720_fingerprint.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_record720_fingerprint.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_record720_fingerprint.py
python3 triage_evidence/seal_daemon_record720_fingerprint.py
```

Complexity is O(source/profile bytes + visited instructions + effects + retained oracle stores + solver resources) time and O(profiles + largest decoded case + decoder cache) space. Source arithmetic has explicit u32/u64 widths; addresses and extents are in bytes. Source binaries, original supplied inputs, earlier evidence and IDBs are preserved. No native target/framework, cryptographic acceptance, Mach/IOKit operation or hardware PAC executes.

QG1: Factual analysis; no normative conclusion required. QG2: F1-F12 retain premises and falsification probes. QG3: This increment covers route convergence, callback records, digest span/output and ownership boundaries; the full goal remains active. QG4: Modular arithmetic, widths, endianness, byte extents and complexity are explicit. QG5: Callback versus parser success, source versus native evidence, frame epochs and heap ownership remain distinct. QG6: Current image/IDB, original fixups, source lifts and independent replays/oracles provide provenance. QG7: Impact-ranked continuation targets are bounded above.
