# fairplayd: packed halfwords and their scalar/count inputs

The two-byte producer at `0x100b75220..0x100b75548` combines a big-endian auxiliary halfword, a four-bit count field and a decoded scalar, then applies XOR `0x534c`. Its count loop computes `max(1,bit_length(D))` for the low-16-bit decoded scalar. The retained fields encode **0 and 2**, respectively. This resolves the separate halfword reduction left open by the [packed-word report](daemon_packed_words_report.md); complete native field names, scalar admission and daemon-kext buffer identity remain unknown. [PH1-PH5; PH-A1-PH-A5]

This increment reuses the inherited non-NULL growth journals. It adds no target interval, guest input, owner, root definition or API-return premise. The 304-member admission scope and byte-writer contracts remain pinned prior evidence. Fresh checks here cover the halfword producer, count setup/iterations, scalar preparation and selected saved-register interfaces. [PH2-PH5]

| Evidence | Primary source and scope |
| --- | --- |
| PH1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original instruction bytes, table slots and format-12 authentication metadata. |
| PH2 | [Append checks](triage_evidence/daemon_append_fields_checks.json.zst), decoded SHA-256 `bac22d45750863b7d3bce0993bc891b70a60f43548907c1135a64f89c50e91f7`, and [audit](triage_evidence/daemon_append_fields_audit.json.zst), `a79919e954824d1e1716e3298b455d6f8f03966cfc5ef6242c80d97dad903049`; [growth checks](triage_evidence/daemon_descriptor_growth_checks.json.zst), `b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2`, retain complete source frames and effects. |
| PH3 | [Extractor](triage_evidence/recover_daemon_packed_halves.py) and [checks](triage_evidence/daemon_packed_halves_checks.json.zst): four concrete fields, six count iterations, source spans, scalar/byte custody, twelve register bridges and original dispatch slots. |
| PH4 | [Independent auditor](triage_evidence/audit_daemon_packed_halves.py) and [receipt](triage_evidence/daemon_packed_halves_audit.json.zst): 32 nonvacuous UNSAT source obligations, fresh selected replay and four SAT interpretation controls. |
| PH5 | [Publication verifier](triage_evidence/verify_daemon_packed_halves_publication.py): fresh extraction/audit, source-query checks, exact manifest delta, original-input preservation and decoded path hygiene. |

## Composed halfword equation

Let A be the two bytes loaded at `0x100b75238/0x100b7523c`, interpreted in big-endian order; n is entry W24 and K is entry W23. The producer requires W25=`0x7a6302fa`. The W-register operations wrap at 32 bits, and variable shifts use the low five bits of the count. Define u16(x) as x modulo 2^16. The value consumed by the adjacent writer is N, not either output register individually. [PH1, PH3-PH4; PH-A2]

```
A = (first_byte << 8) OR second_byte
D = u16(K XOR 0x0df8)
B = ((u32(A << (n & 31))) AND 0x0fff) OR u16(n << 12)
V = u16(B + D)
N = u16(-2 - producer_exit_W8 - producer_exit_W10)
  = V XOR 0x534c
```

This arithmetic identity covers every 16-bit A and every 32-bit n and K in the stated W25 phase. The field interpretation below additionally requires count/scalar bounds. The original prologue reloads X28, obtains the stack adjustment from the entry SP+0x490 cell, changes SP and then reads the two bytes at adjusted SP+0x39a/+0x39b. All four concrete instances use a zero adjustment; replay verifies these reads and SP transitions rather than assuming them. [PH1, PH3-PH4; PH-A2]

| Original source interval, end exclusive | Proven interface |
| --- | --- |
| `0x100b75240..0x100b75274` | Combine the byte registers as BE16(A), cancel the input arithmetic encoding, produce `u32(A<<(n&31))` and preserve low16(n) in W9. |
| `0x100b75274..0x100b752d8` | For arbitrary input x and W25=`0x7a6302fa`, W8 becomes `(x&0x0fff) XOR 0x0403c778`. |
| `0x100b752d8..0x100b75304` | Consume the preceding representation and low16(n); low16(W8) becomes `u16((x&0x0fff) OR (n<<12))`. |
| `0x100b75304..0x100b753b4` | For arbitrary input x and scalar K, low16(W8) becomes `u16(x+(K XOR 0x0df8)+0x0f24)`. |
| `0x100b753b4..0x100b75548` | For arbitrary input x, `u16(-2-W8-W10)` becomes `u16(x-0x0f24) XOR 0x534c`. |

The last two stages cancel the additive bias modulo 2^16. Their contracts constrain only the consumed low halfword; they do not give semantic names to intermediate signed shifts or to either final complement register. Each original interval is lifted independently, including the final multiply/shift and conditional-select arithmetic. The composition is an explicit consequence of those contracts; it is not an unsupported claim of a monolithic full-producer SMT proof. [PH4; PH-A2]

## Scalar, count and saved-register interfaces

The count setup initializes W24 to zero. Under the recovered fixed register phase, an iteration at `0x100b787c8` decodes the low halfword of W10 with XOR `0x0df8`, increments W24 and prepares the encoded right shift. Its continuation test uses the current decoded scalar, before replacing it with the next value. [PH1, PH3-PH4; PH-A3]

```
count = 0
current = low16(K) XOR 0x0df8
do:
    count = u32(count + 1)
    next = current >> 1
    done = current < 2                     # unsigned
    current = next
while not done
```

Sixteen nonvacuous width partitions cover every u16 scalar. Width 1 contains 0 and 1; each remaining partition contains scalars with the corresponding highest set bit. Every earlier iteration continues, and the final one exits. Together with the source step, initialization and dispatch contracts, these establish `n=max(1,bit_length(D))`, with 1..16 iterations. Complexity is O(max(1,bit_length(D))) time and O(1) state. [PH4]

| Scalar predicate | Original index / slot | Target | Authentication metadata |
| --- | --- | --- | --- |
| D >= 2 | 0x296e / `0x10104ea60` | `0x100b787c8`, continue | IA diversity 0x1590, address diversity 0 |
| D < 2 | 0x2997 / `0x10104eba8` | `0x100b75148`, exit | Same |

Both are original authenticated rebases. Source `BRAA X12,X17` at `0x100b78814` uses X17=`0x1590`. All six retained branch targets match the source-selected original slots. This checks logical authentication metadata and target selection; hardware authentication and native relocated pointer values remain unknown. [PH1, PH3-PH4; PH-A1]

| Source location / interface | Established behavior and limit |
| --- | --- |
| `0x100c19e6c` | Set K=`0x0df8`, encoding scalar zero. No scalar memory input occurs in this instruction. |
| `0x1009a308c`, stack SP+0x2b4 | Read a u16 cell; the enclosing `0x1009a3080..0x1009a30a4` source, with W19=`0x7a6302fa`, sets K to `cell XOR 0x0df8`. The retained cell at `0x680005fe24` contains `0200` in memory, representing scalar 2. Its earlier writer is outside this interval. |
| `0x100b6e64c`; `0x100b6e684` | Initialize count W24=0; copy X23 into the initial scalar register X10. |
| `0x100b75148..0x100b75154` | With recovered W19=`0x0e18`, derive W25=`0x7a6302fa`. |
| `0x100acd9cc/0x100acd9d0` | Save X26/X25 and X24/X23 in paired 8 B cells. |
| `0x100a6d3bc/0x100a6d3c0` | Restore X24/X23 and X26/X25. All bytes of the consumed count/scalar/phase cells retain those exact earlier writes in the concrete journals. |
| `0x100a0ca74` -> `0x100b75238/0x100b7523c` | Last local writes of the two auxiliary bytes are encoded-stream stores. Their earlier scalar/randomness semantics remain unknown. |

There are twelve independently checked saved-register joins: count, raw scalar and mask phase for each of four occurrences. The universal save/restore identity assumes unchanged saved cells and the corresponding SP. Concrete byte custody checks that premise for these occurrences. This is a source/model callee interface; it does not prove a native helper invocation, current native epoch or general preservation by every path through the helper. [PH2-PH4; PH-A3-PH-A5]

```
constant 0 / prior u16 cell -> XOR scalar representation -> bit-count loop
                                         |                     |
                                         +---- X23 / X24 ------+
                                                   |
phase from W19 -> X25 ---------> saved cells -> helper -> restored registers
                                                                   |
encoded-stream stores -> two bytes -> BE16 auxiliary -> shift/pack/add
                                                                   |
                                      complement sum -> XOR -> byte masks
                                                                   |
                                                               H halfword
```

## Format, concrete fields and word comparison

For `1 <= n <= 12` and `D < 2^n`, scalar addition cannot carry into the separate auxiliary/count fields. The packed value then has the following organization: [PH4; PH-A4]

```
bit 15           12 11                    n n-1             0
    +--------------+----------------------+----------------+
    | count: 4 bits| low(12-n) bits of A   | scalar: n bits |
    +--------------+----------------------+----------------+
                   12-bit payload
```

The inverse is `n=V>>12`, `D=V&((1<<n)-1)` and `auxiliary=(V&0x0fff)>>n`. It recovers only the low 12-n auxiliary bits. With the source-produced count, these separate fields are guaranteed for `D <= 0x0fff`. The unconditional arithmetic equation still applies above that domain; native admission of such scalars is unknown. [PH4; PH-A4-PH-A5]

Each row occurs in both inherited non-NULL growth classes. Offsets are byte offsets from modeled buffer H. [PH2-PH4]

| H offset / B | Input bytes / BE16 A | Scalar D | Count n | Retained auxiliary bits / value | Packed V | Writer-consumed N | Stored bytes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 71 | c343 / 0xc343 | 0 | 1 | 11 / 0x343 | 0x1686 | 0x45ca | 0704 |
| 15 | 2fda / 0x2fda | 2 | 2 | 10 / 0x3da | 0x2f6a | 0x7c26 | 60b3 |

For H+15, `(2<<12) OR (0x3da<<2) OR 2 = 0x2f6a`; XOR `0x534c` yields `0x7c26`. The pinned writer mask is `1c95`, giving stored bytes `60b3`. For H+71 the corresponding mask is `42ce`, giving `45ca XOR 42ce = 0704`. These byte-writer compositions retain the existing D/E/K banks and output/read-cell disjointness premise; the current audit replays the producer, not the old writer/admission corpus. [PH2-PH4; PH-A4]

The comparison below uses the separately established [word contract](daemon_packed_words_report.md). It establishes related representations, not an external protocol field-name mapping. [PH2-PH4; PH-A5]

| Property | Four-byte producer | Two-byte producer |
| --- | --- | --- |
| Arithmetic representation | u32 packed word | low16 packed halfword |
| Count / payload widths | 5 / 27 bits | 4 / 12 bits |
| Decoded scalar | K XOR 0x8b3dc651 | low16(K) XOR 0x0df8 |
| Auxiliary input | Entry W8 XOR 0x6703cce9 | Big-endian pair of source bytes |
| Count | max(1,bit_length(D)), 1..32 | max(1,bit_length(D)), 1..16 |
| Guaranteed separated scalar domain | D <= 0x07ffffff | D <= 0x0fff |
| XOR at writer input | 0xe4b5bf34 | 0x534c |
| Retained fields, offset / scalar | 1 / 76; 57 / 20; 65 / 1 | 15 / 2; 71 / 0 |

Four SAT controls bound the interpretation without supplying a target input. [PH4]

| Control | Verified result | Limit |
| --- | --- | --- |
| D=0 | Original source gives count 1 and exit index 0x2997 | A zero-width interpretation is false. |
| D=0x1000, source count 13, A=0 | V=0xe000, decoded count 14 | Above the 12-bit scalar domain, addition can alter count bits; native admission is unknown. |
| D=0, count 1, A=0 or 0x8000 | Both give V=0x1000 | The full auxiliary input is not recoverable. |
| Source bytes 2fda versus reversed interpretation da2f | Source V=0x2f6a, reversed V=0x28be | Endianness is observable and cannot be inferred from the host's integer order. |

## Verification and assumption register

Fresh independent replay checks **1,066 original instructions**, 30 selected spans, 35,072 GP/SP values, 1,096 NZCV frames, 48 reads and 16 writes. It checks six logical count edges, four retained field decodes and twelve saved-register joins. The 32 nonvacuous UNSAT obligations comprise 15 source/composition contracts, sixteen complete u16 width partitions and one bounded format inverse. Four SAT controls have explicit witnesses. Earlier admissions and byte-writer replay remain prior pinned evidence. [PH2-PH5]

Time is O(parent receipt bytes + retained visits + reads*writes + selected visits*32 + proof DAG); storage is O(parent receipts + selected evidence + proof DAG). Solver search is separate, with a 30 s bound per query. Register operations are u32/u64 as stated, payload projection is u16, counts are dimensionless and storage offsets/extents use B. Nontrivial JSON archives use `zstd --ultra -22 -q -T1` and decoded round-trip verification. [PH3-PH5]

No new incoming/outgoing Mach name, right disposition, emission site or native daemon-kext transaction is established. Pending malloc97 and NULL-route undefined S+0x30 remain unchanged. No native target API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation executes. Original reference data suffice for this increment; IDA is not accessed. [PH2-PH5; PH-A5]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PH-A1: Pinned image, dependencies and parent journals apply | Source identities, concrete values and dispatch metadata | Verify hashes, exact extraction, selected instruction words, original authenticated slots and complete selected replay. |
| PH-A2: The stated W25 phase, widths and fragment interfaces apply | Universal composed halfword equation | Prove byte order, masked variable shifts, every fragment and low16 composition; verify W25 derivation and each retained SP/memory transition. Do not infer individual final-register semantics from their consumed sum. |
| PH-A3: Recovered loop phase and corresponding unchanged saved cells apply | Bit-count semantics and register bridge | Prove phase preservation, initialization, dispatch and all sixteen width partitions; check every actual count iteration and every byte's last writer through save/restore. |
| PH-A4: Count/scalar bounds and inherited writer premises apply | Separate-field inverse and stored-byte composition | Prove the bounded inverse, decode all four instances, retain output/read-bank disjointness and check out-of-domain, auxiliary-loss and endian controls. |
| PH-A5: Local source contracts do not establish native identity/admission | Native field names, scalar units, caller state, ownership and transport | Require the earlier stack-cell writer, complete auxiliary source, native initializer/caller epoch and matched daemon-kext buffers/messages. Preserve allocation and undefined-field frontiers. |

| Impact | Bounded continuation | Current evidence limit |
| --- | --- | --- |
| High | Find the earlier producer of SP+0x2b4 and any scalar admission bounds | Exact current read/encoding and value 2; no writer in the retained interval. |
| High | Join both producer families' auxiliary inputs to their complete earlier source | Halfword bytes have local encoded-stream custody; randomness and full native provenance remain unknown. |
| High | Match the five decoded scalar fields to actual daemon-kext buffer consumers | Local representation and offsets are established; native transport identity is unknown. |
| High | Continue the pending allocation and unresolved NULL route when their missing native premises are available | No allocation result or undefined descriptor value is supplied here. |
| Medium | Compare other callers' W25 phases and count bounds with these contracts | The current formula explicitly depends on W25; other phases require separate evidence. |

**QG1**: factual technical analysis. **QG2**: PH-A1-PH-A5 state dependencies and falsification probes. **QG3**: the halfword/count/interface increment is covered; the full goal remains active. **QG4**: widths, source counts, byte offsets, exact arithmetic and complexity are explicit. **QG5**: source arithmetic, bounded format interpretation, retained model custody and native unknowns are separated. **QG6**: original bytes/fixups, fresh replay, nonvacuous proofs and publication verification establish provenance. **QG7**: adjacent opportunities and limits have impact labels.

Follow-up: The [halfword reader/update report](daemon_halfword_update_report.md) joins the old F+15 scalar 1 to the later H+15 scalar 2. A paired byte-reader inverse, original increment/store and cross-interval custody resolve the earlier scalar-cell writer. Forty-three source obligations, sixteen exact ring reductions and 656 freshly replayed instructions qualify the source contracts; 152 exports and two growth classes retain the consumed bytes. The zero scalar selects a separate route, and the composed reader bound prevents loss at the later u16 read. Native field names, admission and daemon-kext pairing remain unknown; the full goal remains active.
