# CoreFP1201 integer export, status flow and complete local helper return

Original `0x32f628` exports an encoded magnitude into a requested fixed-length big-endian byte buffer, adding leading zero bytes. It checks output length against the absolute encoded limb count, then stores its own status at record+0x18. All 16 retained complete arithmetic cases export 128 B into the candidate request1201 input range and complete the local child/wrapper. Two diagnostic short-export controls establish a distinct status-flow fact: the exporter rejects the requested length, while its selected caller still publishes root status `0xba1df9db` and the separate count value 8. These are private, explicitly altered inputs; native admission and external controllability remain unknown.

## Primary evidence and assumption register

The [original-byte journals](triage_evidence/fpsd1201_export_checks.json), [fresh IDA capture](triage_evidence/fpsd1201_export_ida_readback.json), [independent replay receipt](triage_evidence/fpsd1201_export_audit.json), [producer](triage_evidence/recover_fpsd1201_export.py), [auditor](triage_evidence/audit_fpsd1201_export.py) and [publication verifier](triage_evidence/verify_fpsd1201_export_publication.py) retain the complete bounded evidence. Logical JSON links resolve to compressed `.json.zst` artifacts. The prior [auxiliary/exponentiation report](fpsd1201_auxiliary_report.md) supplies the receipt-pinned arithmetic checkpoints; its prefix instructions are not rerun here.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| EX1 | The pinned reference and original IDA bytes identify these instructions. All address/function claims depend on this image. | Independently parse the universal image, arm64e slice, 1602 compiler starts, 79512 fixup words, 3072 B of banks, 41224 B of selected code and the earlier complete parent. Reject any mismatch. |
| EX2 | Authenticated IA rows are modeled with their original target/diversity and address diversity 0. Private continuation depends on that model. | Check each original pointer association, pre-branch CPU frame and source journal. Native hardware PAC validation remains unknown. |
| EX3 | The predecessor's receipt validates the restored private arithmetic state. Retained output provenance depends on that state. | Pin receipt SHA-256 `623b257cc3ccb1e670cad46a50615f43d21cf6e0abbad4ae9cb80c7f0ea80084`, original generator/auditor identities, exact RAM and the checkpoint's reaching pointer load. |
| EX4 | Isolated records and two shortened nested lengths are explicit diagnostic inputs. Their native producers/admission remain unknown. | Reconstruct every control independently; supply no arithmetic result. Compare unchanged retained cases with both shortened controls and independently generated magnitude/length cases. |
| EX5 | Source descriptor limbs and destination backing are valid for the declared private records. Native capacity, ownership and alias rules are unknown. | Check descriptor/payload stability, byte-exact output, rejection without payload read, null-destination zero-length behavior and complete final RAM. Partial overlaps are outside this case set. |
| EX6 | The completed local helper returns into a declared private stop, not the original native parent execution. Native parent/transport conclusions remain conditional. | Check complete child/wrapper epilogues and original parent call/status-load instructions separately. Establish upstream frame/register/global state before replaying the parent or asserting native delivery. |
| EX7 | Local result/status/cursor stores establish no Mach right. All cross-layer conclusions retain this boundary. | Trace actual serialization/API/right paths and endpoint identity; the newly executed paths contain no Mach API invocation. |

The universal image SHA-256 is `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`; the selected arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. New body `[0x32f628,0x32f954)` is 812 B, SHA-256 `479eee35468a4630dbbe4ba06f5144ac2529d82fc9b3406fa2db0c33d14de254`. Fresh IDA current and original bytes match the file; its initial function end `0x32f780` omits reachable continuation blocks. The compiler start list supplies the complete selected extent. No IDB edit is requested.

## Export record and capacity predicate [EX1-EX5]

X0 points to a record with 28 B of defined incoming/result fields. For p=low32(X0), all word arithmetic below is modulo 2^32:

```text
H = (p XOR 0xd97ffe38) * 0xfcf33521
MEM32[A+0x10] XOR H = 0x80e8
N = MEM32[A+0x14] - H + 0xd9b822c7
```

The original OR/shift/subtract mask expression equals H for every 32-bit p. The retained and independently reconstructed source obligations also establish the length codec and the zero-length sentinel relation.

| Offset | Width | Role / original access |
| --- | --- | --- |
| +0x00 | 64 bits | Destination byte pointer; loaded at `0x32f85c` before an actual byte store |
| +0x08 | 64 bits | Source descriptor; loaded at `0x32f6d0` |
| +0x10 | 32 bits | Encoded entry state; loaded at `0x32f6f0` |
| +0x14 | 32 bits | Encoded requested output length N in B; same LDP |
| +0x18 | 32 bits | Exporter status; written at `0x32f930` |

Descriptors retain signed count `s32(MEM32[D+4]-0x4b0cf050)`, payload pointer D+8, and little-order 32-bit magnitude limbs XOR `0x1ac70ef2`. Negative count signs are discarded for export; output is the magnitude. Descriptor metadata and active payload remain unchanged.

For ordinary decoded count c, the selected admission condition is `N >= 4*abs(c)`. It uses the encoded limb count, including leading zero limbs, rather than the minimum bytes needed by the numerical value. For example, a one-limb value 1 requires at least 4 B; a three-limb representation of value 1 with two leading zero limbs requires at least 12 B. Shorter lengths reject without reading the payload or writing destination bytes.

The exact source comparison at `0x32f708` is unsigned `CMP X17,W10,SXTW #2`. Here X17 holds zero-extended N and W10 holds width-limited absolute count. For INT32_MIN count, that absolute operation retains `0x80000000`; sign extension and the shift produce unsigned `0xfffffffe00000000`. Every 32-bit N is below this value, so that count is rejected. A full-domain retained/independent obligation checks this boundary. No native malformed-count admission result is inferred.

| Condition in the selected state | Destination effect | Stored exporter status |
| --- | --- | --- |
| Length below the count-derived requirement | No payload read or destination write | `0x45e2a205` |
| Admitted, N=0 and count=0 | No destination access | `0xba1df9db` |
| Admitted, N>0 | Exactly N byte stores, including leading zero fill | `0xba1df9db` |

There is no demonstrated positive-length null-destination admission guard. The isolated null-destination test uses only N=0/count=0 and performs no destination access; it establishes no general null-pointer contract.

## Output byte order and complete function [EX1-EX5]

The exporter consumes active magnitude limbs from least significant to most significant. Within each limb it emits low byte first, but destination indices run from N-1 down to 0. Once active limbs are exhausted, encoded zero supplies all remaining leading bytes. Thus the resulting contiguous buffer is big-endian, padded on the left to exactly N B.

```text
source encoded limb 0 -> decode -> byte 0 -> destination[N-1]
                                  byte 1 -> destination[N-2]
                                  byte 2 -> destination[N-3]
                                  byte 3 -> destination[N-4]
source encoded limb 1 -> decode -> next four descending positions
...
encoded zero                   -> remaining leading zero positions
```

At writer `0x32f880`, the audited selected state W26=`0x32fa` reduces the source XOR terms to limb XOR `0x1ac70ef2`; its counter update reduces to decrement by one. The independent replay checks the decoded word, shift 0/8/16/24, exact destination address and byte value at every executed writer. Stores occur at `0x32f880`; the result code is emitted at `0x32f930`; RETAB `0x32f950` executes on every complete call. The function restores its 112 B frame, callee-saved X19..X30 and unchanged SIMD registers in the declared private executions.

For admitted backed records, a compact numerical interpretation is:

```text
value = sum((encoded_limb[j] XOR 0x1ac70ef2) * 2^(32*j))
output[0:N] = value.to_bytes(N, big_endian)
```

The capacity check remains count-based even when this mathematical value would fit in fewer bytes. The selected algorithm takes O(N+1) time and O(1) auxiliary space. The 114 isolated profiles include signed counts, zero, byte/limb boundaries, exact/short/padded lengths, two explicit leading zero limbs, 1024/2048/4096-bit magnitudes, null destination with zero output, and both selected INT32_MIN rejection lengths. They do not establish arbitrary overlap, allocation or native admission behavior.

## Result delivery and distinct status/count channels [EX1-EX6]

The call at `0x981bc8` uses original slot `0x1d03d10`, IA diversity `0xa77e`, address diversity 0, selecting `0x32f628`. Its original reaching load occurs before the restored checkpoint and is pinned separately. The 16 retained continuations use the exact arithmetic descriptors produced by the preceding increment. Each exports N=128 bytes into private P+0x880..P+0x8ff, with 124..128 leading zero bytes for these one-word/zero results. No arithmetic output is supplied or replaced by this increment.

The exporter returns through its full epilogue, then the selected caller follows:

| Site | Exact local action | Established channel |
| --- | --- | --- |
| `0x32f930` | Store status through export record+0x18 | Exporter's own result marker |
| `0x981bd8..0x981be0` | Load saved output pointer and saved word at SP+0x1c; store that word through the pointer | Separate 32-bit root count, value 8 in all 18 nested controls |
| `0x981bf8` | Store `0xba1df9db` at root record+0x30 | Root helper's result marker |
| `0x981c30` | Child RETAB | Complete arithmetic/export child return |
| `0x981e54` | Store zero through the root wrapper's separate cursor pointer | 8 B stack-adjustment output |
| `0x981e68` | Wrapper RETAB | Complete local helper return |

The count value 8 is the saved nominal modulus width in bytes, computed before the earlier diagnostic modulus replacement. Source `0x981264..0x981280` decodes the original context descriptor's absolute limb count; `0x9813dc` saves it. Original `0x981764` loads that count together with shift value 2, `0x981768` shifts it left by 2, and paired store `0x981788` replaces the saved count with the byte width. The [earlier operand journals](triage_evidence/fpsd1201_operand_checks.json) and their pinned [audit receipt](triage_evidence/fpsd1201_operand_audit.json) corroborate this sequence across all 36 prior profiles: declared original count 2, shift 2, stored width 8. Those prefix instructions are not rerun here.

Thus three quantities remain distinct in these controls: original saved modulus width 8 B, later patched working modulus width 4 B, and requested/exported buffer length 128 B. The source precomputation-entry patch changes the working modulus after the saved width was computed. The returned 8 is not evidence of eight destination stores or a native eight-byte modulus. Native context production remains unknown; the declared original descriptor count is a fixture. This audit checks the saved-word lineage, exact final output pointer/store and complete final state.

No source read between the exporter return and the private root-helper return overlaps the export status word. Two explicit controls alter only the encoded requested export length of the retained n=3 case, from 128 to 0 or 3. The source result is one limb, so both export attempts reject, emit `0x45e2a205`, perform no payload read and leave the candidate 128 B range unchanged. Nevertheless, the selected caller still stores count 8, publishes root status `0xba1df9db`, emits zero stack adjustment and returns. Native callers may establish stronger preconditions; these private controls establish local status nonpropagation, not a native defect or successful protected transaction.

| Nested class | Cases | Export status | Candidate 128 B effect | Root marker / count / adjustment |
| --- | --- | --- | --- | --- |
| Retained arithmetic checkpoints | 16 | `0xba1df9db` | Complete padded big-endian integer | `0xba1df9db` / 8 / 0 |
| Explicit length 0 or 3 controls | 2 | `0x45e2a205` | Unchanged diagnostic bytes | `0xba1df9db` / 8 / 0 |

The complete source-staged local path now has the following evidence chain:

```text
declared constructor context and original 128 B import
  -> explicitly backed/canonicalized arithmetic controls in earlier increments
  -> original precomputation and complete exponentiation
  -> original 128 B big-endian export into candidate P+0x880
  -> separate count store and root marker
  -> complete child/wrapper return into private stop
       [original native parent continuation remains unexecuted]
```

## Parent/transport boundary and environmental context [EX1,EX2,EX6,EX7]

The earlier complete parent bytes establish its actual local helper call at `0x8f3560`. The native return address would be `0x8f3564`; the private harness instead returns to its declared stop. Original parent `0x8f3588..0x8f3590` consumes the separate cursor adjustment and assigns SP. Original `0x8f3594` loads W9 from FP-0x88, and `0x8f3598` compares it with `0xba1df9db`. This is the same root marker cell because the constructed root record is FP-0xb8 and `-0xb8+0x30=-0x88`. It is not the export status cell. Those instructions are independently checked against the pinned complete parent; their execution in a coherent native parent frame is not claimed.

The [caller report](fpsd1201_caller_report.md)'s request1201 source pointer comes from the nominal SP+0x1b8 cell, also used by the original constructor as the candidate destination. The complete private helper now establishes how that declared destination is filled. The remaining link to request1201 serialization still depends on parent frame epochs, retained pointer/owner cells, intervening control flow and actual endpoint identity. The original builder's Mach emission remains at `0x8e04`; this increment invokes no Mach API and emits no Mach right.

The exporter updates obfuscation globals `0x1d43fb8` and `0x1d37f68`; all accesses are retained. Complete local guard comparisons, PAC substitutions, mapped globals and backing are private-model evidence. They do not establish native initialization, locking, ownership, accepted hardware operations or daemon/kext pairing. The earlier even-modulus arithmetic controls and width-mismatched product counterexamples remain separate from the export contract.

## Independent validation and bounded continuation

Fresh replay passes 132 profiles: 16 retained nested continuations, two shortened nested exports, 112 ordinary isolated records and two minimum-count controls. All 132 exporters return; 84 admit and 48 reject. The auditor checks 306357 original visits, 33249 reads, 10213 writes, 20104 explicit PAC models, 20740 complete observed CPU frames, 264 export points and 108 root points. Independent byte oracles check all 8179 byte stores. Restored, initial and final RAM each total 20004864 B across the profiles. Eighteen reaching pointer loads, 805 original pointer/profile associations, 54 root publication stores and 18 unread local export statuses are checked. Four retained and four independently reconstructed solver obligations pass; 24 exact source instructions and the 36 receipt-pinned earlier count-lineage profiles are checked separately.

| Impact | Bounded continuation | Falsification / current boundary |
| --- | --- | --- |
| High | Recover native modulus/exponent/count and capacity admission. | Establish real context producers and show whether count-derived capacity and the ignored exporter status are constrained before this call. Diagnostic counterexamples do not establish native exposure. |
| High | Follow the original parent after `0x8f3564` with coherent frame/register/global state. | Connect the actual marker comparison, candidate buffer, scalar guard and builder call; avoid equating identical SP offsets across different frame epochs. |
| High | Join the candidate bytes to real request1201 transport, endpoint/right ownership and daemon/kext/deeper consumption. | Existing builder ABI and private export are separate evidence until concrete identity and delivery are established. |
| Medium | Establish native context-width production and consistency. | The separate saved width is count*4 B before the diagnostic modulus patch; actual export length is 128 B. Trace real descriptor construction before assigning native numerical sizes. |
| Medium | Extend valid alias and native capacity semantics. | Current descriptor/payload preservation and destination checks cover disjoint declared backing; partial overlaps and ownership remain unknown. |
| Low | Extend full helper arithmetic beyond retained one-word moduli. | The exporter covers magnitudes through 4096 bits; that does not extend the complete exponentiation consumer's tested modulus widths. |

Quality gates: **QG1** factual technical analysis requires no normative content. **QG2** EX1-EX7 identify assumptions, dependent results and falsification probes. **QG3** this increment covers export roles, incoming/outgoing fields, numerical output, exact stores/returns, separate status/count/cursor channels, parent interfaces and port consequences. **QG4** B denotes bytes; limb widths, modular arithmetic, signed extension, count units and complexity are explicit. **QG5** zero, signs, leading limbs, insufficient length, INT32_MIN, status nonpropagation, distinct count/length and native limits remain separate. **QG6** original bytes, fresh IDA, independent parsing, pinned receipts, fresh replay and byte oracles support claims. **QG7** impact-ranked continuation is bounded. The full investigation remains active.
