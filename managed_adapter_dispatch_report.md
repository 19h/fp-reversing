# Managed-app adapter: local dispatch, records and status contracts

All ten authenticated BLRAA call sites in each previously identified context/buffer adapter resolve to six local compiler entries. Five sites share one record-forwarding helper. Thirty-four bank occurrences are checked on all256 byte indices each; they represent26 distinct address/key triples across the two images. Twelve status gates have24 resolved outcomes. The selected bodies also have eight direct calls to bound libSystem `___stack_chk_fail`. This identifies local calls and specific external failure edges; transitive external interfaces, complete processing semantics, runtime PAC, native outputs and RPC700 involvement remain **unknown**.

This extends the [managed-app/AMS context bridge](managed_fairplay_bridge_report.md). Original input and slice identities remain those in that report; the [new source artifact](triage_evidence/managed_adapter_dispatch_source.json) independently rehashes and recaptures them. Addresses below are unslid original addresses, not live pointers or Mach names.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| AD1 | Original slices and parent artifacts delimit this corpus | Addresses, bytes and classifications | Rehash both universal files/slices and all dependency artifacts; validate loaded-image identity independently |
| AD2 | Bank bytes and chain records retain their recorded values | Fixed dispatch results despite mutable scalar state | Exhaust all256 byte indices; compare every original fixup with dyld_info; runtime mutation or different images invalidate native extrapolation |
| AD3 | Reviewed W/X widths and index truncations match the translation | Constant lookup indices and 32-bit status algebra | Check original UXTB, AND255, W stores and X loads; retain full original bodies and selected instruction assertions |
| AD4 | Original compiler starts delimit the displayed local callees | Six callee roles per image | Re-read complete function-start extents; distinguish function starts from interior branch targets and unexamined nested bodies |
| AD5 | Post-prologue SP is divisible by8 for the recorded aligned zero-fill case | Exact128 B zero region and advanced X0 | Inspect native SP/alignment separately; the scalar bulk-count proof does not establish runtime mapping or reachability |
| AD6 | Record/work-buffer pointers are valid and each stage retains its own schema and encoding | +24/+12/+8 status fields and output width | Check mapping/extents and stores/loads by stage; do not flatten overlapping records or equate distinct encoded status classes |
| AD7 | Fixup authentication metadata describes intended static linkage | Modifier/diversity/key matches | Verify actual signed pointers and hardware authentication separately; no PAC execution is performed |
| AD8 | Selected nested edges and direct failures delimit the recovered outbound graph | Local versus external interface boundary | Recover further callee bodies, BRAA tail targets and actual execution before concluding absence of transitive IPC or identifying RPC700 |

## Constant banks and shared state

Each selected lookup has the form `u8(i XOR B[A[i] XOR k])`, where i and k are u8 values. Its256 outputs are identical for the recorded bank pair and key. The full scalar state computation may produce any32-bit value; UXTB and the final AND255 reduce the relevant dependency to i. Consequently, these selected target indices are constant under the pinned bank/table assumption, without executing the state computation [AD2,AD3].

The original table base is `T=0x100537520`; dispatch base is `D=0x10052faa0` in both slices. A decoded pointer may lead to bytes, writable state, a local compiler entry or an interior continuation; these are different pointer roles. Each role retains its original chain-membership evidence. Initial state selectors resolve to cells `C1=0x10055a2a8`, `C2=0x10055a578`. The adapter's initial update is [AD3]:

```text
All expressions below are modulo 2^64.
K = 0x8e5b334100e20f70; M = 0x000000006cca9517
V1 = load_u64(C1); V2 = load_u64(C2)
delta = V2 - V1 - (post_prologue_SP + 0x30)
store_u64(C1, delta*M + K)
store_u64(C2, (delta XOR K)*M)
```

Subsequent selectors read the low32 bits. Original on-disk cell values are retained separately from unknown runtime values. Other helpers also use the shared state region. Native sequencing, reentrancy and synchronization are not established; the state is not identified as a Mach-port table or a protocol request counter.

## Authenticated call sites and local roles

| Role at inspected call | Daemon site | Agent site | Daemon target | Agent target |
| --- | --- | --- | --- | --- |
| Zero128 B working region |0x10040c4a4 |0x10040c4a0 |0x1004774d4 |0x1004774d0 |
| Initial record helper |0x10040c540 |0x10040c53c |0x10040d638 |0x10040d634 |
| Field forwarding stage1 |0x10040c5ec |0x10040c5e8 |0x1004237cc |0x1004237c8 |
| Field forwarding stage2 |0x10040c714 |0x10040c710 |0x1004237cc |0x1004237c8 |
| Field forwarding stage3 |0x10040c828 |0x10040c824 |0x1004237cc |0x1004237c8 |
| Field forwarding stage4 |0x10040c93c |0x10040c938 |0x1004237cc |0x1004237c8 |
| Field forwarding stage5 |0x10040ca68 |0x10040ca64 |0x1004237cc |0x1004237c8 |
| Buffer-record helper |0x10040cb48 |0x10040cb44 |0x10040749c |0x100407498 |
| Fixed marker writer |0x10040cc2c |0x10040cc28 |0x100412a64 |0x100412a60 |
| Conditional status-field writer |0x10040ccc4 |0x10040ccc0 |0x1004060e4 |0x1004060e0 |

These are analyst role descriptions, not recovered symbol names or complete API signatures. Source records include each pointer slot, bank constant, index addition, target and call-site modifier. For all20 calls, on-disk auth metadata specifies key index0, no address diversity and diversity equal to the explicit X17 modifier. Twelve selected nested edges have the same checked correspondence. This is static consistency, not successful native authentication [AD7].

```text
adapter
  +-> local byte fill: zero working region
  +-> initial record helper
  +-> same field helper, five stages
  |     +-> fixed marker writer
  |     +-> further local body; semantics unknown
  +-> buffer-record helper
  |     +-> further local body; semantics unknown
  +-> fixed marker writer
  +-> conditional status-field writer
  +-> shared status/output handling

selected canary mismatch paths -> libSystem ___stack_chk_fail
native IPC / RPC700 / successful processing: UNKNOWN
```

The initial helper additionally resolves to the marker writer, conditional status writer and another local body. Selected nested unknown targets are daemon `0x1004047ec`, `0x1004241dc`, `0x10043bb60`; agent `0x1004047e8`, `0x1004241d8`, `0x10043bb5c`. Their compiler boundaries and original16-byte prefixes are retained, but this increment does not claim complete recovery of their bodies or outbound effects [AD4,AD8].

## Working buffer and stage-specific records

The first call passes X0=post-prologue SP+0x40, W1=0 and X2=0x80. The local helper first fills up to the next eight-byte boundary, then groups eight-byte stores and finishes remaining bytes. On the static normal path under AD5/AD6, this call has no prefix/tail: sixteen eight-byte stores cover exactly128 B. Its ordinary return leaves X0 advanced to the region's end in this case; it is not assigned the standard C memset return contract. The adapter prepares a new X0 before the next call.

For bulk word count q, `groups=(q+7)>>3`; the first group contains `q mod8` stores, or8 when that remainder is0. Remaining groups contain8 stores each. The SMT query proves `first+8*(groups-1)=q` for all `1<=q<=2^61-1`, covering the possible `u64_remaining>>3` domain. It proves the manually translated count algebra, not the entire machine-code function, native memory validity or reachability.

R denotes the stack-record address passed in X0. The following field observations are deliberately stage-specific [AD6]:

| Helper role | Original reads/writes relevant to its local ABI | Unresolved meaning |
| --- | --- | --- |
| Initial record helper | Reads R+0/R+4 as u32; a recovered local block obtains pointer64 at R+8 and ORs bit7 into the pointed byte | Nested checks and complete initialization contract unknown |
| Repeated field forwarding | Reads u32 at R+0 and pointer-sized words at R+8/R+16; after selected nested calls copies u32 status into R+24 | Logical field identifiers, full payload constraints and nested operation unknown |
| Buffer-record helper | Reads pointer64 at R+0 and u32 fields at R+8/R+16; copies nested u32 result into R+12 | Count/encoding units and buffer operation unknown |
| Marker writer, complete16 B body | Writes `0x723c284b` as u32 to R+4 and returns | Logical marker classification unknown |
| Conditional status writer | Reads u32 at R+4; chooses a global u32 or literal `0x1500a936`; writes u32 to R+8; also updates state cells | Full address-dependent input predicate and meaning of status classes unknown |

The status writer's resolved source pointer slot is `0x100537668`; its object field at +76 B is `0x10055a488`. Original bytes contain u32 `0x15014d6d`. The runtime value is unknown. This word is not equated with the distinct intermediate encoded-zero constant `0x0ef7dc36`.

## Status gates and caller-output store

The first five gates read R+24; the sixth reads R+12. Their predicate is equality with `0x0ef7dc36`. False selects dispatch index0x3a0 and the shared epilogue. True selects the next stage:

| Daemon branch site | Agent branch site | True index | Daemon true target | Agent true target |
| --- | --- | --- | --- | --- |
|0x10040c61c |0x10040c618 |0x74d |0x10040c620 |0x10040c61c |
|0x10040c740 |0x10040c73c |0xc80 |0x10040c744 |0x10040c740 |
|0x10040c854 |0x10040c850 |0x3a7 |0x10040c858 |0x10040c854 |
|0x10040c968 |0x10040c964 |0xd41 |0x10040c96c |0x10040c968 |
|0x10040ca94 |0x10040ca90 |0xa22 |0x10040ca98 |0x10040ca94 |
|0x10040cb88 |0x10040cb84 |0x89f |0x10040cb8c |0x10040cb88 |

The false targets are daemon `0x10040d5f0` and agent `0x10040d5ec`. Ordinary epilogue returns `W0 = W8 XOR 0x0ef7dc36`. A full32-bit query proves this result equals0 exactly when W8 equals that constant. Other returned values are not assigned OS or application error names.

Later branches classify another status word and parse the working region; those conditions are not flattened into the six early gates. A directly observed completion block loads u64 from local SP+0x28 and writes it through the original X3 argument saved at SP+8. The store is daemon `0x10040d5e4` / agent `0x10040d5e0`; it is eight bytes. Direct early-gate branches bypass this block. This does not prove the caller's memory is otherwise unchanged: transitive callee writes and full path predicates remain unresolved.

The four selected canary-failure calls per image resolve through chain slot `0x1005391d8` to Mach-O import `___stack_chk_fail`, ordinal607, libSystem, addend0. All eight original emission sites and stub bytes are retained in the source artifact. There is no newly identified Mach/IOKit emission among these particular resolved calls; unresolved BRAA tails and transitive callees prevent an overall IPC-absence conclusion [AD8].

## Verification, provenance and continuation

[Recovery](triage_evidence/recover_managed_adapter_dispatch.py) retains14 complete original bodies:4392 instructions/17568 B. It checks34 bank occurrences, including repeated address/key triples, on8704 byte inputs; there are26 distinct bank identities across both images. It independently compares37622 format12 fixups against read-only dyld_info output. It preserves20 adapter call mappings,12 selected nested edges,12 gates/24 outcomes, eight direct external calls and all consumed pointer records.

[Validation](triage_evidence/validate_managed_adapter_dispatch.py) recaptures original sources, checks212 selected instruction assertions, re-evaluates all bank identities, checks static auth metadata and runs two timeout-bounded scalar queries, both unsat. Eight controls alter a bank, target, diversity, gate field, marker, output width, fill length or execution scope; all are rejected. These checks do not establish full semantic equivalence of4392 instructions or actual protected processing.

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_managed_adapter_dispatch.py
python3 triage_evidence/verify_managed_adapter_dispatch_publication.py
```

Extraction/validation is O(B+F+I+256K) time/space in source bytes B, fixups F, selected instructions I and bank occurrences K; scalar solver cost is separate and bounded to10 s per query. Sizes are in bytes; indices, scalar states and counts have explicit u8/u32/u64 widths. No target execution/emulation, hardware PAC, service mutation, FairPlay message or native output is introduced.

| Impact | Remaining interface gap | Discriminating continuation |
| --- | --- | --- |
| High | Three selected deeper local bodies remain opaque | Recover their external targets and record transformations before naming the adapter's operation or assigning an endpoint |
| High | Remaining BRAA tails and final parsing predicates unknown | Recover compact branch/data semantics with original-byte and full-width checks; preserve actual reachability as a separate question |
| Medium | Shared state and mutable category word | Determine caller sequencing and real storage lifetime; original initial bytes do not establish a runtime invariant |
| Medium | Output provenance and extent constraints | Track the SP+0x28 value, all writes through caller pointers and stage-specific field definitions |
| Low | Local byte-fill helper differs from standard memset ABI | Preserve its advanced-pointer return and call-specific zero/128 B contract when assigning analytical names |

QG1: Factual static interface and data-flow analysis; no normative conclusion.

QG2: AD1-AD8 state dependencies and falsification probes.

QG3: The adapter's authenticated calls, selected nested interfaces, direct failures, early gates and record widths are covered; complete processing and full interface investigation remain active.

QG4: Byte extents, width-limited arithmetic, modulo64 state updates, complete32-bit status and64-bit word-count domains, and extraction complexity are explicit.

QG5: Repeated bank evaluations versus distinct identities, local calls versus transitive effects, auth metadata versus native PAC, state snapshots versus runtime, and differing record encodings are separated.

QG6: Original hashes/UUIDs, compiler boundaries, fixup membership/dyld_info agreement, original instruction bodies and complete scalar query text provide provenance. Callee names are analytical roles.

QG7: Impact-labeled continuation is bounded to unresolved data/control and external-interface links.

[Delivery checks](triage_evidence/managed_adapter_dispatch_delivery.json) and [quality metadata](triage_evidence/managed_adapter_dispatch_quality_gates.json) apply only to this increment. Original inputs and prior evidence are preserved except for explicit report/index/publisher updates.
