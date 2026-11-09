# Page callback: token lookup, owner record and mapped metadata

Original execution connects `_EQlZPp(token,offset,source,destination)` to operation `0x94f8574b`, a shared linked token lookup, the matching owner's child at +`0x2e8`, and the FPAppSecurityInfo fields used by the [mapped-region close suffix](kext_mapped_cleanup_report.md). This is a continuous private CPU path through original wrapper, dispatcher, lookup and consumer instructions, with explicit allocation/warm/registry premises. Native registry initialization, constructor publication and a complete page-decrypt operation remain unknown. [PC1-PC8]

Five proofs recover the shared address key, page token bias, node-token match and offset mask/domain. Positive cases reach the original load of record+`0x48` and calculate a mapped metadata-entry address. Execution stops before the first metadata-byte load at `0xfffffe000a60e0fc`; no payload decryption or native mapping operation is executed.

Evidence: [original code, selectors, views and five proofs](triage_evidence/kext_page_context_source.json), [private paths and field snapshots](triage_evidence/kext_page_context_profiles.json), [independent replay/oracles](triage_evidence/kext_page_context_checks.json), [preservation](triage_evidence/kext_page_context_delivery.json), and [scoped gates](triage_evidence/kext_page_context_quality_gates.json).

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PC1 | Original collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` supplies all visited code and logical format-8 pointers. | Rehash and recapture ranges/slots; replay checks each visited original word. Native kernel/daemon pairing is separately unknown. |
| PC2 | Private CPU execution follows A64 arithmetic and declared logical authenticated branches. | Separate executor checks words, memory accesses, targets/modifiers, registers and boundaries. Hardware PAC is not exercised; address-key codecs are not authentication proof. |
| PC3 | Warm flag `0xfffffe000ccca078` is explicitly 1 in private image state. | File-state flag0 enters cold initialization before lookup; that separate path is not silently modeled. Native consistency of flag1 with the supplied registry is unknown. |
| PC4 | Registry cell `0xfffffe000cccca58` is NULL or heads the declared one-/two-node private list. Nodes have readable fields and encoded token words. | Cases test empty, miss, head match and tail match, including upper token bits. Prove native list construction, ownership, synchronization and lookup lifetime separately. No cycle/completeness claim is made. |
| PC5 | Matching owner has a declared child, marker, second field, flags and mapped metadata description. Other private owner/record bytes are zero fixtures. | Vary absent child, bad marker, `0xabcd`, owner bit `0x80`, page indices, field sum and +`0x40` value. Native field writers and full valid-object invariants remain unknown. |
| PC6 | Allocator models return disjoint declared regions: 16384-byte/64-aligned frame, 4096-byte AllocType and 104-byte FPAESParameters. Free models have no effects; caller-saved registers/NZCV are clobbered. | Check original type views, every modeled call argument and source cleanup request. These models prove neither native allocation/initialization nor reference balance. |
| PC7 | The local page producer's control seed W21=`0x90b` and lookup operation index `0xc18` arise on the recorded original page path. | Record source-produced keyed fields and prove their scalar identities. Offset-domain proof quantifies all u64 offsets; finite range/entry tests do not prove the full two-u64-field predicate. |
| PC8 | Metadata, `0xabcd` and wrapper-return boundaries terminate the declared scope. | Stop before metadata-byte access/crypto; verify source/destination buffers are untouched in this prefix. Establish constructor -> owner publication -> page use -> close in one native lifetime before claiming a full exchange. |

No IDA query was needed: supplied C/call artifacts locate the wrapper, and original collection bytes resolve the additional contracts. No original input, IDB, saved memory, native task, Mach right, VM mapping or key state was changed.

## Callback and private dispatch ABI

The [text-pager report](text_pager_interface_report.md) establishes the kernel caller through provider slot +`0x8a8`, adapter `bvqhJ` at `0xfffffe000a504e4c`, to `_EQlZPp` at `0xfffffe000a5a4bc0`. Source arguments are token in X0, u64 offset in X1, source pointer in X2 and destination pointer in X3. The wrapper stores only low32(token) in the internal argument record. [PC1,PC7]

| Internal argument offset | Extent | Source meaning |
| --- | --- | --- |
| +0 | 4 bytes | low32(token) |
| +4 | 4 bytes | No source-defined input claim; alignment/padding is unassigned |
| +8 | 8 bytes | Offset |
| +16 | 8 bytes | Source pointer |
| +24 | 8 bytes | Destination pointer |

The wrapper requests `_IOMallocAligned(0x4000,0x40)` at `0xfffffe000a5a4d54`, `_IOMallocTypeImpl(AllocType view0xfffffe000847bea0)` at `0xfffffe000a5a4dd8`, and initializes arenas through original helper `0xfffffe000a687ecc`. At `0xfffffe000a5a4f00`, the selected target is the original dispatcher `0xfffffe000a606728`. Its argument is the source-populated frame F, not the external page buffers. [PC6,PC7]

For `Kf=(low32(F) XOR 0x97099bc0)*0xef54ff65`, modulo 2^32:

```text
F+0x10 = Kf XOR 0x94f8574b
F+0x18 = 0x3e784ff5 - Kf
F+0x28 = pointer to the 32-byte analytical argument view
F+0x30 = AllocType scratch pointer
```

The dispatcher requests a distinct FPAESParameters object at `0xfffffe000a609e3c`, using view `0xfffffe000847b760` (104 bytes). The private model keeps this object disjoint from the AllocType region. Reusing one return pointer for both would change the fixture's aliasing and is not part of this report.

## Shared token lookup and owner identity

The page operation calls original shared lookup `0xfffffe000a5b07f4` at `0xfffffe000a60a024`. It uses the same operation index, address key, biased token and registry cell as the [close wrapper](kext_close_report.md). Let L be the lookup argument-record address, T the low32 token and K its u32 address key. [PC1,PC4,PC7]

```text
K = (low32(L) XOR 0x280834b2) * 0xf87ec353  (mod 2^32)
L+0  : pointer to an owner-pointer output slot
L+8  : K + 0xc18                         (u32)
L+12 : output status byte               (separate write epoch)
L+16 : (T + 0x7a2abb13) XOR K            (u32)
```

Five local proofs include the source equivalence of K, the page producer's bias and the node-match condition. The node's raw word at +4 equals `T XOR 0x31ae0066` on a match; this statement quantifies all u32 token/node words, rather than fitting the finite cases. The list head is loaded through original cell `0xfffffe000cccca58`. A miss loads next node from node+`0x10` and repeats. A match writes the node pointer through the supplied output slot and writes status byte `0x23`; exhausted/NULL lookup writes `0x22` without publishing a node. There is no reconstructed complete node type or native lock/reference contract here.

| Resolved role | Original selected slot | Logical target / modifier |
| --- | --- | --- |
| Page dispatcher | `0xfffffe000847a858` | `0xfffffe000a606728`, IA diversity `0xd0c8`, address-diversity0 |
| Shared lookup | `0xfffffe000847a850` | `0xfffffe000a5b07f4`, IA diversity `0x8bbb`, address-diversity0 |
| Registry cell | `0xfffffe00084729b8` | `0xfffffe000cccca58`, unauthenticated original data pointer |

These are original pointer-chain and exhaustive-selector bindings. They establish the logical selected addresses and recorded modifiers; hardware authentication is untested. The u32 token is a private lookup identifier in this contract, not an established Mach port name or right.

| Original source site | Established operation |
| --- | --- |
| `0xfffffe000a5b0924` | Load list head through resolved registry cell |
| `0xfffffe000a5b09b4` | Read node+4 token word |
| `0xfffffe000a5b0a44` | Load next link at node+`0x10` |
| `0xfffffe000a5b0ac0` | Publish matching node through the output pointer |
| `0xfffffe000a5b0ad4` | Write lookup status byte |
| `0xfffffe000a60a034` | Page caller reads lookup status before selecting its continuation |
| `0xfffffe000a60a070` | Load returned owner pointer from the source-written output slot |
| `0xfffffe000a60cb9c` | Load owner+`0x2e8` as the security-record child |

Head and tail cases check actual source writes and one/two node-token reads. Miss cases check the NULL-terminating link traversal. Incoming X0 values 1 and `0x100000001` both marshal token1 at the same private addresses; upper bits of the original saved X0 do not become the lookup token. This does not prove that all native token values have live owners. [PC4,PC7]

```text
page callback -> provider+0x8a8 -> EQlZPp
    -> operation 0x94f8574b
    -> registry head -> node+4 token comparison
                          | miss -> node+0x10 -> repeat
                          | match
                          v
                      owner pointer
                          |
                      owner+0x2e8
                          |
                FPAppSecurityInfo child
                          |
               guards -> child+0x48 mapped base
                          |
                metadata-address frontier
```

This adds original execution continuity from the page wrapper into the child read. The constructor's publication of that live owner/child and subsequent close invocation remain separate unresolved lifetime joins. The [FPAppSecurityInfo report](kext_security_record_report.md) establishes static allocation/free type descriptions and the requested record extent.

## Offset, record and mapped-data gates

The original offset mask is `0xfffff00000000fff`. Its source derivation is proved, and a separate bit-vector identity establishes that mask-clear offsets are precisely multiples of 4096 bytes below `2^44` bytes. The latter bound is 17592186044416 bytes; the page index is offset shifted right12. The page caller rejects a NULL owner or nonzero masked offset before accessing the security-record child. [PC5,PC7]

| Gate / field | Original source | Established result |
| --- | --- | --- |
| Owner and offset | `0xfffffe000a60a070..0xfffffe000a60a09c` | Owner must be non-NULL; `offset & mask` must be zero on the examined continuation |
| Child pointer | `0xfffffe000a60cb9c` | NULL child selects an error route |
| Child marker | `0xfffffe000a60cbe0..0xfffffe000a60cc0c` | Word0 compared with `0xbeefed02`; mismatch selects an error route |
| Child second field | `0xfffffe000a60cc20` | Qword+8 compared with `0xabcd`; equality selects a distinct continuation stopped at `0xfffffe000a60cc4c` |
| Page-range operands | `0xfffffe000a60dc44..0xfffffe000a60dd48` | Compute page index and read child+`0x20/+0x28`; tested ordinary sums admit indices below the sum |
| Base/extent operands | `0xfffffe000a60dfc0`, `0xfffffe000a60e018` | Read u32 child+`0x40` and mapped extent+`0x50` before the mapped-pointer path |
| Owner flag | `0xfffffe000a60e098..0xfffffe000a60e0c4` | Owner+`0x28` bit `0x80` must be set on the examined metadata path |
| Mapped pointer | `0xfffffe000a60e0d8` | Load child+`0x48`, the address installed by the earlier mapping component |
| Metadata frontier | `0xfffffe000a60e0fc` | Pending `LDRB W12,[X16,#0xf]`; stop before this instruction |

The range cases keep word20=0 and vary word28 over0/1/2/4096, with page indices0/1/2. The first mapped metadata address in the accepted cases is `mapped_base + word40 + 32*page_index`, with word40 values0/32. The pending first load is byte15 of that candidate entry. The 32-byte stride and base addition are finite source-execution results here, not an all-u32/u64 index/extent proof. Complete metadata bounds, record format, byte interpretation and crypto continuation remain unknown. In particular, reaching this address is not a completed page-decrypt result. [PC5,PC8]

## Results, reproduction and remaining interfaces

The explicit source capture has six ranges / 1309 instructions, four type views, three exhaustive 256-input selectors and five source/bit-vector proofs. Eighty-three private cases execute 376547 original visits. Independent replay verifies every visited word, 43324 reads / 262027 bytes, 21394 writes / 125403 bytes, 9548 logical PAC steps, 420 declared allocator/free returns and 83 final boundaries. There are 51 lookup hits, 32 misses, 83 node-token reads and 32 next-link reads. The supplied argument records and keyed lookup fields are checked in all83 cases. [PC1-PC8]

| Boundary / result | Cases | Interpretation |
| --- | ---: | --- |
| Mapped-metadata frontier | 25 | Original mapped-base load executed and candidate entry address checked; pending metadata load not executed |
| `0xabcd` record frontier | 1 | Distinct record-field branch, stopped before its continuation |
| Wrapper returns `0xffff5b36` | 32 | Lookup miss/empty list in these fixtures |
| Wrapper returns `0xffff5bd9` | 24 | Examined bad-offset, child, marker or page-range routes |
| Wrapper returns `0xffff5bef` | 1 | Examined owner-flag-clear route after the preceding guards |

The three numeric return values are zero-extended W0 results; symbolic/business error names are unknown. Intermediate frame fields at a stopped frontier do not establish operation success. Page source and mapped metadata ranges have no CPU data reads before the selected boundaries; the first4096 destination bytes retain their declared canary in all83 cases. The wrappers' inspected external calls are local allocation/free operations, with no additional Mach right or IPC emission observed in this bounded prefix. This does not characterize all page-operation continuations.

```sh
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
  Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kext_page_context.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
  Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kext_page_context.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
  Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kext_page_context.py
```

Recovery takes O(B+I+256K) time plus timeout-bounded SMT solving, where B is image bytes, I captured instructions and K banks. Recording/replay takes O(B+V+E) time and O(B+J) space, where V is visits, E modeled events and J journals. The list itself performs O(L) node steps for a terminating L-node list; this bound does not apply to unproved native cycles. Publication validation takes O(total artifact bytes + links).

| Impact | Unresolved question / opportunity | Discriminating evidence |
| --- | --- | --- |
| High | Constructor-to-list publication | Recover the original writes to node+4, next link and registry head, then join the allocated FPAppSecurityInfo to owner+`0x2e8` |
| High | Successful close lookup | Reuse the independently established lookup contract with original close entry and follow source unlink/retirement under explicit object premises |
| High | Metadata format and consumer | Prove the full index/base/extent predicates and follow original metadata-byte reads into the next local interface; no complete crypto result is established here |
| Medium | Registry synchronization | Recover reference acquisition, exclusion and concurrent close/page lifetime before assigning native ownership guarantees |
| Medium | Warm/cold state consistency | Join startup writers and node construction; flag1/private-list executions are not native initialization evidence |
| Low | Error-code provenance | Identify original shared status definitions or complete caller normalization before assigning symbolic meanings |

- QG1: Factual binary/ABI analysis; no normative conclusion required.
- QG2: PC1-PC8 identify premises, dependent claims and falsification probes.
- QG3: Page marshalling, dispatch, linked lookup, child/offset/record gates, mapped-address prefix and validation are covered. Full interface goal remains incomplete.
- QG4: Byte extents, u32/u64 arithmetic, 4096-byte alignment, 44-bit bound, finite stride claim and complexity are explicit; five proofs and independent replay pass.
- QG5: Cold/warm premises, NULL/miss/hit/tail cases, invalid offsets, record branches, owner flag and finite arithmetic scope are distinguished. No native success follows from a frontier.
- QG6: Original bytes/fixups, source-produced records, solver obligations and separate CPU/argument oracles support the scoped claims. Models/native unknowns remain explicit.
- QG7: Impact-labeled continuation remains bounded to publication, close, metadata, synchronization and startup interfaces.
