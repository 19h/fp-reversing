# List-sized output allocation, byte transformation and trailing record

The component at 0x1006bc13c, under compatible continuation phase0x1593, measures a linked list, allocates an output size divisible by16 B, transfers node bytes through an address-dependent XOR operation, appends a 10 B record and zero padding, then publishes an8 B pointer and4 B encoded length. The original allocator call is `_malloc` at0x1006c318c. This supplies a conditional allocation origin for the previously recovered frame+0x8378/frame+0x1210 output pair. The actual incoming phase producer, source-encoding inverse, native ownership/return and daemon/kext exchange remain unproved. [LS1-LS7]

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are unslid VAs; offsets/constants are hexadecimal; byte counts are decimal. Evidence: [original source, pointers and phase census](triage_evidence/daemon_list_output_source.json), [complete static certificates](triage_evidence/daemon_list_output_checks.json), [fresh read-only IDA capture](triage_evidence/daemon_list_output_ida.json), [preservation](triage_evidence/daemon_list_output_delivery.json), [quality gates](triage_evidence/daemon_list_output_quality_gates.json).

## Conditional entry, data structures and returns

K is the shared-core frame SP. The caller at0x100847960 supplies X21=u64[K+0x1c10], X19=&u32[K+0x1210] and X8=&u64[K+0x8378]. Its phase-dependent table expression is `(W22 XOR0x5ddc)+(W22+0x23b2)` modulo2^32. Phase0x1593 selects index0x8194 ->0x1006bc13c, IA diversity0x6e32. [LS2,LS3]

The phase result is a constrained source inference. All23 original IA/ad0 continuation fixups with diversity0x5677 are checked against the caller edge and both initial pointer-gate bindings. Exactly phase0x1593 satisfies that combination. This does not prove that the earlier caller actually produces this phase, or that hardware PAC succeeds. The saved continuation is table[0x1593], slot0x101044b88 ->0x10090f880, diversity0x5677. [LS1,LS2]

| Interface | Source-established representation |
| --- | --- |
| Container X21 | Its first8 B hold a head pointer; other container fields unknown |
| Node+0 | Next pointer,8 B |
| Node+0x10 | Plain unsigned byte extent n,4 B |
| Node+0x18 | Source-byte pointer,8 B; read on the nonzero-node branch |
| Saved output address | X8 saved in K+0x8860; caller supplies &K+0x8378 |
| Encoded output extent | Published through X19; caller supplies &K+0x1210 |
| Return channels | W10 Boolean result and W6 raw u32 status; pointer/extent travel through memory |

A general node needs at least32 B for these accesses. This is a consumer-side projection, not a canonical Apple type declaration or proof that a previously observed node allocation is this exact object. [LS3-LS5]

```text
caller phase0x1593
  -> container pointer gate
     NULL -> W10=0, raw74c29d88 -> saved continuation
     present -> walk node+0, sum node+0x10 with carry check
       -> compute padding/extent gate
       -> malloc(L), save D at K+0x5af8
          NULL -> W10=0, raw74c29d85 -> saved continuation
          present -> second list pass
            -> reverse byte transfer within each nonzero node
            -> advance cumulative offset; follow next node
            -> append10 B record and P zero bytes
            -> publish D and encoded L
            -> W10=1, raw8b3dc651 -> saved continuation
```

Carry or extent rejection returns W10=0 with raw0x74c29d8f. A NULL container and a non-NULL container with a NULL head have different paths: the latter has total T=0 and reaches a16 B allocation under normal allocation return. Failure branches return before this component writes its borrowed output cells. These are source contracts, not native failures or successful allocations. [LS2-LS5]

## Size arithmetic and allocation ABI

The first pass reads each n as u32 and uses CMN at0x1006875d4 before adding it at0x1008fdb08. The continuation at0x1008fdb0c loads the next pointer. The guard permits the addition exactly when the mathematical u64 sum fits u32; it therefore prevents u32 accumulation wrap under a stable finite list. Let T be the accepted total. [LS3,LS4]

```text
P = 16 - ((T + 10) & 15)       P in {1,...,16} B
L = T + 10 + P                mathematical size in B
admit iff T + P < 0xfffffff6
      iff T <= 0xffffffe5
```

For admitted T, `16 <= L <= 4,294,967,280 B` (0xfffffff0), and L is divisible by16 B. The maximum admitted T is4,294,967,269 B (0xffffffe5). T=0 gives P=6 B/L=16 B; T=6 B gives P=16 B/L=32 B. The already-aligned T+10 case receives a full16 B zero tail. The original u32 arithmetic, the widened unsigned admission comparison and the final allocation argument are proved together for every u32 T. [LS3-LS5]

| Site | Established effect |
| --- | --- |
| 0x10082d364..0x10082d42c | Derive P, save P+0x081b1b9c in K+0x5024 and partition admission |
| 0x1006c3120 | Save encoded extent E=L XOR0x8b3dc651 in K+0x5308 |
| 0x1006c3170 | W0 := L; X0 receives its zero extension |
| 0x1006c318c | Call original slot0x10109ff58 / IA0x6aa4, libSystem `_malloc` |
| 0x1006c3194 | Save returned pointer D in K+0x5af8 |

With the inherited C-bank frame cuts, selection is checked for all256 inputs and against the original chained import. No allocator is executed. A normal, valid allocator result and preserved frame state are premises for the subsequent memory contract. [LS1,LS2,LS5]

## Byte transfer and complete layout under list/owner premises

The second pass skips data access for n=0. For n>0, the setup at0x10087bbbc establishes index i=n-1, source S=u64[node+0x18], and destination D+C+n-1, where C is the preceding cumulative extent. The byte component at0x1009c3d34 reads one byte at S+i and stores one byte at the current destination, then decrements the destination. The source counter decreases by1 and its auxiliary shifted-address value by8. Index zero selects the node-completion edge; other indices repeat. [LS3-LS6]

The proved value contract is `stored_byte = input_byte XOR m(S,i)`, where m is the exact zero-input-byte SSA expression in the checks artifact. The mask is independent of the input byte. Finite mathematical valuations with input byte0 give:

| S | i | Output byte |
| --- | --- | --- |
| 0x10001000 | 0 | 0xa1 |
| 0x10001000 | 1 | 0xe3 |
| 0x10001008 | 0 | 0x35 |

These are symbolic-expression valuations, not mapped buffers or executed guest/native instructions. They refute a plain-copy interpretation. The producer-side encoding, its inverse relationship to this transform and any plaintext/cryptographic interpretation are unknown. A compact closed form for m remains a continuation target; its full source-derived bit-vector expression is retained. [LS6]

After the last byte, 0x1006f8aa4 restores the node-level control state and reloads n. Block0x1009019f8 advances C by n and loads node+0. Induction on a finite stable acyclic list, combined with the proved n-byte reverse loop, gives adjacent destination intervals [D+C,D+C+n). The first-pass total then equals the second-pass count T. Valid, disjoint source/output owners are required for the read-value interpretation and frame/nonwrapping premises for actual accesses. The proofs do not establish those native ownership or stability facts. [LS3-LS5]

The resulting conditional layout is:

```text
D+0                         transformed node bytes, total T B
D+T       +0..+3            00 00 00 00
          +4..+5            50 DB
          +6..+9            BE32(P)
D+T+10                      P zero bytes
D+L                         end of allocation
```

All ten stores at0x1009178e4 and the padding iteration at0x1006d6a30 are checked at their exact byte addresses. The trailing record follows the body. Its tag's application-level meaning and the corresponding receiver are unknown. The header-address theorem requires the admitted T bound; unrestricted u32 totals can wrap intermediate offsets and are not covered by that theorem. [LS3-LS6]

## Output handoff, parent continuation and external boundary

At0x10068f638, the helper stores D through the address saved at K+0x8860. At0x10068f644 it writes u32[K+0x5308] through X19. It restores the saved continuation, assigns W10=1 and W6=0x8b3dc651, then returns through0x10066efc4. Under core tag0x6cf4, the continuation0x10090f880 selects parent publication0x1007518a4 on success; failure selects0x100902518, whose further behavior is not recovered here. [LS2,LS3,LS7]

The [preceding output report](daemon_output_publication_report.md) establishes the subsequent K+0x8378/K+0x1210 -> K+0x70c8/K+0x3928 component, then the borrowed output pair with decoded L. These source joins retain their frame/cell-preservation premises. The [XPC bridge](daemon_xpc_core_bridge_report.md) and [reply lifecycle](daemon_xpc_reply_lifecycle_report.md) supply later data setter0x100bd6a5c, send0x100bb4d08 and eventual output free. Continuous caller reachability, unique lifetime and the adapter delta-zero join remain unproved. [LS7]

No new Mach port, descriptor, message emission or native FairPlay exchange is observed. This increment establishes an internal allocation/representation interface that can feed the existing conditional reply contract.

## Read-only IDA comparison and validation

Because reference data did not establish the nested target's prior annotations, the loaded fairplayd database `6b117c693e3b` was queried read only. Two ranges,56 B and112 B, match all168 original bytes. IDA treats the queried blocks as separate fragments; these bounds do not establish complete semantic-function boundaries. No useful prior semantic name was supplied. No database edit, save or target execution occurred. [LS8]

Nineteen ranges retain814 A64 instructions/3256 B. The checks recapture59 earlier ranges over5020 B, verify30 original edges and45 pointer records against all61737 fixup memberships, and pass31 explicit instruction assertions. Nine complete SMT obligations cover size/allocation, trailing record, padding, sum carry, compatible phase/parent control, output bytes, the byte transform, node-copy control and entry/list/padding initialization. The translations contain820 source-site instances/667 unique sites and786 SSA definitions. Thirty-seven size cases,16 padding counts/136 iterations, six sum boundaries, three byte valuations and eight altered-evidence rejections pass.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_list_output.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_list_output.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/seal_daemon_list_output.py
```

The IDA file is a retained live read-only capture; offline commands verify it, not regenerate it. Capture/check complexity is O(image+fixups+captured/prior bytes). Under the declared finite-list contract, the component's work is O(node count+T+P) with one L-byte allocation and O(1) auxiliary traversal state. SMT resources are additional. All widths and modular operations are explicit; byte output fields use the indicated big-endian order.

## Assumption register

| ID | Premise | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LS1 | Pinned original image/fixups and source captures are authoritative | Sites, widths, pointer bindings and scalar translations | Rehash and recapture; compare fresh fixup catalog and selected raw words |
| LS2 | Caller phase0x1593, core tag0x6cf4, original table epoch and inherited C-bank frame cuts apply | Nested helper, malloc selection and parent-return control | Recover actual W22/field producers and intervening writers; repeat all23 continuation constraints; metadata compatibility does not execute PAC |
| LS3 | Frame/node/source/output owners are valid, correctly sized, distinct where required and nonwrapping | Actual access effects and full layout application | Establish owner roots, aliases and extents; retain admission bound in header proof |
| LS4 | The list is finite, acyclic and stable across measurement and transfer | T equality, termination and adjacent output intervals | Establish producer ownership/synchronization and all next/size/data writers; separate passes alone do not prove stability |
| LS5 | Malloc returns normally under the inherited scalar ABI and a non-NULL D owns L writable bytes disjoint from live inputs | Allocation-backed writes and publication | Observe actual allocator/lifetime before native claims; test failures only as source branches here |
| LS6 | The proved XOR transfer is a representation contract; producer inverse and application-level meaning are unknown | Limits on plaintext, tag/padding semantics and byte interpretation | Recover source-buffer writers and an actual matching receiver; do not replace the transfer with memcpy |
| LS7 | Saved output/frame/status cells survive subsequent helper/core returns; XPC same-cell use additionally requires delta zero | Later output forwarding, copying and freeing | Recover continuous caller/return path, budget write history and actual before/after SP; native guards/PAC remain unobserved |
| LS8 | Fresh IDA capture attests only two ranges and fragment metadata | Corroboration of168 B and bound cautions | Compare raw ranges with original bytes; require complete compiler/control evidence for whole-function claims |

## Bounded continuation targets

| Impact | Evidence target | Uncertainty resolved |
| --- | --- | --- |
| High | Actual W22 producer at0x100847960 | Whether the phase1593 component occurs on the parent path |
| High | Source-buffer writes corresponding to m(S,i) | Producer-side inverse and meaningful payload bytes |
| High | Container/list ownership, mutation and synchronization | Native validity of the two-pass stable-list premise |
| High | Full parent/core return and adapter budget history | End-to-end output identity and delta-zero XPC join |
| High | Native selector26/RPC502/700 pairing | Actual daemon/kext port/right identity and exchange |
| Medium | Receiver for the trailing zero-identifier/0x50db record | Its application-level purpose and acceptance rules |
| Medium | Compact mask expression from the retained SSA | Human-readable representation semantics beyond the exact certificate |

QG1: Pass; factual source/interface analysis.
QG2: Pass; LS1-LS8 state assumptions, dependent results and falsification probes.
QG3: Pass for this increment; allocation, representation, control/return and later reply touchpoints are reported. The full interface goal remains active and incomplete.
QG4: Pass; byte widths, modular/carry rules, admitted extents, endian order, loop invariants and complexity are explicit.
QG5: Pass within scope; compatible phase versus actual producer, stable-list induction versus native ownership, XOR transfer versus plaintext, admitted header offsets versus unrestricted u32 values, and local allocation versus IPC remain distinct.
QG6: Pass; original bytes/fixups, fresh IDA readback, explicit translations and complete solver queries provide provenance.
QG7: Pass; unresolved architectural joins and bounded continuation targets are impact-labeled above.
