# Collection retirement, outer owner cleanup and status/output joins

> Composition correction: the earlier prose treated the heap value loaded from frame+0x3950 as the pointer-cell address forwarded unchanged to cleanup. At0x10097a0dc/0x10097a0e0, X8 becomes &frame[0x6520]. Cleanup reads the original builder through this local cell. The corrected source join and a rejected preservation interpretation are recorded in the [builder-owner report](daemon_builder_owner_join_report.md) and its machine-readable erratum. Historical local-query JSON is preserved.

The helper beginning at `0x1006e3d4c` supplies a private constant interface to a collection drain at `0x1005134ec`. For a nonnull pointer cell containing a nonnull collection, the source saves each node's next pointer, conditionally releases its buffer, releases the node, and eventually releases the container and clears the supplied pointer cell. The selected calls resolve to original `_free` under the documented byte-bank roots. These are conditional source effects; actual native ownership, allocator behavior and hardware authentication are unknown. [CR1-CR5]

The outer finish at `0x10090a400` is shared by success and non-success. Success publishes heap builder pointer H loaded from K+0x3950. Non-success first saves H at K+0x6520 and forwards PTR=&K[0x6520] to cleanup. Non-success enters a wrapper that, under compatible phases and an exclusively owned object graph, drains child pointer cells at O+8 and O+0, releases O, clears the supplied pointer cell and saved pointer scratch, then publishes a null result with the original low 32 status. This is whole-owner retirement, not restoration of preexisting records. Whether the earlier descriptor constructors own these same physical objects remains unknown. [CR2-CR6]

The frozen successful profiles separately establish temporary-collection disposal: twelve episodes, each containing two buffer frees, two node frees and one container free. Their actual caller is `0x100902518`, using a frame pointer cell at K+0x1c10. They do not take the new outer-disposal or generic-constructor-error caller paths. A positive occurrence of a shared finish/output block cannot be used to label its error branch as observed. [CR7]

Evidence: [source, original fixups/banks and frozen lifetimes](triage_evidence/daemon_collection_retirement_source.json), [source certificate and alteration checks](triage_evidence/daemon_collection_retirement_checks.json), [extractor](triage_evidence/recover_daemon_collection_retirement.py), [validator](triage_evidence/validate_daemon_collection_retirement.py), [preservation](triage_evidence/daemon_collection_retirement_delivery.json), [scoped gates](triage_evidence/daemon_collection_retirement_quality_gates.json). Adjacent contracts: [descriptor callers](daemon_constructor_callers_report.md), [lookup/replacement](daemon_constructor_lookup_report.md), [candidate failure cleanup](daemon_constructor_failure_report.md), [bank origins](daemon_constructor_bank_origins_report.md). Reference data sufficed; no additional IDA access/mutation, target execution, new emulation, native API or IPC operation occurred.

| Evidence | Scope |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Original source capture | 31 fragments, 518 instructions, 2072 B |
| Exact-once SSA coverage | All 483 instructions other than terminal BRAAs and four BLRAA calls; 451 SSA definitions |
| Source certificate | 35 UNSAT component queries; ten rejected alterations |
| Pointers and branches | 39 independently decoded original pointer records; 31 terminal branches; 45 selected slot/modifier matches |
| Allocator selection | Four call sites; 1024 exhaustive byte-bank cases |
| Preservation | Three local register-liveness intervals; 44 prior ranges/3700 B recaptured |
| Frozen private evidence | 12 drain episodes; 24 buffers, 24 nodes and 12 containers retired by the private model; 3408 B total allocation extents |
| Unobserved caller paths | Zero outer-disposal entries and zero generic constructor error entries in that corpus |

Addresses, frame offsets, selectors and constants are hexadecimal. Extents use B. K denotes the shared frame, CELL a supplied pointer-cell address, C its collection pointer, N a node, B its record buffer, and NEXT the saved next pointer. H is the heap builder value loaded by the outer finish; PTR=&K[0x6520] is the cleanup wrapper's local pointer-cell address, and O=*PTR=H its object, OUT its separate result-cell address, and CONT a saved code pointer. Widths and zero extension are explicit; arithmetic is modular at u32/u64 width. These names are analytical roles, not public Apple declarations or IDB renames.

## Drain control and lifetime contract [CR1-CR5]

```text
CELL / continuation selector / compatible phase and bank roots
                           |
                    save continuation
                           |
                 CELL == 0? ----yes----> return
                           |
                           no
                           v
                    C = *CELL
                 C == 0? -------yes----> return
                           |
                           no
                           v
                       N = C.head
                           |
                 +---- N == 0? ----yes----> free(C)
                 |         |                 |
                 |         no             *CELL = 0
                 |         v                 |
                 |    NEXT = N.next          v
                 |    B = N.buffer         return
                 |         |
                 |    B != 0? -> free(B); N.buffer = 0
                 |         |
                 |       free(N)
                 |       N = NEXT
                 +---------+
```

Under readable, stable, finite acyclic and exclusively owned list premises, the analytical behavior is:

```text
save CONT selected by incoming W8
if CELL != 0:
    C = *CELL
    if C != 0:
        N = C.head
        while N != 0:
            NEXT = N.next
            B = N.buffer
            if B != 0:
                free(B)
                N.buffer = 0
            free(N)
            N = NEXT
        free(C)
        *CELL = 0
transfer through CONT
```

This is source interpretation, not runnable target code. The unknown/native allocator effects and call-return contract are separate premises. In particular, the helper does not preserve incoming X6 as a status result: setup explicitly stages W6=0x10ed8, and allocator calls can change caller-saved registers. Callers that need an earlier status save it independently.

| Stage | Exact fields and branch contract |
| --- | --- |
| Setup `0x1006e3d4c` | W24=0x6cf4 and core phase [K+0x9d0]=0x6cf4 produce selector0x8f82 ->0x1005134ec; incoming W8 remains the caller-continuation selector; X19=CELL |
| Entry `0x1005134ec` | Resolves W8 through the original table and saves CONT/u64 at K+0x43c0 before the CELL guard; CELL!=0 selects0xbdb4 ->0x1005b611c; CELL==0 selects0xbdb7 ->0x1004bd39c |
| Container gate `0x1005b611c` | Reads C/u64 at CELL; C!=0 selects0xb545 ->0x1005cbf14; C==0 selects0xb57d ->0x1004bd39c |
| Head gate `0x1005cbf14` | Reads N/u64 at C+0; saves phase/u32 at K+0x9b8; N!=0 selects0x645c ->0x1005250f4; N==0 selects0x6452 ->0x1004d7534 |
| Node stage `0x1005250f4` | Reads NEXT/u64 at N+0 into X25, then B/u64 at N+0x18 into X0; B!=0 selects0x6e20 ->0x1007cf698; B==0 selects0x6e13 ->0x1005faf58 |
| Buffer call/post-call | `_free(B)` at0x1007cf700; after normal return, stores zero/u64 at N+0x18 and selects0x1005faf58 |
| Node call/post-call | `_free(N)` at0x1005fafc4; saved NEXT becomes X21. NEXT!=0 selects0x1005250f4; NEXT==0 selects0x1004d7534 |
| Container call/post-call | `_free(C)` at0x1004d7588; after normal return, writes zero/u64 to CELL, reloads CONT from K+0x43c0 and selects0x1004bd39c |
| Return `0x1004bd39c` | Transfers through X8=CONT with IA modifier0xe0d4; no public status meaning is assigned |

NULL CELL skips the CELL read after the required frame/table/continuation accesses. Nonnull CELL containing NULL C returns without writing the already-null cell. A nonnull container with NULL head is still released and its pointer cell cleared. A node with NULL buffer is still released. These differ from candidate-failure cleanup, which reads a node field before its buffer-null predicate and does not establish NULL-node admission.

The source uses each node's +0 next link; it does not need node.prev, node.extent, header decoding or container.tail for traversal. It saves NEXT before buffer/node retirement. No C.head progress store occurs in the captured drain; the original head/tail can remain stale until C itself is freed. The source therefore does not establish concurrent observation, reentrancy, synchronization or validity of external aliases during retirement. Tail/link consistency remains an owner premise rather than a traversal check.

## Four original allocator selectors [CR1-CR4]

Let c0 and c1 be arbitrary u32 words loaded through controller pointers at K+0x9c8 and K+0x9c0. Each selector computes a controller word J, reads left[u8(J)] and then right[left-byte XOR key], XORs the latter with J, takes the low byte and adds the tabulated constant. The concrete original arrays establish the resulting byte for every input i=0..255.

| Released owner / call site | Controller J/u32 | Left/right frame roots | Key | Collapsed byte | Addend | Selected index |
| --- | --- | --- | --- | --- | --- | --- |
| B / 0x1007cf700 | ((c1-c0) XOR0xa6)*0x0a5cd4cf | +0x9b0/+0x9a8 | 0xe4 | 0x5d | 0xcbab | 0xcc08 |
| N / 0x1005fafc4 | ((c0 XOR c1) XOR0xa6)*0x0a5cd4cf | +0x5f0/+0x5e0 | 0x9a | 0xe5 | 0xcb23 | 0xcc08 |
| C / 0x1004d7588 | ((c0 XOR c1) XOR0xa6)*0x0a5cd4cf | +0x9b0/+0x9a8 | 0xf3 | 0x43 | 0xcbc5 | 0xcc08 |
| O / 0x100580884 | ((c1+c0) XOR0xa6)*0x0a5cd4cf | +0x968/+0x960 | 0xbb | 0xbb | 0xcb4d | 0xcc08 |

The corresponding original array roots are A=(0x100fc4230,0x101031fa0), C=(0x101031da0,0x100e99900) and B=(0x100fc4130,0x101031ea0), respectively. The outer object uses B; node retirement uses C; buffer/container retirement uses A with different keys/addends. The 1024 finite bank cases establish `i XOR right[left[i] XOR key]=collapsed_byte`; source queries independently establish actual controller-word addresses, byte addresses, frame root loads, selected table slot, call argument and modifier. Register/lifetime premises are not replaced by the finite numeric enumeration.

All four resolve to original slot0x10109ff30, `_free`, total addend zero, IA diversity0x46a2 and address diversity zero. Original chained records and a fresh original fixup catalog support this binding. An original authenticated binding and matching modifier are static metadata; hardware authentication, live table/root values, actual frees and allocator side effects remain unknown.

## Outer finish and two-child owner retirement [CR2-CR6]

At `0x10090a400`, incoming phase W21=0x6cf4 and arbitrary raw X6 produce:

| Condition / action | Source consequence |
| --- | --- |
| All statuses | Save low 32 W6 at K+0x3c64; load H/u64 from K+0x3950 |
| W6==0x8b3dc651 | Index0x785b ->0x100966d9c, supplying X8=H, W10=success and W9=0x6f33 |
| Other W6 | Index0x7863 ->0x10097a0c4, entering disposal |

This finish is also a continuation of the u32 typed adapter in the frozen corpus. The descriptor array's first/second non-success returns can reach it, but do not define its complete incoming-call set.

Disposal saves H at K+0x6520, changes X8 to PTR=&K[0x6520], saves that address at K+0x4a68, and stores raw private marker0x8f8d9650 at K+0x36c4. The next stages save PTR at K+0x5120, guard PTR before reading O=*PTR=H, and save O at K+0x77b8. The local cell address is not H. The callee also has general NULL-PTR/NULL-O skip branches; the selected source join supplies the frame-local cell, subject to frame validity.

For nonnull PTR/O under the owner premises, the exact source hierarchy is:

```text
PTR = &K[0x6520], also saved at K+0x5120
 |
 +-- *PTR = O = H  (saved at K+0x77b8)
             |
             +-- [O+8] = child collection pointer
             |      drain CELL=O+8, continuation selector0xb68
             |
             +-- [O+0] = child collection pointer
                    drain CELL=O+0, continuation selector0xb9f
             |
             +-- free(O)
                    |
                    +-- *PTR = 0
```

`0x10083dd58` supplies X19=O+8, W24=0x6cf4 and W8=0xb68 to the drain setup. After that normal return, `0x1004c61ec` reloads O and uses the re-staged W3/W4 constants to select0x10058bca4. This second entry supplies X19=O, preserves return selector0xb9f and reuses the drain constant interface. After the second normal return, `0x10058081c` releases saved O. Its normal post-call path selects `0x100543b94` to write *PTR=0 when PTR is nonnull. Compatible source return selectors map0xb68 ->0x1004c61ec and0xb9f ->0x10058081c, both IA0xe0d4.

The final container-free path explicitly re-stages private constants W0..W7, W14..W16, W21 and W23. In particular, W3=0xffff9eab, W4=0x6ad4, W14=0x50c0 and W15=0x228e support the second drain join. These are source writes, not an assumption that an ordinary allocator preserves caller-saved W3/W4. Other required callee-saved registers and SP still require the normal allocator-call premise. NULL-cell/null-container early paths preserve the corresponding initially staged constants.

This wrapper's source view has two child pointer cells. It must not be equated with the constructor's head/tail container or the descriptor's 40 B record merely because offsets+0/+8 recur. The [builder-owner report](daemon_builder_owner_join_report.md) now establishes the selected source join from the 128 B builder producer and its two 16 B child containers to these same child-cell offsets. Native physical ownership and unmodeled intervening reaching definitions remain unknown. Conditional on those constructors having committed into these exclusively owned child collections, disposal retires those commits along with the graph; it does not restore the graph's prior contents. No transactional rollback, global alias invalidation or native failure behavior is established.

## Output publication and status width [CR2-CR6]

With the setup marker0x8f8d9650 preserved in the frame, the signed marker dispatcher selects0x100708ef8 ->0x10075a47c ->0x100706894 ->0x10078cd00. The certificate proves all-u32 marker predicates for those captured stages, then composes only the setup marker through the nil leaf. Alternate marker workflows are not claimed complete.

The nil leaf clears K+0x3950/u64, sets X8=0 and loads saved W10/u32 from K+0x3c64. Shared output stage `0x100966d9c` performs:

| Operand / effect | Exact private source contract |
| --- | --- |
| OUT | Loaded/u64 from K+0x7700; must be writable for the final 8 B store |
| Result pointer | Stores X8/u64 at OUT; H on exact success, zero after disposal |
| Saved continuation | Loaded/u64 from K+0x86d8 into X20 |
| Status | X6=X10; X10 is zero-extended saved W10 on the failure route, or zero-extended success on success |
| Final transfer | Index0x6f33 ->0x100755bc0, then BRAA X20 with IA0x2cca |

Therefore this outer failure interface returns `zero_extend64(low 32(original X6))`, even though the inner descriptor walker preserved the full incoming X6. The width difference is explicit and source-proved. Raw public error names, public calling convention and native continuation identity remain unknown.

A separate generic constructor error path at `0x1008f045c` saves low 32 status at K+0x850c and copies C from K+0x2ff8 to a local pointer cell at K+0x1548. It calls the same drain with return selector0xb9e ->0x1005271b0. That return clears K+0x2ff8 and restores W6/u32. Shared output block0x100758ae8 writes the saved collection pointer to OUT=[K+0x7068]; under this error clear it writes zero. Transfer0x1008c8b80 reloads CONT from K+0x5ff0 and branches with IA0xfc72. Its positive frozen occurrence comes from a different predecessor and does not establish this error path as observed.

## Frozen successful-finish and temporary-drain evidence [CR7]

Each retained profile reaches the outer finish from `0x100781e0c` and selects the success target0x100966d9c. None enters0x10097a0c4,0x10058081c or0x1008f045c. The same profile later has a drain episode entered by `0x100902518`; its source supplies CELL=K+0x1c10, phase0x6cf4 and continuation selector0xb70 ->0x10081bf90. It saves its earlier low 32 status at K+0x6c88, independently of drain X6 scratch. This caller is distinct from the two new failure callers.

All twelve episodes have the sequence buffer0,node0,buffer1,node1,container. Each free argument matches an earlier recorded malloc result and extent. The retired node/buffer pairs are the fourth and fifth constructor allocations in each corresponding recorded allocation sequence; the container originates at allocator return0x10069985c. This identifies specific frozen owners without assuming that every constructor belongs to the same collection. The two node allocations are 32 B each; the container is 16 B; buffer0 is 14 B; buffer1 varies with the profile. These are frozen private allocation extents, not incoming constructor-register snapshots or native allocator measurements.

| Profiles | Count | Buffer1 extent / B | Total retired per profile / B | Group total / B |
| --- | ---: | ---: | ---: | ---: |
| default,count0,count1,count57,countmax,opaque0,opaquemax | 7 | 122 | 14+32+122+32+16=216 | 1512 |
| path_empty,path_one | 2 | 74 | 14+32+74+32+16=168 | 336 |
| path15,path16 | 2 | 90 | 14+32+90+32+16=184 | 368 |
| path1023 | 1 | 1098 | 14+32+1098+32+16=1192 | 1192 |
| Total | 12 | Variable | Variable | 3408 |

At each node free, its known-byte mask confirms the saved next/previous links and a zero 8 B buffer pointer. The first node's next points to the second; the second node's next is zero; previous links are consistent. At container free, its 16 known bytes still contain the original head and tail pointers. Four node bytes at offsets0x14..0x17 remain unknown in these records; no initialized padding/type meaning is assigned. This frozen snapshot is consistent with the source's lack of head/tail updates during drain and with buffer clearing before node release.

The private `_free` records identify their model as lifetime retirement only. PAC authentication was bypassed. Consequently these observations establish the retained model's event order, arguments and bytes, not native deallocation, authentic ownership, hardware PAC acceptance, a successful live IPC transaction or a kernel peer. No generator, CPU emulation or native transaction was rerun.

## Complexity and conditional memory footprint [CR3-CR5]

For n nodes in a finite acyclic collection, the drain performs O(n) source control work, O(1) scalar auxiliary storage, exactly n node-release calls, b buffer-release calls where 0<=b<=n, and one container-release call. Total allocator-call count is n+b+1 when C is nonnull; NULL CELL/C produces none. Allocator internal complexity is unknown. The source performs no payload-length-dependent copying during retirement. Its traversal reads 8 B at C+0, then 8 B at each N+0 and N+0x18; byte-bank/controller/frame accesses are additional fixed work per call. Buffer release adds an 8 B zero store at N+0x18; final container release adds an 8 B zero store at CELL. These are explicit source accesses, not complete allocator side effects.

For the outer object with two disjoint child collections of n0 and n1 nodes, control work is O(n0+n1), scalar auxiliary storage is O(1), and one additional object-release call occurs after both child drains. Premises include readable/writable pointer cells, valid allocation bases, disjoint node/buffer/container/object/frame owners, stable next links, normal allocator returns and no concurrent mutation. A finite-node rank decreases by one per completed iteration only under these premises. Cycles, shared owners, invalid allocation pointers, intervening writes and interrupted calls have no established complete behavior here.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Static stress test or falsification probe |
| --- | --- | --- |
| CR1 | Bytes, chained pointers and arrays belong to the pinned thin image. All source roles depend on build identity. | Rehash the original image; recapture all fragments and original pointer words; compare a fresh fixup catalog. Reject cross-build substitutions. |
| CR2 | Compatible core/entry phases, original table roots and saved continuation epochs are supplied. Private ABI joins depend on these conditions. | Trace producers of each phase/selector/frame cell; compare source-selected slots and original IA metadata. Equal modifiers alone do not identify a target. |
| CR3 | CELL/PTR/OUT and conditionally accessed fields are valid for the stated widths/lifetimes. Memory effects depend on these owner premises. | Recover original allocations, stores and last uses; prove full conditional read/write footprints, nonwrapping addresses and frame/heap separation. A nonnull pointer is insufficient. |
| CR4 | Lists are finite, acyclic and exclusively owned; child/object/container/node/buffer allocations are disjoint with valid release bases. Whole-graph disposal and termination depend on this condition. | Establish constructor-to-owner reaching definitions and list invariants; examine aliases/shared references. Repeated offsets+0/+8 are not a type or ownership proof. |
| CR5 | Each selected `_free` call returns normally and preserves the required callee-saved registers and SP; bank roots contain the captured original arrays. Post-call joins depend on these premises. | Check exact source call argument, byte addresses and exhaustive bank relation; check local register liveness and restored custom constants. Native allocator/PAC effects remain untested. |
| CR6 | Saved marker/status and result/continuation cells retain their source-defined values across calls under disjoint stable ownership. Nil-result/u32-return composition depends on this premise. | Trace all reaching stores to36c4/3c64/3950/7700/86d8 and850c/2ff8/7068/5ff0, including unknown callees and aliases. The inner full-X6 return does not imply an outer full-X6 return. |
| CR7 | The frozen private corpus retains its recorded source identity, event order, free arguments and known-byte masks. Occurrence/lifetime counts are corpus-bound. | Rehash profiles, partition actual drain entry-to-return episodes, match frees to recorded allocations, and distinguish shared success/output occurrences from unobserved error callers. No native relabeling is permitted. |
| CR8 | Public status names, real Mach rights/peers, successful native selector26/RPC502/700 pairing and actual constructor-to-disposal owner aliases remain unknown. | Require same-build source/owner/endpoint provenance before composing those interfaces. The failed UserClient-open capture supplies no successful connection or native pairing. |

## Bounded continuation opportunities

| Impact | Further static work | Question resolved |
| --- | --- | --- |
| High | Recover producers and aliases of PTR at K+0x3950 and O's two child fields; join descriptor constructor owners to this exact graph. | Which earlier commits are retired on failure, and the actual scope of ownership transfer. |
| High | Trace OUT/CONT producers for both outer and generic paths through their callers. | Public-facing result/status shape and where this private object lifecycle reaches serialized IPC state. |
| High | Establish same-frame initializer-to-consumer reaching definitions and native endpoint/image identity. | Remaining owner/phase/root/PAC assumptions and daemon-kext selector26/RPC502/700 pairing. |
| Medium | Follow observed post-drain0x10081bf90 and the K+0x6c88 status save to its final restore. | Subsequent temporary-buffer disposal, error preservation and source-to-IPC publication ordering. |
| Medium | Recover alternate private-marker branches beyond the default disposal marker. | Additional wrapper cleanup/output cases without treating shared block occurrences as branch evidence. |
| Low | Use distinct analytical names for common finish, candidate cleanup, collection drain and two-child wrapper retirement. | Prevent conflating different owners and return widths during subsequent annotations. |

## Scoped quality gates

- QG1: The increment reports technical source, ABI and frozen lifetime evidence; no normative conclusion is required.
- QG2: CR1-CR8 enumerate assumptions, dependencies and falsification probes.
- QG3: The increment covers complete selected drain branches, four allocator selectors, two-child wrapper/default failure publication, generic error publication, saved status widths and distinct frozen caller evidence. The full investigation remains active.
- QG4: All widths, modular domains, address/offset notation, B extents, zero extension, explicit accesses and conditional complexity bounds are stated. Frozen total 3408 B is reproducible from the table.
- QG5: All 483 nonbranch/noncall source instructions are translated exactly once;31 terminal branches/four calls are separately checked. The earlier inter-block X8 prose composition was incorrect despite those local checks; it is corrected by the explicitly linked source-join erratum. Shared finish/output blocks are distinguished from error-only paths; literal metadata compatibility is distinguished from hardware authentication. Unknown node bytes and physical owner joins remain explicit.
- QG6: Original bytes,39 independently decoded pointer records,a fresh fixup catalog,1024 original bank cases,35 UNSAT queries,ten rejected alterations and retained private lifetime records provide scoped provenance. No new target execution or native transaction is claimed.
- QG7: Continuations are bounded and impact-labeled above. Native ownership,public ABI/peer identity and complete goal coverage remain unknown; scoped passing gates do not imply full-goal completion.
