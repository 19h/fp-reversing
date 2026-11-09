# Digest-context overwrite, decoded output copy and completion marker

The post-serialization source overwrites context bytes 0..91 with an address-dependent pattern, preserves the size/selector fields at +0x5C/+0x60, and copies the serialized output backwards into a separately saved destination while XORing each byte with 0x98. It then subtracts 32 bytes from the scratch cursor, restores four saved registers and stores byte 1 through a saved marker pointer. For the checked SHA-1 compositions, the destination receives canonical 20-byte digest values. Native same-frame continuity, the destination-to-cache join and driver IPC linkage remain unknown. The full daemon/kext/deeper-interface investigation remains active. [GC1-GC12]

This extends the [serializer/root report](daemon_digest_output_report.md). It does not resume the earlier unknown-frame frontiers. The new executor starts a separately declared phase at 0x100BB1620. A source proof shows that the preceding opaque-root copy prefix preserves the inputs needed by this phase; that independence does not supply the missing fields or establish a fault-free native path through their reads.

## Provenance and verified extent

| Evidence | Extent |
| --- | --- |
| Original daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Source contracts | 21 spans / 348 instructions; 253 distinct instructions observed in the new traces |
| Read-only current IDB | Target `6b117c693e3b`; 19 ranges / 1,404 bytes, raw identical; includes all source spans and 12 additional bytes |
| Branch metadata | 15 original authenticated fixups, checked against original words and import/rebase metadata |
| Source equations | 24 rebuilt UNSAT obligations; 48 original/normalized SMT artifacts; 329 lifted instructions |
| Complete declared phases | 140: 128 former serializer cases across two owner layouts, plus 12 conditional SHA-1 output compositions |
| Single overwrite iterations | 256 cases covering every low seed byte, varied upper seed bits and counts 1..92 |
| New source visits | 489,164 = 473,020 executed A64 instructions + 16,144 modeled BRAA visits |
| Ordered memory effects | 32,224 reads / 27,944 writes, independently checked |
| Output effects | 140 context overwrites, 1,392 decoded destination bytes and 140 marker-byte stores |
| Retained pointer audit | 288 unchanged short-path cases; 74,400 retained effects inspected, including 3,456 tracked reads and 1,728 tracked writes |

[Contracts and source spans](triage_evidence/daemon_digest_completion_contracts.json), [source proofs](triage_evidence/daemon_digest_completion_proofs.json), [new phase journals](triage_evidence/daemon_digest_completion_profiles.json), [reference equations](triage_evidence/daemon_digest_completion_model.py), [retained pointer audit](triage_evidence/daemon_digest_completion_inputs.py), [independent checks](triage_evidence/daemon_digest_completion_checks.json) and [IDB bytes](triage_evidence/daemon_digest_completion_ida_bytes.json) retain the evidence. [Preservation](triage_evidence/daemon_digest_completion_preservation.json) and [scoped gates](triage_evidence/daemon_digest_completion_quality_gates.json) seal this increment.

All offsets and constants below use hexadecimal 0x notation. Counts/extents are decimal bytes. F is the outer SP; C is the 100-byte context; O is the 32-byte encoded-output reservation; D is the separate 64-byte destination reservation in the retained layout. u32/u64 arithmetic wraps modulo 2^32/2^64. Valid owner bounds, nonoverlap and saved-cell preservation are explicit premises. No native fairplayd process, library call, Mach/IOKit operation, hardware PAC or IDB mutation executes.

## Phase entry and opaque-root boundary

The earlier serializer stops before 0x100BB15D0 reads F+0x3050. That prefix copies six opaque values into ten frame slots, including numeric aliases of the root. Its source instructions preserve SP, X2, X8, X9, X11, X13, X27, X30 and the six saved cells needed by the new phase. The proof gives every protected saved cell its own independent symbolic value. No root dereference occurs in that prefix.

The new phase declares these eight incoming registers, with the saved context/output/destination/cursor/marker and restore cells separately defined:

| Register | Entry contract at 0x100BB1620 |
| --- | --- |
| SP / X30 | F / table root 0x101039EF0 |
| W27 / W11 / W2 | 0x471C / 0x8204CE66 / 0x7E8C |
| X8 | 0x3705FAA50A75FA00 |
| W9 | 0xBB74A819 |
| X13 | Seed computed by 0x100BB1574..0x100BB15D0 from F and W27=0x471C |

The frozen serializer cases provide the same X8/W9/W27 values; the source seed equation is checked for every u64 F. The mode-derived first branch uses slot 0x101062FB8 -> 0x100A048D4, IA 0x8008. A048D4 adds 0xC8FA055AF58A065C to X8, producing exactly 92, moves the seed into X11 and reaches 0x100A1BF1C through slot 0x101079350, IA 0xB08B. These constants are internal phase/control inputs, not transport selectors.

At 0x100BB16B8, X6=load64(F+0x2A70) supplies overwrite owner C. The later size-bearing pointer C'=load64(F+0x3610) comes from a separate saved cell. All new completion fixtures declare C'=C. The retained audit establishes C' at the earlier frontier; the preceding finalizer/serializer contracts separately carry C into F+0x2A70 in their later phase. A continuous native equality/preservation chain is not established. The local copy/count equations do not require the overwrite owner and size-bearing owner to be identical.

## Address-dependent context overwrite

The loop at 0x100A1BF1C writes one byte at C+remaining-1, decrements the remaining count through F+0x2BA0 and increments its u64 seed. It visits context offsets 91,90,...,0. The source never reads the old bytes in this interval. Its live-input handover and original continue/exit cells are proved for every seed and remaining count 1..92, with nonempty domains checked.

The exact byte function is given below. `lo8` retains the least significant 8 bits; intermediate values may be reduced to 8 bits after each operation. The proof checks this reduced equation against the original 32-bit MBA with all upper input bits free.

```text
s = lo8(seed)
a = s XOR 0x7D
b = s AND 0x6E
c = ((s XOR 0x6D) AND (b << 1)) XOR b
d = (((a << 1) XOR 0x1C XOR 0x3A) AND a) XOR ((a << 1) AND 0x12)
e = d XOR 0x11
c = c XOR (d AND (c << 2))
c = c XOR ((0x40 XOR (e << 2)) AND (e AND (c << 4)))
byte = lo8((s XOR (c << 1) XOR 0xD4) * (s + 0x7F))
```

This is a deterministic overwrite pattern with period 256 in the seed argument. It is not a zero-fill contract, and no randomness, physical erasure or security guarantee is inferred. For F=0x6B00040000, the resulting first context bytes are `0c c0 9e 52 68 14 da 86`. Context bytes +0x5C..+0x63 remain unchanged. Thus the message buffer, counters and five encoded state words are overwritten; the output-size and selector words survive. Only the size word is subsequently read in the checked phase. O remains unchanged.

## Decoded output and scratch restoration

After the overwrite, a fixed-W9 dispatcher traverses ABD000, A21560, BDB0F0, B3FFB0, BABCE8 and BF7B18 before reaching B132F8. Six source obligations verify this exact constant-dependent route. No general meaning is assigned to other W9 values or their untraversed routes.

At 0x100B132FC, the source loads C' from F+0x3610, then reads N:u32 at C'+0x5C. The local proof covers every u32 N: the MBA produces `W13 = N XOR 0x6A2C85C3`; zero selects the restore path, nonzero selects 0x1009A33BC. The copy-entry XOR recovers exactly N into X11.

| Source site | Exact role |
| --- | --- |
| 0x1009A33BC | D=load64(F+0x32E8) |
| 0x1009A33C0 | O=load64(F+0x31A8) |
| 0x1009A33CC | Recover N from the encoded control value |
| 0x1009A2E90..0x1009A2EB4 | For j=N-1 down to 0: D[j]=O[j] XOR 0x98 |
| 0x100B56668..0x100B5666C | Load scratch cursor Q; form Q-32 |
| 0x100B56674..0x100B56680 | Restore X28/X23/X24/X26 from F+0x2A88/+0x2A90/+0x2978/+0x2988 |
| 0x100A53638 | Store Q-32 to F+0x3620 |
| 0x100A53640..0x100A53644 | Load marker pointer from F+0x26E0; store byte 1 |
| 0x100A53648 | Reload opaque u32 saved value from F+0x2EDC into W22 |
| 0x100B687F4 | Next frontier: undefined u64 read at F+0x3650, stopped before execution |

The copy-loop byte equation, address, decrement, branch and live-input handover are proved for every input byte and nonzero u32 count under valid-owner premises. The zero-size path does not read O or D or copy bytes; it still reaches cursor restoration and the marker store under the declared entry contract. This does not establish that an arbitrary native caller admits zero size or a NULL destination at that entry.

| Checked serializer result | Decoded destination bytes |
| --- | --- |
| Selector1 / size16 | LE32(H0)..LE32(H3); algorithm identity remains unknown |
| Selector2 / size20 | BE32(H0)..BE32(H4); SHA-1 identity follows the preceding core evidence |
| Either checked selector / size0 | No destination bytes written |

Twelve new completion phases take the actual encoded outputs saved by the preceding six core/serializer compositions, using two owner layouts. The resulting 20-byte values equal independent SHA-1 expectations for the three modeled messages: empty, ASCII `A` and U+00E9 encoded as UTF-8. The source-produced output values cross an explicit component boundary; the original core and serializer are not rerun or represented as one native call here.

## Retained saved-pointer provenance and geometry

All 288 retained short-path models preserve the following values. The audit checks frozen entry groups and every overlapping ordered read/write, including the source writers in BAFF6C. Their original frontier remains 0x100ABEE7C before F+0x2E50. Parent model premises, including declared CF outputs, remain applicable.

| Saved cell | Retained value / last relevant effect |
| --- | --- |
| F+0x3278 / F+0x2F00 | D=F+0x3C30; retained source prefix |
| F+0x32E8 | Same D; copied by 0x100BAFFB4 |
| F+0x3238 / F+0x3610 | C=F+0x3C70; latter written by 0x100BAFF90 |
| F+0x31A8 | O=F+0x3CE0; written by 0x100BAFFA4 |
| F+0x3620 | 0x310 after the output reservation; written by 0x100BAFFAC |
| F+0x26E0 | Marker pointer 0x1010C67F8 in these retained models |
| F+0x2EDC | 0x8B3DC651; written by 0x1009153AC; native status meaning unknown |

An all-u64 source contract for 0x10082F448..0x10082F464 establishes D=F+0x39F0+Q, saves it at F+0x3278 and increments the cursor by 64. ABDF8C forwards F+0x3278 to F+0x2F00; BAFFB0 forwards it again to F+0x32E8. This establishes local producer/consumer interfaces and retained numeric correspondence, not a newly proved native predecessor chain.

```text
retained frame layout, relative to F

+0x3C30  D: 64-byte destination reservation
         first 20 bytes receive canonical SHA-1 in checked compositions
+0x3C70  C: 100-byte context
         bytes 0..91 overwritten; size/selector preserved
+0x3CD4  12-byte gap
+0x3CE0  O: 32-byte encoded-output reservation
+0x3D00  next scratch boundary

source core -> encoded serializer O -> XOR0x98 copy -> D
                    |                              |
              preserved here               separate from 36-byte heap cache

overwrite -> decode copy / zero-size skip -> cursor -32 -> marker byte=1
                                                        |
                                               stop before F+0x3650
```

The marker pointer is present in the verified frozen entry groups; its complete original caller provenance is unknown. Its native readers, synchronization and lifecycle are also unknown. No atomic operation, ordering guarantee, Mach right, descriptor, message or IOKit emission is established by this phase. A frame offset is not a global type: the bounded census also finds unrelated writers of F+0x26E0, including encoded allocator-derived values in other phases.

## Five auxiliary root-field producers

The earlier root prefix additionally reads five saved fields. One source-local producer block, 0x100BD8F80..0x100BD9000, derives all five from B=F+0x39F0+Q and increments the scratch cursor by 0x4730, or 18,224 bytes:

| Saved field | Produced value |
| --- | --- |
| F+0x33C8 | B+0x60 |
| F+0x2DA8 | B+0xE80 |
| F+0x3108 | B+0x1CA0 |
| F+0x34B8 | B+0x2AC0 |
| F+0x2C28 | B+0x38E0 |

The proof covers these aliases, six further saved aliases and the u64 cursor update. It does not prove a native allocation extent or join that producer to the retained identity path. The bounded original-text census records 17 exact unsigned-immediate STR64 sites for the nine investigated offsets. It excludes computed, paired, aliased, overlapping and other-width stores. The separate F+0x3050 root remains unresolved.

## Assumption register and bounded continuation

| ID | Premise / dependent results | Stress or falsification probe |
| --- | --- | --- |
| GC1 | Pinned image, fixups and current IDB identity / all source claims | Rehash image; independently decode 15 fixups; compare 19 read-only ranges |
| GC2 | Separated valid frame/context/output/destination/marker owners / byte and address equations | Reject undefined reads/outside writes; test separated and retained layouts; recover native bounds/lifetimes |
| GC3 | Eight declared phase-entry registers / complete isolated phases | Check preceding seed source and original target cells; audit minimal GPR definedness |
| GC4 | Opaque alias prefix preserves phase inputs / independence result | Give protected fields distinct symbols; inspect all stores; require actual defined fields for native traversal |
| GC5 | Fixed W9/mode constants / recovered dispatcher path | Rebuild six source branch obligations; other incoming constants and routes remain outside the result |
| GC6 | Context size/selector are defined, survive overwrite and C'=C / combined context/size interpretation | Leave initial bytes 0..91 undefined; check all 92 write positions, preserved final eight bytes and both separately saved pointer cells; native equality/preservation remains open |
| GC7 | Nonzero copy size has matching readable/writable owners / copy semantics | All-byte/address/control proof with nonempty count domain; finite 0/16/20 cases and tail masks |
| GC8 | Saved cursor and four restore values are available / epilogue | Audit retained cells and exact widths; prove cursor subtraction modulo 2^64; native preservation remains open |
| GC9 | Marker points to a writable byte / completion store | Check sole byte store and source PC; do not infer native status semantics, readers or ordering |
| GC10 | Frozen CF/UTF-8 and prior component premises apply / retained and SHA-1 value matches | Rehash parents; audit 288 saved-field views; keep native and retained frontiers unchanged |
| GC11 | Auxiliary producer uses the same frame epoch when joined / five alias candidates | Recover real predecessors, cursor and lifetimes; do not infer continuity from matching offsets |
| GC12 | D differs from the 36-byte heap cache / architectural scope | Require an explicit later copy/transform/publication and matching IPC consumer before joining them |

| Impact | Additional opportunity / unresolved pattern | Required next evidence |
| --- | --- | --- |
| High | Canonical digest bytes now have a source-local sink D | Follow D=F+0x3C30 consumers and any subsequent cache transform/publication |
| High | Marker store and next saved owner define another continuation interface | Recover F+0x3650 and marker callers/readers with actual frame provenance |
| High | Root barrier has one root and five auxiliary dependencies | Join F+0x3050 and BD8F80-derived aliases to the relevant frame epoch |
| High | Native daemon/cache-to-kext data flow remains unjoined | Match actual output ownership and bytes to Mach/IOKit emissions and driver inputs |
| Medium | Context content is overwritten before output decoding | Recover other users of the shared phase and distinguish pattern semantics from native erasure guarantees |
| Medium | Frame cells carry unrelated pointer encodings in different phases | Preserve per-phase widths/producers rather than assigning global stack-field types |

Reproduce from this directory with the pinned Python/Z3 environment used in the preceding reports. Run `probe_daemon_digest_completion.py`, `recover_daemon_digest_completion.py`, `prove_daemon_digest_completion.py`, then `validate_daemon_digest_completion.py` in `triage_evidence`. The validator independently checks GPR/byte definedness, ordered effects, exact source/fixup/IDB bytes, all retained tracked fields and fresh execution of all 396 cases. It rebuilds each original SMT formula, proves it UNSAT and verifies equivalence to its normalized artifact; this avoids relying on simplifier AST ordering. Time is O(source bytes + new visits/effects + retained effects + solver resources). Space includes compressed artifacts, the largest decoded/fresh journal, one private map and solver DAGs. Each solver query has a 30-second limit; no polynomial solver bound is claimed.

QG1: factual technical scope. QG2: GC1-GC12 with dependencies/probes. QG3: overwrite/copy/completion increment covered; full objective remains incomplete. QG4: explicit byte extents, endian outputs, u32/u64 arithmetic and executed/modeled counts. QG5: source-local independence, finite component composition, unchanged retained frontiers and native joins are distinguished. QG6: original source/fixups, current IDB, rebuilt proofs, independent byte ledgers and fresh source execution support scoped claims. QG7: impact-ranked continuation table provided.
