# Mode1 inverse tables and fixed cyclic operation: research checkpoint

This checkpoint contains source-pinned findings and partial validation. It does not complete the second-shuffle equivalence proof or the composed256-entry table-generation contract. The prior sealed interface manifest remains the inventory of the last fully sealed report;these checkpoint artifacts are intentionally outside that inventory until the next full seal.

Confirmed findings:

- The original inverse loop at0x100dd165c reads sixteen entries from the first scattered permutation and writes its inverse into a disjoint16-cell region. If A[j]=E(pi(j)),then B[pi(j)]=E(j),where E(j)=0xd4 XOR j. Its16-round control and source stores are SMT-certified.
- The following loop at0x100c97370 restores A[j]=E(j) in16 rounds while retaining B. The recovered next block reads the second state-bank spills;its full swap and equality contracts remain unproved in this checkpoint.
- A fixed944 B original data region at0x100f715a0 is selected by two original256 B banks. All256 possible selector inputs choose the same offset208. The sampled source index domain yields a256-entry operation whose decoded values are nibbles.
- The fixed decoded operation is isomorphic to addition modulo16. Identity label9,generator label3,a16-label cycle,all256 isomorphism pairs and all4096 associativity triples are checked directly against the captured original bytes. This classification does not identify a standard FairPlay cipher or establish the generated runtime table's final algebraic properties.

Evidence: [source snapshot](triage_evidence/daemon_mode_one_inverse_tables_source.json.zst), [partial proof record](triage_evidence/daemon_mode_one_inverse_tables_checks.json.zst), [extractor](triage_evidence/recover_daemon_mode_one_inverse_tables.py), [validator in development](triage_evidence/validate_daemon_mode_one_inverse_tables.py), [preceding sealed report](daemon_mode_one_scatter_report.md).

The source snapshot contains10 ranges/1052 summed instructions and1003 distinct sites,including overlapping first-shuffle/seed context. Nine pointers,nine branch/modifier matches,three data ranges/1456 B and three prior recaptures/1804 B are checked. Eleven SMT queries return UNSAT. Only170 distinct instruction sites are translated so far;828 nonbranch sites remain untranslated. The JSON explicitly sets all_checks_pass=false and validation_stage=checkpoint_partial. No target execution,CPU emulation,FairPlay request or live-IDB mutation is performed. IDA memory lookup was attempted,but no authenticated bridge worker was reachable;no IDA fact is used as evidence.

The source artifact is fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e. Addresses are unslid;state arithmetic is u32 unless stated otherwise. Byte extents use B. Original bytes,fixups and finite source-data calculations supply provenance. New metadata omits username-bearing paths.

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| IT1 |Pinned original artifact and original fixup interpretation |Rehash and recapture source/data bytes;reject a mismatch |
| IT2 |Same valid,nonwrapping private frame and stable coherent source tables |Trace owners and intervening writes;native validity/concurrency are not established |
| IT3 |The prior A cells form a permutation of the sixteen E values |Replay the preceding source contracts;without bijectivity the inverse-table conclusion is conditional |
| IT4 |Pointer rebases and immutable byte-bank contents agree with the original image |Recheck the two root records and all256 bank evaluations;native mappings/PAC remain unknown |
| IT5 |The fixed operation's sampled index formula matches the later source pipeline |Finish the complete source-to-table proof;the full generated operation is not yet classified |

High-impact continuation: complete the second shuffle,compare its choices with the first under equal state banks,and prove the full table writer's input/output representation and memory footprint. Medium-impact continuation: trace the next consumer and connect generated local tables to caller-visible effects. Native daemon/kext exchange,whole return and budget history remain unknown.

QG1: No normative content is required.

QG2: IT1-IT5 record assumptions and falsification probes.

QG3: Checkpoint source capture and explicitly bounded findings are covered;the remaining semantic chain is explicitly incomplete.

QG4: Word widths,byte extents,summed/distinct sites and finite domains are distinguished.

QG5: Fixed-table group structure is not presented as a proof of the full generated table. Partial translation is explicit.

QG6: Original byte/fixup/data hashes,eleven UNSAT queries and finite algebra checks ground the confirmed findings.

QG7: Follow-ups are impact-ranked and retain the full cross-layer objective. This is a publication checkpoint,not a completed semantic report.
