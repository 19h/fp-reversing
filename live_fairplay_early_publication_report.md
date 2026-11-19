# Installed selector 26 first-record publication

The installed FairPlayIOKit continuation at `0xfffffe000a696e44` sends the first serialized record through the shared lookup. The freshly initialized container returns a miss with a zero old-node result. The selected append writes the new node into both container links at `0xfffffe000a6a3d58`. Its saved callback returns to the early parser cursor gate. The audit checks this path in 24 installed-code suffix replays seeded at the serialization frontier. Native publication and a matched daemon request remain unknown. [Prior writer audit](live_fairplay_early_writer_report.md) [Audit script](triage_evidence/audit_live_fairplay_early_publication.py) [Audit receipt](triage_evidence/live_fairplay_early_publication_audit.json.zst)

```text
serialized record -> lookup(H, encoded tag, &C[0x50])
  -> empty H -> status MISS, old node = 0
     -> store J into H.head and H.tail -> saved callback with SUCCESS
        -> compare cursor with input extent
           |-- cursor == extent -> exhausted-input target (24 fixtures)
           `-- cursor <  extent -> next-header target (source proof)
```

## Lookup request and container writes

F is the frame base, S the workspace, C the auxiliary region, H the 16 B container, J the new 32 B node, and Z the serialized record buffer. The prefix allocates H through a modeled typed return and clears both H words with the source `STP` at `0xfffffe000a677858`. The pointer to H resides at C+0x20. The new node resides at C+0x58. The frame at F+0x348 retains C+0x50, previously computed from C by the producer at `0xfffffe000a676ff4`. [Installed allocation and node handoff](live_fairplay_early_data_report.md)

| Installed stage | Input or effect |
| --- | --- |
| Early request branch `0xfffffe000a696ec4` | Index `0x49a` and modifier `0x0ee9` select lookup at `0xfffffe000a6a3c44`. X2=C, X4=S, X7=installed dispatch base, X22=H, W9=raw tag XOR `0x31ae0066`, X10=C+0x50 and W8=`0x6c`. |
| Lookup entry `0xfffffe000a6a3c44` | Store caller return PC into C+0xc8, encoded tag into S+0, and the output alias into C+0x758. |
| Head load `0xfffffe000a6a3da4` | Read H+0. On this path the head is zero. Save it to C+0x2b0 and store zero to the caller's C+0x50 at `0xfffffe000a6a3ddc`. |
| Lookup callback `0xfffffe000a6a3cf0` | Return to the saved early target `0xfffffe000a6a3cf4` with modifier `0x8d28`, W23=`0xce515bda` and X22 holding descriptor metadata. |
| Empty append `0xfffffe000a6a3d54` | Match raw miss, load H's tail and J, and select the empty-tail arm through index `0xd6a`. The `STP X10,X10,[X9]` at `0xfffffe000a6a3d58` stores J at H+0 and H+8. |
| Saved callback transfer `0xfffffe000a6a53bc` | Load C+0x260 and branch to `0xfffffe000a6a2d30` with modifier `0xf596` and W23=`0x31ae0066`. |
| Parser callback and cursor gate | Success selects `0xfffffe000a6a1c84` via modifier `0xc9dc`. The gate compares the u64 cursor at S+0xa10 with the decoded u32 input extent at S+0xb5c. Its transfer at `0xfffffe000a6a1cb8` uses modifier `0x2f10`. Equal selects `0xfffffe000a6a1cbc`. A remaining suffix selects `0xfffffe000a6a1db8` under the source proof. |

The head and tail updates leave J+0 and J+8 zero, preserve the u32 extent L+10 at J+0x10, and preserve Z at J+0x18. C+0x50 stays zero and C+0x58 keeps J. The selected suffix performs eight 4 B or 8 B store events totaling 60 B, including the two lanes of the `STP`. Each event is disjoint from Z's L+10 B range. The entry cursor is L+10, so the exhausted-input result holds for all retained fixtures. The audit stops before the first instruction at that target. The selected empty lookup and append use O(1) work and O(1) additional storage. [Historical publication and callback source proof](userclient_early_publication_report.md)

## Relocated controller table and descriptor

The callback combines two controller words obtained through F+0xa30 and F+0xa38. On this build they point to `0xfffffe000cd42eb0` and `0xfffffe000cd430d8`. The lookup arrays rooted through F+0xa00 and F+0xa20 start at `0xfffffe0007939f80` and `0xfffffe00079434b0`. Both 256 B arrays match the archived bytes. The audit checks that `i XOR right[left[i] XOR 0x87]` gives `0xdf` for every u8 i. Subtracting `0x93` selects index `0x4c` regardless of the controller-derived byte.

The installed pool-relative slot at `0xfffffe0008488c00` resolves to `0xfffffe0008492784`. Subtracting 4 gives the descriptor at `0xfffffe0008492780`. Its 64 B image matches the selected allocation descriptor at `0xfffffe0008491f40` and null-data retirement descriptor at `0xfffffe0008492a40`. All three decode as `site.FPTTLVNode`, signature `1121`, flags `0x64` and object size 32 B. The audited empty-container callback carries this descriptor in X22. The selected suffix has eleven logical branches and issues no allocator or free call. A nonempty lookup could select different code and remains unresolved here. [Installed allocation and retirement descriptors](live_fairplay_early_data_report.md)

## Evidence boundary and assumption register

The audit pins build `26C5035r` and matches the installed collection and bounded function hash from the preceding writer audit. Of 186 captured words across 15 spans, 184 are byte-identical. The changed ADRP/ADD pair at `0xfffffe000a6a3cdc` and `0xfffffe000a6a3ce0` forms installed pool base `0xfffffe00084889a0`. All 30 recorded authenticated table slots and both direct status branches resolve to their translated targets. Eighteen archived solver queries reproduce their UNSAT results with a 115 s per-query limit. [Installed writer identity](live_fairplay_early_writer_report.md) [Original source and solver premises](userclient_early_publication_report.md)

The installed prefix replays to the first writer metadata load and matches the prior receipt in all 24 cases. The audit compares 16 retained cells per case, accounting for six address translations, and checks two further saved frame roots. It starts the suffix at the common serialization frontier with the three incoming GPR projections consumed by the request. The archived source proofs supply their request contract. The same replay memory supplies the retained private cells. The suffix executes 4,392 installed instruction visits in total and checks 20 private loads, eight stores and eleven logical transfers per case. The intervening writer is covered by the earlier conditional serialization proof. The suffix leaves the record range untouched and does not read its bytes.

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| P1 | Installed bytes, relocation and normalized pointers correspond to the archived source paths. Claims about selected control flow depend on these bindings. | Compare the pinned function, rebase the code words and resolve the direct branches, pool roots and chained slots. |
| P2 | Retained frame, workspace, auxiliary and node cells survive the writer to the common frontier. The suffix projections and field checks depend on those epochs. | Check the source-projected request fields for all three body types and look for writes to the suffix's exact read set between its cutoff and entry. |
| P3 | H and J are separate valid objects with empty links, and Z is disjoint and holds L+10 B under the storage premise. The first append and record-preservation result depend on this. | Check the source zero stores and extent, then compare the eight suffix store footprints with Z. A nonempty H selects a different path. |
| P4 | The captured arrays remain stable and logical authenticated transfers use the stated targets and modifiers. The descriptor and callback path depend on this. | Exhaust the 256 byte indices, resolve the selected unauthenticated descriptor fixup and compare transfer operands. Native authentication requires separate evidence. |
| P5 | The retained fixtures contain exactly one complete record. Exhaustion depends on cursor equality and the callback success token. | Compare the source cursor with the u32 extent and test the remaining-suffix branch under its separate source premise. |

High impact applies to the precise store and callback chain, and to the next unresolved exhausted-input phase at `0xfffffe000a6a1cbc`. Medium impact applies to the third descriptor's type identity and the untraced nonempty or replacement path. Low impact applies to inferring business meaning from the private lookup index. This audit adds no Mach emission site. Native ownership and synchronization, end-of-input handling, and daemon correlation remain open. [Mach ports and emission sites](mach_ports_report.md)

QG1 covers factual scope. QG2 records premises and probes. QG3 covers first lookup, publication, callback and cursor. QG4 checks widths and bounded memory events. QG5 distinguishes the installed prefix, conditional writer and installed suffix. QG6 ties the claims to pinned source, fixups, bank data and replay results. QG7 bounds the remaining records, lifecycle and IPC joins.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_early_publication.py "$CURRENT_COLLECTION"
```
