# Selector 26 fallback parser and copying-reader output

A continuous offline replay of the installed FairPlayIOKit core links the four reconstructed `fairplayd` selector 26 aggregates to the command comparison and the 19 B copying-reader output. The fallback protects a copy of the full staging extent and builds a fresh three-node container. Its first record supplies command `0x88594abe`. With a nonnull saved provider and ordinary successful modeled allocations, its last record supplies the reader's 19 B output. [First parser and retirement](live_fairplay_selector26_parse_report.md) [Conditional command dispatch](daemon_selector26_command_report.md) [Auditor](triage_evidence/audit_live_fairplay_selector26_fallback.py) [Compressed receipt](triage_evidence/live_fairplay_selector26_fallback_audit.json.zst)

## Fallback input and parser custody

```text
I[0..N) -> full protected copy B[0..N)
                |
                v
          new container at C+0x600
                |
                +-> head 0x744b91e8 -> scalar 0x88594abe
                |                            |
                +-> middle 0x812b9aed        v
                +-> tail 0x172ba3a8 -> reader -> 19 B output
```

I is the original staging allocation, B the fallback byte buffer, C the private context, S the workspace and F the retained SP. N is 272 B or 288 B. The full copy executes one byte load at `0xfffffe000a682fa0` and one byte store at `0xfffffe000a682fd8` per iteration in descending offset order. It writes B, keeps I intact and copies the trailer body byte at N-1 that the first parser skipped. The fallback buffer uses the same address-dependent XOR mask already cross-checked for individual protected records. [Protected byte representation](userclient_fallback_parser_report.md)

| Event | Installed PC | State and data |
| --- | --- | --- |
| Full-extent allocation | `0xfffffe000a682e88` | `_IOMallocData(N)`, IA discriminator `0xca0c`. Return B is saved at C+0x90. |
| Parser handoff setup | `0xfffffe000a683164` through `0xfffffe000a683170` | C+0x5c8 receives command resume `0xfffffe000a697d98`. C+0x188 receives address C+0x600. S+0xc8c receives N XOR `0x31ae0066`. C+0x618 receives B. |
| Container allocation | `0xfffffe000a683228` | `_IOMallocTypeImpl`, descriptor `0xfffffe00084920c0`, `site.FPTTLV`, 16 B. |
| Node and record allocation | `0xfffffe000a68375c`, `0xfffffe000a683950` | 32 B `site.FPTTLVNode` descriptor `0xfffffe0008492ac0`, followed by `_IOMallocData` for each serialized record. |
| Parser output | `0xfffffe000a6a1c60`, `0xfffffe000a6a1c80` | Publish new container at C+0x600. Resume command caller under IA discriminator `0x481b` with W23=`0x31ae0066`. |

The parser reads all B offsets except N-1 once and commits F+0xa80 to N. For N=272 B the cursor visits 0, 14, 232, 261 and 272 B. For N=288 B it visits 0, 14, 248, 277 and 288 B. The three nonzero records give allocation extents of 14 B, 218 or 234 B, and 29 B. The auditor checks the full decoded record bytes, header-to-body extents and both link directions. The zero-tag trailer contributes to the cursor and leaves the third node at the tail. The modeled retirements of the first container and its children remain in force across this handoff.

## Command and output

| Decision or store | Installed PC | Observed contract |
| --- | --- | --- |
| Scalar comparison | `0xfffffe000a67bee0` | The head record supplies big-endian `0x88594abe`. S+0xcf0 and W8 hold the encoded `0xb9f74ad8`. Equality selects `0xfffffe000a67eea4`. |
| Saved provider | `0xfffffe000a67ef0c` | F+0x738 nonnull selects `0xfffffe000a67ef10`. Null selects `0xfffffe000a698090`, with W23=`0xce515bbf` at the endpoint. |
| Private reader transfer | `0xfffffe000a67ef5c` | X22 carries the new container. W9=`0x2685a3ce` for tag `0x172ba3a8`. X10=&S+0xaa8, X11=&C+0x128 and W24=`0x133`. Logical target `0xfffffe000a6a3bb8`, IA discriminator `0x73ed`. |
| Length and allocation | `0xfffffe000a67efe8`, `0xfffffe000a67f118` | Store encoded length `0x31ae0075` at S+0xaa8. Request `_IOMallocData(19)`, IA discriminator `0xca0c`. |
| Copy and pointer publication | `0xfffffe000a67f27c`, `0xfffffe000a67f2a8` | Write 19 individual bytes at output offsets 18 through 0. Store the resulting pointer at C+0x128. |
| Reader resume | `0xfffffe000a6a42ac` | Chained slot `0xfffffe000848a358` binds resume index `0x133` to `0xfffffe000a698254`, IA discriminator `0x3aa3`. W23=`0x31ae0066`. |

In all eight reader cases the search reads the four tag bytes of each node. Only the tail's type, length and body are read after that match. The 19 stores reproduce staging offsets 242 through 260 B for the 272 B aggregate or 258 through 276 B for the 288 B aggregate. The final byte is already zero in each of the four source spans. The reader adds no byte. The 19 B output has SHA-256 `fac56b6d1af48433a996527e78971bfff515e5e1766d1085bcc6911365391a4a` in every case. Its consumption and eventual result remain unknown for these aggregates. [Reader contract and output cells](userclient_input_reader_report.md)

A null full-extent allocation takes `0xfffffe000a6a734c` without rereading I or writing C+0x600. It requests `_IOFreeTypeImpl` at `0xfffffe000a6a73f0` with descriptor `0xfffffe0008492500` and the 4096 B context C. Under an ordinary modeled return, it then requests `_IOFreeAligned(S,16384)` at `0xfffffe000a6a7440`, IA discriminator `0x84ff`. The replay stops at that call with W23=`0x31ae0066`. The external return and IOKit status remain unknown.

## Verification and scope

Thirty-two cases cover the four aggregates, two saved provider values, two writer scratch fills, and null and nonnull outcomes of the full-extent fallback allocation. Each case first reconstructs the previous continuous replay and compares it with the pinned first-parser receipt. Eight successful reader cases compare all 19 published bytes against the matching original staging slice. The remaining nonnull fallback cases stop on the null-provider cleanup edge. The null-fallback cases stop at the workspace release request. The auditor checks installed collection identity, typed descriptor data and chained pointers. It compares the executed instruction words at the fallback and reader boundary with their corresponding addresses in the normalized original. [First-parser receipt](triage_evidence/live_fairplay_selector26_parse_audit.json.zst)

The fallback segments record 388,672 instruction-site observations, including endpoints. The audit compares 2,507 distinct words, records the six differences and verifies raw encodings and targets for 82 additional loaded fixup slots. The installed collection SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. The decoded receipt SHA-256 is `3319b02d521f7abcd11d36ab0ec6941b836177e2be5d7ae5aa34afe8b338dae1`.

```sh
uv run --offline --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_live_fairplay_selector26_fallback.py "$COLLECTION" "$RECEIPT"
```

The copy takes O(N) time and N bytes of new storage with O(1) loop state. The reader traverses at most R list nodes and copies L bytes, so its selected nonnull route takes O(R+L) source work and L bytes of new data storage, excluding allocator execution. Here R=3 and L=19 B.

The Mach transport evidence remains request 2865 on the existing connection right and reply 2965 on the separately supplied send-once reply right. The supplied emulated trace ends at failed open 2862/2962 with a null connection. This replay starts at the core's modeled staging input, and native daemon-to-kext delivery remains unknown. [Mach transport and emitters](live_iokit_mach_transport_report.md) [Supplied RAX trace](zut_trace_report.md)

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. Original staging contains one of the four reconstructed daemon aggregates. | Complete byte custody and field-to-output correspondence. | Match daemon method bytes and provider staging in the same observed transaction. |
| A2. The selected model uses ordinary register-only allocator returns, with later allocations nonnull, fresh and disjoint. | New buffer, list and reader identities. | Check placement and failure outcomes independently and compare the resulting ABI traces. |
| A3. The selected frame and controller bytes apply, with either retained writer scratch fill. | Parser and command continuation sequence. | Change frame placement or controller bytes and compare cursor, output hash and continuation. |
| A4. Original instructions and chained fixups establish logical control flow. | Indirect transfers and imported API requests. | Compare the same call sites, arguments and continuations in a matched native trace. |

| Impact | Evidence still open |
| --- | --- |
| High | Trace consumption of the published 19 B, the deeper calls it feeds and selector 26 reply construction. |
| High | Correlate one daemon request, provider task copy, core entry and Mach reply in a native observation. |
| Medium | Identify alternate parser or reader exits when a later modeled allocator returns null. |

QG1-QG3 cover factual claims, assumptions and both fallback allocation outcomes. QG4-QG5 cover byte custody, exact extent accounting, linked records, continuation selection and output values. QG6-QG7 cover pinned source evidence and the scoped open boundaries.
