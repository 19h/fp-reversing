# Installed selector 26 early record writer

The installed FairPlayIOKit writer uses the early node retained at C+0x58 and its buffer pointer at J+0x18. Under the checked storage and control-flow premises it writes a 10 B header and the selected scalar or span body into that buffer. All three accepted domains join at `0xfffffe000a696e44`. The installed instruction replay reaches the writer setup and stops before its first metadata load. Serialization is a conditional source result tied to the installed bytes. [Installed writer handoff](live_fairplay_early_data_report.md) [Audit script](triage_evidence/audit_live_fairplay_early_writer.py) [Audit receipt](triage_evidence/live_fairplay_early_writer_audit.json.zst)

```text
J+0x18 holds Z -> shared writer setup -> tag -> type -> length
                       |                                |
                       + replay stops before loads      +-> scalar32 --+
                                                        +-> scalar64 --+-> common continuation
                                                        +-> span ------+
```

## Installed bindings and replay

The audit pins build `26C5035r`, kernel UUID `90195379-954d-3ca3-baac-327341f14211`, and kext UUID `316464f8-eade-30ca-938e-2f430b1ed5bc`. It checks collection SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126` and the complete installed `_PRnut72j9` function hash. The 227 archived header words and 352 archived payload words match at a code translation of +0x41190. The audit resolves 17 distinct installed authenticated table fixups, verifies their landing instructions, and checks three direct branch site/target pairs. The table base is `0xfffffe00084899c0`. The solver reproduces 14 header and 15 payload UNSAT results from the pinned historical source lifts. [Header proof source](userclient_early_writer_report.md) [Payload proof source](userclient_early_payload_report.md)

The current replay executes 46,884 instruction visits and checks 528 logical edges for 24 archived nonzero-data cases. Four profiles, including zero and nonzero spans, each run with two private placements and three controller fixtures. The selected X1 extent fits u32. Every case matches 11 proof-projected registers at the branch `0xfffffe000a6a2a78`, the four fully defined setup cells, and seven retained payload cells. The comparison accounts for the installed table address in F+0xa60. Allocation results are register fixtures and the replay supplies no bytes for the eight unresolved setup cells. It stops at `0xfffffe000a695c74`, after the selected entry at `0xfffffe000a695c64`. [Installed replay and memory model](live_fairplay_early_data_report.md)

## Buffer, header and payload channels

F is the frame base, C the auxiliary region, S the workspace, J the 32 B node, and Z its data buffer. D, V and L are the raw u32 tag, u16 type and u32 body length. X16 carries J+0x18 at the writer handoff. The selected header path obtains J through C+0x58, obtains the early type from S+0x1b2, and obtains the length from S+0x94. The common BE32 writer at `0xfffffe000a695df4` handles D at offsets 0 through 3 and L at offsets 6 through 9. The early BE16 type writer at `0xfffffe000a696158` handles V at offsets 4 and 5. The individual stores apply the address-derived byte mask established in the archived source study. [Header layout and mask proof](userclient_early_writer_report.md)

| Wire type | Body source and width condition | Buffer extent | Installed payload site | Modifier at common continuation |
| --- | --- | --- | --- | --- |
| `0x9777`, u32 | S+0x110, L=4 | 14 B | `0xfffffe000a695fc4`, reuses BE32 writer | `0x3aa3` |
| `0x8485`, u64 | S+0xad0 via F+0xf8, L=8 | 18 B | `0xfffffe000a696c5c`, writer at `0xfffffe000a696ca4` | `0xc4bd` |
| `0x50db`, span | C+0x168 supplies P, S+0xca8 supplies encoded L | L+10 B | L=0 bypass at `0xfffffe000a69638c`, nonzero setup at `0xfffffe000a69651c` | `0x4bb5` for zero, `0xd76c` after copy |

| Retained cell | Width | Source contract |
| --- | --- | --- |
| F+0x104 | 4 B | `0x802218a3`, u64 writer index control |
| F+0x560 | 8 B | `0x886a1ca0`, span address arithmetic control |
| F+0xf8 | 8 B | S+0xad0, u64 channel address |
| F+0xa60 | 8 B | Installed dispatch table base |
| S+0xad0 | 8 B | Encoded scalar64 |
| S+0xca8 | 8 B | Encoded length, from the earlier data request path |
| C+0x168 | 8 B | P, the plaintext span source |

For L>0 the span step reads P+c-1 at `0xfffffe000a696560` and stores a masked byte to Z+c+9 at `0xfffffe000a6965a0`, with c counting from L to 1. It covers exactly L bytes at Z+10 through Z+L+9 in O(L) time and O(1) additional scratch space under the separated-span premise. For L=0 the span arm reaches the continuation without a payload read. The u32 and u64 cases have fixed-size stores. The checked type and scalar-width failure edges target `0xfffffe000a6a5204`. The effects of that failure body remain unknown here. [Payload selection and copy proof](userclient_early_payload_report.md)

The four undefined 8 B C cells, three undefined 4 B S cells, and one undefined 2 B S cell total 46 B. The two-world header proof holds the selected roots and valid ranges fixed while allowing the eight cells to vary. It proves equality of ten header byte values, 25 load addresses, 15 store addresses and seven selected target/modifier pairs. Other scratch contents can vary. The payload claims use their own retained-cell and control premises. The alternate pointer retag proofs establish their bit transforms. Native pointer aliases and authentication remain unknown. [Header independence proof scope](userclient_early_writer_report.md) [Payload premises](userclient_early_payload_report.md)

## Assumption register and bounded coverage

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| W1 | Pinned installed collection and archived lifts describe the same selected instructions and translated calls. The installed source result depends on these bindings. | Rehash the function, compare the words, resolve each installed fixup and decode the direct branches. |
| W2 | Fixture allocator returns and admitted u32 extents select the early handoff. The replay comparison depends on that entry state. | Compare the eleven branch registers, frame base, flags and cell values at the cutoff. Check the same path with an independently captured input and allocation epoch. |
| W3 | The selected phase retains valid separated F, S, C, J and Z regions, normal pointer tags, and Z extent L+10 within u32. The header and payload composition depends on these premises. | Check allocation epochs and aliasing, test phase selection and compare the actual destination addresses. |
| W4 | A nonzero span has L readable bytes at P, separated from Z. The reverse-copy result depends on this premise. | Verify source extent and separation for a nonzero span. A zero-length span should exhibit zero payload read events. |
| W5 | Joining at a common continuation establishes a control target. Publication and daemon correlation require the succeeding node/connection epochs. | Trace the first container write and correlate it with an admitted daemon request using the connection and input staging evidence. |

High impact applies to the installed early-node selection, buffer extent, and type-specific data flow. Medium impact applies to the exact shared continuation, which gives a starting point for tracing node publication. Low impact applies to predicting business semantics from the wire type values alone. Native allocation epochs, publication, and a matching daemon request remain unknown. This increment establishes no additional Mach emitter. [Mach ports and emission sites](mach_ports_report.md)

QG1 covers factual scope. QG2 records premises and falsification probes. QG3 covers the writer handoff, header, three payload arms and return to the common continuation. QG4 checks widths, byte extents and copy bounds. QG5 bounds the conclusions at the observed replay cutoff and conditional continuation. QG6 ties the results to the installed original bytes, chained pointers and pinned proof queries. QG7 identifies the remaining publication and IPC joins.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_early_writer.py "$CURRENT_COLLECTION"
```
