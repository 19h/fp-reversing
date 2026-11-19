# Installed FPMessage initialization and parser re-entry

The installed initializer consumes the 112 B attribute from the schema lookup path and produces a separate 128 B `site.FPMessage`. It reads all 107 defined attribute bytes, skips the five unwritten positions, and writes 123 message bytes. Both attribute modes reach the same parser entry with the original input pointer and encoded extent. A null message allocation instead publishes `0xce515bb2` and transfers to cleanup. [Attribute producer](live_fairplay_message_attributes_report.md) [Auditor](triage_evidence/audit_live_fairplay_message_initialization.py) [Replay receipt](triage_evidence/live_fairplay_message_initialization_audit.json.zst)

The reconstructed selector 26 aggregates reach the same FPMessage allocation with a second-reader pointer, an extent of 208 B or 224 B, and output address C+0x210. That caller continues toward a separate FPMessageAttr allocation. [Selector 26 discriminator and message handoff](live_fairplay_selector26_consumer_report.md)

```text
constructed FPMessageAttr -> save input pointer and encoded extent
                             -> clear 32 B of separate workspace
                             -> request typed FPMessage
  |-- null     -> publish ce515bb2 -> pending cleanup
  `-- nonnull  -> initialize 128 B object -> publish parser context
                -> common FPTTLV parser entry
```

## Installed transfers and data flow

Addresses are unslid VAs for build `26C5035r`. A is the attribute, M the new message, I the retained input pointer, N the u32 input extent, C the auxiliary region and S the workspace. All eight composed cases carry N=14 and the same previously reconciled input site per fixture. The zero-extent gate is covered by a separate archived proof.

| Installed site | Effect |
| --- | --- |
| `0xfffffe000a698740` | Enter with X20=I, W22=N XOR `0x31ae0066` and X8=C+0x360. Save I at C+0x498, the encoded extent at S+0x150 and the callback `0xfffffe000a677ec4` at C+0x5d0. |
| `0xfffffe000a6987d8` | BLRAA to the local clear helper `0xfffffe000a6c8ef4`, modifier `0x46ae`. X0=S+0xcc8, W1=0, X2=32, nominal return `0xfffffe000a6987dc`. |
| `0xfffffe000a6988e8` | BLRAA to `_IOMallocTypeImpl` at `0xfffffe000c509774`, modifier `0xd0c8`, nominal return `0xfffffe000a6988ec`. |
| `0xfffffe000a698924` | Store allocator result M at C+0x788 on both allocation outcomes. |
| `0xfffffe000a698acc` | Enter the attribute-to-message initializer with X0=M, X19=A and modifier `0x2ee0`. |
| `0xfffffe000a694f00` | Return through the saved private initializer callback with modifier `0x7fb0`. |
| `0xfffffe000a697d28`, `0xfffffe000a697d2c` | Publish M at C+0x718 and I at C+0x18. |
| `0xfffffe000a697d5c`, `0xfffffe000a697d60` | Publish encoded extent at S+0xc8 and parser phase `0xfbb3f478` at S+0x1e0. |
| `0xfffffe000a697d94` | BRAA to common FPTTLV parser entry `0xfffffe000a6774c8`, modifier `0xb40b`. |
| `0xfffffe000a682cc8` | Null allocation transfers to cleanup `0xfffffe000a6a3374` with modifier `0x682a` after writing `0xce515bb2` at S+0xab8. This arm reads no attribute bytes. |

The allocator uses descriptor `0xfffffe0008492000`, named `site.FPMessage`, flags32 `0x64`, signature `1122222222222222`, extent 128 B. The descriptor slot is `0xfffffe0008488e80` with a 12 B subtraction. The allocator and local clear slots are `0xfffffe0008491258` and `0xfffffe0008491110` respectively. Allocation returns are modeled. The local helper is replayed from its actual instructions. [Original descriptor and continuation evidence](userclient_message_initialization_report.md)

## Local clear and attribute mapping

The installed 360 B clear helper matches the historical bytes. Separate replays cover all eight alignments for a 32 B zero fill. Each writes exactly the destination bytes once, preserves SP and X19 through X30, and returns to the nominal link. The aligned case leaves X0=D+32. The seven unaligned cases leave X0=D+31, where D is the original destination. The composed callers exercise the aligned case. Across the eight alignment cases, 80 of the helper's 90 words execute. Other lengths retain unknown behavior in this audit.

| Message location | Width | Source-derived value |
| --- | ---: | --- |
| +0x00, +0x08 | 8 B each | Zero |
| +0x10 | 4 B | A+0x00, value `0x3908f615` |
| +0x14 | 4 B | 1 for zero mode, 0 for nonzero mode |
| +0x18, +0x38 | 32 B each | A+0x08 and A+0x28 respectively |
| +0x58, +0x5c | 4 B each | A+0x48 and A+0x4c respectively |
| +0x60, +0x61 | 1 B each | A+0x50 and A+0x51 respectively |
| +0x62 | 2 B | Unwritten |
| +0x64 | 4 B | A+0x54, retained payload header |
| +0x68 | 16 B | A+0x58 XOR the fixed byte mask |
| +0x78 | 4 B | A+0x68, value 16 |
| +0x7c | 1 B | `0xca OR (A[0x6c] AND 1)`, value `0xcb` |
| +0x7d | 3 B | Unwritten |

All three 16 B constant arrays match the archived content at the corresponding installed locations, `0xfffffe00079501e0`, `0xfffffe000794cb46` and `0xfffffe000793c324`. They combine with the index-dependent term to form the byte mask `e4 3a 4e c1 53 6f 29 de d6 b3 0e 15 5e 08 3e 20`. The replay checks each transformed byte. The five unwritten message bytes remain unknown in the message's own allocation. The caller passes the prepared state to the internal parser. The selected suffix has no Mach send or right transfer. [Historical transform proof](userclient_message_initialization_report.md) [Mach port evidence](mach_ports_report.md)

## Verification and assumptions

The audit checks 628 selected words across 24 spans and four pool-address relocation words, resolves 25 authenticated continuation fixups, and exhausts six bank selectors over 256 inputs each. The two scalar fixtures each run both attribute modes with a nonnull and a null message allocation. The eight composed suffixes cover 6,992 caller instructions, a further 328 local-clear instructions, 522 stores and 178 transfers. The 45 retained zero-fill and extent-gate proof partitions reproduce UNSAT. The older symbolic report retains its broader arbitrary-input obligations. The fixed-size initialization and clear use O(1) time and space with respect to N. The audit stops at the next parser entry and does not measure parser cost.

| Assumption | Dependent result and falsification probe |
| --- | --- |
| M1. Pinned collection and relocation | Rehash the collection, compare both source envelopes, rederive selected bank relations, and resolve descriptor and branch fixups. |
| M2. Preceding attribute and input roots carry forward | Compare the four occupied attribute case records, five saved frame cells, original protected bytes and preserved 112 B attribute image. |
| M3. Ordinary modeled allocation return and separate storage | Replay both allocation outcomes in both modes. Check exact output byte coverage, frame and workspace effects, and no attribute read on the null arm. Native allocation and pointer lifetime are unknown. |
| M4. Exact clear scope and nominal authentication | Replay all eight alignments, each with a writable 32 B modeled destination. Check the write set, return, SP, and saved registers. Native authentication remains unknown. |
| M5. Fixture input extent and transport identity | The successful replay observes nominal re-entry with the retained 14 B fixture extent. An end-to-end daemon claim requires evidence of the native staging subview and matching transaction. |

| Impact | Open interface |
| --- | --- |
| High | Follow the installed parser from this second entry epoch with the newly published message and retained input. |
| High | Establish native lifetime and transaction identity for the staged input, shared table payload and newly allocated message. |
| Medium | Trace the message allocation failure through cleanup, ownership and caller-visible status. |

QG1 factual scope, QG2 assumptions and falsification probes, QG3 both initialization modes and failure, QG4 exact widths and counts, QG5 distinct storage and modeled return, QG6 pinned provenance, and QG7 bounded continuation pass for this increment. Native parsing and transport remain open.
