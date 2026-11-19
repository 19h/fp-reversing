# Selector 26 discriminator and second-span message handoff

The FairPlayIOKit continuation after the 19 B selector 26 copy hashes the first 18 bytes into discriminator `0xd9477e9d`. It then requests the middle record from the same three-node container and copies its complete 208 B or 224 B body. The message setup retains that second pointer and encoded length and requests a 128 B `site.FPMessage`. All four reconstructed `fairplayd` aggregates reach this sequence in a continuous offline replay with a nonnull saved provider and ordinary successful modeled allocations. [Copying-reader predecessor](live_fairplay_selector26_fallback_report.md) [Auditor](triage_evidence/audit_live_fairplay_selector26_consumer.py) [Compressed receipt](triage_evidence/live_fairplay_selector26_consumer_audit.json.zst)

```text
first reader -> 19 B incl. NUL -> discriminator at workspace +0xc90
                      |
                      v
same list -> middle tag 0x812b9aed -> second reader -> 208 or 224 B
                                                          |
                                                          v
                                              message setup retains extent
                                                          |
                                                          v
                                               FPMessage allocation
```

## Discriminator source

C denotes the core's private context, S its workspace, F the retained SP and Q the second reader's output. The first reader's resume PC `0xfffffe000a698254` receives W23=`0x31ae0066`. After the success test, `0xfffffe000a6982bc` loads the saved output address from F+0x478 and `0xfffffe000a6982c0` loads the buffer pointer from C+0x128. The byte at offset 0 is read at `0xfffffe000a698314`. The loop then reads offsets 1 through 18 at `0xfffffe000a6983c4` and stops at the NUL. The replay records zero reads of the first reader's encoded extent at S+0xaa8 during this calculation. [Earlier source proof of the discriminator](userclient_discriminator_origin_report.md)

The independent integer check starts with 5381 and applies `h = (33*h + byte) mod 2^64` to the 18 nonzero bytes in order. It obtains `h = 0xdbcd5bd6fd7a22c6`. The installed unsigned high-product reduction and independent `h mod (2^32 - 1)` both give `0xd9477e9d`, which STR at `0xfffffe000a698430` places at S+0xc90. All eight composed cases agree. The earlier source maps S+0xc90 to the UIDList discriminator channel. The selected sequence here preserves the stored value through message setup. [Earlier UIDList discriminator mapping](userclient_discriminator_origin_report.md)

## Second record copy and message setup

| Installed PC | Contract observed on the selected sequence |
| --- | --- |
| `0xfffffe000a6984a8` | Shared reader transfer to `0xfffffe000a6a3bb8`, IA discriminator `0x73ed`. X22 holds the same fresh container. W9 holds `0xb0859a8b` for raw key `0x812b9aed`. X10 points to S+0xabc, X11 points to C+0x178 and W24 is resume index `0x134`. |
| `0xfffffe000a6a3ddc` | The head's four-byte tag misses. The middle node matches and is stored at C+0x400. The tail's protected record bytes receive no read during this second lookup or copy. |
| `0xfffffe000a67efe8`, `0xfffffe000a67f118` | Store the encoded length at S+0xabc and request `_IOMallocData` for the decoded extent. |
| `0xfffffe000a67f27c`, `0xfffffe000a67f2a8` | Write one decoded byte per descending output offset. Publish Q at C+0x178. |
| `0xfffffe000a6a42ac` | Resume at `0xfffffe000a6984ac` with W23=`0x31ae0066`. Original chained slot `0xfffffe000848a360` binds index `0x134`, IA discriminator `0x3aa3`. |
| `0xfffffe000a698560` | Request 8 B `site.FPSecureTunnelAttr` using descriptor `0xfffffe0008492240`, signature empty, flags `0x6c`. After nonnull return, write u32 7 followed by byte values 1 and 1. C+0xf0 and C+0x6d0 retain its pointer. |
| `0xfffffe000a69866c`, `0xfffffe000a6987d8` | Execute the same local zero-fill helper at `0xfffffe000a6c8ef4` on S+0xb00 and S+0xcc8, respectively, for 32 B each. Both aligned calls return after writing exactly four zero qwords. |
| `0xfffffe000a698754` through `0xfffffe000a698764` | Save resume `0xfffffe000a698ad0` at C+0x5d0 and &C+0x210 at C+0x430. Move Q into C+0x498 and the same encoded extent into S+0x150. |
| `0xfffffe000a6988e8` | Request 128 B `site.FPMessage` using descriptor `0xfffffe0008492000`, signature `1122222222222222`, flags `0x64`. The nonnull modeled result is retained at C+0x788. |

The reader's exact output maps to the original aggregate as follows. Extents are bytes and ranges are half-open.

| Aggregate extent | Source range | Copied extent | Encoded extent |
| ---: | --- | ---: | --- |
| 272 B | `[24,232)` | 208 B | `0x31ae00b6` |
| 288 B | `[24,248)` | 224 B | `0x31ae0086` |

The copied range starts with nested tag `0x7976211a` and includes the previously reconstructed span keyed by `0xfd2821c7`. The audit compares every copied byte against staging and checks the actual reads of the protected middle record. The subsequent setup reads the pointer and encoded length, with zero reads of Q's body through the reported endpoints. The child fields' interpretation remains open. [Daemon nested spans](daemon_selector26_request_bytes_report.md)

## Workspace boundary and bounded probes

The continuous replay reaches `0xfffffe000a693fac`, which loads W19 from S+0xd0c. No source store in the composed prefix defines its four bytes. The model stops before this load with the new FPMessage pointer in X0. The two following probes each start from a copy of that exact state and substitute a value only for that read. Both preserve the supplied value in W19 and reach the same pending `_IOMallocTypeImpl` at `0xfffffe000a69405c`, descriptor `0xfffffe0008491c80` for the 112 B `site.FPMessageAttr`. The probe values are zero and `0x10203040`. The installed message-attribute audit separately establishes this descriptor and the later random-call interface under different predecessor conditions. The native origin of the workspace word and the later constructor effects for these aggregates remain unknown. [Installed message-attribute constructor](live_fairplay_message_attributes_report.md)

## Verification and scope

Eight cases cover four hash-verified daemon aggregates and two retained writer scratch fills with a nonnull provider. Each preceding fallback replay agrees with the published receipt. The two workspace values give sixteen additional short probes. The analysis uses the pinned collection and verifies the new descriptor data, slot encodings, and helper bytes. Allocation results are supplied as ordinary register-only returns and use fresh, disjoint modeled storage. The zero-fill helper runs through its actual instructions. The discriminator takes O(L) time and O(1) state for L bytes through NUL. The second reader takes O(R+B) time and B bytes of output storage, where R is the number of examined nodes and B is the copy extent. [Installed fallback replay](triage_evidence/live_fairplay_selector26_fallback_audit.json.zst)

The auditor compares 1,354 distinct installed words with the normalized original, records six differences and verifies 23 newly loaded fixup slots. The eight continuous segments execute 63,344 core instructions and 656 helper instructions. Each bounded probe executes another 44 instructions before the pending call. The installed collection SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. The decoded receipt SHA-256 is `f3486100341b48047579fe4efe50cdf04c475be1c7d1761057577b2695862fdc`.

```sh
uv run --offline --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_live_fairplay_selector26_consumer.py "$COLLECTION" "$RECEIPT"
```

The new calls are private kernel transfers and allocator requests. The known external edge remains Mach method request 2865 and reply 2965. The supplied trace ends at the failed 2862/2962 open. No native transaction joins the reconstructed inputs to this path. [Mach emitters and rights](live_iokit_mach_transport_report.md) [Supplied RAX trace](zut_trace_report.md)

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The reconstructed staging, provider, and previous modeled state apply. | Selected 19 B hash and second reader data lineage. | Pair an observed method request with actual provider staging and compare the copied ranges. |
| A2. Ordinary nonnull allocators return without changing caller memory and supply disjoint writable storage. | Second copy, attributes and message pointer handoff. | Verify alias and allocator effects at the actual calls. |
| A3. The prior frame, controller state and tested scratch fills apply. | Exact control-flow path through message setup. | Change frame placement and controller bytes, then compare helper, output and continuation arguments. |
| A4. The workspace probes replace only the undefined read with their declared u32 values. | Same following descriptor request in the sixteen probes. | Resolve the native reaching definition and compare the live W19 value at the allocation site. |

| Impact | Open interface |
| --- | --- |
| High | Follow the copied body through the selected message-attribute continuation to the nested parser and reply construction. |
| High | Correlate a native daemon request, task copy, core execution and Mach reply. |
| Medium | Establish the native reaching definition and later uses of S+0xd0c for the selected call path. |

QG1-QG3 cover factual scope, assumptions, both record readers and message handoff. QG4-QG5 cover the unsigned reduction, byte ranges, copy order and bounded workspace probes. QG6-QG7 cover pinned source provenance and the unresolved kernel and transport boundaries.
