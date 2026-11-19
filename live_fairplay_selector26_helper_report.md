# Installed selector 26 private helper return

The installed FairPlayIOKit core passes a workspace record to a private helper after publishing four protected nested records. Across 16 offline cases, the helper checks the order of two addresses, updates two image-backed state cells, processes the nested records and stores `0x31ae0066` at record offset `+0x40`. The core reloads that word before reaching another 16 B `FPTTLV` allocation request. The fixture history and the open transport boundary are recorded in the preceding reports. [Nested records](live_fairplay_selector26_nested_report.md) [Mach transport](live_iokit_mach_transport_report.md)

## Call and record interface

`S` denotes the core workspace, `C` the saved context, and `R = S + 0x968` the helper's argument record. The call at `0xfffffe000a680f5c` passes `R` in `X0` and retains it in `X20`. The format 8 chained slot at `0xfffffe0008491630` resolves to `0xfffffe000a6c3c50` with modifier `0x9ae8`. The installed function-start range is `[0xfffffe000a6c3c50, 0xfffffe000a6c77b0)`. The original normalized decompilation identifies the corresponding entry as `sub_FFFFFE000A682AC0` in `com.apple.driver.FairPlayIOKit.c` at line 232193. The replay verifies preservation of `SP` and `X19` through `X29` on return.

| Offset in `R` (B) | Width (B) | Installed load | Observed value or source |
| --- | ---: | --- | --- |
| `+0x18` | 4 | `0xfffffe000a6c3d90` | Encoded phase `0x1b0e98d8` |
| `+0x38` | 8 | `0xfffffe000a6c3d98` | Workspace pointer `S + 0xe40` |
| `+0x00` | 8 | `0xfffffe000a6c3d9c` | Context `C` |
| `+0x58` | 4 | `0xfffffe000a6c3da0` | `0xd63c6ccd` at 288 B and `0xd63c6cdd` at 272 B |
| `+0x30` | 4 | `0xfffffe000a6c3e60` | Encoded word `0x535ec7c4` |
| `+0x10` | 8 | `0xfffffe000a6c3ed0` | Fourth protected nested body |
| `+0x48` | 8 | `0xfffffe000a6c3ed4` | Second protected nested body |
| `+0x50` | 8 | `0xfffffe000a6c3fb0` | Fourth protected nested body, alias of `+0x10` |
| `+0x40` | 4 | `0xfffffe000a680f64` | Helper status `0x31ae0066`, core-side load |

The first observed helper-side guard calls `0xfffffe000a6c905c` from `0xfffffe000a6c3e2c` with modifier `0x4d6a`. The arguments are `S + 0xe80` in `X0` and `C` in `X1`. The guard compares them as unsigned addresses and returns on the observed ordering. The helper uses the low words of two state cells during later dispatch. The first two 8 B stores update `0xfffffe000cd47580` at `0xfffffe000a6c3d48` and `0xfffffe000cd430d8` at `0xfffffe000a6c3d50`. Each of the 16 cases observes the same pair of updates with the inherited input state.

## Repetition and return

| Caller class | Outer extent (B) | Nested span (B) | Visits to `0xfffffe000a6c7700` | Instruction visits per case | `X0` on return |
| --- | ---: | ---: | ---: | ---: | --- |
| `0x98` | 272 | 96 | 6 | 17,248 | `0xa0cf1a2e` |
| `0x99` | 272 | 96 | 6 | 17,248 | `0x8fdf1a2e` |
| `0x98` | 288 | 112 | 7 | 19,926 | `0x84c91a2e` |
| `0x99` | 288 | 112 | 7 | 19,926 | `0x84c91a2e` |

Continuing visits at `0xfffffe000a6c7700` branch to `0xfffffe000a6c7704`, then `0xfffffe000a6c77ac` branches back to the processing block at `0xfffffe000a6c4dd8`. The last visit branches to `0xfffffe000a6c4244` on every case. The observed counts equal the two nested span sizes divided by 16 B. General iteration bounds and the transformation's semantics are unknown.

The helper stores the 4 B word at `R + 0x40` at `0xfffffe000a6c427c`, then returns at `0xfffffe000a6c429c`. The word had no defined value at helper entry in the replay. The core resumes at `0xfffffe000a680f60`, loads the word into `W23` at `0xfffffe000a680f64` and takes the dispatch at `0xfffffe000a680f70` to `0xfffffe000a681f7c`. It reaches the `_IOMallocTypeImpl` call at `0xfffffe000a683228`. The descriptor at `0xfffffe00084920c0` requests 16 B for `site.FPTTLV`, signature `11`, flags `0xe4`. The replay ends at that call. The next audit follows both modeled allocation outcomes through staging restoration and the core epilogue. [Core cleanup and result](live_fairplay_selector26_core_return_report.md)

## Evidence and limits

The audit compares every predecessor replay result with its archived case and retains 3,902 distinct installed instruction words, including the pending allocator site, and 31 newly observed chained slots. The 16 cases cover 297,392 instruction visits. The installed FairPlayIOKit UUID is `316464f8-eade-30ca-938e-2f430b1ed5bc`. The collection SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. The decoded receipt SHA-256 is `47787985d8651eff9da158e07233ade7cb2b32856b9024c27c4e0b3c3d0008ed`. [Auditor](triage_evidence/audit_live_fairplay_selector26_helper.py) [Compressed receipt](triage_evidence/live_fairplay_selector26_helper_audit.json.zst)

```sh
uv run --offline --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_live_fairplay_selector26_helper.py "$COLLECTION" "$RECEIPT"
```

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The four source aggregates, two scratch fills and two workspace probes cover the declared replay cases. | Record reads, repeat counts, status and immediate continuation. | Compare the entry record and resulting field accesses against an ordinary matched transaction. |
| A2. Image-backed state begins with the inherited values and has no concurrent writers in the replay. | Exact state writes and dependent dispatch. | Establish native initialization and ownership of both cells and compare their values at helper entry. |
| A3. The replay models authenticated transfers from resolved image slots and modifiers. | Selected call and return control flow in the model. | Correlate the image identity and transfer sites with a native capture. |

| Impact | Open interface |
| --- | --- |
| High | Connect the post-helper allocation and output ownership to provider copy-back and the synchronous reply fields. |
| High | Match a native request and reply. The supplied RAX trace ends at service open, before method request 2865. [Supplied trace](zut_trace_report.md) |
| Medium | Establish the two state cells' lifetime and the origin of the workspace and encoded record fields. |

QG1-QG3 cover observed routine behavior, premises and interfaces. QG4-QG5 cover byte widths, counts and case variation. QG6-QG7 cover image and receipt identity, recorded recurrence and open native behavior.
