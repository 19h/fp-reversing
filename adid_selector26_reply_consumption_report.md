# CoreADI adid primary selector 26 reply consumption

The primary `adid` helper consumes the selector 26 reply count, descriptor extent and descriptor address in that order. When the counts match the sampled 96 B request, the helper copies the pointed-to bytes before publishing an encoded API status. Both retained return profiles take this copy path, including the nonzero API return with an unchanged output-size cell and descriptor. The current installed arm64e code reproduces the prior ordered PC and instruction-word digests for both complete private runs. [Live slice identity](fairplay_live_slice_identity_report.md) [Primary and Avp transport](adid_iokit_caller_report.md)

| Order | Preferred PC | Field or operation |
| --- | --- | --- |
| 1 | `0x10001f90c` | Read u64 output size at SP+0 B and compare it with 16 B. |
| 2 | `0x10001f950` | Read u32 descriptor extent at SP+16 B. The active comparison checks agreement with the encoded submitted extent. |
| 3 | `0x10001f9b4` | Read u64 descriptor address at SP+8 B. |
| 4 | `0x10001fa48`, `0x10001fa50` | Read from the returned address and store to the original buffer saved in X20. Both observed offset sequences descend from 95 B to 0 B. |
| 5 | `0x10001fa84` | Store the u32 local status at the transport helper record's +4 B field before returning at `0x10001fa9c`. |

The framework's nominal success path copies all 16 inline bytes. The watched descriptor range in `adid` has exactly the three field loads shown above, with no load overlapping the last four descriptor bytes in these profiles. The returned address equals the saved destination in both models, so the 96 reads and 96 stores preserve the pointed-to bytes at API return. The same outer layout and matching-size read order appear in the separately audited `fairplayd` descriptor helper. [Current framework copyout](live_iokit_selector26_inline_reply_report.md) [fairplayd reply fields](daemon_selector26_reply_fields_report.md)

## Status ownership and propagation

At selector 26 call PC `0x10001f908`, the audited phase in W22 is `0x10d0`. For a u32 API result S, the instructions at `0x10001f978`–`0x10001f9a8` yield the following local identity, with all operations modulo 2^32.

```text
A = 0xfddffdaf
M = (0x10d0 + 0x1279) XOR 0xfbbfd817 = low32(A << 1)
W12 = (S XOR A) + 0x027926e0 + (M AND low32(S << 1))
    = S + 0x0059248f
```

The reduction uses `(S XOR A) + 2*(S AND A) = S + A`. It applies to all u32 S when execution enters this block with the recorded phase. The two preserved profiles show how that local word is consumed by two further record layers.

| Modeled API result | Local store `0x10001fa84` and reload `0x10004c120` | Initializer store `0x10002193c` and caller reload `0x100059558` | Caller store `0x100059820` |
| --- | --- | --- | --- |
| Zero, unchanged bytes | `0x0059248f` | `0x0059248f` | `0x00587c85` |
| `0xe00002c7`, unchanged bytes | `0xe0592756` | `0x00587c93` | `0x00587c93` |

The two outer columns are case observations. The general error-code map and the context gate's output for other states remain unknown. The zero-status case reaches the existing caller context gate before writing its final caller-record status. [Caller context and result cases](adid_iokit_caller_report.md)

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The installed arm64e image matches the recorded hashes and original chained-fixup table. | Preferred PCs and replay scope. | Re-read the selected slice and reproduce the prior ordered PC and instruction-word digest for each profile. |
| The retained API model yields output count 16 B, extent 96 B and unchanged pointed-to address. | Selected branches and same-address copy. | Compare watched count, descriptor and source/destination addresses for each modeled return. |
| W22 is `0x10d0` at the local status codec. | Full-width additive status identity. | Verify the reaching phase and rederive the carry mask and additive constant from the raw instructions. |
| Previously retained checkpoint state and private return models describe each case. | Parent and outer record observations. | Watch the three record cells through the original helper and caller. Check their values and read/write order alongside the prior trace digest. |

The byte copy takes O(N) time and O(1) auxiliary storage for N pointed-to bytes. The audit verifies 127,407 instruction visits across two profiles. Native reply shape, runtime payload effects, and the general mapping from local status to the initializer and caller words remain unknown. The latter mapping has medium impact on attributing user-space failures to the provider. A correlated native exchange has high impact. [Audit script](triage_evidence/audit_adid_selector26_reply_consumption.py) [Compressed receipt](triage_evidence/adid_selector26_reply_consumption_audit.json.zst)
