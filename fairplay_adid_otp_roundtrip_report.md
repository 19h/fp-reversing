# fairplayd and adid CoreADI OTP round trip

The exact 20 B request recovered from `fairplayd` produces two different four-byte replies in the installed `adid` image under two explicit peer models. A NULL `adi-client` lookup produces `ffff4ff2` before the provider reads any request bytes. The archived `akd` peer model allows command dispatch and produces `ffff4ffb`. In both cases the client propagates the provider's exact bytes to its original caller as W0 and leaves all four output cells zero. The installed `fairplayd` arm64e signature omits the `adi-client` declaration. Its effective runtime entitlement result and the native exchange remain unknown. [Request serializer](daemon_adid_request_origin_report.md) [Client reply reader](daemon_adid_reply_fields_report.md)

```text
fairplayd: source-built data -> pending synchronous XPC send
                                     |
                                     v
adid:                  get_data -> peer checks
                                     |
                   +-----------------+-----------------+
                   |                                   |
             NULL lookup                        archived peer model
             no byte reads                      reads all 20 bytes
             ffff4ff2                            ffff4ffb
                   |                                   |
                   +-------------- data ---------------+
                                     |
                       _xpc_dictionary_send_reply
                                     |
                       fairplayd: copy, BE32, W0
```

## Signature and peer evidence

The installed and pinned `fairplayd` arm64e slices have UUID `204741e9-b89f-32b4-9321-51f3975c7cac` and match at CodeDirectory hash `3e40588fde6998b2782a2f48bed6e2473f851dfa`. Independent CodeDirectory parsing and `codesign` agree. The two `codesign` entitlement dictionaries are equal, contain ten keys and omit `adi-client`. This is a file declaration result. The provider uses the incoming XPC audit token to construct a Security task and asks that task for `adi-client` at `0x1001691c8`. The effective value for the native sender was not observed. [Earlier process slice binding](live_fairplay_adid_ipc_report.md) [Provider peer inspection](adid_receiver_report.md)

The unchanged producer bytes are `00000001 cfe0b46a 00000001 fffffffffffffffe`. All eight prior clock-success send receipts contain that same 20 B dictionary value. The provider runs from the retained peer callback entry at `0x100029fc8` on the installed `adid` arm64e image. The `akd` control and the exact `fairplayd` request under the archived peer model have identical ordered PC-and-instruction digests, also equal to the historical `akd` receipt. [Prior provider ingress and control paths](adid_otp_ingress_report.md) [Named akd operation](akd_adid_client_report.md)

| Original bytes and peer premise | Request bytes read by provider | OTP parser reached | Reply bytes | Signed i32 |
| --- | ---: | --- | --- | ---: |
| Named `akd` OTP control with its archived peer model | 20 | `0x10016dab8` | `ffff4ffb` | −45,061 |
| Exact `fairplayd` request with unchanged archived peer model | 20 | `0x10016dab8` | `ffff4ffb` | −45,061 |
| Exact `fairplayd` request with NULL lookup and archived diagnostic path | 0 | No | `ffff4ff2` | −45,070 |
| Exact `fairplayd` request with NULL lookup and installed `fairplayd` diagnostic path | 0 | No | `ffff4ff2` | −45,070 |

The two NULL-lookup traces have identical ordered PC-and-instruction digests. The modeled `proc_pidpath` at `0x100169ac8` returns 23 B for the archived diagnostic path and 71 B for the installed executable path, excluding NUL. Both traces request the dictionary value at `0x1000aa598`, then return the error without reading any of its 20 bytes or querying `kern.hv_vmm_present`. This is evidence for the observed peer-check path. Audit identity, the Security task API, path replies and provider runtime state are private model inputs.

## Reply custody and interface boundaries

On the command-dispatch path, source writes at `0x1002028bc`, `0x1002028a8`, `0x1002028c4`, and `0x1002028d0` define the eventual four-byte response in offset order. Original code reads those bytes at `0x1001fcca0` and writes offsets 0 through 3 to the output buffer at `0x1001fcca8`. The NULL-lookup path instead writes offsets 3 through 0 at `0x1001fcd80`. In both paths the core returns wrapper status 0 at `0x1000aa910`, with a nonzero output pointer and extent 4. The pointer and extent reach the `data` setter at `0x1000aa9fc`. The same reply dictionary reaches the XPC send at `0x1000aaa70`. Wrapper status 0 does not encode the application status carried by the payload.

Eight `fairplayd` continuations per provider result replay the original send prefix and receive exactly the four source-written bytes. Each takes its four byte reads from offsets 0 through 3 of the owned copy, returns W0 at `0x100701a7c`, and leaves the 8 B, 4 B, 8 B and 4 B caller cells zero. The previous opaque-frame noninterference check passes on both results. The 4 B error copy and return have the same ownership outcome in the two checked branches.

No provider replay visits the known primary FairPlayIOKit or Avp acquisition and method sites or records an IOKit API call. These paths establish the XPC emission site and client correspondence under the supplied models. The Mach destination and reply right names for an actual exchange, its effective peer state, native delivery and any causal relation to a kext operation remain unknown. A literal search for this service, selector and observed results in `annotated-strace-rax-user.txt` yielded no match and supplies no transaction-level corroboration.

## Assumptions and verification

| ID | Dependent result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | Source labels and visited code belong to the checked arm64e images. | Pin the installed provider's universal and arm64e hashes, compare all 11,451 fixups with a fresh `dyld_info` walk, and compare the client's architecture-specific CodeDirectory and embedded entitlement dictionary. A different image needs its own mapping. |
| A2 | The modeled peer state defines each provider outcome. | Recover the exact original request from all eight source receipts. Compare the named `akd` control with changed request bytes under otherwise unchanged inputs. Swap the diagnostic path under the NULL premise. Effective native lookup and command admission are unknown. |
| A3 | Provider output is source-written and the same byte sequence reaches the client. | Verify the last store for every byte, the staged source on the dispatch path, the response pointer and extent at the wrapper, and equality of the XPC reply object at setter and send. Check full client prefix digests and BE32 return in all 16 continuations. |
| A4 | The observed routes are independent of the earlier unresolved client frame values. | Follow opaque bytes and register dependencies through the actual suffix and reject consumption by address, branch, import or result. Other reply paths require their own check. |
| A5 | No new kext edge is observed for these callbacks. | Search the full executed provider PC sequences and API events for the established acquisition and transport sites. Other peer/environment states and independent IOKit operations are outside the four callbacks. |

The audit covers four provider callbacks and 113,806 original provider visits, plus 16 client continuations and 37,744 original client visits. The source and evidence processing use O(B + F + V + E) time and space per fixed-size exchange, with B image bytes, F fixups, V visits and E retained events. The source-writer lookback is repeated for four bytes. Primary evidence is the pinned Mach-O code and CodeDirectories, the archived peer snapshot, and the two retained client receipts. [Auditor](triage_evidence/audit_fairplay_adid_otp_roundtrip.py) [Compressed audit](triage_evidence/fairplay_adid_otp_roundtrip_audit.json.zst)

The signed declaration and the NULL-lookup result have high impact on attributing the named OTP path to the native daemon. The identical diagnostic-path traces have medium impact on interpreting path observations as evidence of peer admission. The separation between wrapper status and wire status is required when comparing instrumentation at the two ends.
