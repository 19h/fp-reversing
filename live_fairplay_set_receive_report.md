# Port-set readiness and the FairPlay receive name on macOS 26C5035r

The installed kernel can make a receive port available to a port set when a message is already queued at attachment. On receive, the set selects a member queue. The message's destination right supplies the receive name that the kernel copies into the user header. CoreFoundation looks up its source with that returned member name. A task-local Mach test confirms the behavior for ports owned by the audit process. A corresponding native `fairplayd` receive remains unobserved. [FairPlay attachment](live_fairplay_port_set_report.md) [CoreFoundation receive and dispatch](live_fairplay_cf_receive_report.md)

```text
queued message -> attach member -> set ready list
                                      |
caller receives on set -> select member queue -> dequeue
                                                  |
                                                  v
                             translate message destination right
                                                  |
                                                  v
                  user header msgh_local_port -> CF source lookup
```

## Current kernel delivery and name translation

| Transition | Current instruction site | Established operation |
| --- | --- | --- |
| Check for a queued message during attachment | `0xfffffe000bd0f8d4` and `0xfffffe000bd0fae4` | The attachment helper reads the existing message head. If a queued message has no selected waiting receiver on the audited branch, the helper marks the member ready in the set. |
| Publish and read readiness | `0xfffffe000bdb587c` and `0xfffffe000bdb3ed0` | The empty ready-list path publishes the link at set waitq +0x18. The receive helper reads that same field. |
| Select a ready member | `0xfffffe000bd10514`, `0xfffffe000bd10524`, `0xfffffe000bdb3f00` | Wait-queue type 5 selects the set helper. The helper loads the member wait queue from the ready link and returns it after its availability and lock checks. |
| Select the head message | `0xfffffe000bd10534` through `0xfffffe000bd1053c` | Unlocks the set, derives the member object from its returned wait queue, and reads the head at member waitq +0x18. |
| Translate the destination right | `0xfffffe000bd0d280`, `0xfffffe000bd122a8` | For the ordinary send-right case where the destination receive object belongs to the receiving space, loads its u32 receive name and returns it through the destination output pointer. |
| Pack the user name | `0xfffffe000bd0d384`, `0xfffffe000bd0d398`, `0xfffffe000bd0e5f8`, `0xfffffe000bd0e608` | Stages the translated names in the internal header, narrows the 64-bit slots, and packs the 32-bit remote and local names in the user header. |
| Route the message in CF | `0x18479eb54`, `0x18479eb7c`, `0x18479d6d4` | Reads the member name at user header +12 B, returns it from the receive helper, and uses it as the key in the mode's source dictionary. |

The port set is the receive argument. It provides a collection of member queues. The decoded message header instead carries the translated destination receive name. Prior FairPlay-specific source evidence supplies the callback and RPC 502 route when CoreFoundation selects the corresponding valid source. [CF callback and RPC 502](live_fairplay_cf_receive_report.md) [Earlier receive selector and modeled ready-member return](kernel_queue_receive_report.md)

The captured kernel UUID `90195379-954d-3ca3-baac-327341f14211` matches the running kernel. The file SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. CoreFoundation UUID `14db37b1-11f1-31ad-9c07-74bed59a8036` comes from the dyld cache with running UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`. All instruction sites are unslid.

## Task-local experiment

The audit allocated two receive rights, A and B, inserted send rights to both, and allocated one initially empty port set. Each test message had a 24 B Mach header and one 4 B marker, for 28 B inline. Receive calls used a 128 B buffer and zero-timeout polls. The experiment checked that successful receives preserved the marker and returned the expected member name in `msgh_local_port` with a null remote name. The five known FairPlay check-ins and successful guest insertions come from a different recording. [Guest namespace and membership](live_fairplay_checkin_report.md)

| Sequence | Receive target | Result |
| --- | --- | --- |
| Send marker 1 to A while A is outside the set. | Set | Timeout |
| Attach A without sending again. | Set | Marker 1, local name A |
| Poll after that receipt. | Set | Timeout |
| Attach B, then send marker 2 to B. | Set | Marker 2, local name B |
| Send marker 3 to attached A, then detach A before polling. | Set | Timeout |
| Poll A directly without resending marker 3. | A | Marker 3, local name A |

The SDK assertions verify header size, field offset, dispositions and timeout status. All messages stayed within the audit task, and cleanup destroyed both port objects and the set. The experiment verifies visibility and name translation for the selected event order. Concurrent waiters, ordering among simultaneously ready members, and live FairPlay message delivery remain unknown.

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The verified kernel and cache images apply to the analyzed build. This supports the reported source locations. | Rehash the fileset and check the kernel, cache and library identities before decoding original instructions. |
| A2 | Queue-link reads and writes refer to the same set waitq. This supports the structural ready-list join. | Recover both call arguments and independently compare the ready-list field, member backlink and returned queue. |
| A3 | The private test uses distinct simultaneously live names and the three selected marker values identify the intended messages. | Check all receive target and local-name fields, marker order, the three timeouts and cleanup. |
| A4 | A matching native daemon event would require the effective source and destination name in the same daemon lifetime. This remains unresolved. | Correlate the member returned by a normal daemon receive with the installed CF dictionary key and callback event. |

**High impact.** A native receive on the run-loop set becomes attributable to a service member when the received local name is linked to the daemon's check-in output.

**Medium impact.** Detachment can make a queued message unavailable through the set while the receive port still holds it. A timeout on the set leaves the detached member's queue state unresolved.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_set_receive.py \
  "$KERNEL_COLLECTION"
```

The audit verifies original branch targets and decoded instruction windows, then reproduces 12 private operations including the six receives or polls above. With B input bytes, F fixups, N symbols and I checked instruction words, time and working space are O(B + F + N + I). [Audit script](triage_evidence/audit_live_fairplay_set_receive.py) [Compressed receipt](triage_evidence/live_fairplay_set_receive_audit.json.zst)
