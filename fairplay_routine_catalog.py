#!/usr/bin/env python3
"""Join source, raw-native transfers, and pointer evidence for every IDB routine."""
import collections
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'triage_evidence'
fs=json.loads((OUT/'function_index.json').read_text())
native=json.loads((OUT/'native_function_layout.json').read_text())
transfers=json.loads((OUT/'native_transfers.json').read_text())
ptrs=json.loads((OUT/'local_function_pointer_refs.json').read_text())
vt=json.loads((OUT/'native_detail.json').read_text())['vtable']
by_address={f['address']:f for f in fs}
by_name={f['name']:f for f in fs}
ins=collections.defaultdict(list);outs=collections.defaultdict(list)
for t in transfers:
    if t['function_address']:outs[t['function_address']].append(t)
    if t.get('target') in by_address:ins[t['target']].append(t)
roles={
 'Dqyxc6zf2Sv':('seed generation','diagnostic strings, version checks, IOAESAccelerator operations','established interface role'),
 'Fd7DxKaV3':('in-field seed generation','diagnostics, version 0x82 gate, two 1024-byte AES operations','established interface role'),
 'KLzN':('exchange with Hoover through AppleSTDP2700','service string, OSData request, response-length check, diagnostics','established interface role'),
 'LDdKLPm0':('encrypted seed segment extraction','diagnostics, version/offset checks, fixed-shared-key helper, AES provider','established interface role'),
 'fDkV4Su':('encryptSUInfo provider operation','diagnostics, length/alignment gates and AES provider','established interface role'),
 'J8i0aN2gZ6hA3nG':('encryptWithWrappedKey provider operation','diagnostics, two bounded inputs and AES provider','established interface role'),
 'uej58Beal':('FP message input mapping and core forwarding','selector 26 provider vtable slot 0xA20, descriptors, PRnut72j9','established interface role'),
 'n4HesG39n':('constant status stub for FPDI provider slot','selector 40 provider vtable slot 0xA28; constant return','established implementation'),
 'RUD5XlDtQjk':('sample operation dispatcher wrapper','ucDecryptOneSample -> yt8uPOVu, marshalled task/buffers, core2 tag 0x5A29762C','interface established; inner operation partial'),
 'UeFdbi':('versioned task/message operation wrapper','ucRunVersioned -> qtQQt; frame dispatch and length/status propagation','interface established; inner operation partial'),
 'fcHfFIGhsx':('app-origin context construction interface','three provider constructors, origin parameter, context output and core2 tag 0xD11612F2','interface established; context semantics partial'),
 'cmam7f':('core2 provider-start operation','provider start caller and core2 tag 0x1414EE04','established lifecycle association'),
 'uzZm1ih0':('core2 provider-stop operation','provider stop caller and core2 tag 0xEAB485F6','established lifecycle association'),
 'V2F1SYee':('version query backend','provider uOxAg, UserClient ucGetVersion via vtable 0x8C0','established interface association'),
 'QIWEiU':('protocol capabilities query backend','provider Q5TC6, UserClient ucGetProtocolCapabilities via 0x8C8','established interface association'),
 'wT74ohNhs04Oy':('LSKD query returning a 32-bit field','selector 1, checks response field against 0x1B5B, reads field 0x65','structural role established; field meaning unknown'),
 'R2nPsUOYx6h':('LSKD session request/response interface','selector 6 initKextSession and copied user buffers','established interface association'),
 'WkhY6wTBlbHrpaT0':('encrypted-data message processing interface','selector 18, mapped input, 3072-byte output, two output scalars','established interface association'),
 'ZURJElCowjwysX':('AVD permission request interface','_KDIsAVDDecryptionAllowedParamsIO, version==1, fields 0x72 and 0x7E','established interface association'),
 'sxvHysrIgQq2V':('AVD decrypt request/result adapter','_AVDDecryptParams, sets request fields and updates +0xF0 result','established interface association'),
 'eJ7hqOh8Z':('opaque-context to 64-bit result request','request field 0x72, execute, get field 0x88','structural role established; result meaning unknown'),
 'zzLw2eOVu9pOHqpiNw1K4ki':('set 64-bit request field','field 0x72 receives opaque context; lower helper serializes eight bytes','strong contextual inference'),
 'JmmzRQjC7QF6ZQbBA':('set byte-span request field','pointer/length pairs and field IDs at callers; shared field insertion helper','strong contextual inference'),
 'Hpu7ZBOFQYIwvPDYn9':('set 32-bit request field','integer argument serialized to four bytes then common field insertion','strong contextual inference'),
 'V9Z6DQ1D8vW2ehH1G1m':('read 64-bit response field','64-bit output pointers and field IDs 0x88/0x8C','strong contextual inference'),
 'kfszHrZ3N4HMtvfB5Bws':('read 32-bit response field','32-bit output pointers and field IDs 0x65/0x69','strong contextual inference'),
 'NxUj27MuIpS68FLnG':('response type/version query','output checked against 0x1B5B','strong contextual inference'),
 'TdtbU9WbbSyE1sdsj':('execute request and produce response interface','16 KiB frame, tag 0x563, input object plus output reference','strong contextual inference; transport inside unresolved'),
 'npoKianhz5eqeqJHjqa9':('request/response object cleanup interface','conditional calls on both temporary objects after success/failure','strong contextual inference; exact ownership unknown'),
 'sub_FFFFFE000A561058':('unsigned address ordering guard','BRK if first address exceeds second; returns first address','native confirmed'),
 'sub_FFFFFE000A687ECC':('unsigned address ordering guard','same structure as A561058','native confirmed'),
 'sub_FFFFFE000A5A2064':('synchronous Mach RPC stub, request ID 502','native emission A5A20F8 and fixed request/reply schema','native confirmed'),
 'sub_FFFFFE000A5A22D4':('synchronous Mach RPC stub, request ID 700','native emission A5A2368 and fixed request/reply schema','native confirmed'),
 'sub_FFFFFE000A5A1CF8':('read little-endian u32 from fp-state worker result','worker call then four-byte reconstruction','source established'),
 'sub_FFFFFE000A5A1E98':('write little-endian u32 through fp-state worker','worker read then mode=1 and four-byte update','source established'),
 'sub_FFFFFE000A5A1DB4':('synchronous worker launch/wait bridge','lock, fp-state name, thread start, wait loop, thread deallocation','source established'),
 'sub_FFFFFE000A5A1F94':('NVRAM fp-state worker continuation','IODeviceTree:/options, accessNVRAMProperty, wakeup','source established'),
 'sub_FFFFFE000A606728':('core2 operation demultiplexer','frame tag decoding, table dispatch, shared status field','algebra plus native table targets'),
 'sub_FFFFFE000A55F5E4':('core1 request execution dispatch entry','frame tag decoding and null-output pointer partition','algebra plus native table targets'),
}

def short_name(n):
    m=re.match(r'__ZN30com_apple_driver_FairPlayIOKit(\d+)(.*)',n)
    return m[2][:int(m[1])] if m else n.lstrip('_') if not n.startswith('sub_') else n

catalog=[];category=collections.Counter()
for nf in native['functions']:
    f=by_address.get(nf['start']);n=nf['name'];short=short_name(n)
    role,evidence,confidence=roles.get(short,('unknown','static neighbors and source evidence retained; semantics not assigned','unknown'))
    if f:
        forwarding=re.search(r'return ([A-Za-z_]\w*)\(([^;]*)\);',f['body'],re.S)
        if confidence=='unknown' and n.startswith('__ZN30com_apple_driver_FairPlayIOKit') and forwarding and not re.search(r'\bif\s*\(',f['body']) and len(f['body'])<1600:
            role='provider wrapper forwarding to '+forwarding[1];evidence='supplied C forwarding expression; argument and native-edge evidence retained';confidence='established wrapper association'
        returns=re.findall(r'return (0x[0-9A-F]+)LL;',f['body'])
        # Whole-body single-return patterns only, avoiding a conditional error path.
        if returns and f['body'].count('return ')==1 and not re.search(r'\bif\s*\(',f['body']) and len(f['body'])<1500:
            role='constant return '+returns[0];evidence='single unconditional return in supplied C; check native instructions before using as reachability proof';confidence='source established'
    row={'address':nf['start'],'name':n,'short_name':short,'role':role,'role_evidence':evidence,'confidence':confidence,
         'c_lines':[f['line'],f['end_line']] if f else None,'native_chunks':nf['chunks'],
         'native_direct_incoming':ins[nf['start']],'native_transfers':outs[nf['start']],
         'pointer_slots_to_entry':ptrs.get(nf['start'],[]),
         'strings':f['strings'] if f else [],'globals':f['globals'] if f else [],
         'textual_callers':f['resolved_textual_callers'] if f else [],
         'textual_callees':f['resolved_textual_callees'] if f else [],
         'asm_transfer_annotations':f['asm_transfers'] if f else []}
    catalog.append(row);category[confidence]+=1
(OUT/'routine_catalog.json').write_text(json.dumps(catalog,indent=2)+'\n')

# Join recovered virtual slots, preserving the distinction from direct call edges.
routes=[];by_offset={int(x['offset'],16):x for x in vt}
for f in fs:
    if f['name'].startswith('__ZN40com_apple_driver_FairPlayIOKitUserClient') and '_vfpthunk_' not in f['name']:
        for off in sorted(set(int(x,16) for x in re.findall(r'\*\(_QWORD \*\)\(v\d+ \+ (0x[0-9A-F]+)\)',f['body']))):
            if off in by_offset:routes.append({'userclient':f['name'],'address':f['address'],'line':f['line'],'offset':hex(off),'provider':by_offset[off]['name'],'provider_address':by_offset[off]['value']})
(OUT/'userclient_provider_routes.json').write_text(json.dumps(routes,indent=2)+'\n')
print(json.dumps({'native_routines_catalogued':len(catalog),'confidence_categories':dict(category),'virtual_routes_recovered':len(routes)},indent=2))
