#!/usr/bin/env python3
"""Verify bounded app-context contracts against original files.

The register-to-field translation is manually audited in the report. Exhaustive
byte selectors and algebraic identities do not establish full-path reachability.
No target code, RPC, or harness guest is executed. O(B+E) time/space for input
bytes B and evidence E; each selector identity checks all 256 byte inputs.
"""
import hashlib
import json
from pathlib import Path
import struct

from verify_interface_contracts import Image

ROOT = Path(__file__).resolve().parent
BASE = 0xfffffe0008472f20
POOL = 0xfffffe0008471f00
MASK = 0xffffffff


def main():
    image = Image(ROOT.parent/'com.apple.driver.FairPlayIOKit')
    checks = []
    for name in ['app_context_wrappers_native.json','app_context_providers_native.json']:
        for r in json.loads((ROOT/name).read_text()):
            raw = bytes.fromhex(r['bytes'])
            assert image.read(int(r['start'],16),len(raw)) == raw
            checks.append({'source':name,'start':r['start'],'bytes':len(raw)})
    collection = json.loads((ROOT/'app_context_collection_native.json').read_text())
    data = Path(collection['kernel_collection']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == collection['sha256']
    for r in collection['ranges']:
        raw = bytes.fromhex(r['bytes']);off=r['file_offset']
        assert data[off:off+len(raw)] == raw
        assert hashlib.sha256(raw).hexdigest() == r['sha256']
        checks.append({'source':'kernel collection','start':r['start'],'bytes':len(raw)})
    # Independent saved full-text direct-transfer scan and live XrefsTo result.
    transfers = json.loads((ROOT/'native_transfers.json').read_text())
    direct = [x['ea'] for x in transfers if x.get('target')=='0xfffffe000a66a7e0']
    expected = ['0xfffffe000a504dd8','0xfffffe000a504f18','0xfffffe000a504f58']
    assert sorted(direct)==expected
    live = json.loads((ROOT/'app_context_live_xrefs.json').read_text())
    assert sorted(x['from'] for x in live[0]['xrefs'] if x['iscode'])==expected
    assert not [x for x in live[0]['xrefs'] if not x['iscode']]
    assert '0xfffffe000a66a7e0' not in json.loads((ROOT/'local_function_pointer_refs.json').read_text())
    selector_checks = []
    def qword(a):
        return struct.unpack('<Q',image.read(a,8))[0]
    for name,left,right,key,additive,base,target in [
        ('wrapper dispatcher',0xfffffe0007941f60,0xfffffe000794a0d0,5,0xefa,BASE,0xfffffe000a606728),
        ('wrapper typed free',0xfffffe0007949dd0,0xfffffe000792fbc0,0x16,0xea3,BASE,0xfffffe000c4ba368),
        ('wrapper free type descriptor',0xfffffe0007949dd0,0xfffffe000792fbc0,0x73,0x88,POOL,0xfffffe000847ba6c),
        ('wrapper aligned free',0xfffffe0007941f60,0xfffffe000794a0d0,0x98,0xe90,BASE,0xfffffe000c4b9a24),
    ]:
        l,r=image.read(left,256),image.read(right,256)
        values={x^r[l[x]^key] for x in range(256)}
        assert len(values)==1
        constant=values.pop();index=additive+constant;slot=base+8*index
        assert qword(slot)==target
        selector_checks.append({'name':name,'left':hex(left),'right':hex(right),
            'key':hex(key),'constant':hex(constant),'index':hex(index),
            'slot':hex(slot),'target':hex(target),'inputs_checked':256})
    assert qword(POOL+0x33*8)-12==BASE
    # Source-derived representation of the 40-byte argument record.
    fields=[{'offset':0,'width':8,'input':'X0 / char const *'},
            {'offset':8,'width':4,'input':'dispatcher output token'},
            {'offset':16,'width':8,'input':'X1 / signed scalar0'},
            {'offset':24,'width':8,'input':'X2 / signed scalar1'},
            {'offset':32,'width':4,'input':'W3 / origin'},
            {'offset':36,'width':4,'input':'W4 / mode'}]
    # u32(x + c) - u32(-a*x) cancellation in the frame protocol is
    # an identity because a+(-a) == 0 modulo 2^32; no finite sample proof.
    assert (0xef54ff65+0x10ab009b)&MASK==0
    # Conditional constants propagated from the already-proven host lookup.
    w20=0x43f
    w22=((w20+0x72b0ca9f)&MASK)&0x8d4f3bbd
    w23=w22^0xa9e
    w24=w23*0x6fd
    later_w20=w22^0x8f1
    w27=w23*0x224
    rpc_base=later_w20^0xa87
    assert (w22,w23,w24,later_w20,w27,rpc_base)==(0xa9c,2,0xdfa,0x26d,0x448,0x8ea)
    assert qword(BASE+8*0x43f)==0xfffffe000a60ae40
    assert qword(BASE+8*0x448)==0xfffffe000a615f80
    assert qword(BASE+8*(later_w20^0xa21))==0xfffffe000a60b7c8
    mode_indices={str(eq):rpc_base^(eq*((rpc_base-0x6fe)&MASK)) for eq in [0,1]}
    assert mode_indices=={'0':0x8ea,'1':0x906}
    assert qword(BASE+8*0x8ea)==0xfffffe000a60d334
    assert qword(BASE+8*0x906)==0xfffffe000a60b820
    status_xor=0x31ae0066
    statuses={hex(x):hex(x^status_xor) for x in [0xce5159fd,0xce5159fa,0xce515b8a]}
    # These are local status transforms, not an enum assignment.
    assert statuses=={'0xce5159fd':'0xffff599b','0xce5159fa':'0xffff599c','0xce515b8a':'0xffff5bec'}
    assert qword(BASE+8*((0x8cebc8ce+0x731440a8)&MASK))==0xfffffe000a66aba0
    out={'scope':'original-byte consistency and source-derived local algebra; no native execution/PAC/full-path proof',
         'byte_checks':checks,'direct_call_sites':direct,'argument_record_bytes':40,
         'record_fields':fields,'bank_checks':selector_checks,
         'conditional_states':{'host_success_w20':hex(w20),'next_w22':hex(w22),
            'origin_independent_w23':hex(w23),'later_w20':hex(later_w20),
            'sp_178_u32':hex(later_w20),'sp_100_u32':hex(rpc_base),
            'prerequisite':'reach AE40 with AD28 constants, then B55C and B7C8 with the saved scalar state'},
         'rpc_entry_index_by_mode_equal_one':{k:hex(v) for k,v in mode_indices.items()},
         'private_status_decode':statuses,'collection_ranges_verified':len(collection['ranges']),
         'unresolved':['all transitions between the verified slices','complete destination object aliases and lifetime',
                       'alternate mode reachability','kernel consumer names','native port-object ownership']}
    (ROOT/'app_context_contract_validation.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'byte_checks':len(checks),'bank_identities':len(selector_checks),
         'caller_sets_agree':True,'conditional_rpc_indices':'0x8ea/0x906','record_bytes':40}))


if __name__=='__main__':
    main()
