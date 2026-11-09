#!/usr/bin/env python3
"""Original release/reader/callback source contracts and IDB readback.
O(source bytes+256*bank rules) time/output; no native owner, input or IPC join.
"""
import json,hashlib,re
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,POOL,selected,qword
from capture_daemon_record720 import sha
from recover_daemon_context_lock import ida_output
from recover_daemon_descriptor_producers import verify_used_fixups
SPECS=[('release_caller',0x100be0b98,0x100be0c54),('release_wrapper',0x100435b9c,0x100435d7c),('owner_header',0x100260f00,0x100260f40),('child_release',0x1002084f0,0x100208590),('owner_release',0x1001c6088,0x1001c6118),('release_return',0x100270ac4,0x100270ae4),('reader_caller',0x1003e54a4,0x1003e55f8),('reader_entry',0x10044dd40,0x10044deac),('first_byte',0x100315abc,0x100315b30),('next_byte',0x10022cb40,0x10022cc00),('callback_record',0x100478e00,0x100478ef8),('callback_entry',0x10040f7a4,0x10040f824),('callback_descriptor',0x1010389a0,0x1010389d8),('post_release_frontier',0x100b90ee0,0x100b90ef8)]
def capture():
    spans=[{'label':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':hashlib.sha256(IMAGE.read(a,z-a)).hexdigest()}for n,a,z in SPECS]
    rules=[('release_state1',0x101031da0,0x100e99900,0x9a,0xe7,POOL,0xffffffff998f370a),('release_state2',0x100fc4230,0x101031fa0,0xe4,0x37,POOL,0xffffffffec9e1772),('release_table',0x101031da0,0x100e99900,0x86,0x8c2,POOL,0xffffffffd0c4d1ee),('caller_release',0x100fc4230,0x101031fa0,0x6c,0xcca3,TABLE,0),('child_free',0x100e99a00,0x100f4e390,0x6d,0xcb38,TABLE,0),('owner_free',0x100fc4130,0x101031ea0,0xbb,0xcb4d,TABLE,0),('reader_table',0x100e99a00,0x100f4e390,0xd7,0x88e,POOL,0xffffffffd0c4d1ee)];banks=[{'label':n,**selected(l,r,k,a,b,bias)}for n,l,r,k,a,b,bias in rules]
    slots={int(r['slot'],16)for r in banks}|{0x1010389a8,0x10109ff30};routes=[]
    for j in [0xbbb3,0xbbde,0x479a,0x47bc,0x7143,0x80d1,0x80e4,0xb048,0xb087]:
        a=TABLE+j*8;slots.add(a);routes.append({'index':hex(j),'slot':hex(a),'target':hex(qword(a))})
    ida=json.loads((ROOT/'daemon_record720_release_ida.json').read_text());assert not ida.get('isError');live=[]
    text=ida['content'][0]['text'];body=text.split('[assist:tool-output]',1)[1].split('[/assist:tool-output]',1)[0].strip()
    if body.startswith('{'):rows=json.loads(body)['results']
    else:
        rows=[];lines=body.splitlines();expected=int(re.search(r'^count: (\d+)$',body,re.M)[1])
        for j,line in enumerate(lines):
            m=re.fullmatch(r'\s*(0x[0-9a-fA-F]+)\t(0x[0-9a-fA-F]+)\t(\d+)\t(\d+)\t(\d+)',line)
            if m:
                assert m[1]==m[2]and j+1<len(lines);b=re.fullmatch(r'\s*bytes: ([0-9a-fA-F]+)',lines[j+1]);assert b
                rows.append({'address':m[1],'bytes':b[1],'size_read':int(m[4]),'size_requested':int(m[5])});assert int(m[3])==int(m[5])
        assert len(rows)==expected
    for r in rows:
        a=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert len(b)==r['size_read']==r['size_requested'];orig=IMAGE.read(a,len(b));normalized=[]
        if orig!=b:
            assert a==0x1010389a0 and len(b)==56;check=bytearray(orig);check[8:16]=qword(0x1010389a8).to_bytes(8,'little');assert bytes(check)==b;normalized=['0x1010389a8']
        live.append({'address':hex(a),'size_bytes':len(b),'original_sha256':hashlib.sha256(orig).hexdigest(),'IDA_sha256':hashlib.sha256(b).hexdigest(),'match_kind':'single original fixup normalized'if normalized else'raw identical','normalized_fields':normalized})
    return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_release_ida.json','daemon_record720_handoff_source.json','daemon_record720_handoff_checks.json','daemon_receive_tools.py','recover_daemon_descriptor_producers.py']},'source_sha256':sha(SOURCE),'spans':spans,'exhaustive_banks':banks,'routes':routes,'original_fixups':verify_used_fixups(slots),'live_IDB_matches':live,'native_target_executed':False,'idb_mutated':False,'registry_publication_established':False,'full_goal_complete':False}
def main():
    p=capture();(ROOT/'daemon_record720_release_source.json').write_text(json.dumps(p,indent=2)+'\n');print(json.dumps({'spans':len(p['spans']),'banks':len(p['exhaustive_banks']),'IDA_bytes':sum(r['size_bytes']for r in p['live_IDB_matches'])}),flush=True)
if __name__=='__main__':main()
