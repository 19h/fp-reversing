#!/usr/bin/env python3
"""Original arena-list source and explicit component-input handovers.
O(retained initializer/checkpoint bytes + bounded source) time/space.
No native epoch continuity; empty sentinel state is a declared contract case.
"""
import json,copy,zlib,base64,hashlib
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from capture_daemon_record720 import sha
from validate_daemon_record720_fingerprint import unpack

D=0x1010b5ef0;L=D+48;N=90000;M=0x5e878c613b8123ea
SPECS=[('list_entry',0x1004a0604,0x1004a064c),('nonempty',0x10063106c,0x1006310c0),
 ('fit_guard',0x100552ce0,0x100552d24),('fill',0x10060818c,0x100608220),
 ('patch',0x10058833c,0x1005883e0),('malloc_call',0x100477834,0x100477844),
 ('save_continuation',0x100637de0,0x100637e10),('restore_continuation',0x100634280,0x100634290),
 ('caller',0x10031f248,0x10031f278)]

def group_bytes(data):
    out=[];start=last=None
    for at in sorted(data):
        if last is None or at!=last+1:
            if last is not None:out.append({'address':hex(start),'bytes_hex':bytes(data[j]for j in range(start,last+1)).hex()})
            start=at
        last=at
    if last is not None:out.append({'address':hex(start),'bytes_hex':bytes(data[j]for j in range(start,last+1)).hex()})
    return out

def capture():
    parent=json.loads((ROOT/'daemon_record720_spill_source.json').read_text());storage=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());rows=storage['cases'];cases=[]
    fields=json.loads((ROOT/'daemon_record720_fields_profiles.json').read_text());fr=next(r for r in fields['cases']if r['context']['extension']['readiness_byte']==1);t=unpack(fr);S=int(parent['context']['SP'],16)
    load=[e for e in t['events']if e['pc']=='0x100637e00'and e['kind']=='read'];store=[e for e in t['events']if e['kind']=='write'and int(e['address'],16)==S+0x258];assert len(load)==len(store)==1 and load[0]['address']=='0x10103b7c0'and store[0]['pc']=='0x100637e04'and load[0]['bytes_hex']==store[0]['after_hex']=='48f2310001000000';assert FIXUPS[0x10103b7c0]['target']==0x10031f248
    for label,which in [('sentinel_equal',0),('initial_arena0',0),('initial_arena1',1)]:
        old=rows[which];H=int(old['heap_snapshot']['address'],16);heap=zlib.decompress(base64.b64decode(old['heap_snapshot']['bytes_zlib_base64']));mask=zlib.decompress(base64.b64decode(old['heap_snapshot']['known_mask_zlib_base64']));desc=bytes.fromhex(old['descriptor']['bytes_hex']);dm=bytes.fromhex(old['descriptor']['source_written_mask_hex']);assert len(heap)==len(mask)==N and sum(bool(x)for x in mask)==48
        expected={H:M,H+8:M+N-24,H+24:L,H+32:L,H+N-24:M+N-24,H+N-16:M^(1<<63)}
        for at,value in expected.items():assert heap[at-H:at-H+8]==value.to_bytes(8,'little')and all(mask[at-H:at-H+8])
        additional={D+j:b for j,(b,m)in enumerate(zip(desc,dm))if m};assert len(additional)==80
        if label=='sentinel_equal':
            for off in [72,80]:
                for j,b in enumerate(L.to_bytes(8,'little')):additional[D+off+j]=b
        else:additional.update({H+j:b for j,(b,m)in enumerate(zip(heap,mask))if m})
        c=copy.deepcopy(parent['context']);known={int(g['address'],16)+j for g in c['known_byte_groups']for j in range(len(g['bytes_hex'])//2)};assert not(known&additional.keys())
        c['known_byte_groups']+=group_bytes(additional);c['additional_owners']=[]if label=='sentinel_equal'else[{'address':hex(H),'size_bytes':N}];c['memory_pointer_origins']={hex(S+0x258):'0x10103b7c0'}
        cases.append({'label':label,'context':c,'arena_owner':None if label=='sentinel_equal'else hex(H),'declared_epoch_continuity':False,'initializer_case_index':which,'initializer_source_written_bytes_handed_over':len(additional),'sentinel_equal_is_declared_fixture':label=='sentinel_equal'})
    raw=json.loads((ROOT/'daemon_arena_list_ida.json').read_text());assert not raw.get('isError');body=raw['content'][0]['text'].split('[assist:tool-output]',1)[1].split('[/assist:tool-output]',1)[0].strip();ida=json.loads(body)['results'];assert len(ida)==9;live=[]
    for r in ida:
        a=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert len(b)==256 and IMAGE.read(a,len(b))==b;live.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    spans=[{'label':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':hashlib.sha256(IMAGE.read(a,z-a)).hexdigest()}for n,a,z in SPECS]
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_spill_source.json','daemon_record720_spill_symbolic.json','daemon_record720_fields_profiles.json','daemon_arena_storage_profiles.json','daemon_arena_storage_checks.json','daemon_arena_list_ida.json','daemon_arena_list_symbolic.py']},'spans':spans,'cases':cases,'continuation_provenance':{'source_read':load[0],'source_store':store[0],'slot':'0x10103b7c0','target':'0x10031f248','modifier':'0x7315'},'live_IDB_matches':live,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}

if __name__=='__main__':
    r=capture();(ROOT/'daemon_arena_list_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'cases':len(r['cases']),'source_spans':len(r['spans']),'IDB_bytes':sum(r['size_bytes']for r in r['live_IDB_matches'])}))
