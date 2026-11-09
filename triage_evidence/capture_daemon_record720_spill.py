#!/usr/bin/env python3
"""Capture a source-derived stopped context, spill census and IDB windows.
O(text words + parent visits/effects) time; O(parent case + known bytes) space.
No missing byte is given a value and no native target/IDB mutation occurs.
"""
import json,struct,hashlib
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM
from capture_daemon_record720 import sha
from validate_daemon_record720_fingerprint import unpack
from daemon_digest_output_access import register_access,key
from recover_daemon_iokit_census import text_section

SPECS=[('restore',0x100633ee8,0x100633f68),('save',0x100638710,0x100638784),
 ('next',0x1004cd280,0x1004cd308),('selector_bytes',0x100540a00,0x100540a68),
 ('selector',0x1004a95dc,0x1004a96f4),('descriptor_read',0x1004a0604,0x1004a0624),
 ('arena_publication',0x10032a54c,0x10032a574)]
CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);CS.detail=True

def capture():
    profiles=json.loads((ROOT/'daemon_record720_fields_profiles.json').read_text());row=next(r for r in profiles['cases']if r['context']['extension']['readiness_byte']==1);t=unpack(row);assert t['boundary']['pc']=='0x100633f04';c=row['context'];ram={};known={key(n)for n in c['entry_defined_GPRs']}
    for g in c['known_byte_groups']:
        for j,b in enumerate(bytes.fromhex(g['bytes_hex'])):ram[int(g['address'],16)+j]=b
    for pc,raw in t['steps']:
        assert IMAGE.read(pc,4).hex()==raw;i=next(CS.disasm(bytes.fromhex(raw),pc));reads,writes=register_access(i);known.update(key(i.reg_name(r))for r in writes)
    if t['API_models']:known.update(['x'+str(j)for j in range(18)]+['x30'])
    for e in t['events']:
        if e['kind']=='write':
            for j,b in enumerate(bytes.fromhex(e['after_hex'])):ram[int(e['address'],16)+j]=b
    assert len(t['API_models'])==1 and t['API_models'][0]['binding']['symbol']=='_malloc'
    S=int(t['boundary']['SP'],16);assert all(S+0x2e8+j not in ram for j in range(8))
    groups=[];addresses=sorted(ram);start=last=None
    for a in addresses:
        if last is None or a!=last+1:
            if last is not None:groups.append({'address':hex(start),'bytes_hex':bytes(ram[x]for x in range(start,last+1)).hex()})
            start=a
        last=a
    groups.append({'address':hex(start),'bytes_hex':bytes(ram[x]for x in range(start,last+1)).hex()})
    spans=[{'label':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':hashlib.sha256(IMAGE.read(a,z-a)).hexdigest()}for n,a,z in SPECS]
    raw=json.loads((ROOT/'daemon_record720_spill_ida.json').read_text());assert not raw.get('isError');body=raw['content'][0]['text'].split('[assist:tool-output]',1)[1].split('[/assist:tool-output]',1)[0].strip();rows=json.loads(body)['results'];assert len(rows)==7;live=[]
    for r in rows:
        a=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert len(b)==512 and IMAGE.read(a,len(b))==b;live.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    A,N=text_section();text=IMAGE.read(A,N);census=[];overlaps=[]
    for j,(w,)in enumerate(struct.iter_unpack('<I',text)):
        if w&0xffffffe0==(0xf90003e0|((0x2e8//8)<<10)):
            pc=A+4*j;i=next(CS.disasm(IMAGE.read(pc,4),pc));census.append({'pc':hex(pc),'word':hex(w),'instruction':i.mnemonic+' '+i.op_str})
        if (w>>5)&31!=31:continue
        span=None
        if w&0x3b000000==0x39000000:
            vector=(w>>26)&1;op=(w>>22)&3
            if op==0 or(vector and op==2):
                width=16 if vector and op==2 else 1<<(w>>30);off=((w>>10)&4095)*width;span=(off,width)
        elif w&0x3a000000==0x28000000 and not((w>>22)&1):
            vector=(w>>26)&1;op=w>>30
            if (vector and op<=2)or(not vector and op in[0,2]):
                width=(4<<op)if vector else(4 if op==0 else 8);imm=(w>>15)&127;imm-=128 if imm&64 else 0;mode=(w>>23)&3;off=0 if mode==1 else imm*width;span=(off,width*2)
        if span is not None and span[0]<0x2f0 and 0x2e8<span[0]+span[1]:
            pc=A+4*j;i=next(CS.disasm(IMAGE.read(pc,4),pc));o=next(o for o in i.operands if o.type==ARM64_OP_MEM);assert i.mnemonic.startswith(('str','stp','stnp'))and i.reg_name(o.mem.base)=='sp'and o.mem.disp==span[0]
            overlaps.append({'pc':hex(pc),'word':hex(w),'instruction':i.mnemonic+' '+i.op_str,'SP_offset_bytes':span[0],'store_size_bytes':span[1]})
    assert len(census)==48
    context={'parent_case_index':row['case_index'],'parent_payload_sha256':row['payload_sha256'],'source_visits_consumed':len(t['steps']),'entry_PC':t['boundary']['pc'],'SP':t['boundary']['SP'],'outer_SP':c['SP'],'known_GPRs':{('x'+str(j)):v for j,v in enumerate(t['boundary']['registers31'])if 'x'+str(j)in known},'known_byte_groups':groups,'known_byte_count':len(ram),'frame_owner':{'address':hex(int(c['SP'],16)-0x4000),'size_bytes':0x18000},'save_blocks_absent_from_parent_prefix':all(pc not in[0x100638710,0x100638874,0x1008010bc]for pc,b in t['steps']),'unavailable_bytes_not_assigned':True}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_fields_profiles.json','daemon_record720_fields_checks.json','daemon_record720_spill_ida.json','daemon_digest_output_access.py']},'spans':spans,'context':context,'live_IDB_matches':live,'STR64_SP_2E8_census':census,'immediate_SP_store_overlap_census':overlaps,'census_scope':'Aligned unsigned-immediate single stores and immediate pair stores overlapping [SP+0x2E8,SP+0x2F0) across __text; exact STR64 subset separated. SP aliases, register offsets, prior SP movement and frame equivalence excluded. Candidates are not native producers.','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}

if __name__=='__main__':
    r=capture();(ROOT/'daemon_record720_spill_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'known_bytes':r['context']['known_byte_count'],'source_spans':len(r['spans']),'literal_candidates':len(r['STR64_SP_2E8_census'])}))
