#!/usr/bin/env python3
"""Complete private generated stream, refill contracts and caller data flow.

Main paths add no input bytes or returns. Separate controls replace one
word register or one u32 generation counter. Inherited source-compatible
caller/constructor premises do not establish a coherent native epoch.
O(parent bytes+visits+effects+packed receipts) time/storage. Native target
API/IPC, allocation/free, hardware PAC and IDB mutation never execute.
"""
import json,struct
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes,fixture_bytes
from recover_daemon_environment_outputs import fixups
import recover_daemon_postseed_output as Parent

P='daemon_generated_stream';ENTRY=Parent.NEXT;BYTE=Parent.BYTE;REFILL=0x100b32e70
DONE=0x100a6d370;ADMISSION=0x100a6e57c;TWIST_ENTRY=0x100a6cd1c
NEXT=0x10054b43c;G=Parent.G;COUNTER=0x1010c8258
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_postseed_output.py',
      'audit_daemon_postseed_output.py','daemon_postseed_output_checks.json','daemon_postseed_output_audit.json',
      'recover_daemon_environment_outputs.py','recover_daemon_context_unseal.py',
      'recover_daemon_return_bank_origins.py','audit_daemon_readiness_arena.py','audit_daemon_network_record.py']
unpack=Parent.Parent.Parent.unpack;pack=Parent.Parent.Parent.pack;compact=Parent.Parent.Parent.compact_fixtures
def restore(row):return Parent.restore(row)
def entry(row):
    return {**row,'source_writes':[],'boundary_NZCV':row['entry_NZCV'],
            'boundary':{'pc':row['entry_PC'],'registers31':row['entry_registers31'],'Q_registers32':row['entry_Q_registers32'],'SP':row['caller_SP']}}
def word(s,a,n=4):return int.from_bytes(bytes(s[a+j] for j in range(n)),'little')
def rc(row):return {k:len(row[f]) for k,f in [('source_visits','source_visits'),('reads','source_reads'),('writes','source_writes'),('logical_edges','logical_edges'),('source_calls','source_calls')]}

def zero_key(row):
    s=fixture_bytes(row,'private')|fixture_bytes(row,'image');sp=int(row['caller_SP'],16)
    a=int(row['entry_registers31'][4],16)+int(row['entry_registers31'][2],16)-1
    ci=word(s,word(s,sp+0x160,8));cache=word(s,word(s,sp+0x168,8),8);cached=word(s,cache+(ci&0x0ba3ccc8))
    r=(cached+(a&0xffffffff))&0xffffffff;mask=word(s,0x1010c6800,8)^0xa7a730ec;text=word(s,0x1010ca2a8,8)^0x12af5504870a589f
    aa=text+(((r+0x0ba3ccc8)&0xffffffff)&mask);ba=text+(((r+0x0ba3ccca)&0xffffffff)&mask)
    return (0xd7^(31*a)^IMAGE.read(aa,1)[0]^IMAGE.read(ba,1)[0])&255

def case(index,parent):
    old=unpack(parent['intervals'][-1]['packed']);v=restore(old);initial=state_bytes(old);rows=[];counts=Counter();used=set();first_byte=first_refill=None
    def run(pc,targets,label):
        v.cut_stops=set(targets);r=v.interval(pc,label);rows.append({'label':label,'packed':pack(r)});counts.update(rc(r))
        used.update(int(x['address'],16) for x in r['source_reads'] if int(x['address'],16) in FIXUPS);compact(v);return r
    pc=ENTRY
    while pc!=DONE:
        if pc==ENTRY:r=run(pc,[BYTE,REFILL],'byte_shift_and_cached_root_refresh')
        elif pc==BYTE:
            r=run(pc,[ENTRY,DONE],'encoded_byte_attempt')
            if first_byte is None:first_byte=r
        elif pc==REFILL:
            r=run(pc,[Parent.TWIST1],'counter_record_refill_to_twist')
            if first_refill is None:first_refill=r
            for a,b,label in [(Parent.TWIST1,Parent.TWIST2,'refill_first_twist227'),(Parent.TWIST2,Parent.TWIST_LAST,'refill_second_twist396'),
                              (Parent.TWIST_LAST,Parent.SELECT,'refill_last_twist_and_retained_index'),(Parent.SELECT,Parent.COUNTER,'refill_selection_and_counter_comparison'),
                              (Parent.COUNTER,BYTE,'refill_counter_and_temper')]:r=run(a,[b],label)
        else:raise AssertionError(hex(pc))
        pc=int(r['boundary']['pc'],16)
        assert len(rows)<160
    completed=state_bytes(r);sp=int(old['boundary']['SP'],16);output=word(initial,sp+0xa0,8)
    result32=bytes(completed[output+j] for j in range(32));final_array=bytes(completed[G+j] for j in range(2496))
    r=run(DONE,[],'status_epilogues_arena_copy_scratch_overwrite_to_malloc')
    assert r['boundary']['pc']==hex(NEXT) and r['boundary']['detail']['symbol']=='libSystem/_malloc' and r['boundary']['registers31'][0]=='0x68'
    return {'parent_case_index':index,'intervals':rows,'counts':dict(counts),'used_fixups':[hex(x) for x in sorted(used)],
            'output_pointer':hex(output),'completed_output32_hex':result32.hex(),'final_generated_array2496_hex':final_array.hex(),
            'final_private_output32_hex':bytes(state_bytes(r)[output+j] for j in range(32)).hex(),
            'arena_output_base':'0x6500115b54','arena_output32_hex':bytes(state_bytes(r)[0x6500115b54+j] for j in range(32)).hex(),
            'final_boundary':r['boundary'],'final_NZCV':r['boundary_NZCV']},first_byte,first_refill

def zero_control(index,before):
    v=restore(entry(before));key=zero_key(before);old=int(before['entry_registers31'][9],16);new=key*0x01010101;v.set(9,new)
    rows=[];counts=Counter();pc=BYTE
    for k in range(3):
        for a,targets,label in [(pc,[ENTRY],'forced_zero_byte_attempt'),(ENTRY,[BYTE,REFILL],'forced_zero_shift_route')]:
            v.cut_stops=set(targets);r=v.interval(a,label);rows.append(pack(r));counts.update(rc(r));compact(v)
        pc=int(r['boundary']['pc'],16)
    assert pc==REFILL
    return {'parent_case_index':index,'parent_main_interval_index':1,'entry_register_effect':{'register':'x9','before':hex(old),'after':hex(new),
            'provenance':'separate_three_zero_attempt_word_premise'},'zero_source_byte':hex(key),'intervals_packed':rows,'counts':dict(counts),
            'final_boundary':r['boundary'],'final_NZCV':r['boundary_NZCV']}

def counter_control(index,before,value):
    v=restore(entry(before));f={'address':hex(COUNTER),'bytes_hex':struct.pack('<I',value).hex(),'provenance':'separate_current_generation_counter32'}
    v.image_fixture(COUNTER,bytes.fromhex(f['bytes_hex']),f['provenance']);v.cut_stops={ADMISSION,TWIST_ENTRY};r=v.interval(REFILL,'separate_zero_or_max_generation_counter')
    assert r['boundary']['pc']==hex(ADMISSION if value==0 else TWIST_ENTRY)
    return {'parent_case_index':index,'counter32':value,'effect':f,'parent_main_interval_index':7,'intervals_packed':[pack(r)],'counts':rc(r)}

def source():
    spans=[('shift_and_roots',ENTRY,0x100bf6dc4),('refill',REFILL,0x100b330bc),('refill_record_leaf',0x10041a5e0,0x10041a670),
           ('completion_status_and_epilogue',DONE,0x100a6d3d0),('adapter_return',0x100add7d8,0x100add7fc),
           ('caller_frame_restore',0x100605f1c,0x100605f5c),('arena_byte_copy',0x100576f0c,0x100576f4c),
           ('private_scratch_overwrite',0x10054b728,0x10054b768),('caller_fields',0x1005bf610,0x1005bf650),
           ('pending_allocation',0x10054b3c8,0x10054b440)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in spans]

def intervals(e):
    for c in e['cases']:
        for p in c['intervals']:yield unpack(p['packed'])
    for c in e['zero_controls']+e['counter_controls']:
        for p in c['intervals_packed']:yield unpack(p)

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));cases=[];zeros=[];controls=[];counts=Counter();used=set()
    for j,c in enumerate(p['cases']):
        main,byte,refill=case(j,c);cases.append(main);zeros.append(zero_control(j,byte))
        controls.extend(counter_control(j,refill,value) for value in [0,0xffffffff]);print(json.dumps({'case':j,'main':main['counts']}),flush=True)
    e={'cases':cases,'zero_controls':zeros,'counter_controls':controls}
    total=0
    for r in intervals(e):
        total+=1;counts.update(rc(r));used.update(int(x['address'],16) for x in r['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'source_regions':source(),'source_fixups':fixups(used),**e,'verified_counts':{'cases':len(cases),'zero_controls':len(zeros),'counter_controls':len(controls),'intervals':total,**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
