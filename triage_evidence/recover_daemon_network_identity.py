#!/usr/bin/env python3
"""Original daemon network-identity helpers and explicit IOKit API boundaries.

Retained positive paths preserve undefined roots. Separate helper entries and
API return/output fixtures are premises. O(text words+cases*(visits+effects)
+source+queries) time/space; 30 s/query. No native API/IPC or hardware PAC.
"""
import itertools,json,struct
from collections import Counter
from hashlib import sha256
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_iokit_census import text_section
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_pidpath_consumer as Parent

P='daemon_network_identity';ENTRY=0x1000040a8;INNER=0x10000425c
CACHE=0x1010c570a;RETURN=Parent.ERROR
SPECS=[('cache_and_network_fallback',ENTRY,INNER),('iterator_and_MAC_property',INNER,0x1000043ac)]
STUBS={0x100e2a840:0x1010b1bf0,0x100e2a870:0x1010b1c08,0x100e2a900:0x1010b1c50,
       **{0x100e2a910+16*j:0x1010b1b98+8*j for j in range(7)}}
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py',
      'recover_daemon_pidpath_consumer.py','daemon_pidpath_consumer_checks.json',
      'audit_daemon_pidpath_consumer.py','recover_daemon_return_bank_origins.py',
      'recover_daemon_iokit_census.py','probe_daemon_descriptor_producers.py',
      'recover_daemon_environment_outputs.py','audit_daemon_environment_outputs.py']

class Run(Parent.Run):
    def code(self,u,a,n,d):
        self.flush()
        if a in {pc for _,x,y in SPECS for pc in range(x,y,4)}:
            i=next(self.cs.disasm(IMAGE.read(a,4),a))
            if i.mnemonic=='bl':
                target=i.operands[0].imm
                if target in STUBS:
                    slot=STUBS[target]
                    return self.stop('before_unmodeled_import_call',{'symbol':FIXUPS[slot]['target'],
                        'direct_stub':hex(target),'slot':hex(slot),'address_diversity':1,
                        'modifier_source':'original GOT slot address; stub not executed'})
                assert target==INNER
                return self.stop('before_original_internal_helper_call',{'target':hex(target)})
        return super().code(u,a,n,d)

def fresh(placement=0):
    c=next(c for c in Parent.Parent.configuration() if c['placement']==placement)
    v=Run(c);v.cut_stops={RETURN};v.set(30,RETURN)
    return v

def retained():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));out=[]
    for j,c in enumerate(p['result_cases']):
        if c['trace']['boundary']['pc']!=hex(Parent.POSITIVE):continue
        v=Parent.reify(c['trace'],c['configuration']);v.cut_stops=set()
        row=v.interval(Parent.POSITIVE,'retained_positive_path_without_new_roots')
        assert row['boundary']['pc']=='0x1005a8cd4'
        assert row['boundary']['detail']['address']==hex(v.C+0x858)
        assert row['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
        out.append({'parent_case_index':j,'trace':row})
    assert len(out)==8
    return out

def cache_cases():
    out=[]
    for flag,null in itertools.product(range(256),[False,True]):
        v=fresh(0x100 if null else 0);v.cfg={**v.cfg,'flag8':flag,'output_null':null}
        v.image_fixture(CACHE,bytes([flag])+bytes.fromhex('1032547698ba'),'declared_cache_state')
        target=0 if null else Parent.Base.P+0x3000;v.set(0,target)
        if target:v.fixture(target,bytes.fromhex('eeeeeeeeeeee'))
        row=v.interval(ENTRY,'separate_cache_helper_entry')
        assert row['boundary']['pc']==hex(RETURN if flag&1 else 0x1000040d8)
        if flag&1:
            assert int(row['boundary']['registers31'][0],16)==flag
            if target:assert bytes(v.u.mem_read(target,6)).hex()=='1032547698ba'
        else:assert row['boundary']['registers31'][:2]==['0x0',hex(v.C-64)]
        out.append({'trace':row,'output64':hex(target),'warm':bool(flag&1)})
    return out

def inner_cases():
    out=[]
    for name,mode,booleans,parent_status,property_present in [
        ('empty',1,[],0,True),('builtin_false_exhausted',1,[0],0,True),
        ('parent_failure',1,[1],9,True),('missing_MAC',1,[1],0,False),
        ('MAC_present',1,[1],0,True),('mode0_false_builtin',0,[0],0,True),
        ('skip_false_then_true',1,[0,1],0,True),('missing_builtin',1,[None],0,True)]:
        v=fresh();v.cfg={**v.cfg,'inner_case':name,'mode32':mode};s=v.C
        output=Parent.Base.P+0x3000;allocator=Parent.Base.P+0x4000
        v.fixture(output,bytes.fromhex('eeeeeeeeeeee'));v.fixture(allocator,bytes(8))
        v.image_fixture(0x1010b1dc0,struct.pack('<Q',allocator),'declared_allocator_variable_address')
        v.set(0,0x6001);v.set(1,mode);v.set(2,output);start=INNER;rows=[];events=[];ix=0;current=None
        while True:
            row=v.interval(start,'separate_iterator_helper_with_API_premises');rows.append(row)
            if row['boundary']['pc']==hex(RETURN):break
            assert row['boundary']['kind']=='before_unmodeled_import_call'
            symbol=row['boundary']['detail']['symbol'].split('/_',1)[1]
            args=[int(x,16) for x in row['boundary']['registers31'][:8]];status=0;effect=None;void=False
            if symbol=='IOIteratorNext':
                assert args[0]==0x6001
                if ix<len(booleans):current=booleans[ix];status=0x6101+ix;ix+=1
            elif symbol=='IORegistryEntryCreateCFProperty':
                assert args[2:4]==[0,0]
                if args[1]==0x1010b19f8:status=0 if current is None else 0x7001
                else:assert args[1]==0x1010b19d8;status=0x7002 if property_present else 0
            elif symbol=='CFBooleanGetValue':assert args[0]==0x7001;status=current
            elif symbol=='IORegistryEntryGetParentEntry':
                assert args[1]==0x101033c83 and args[2]==s-0x60+0xc
                status=parent_status
                if not status:effect=(args[2],struct.pack('<I',0x6201))
            elif symbol=='CFDataGetBytes':
                assert args[:4]==[0x7002,0,6,output]
                effect=(output,bytes.fromhex('0123456789ab'));void=True
            else:assert symbol in ['IOObjectRelease','CFRelease'];void=symbol=='CFRelease'
            event=v.imported_return(row,status,effect)
            if void:
                v.set(0,0xfedcba9876543210);event['return_registers31'][0]=hex(v.reg(0));event.pop('return32');event['void_return_premise']=True
            event['fixture_symbol']=symbol;events.append(event);start=int(row['boundary']['pc'],16)+4
        out.append({'name':name,'mode32':mode,'intervals':rows,'API_return_premises':events,
                    'result32':int(rows[-1]['boundary']['registers31'][0],16)&0xffffffff,
                    'output6_hex':bytes(v.u.mem_read(output,6)).hex(),'native_API_executed':False})
    return out

def source():
    regions=[];calls=[]
    for name,a,b in SPECS:
        ins=list(CS.disasm(IMAGE.read(a,b-a),a));assert len(ins)*4==b-a
        regions.append({'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
                        'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
        for i in ins:
            if i.mnemonic!='bl':continue
            t=int(i.op_str.removeprefix('#'),16)
            calls.append({'pc':hex(i.address),'target':hex(t),'symbol':FIXUPS[STUBS[t]]['target'] if t in STUBS else 'internal_MAC_iterator_helper'})
    stubs=[]
    for a,slot in STUBS.items():
        ins=list(CS.disasm(IMAGE.read(a,16),a))
        assert [i.mnemonic for i in ins]==['adrp','add','ldr','braa']
        assert ins[-1].op_str=='x16, x17'
        stubs.append({'entry':hex(a),'slot':hex(slot),'bytes_hex':IMAGE.read(a,16).hex(),'symbol':FIXUPS[slot]['target']})
    strings=[]
    for a,text in [(0x101033c83,'IOService'),(0x101033c8d,'IOMACAddress'),(0x101033c9a,'en0'),(0x101033c9e,'en1'),(0x101033ca2,'IOBuiltin')]:
        raw=IMAGE.read(a,len(text)+1);assert raw==text.encode()+b'\0';strings.append({'address':hex(a),'value':text,'bytes_hex':raw.hex()})
    a,n=text_section();raw=IMAGE.read(a,n);refs=[]
    for j,(word,) in enumerate(struct.iter_unpack('<I',raw)):
        if word&0x7c000000!=0x14000000:continue
        off=word&0x3ffffff;off-=1<<26 if off>>25 else 0;pc=a+4*j;target=pc+4*off
        if target in [ENTRY,INNER]:refs.append({'pc':hex(pc),'target':hex(target),'kind':'bl' if word>>31 else 'b','word':hex(word)})
    pointer_refs=[{'slot':hex(a),**r} for a,r in FIXUPS.items() if r['target'] in [ENTRY,INNER]]
    return {'regions':regions,'calls':calls,'stubs':stubs,'strings':strings,
            'original_fixups':Parent.Env.fixups([*STUBS.values(),0x1010b1dc0,0x1010b19d8,0x1010b19e8,0x1010b19f8,0x1010b1a08,0x1010a1718]),
            'direct_branch_census':{'text_address':hex(a),'text_size_bytes':n,'text_sha256':sha256(raw).hexdigest(),'matches':refs},
            'fixup_references':pointer_refs}

def obligations():
    s,out=z3.BitVecs('ni_SP64 ni_output64',64);flag=z3.BitVec('ni_ready8',8);data=z3.BitVec('ni_MAC48',48);qs=[]
    def prove(name,bad,premise=z3.BoolVal(True)):
        q=z3.Solver();q.set(timeout=30000);q.add(premise);assert q.check()==z3.sat;q.add(bad);assert q.check()==z3.unsat
        qs.append({'label':name,'query':q.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    v=Algebra();v.seed('x8',CACHE+1);v.seed('x19',out);v.seed('x21',CACHE&~4095)
    mem(v,CACHE+1,4,z3.Extract(31,0,data));mem(v,CACHE+5,2,z3.Extract(47,32,data));mem(v,CACHE,1,flag)
    v.run_block(0x100004234,0x100004244)
    prove('arbitrary_48_bit_cache_copy_exact_two_plus_four_byte_stores',z3.Or(cell(v,out,4)!=z3.Extract(31,0,data),cell(v,out+4,2)!=z3.Extract(47,32,data)))
    v.run_block(0x100004244,0x100004248)
    prove('warm_return_preserves_entire_flag_byte',v.read('x0')!=z3.ZeroExt(56,flag))
    prove('warm_test_uses_bit_zero_only',((flag&1)!=0)!=(z3.Extract(0,0,flag)==1))
    return qs

def intervals(e):
    return [c['trace'] for c in e['retained_cases']+e['cache_cases']]+[r for c in e['inner_cases'] for r in c['intervals']]

def build():
    e={'retained_cases':retained(),'cache_cases':cache_cases(),'inner_cases':inner_cases()};counts=Counter()
    for r in intervals(e):counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']))
    e.update(scope=__doc__,generator_sha256=sha(__file__),source_sha256=sha(SOURCE),dependencies={n:sha(ROOT/n) for n in DEPS},
             source=source(),source_proofs=obligations(),verified_counts={'retained_cases':8,'cache_cases':512,'inner_cases':8,'intervals':len(intervals(e)),**counts},
             native_API_executed=False,native_daemon_kext_pairing_established=False,full_goal_complete=False)
    return e

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
