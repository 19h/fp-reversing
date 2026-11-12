#!/usr/bin/env python3
"""Independent scan-entry replay, integer models and original-byte components.

Does not import the new producer. O(C*(B+V*J+P*F+R)+C*(10240*102+
3072*24+1024*9)) time; bounded private maps; 30 s/SMT query.
No native target/API/IPC or IDB operation.
"""
import json
from pathlib import Path
from collections import Counter
from hashlib import sha256
import z3
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as U
import audit_corefp_phase_parameters as F
from verify_daemon_reader_record_payloads_publication import read
ROOT=F.ROOT;C=F.C;SHA=F.SHA;M=2**32-1;D=0xeb3e515b
SPECS=[('encode',0x1b4790,0x1b47c0),('first_initializer',0x1b51d4,0x1b536c),('decode',0x1b55f0,0x1b5620),
 ('second_initializer',0x1b63e4,0x1b6530),('control_writer',0x1b4dec,0x1b4e10)]


def mix64(seed,variable_shift=2):
    def chain(x,steps):
        for sign,n in steps:x=(x+sign*(x//2**n))%2**64
        return x
    a=chain((seed+0x57591561cfca294a)%2**64,[(1,31),(1,11),(1,variable_shift)])
    b=chain((a+0x9801c171577bca01)%2**64,[(-1,29),(-1,14),(1,1)])
    c=chain((b+0x6edf733dd7daa684)%2**64,[(1,29),(1,10),(1,3)])
    d=chain(c^0xa4ee2625fd04e1d5,[(1,30),(-1,14),(1,4)])
    e=chain((d+0x115191787f9f5c08)%2**64,[(-1,30),(-1,13),(1,2)])
    f=chain((e+0xe8445ed68b2a859b)%2**64,[(1,24),(1,11),(1,2)])
    g=chain((f+0x745ace6e274e4c6c)%2**64,[(-1,31),(1,10),(-1,7)])
    h=chain((g+0xe3d0b888f4003be8)%2**64,[(1,25),(1,10),(-1,7)])
    j=chain((h+0x0680844d79c49795)%2**64,[(1,26),(-1,15),(1,5)])
    return [(a^d^g)%2**32,(b^e^h)%2**32,(c^f^j)%2**32]


class Replay(F.Replay):
    def __init__(self,*args):super().__init__(*args);self.components={};self.scan_ends=[]
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert name not in self.components;self.components[name]={'entry':F.F.A.capture(self)}
            if pc==C.BASE+hi:self.components[name]['end']=F.F.A.capture(self)
        if pc in [C.BASE+0x1b54d0,C.BASE+0x1b66ac]:self.scan_ends.append(F.F.A.capture(self))
        return super().code(u,pc,n,d)


class Component:
    def __init__(self,p,b,s):
        self.b=b;self.s=s;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);mapped=set()
        for row in p['initial_RAM']:
            at=int(row['address'],16);self.u.mem_map(at,4096);self.u.mem_write(at,C.unpack(row['payload']));mapped.add(at)
        for row in b['reads']:
            at=int(row['address'],16);raw=bytes.fromhex(row['bytes_hex'])
            for page in range(at&~4095,(at+len(raw)+4095)&~4095,4096):
                if page not in mapped:self.u.mem_map(page,4096);self.u.mem_write(page,C.initial_page(s,page));mapped.add(page)
            self.u.mem_write(at,raw)
        _,self.lo,self.hi=next(x for x in SPECS if x[0]==b['name']);self.source=s.read(self.lo,self.hi-self.lo)
        for page in range((C.BASE+self.lo)&~4095,(C.BASE+self.hi+4095)&~4095,4096):
            if page not in mapped:self.u.mem_map(page,4096);self.u.mem_write(page,C.initial_page(s,page));mapped.add(page)
        self.u.mem_write(C.BASE+self.lo,self.source);self.sp=int(b['entry']['CPU']['SP'],16);self.stack=bytes.fromhex(b['entry']['stack1312_hex'])
        self.u.mem_write(self.sp,self.stack);C.restore(self.u,b['entry']['CPU']);self.context=self.u.context_save()
        frame,stack=self.run();assert frame==b['end']['CPU']and stack.hex()==b['end']['stack1312_hex']
    def run(self,registers=None,stack=None):
        self.u.context_restore(self.context);self.u.mem_write(self.sp,self.stack if stack is None else bytes(stack))
        for j,v in (registers or {}).items():self.u.reg_write(getattr(U,'UC_ARM64_REG_X'+str(j)),v)
        self.u.emu_start(C.BASE+self.lo,C.BASE+self.hi,count=(self.hi-self.lo)//4+1);assert self.u.reg_read(U.UC_ARM64_REG_PC)==C.BASE+self.hi
        return C.frame(self.u),bytes(self.u.mem_read(self.sp,1312))
    def intact(self):assert bytes(self.u.mem_read(C.BASE+self.lo,len(self.source)))==self.source


def initializer_cases(component,kind):
    b=component.b;frame=b['entry']['CPU']['X31'];inputs=[6,5,1]if not kind else[15,6,14];outputs=[26,30,22]if not kind else[15,10,11];seedreg=7 if not kind else 1
    seed=int(frame[seedreg],16);base=[int(frame[j],16)&M for j in inputs];cases=0;digest=sha256()
    def run(seed,words):
        nonlocal cases
        regs={seedreg:seed,**dict(zip(inputs,words))};actual,stack=component.run(regs);assert stack==component.stack
        wanted=[x^y for x,y in zip(words,mix64(seed))];got=[int(actual['X31'][j],16)&M for j in outputs];assert got==wanted
        digest.update(json.dumps(actual,sort_keys=True).encode());cases+=1
    for lane in range(8):
        for value in range(256):run((value<<(lane*8))^0x9e3779b97f4a7c15,base)
    for j in range(3):
        for lane in range(4):
            for value in range(256):
                words=base[:];words[j]=(value<<(lane*8))^(((j+1)*0x6a09e667)&M);run(seed,words)
    controls=[]
    if not kind:
        stack=bytearray(component.stack);stack[0x348:0x350]=bytes(8);actual,after=component.run(stack=stack);assert after==stack
        ctrl=0x32f291f3&0xcd0d6df7;n=(ctrl-0x4d23)%64;got=[int(actual['X31'][j],16)&M for j in outputs]
        assert n!=2 and got==[x^y for x,y in zip(base,mix64(seed,n))]and got!=[x^y for x,y in zip(base,mix64(seed))]
        controls.append({'control_u64':'0x0','shift':n,'seed_u64':hex(seed),'input_words_u32':list(map(hex,base)),'actual_words_u32':list(map(hex,got)),'fixed_two_candidate_rejected':True})
    component.intact();assert cases==5120
    return {'name':b['name'],'finite_initializer_cases':cases,'finite_source_visits':cases*(component.hi-component.lo)//4,'output_words_checked':cases*3,
      'ordered_frames_sha256':digest.hexdigest(),'off_premise_controls':controls,'source_bytes_preserved':True}


def field_cases(encoder,decoder):
    cases=0;digest=sha256()
    for j in range(3):
        for lane in range(4):
            for value in range(256):
                words=[0x10203040,0x50607080,0x90a0b0c0];words[j]=value<<(lane*8)
                left,stack=encoder.run(dict(zip([16,9,14],words)));right,after=decoder.run(stack=stack);assert after==stack
                l=[int(left['X31'][k],16)&M for k in [6,5,1]];r=[int(right['X31'][k],16)&M for k in [15,6,14]]
                assert l==[x^k for x,k in zip(words,[0x9f6cb307,0xa473e160,0xd0824f19])]and r==[x^k for x,k in zip(words,[0x7452e25c,0x4f4db03b,0x3bbc1e42])]
                assert all(a^b==D for a,b in zip(l,r))
                for off,word in zip([0x410,0x3f8,0x400],words):assert int.from_bytes(stack[off:off+4],'little')==word
                digest.update(b''.join(x.to_bytes(4,'little')for x in l+r));cases+=1
    encoder.intact();decoder.intact();assert cases==3072
    return {'finite_encoding_pairs':cases,'finite_source_visits':cases*24,'paired_words_checked':cases*3,'ordered_words_sha256':digest.hexdigest(),'source_bytes_preserved':True}


def control_cases(component):
    cases=0;digest=sha256()
    for lane in range(4):
        for value in range(256):
            word=(value<<(lane*8))^0xa5a5a5a5;frame,stack=component.run({11:word});want=(10*(word^0x82d1))%2**32
            expected=bytearray(component.stack);expected[0x348:0x350]=want.to_bytes(8,'little');assert stack==expected and int(frame['X31'][13],16)==want
            digest.update(stack);cases+=1
    component.intact();assert cases==1024
    return {'finite_control_writer_cases':cases,'finite_source_visits':cases*9,'zero_extended_u64_stores_checked':cases,'ordered_stack_sha256':digest.hexdigest(),'source_bytes_preserved':True}


def epochs(p):
    sp=0x62017ad0;out=[]
    for off,writer,reader,n in [(0x410,'0x1b47a8','0x1b5618',4),(0x3f8,'0x1b47b8','0x1b55f8',4),(0x400,'0x1b4798','0x1b5608',4),(0x348,'0x1b4e0c','0x1b529c',8)]:
        ws=[w for w in p['writes']if p['visits'][w['visit']]['pc']==writer];rs=[r for r in p['reads']if p['visits'][r['visit']]['pc']==reader]
        assert len(ws)==len(rs)==1;w,r=ws[0],rs[0];at=sp+off;assert int(w['address'],16)==int(r['address'],16)==at and w['visit']<r['visit']and w['size_B']==r['size_B']==n and w['after_hex']==r['bytes_hex']
        assert not any(w['visit']<v['visit']<r['visit']and int(v['address'],16)<at+n and at<int(v['address'],16)+v['size_B']for v in p['writes'])
        out.append({'offset':hex(off),'store_PC':writer,'read_PC':reader,'store_visit':w['visit'],'read_visit':r['visit'],'size_B':n,'value_hex':r['bytes_hex'],'no_intervening_overlapping_write':True})
    return out


def main():
    raw=read(ROOT/'corefp_scan_entry_checks.json').encode();e=json.loads(raw);s=C.Pointers();assert e['generator_sha256']==SHA((ROOT/'recover_corefp_scan_entry.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    pins={}
    for name,h in e['parent_pins'].items():
        rr=read(ROOT/name).encode();assert SHA(rr)==h;pins[name]=json.loads(rr)
    for name,h in e['dependencies'].items():assert SHA(read(ROOT/name).encode())==h
    for region,(name,lo,hi)in zip(e['source_regions'],SPECS):
        assert region['name']==name and int(region['start'],16)==lo and int(region['end'],16)==hi
        assert region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)]
    wa=pins['corefp_workspace_audit.json'];pe=pins['corefp_output_packing_checks.json'];ce=pins['corefp_workspace_consumers_checks.json'];le=pins['corefp_late_preparation_checks.json'];se=pins['corefp_preparation_scans_checks.json'];ph=pins['corefp_phase_parameters_checks.json'];parent=pins['corefp_workspace_checks.json']
    frozen=ph['source_checks']['proofs']+se['source_checks']['proofs']+[p for m in le['transfer_models']for p in m['proofs']]+[pe['common_inverse_proof']]+[p for m in pe['transfer_models']for p in m['proofs']]+ce['source_model']['proofs']+ce['canonical_phase_proofs']+wa['source_checks']['proofs']+[p for f in wa['frozen_source_checks']for p in f['proofs']]
    new=e['source_checks']['proofs'];assert len(new)==23 and len(frozen)==1121
    for p in new+frozen:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    corridor=e['corridor'];assert corridor['start']=='0x1b54d0'and corridor['end']=='0x1b66ac'and len(corridor['instructions'])==1143
    rows=[];branches=[];names={'w5','x5','w26','x26','w30','x30','lr','w22','x22'}
    for i in C.CS.disasm(s.read(0x1b54d0,4572),0x1b54d0):
        rows.append({'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str});rr,ww=i.regs_access();assert not names&{i.reg_name(j)for j in ww}and not any(i.group(j)for j in [2,3])
        if i.group(1):assert i.mnemonic=='braa';branches.append(hex(i.address))
    assert rows==corridor['instructions']and branches==corridor['branch_sites']and len(branches)==7
    totals=Counter();oracles=[];slot_epochs=[]
    for j,p in enumerate(parent['profiles']):
        totals.update(F.F.A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());F.F.W.workspace_oracle(p,r,s,parent['workspace_constructions'][j]);F.F.W.preparation_oracle(p,r,s)
        components={}
        for k,(name,lo,hi)in enumerate(SPECS):
            b=e['blocks'][j*5+k];assert b['name']==name and b['label']==p['configuration']['label']and all(r.components[name][t]==b[t]for t in ['entry','end'])
            start,end=b['entry']['source_visit'],b['end']['source_visit'];assert end-start==(hi-lo)//4 and b['visits']==p['visits'][start:end]
            for key in ['reads','writes','PAC_models']:assert b[key]==[v for v in p[key]if start<=v['visit']<end]
            components[name]=Component(p,b,s)
        joins=e['joins'][j];assert joins['first_scan_end']==r.scan_ends[0]==se['blocks'][2*j]['end']and joins['second_scan_end']==r.scan_ends[1]==se['blocks'][2*j+1]['end']==r.phase['entry']
        a,b=[list(map(lambda x:int(x,16)&M,q['CPU']['X31']))for q in r.scan_ends];assert a[5]==b[5]==b[12]==(a[14]-0xdecc2544)%2**32 and a[14]==b[4]
        assert joins['downstream_shared_seed_u32']==hex(a[5])and joins['common_final_h_u32']==hex(a[14])
        assert len(joins['corridor_PAC_models'])==(23 if p['configuration']['length_u32']==32 else 21)and all(0x1b54d0<=int(v['target'],16)-C.BASE<=0x1b66ac for v in joins['corridor_PAC_models'])
        lc=components['first_initializer'].b['entry']['CPU']['X31'];rc=components['second_initializer'].b['entry']['CPU']['X31'];assert lc[7]==rc[1]
        assert all((int(lc[u],16)^int(rc[v],16))&M==D for u,v in zip([6,5,1],[15,6,14]))
        assert int(components['control_writer'].b['entry']['CPU']['X31'][11],16)&M==0x8568
        slot_epochs.append({'label':p['configuration']['label'],'epochs':epochs(p)})
        oracles.append({'label':p['configuration']['label'],'initializers':[initializer_cases(components['first_initializer'],0),initializer_cases(components['second_initializer'],1)],
          'fields':field_cases(components['encode'],components['decode']),'control':control_cases(components['control_writer'])})
        print(json.dumps({'audited':p['configuration']['label']}),flush=True)
    assert dict(totals)==pins['corefp_phase_parameters_audit.json']['result']['independent_replay']and e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    result={'verified_counts':e['verified_counts'],'independent_replay':dict(totals),'actual_full_frames':30,'finite_initializer_cases':61440,'initializer_output_words_checked':184320,
      'finite_encoding_pairs':18432,'encoded_pair_words_checked':55296,'finite_control_writer_cases':6144,'finite_source_visits':6180864,'off_premise_controls':6,'off_premise_source_visits':612,
      'stable_field_epochs':18,'stable_control_epochs':6,'corridor_PAC_models_checked':130,'new_queries_unsat':23,'frozen_queries_unsat':1121,'total_queries_unsat':1144,'all_checks_pass':True,'native_target_executed':False}
    assert sum(v['finite_source_visits']for o in oracles for v in [*o['initializers'],o['fields'],o['control']])==result['finite_source_visits']
    out={'result':result,'checks_sha256':SHA(raw),'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],'dependencies':e['dependencies'],
      'component_oracles':oracles,'slot_epochs':slot_epochs,'fresh_replay_completed':True,'process_exit_code':0,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,
      'earlier_arithmetic_passes_universally_reduced':False,'general_raw_preparation_contract_established':False,'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_scan_entry_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
