#!/usr/bin/env python3
"""Scan-entry u64 mixers, earlier word encodings and downstream seed carriers.

Typed private stack/control/PAC/caller premises remain explicit.
O(C*(B+V*J+P*F+R)) replay time/space; 30 s/SMT query.
No native target/API/IPC or IDB operation.
"""
import json
from pathlib import Path
from collections import Counter
import z3
import recover_corefp_phase_parameters as P
ROOT=P.ROOT;C=P.C;S=C.Pointers();SHA=P.SHA;M32=2**32-1;M64=2**64-1;D=0xeb3e515b
SPECS=[{'name':'encode','start':0x1b4790,'end':0x1b47c0}, {'name':'first_initializer','start':0x1b51d4,'end':0x1b536c},
 {'name':'decode','start':0x1b55f0,'end':0x1b5620},{'name':'second_initializer','start':0x1b63e4,'end':0x1b6530},
 {'name':'control_writer','start':0x1b4dec,'end':0x1b4e10}]
PINS={**P.PINS,'corefp_phase_parameters_checks.json':'cd03e79296510d37ca618ba00e43a1e9566216e8f229a625f7270c020f5f55c8',
 'corefp_phase_parameters_audit.json':'8389aac58db7e1123f7a902f215167fa35d1df68cf3a38542073d4d0775cbb44'}


def long_mix(seed):
    def add(x,n):return (x+P.shift(x,n))&M64
    def sub(x,n):return (x-P.shift(x,n))&M64
    a=add(add(add((seed+0x57591561cfca294a)&M64,31),11),2)
    b=add(sub(sub((a+0x9801c171577bca01)&M64,29),14),1)
    c=add(add(add((b+0x6edf733dd7daa684)&M64,29),10),3)
    d=add(sub(add(c^0xa4ee2625fd04e1d5,30),14),4)
    e=add(sub(sub((d+0x115191787f9f5c08)&M64,30),13),2)
    f=add(add(add((e+0xe8445ed68b2a859b)&M64,24),11),2)
    g=sub(add(sub((f+0x745ace6e274e4c6c)&M64,31),10),7)
    h=sub(add(add((g+0xe3d0b888f4003be8)&M64,25),10),7)
    j=add(sub(add((h+0x0680844d79c49795)&M64,26),15),5)
    return [(a^d^g)&M32,(b^e^h)&M32,(c^f^j)&M32]


def source_checks():
    proofs=[];sp=z3.BitVec('entry_SP64',64);seed=z3.BitVec('entry_seed64',64);ctrl=z3.BitVec('entry_control64',64)
    values=[z3.BitVec('entry_word'+str(j),32)for j in range(3)];wanted=[x^z3.Extract(31,0,y)for x,y in zip(values,long_mix(seed))]
    control=(z3.Extract(31,0,ctrl)+0x32f291f3)&0xcd0d6df7;shift=(control-0x4d23)&63
    for kind,spec in enumerate([SPECS[1],SPECS[3]]):
        regs={j:z3.BitVec('init'+str(kind)+'_X'+str(j),64)for j in range(31)};regs[7 if not kind else 1]=seed;reads=[]
        for j,v in zip([6,5,1]if not kind else[15,6,14],values):regs[j]=z3.ZeroExt(32,v)
        def load(at,n,i):
            assert kind==0 and n==8;reads.append({'address':str(at),'pc':hex(i.address)});P.P.prove(proofs,'first_control_load_address',at==sp+0x348);return ctrl
        state=P.Lift(regs,sp,load).execute(list(C.CS.disasm(S.read(spec['start'],spec['end']-spec['start']),spec['start'])))
        for j,(reg,v)in enumerate(zip([26,30,22]if not kind else[15,10,11],wanted)):
            P.P.prove(proofs,('first'if not kind else'second')+'_initializer_word_'+str(j),state.rr('w'+str(reg))==v,[shift==2]if not kind else[])
        assert len(reads)==(1 if not kind else 0)
        if not kind:
            P.P.prove(proofs,'first_control_value',state.rr('w10')==control)
            P.P.prove(proofs,'first_scan_constant_parameters',z3.And(*[state.rr('w'+str(j))==v for j,v in {0:0xdecc2544,9:0xef6612a2,2:0x750549fb,4:0x6d31a173}.items()]))
    P.P.prove(proofs,'retained_control_4d3a',z3.And(control==0x4d25,shift==2),[ctrl==0x4d3a])
    P.P.prove(proofs,'initializer_shift_implies_scan_tail_shift',((control-0x4d1d)&31)==8,[shift==2])
    a,b,c=[z3.BitVec('bank_'+str(j),32)for j in range(3)];mask=[z3.BitVec('bank_mix_'+str(j),32)for j in range(3)]
    P.P.prove(proofs,'common_u64_initializer_preserves_bank_xor',z3.And(*[((v^m)^((v^D)^m))==D for v,m in zip([a,b,c],mask)]))
    # Original earlier encoding and later decoding are distinct source epochs.
    regs={j:z3.BitVec('encode_X'+str(j),64)for j in range(31)}
    for reg,v in zip([16,9,14],[a,b,c]):regs[reg]=z3.ZeroExt(32,v)
    enc=P.Lift(regs,sp).execute(list(C.CS.disasm(S.read(SPECS[0]['start'],48),SPECS[0]['start'])))
    P.P.prove(proofs,'encoded_stack_stores',z3.And(*[z3.And(at==sp+off,value==v)for (at,value),(off,v)in zip(enc.stores,[(0x400,c),(0x410,a),(0x3f8,b)])]))
    first=[a^0x9f6cb307,b^0xa473e160,c^0xd0824f19]
    P.P.prove(proofs,'encoded_register_words',z3.And(*[enc.rr('w'+str(reg))==v for reg,v in zip([6,5,1],first)]))
    loads=[];fields=[b,c,a];offsets=[0x3f8,0x400,0x410]
    def load(at,n,i):
        j=len(loads);assert n==4;P.P.prove(proofs,'decoded_stack_address_'+str(j),at==sp+offsets[j]);loads.append(at);return fields[j]
    dec=P.Lift({j:z3.BitVec('decode_X'+str(j),64)for j in range(31)},sp,load).execute(list(C.CS.disasm(S.read(SPECS[2]['start'],48),SPECS[2]['start'])))
    second=[a^0x7452e25c,b^0x4f4db03b,c^0x3bbc1e42]
    P.P.prove(proofs,'decoded_register_words',z3.And(*[dec.rr('w'+str(reg))==v for reg,v in zip([15,6,14],second)]))
    P.P.prove(proofs,'encoded_decoded_pair_xors',z3.And(*[(u^v)==D for u,v in zip(first,second)]))
    producer=z3.BitVec('control_producer_W11',32);regs={j:z3.BitVec('control_writer_X'+str(j),64)for j in range(31)};regs[11]=z3.ZeroExt(32,producer)
    writer=P.Lift(regs,sp).execute(list(C.CS.disasm(S.read(0x1b4dec,36),0x1b4dec)));assert len(writer.stores)==1
    at,value=writer.stores[0];P.P.prove(proofs,'control_writer_address_and_value',z3.And(at==sp+0x348,value==z3.ZeroExt(32,10*(producer^0x82d1))))
    P.P.prove(proofs,'control_writer_retained_8568',value==0x4d3a,[producer==0x8568])
    for kind,(lo,hi,carrier,h)in enumerate([(0x1b5444,0x1b54ac,5,14),(0x1b6620,0x1b6688,12,4)]):
        regs={j:z3.BitVec('carrier'+str(kind)+'_X'+str(j),64)for j in range(31)};byte=z3.BitVec('carrier'+str(kind)+'_byte8',8)
        state=P.P.Lift(regs,lambda at,n,i:byte).execute(list(C.CS.disasm(S.read(lo,hi-lo),lo)))
        P.P.prove(proofs,'tail'+str(kind)+'_final_fold_carrier',state.rr('w'+str(carrier))+state.rr('w0')==state.rr('w'+str(h)))
    return {'proofs':proofs,'first_initializer_premise':'((control32-0x4d23)&63)==2; control32=(low32(load_u64(SP+0x348))+0x32f291f3)&0xcd0d6df7',
      'composition':'common initializers preserve an incoming bank XOR under equal u64 seeds; scans preserve that XOR and give equal final h; tail carriers equal final_h-a; writer-free corridor preserves first carrier'}


def corridor():
    lo,hi=0x1b54d0,0x1b66ac;rows=P.P.source_rows(lo,hi);names={'w5','x5','w26','x26','w30','x30','lr','w22','x22'};branches=[]
    for i in C.CS.disasm(S.read(lo,hi-lo),lo):
        reads,writes=i.regs_access();assert not names&{i.reg_name(j)for j in writes};assert not any(i.group(g)for g in [2,3])
        if i.group(1):assert i.mnemonic=='braa';branches.append(hex(i.address))
    assert len(rows)==1143 and len(branches)==7
    return {'start':hex(lo),'end':hex(hi),'instructions':rows,'preserved_registers':['X5','X26','X30','X22'],'branch_sites':branches,
      'premise':'normal execution remains within this interval until end; no call/return or external register mutation'}


class Capture(P.Capture):
    def __init__(self,*args):super().__init__(*args);self.components={};self.scan_ends=[]
    def code(self,u,pc,n,d):
        self.flush()
        for spec in SPECS:
            if pc==C.BASE+spec['start']:assert spec['name']not in self.components;self.components[spec['name']]={'entry':P.P.A.capture(self)}
            if pc==C.BASE+spec['end']:self.components[spec['name']]['end']=P.P.A.capture(self)
        if pc in [C.BASE+0x1b54d0,C.BASE+0x1b66ac]:self.scan_ends.append(P.P.A.capture(self))
        return super().code(u,pc,n,d)


def main():
    pinned={}
    for n,h in PINS.items():
        raw=P.P.read(ROOT/n).encode();assert SHA(raw)==h;pinned[n]=json.loads(raw)
    parent=pinned['corefp_workspace_checks.json'];scans=pinned['corefp_preparation_scans_checks.json'];phase=pinned['corefp_phase_parameters_checks.json'];blocks=[];joins=[];totals=Counter()
    for j,p in enumerate(parent['profiles']):
        r=Capture(p,parent['source_spans'],S);totals.update(r.run());assert len(r.components)==5 and len(r.scan_ends)==2
        label=p['configuration']['label']
        for spec in SPECS:
            b=r.components[spec['name']];lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert hi-lo==(spec['end']-spec['start'])//4
            b.update({'label':label,'name':spec['name'],'visits':p['visits'][lo:hi],**{k:[v for v in p[k]if lo<=v['visit']<hi]for k in ['reads','writes','PAC_models']}});blocks.append(b)
        for kind in range(2):assert r.scan_ends[kind]==scans['blocks'][j*2+kind]['end']
        assert r.phase['entry']==phase['blocks'][j]['entry']==r.scan_ends[1]
        a,b=r.scan_ends;ar=list(map(lambda x:int(x,16)&M32,a['CPU']['X31']));br=list(map(lambda x:int(x,16)&M32,b['CPU']['X31']))
        assert ar[5]==br[5]==br[12]and ar[14]==br[4]and ar[5]==(ar[14]-0xdecc2544)&M32
        left=r.components['first_initializer'];right=r.components['second_initializer'];lc=left['entry']['CPU']['X31'];rc=right['entry']['CPU']['X31'];s1=int(lc[7],16);s2=int(rc[1],16)
        v1=[int(lc[k],16)&M32 for k in [6,5,1]];v2=[int(rc[k],16)&M32 for k in [15,6,14]];assert s1==s2 and all(x^y==D for x,y in zip(v1,v2))
        for region,values,regs in [(left,v1,[26,30,22]),(right,v2,[15,10,11])]:assert [hex(x^y)for x,y in zip(values,long_mix(s1))]==[hex(int(region['end']['CPU']['X31'][k],16)&M32)for k in regs]
        lo,hi=a['source_visit'],r.scan_ends[1]['source_visit'];edges=[x for x in p['PAC_models']if lo<=x['visit']<hi]
        assert all(0x1b54d0<=int(x['target'],16)-C.BASE<=0x1b66ac for x in edges)
        joins.append({'label':label,'first_scan_end':a,'second_scan_end':r.scan_ends[1],'initializer_seeds_u64':list(map(hex,[s1,s2])),
          'initializer_inputs_u32':[list(map(hex,v1)),list(map(hex,v2))],'downstream_shared_seed_u32':hex(ar[5]),'common_final_h_u32':hex(ar[14]),'corridor_PAC_models':edges})
        print(json.dumps({'captured':label}),flush=True)
    checks=source_checks();census=corridor();deps=['recover_corefp_phase_parameters.py','audit_corefp_phase_parameters.py',*phase['dependencies']]
    counts={'profiles':6,'regions':30,'primary_source_instructions':218,'primary_source_B':872,'regional_visits':1308,'regional_reads':24,'regional_writes':24,
      'regional_PAC_models':0,'corridor_static_instructions':1143,'corridor_static_B':4572,'corridor_branch_sites':7,'new_queries_unsat':len(checks['proofs']),'shared_seed_joins':6,'initial_bank_xor_joins':18}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,'dependencies':{n:SHA(P.P.read(ROOT/n).encode())for n in deps},
      'source_regions':[{**sp,'start':hex(sp['start']),'end':hex(sp['end']),'instructions':P.P.source_rows(sp['start'],sp['end'])}for sp in SPECS],
      'tail_source_regions':[{'start':hex(lo),'end':hex(hi),'instructions':P.P.source_rows(lo,hi)}for lo,hi in [(0x1b5444,0x1b54ac),(0x1b6620,0x1b6688)]],
      'source_checks':checks,'corridor':census,'blocks':blocks,'joins':joins,'verified_counts':counts,'replay_totals':dict(totals),'native_target_executed':False,'native_API_executed':False,
      'IDB_mutated':False,'new_live_IDA_claim':False,'earlier_arithmetic_passes_universally_reduced':False,'general_raw_preparation_contract_established':False,
      'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_scan_entry_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
