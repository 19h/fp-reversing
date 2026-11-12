#!/usr/bin/env python3
"""Independent word-recurrence replay, scalar frames and original-byte oracle.

Does not import the new producer. O(C*(B+V*J+P*F+R)+7184*K)
time; bounded private maps; 30 s/SMT query. No native API/IPC or IDB.
"""
import copy,json
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as U
from capstone.arm64_const import ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_EXT_SXTW
import audit_corefp_word_codec as W
from verify_daemon_reader_record_payloads_publication import read
ROOT=W.ROOT;C=W.C;SHA=W.SHA;MOD=2**64;M=2**32-1;A=0x98c9b5333f174cc8;B=0x9f8ba664;H0=0x5f3bad8804febfc3;D=0xeb3e515b
SPECS=[('first_head',0x1b4934,0x1b4d50),('first_tail',0x1b4f1c,0x1b51bc),('second_head',0x1b57d0,0x1b5c20),('second_tail',0x1b5e1c,0x1b63dc)]
CONFIG=[{'q':19,'u':28,'bank':[6,5,1],'out':[6,5,1],'h':19,'a':24,'b':25,'idx':[26,20],'offset':[0x39e1ddf8040f6d97,0x8e7be58772c8acbc],'off':11},
 {'q':3,'u':2,'bank':[6,5,1],'out':[6,5,1],'h':19,'a':24,'b':25,'idx':[21,7],'offset':[0xbec6c5b243bc2e2a,0xb734847988e67a6b],'off':16},
 {'q':12,'u':3,'bank':[15,6,14],'out':[15,6,14],'h':12,'a':28,'b':23,'idx':[2,16],'offset':[0xa979c44cd2feacd9,0xab9cc2fde8ded45c],'off':10},
 {'q':12,'u':20,'bank':[15,6,14],'out':[15,6,14],'h':12,'a':28,'b':23,'idx':[2,1],'offset':[0xaaffa7ee5b811e24,0xfd304a0c9b339831],'off':24}]


def mix(x):
    x%=MOD;x=(x+x//4294967296)%MOD;x=(x-x//65536)%MOD;return (x+x//256)%MOD
def oracle(q,u,i,bank,a=A,b=B):
    t=mix((q+i)%MOD);v=mix((((t+a)%MOD)^u)+i)
    return [bank[0]^(t%2**32)^(v%2**32),bank[1]^((t+b)%2**32)^((v+b)%2**32),bank[2]^((t+a)%2**32)^((v+a)%2**32)],(v+a)%MOD,v,t


class Replay(W.Replay):
    def __init__(self,*args):super().__init__(*args);self.recurrence_components=[];self.current_recurrence=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert self.current_recurrence is None;self.current_recurrence={'name':name,'entry':W.E.F.F.A.capture(self)}
            if pc==C.BASE+hi and self.current_recurrence is not None and self.current_recurrence['name']==name:
                self.current_recurrence['end']=W.E.F.F.A.capture(self);self.recurrence_components.append(self.current_recurrence);self.current_recurrence=None
        return super().code(u,pc,n,d)


def scalar(b,s):
    cpu=copy.deepcopy(b['entry']['CPU']);regs=list(map(lambda x:int(x,16),cpu['X31']));sp=int(cpu['SP'],16);nzcv=int(cpu['NZCV'],16);stack=bytes.fromhex(b['entry']['stack1312_hex']);memory={};reads=[]
    for r in b['reads']:
        for j,v in enumerate(bytes.fromhex(r['bytes_hex'])):memory[int(r['address'],16)+j]=v
    def rr(n):
        n={'fp':'x29','lr':'x30'}.get(n,n)
        if n=='sp':return sp
        if n in ['xzr','wzr']:return 0
        return regs[int(n[1:])]%2**(32 if n[0]=='w'else 64)
    def put(n,v):n={'fp':'x29','lr':'x30'}.get(n,n);regs[int(n[1:])]=v%2**(32 if n[0]=='w'else 64)
    def val(i,o,bits):
        v=rr(i.reg_name(o.reg))if o.type==1 else o.imm
        if o.ext:assert o.ext==ARM64_EXT_SXTW;v%=2**32;v-=2**32 if v>=2**31 else 0
        if o.shift.type:
            if o.shift.type==ARM64_SFT_LSL:v*=2**o.shift.value
            else:assert o.shift.type==ARM64_SFT_LSR;v//=2**o.shift.value
        return v%2**bits
    def condition(i):
        c=bool(nzcv&(1<<29));z=bool(nzcv&(1<<30));cc=i.op_str.rsplit(', ',1)[1];return {'lo':not c,'hi':c and not z,'eq':z,'ne':not z}[cc]
    _,lo,hi=next(v for v in SPECS if v[0]==b['name'])
    for serial,i in enumerate(C.CS.disasm(s.read(lo,hi-lo),lo)):
        m=i.mnemonic;o=i.operands;n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64
        if m in ['ldr','ldur']:
            mem=o[1];at=rr(i.reg_name(mem.mem.base))+mem.mem.disp
            if mem.mem.index:
                v=rr(i.reg_name(mem.mem.index));v-=2**32 if mem.ext==ARM64_EXT_SXTW and v>=2**31 else 0;at+=v*2**mem.shift.value
            at%=MOD;width=bits//8;raw=stack[at-sp:at-sp+width]if sp<=at and at+width<=sp+len(stack)else bytes(memory[at+j]for j in range(width));reads.append({'visit':b['entry']['source_visit']+serial,'address':hex(at),'size_B':width,'bytes_hex':raw.hex()});put(n,int.from_bytes(raw,'little'));continue
        if m=='mov':put(n,val(i,o[1],bits));continue
        if m=='movk':put(n,(rr(n)&~(65535<<o[1].shift.value))|(o[1].imm<<o[1].shift.value));continue
        if m=='cmp':
            a,c=val(i,o[0],bits),val(i,o[1],bits);v=(a-c)%2**bits;nzcv=((v>>(bits-1))<<31)|(int(v==0)<<30)|(int(a>=c)<<29)|(int(bool(((a^c)&(a^v))>>(bits-1)))<<28);continue
        if m=='cset':put(n,int(condition(i)));continue
        if m=='csel':put(n,val(i,o[1]if condition(i)else o[2],bits));continue
        a,c=val(i,o[1],bits),val(i,o[2],bits)
        if m=='add':v=a+c
        elif m=='sub':v=a-c
        elif m=='and':v=a&c
        elif m=='eor':v=a^c
        elif m=='mul':v=a*c
        else:assert m=='lsl';v=a*2**(c%bits)
        put(n,v)
    cpu.update({'X31':list(map(hex,regs)),'NZCV':hex(nzcv),'PC':hex(C.BASE+hi)});assert cpu==b['end']['CPU']and stack.hex()==b['end']['stack1312_hex']and reads==b['reads']and not b['writes']


class Component:
    def __init__(self,b,s):
        self.b=b;self.kind=next(j for j,v in enumerate(SPECS)if v[0]==b['name']);_,self.lo,self.hi=SPECS[self.kind];self.c=CONFIG[self.kind];self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);mapped=set()
        def write(at,raw):
            for page in range(at&~4095,(at+len(raw)+4095)&~4095,4096):
                if page not in mapped:self.u.mem_map(page,4096);mapped.add(page)
            self.u.mem_write(at,raw)
        self.source=s.read(self.lo,self.hi-self.lo);write(C.BASE+self.lo,self.source);cpu=b['entry']['CPU'];self.sp=int(cpu['SP'],16);self.stack=bytes.fromhex(b['entry']['stack1312_hex']);write(self.sp,self.stack)
        for r in b['reads']:write(int(r['address'],16),bytes.fromhex(r['bytes_hex']))
        C.restore(self.u,cpu);self.context=self.u.context_save();frame=self.run();assert frame==b['end']['CPU']
    def run(self,regs=None):
        self.u.context_restore(self.context)
        for k,v in (regs or {}).items():self.u.reg_write(getattr(U,'UC_ARM64_REG_X'+str(k)),v)
        self.u.emu_start(C.BASE+self.lo,C.BASE+self.hi,count=(self.hi-self.lo)//4+1);assert self.u.reg_read(U.UC_ARM64_REG_PC)==C.BASE+self.hi and bytes(self.u.mem_read(self.sp,len(self.stack)))==self.stack
        return C.frame(self.u)
    def audit(self):
        c=self.c;entry=list(map(lambda v:int(v,16),self.b['entry']['CPU']['X31']));q=entry[c['q']];u=entry[c['u']];index=(entry[c['idx'][0]]+c['offset'][0])%MOD;bank=[entry[j]&M for j in c['bank']];digest=sha256();cases=0
        def check(q,u,index,bank):
            nonlocal cases
            regs={c['q']:q,c['u']:u,**dict(zip(c['bank'],bank)),**{j:(index-v)%MOD for j,v in zip(c['idx'],c['offset'])}};frame=self.run(regs);rr=list(map(lambda v:int(v,16),frame['X31']));out,h,v,t=oracle(q,u,index,bank)
            assert [rr[j]&M for j in c['out']]==out and rr[c['h']]==h
            if self.kind in [1,3]:assert rr[7 if self.kind==1 else 1]==v
            digest.update(json.dumps(frame,sort_keys=True).encode());cases+=1
        for lane in range(8):
            for byte in range(256):check(((byte<<(8*lane))^0x9e3779b97f4a7c15)%MOD,u,index,bank)
        for lane in range(8):
            for byte in range(256):check(q,((byte<<(8*lane))^0x6a09e667f3bcc909)%MOD,index,bank)
        for j in range(3):
            for lane in range(4):
                for byte in range(256):words=bank[:];words[j]=byte<<(8*lane);check(q,u,index,words)
        for i in [0,1,2,3,7,15,31,63,127,255,256,65535,2**31,2**32-1,2**32,MOD-1]:check(q,u,i,bank)
        assert cases==7184
        changed=entry[c['off']]^1;controls=[]
        for value in [q,0,1,MOD-1,0x9e3779b97f4a7c15]:
            frame=self.run({c['q']:value,c['off']:changed});rr=list(map(lambda v:int(v,16),frame['X31']));out,h,v,t=oracle(value,u,index,bank);got=[rr[j]&M for j in c['out']];rejected=got!=out or rr[c['h']]!=h
            controls.append({'control_register':'X'+str(c['off']),'retained_control_u64':hex(entry[c['off']]),'changed_control_u64':hex(changed),'q_u64':hex(value),'product_u64':hex(u),'index_u64':hex(index),'incoming_bank_u32':list(map(hex,bank)),
              'actual_bank_u32':list(map(hex,got)),'candidate_bank_u32':list(map(hex,out)),'actual_h_u64':hex(rr[c['h']]),'candidate_h_u64':hex(h),'common_contract_rejected':rejected})
            if rejected:break
        assert controls[-1]['common_contract_rejected']and bytes(self.u.mem_read(C.BASE+self.lo,len(self.source)))==self.source
        return {'name':self.b['name'],'cases':cases,'source_visits':cases*(self.hi-self.lo)//4,'ordered_frames_sha256':digest.hexdigest(),'source_bytes_preserved':True,'off_premise_controls':controls}


def stream_join(profile,blocks,join,codec,entry):
    label=profile['configuration']['label'];n=len(join['raw_words_u64']);groups=[blocks[:n],blocks[n:]];words=list(map(lambda v:int(v,16),join['raw_words_u64']));streams=[]
    assert words==[int(v['raw_word_u64'],16)for v in next(j for j in codec['joins']if j['label']==label)['epochs']]
    for side,group in enumerate(groups):
        encoded=next(b for b in entry['blocks']if b['label']==label and b['name']==('encode'if not side else'decode'))['end'];initial=list(map(lambda v:int(v,16),encoded['CPU']['X31']));bank=[initial[k]&M for k in ([6,5,1]if not side else[15,6,14])];initial_bank=bank[:];h=H0;steps=[]
        for i,(word,b)in enumerate(zip(words,group)):
            k=next(j for j,spec in enumerate(SPECS)if spec[0]==b['name']);c=CONFIG[k];rr=list(map(lambda v:int(v,16),b['entry']['CPU']['X31']));u=(word*W.MULT)%MOD
            assert rr[c['u']]==u and rr[c['q']]==h^u and [rr[j]&M for j in c['bank']]==bank and rr[c['a']]==A and rr[c['b']]==B
            assert (rr[c['idx'][0]]+c['offset'][0])%MOD==(rr[c['idx'][1]]+c['offset'][1])%MOD==i
            bank,h,v,t=oracle(h^u,u,i,bank);end=list(map(lambda x:int(x,16),b['end']['CPU']['X31']));assert [end[j]&M for j in c['out']]==bank and end[c['h']]==h
            assert b['normalized_index_u64']==hex(i)and b['oracle']=={'bank_u32':list(map(hex,bank)),'h_u64':hex(h),'v_u64':hex(v),'t_u64':hex(t)}
            steps.append({'index':i,'raw_word_u64':hex(word),'product_u64':hex(u),'t_u64':hex(t),'v_u64':hex(v),'h_u64':hex(h),'bank_u32':list(map(hex,bank))})
        target=join['first_initializer'if not side else'second_initializer'];regs=list(map(lambda v:int(v,16),target['CPU']['X31']));assert bank==[regs[k]&M for k in ([6,5,1]if not side else[15,6,14])]and v==regs[7 if not side else 1]
        expected=next(b for b in entry['blocks']if b['label']==label and b['name']==('first_initializer'if not side else'second_initializer'))['entry'];assert target==expected
        streams.append({'initial_bank_u32':list(map(hex,initial_bank)),'initial_h_u64':hex(H0),'steps':steps,'final_bank_u32':list(map(hex,bank)),'initializer_seed_u64':hex(v)})
    assert streams[0]['initializer_seed_u64']==streams[1]['initializer_seed_u64']and all(int(a,16)^int(b,16)==D for a,b in zip(streams[0]['initial_bank_u32'],streams[1]['initial_bank_u32']))and all(int(a,16)^int(b,16)==D for a,b in zip(streams[0]['final_bank_u32'],streams[1]['final_bank_u32']))
    return {'label':label,'word_count':n,'streams':streams,'shared_seed_u64':streams[0]['initializer_seed_u64'],'final_bank_xors_u32':[hex(D)]*3}


def main():
    raw=read(ROOT/'corefp_word_recurrence_checks.json').encode();e=json.loads(raw);s=C.Pointers();assert e['generator_sha256']==SHA((ROOT/'recover_corefp_word_recurrence.py').read_bytes())and e['thin_sha256']==C.THIN_SHA;pins={}
    for n,h in e['parent_pins'].items():
        rr=read(ROOT/n).encode();assert SHA(rr)==h;pins[n]=json.loads(rr)
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert len(e['source_regions'])==4
    for region,(name,lo,hi)in zip(e['source_regions'],SPECS):
        assert region['name']==name and region['start']==hex(lo)and region['end']==hex(hi)and region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)]
    assert len(e['source_checks']['cuts'])==16
    for cut in e['source_checks']['cuts']:
        lo,hi=map(lambda k:int(cut[k],16),['start','end']);assert cut['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)]
    old=W.frozen(pins)+pins['corefp_word_codec_checks.json']['proofs'];new=e['source_checks']['proofs'];assert len(old)==1155 and len(new)==37
    for p in old+new:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    print(json.dumps({'queries_unsat':1192}),flush=True);parent=pins['corefp_workspace_checks.json'];codec=pins['corefp_word_codec_checks.json'];totals=Counter();oracles=[];joins=[];offset=0
    for j,p in enumerate(parent['profiles']):
        totals.update(W.E.F.F.A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());W.E.F.F.W.workspace_oracle(p,r,s,parent['workspace_constructions'][j]);W.E.F.F.W.preparation_oracle(p,r,s)
        assert r.current_recurrence is None;start_offset=offset
        for b0 in r.recurrence_components:
            b=e['blocks'][offset];old=codec['blocks'][offset];offset+=1;assert b['name']==b0['name']==old['name']and b['label']==p['configuration']['label']and all(b[t]==b0[t]for t in ['entry','end'])and b['entry']==old['end']
            lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert b['visits']==p['visits'][lo:hi]
            for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if lo<=v['visit']<hi]
            scalar(b,s);oracles.append({'label':b['label'],**Component(b,s).audit()})
        joins.append(stream_join(p,e['blocks'][start_offset:offset],e['joins'][j],codec,pins['corefp_scan_entry_checks.json']));print(json.dumps({'audited':p['configuration']['label']}),flush=True)
    expected={'profiles':6,'regions':32,'source_instructions':1075,'source_B':4300,'regional_visits':8226,'regional_reads':18,'regional_writes':0,'regional_PAC_models':0,'word_steps':32,'new_queries_unsat':37,'normalization_cuts':16}
    assert offset==32 and e['verified_counts']==expected and sum(len(b['visits'])for b in e['blocks'])==8226 and sum(len(b['reads'])for b in e['blocks'])==18 and not any(b['writes']or b['PAC_models']for b in e['blocks'])
    assert dict(totals)==pins['corefp_word_codec_audit.json']['result']['independent_replay']and e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    result={'verified_counts':expected,'independent_replay':dict(totals),'actual_full_frames':32,'independent_scalar_frames':32,'finite_component_cases':sum(o['cases']for o in oracles),'finite_source_visits':sum(o['source_visits']for o in oracles),
      'off_premise_cases':sum(len(o['off_premise_controls'])for o in oracles),'off_premise_source_visits':sum(len(b['visits'])*len(o['off_premise_controls'])for b,o in zip(e['blocks'],oracles)),
      'rejected_metadata_domains':32,'paired_streams':6,'new_queries_unsat':37,'frozen_queries_unsat':1155,'total_queries_unsat':1192,'all_checks_pass':True,'native_target_executed':False}
    assert result['finite_component_cases']==229888 and result['finite_source_visits']==7184*8226
    out={'result':result,'checks_sha256':SHA(raw),'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],'dependencies':e['dependencies'],'component_oracles':oracles,'stream_joins':joins,
      'fresh_replay_completed':True,'process_exit_code':0,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'earlier_arithmetic_passes_universally_reduced':False,'word_recurrence_universally_reduced':True,'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_word_recurrence_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
