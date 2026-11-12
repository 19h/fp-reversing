#!/usr/bin/env python3
"""Independent phase replay, integer model and original-byte component audit.

Does not import the new producer. O(C*(B+V*J+P*F+R)+C*9216*234)
time; bounded private maps; 30 s/SMT query. No native target/API/IPC or IDB.
"""
import copy,json
from pathlib import Path
from collections import Counter
from hashlib import sha256
from functools import reduce
import operator,z3
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as U
from capstone.arm64_const import ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_EXT_SXTW
import audit_corefp_preparation_scans as F
from verify_daemon_reader_record_payloads_publication import read
ROOT=F.ROOT;C=F.C;SHA=F.SHA;M=2**32-1;START=0x1b66ac;CORE=0x1b6950;END=0x1b69c4;D=0xeb3e515b
INPUTS=[26,30,22,15,10,11,5,12]


def seed_masks(s):
    def plus(x,n):return (x+x//2**n)%2**32
    def minus(x,n):return (x-x//2**n)%2**32
    a=plus(plus((s+3491588056)%2**32,14),6)
    b=minus(plus(a^2381486206,11),1)
    c=plus(minus((b+4055371940)%2**32,11),8)
    x=minus(minus(c^612895246,9),8)
    y=minus(plus((x+3524045878)%2**32,13),3)
    z=plus(plus((y+143558721)%2**32,11),5)
    t=minus(plus((z+3646623577)%2**32,9),4)
    v=minus(plus(t^1645640529,13),5)
    w=plus(minus((v+1582860180)%2**32,15),8)
    return a^x^t,b^y^v,c^z^w


def oracle(values):
    a,b,c,d,e,f,s,t=values;left=[a^x for a,x in zip([a,b,c],seed_masks(s))];right=[d^x for d,x in zip([d,e,f],seed_masks(t))]
    a,b,c=left;d,e,f=right;r=(c%8)^5;v=(f^6)%8;k=(-r)%8;l=(-v)%8
    q=(255*2**k)%2**32 if r else 0;z=(255*2**l)%2**32 if v else 0
    rep=lambda x:int.from_bytes(bytes([x])*4,'little');par=lambda x:reduce(operator.xor,x.to_bytes(4,'little'))
    qb=q%256;zb=z%256;first=((a^(a&q))%256)if r else 0;second=((d^(d&z))%256)if v else 0
    hu=rep(par(d)^0x7f);hv=rep(par(e)^0x51);m1=(a%128)^0x5d;m2=(d%128)^6
    fields={23:rep(m2),25:v,28:l,19:k,24:first^rep(qb),27:second^rep(zb),20:rep(zb)^(M^(((zb*0xf5000000)%2**32)&e)),
      21:b,22:e,10:hu^hv,16:0x7631365f}
    stores=[(0x450,c),(0x48,m1),(0x410,rep(m1)),(0x458,r),(0x1c,qb),(0x400,a),(0x24,rep(qb)),(0x44,m2),(0x3f8,d),(0x6c,hu),(0x70,hv)]
    return {'left':left,'right':right,'m1':m1,'m2':m2,'r1':r,'r2':v,'M':rep(m2),'b':par(d^e)^0x2e,
      'K':a^b^0x7631365f,'Q':d^e^0x8b95e221,'fields':fields,'stores':stores}


class Replay(F.A.Replay):
    def __init__(self,*args):super().__init__(*args);self.phase={}
    def code(self,u,pc,n,d):
        self.flush()
        if pc==C.BASE+START:assert not self.phase;self.phase['entry']=F.A.capture(self)
        if pc==C.BASE+CORE:self.phase['core_end']=F.A.capture(self)
        if pc==C.BASE+END and 'end'not in self.phase:self.phase['end']=F.A.capture(self)
        return super().code(u,pc,n,d)


def scalar(b,s):
    cpu=copy.deepcopy(b['entry']['CPU']);reg=[int(x,16)for x in cpu['X31']];sp=int(cpu['SP'],16);nzcv=int(cpu['NZCV'],16)
    stack=bytearray.fromhex(b['entry']['stack1312_hex']);memory={};reads=[];writes=[];lo=b['entry']['source_visit']
    for row in b['reads']:
        at=int(row['address'],16)
        if not sp<=at<sp+1312:
            for j,v in enumerate(bytes.fromhex(row['bytes_hex'])):assert memory.get(at+j,v)==v;memory[at+j]=v
    def rr(n):
        n={'fp':'x29','lr':'x30'}.get(n,n)
        if n in ['xzr','wzr']:return 0
        if n=='sp':return sp
        return reg[int(n[1:])]%2**(32 if n[0]=='w'else 64)
    def put(n,v):
        n={'fp':'x29','lr':'x30'}.get(n,n);reg[int(n[1:])]=v%2**(32 if n[0]=='w'else 64)
    def value(i,o,bits):
        v=rr(i.reg_name(o.reg))if o.type==1 else o.imm
        if o.ext:
            assert o.ext==ARM64_EXT_SXTW;v%=2**32;v-=2**32 if v>=2**31 else 0
        if o.shift.type:
            if o.shift.type==ARM64_SFT_LSL:v*=2**o.shift.value
            else:assert o.shift.type==ARM64_SFT_LSR;v//=2**o.shift.value
        return v%2**bits
    def address(i,o):
        a=rr(i.reg_name(o.mem.base))+o.mem.disp
        if o.mem.index:
            v=rr(i.reg_name(o.mem.index))
            if o.ext==ARM64_EXT_SXTW and v>=2**31:v-=2**32
            a+=v*2**o.shift.value
        return a%2**64
    def fetch(at,n):
        if sp<=at and at+n<=sp+1312:return bytes(stack[at-sp:at-sp+n])
        return bytes(memory[at+j]for j in range(n))
    for serial,i in enumerate(C.CS.disasm(s.read(START,END-START),START)):
        if i.address==CORE:
            core={**cpu,'X31':list(map(hex,reg)),'NZCV':hex(nzcv),'PC':hex(C.BASE+CORE)}
            assert core==b['core_end']['CPU']and stack.hex()==b['core_end']['stack1312_hex']
        m=i.mnemonic;o=i.operands;n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64
        if m in ['str','stur','stp','ldr','ldur','ldp']:
            pair=m in ['stp','ldp'];at=address(i,o[2 if pair else 1]);names=[n,i.reg_name(o[1].reg)]if pair else[n]
            for j,name in enumerate(names):
                a=at+j*bits//8;width=bits//8;before=fetch(a,width)
                if m.startswith('st'):
                    assert sp<=a and a+width<=sp+1312;raw=rr(name).to_bytes(width,'little');stack[a-sp:a-sp+width]=raw
                    writes.append({'visit':lo+serial,'address':hex(a),'size_B':width,'before_hex':before.hex(),'after_hex':raw.hex()})
                else:
                    reads.append({'visit':lo+serial,'address':hex(a),'size_B':width,'bytes_hex':before.hex()});put(name,int.from_bytes(before,'little'))
            continue
        if m=='braa':assert i.address==END-4 and rr('x2')==C.BASE+END and rr('x17')==0x2c2a;continue
        if m=='mov':put(n,value(i,o[1],bits));continue
        if m=='movk':v=rr(n)&~(65535*2**o[1].shift.value);put(n,v|o[1].imm*2**o[1].shift.value);continue
        if m=='neg':put(n,-value(i,o[1],bits));continue
        if m=='cmp':
            a,c=value(i,o[0],bits),value(i,o[1],bits);v=(a-c)%2**bits
            nzcv=((v>>(bits-1))<<31)|(int(v==0)<<30)|(int(a>=c)<<29)|(int(bool(((a^c)&(a^v))>>(bits-1)))<<28);continue
        if m in ['csel','csinv']:
            assert i.op_str.endswith(', eq');v=value(i,o[1],bits)if nzcv&(1<<30)else value(i,o[2],bits)^(M if m=='csinv'else 0);put(n,v);continue
        a,c=value(i,o[1],bits),value(i,o[2],bits)
        if m in ['and','ands']:v=a&c
        elif m=='add':v=a+c
        elif m=='sub':v=a-c
        elif m=='eor':v=a^c
        elif m=='eon':v=a^(M^c)
        elif m=='mul':v=a*c
        else:assert m=='lsl';v=a*2**(c%bits)
        if m=='ands':nzcv=((v>>(bits-1))<<31)|(int(v==0)<<30)
        put(n,v)
    cpu.update({'X31':list(map(hex,reg)),'NZCV':hex(nzcv),'PC':hex(C.BASE+END)})
    assert cpu==b['end']['CPU']and stack.hex()==b['end']['stack1312_hex']and reads==b['reads']and writes==b['writes']
    return {'instructions':198,'reads':len(reads),'writes':len(writes),'stack_final_B':len(stack),'all_CPU_fields_match':True}


def machine(p,b,s,g):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);mapped=set()
    for row in p['initial_RAM']:
        at=int(row['address'],16);u.mem_map(at,4096);u.mem_write(at,C.unpack(row['payload']));mapped.add(at)
    def write(at,raw):
        for page in range(at&~4095,(at+len(raw)+4095)&~4095,4096):
            if page not in mapped:u.mem_map(page,4096);u.mem_write(page,C.initial_page(s,page));mapped.add(page)
        u.mem_write(at,raw)
    for row in b['reads']:write(int(row['address'],16),bytes.fromhex(row['bytes_hex']))
    source=s.read(START,0x1b6a54-START);write(C.BASE+START,source)
    sp=int(b['entry']['CPU']['SP'],16);stack=bytes.fromhex(b['entry']['stack1312_hex']);write(sp,stack);C.restore(u,b['entry']['CPU']);context=u.context_save();pac={'n':0}
    def branch(uc,pc,n,d):
        assert pc==C.BASE+END-4 and uc.reg_read(U.UC_ARM64_REG_X2)==C.BASE+END and uc.reg_read(U.UC_ARM64_REG_X17)==0x2c2a
        pac['n']+=1;uc.reg_write(U.UC_ARM64_REG_PC,C.BASE+END)
    u.hook_add(UC_HOOK_CODE,branch,begin=C.BASE+END-4,end=C.BASE+END-4)
    u.emu_start(C.BASE+START,C.BASE+END,count=199)
    assert C.frame(u)==b['end']['CPU']and bytes(u.mem_read(sp,1312)).hex()==b['end']['stack1312_hex']and pac['n']==1
    base=[int(b['entry']['CPU']['X31'][j],16)&M for j in INPUTS];digest=sha256();cases=0;coherent=0;independent=0
    def run(values,index=None):
        nonlocal cases,coherent,independent
        u.context_restore(context);write(sp,stack)
        for j,v in zip(INPUTS,values):u.reg_write(getattr(U,'UC_ARM64_REG_X'+str(j)),v)
        expected=oracle(values);u.emu_start(C.BASE+START,C.BASE+END,count=199);assert u.reg_read(U.UC_ARM64_REG_PC)==C.BASE+END
        got=C.frame(u);want=bytearray(stack)
        for off,v in expected['stores']:want[off:off+4]=v.to_bytes(4,'little')
        want[0x348:0x34c]=(0x40f6).to_bytes(4,'little')
        assert bytes(u.mem_read(sp,1312))==want
        for j,v in expected['fields'].items():assert int(got['X31'][j],16)==v,(j,values)
        digest.update(bytes(u.mem_read(sp,1312)));digest.update(json.dumps(got,sort_keys=True).encode());cases+=1
        if index is None:independent+=1
        else:
            coherent+=1;assert expected['m1']==expected['m2']and expected['r1']==expected['r2']and expected['K']^expected['Q']==0xfda4d47e
            u.reg_write(U.UC_ARM64_REG_X13,index);u.emu_start(C.BASE+END,C.BASE+0x1b6a54,count=37);assert u.reg_read(U.UC_ARM64_REG_PC)==C.BASE+0x1b6a54
            j=F.W.rol8(F.W.phi(index,expected['M']&255,8),expected['r1'])^expected['b']
            x=F.W.rolbytes(F.W.phi(F.W.expand(g[index]),expected['M'],32),expected['r1'])^expected['K'];y=(g[index]<<8)^0x65^expected['Q']
            for reg,value in [(7,x),(6,y)]:assert int.from_bytes(u.mem_read(int(got['X31'][reg],16)+4*j,4),'little')==value
        return expected
    for j in range(8):
        for lane in range(4):
            for value in range(256):
                values=base[:];values[j]=(value<<(8*lane))^(((j+1)*0x9e3779b9)&M);run(values)
    for rotation in range(8):
        for mask in range(128):
            serial=rotation*128+mask;seed=((serial+1)*0x6a09e667)&M;bias=((serial+3)*0xbb67ae85)&M
            left=[((serial*0x3c6ef372)&0xffffff80)|((mask^6^D)&127),bias,((bias^0xa54ff53a)&0xfffffff8)|(rotation^5)]
            original=[x^y for x,y in zip(left,seed_masks(seed))];q=run([*original,*[x^D for x in original],seed,seed],serial%256)
            assert q['m1']==mask and q['r1']==rotation
    witnesses=[]
    for which in ['bank_xor','shared_seed']:
        for seed in range(32):
            left=[0,0,0];right=[x^(D^1 if which=='bank_xor'else D)for x in left]
            values=[*left,*right,seed,seed if which=='bank_xor'else seed+1];q=oracle(values)
            if q['m1']!=q['m2']or q['r1']!=q['r2']:
                witnesses.append({'omitted_premise':which,'inputs_u32':list(map(hex,values)),'masks_u8':[q['m1'],q['m2']],'rotations':[q['r1'],q['r2']]});break
        else:raise AssertionError('missing premise counterexample')
    assert cases==9216 and independent==8192 and coherent==1024 and pac['n']==cases+1
    assert bytes(u.mem_read(C.BASE+START,len(source)))==source
    return {'label':b['label'],'finite_phase_cases':cases,'independent_input_cases':independent,'coherent_parameter_cases':coherent,'finite_phase_source_visits':cases*198,
      'finite_constructor_cases':coherent,'finite_constructor_source_visits':coherent*36,'finite_PAC_models':cases,'actual_full_frames':1,
      'joint_mask_rotation_pairs_checked':1024,'ordered_frames_sha256':digest.hexdigest(),'source_bytes_preserved':True,'premise_counterexamples':witnesses}


def main():
    raw=read(ROOT/'corefp_phase_parameters_checks.json').encode();e=json.loads(raw);s=C.Pointers();assert e['generator_sha256']==SHA((ROOT/'recover_corefp_phase_parameters.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    pins={}
    for name,h in e['parent_pins'].items():
        rawp=read(ROOT/name).encode();assert SHA(rawp)==h;pins[name]=json.loads(rawp)
    for name,h in e['dependencies'].items():assert SHA(read(ROOT/name).encode())==h
    ins=[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(START,END-START),START)]
    assert ins==e['instructions']and len(ins)==198
    parent=pins['corefp_workspace_checks.json'];wa=pins['corefp_workspace_audit.json'];le=pins['corefp_late_preparation_checks.json'];pe=pins['corefp_output_packing_checks.json'];ce=pins['corefp_workspace_consumers_checks.json'];se=pins['corefp_preparation_scans_checks.json']
    frozen=se['source_checks']['proofs']+[p for m in le['transfer_models']for p in m['proofs']]+[pe['common_inverse_proof']]+[p for m in pe['transfer_models']for p in m['proofs']]+ce['source_model']['proofs']+ce['canonical_phase_proofs']+wa['source_checks']['proofs']+[p for f in wa['frozen_source_checks']for p in f['proofs']]
    new=e['source_checks']['proofs'];assert len(new)==51 and len(frozen)==1070
    for p in new+frozen:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    totals=Counter();scalars=[];machines=[];forms=[]
    for j,(p,b)in enumerate(zip(parent['profiles'],e['blocks'])):
        totals.update(F.A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());assert all(r.phase[k]==b[k]for k in ['entry','core_end','end'])
        assert b['entry']==se['blocks'][2*j+1]['end'];lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert hi-lo==198 and b['visits']==p['visits'][lo:hi]
        for key in ['reads','writes','PAC_models']:assert b[key]==[x for x in p[key]if lo<=x['visit']<hi]
        F.W.workspace_oracle(p,r,s,parent['workspace_constructions'][j]);F.W.preparation_oracle(p,r,s);scalars.append(scalar(b,s))
        values=[int(b['entry']['CPU']['X31'][k],16)&M for k in INPUTS];q=oracle(values);form=e['parameter_oracles'][j]
        assert values[-1]==values[-2]and all(a^b==D for a,b in zip(values[:3],values[3:6]))
        assert form['left_mixed_u32']==list(map(hex,q['left']))and form['right_mixed_u32']==list(map(hex,q['right']))
        for key,expected in [('mask_u32',hex(q['M'])),('rotate_per_byte',q['r1']),('index_xor_u8',hex(q['b'])),('first_xor_u32',hex(q['K'])),('second_xor_u32',hex(q['Q']))]:assert form[key]==expected==wa['workspace_oracles'][j][key]
        assert len(b['reads'])==6 and len(b['writes'])==12 and len(b['PAC_models'])==1
        pr=b['PAC_models'][0]['pointer_row'];assert pr['address']=='0x1cbdd78'and pr['authenticated']and pr['chain_membership_verified']and not pr['bind']
        g=bytes.fromhex(wa['workspace_oracles'][j]['canonical_permutation_hex']);machines.append(machine(p,b,s,g));forms.append(form)
        print(json.dumps({'audited':b['label'],'finite_cases':sum(v['finite_phase_cases']for v in machines)}),flush=True)
    assert dict(totals)==pins['corefp_preparation_scans_audit.json']['result']['independent_replay']and e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    result={'verified_counts':e['verified_counts'],'independent_replay':dict(totals),'independent_scalar':dict(sum((Counter({k:v for k,v in r.items()if type(v)is int})for r in scalars),Counter())),
      **{k:sum(r[k]for r in machines)for k in ['finite_phase_cases','independent_input_cases','coherent_parameter_cases','finite_phase_source_visits','finite_constructor_cases','finite_constructor_source_visits','finite_PAC_models','actual_full_frames','joint_mask_rotation_pairs_checked']},
      'new_queries_unsat':51,'frozen_queries_unsat':1070,'total_queries_unsat':1121,'all_checks_pass':True,'native_target_executed':False}
    out={'result':result,'checks_sha256':SHA(raw),'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],'dependencies':e['dependencies'],
      'scalar_oracles':scalars,'machine_oracles':machines,'parameter_oracles':forms,'fresh_replay_completed':True,'process_exit_code':0,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,
      'upstream_shared_seed_and_bank_xor_universal':False,'general_raw_preparation_contract_established':False,'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_phase_parameters_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
