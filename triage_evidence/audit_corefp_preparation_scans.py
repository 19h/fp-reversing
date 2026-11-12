#!/usr/bin/env python3
"""Independent split-scan replay, scalar interpreter and private component tests.

Does not import the new producer. Source interfaces are typed and PAC is
modeled. O(C*(B+V*J+P*F+R)+N*4352*600) time; bounded private maps;
30 s/SMT query. No native target/API/IPC or IDB operation.
"""
import copy,json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as U
from capstone.arm64_const import ARM64_EXT_SXTW,ARM64_SFT_LSL,ARM64_SFT_LSR
import z3
import audit_corefp_late_preparation as F
from verify_daemon_reader_record_payloads_publication import read
A=F.A;W=F.W;C=F.C;ROOT=F.ROOT;SHA=F.SHA;M32=(1<<32)-1
SPECS=[{'kind':0,'start':0x1b536c,'end':0x1b54d0,'init':0x1b53c4,'head':0x1b53c8,'tail':0x1b5444,'head_dispatch':0x1b5440,'tail_dispatch':0x1b54cc,'state':[26,30,22,14],'split':11,'counter':8},
 {'kind':1,'start':0x1b6530,'end':0x1b66ac,'init':0x1b65a4,'head':0x1b65a8,'tail':0x1b6620,'head_dispatch':0x1b661c,'tail_dispatch':0x1b66a8,'state':[15,10,11,4],'split':13,'counter':12}]


def select_split(p,kind):
    if kind==0:
        a=(int(p[4])+4)%16;b=(int(p[a])+14)%16;c=(int(p[b])+2)%16;v=int(p[c])%16
    else:
        a=(int(p[2])+14)%16;b=(int(p[a])+14)%16;c=int(p[b])%16;v=(int(p[c])+3)%16
    return v if v else 1


def run_fold(p,cpu,kind,n=None):
    q=[int(v,16)&M32 for v in cpu['X31']];acc=[q[j]for j in SPECS[kind]['state']];initial=acc[:];k=q[2 if not kind else 6];aa=q[0];bb=q[9]
    n=select_split(p,kind)if n is None else n;residue=None
    for index,byte in enumerate(p):
        product=(int(byte)*k)%2**32;first=((product^acc[3])+index)%2**32
        first=(first+first//2**16)%2**32;first=(first+first//2**8)%2**32
        second=(((first+aa)%2**32)^product)+index;second%=2**32
        second=(second+second//2**16)%2**32;second=(second+second//2**8)%2**32
        acc=[acc[0]^first^second,acc[1]^((first+bb)%2**32)^((second+bb)%2**32),acc[2]^((first+aa)%2**32)^((second+aa)%2**32),(second+aa)%2**32]
        if index+1==n:residue=acc[2]^acc[3]if kind==0 else(first+bb)%2**32
    assert residue is not None
    return acc,[acc[j]^initial[j]for j in range(3)],residue


class Replay(A.Replay):
    def __init__(self,*args):super().__init__(*args);self.scans=[]
    def code(self,u,pc,n,d):
        self.flush()
        for spec in SPECS:
            if pc==C.BASE+spec['start']:self.scans.append({'kind':spec['kind'],'entry':A.capture(self)})
            if pc==C.BASE+spec['end']:self.scans[-1]['end']=A.capture(self)
        return super().code(u,pc,n,d)


def scalar(block,s):
    cpu=copy.deepcopy(block['entry']['CPU']);regs=[int(x,16)for x in cpu['X31']];sp=int(cpu['SP'],16);stack=bytes.fromhex(block['entry']['stack1312_hex']);memory={}
    for r in block['reads']:
        at=int(r['address'],16)
        for j,b in enumerate(bytes.fromhex(r['bytes_hex'])):assert memory.get(at+j,b)==b;memory[at+j]=b
    def rr(n):
        n={'fp':'x29','lr':'x30'}.get(n,n)
        if n=='sp':return sp
        if n in ['wzr','xzr']:return 0
        return regs[int(n[1:])]&((1<<(32 if n[0]=='w'else 64))-1)
    def put(n,v):
        n={'fp':'x29','lr':'x30'}.get(n,n);regs[int(n[1:])]=v&((1<<(32 if n[0]=='w'else 64))-1)
    def value(i,o,bits):
        v=rr(i.reg_name(o.reg))if o.type==1 else o.imm
        if o.ext:
            assert o.ext==ARM64_EXT_SXTW;v&=M32
            if v>>31:v-=1<<32
        if o.shift.type:
            if o.shift.type==ARM64_SFT_LSL:v<<=o.shift.value
            else:assert o.shift.type==ARM64_SFT_LSR;v>>=o.shift.value
        return v&((1<<bits)-1)
    nzcv=int(cpu['NZCV'],16);actual_reads=[];pac=iter(block['PAC_models']);lo=block['entry']['source_visit'];pc=int(cpu['PC'],16)-C.BASE
    for serial,row in enumerate(block['visits']):
        assert int(row['pc'],16)==pc;i=next(C.CS.disasm(s.read(pc,4),pc));m=i.mnemonic;o=i.operands;name=i.reg_name(o[0].reg);bits=32 if name.startswith('w')else 64;mask=(1<<bits)-1;nextpc=pc+4
        if m in ['ldr','ldur','ldrb','ldurb']:
            mem=o[1];at=rr(i.reg_name(mem.mem.base))+mem.mem.disp
            if mem.mem.index:
                v=rr(i.reg_name(mem.mem.index))
                if mem.ext==ARM64_EXT_SXTW and v>>31:v-=1<<32
                at+=v<<mem.shift.value
            at&=(1<<64)-1;n=1 if m in ['ldrb','ldurb']else bits//8
            raw=stack[at-sp:at-sp+n]if sp<=at and at+n<=sp+1312 else bytes(memory[at+j]for j in range(n))
            actual_reads.append({'visit':lo+serial,'address':hex(at),'size_B':n,'bytes_hex':raw.hex()});put(name,int.from_bytes(raw,'little'))
        elif m=='braa':
            row=next(pac);target=rr(name);modifier=rr(i.reg_name(o[1].reg));assert row['visit']==lo+serial and target==int(row['target'],16)and modifier==int(row['modifier'],16);nextpc=target-C.BASE
        elif m=='mov':put(name,value(i,o[1],bits))
        elif m=='movk':
            shift=o[1].shift.value;put(name,(rr(name)&~(65535<<shift))|(o[1].imm<<shift))
        elif m in ['cmp','tst']:
            a,b=value(i,o[0],bits),value(i,o[1],bits);v=(a-b)&mask if m=='cmp'else a&b
            nzcv=((v>>(bits-1))<<31)|(int(v==0)<<30)
            if m=='cmp':nzcv|=(int(a>=b)<<29)|(int(bool(((a^b)&(a^v))>>(bits-1)))<<28)
        elif m=='csinc':assert i.op_str.endswith(', ne');put(name,value(i,o[2],bits)+1 if nzcv&(1<<30)else value(i,o[1],bits))
        elif m=='cset':
            assert i.op_str.endswith((', eq',', ne'));z=bool(nzcv&(1<<30));put(name,int(z if i.op_str.endswith(', eq')else not z))
        else:
            a,b=value(i,o[1],bits),value(i,o[2],bits)
            if m=='add':v=a+b
            elif m=='sub':v=a-b
            elif m=='mul':v=a*b
            elif m=='and':v=a&b
            elif m=='eor':v=a^b
            elif m=='lsl':v=a<<(b&(bits-1))
            else:assert m=='lsr';v=a>>(b&(bits-1))
            put(name,v)
        pc=nextpc
    cpu.update({'X31':list(map(hex,regs)),'PC':hex(C.BASE+pc),'NZCV':hex(nzcv)});assert cpu==block['end']['CPU']and actual_reads==block['reads']and not block['writes']
    assert block['entry']['stack1312_hex']==block['end']['stack1312_hex']
    return {'visits':len(block['visits']),'reads':len(actual_reads),'PAC_models':len(block['PAC_models']),'writes':0,'all_CPU_fields_match':True,'stack_unchanged_B':1312}


def machine_cases(p,block,s,cells):
    spec=SPECS[block['kind']];u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);mapped=set()
    for row in p['initial_RAM']:
        at=int(row['address'],16);u.mem_map(at,4096);u.mem_write(at,C.unpack(row['payload']));mapped.add(at)
    def write(at,b):
        for page in range(at&~4095,(at+len(b)+4095)&~4095,4096):
            if page not in mapped:u.mem_map(page,4096);u.mem_write(page,C.initial_page(s,page));mapped.add(page)
        u.mem_write(at,b)
    sp=int(block['entry']['CPU']['SP'],16);stack=bytes.fromhex(block['entry']['stack1312_hex']);fixed={}
    for r in block['reads']:
        at=int(r['address'],16)
        if sp<=at and at+r['size_B']<=sp+1312:continue
        for j,b in enumerate(bytes.fromhex(r['bytes_hex'])):assert fixed.get(at+j,b)==b;fixed[at+j]=b
    for at,b in fixed.items():write(at,bytes([b]))
    for cell,row in cells.items():
        page=cell&~4095
        if page not in mapped:u.mem_map(page,4096);u.mem_write(page,C.initial_page(s,page));mapped.add(page)
        assert int.from_bytes(u.mem_read(cell,8),'little')==C.BASE+int(row['target'],16)
    write(C.BASE+spec['start'],s.read(spec['start'],spec['end']-spec['start']));write(sp,stack);C.restore(u,block['entry']['CPU']);entry_context=u.context_save()
    assert bytes(u.mem_read(C.BASE+spec['start'],spec['end']-spec['start']))==s.read(spec['start'],spec['end']-spec['start'])
    C.restore(u,block['initial_dispatch']['CPU']);cut_context=u.context_save();assert int(block['initial_dispatch']['CPU']['X31'][spec['counter']],16)==0
    state={'P':stack[0x498:0x4a8],'forced':None,'PAC':0,'initial':0,'splits':Counter()}
    def branch(uc,pc,n,d):
        offset=pc-C.BASE;initial=offset==spec['init'];tail=offset==spec['tail_dispatch'];target_reg=(15 if not tail else 8)if spec['kind']==0 else(2 if not tail else 14)
        target=uc.reg_read(getattr(U,'UC_ARM64_REG_X'+str(target_reg)));modifier=uc.reg_read(U.UC_ARM64_REG_X17)
        allowed={C.BASE+spec['head']}if initial else{C.BASE+spec['tail'],C.BASE+spec['end']}if tail else{C.BASE+spec['head'],C.BASE+spec['tail']}
        assert target in allowed and modifier==(0x831f if spec['kind']==0 else 0x9720 if tail else 0xc9c2)
        if initial:
            n=uc.reg_read(getattr(U,'UC_ARM64_REG_X'+str(spec['split'])));expected=select_split(state['P'],spec['kind'])if state['forced']is None else state['forced']
            assert n==expected and 1<=n<=15;state['initial']+=1;state['splits'][n]+=1
        state['PAC']+=1;uc.reg_write(U.UC_ARM64_REG_PC,target)
    for pc in [spec['init'],spec['head_dispatch'],spec['tail_dispatch']]:u.hook_add(UC_HOOK_CODE,branch,begin=C.BASE+pc,end=C.BASE+pc)
    def execute(prepared,forced=None):
        u.context_restore(entry_context if forced is None else cut_context);ram=bytearray(stack);ram[0x498:0x4a8]=prepared;write(sp,bytes(ram));state['P']=bytes(prepared);state['forced']=forced
        if forced is not None:u.reg_write(getattr(U,'UC_ARM64_REG_X'+str(spec['split'])),forced)
        before=state['PAC'];start=spec['start']if forced is None else spec['init'];u.emu_start(C.BASE+start,C.BASE+spec['end'],count=601)
        assert u.reg_read(U.UC_ARM64_REG_PC)==C.BASE+spec['end']and state['PAC']-before==17 and bytes(u.mem_read(sp,1312))==ram
        expected,_,residue=run_fold(prepared,block['initial_dispatch']['CPU'],spec['kind'],forced);got=[u.reg_read(getattr(U,'UC_ARM64_REG_X'+str(j)))&M32 for j in spec['state']]
        assert got==expected,(block['label'],spec['kind'],got,expected)
        residue_register=1 if spec['kind']==0 else 3
        assert u.reg_read(getattr(U,'UC_ARM64_REG_X'+str(residue_register)))==residue
        return got
    execute(stack[0x498:0x4a8]);assert C.frame(u)==block['end']['CPU'];state['PAC']=state['initial']=0;state['splits']=Counter();digest=sha256();cases=0;visits=0
    for varied in range(16):
        for value in range(256):
            prepared=bytearray(16);prepared[varied]=value;got=execute(prepared);digest.update(struct.pack('<4I',*got));n=select_split(prepared,spec['kind']);visits+=583-4*n if not spec['kind']else 590-5*n;cases+=1
    for value in range(256):
        prepared=bytes([value])*16;got=execute(prepared);digest.update(struct.pack('<4I',*got));n=select_split(prepared,spec['kind']);visits+=583-4*n if not spec['kind']else 590-5*n;cases+=1
    assert cases==4352 and state['PAC']==cases*17 and state['initial']==cases and set(state['splits'])==set(range(1,16))
    finite_pac=state['PAC'];hist=dict(state['splits']);forced_frames=[]
    for n in range(1,16):
        execute(stack[0x498:0x4a8],n);frame=C.frame(u);expected=copy.deepcopy(block['end']['CPU']);rr=1 if not spec['kind']else 3
        residue=u.reg_read(getattr(U,'UC_ARM64_REG_X'+str(rr)));expected['X31'][rr]=hex(residue);assert frame==expected
        forced_frames.append({'split':n,'residue_register':rr,'residue_u32':hex(residue),'CPU_sha256':SHA(json.dumps(frame,sort_keys=True).encode())})
    assert len({r['CPU_sha256']for r in forced_frames})>1
    return {'label':block['label'],'kind':spec['kind'],'finite_cases':cases,'finite_source_visits':visits,'finite_PAC_models':finite_pac,'finite_steps':cases*16,
      'finite_state_u32_checked':cases*4,'finite_residue_u32_checked':cases,'split_histogram':hist,'ordered_states_sha256':digest.hexdigest(),'actual_full_frame_cases':1,'forced_split_full_frame_cases':15,
      'forced_split_frames':forced_frames,'full_frames_differ_only_by_head_residue':True,'all_split_values_covered':True,'source_bytes_preserved':True,'no_memory_writes':True,
      'scope':'declared scan entries with earlier state fixed; one-byte variations plus constant-fill vectors; separate initial-dispatch cuts force n=1..15; PAC modeled'}


def main():
    raw=read(ROOT/'corefp_preparation_scans_checks.json').encode();e=json.loads(raw);checks_sha=SHA(raw)
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_preparation_scans.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    pinned={}
    for name,h in e['parent_pins'].items():
        raw=read(ROOT/name).encode();assert SHA(raw)==h;pinned[name]=json.loads(raw)
    assert len(pinned)==8
    for name,h in e['dependencies'].items():assert SHA(read(ROOT/name).encode())==h
    parent=pinned['corefp_workspace_checks.json'];pa=pinned['corefp_workspace_audit.json'];pe=pinned['corefp_output_packing_checks.json'];ce=pinned['corefp_workspace_consumers_checks.json'];le=pinned['corefp_late_preparation_checks.json']
    s=C.Pointers()
    for span in parent['source_spans']:assert span==s.function(int(span['start'],16))
    for region,spec in zip(e['source_regions'],SPECS):
        assert int(region['start'],16)==spec['start']and int(region['end'],16)==spec['end']
        ins=list(C.CS.disasm(s.read(spec['start'],spec['end']-spec['start']),spec['start']))
        assert region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in ins]
        assert not any(i.mnemonic.startswith('st')for i in ins)
    frozen=[p for m in le['transfer_models']for p in m['proofs']]+[pe['common_inverse_proof']]+[p for m in pe['transfer_models']for p in m['proofs']]+ce['source_model']['proofs']+ce['canonical_phase_proofs']+pa['source_checks']['proofs']+[p for f in pa['frozen_source_checks']for p in f['proofs']]
    new=e['source_checks']['proofs'];assert len(new)==30 and len(frozen)==1040
    for p in new+frozen:
        assert p['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert q.check()==z3.unsat,p['label']
    cells={}
    for b in e['blocks']:
        for row in b['PAC_models']:
            pr=row['pointer_row'];at=C.BASE+int(pr['address'],16);assert cells.get(at,pr)==pr;cells[at]=pr
    assert len(cells)==7 and all(r['authenticated']and r['chain_membership_verified']and not r['bind']for r in cells.values())
    totals=Counter();scalars=[];machines=[];oracles=[];ordinal=0
    for p,construction,form in zip(parent['profiles'],parent['workspace_constructions'],pa['workspace_oracles']):
        totals.update(A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());W.T.oracle(p,r)
        assert W.workspace_oracle(p,r,s,construction)==form;W.preparation_oracle(p,r,s);pair=[]
        for kind,block in enumerate(r.scans):
            b=e['blocks'][ordinal];o=e['oracles'][ordinal];spec=SPECS[kind];assert b['kind']==o['kind']==kind and b['label']==o['label']==p['configuration']['label']
            assert block['entry']==b['entry']and block['end']==b['end'];lo,hi=b['entry']['source_visit'],b['end']['source_visit']
            for key in ['reads','writes','PAC_models']:assert b[key]==[x for x in p[key]if lo<=x['visit']<hi]
            assert b['visits']==p['visits'][lo:hi]and b['initial_dispatch']==next(x for x in b['PAC_models']if x['pc']==hex(spec['init']))
            prepared=bytes.fromhex(b['entry']['stack1312_hex'])[0x498:0x4a8];init=b['initial_dispatch']['CPU'];q=[int(x,16)&M32 for x in init['X31']]
            assert q[2 if not kind else 6]==0x750549fb and q[0]==0xdecc2544 and q[9]==0xef6612a2 and q[spec['state'][3]]==0x6d31a173
            if kind==0:assert (q[10]-0x4d1d)&31==8
            else:assert q[16]==q[0]and(q[8]-0x41f8)&31==16 and q[1]==0x4b
            n=select_split(prepared,kind);state,delta,residue=run_fold(prepared,init,kind);assert n==o['split']==q[spec['split']]
            assert o['head_residue_u32']==hex(residue)and o['head_residue_register']==(1 if not kind else 3)
            assert list(map(hex,state))==o['final_state_u32']and list(map(hex,delta))==o['xor_deltas_u32']and len(o['iterations'])==16
            assert state==[int(b['end']['CPU']['X31'][j],16)&M32 for j in spec['state']]
            assert hi-lo==(583-4*n if not kind else 590-5*n)and len(b['reads'])==(54 if not kind else 55)and len(b['PAC_models'])==17 and not b['writes']
            scalars.append(scalar(b,s));machines.append(machine_cases(p,b,s,cells));pair.append((delta,state[3]));oracles.append({'label':b['label'],'kind':kind,'split':n,'xor_deltas_u32':list(map(hex,delta)),'final_state_u32':list(map(hex,state)),'head_residue_u32':hex(residue)});ordinal+=1
        assert pair[0]==pair[1];print(json.dumps({'audited':p['configuration']['label'],'regions':ordinal,'finite_cases':sum(m['finite_cases']for m in machines)}),flush=True)
    assert ordinal==12 and dict(totals)==pinned['corefp_workspace_consumers_audit.json']['result']['independent_replay']and e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    counts={'profiles':6,'scan_regions':12,'static_instructions':184,'static_source_B':736,'regional_visits':6674,'regional_reads':654,'regional_writes':0,'regional_PAC_models':204,'prepared_read_instances':240,'scan_steps':192,'new_queries_unsat':30};assert e['verified_counts']==counts
    result={'verified_counts':counts,'independent_replay':dict(totals),'independent_scalar':dict(sum((Counter({k:v for k,v in row.items()if type(v)is int})for row in scalars),Counter())),
      **{k:sum(row[k]for row in machines)for k in ['finite_cases','finite_source_visits','finite_PAC_models','finite_steps','finite_state_u32_checked','finite_residue_u32_checked','actual_full_frame_cases','forced_split_full_frame_cases']},
      'split_values_covered_per_region':15,'relocated_dispatch_cells_checked':7,'paired_delta_matches':6,'frozen_queries_unsat':1040,'total_queries_unsat':1070,'all_checks_pass':True,'native_target_executed':False}
    out={'result':result,'checks_sha256':checks_sha,'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],'dependencies':e['dependencies'],
      'component_oracles':oracles,'scalar_oracles':scalars,'machine_oracles':machines,'dispatch_cells':[{'address':hex(at-C.BASE),**row}for at,row in sorted(cells.items())],
      'fresh_replay_completed':True,'process_exit_code':0,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,
      'general_raw_preparation_contract_established':False,'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_preparation_scans_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
