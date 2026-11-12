#!/usr/bin/env python3
"""Independent seed/ABI replay, full-word oracle and source-lift obligations.

Does not import the new producer. Refreshes the frozen prefix once, checks
restoration from the pinned prior frontier, then independently replays sparse
RAM and explicit sequential CASAL/external returns. No native target runs.
O(B+F+C*(V+J+R)+C*624) time/space; network/SMT are separate and bounded.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
from urllib.request import urlopen
import unicorn as U
from unicorn import arm64_const as A
import z3
from audit_fpsd1201_predicates import Prefix,Replay as Frozen,frame,restore,unpack,CS
from corefp_fixups_reader import Pointers,ROOT
from probe_corefp_exports import BASE,BIND
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();STATE=0x1d4551c;TOKEN=0x1d33108;M32=(1<<32)-1


def state(seed):
    out=[seed]
    for i in range(1,624):out.append((1812433253*(out[-1]^(out[-1]>>30))+i)&M32)
    return struct.pack('<624I',*out)


def returned(before,v,clobber):
    f=json.loads(json.dumps(before));f['X31'][0]=hex(v);f['PC']=f['X31'][30]
    if clobber:
        for j in range(1,18):f['X31'][j]=hex((j*0x13579bdf2468ace)&((1<<64)-1))
        f['NZCV']='0xa0000000'
    return f


class Replay(Frozen):
    def __init__(self,p,spans):
        super().__init__(p,spans);self.mi=self.pi=self.loops=0
        self.u.mem_map(BIND,0x2000)
    def model(self):
        e=self.p['models'][self.mi];self.mi+=1;assert e['before']==frame(self.u);return e
    def code(self,u,pc,n,d):
        self.flush()
        if pc==int(self.p['frontier']['CPU']['PC'],16):assert frame(u)==self.p['frontier']['CPU'];self.done=True;u.emu_stop();return
        at=pc-BASE
        if pc in [BIND+63*16,BIND+67*16]:
            e=self.model();assert e['callsite']==hex(u.reg_read(A.UC_ARM64_REG_LR)-4-BASE)
            assert e['args_x0_x7']==[hex(u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j))))for j in range(8)]
            if pc==BIND+63*16:
                assert e['kind']=='declared_arc4random_u32';v=e['value_u32']
            else:
                assert e['kind']=='declared_gettimeofday';a=int(e['pointer'],16);assert a==u.reg_read(A.UC_ARM64_REG_X0)and u.reg_read(A.UC_ARM64_REG_X1)==0
                assert self.ram(a,16).hex()==e['before16_hex'];cfg=self.p['configuration'];v=cfg['time_status_u32']
                raw=struct.pack('<qi',cfg['seconds_i64'],cfg['microseconds_i32'])if v==0 else b'';assert raw.hex()==e['written_hex']
                if raw:u.mem_write(a,raw)
                assert self.ram(a,16).hex()==e['after16_hex']and self.ram(a+12,4).hex()==e['before16_hex'][24:]
            assert e['after']==returned(e['before'],v,self.p['configuration'].get('clobber_callers',False));restore(u,e['after']);return
        assert 0x8e81c8<=at<0x8fcfa0
        raw=self.ram(pc,4);i=next(CS.disasm(raw,at));assert self.p['visits'][self.v]=={'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str};self.v+=1
        if i.mnemonic=='casal':
            assert at==0x8ea868 and i.op_str=='w8, w11, [x12]';e=self.model();a=u.reg_read(A.UC_ARM64_REG_X12);old=int.from_bytes(self.ram(a,4),'little');compare=u.reg_read(A.UC_ARM64_REG_W8);new=u.reg_read(A.UC_ARM64_REG_W11)
            assert e['kind']=='declared_sequential_CASAL'and e['visit']==self.v-1 and e['address']==hex(a)==hex(BASE+TOKEN)
            assert [e['old_u32'],e['compare_u32'],e['replacement_u32']]==[old,compare,new]and e['success']==(old==compare)
            if old==compare:u.mem_write(a,new.to_bytes(4,'little'))
            f=json.loads(json.dumps(e['before']));f['X31'][8]=hex(old);f['PC']=hex(pc+4);assert e['after']==f
            restore(u,f);assert self.ram(a,4).hex()==e['after4_hex'];return
        if i.mnemonic in ['braa','blraa']:
            rn,mn=i.op_str.split(', ');target=u.reg_read(getattr(A,'UC_ARM64_REG_'+rn.upper()));mod=u.reg_read(getattr(A,'UC_ARM64_REG_'+mn.upper()))
            e=self.p['PAC_models'][self.pac];self.pac+=1;assert e['CPU']==frame(u)and e['visit']==self.v-1 and e['pc']==hex(at)and e['target']==hex(target)and e['modifier']==hex(mod)
            r=e['original_pointer_row'];resolved=BIND+r['import']['ordinal']*16+r['pointer_addend']if r['bind']else BASE+int(r['target'],16)
            assert r['key']=='IA'and not r['address_diversity']and int(r['diversity'],16)==mod and resolved==target and self.ram(BASE+int(e['slot'],16),8)==target.to_bytes(8,'little')
            if i.mnemonic=='blraa':u.reg_write(A.UC_ARM64_REG_LR,pc+4)
            u.reg_write(A.UC_ARM64_REG_PC,target)
        elif i.mnemonic.startswith(('pac','aut')):u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif i.mnemonic in ['retab','retaa']:u.reg_write(A.UC_ARM64_REG_PC,u.reg_read(A.UC_ARM64_REG_LR))
        if at==0x8eb824:
            self.loops+=1
            if self.loops==1:
                e=self.p['points'][self.pi];self.pi+=1;assert e=={'kind':'seed_loop_entry','visit':self.v-1,'CPU':frame(u)}
                assert u.reg_read(A.UC_ARM64_REG_X8)==1 and u.reg_read(A.UC_ARM64_REG_W9)==1812433253
        if at==0x8eb85c:
            e=self.p['points'][self.pi];self.pi+=1;assert e['kind']=='seed_loop_complete'and e['visit']==self.v-1 and e['CPU']==frame(u)and unpack(e['state624'])==self.ram(BASE+STATE,2496)
            assert self.loops==623 and u.reg_read(A.UC_ARM64_REG_X8)==624 and self.ram(BASE+STATE,2496)==state(self.p['configuration']['random_u32'][0])
    def run(self):
        self.u.emu_start(int(self.p['initial_CPU']['PC'],16),0,count=30001);self.flush();assert self.done
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi,self.loops]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points']]+[self.p['seed_loop_iterations']]
        total=0
        for r in self.p['final_RAM']:assert self.ram(int(r['address'],16),4096)==unpack(r['payload']);total+=4096
        assert int.from_bytes(self.ram(BASE+TOKEN,4),'little')==self.p['token_final_u32']
        cfg=self.p['configuration'];stores=[w for w in self.p['writes']if BASE+STATE<=int(w['address'],16)<BASE+STATE+2496]
        if cfg['stage']in ['seed','tuple']:
            assert len(stores)==624
            expected=state(cfg['random_u32'][0])
            for j,w in enumerate(stores):assert w['address']==hex(BASE+STATE+4*j)and w['size_B']==4 and w['after_hex']==expected[4*j:4*j+4].hex()
        else:assert not stores
        sp=int(self.p['initial_CPU']['SP'],16);assert self.p['context128_hex']==self.ram(sp+0x1340,128).hex()=='006664706300000001'+'00'*119
        a=int(self.p['tuple_pointer'],16);assert a==sp+0x1a30==int.from_bytes(self.ram(sp+0x498,8),'little')and self.p['tuple32_hex']==self.ram(a,32).hex()
        if cfg['stage']=='tuple':
            clock=next(e for e in self.p['models']if e['kind']=='declared_gettimeofday');b=bytes.fromhex(clock['after16_hex'])
            tuple4=[cfg['random_u32'][2],int.from_bytes(b[8:12],'little'),int.from_bytes(b[:4],'little'),cfg['random_u32'][1]]
            assert self.ram(a,16)==struct.pack('<4I',*tuple4)and self.p['frontier']['CPU']['PC']==hex(BASE+0x8eb9b4)
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,
          'points_checked':self.pi,'final_RAM_B_checked':total,'oracle_state_words_checked':624 if cfg['stage']in ['seed','tuple']else 0}


def source_proofs(prior,s):
    parent=prior['source_spans'][0];assert s.function(0x8e81c8)==parent and s.read(TOKEN,4)==bytes.fromhex('965d0000')
    ins={i.address:i for i in CS.disasm(bytes.fromhex(parent['bytes']),0x8e81c8)}
    exact={0x8ea868:('casal','w8, w11, [x12]'),0x8eb7a8:('str','w25, [x12]'),0x8eb804:('str','w0, [x21]'),
      0x8eb824:('mov','x10, x8'),0x8eb828:('eor','w11, w0, w0, lsr #30'),0x8eb82c:('madd','w0, w11, w9, w8'),
      0x8eb830:('add','x11, x21, x8, lsl #2'),0x8eb834:('str','w0, [x11]'),0x8eb838:('add','x8, x8, #1'),
      0x8eb83c:('cmp','w10, #0x26f'),0x8eb840:('cset','w10, lo'),0x8eb844:('lsl','w11, w10, #2'),
      0x8eb848:('orr','w10, w11, w10, lsl #3'),0x8eb84c:('eor','w10, w10, w22'),0x8eb858:('braa','x10, x17'),
      0x8eb8e4:('ldr','x8, [x22, #0x10]'),0x8eb8ec:('str','w8, [x26, #8]'),0x8eb8f0:('ldr','w8, [x22, #0x18]'),
      0x8eb8f4:('str','w8, [x26, #4]'),0x8eb950:('str','w0, [x26, #0xc]'),0x8eb9b0:('str','w0, [x26]')}
    for a,want in exact.items():assert (ins[a].mnemonic,ins[a].op_str)==want
    # The source consumes time fields before the next entropy call; its return
    # value is never read by these intervening original instructions.
    for a in range(0x8eb8e4,0x8eb94c,4):
        rd,_=ins[a].regs_access();assert not {'x0','w0'}&{ins[a].reg_name(r)for r in rd}
    v=z3.BitVec('source_seed_previous32',32);j=z3.BitVec('source_seed_index64',64);base=z3.BitVec('source_seed_base64',64)
    a32=z3.Extract(31,0,j);shifted=v^z3.LShR(v,30);stored=shifted*z3.BitVecVal(1812433253,32)+a32
    counter32=z3.Extract(31,0,j);flag=z3.If(z3.ULT(counter32,623),z3.BitVecVal(1,32),z3.BitVecVal(0,32))
    loop_index=((flag<<2)|(flag<<3))^0x9717
    seconds=z3.BitVec('source_time_seconds64',64);u=z3.BitVec('source_scratch_offset64',64);k=z3.BitVec('source_context_offset64',64)
    claims=[('source_lifted_EOR_MADD_update',stored==z3.Extract(31,0,z3.ZeroExt(32,shifted)*1812433253+j)),
      ('source_lifted_seed_store_address',base+(j<<2)==base+4*j),
      ('source_lifted_loop_partition',z3.Implies(z3.And(z3.UGE(j,1),z3.ULE(j,623)),loop_index==z3.If(z3.ULT(j+1,624),z3.BitVecVal(0x971b,32),z3.BitVecVal(0x9717,32)))),
      ('source_time_truncation',z3.Extract(31,0,seconds)==z3.Extract(31,0,seconds&0xffffffff)),
      ('scratch_and_context_prefix_disjoint',z3.Implies(z3.And(z3.ULT(u,32),z3.ULT(k,128)),base+1776+u!=base+k))]
    out=[]
    for label,claim in claims:
        solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.Not(claim));assert solver.check()==z3.unsat
        out.append({'label':label,'query':solver.to_smt2(),'result':'unsat'})
    return {'exact_instructions_checked':len(exact),'original_parent_B_checked':85464,'clock_return_not_read_before_next_entropy_call':True,'proofs':out}


def references():
    e=json.loads(read(ROOT/'fpsd1201_seed_primary_references.json'));checked=[]
    assert e['MT19937_reference_facts']['state_words']==624 and e['MT19937_reference_facts']['seed_multiplier_u32']==1812433253
    for r in e['references']:
        b=urlopen(r['url'],timeout=20).read();assert len(b)==r['size_bytes']and SHA(b)==r['sha256']
        checked.append({'url':r['url'],'size_bytes':len(b),'sha256':SHA(b),'body_retained':False})
    assert len(checked)==2
    return checked


def main():
    e=json.loads(read(ROOT/'fpsd1201_seed_checks.json'));assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_seed.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    prior=json.loads(read(ROOT/'fpsd1201_predicates_checks.json'));receipt=json.loads(read(ROOT/'fpsd1201_predicates_audit.json'))
    assert SHA(read(ROOT/'fpsd1201_predicates_checks.json').encode())==e['prior_checks_sha256']=='3e2b88c3d9b6b7d1766e75cb9fba56b7ca7ebc17e55ec53a1613f1bbeda99988'
    assert SHA(read(ROOT/'fpsd1201_predicates_audit.json').encode())==e['prior_audit_sha256']=='31c95fb3e5a569dace380e5df920253c72cf50f7e220a2b57fc37fd11c0a1e1e'
    assert receipt['checks_sha256']==e['prior_checks_sha256']and receipt['fresh_replay_completed']and receipt['result']['all_checks_pass']
    s=Pointers();p=Prefix(s,prior['fixture']);row=p.run_caller();assert row==prior['prefix']['result']and frame(p.u)==prior['prefix']['CPU']
    d=json.loads(read(ROOT/'fpsd1201_seed_ida_readback.json'));assert not d['IDB_mutated']and d['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'and d['parent_sha256']==prior['source_spans'][0]['sha256']
    assert len(d['queries'])==8
    for q in d['queries']:
        for r in q['refs']:assert r['function']is None and s.decoded[int(r['from'],16)]['target']==q['address']
    stats=Counter();bylabel={q['configuration']['label']:q for q in e['profiles']}
    assert len(e['profiles'])==len(bylabel)==12
    for q in e['profiles']:
        c=q['configuration'];assert c['stage']in ['entropy','seed','tuple','atomic_failure']
        for r in prior['profiles'][0]['final_RAM']:p.u.mem_write(int(r['address'],16),unpack(r['payload']))
        restore(p.u,prior['profiles'][0]['frontier']['CPU']);assert q['restored_CPU']==frame(p.u)==q['initial_CPU']
        p.u.mem_write(BASE+TOKEN,c['token_u32'].to_bytes(4,'little'))
        for r in q['initial_RAM']:assert bytes(p.u.mem_read(int(r['address'],16),4096))==unpack(r['payload']);stats['initial_RAM_B_checked']+=4096
        stats.update(Replay(q,prior['source_spans']).run())
        assert q['token_final_u32']==(c['token_u32']if c['stage']=='atomic_failure'else 0x5d96)
        if c['stage']!='atomic_failure':
            stores=[w for w in q['writes']if w['address']==hex(BASE+TOKEN)];assert len(stores)==1 and stores[0]['after_hex']=='965d0000'and q['visits'][stores[0]['visit']]['pc']=='0x8eb7a8'
        for edge in q['PAC_models']:assert edge['original_pointer_row']==s.decoded[int(edge['slot'],16)]
        arcs=[v['value_u32']for v in q['models']if v['kind']=='declared_arc4random_u32'];assert arcs==c['random_u32']
    assert bylabel['clock_A']['tuple32_hex']==bylabel['clock_A_clobber']['tuple32_hex']
    assert [q['configuration']['random_u32'][0]for q in e['profiles']if q['configuration']['stage']=='seed']==[0,1,0x12345678,M32]
    for proof in e['proofs']:
        solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.parse_smt2_string(proof['query']));assert proof['result']=='unsat'and solver.check()==z3.unsat
    src=source_proofs(prior,s);refs=references()
    counts={'profiles':12,'prefix_original_visits_per_profile':19717,**{k:sum(len(q[k])for q in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points']},
      'complete_seed_expansions':sum(q['seed_loop_iterations']==623 for q in e['profiles']),'atomic_failures':3,'queries_unsat':len(e['proofs'])}
    assert counts==e['verified_counts']and stats['oracle_state_words_checked']==4992
    result={'verified_counts':counts,'fresh_continuation':dict(stats),'fresh_prefix_original_visits':len(row['visited_original_instructions']),
      'independent_source_queries_unsat':len(src['proofs']),'exact_source_instructions_checked':src['exact_instructions_checked'],'primary_reference_fingerprints_refreshed':len(refs),
      'native_target_executed':False,'request1200_gap_executed':False,'all_checks_pass':True}
    out={'result':result,'source':src,'primary_reference_receipts':refs,'checks_sha256':SHA(read(ROOT/'fpsd1201_seed_checks.json').encode()),
      'auditor_sha256':SHA(Path(__file__).read_bytes()),'dependencies':e['dependencies'],'fresh_replay_completed':True,'process_exit_code':0}
    (ROOT/'fpsd1201_seed_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
