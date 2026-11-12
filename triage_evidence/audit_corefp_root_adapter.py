#!/usr/bin/env python3
"""Independent original-byte adapter/root replay and modular ABI contracts.

Does not import the new producer. Complete touched initial RAM, retained CPU,
data accesses, API/PAC effects and final RAM are independently checked.
Conservative O(C*(B+P*F+V*J+R)) time/space upper bound, with 30000 visits
per profile and a separate 30 s bound per bit-vector solver query.
"""
import bisect,json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_corefp_lookup_release import Replay as Frozen,parent_inputs,frame,unpack,CS
from audit_corefp_lookup_initialization import initial_page,declared_inputs
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M64=(1<<64)-1
ENTRY=0x8fcfa0;PARENT=0x63000800;CURSOR=0x63000e00;DONE=0x65000000;HEAP=0x64000000


class Replay(Frozen):
    def __init__(self,p,spans,s):
        super().__init__(p,spans,s);self.ai=0;self.inner=None
    def adapter_point(self,label):
        want={'label':label,'CPU':frame(self.u),'external_word_u64':hex(int.from_bytes(self.ram(CURSOR,8),'little')),
          'internal_word_address':None if self.inner is None else hex(self.inner),
          'internal_word_u64':None if self.inner is None else hex(int.from_bytes(self.ram(self.inner,8),'little')),
          'record48_hex':self.ram(PARENT,48).hex(),'visits_so_far':self.v}
        assert self.p['adapter_points'][self.ai]==want;self.ai+=1
    def code(self,u,pc,n,d):
        self.flush()
        if pc==BASE+0x8fd1b8:self.inner=u.reg_read(A.UC_ARM64_REG_X1);self.adapter_point('before_original_child_call')
        if pc==BASE+0x8e81c8:self.adapter_point('original_root_entry')
        if pc==BASE+0x8fd1bc:self.adapter_point('original_root_return')
        if pc==DONE:self.adapter_point('outer_return')
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=30001);self.flush();assert self.done and not self.once
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi,self.hi,self.li,self.mri,self.di,self.ai,self.bi,self.cert]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points','handoffs','lock_events','metadata_returns','daemon_children','adapter_points']]+[self.p['bootstrap_calls'],self.p['certificate_allocation_attempts']]
        assert self.allocs==self.p['allocations_attempted']==2 and self.snapshot('frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,'points_checked':self.pi,
          'handoffs_checked':self.hi,'lock_events_checked':self.li,'metadata_returns_checked':self.mri,'daemon_children_fresh_checked':self.di,
          'adapter_points_checked':self.ai,'bootstrap_calls_checked':self.bi,'certificate_allocation_attempts_checked':self.cert,
          'outer_returns_checked':1,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(p):
    c=p['configuration'];label=c['label'];seed=int(c['seed_u64'],16);failed=label in ['lookup_error','fallback_error']
    assert set(c)=={'label','allocation_success','lock_init_status_u32','continue_to_bootstrap','bootstrap_results','unlock_status_u32','seed_u64'}|({'clobber_callers'}if label=='clobber_null'else set())
    seq=[(5,None)]if label=='lookup_error'else [(1102,None),(5,None)]if label=='fallback_error'else [(1102,None),(0,0x5034)]if label=='fallback_null'else [(0,0x5017)]
    assert c['allocation_success']==[label!='static_null',True]and c['lock_init_status_u32']==[0,0]and c['continue_to_bootstrap']
    assert c['bootstrap_results']==[{'status_u32':s,**({'write_port_u32':v}if v is not None else {})}for s,v in seq]
    assert c['unlock_status_u32']==(5 if label=='unlock_error'else 0)and bool(c.get('clobber_callers'))==(label=='clobber_null')
    a,entry,returned,outer=p['adapter_points'];assert [r['label']for r in [a,entry,returned,outer]]==['before_original_child_call','original_root_entry','original_root_return','outer_return']
    pad=16*(1+(((seed*0x2edd+1)&M64)>>60));sp=int(p['initial_CPU']['SP'],16);inner=sp-64-pad
    assert [r['internal_word_address']for r in [a,entry,returned,outer]]==[hex(inner)]*4
    assert [r['external_word_u64']for r in [a,entry,returned,outer]]==[hex(seed)]*3+['0x0']
    assert [r['internal_word_u64']for r in [a,entry,returned,outer]]==[hex((seed-256)&M64)]*2+[hex(seed)]*2
    assert [a['CPU']['X31'][0],entry['CPU']['X31'][0]]==[hex(PARENT)]*2
    assert a['CPU']['X31'][1]==entry['CPU']['X31'][1]==hex(inner)and a['CPU']['SP']==entry['CPU']['SP']==hex(inner)
    assert a['record48_hex']==entry['record48_hex']==parent_inputs()[0][1].hex()
    status=0x45e2a2e3 if failed else 0x45e2a20f;record=status.to_bytes(4,'little')+parent_inputs()[0][1][4:]
    assert returned['record48_hex']==outer['record48_hex']==record.hex()and p['parent_return']['parent_record48_hex']==record.hex()
    assert returned['CPU']['X31'][0]==outer['CPU']['X31'][0]==hex(c['unlock_status_u32'])
    assert outer['CPU']['SP']==p['initial_CPU']['SP']and outer['CPU']['X31'][19:31]==p['initial_CPU']['X31'][19:31]
    assert p['parent_return']['cursor_u64']=='0x0'and p['frontier']=={'reason':'parent_return','CPU':outer['CPU']}
    writes=[w for w in p['writes']if int(w['address'],16)<inner+8 and inner<int(w['address'],16)+w['size_B']]
    assert [(p['visits'][w['visit']]['pc'],w['address'],w['size_B'],w['after_hex'])for w in writes]==[
      ('0x8fd114',hex(inner),8,((seed-256)&M64).to_bytes(8,'little').hex()),('0x8e830c',hex(inner),8,seed.to_bytes(8,'little').hex())]
    outer_writes=[w for w in p['writes']if int(w['address'],16)<CURSOR+8 and CURSOR<int(w['address'],16)+w['size_B']]
    assert len(outer_writes)==1 and p['visits'][outer_writes[0]['visit']]['pc']=='0x8fd1c8'and outer_writes[0]['address']==hex(CURSOR)
    assert outer_writes[0]['size_B']==8 and outer_writes[0]['before_hex']==seed.to_bytes(8,'little').hex()and outer_writes[0]['after_hex']=='00'*8
    pac=p['PAC_models'][0];assert pac['pc']=='0x8fd1b8'and pac['target']==hex(BASE+0x8e81c8)and pac['modifier']=='0x41d4'and pac['pointer_row']['address']=='0x1d05150'
    load=p['reads'][pac['load_index']];assert load['address']==hex(BASE+0x1d05150)and p['visits'][load['visit']]['pc']=='0x8fd1ac'
    lock=BASE+0x1d27bf0 if label=='static_null'else HEAP
    assert [v['pointer']for v in p['lock_events']]==[hex(lock)]*2 and [v['status_u32']for v in p['lock_events']]==[0,c['unlock_status_u32']]
    assert p['parent_return']['held_lock_model']==(hex(lock)if c['unlock_status_u32']else None)
    assert p['certificate_allocation_attempts']==int(not failed)and len(p['daemon_children'])==int(label not in ['fallback_null','lookup_error','fallback_error'])
    if label.startswith('pad_'):assert pad==16*(1+int(label[4:]))
    return {'label':label,'seed_u64':hex(seed),'dynamic_padding_B':pad,'fixed_frame_B':64,'internal_word_address':hex(inner),
      'child_input_u64':hex((seed-256)&M64),'child_output_u64':hex(seed),'external_output_u64':'0x0',
      'raw_record_result_u32':hex(status),'residual_X0_u64':hex(c['unlock_status_u32']),'root_source_slot':'0x1d05150',
      'native_target_executed':False,'record_is_upstream_native_input':False}


def source_checks(s):
    exact={0x8fcfb8:('mov','x19, x1'),0x8fd098:('ldr','x21, [x1]'),0x8fd09c:('mov','w15, #0x2edd'),
      0x8fd0d8:('mov','x1, #1'),0x8fd0ec:('madd','x15, x21, x15, x1'),0x8fd0f0:('str','x15, [x16]'),
      0x8fd0f4:('lsr','x15, x15, #0x3c'),0x8fd0f8:('lsl','w15, w15, #4'),0x8fd0fc:('add','w15, w15, #0x1f'),
      0x8fd100:('and','x15, x15, #0x1f0'),0x8fd104:('mov','x16, sp'),0x8fd108:('sub','x20, x16, x15'),0x8fd10c:('mov','sp, x20'),
      0x8fd110:('sub','x15, x21, #0x100'),0x8fd114:('str','x15, [x20]'),0x8fd1ac:('ldur','x8, [x8, #-4]'),
      0x8fd1b0:('mov','x1, x20'),0x8fd1b4:('mov','x17, #0x41d4'),0x8fd1b8:('blraa','x8, x17'),
      0x8fd1bc:('ldr','w8, [x20]'),0x8fd1c0:('sub','w8, w8, w21'),0x8fd1c4:('ubfiz','x8, x8, #4, #0x10'),0x8fd1c8:('str','x8, [x19]'),
      0x8fd1cc:('sub','sp, x29, #0x20'),0x8fd1dc:('retab',''),0x8e8304:('ldr','x9, [x1]'),0x8e8308:('add','x9, x9, #0x100'),0x8e830c:('str','x9, [x1]')}
    for a,want in exact.items():i=next(CS.disasm(s.read(a,4),a));assert (i.mnemonic,i.op_str)==want
    # Original adapter leaves X0 unchanged before the child and after return.
    checked=0
    for lo,hi in [(ENTRY,0x8fd1b8),(0x8fd1bc,0x8fd1e0)]:
        for i in CS.disasm(s.read(lo,hi-lo),lo):
            assert not any(CS.reg_name(r)in ['x0','w0']for r in i.regs_access()[1]);checked+=1
    seed,value=z3.BitVecs('seed_u64 child_value_u64',64);a=seed*0x2edd+1
    nibble=z3.LShR(a,60);w=z3.Extract(31,0,nibble)<<4
    source_pad=z3.ZeroExt(32,w+31)&0x1f0
    delta=z3.Extract(31,0,value)-z3.Extract(31,0,seed)
    source_out=z3.ZeroExt(48,z3.Extract(15,0,delta))<<4
    claims=[('source_padding_all_u64',source_pad,16*(1+nibble)),
      ('source_output_low16_delta_all_u64',source_out,((value-seed)&0xffff)<<4),
      ('root_initial_advance_cancels_bias_all_u64',(seed-256)+256,seed),
      ('failure_external_output_all_u64',z3.substitute(source_out,(value,(seed-256)+256)),z3.BitVecVal(0,64)),
      ('output_period_65536',z3.substitute(source_out,(value,value+65536)),source_out)]
    proofs=[]
    for label,left,right in claims:
        sol=z3.Solver();sol.set(timeout=30000);sol.add(left!=right);assert sol.check()==z3.unsat
        proofs.append({'label':label,'query':sol.to_smt2(),'result':'unsat'})
    sol=z3.Solver();sol.set(timeout=30000);sol.add(z3.Or(z3.ULT(source_pad,16),z3.UGT(source_pad,256),source_pad&15!=0,
      z3.UGT(source_out,0xffff0),source_out&15!=0));assert sol.check()==z3.unsat
    proofs.append({'label':'padding_output_range_and_alignment','query':sol.to_smt2(),'result':'unsat'})
    # Independently enumerate all aligned __text words, not semantic IDA names.
    text=next(v for v in s.meta['sections']if v['section']=='__text');lo=text['address'];raw=s.read(lo,text['size']);sites=[]
    for off in range(0,len(raw)-4,4):
        word=int.from_bytes(raw[off:off+4],'little')
        if word&0xffe0001f!=0xd2800011 or (word>>5)&65535!=0x41d4:continue
        at=lo+off;i=next(CS.disasm(raw[off+4:off+8],at+4))
        if i.mnemonic not in ['braa','blraa']:continue
        ix=bisect.bisect_right(s.starts,at)-1
        sites.append({'modifier_site':hex(at),'callsite':hex(at+4),'instruction':i.mnemonic+' '+i.op_str,'function_start':hex(s.starts[ix]),'function_end':hex(s.starts[ix+1])})
    assert [r['callsite']for r in sites]==['0x77d398','0x8fd1b8','0x9d4064','0x1174224']
    return {'proofs':proofs,'exact_instructions_checked':len(exact),'adapter_no_X0_write_instructions_checked':checked,'literal_call_candidates':sites,
      'text_size_B':len(raw),'text_sha256':SHA(raw),'negative_control_delta_u64':'0x10000','negative_control_external_output_u64':'0x0',
      'zero_output_is_injective':False}


def main():
    e=json.loads(read(ROOT/'corefp_root_adapter_checks.json'));s=Pointers();assert e['thin_sha256']==THIN_SHA and e['daemon_thin_sha256']==SHA(SOURCE.read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_root_adapter.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['declared_inputs_without_profile_seed']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()+parent_inputs()]
    auth=next(r for r in s.meta['sections']if r['section']=='__auth_stubs')
    for f in e['source_spans']:
        a,b=int(f['start'],16),int(f['end'],16)
        if 'kind'in f:assert f['kind']=='complete_import_stub_16B'and b-a==16 and (a-auth['address'])%16==0 and f['bytes']==s.read(a,16).hex()and f['sha256']==SHA(s.read(a,16))
        else:assert f==s.function(a)
    totals=Counter();oracles=[];seeds=[]
    for p in e['profiles']:
        seed=int(p['configuration']['seed_u64'],16);seeds.append(seed)
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':'0x62018000','PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(PARENT);cpu['X31'][1]=hex(CURSOR);cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(initial_page(s,a))
            for addr,raw in parent_inputs()+[(CURSOR,seed.to_bytes(8,'little'))]:
                if a<=addr<addr+len(raw)<=a+4096:b[addr-a:addr-a+len(raw)]=raw
            assert unpack(row['payload'])==bytes(b);totals['initial_RAM_B_checked']+=4096
        replay=Replay(p,e['source_spans'],s);totals.update(replay.run());oracles.append(oracle(p))
    labels=[p['configuration']['label']for p in e['profiles']]
    assert labels==['primary_null','fallback_null','static_null','clobber_null','unlock_error','lookup_error','fallback_error']+['pad_'+str(n)for n in range(16)]+['seed_100','seed_max']
    assert seeds[:7]==[0]*7 and seeds[-2:]==[256,M64]
    assert {v['dynamic_padding_B']for v in oracles}==set(range(16,257,16))
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children','handoffs','lock_events','adapter_points']},
      'bootstrap_calls':sum(p['bootstrap_calls']for p in e['profiles']),'certificate_allocation_attempts':sum(p['certificate_allocation_attempts']for p in e['profiles'])};assert counts==e['verified_counts']
    source=source_checks(s);census=e['census'];assert census['literal_call_candidates']==source['literal_call_candidates']
    assert census['text_sha256']==source['text_sha256']and census['text_size_B']==source['text_size_B']
    same=[r for r in s.decoded.values()if r.get('key')=='IA'and r.get('diversity')=='0x41d4'and not r['bind']]
    assert census['same_diversity_rebase_rows']==same and len(same)==4 and {r['target']for r in same}=={'0x59fb30','0x656b80','0x8e81c8','0x779ff0'}
    assert census['root_reference_rows']==[s.decoded[0x1d05150]]and census['exports']==s.exports
    assert not census['root_is_exported']and not census['adapter_is_exported']
    d=json.loads(read(ROOT/'corefp_root_adapter_ida.json'));live=[]
    assert d['target']=='c3d025e56a86'and not d['IDB_mutated']and not d['native_target_executed']and d['recall']['count']==0 and not d['recall']['truncated']
    for v in d['bytes']['results']:
        raw=bytes.fromhex(v['bytes']);a=int(v['address'],16);assert len(raw)==v['size_read']==v['size_requested']
        if a==0x1d05150:
            assert raw==int(s.decoded[a]['target'],16).to_bytes(8,'little')and raw!=s.read(a,8)
            live.append({'address':v['address'],'size_B':8,'sha256':SHA(raw),'kind':'IDA_decoded_rebase_target',
              'original_chained_word_hex':s.read(a,8).hex(),'original_pointer_row':s.decoded[a]})
        else:
            assert raw==s.read(a,len(raw));live.append({'address':v['address'],'size_B':len(raw),'sha256':SHA(raw),'kind':'original_source_bytes'})
    refs={r['address']:r['xrefs_to']for r in d['xrefs']['results']};assert [r['from']for r in refs['0x8e81c8']]==['0x1d05150']and refs['0x1d05150']==[]
    result={'verified_counts':counts,'independent_client_replay':dict(totals),'compact_oracle_profiles':len(oracles),'client_source_spans':len(e['source_spans']),
      'client_source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans']),
      'live_source_B_checked':sum(v['size_B']for v in live if v['kind']=='original_source_bytes'),'live_decoded_pointer_B_checked':8,
      'source_queries_unsat':len(source['proofs']),'exact_instructions_checked':source['exact_instructions_checked'],'dynamic_padding_values_covered':16,
      'literal_call_candidates':4,'same_diversity_rebase_rows':4,'confirmed_adapter_root_calls':25,
      'daemon_source_visits_fresh_checked':sum(len(c['visited_original_instructions'])for p in e['profiles']for c in p['daemon_children']),
      'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_root_adapter_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'corefp_root_adapter_ida.json').encode()),'dependencies':e['dependencies'],
      'frozen_contract_modules':{n:SHA(read(ROOT/n).encode())for n in ['audit_corefp_lookup_release.py','audit_corefp_cold_metadata.py','audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']},
      'oracles':oracles,'source_contracts':source,'live_byte_ranges':live,'semantic_annotations_used_as_proof':False,
      'full_daemon_CPU_RAM_replayed':False,'fresh_replay_completed':True,'process_exit_code':0,'full_goal_complete':False}
    (ROOT/'corefp_root_adapter_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
