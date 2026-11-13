#!/usr/bin/env python3
"""Second state-mixing pass, final word force and gate reacquisition.

Two frozen first-pass boundaries supply every entry byte and register.
No new API, private or image data is supplied. Packed intervals preserve
complete GP/Q/NZCV, source opcodes, fixups and byte effects. O(parent bytes
+iterations*(visits+state+effects)) time; O(receipts+largest interval) space.
No native API/IPC, allocation/free, hardware PAC or IDB mutation executes.
"""
import json,struct
from collections import Counter
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
import recover_daemon_payload_mix as Parent

P='daemon_second_mix';ENTRY=0x100abba18;COUNTER=0x100a07724
FORCE=0x100b2a200;GATE=0x100b3a848;NEXT=0x100a3881c
G=Parent.G;GATE_WORD=0x1010b5de0
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_payload_mix.py',
      'audit_daemon_payload_mix.py','daemon_payload_mix_checks.json','daemon_payload_mix_audit.json',
      'recover_daemon_context_unseal.py','recover_daemon_context_lock_use.py',
      'recover_daemon_return_bank_origins.py','audit_daemon_readiness_arena.py',
      'audit_daemon_clock_record.py','audit_daemon_context_state_publish.py']

class Run(Parent.RunBase):
    def code(self,u,a,n,d):
        if a==COUNTER and self.reg(25)==1:
            self.flush();return self.stop('before_final_second_pass_counter_decrement')
        skip=a==ENTRY and self.seq==0 and a in self.cut_stops
        if skip:self.cut_stops.remove(a)
        out=super().code(u,a,n,d)
        if skip:self.cut_stops.add(a)
        return out

def restore(row,cls=Run):
    v=cls(row['configuration']);v.foreign_owners=[(int(x['address'],16),x['size_bytes']) for x in row['foreign_owners']]
    v.foreign_defined=set();v.cut_stops=set()
    for j,x in enumerate(row['boundary']['registers31']):v.set(j,int(x,16))
    for j,x in enumerate(row['boundary']['Q_registers32']):v.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
    v.u.reg_write(ar.UC_ARM64_REG_SP,int(row['boundary']['SP'],16));v.u.reg_write(ar.UC_ARM64_REG_NZCV,int(row['boundary_NZCV'],16))
    for kind in ['private','image']:
        for f in row['initial_'+kind+'_fixtures']:
            a=int(f['address'],16);raw=bytes.fromhex(f['bytes_hex'])
            if kind=='private':v.fixture(a,raw)
            elif a>=0x6000000000:v.foreign_fixture(a,raw,f['provenance'])
            else:v.image_fixture(a,raw,f['provenance'])
    for w in row['source_writes']:
        a=int(w['address'],16);raw=bytes.fromhex(w['after_hex'])
        if 0x6800000000<=a<a+len(raw)<=0x6800100000:v.fixture(a,raw)
        elif a>=0x6000000000:v.foreign_fixture(a,raw,'preceding_original_source_write')
        else:v.image_fixture(a,raw,'preceding_original_source_write')
    Parent.compact_fixtures(v);return v

def case(index,parent):
    before=Parent.unpack(parent['exit_intervals_packed'][-1]);assert before['boundary']['pc']==hex(ENTRY)
    v=restore(before);start=state_bytes(before);sp=int(before['boundary']['SP'],16);q=sp+0x220
    rows=[];records=[];counts=Counter();used=set()
    def keep(r,where):
        where.append(Parent.pack(r));counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']),source_calls=len(r['source_calls']))
        used.update(int(x['address'],16) for x in r['source_reads'] if int(x['address'],16) in FIXUPS)
    for iteration in range(623):
        v.cut_stops={ENTRY};r=v.interval(ENTRY,'original_second_mix_iteration')
        assert r['boundary']['pc']==hex(COUNTER if iteration==622 else ENTRY);keep(r,rows)
        records.append({'iteration':iteration+1,'entry_i32':int(r['entry_registers31'][19],16),'entry_remaining32':int(r['entry_registers31'][25],16),
                        'exit_i32':int(r['boundary']['registers31'][19],16),'exit_remaining32':int(r['boundary']['registers31'][25],16),
                        'global_writes':[w for w in r['source_writes'] if G<=int(w['address'],16)<G+2496]})
        Parent.compact_fixtures(v)
        if iteration%128==0:print(json.dumps({'parent_case_index':index,'iteration':iteration+1,**counts}),flush=True)
    second_boundary=r['boundary'];second_NZCV=r['boundary_NZCV'];mixed=bytes(v.u.mem_read(G,2496)).hex()
    final=restore(r,Parent.RunBase);extra=[]
    for pc,target,label in [(COUNTER,FORCE,'original_final_second_counter_exit'),(FORCE,GATE,'original_force_high_bit_and_gate_setup'),(GATE,NEXT,'original_gate_reacquisition')]:
        final.cut_stops={target};r=final.interval(pc,label);assert r['boundary']['pc']==hex(target);keep(r,extra);Parent.compact_fixtures(final)
    return {'parent_case_index':index,'parent_seed_case_index':parent['parent_seed_case_index'],
            'intervals_packed':rows,'iteration_records':records,'exit_intervals_packed':extra,
            'entry_state2496_hex':bytes(start[G+j] for j in range(2496)).hex(),'entry_key16_hex':bytes(start[q+j] for j in range(16)).hex(),
            'second_pass_state2496_hex':mixed,'second_pass_boundary':second_boundary,'second_pass_NZCV':second_NZCV,
            'final_state2496_hex':bytes(final.u.mem_read(G,2496)).hex(),'final_key16_hex':bytes(final.u.mem_read(q,16)).hex(),
            'entry_gate32_hex':bytes(start[GATE_WORD+j] for j in range(4)).hex(),'final_gate32_hex':bytes(final.u.mem_read(GATE_WORD,4)).hex(),
            'final_boundary':r['boundary'],'final_NZCV':r['boundary_NZCV'],'counts':dict(counts),'used_fixups':[hex(a) for a in sorted(used)]}

def source():
    spans=[('second_mix',ENTRY,0x100abba44),('counter',COUNTER,0x100a07768),
           ('nonwrap_index',0x100a6c638,0x100a6c680),('force_and_gate_setup',FORCE,0x100b2a250),
           ('gate_reacquisition',GATE,0x100b3a870),('next_stage',NEXT,0x100a38848)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in spans]

def build():
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')));cases=[case(j,c) for j,c in enumerate(parent['cases'])];counts=Counter()
    for c in cases:counts.update(c['counts'])
    used={int(x,16) for c in cases for x in c['used_fixups']}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'source_regions':source(),'source_fixups':Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used),
            'cases':cases,'verified_counts':{'cases':len(cases),'intervals':sum(len(c['intervals_packed'])+len(c['exit_intervals_packed']) for c in cases),**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
