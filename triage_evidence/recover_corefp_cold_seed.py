#!/usr/bin/env python3
"""Coherent cold fallback through entropy/time, seed and optional-input frontier.

Original root instructions run without a request1200 PC gap or frame restore.
Allocator, bootstrap, once/locks/PAC, sequential CASAL and entropy/time are
declared private models. No native target/API/IPC or IDB mutation executes.
Conservative O(C*(B+P*F+V*J+R+624)) time/space, including frozen
reaching-load scans and page reconstruction; 100000 visits per profile.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from unicorn import arm64_const as A
from recover_corefp_request1200_failure import Run as Frozen,DEPS as PRIOR_DEPS,extra_inputs
from recover_corefp_lookup_release import parent_inputs,PARENT,CURSOR,ENTRY
from recover_corefp_lookup_initialization import frame,pack,ROOT,BASE,inputs
from corefp_fixups_reader import Pointers,THIN_SHA
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();STATE=0x1d4551c;TOKEN=0x1d33108
DEPS=PRIOR_DEPS+['recover_corefp_request1200_failure.py','corefp_request1200_failure_checks.json','corefp_request1200_failure_audit.json',
 'fpsd1201_seed_checks.json','fpsd1201_seed_audit.json','fpsd1201_key_routes_checks.json','fpsd1201_key_routes_audit.json']


def configurations():
    out=[]
    for label,seed,extra in [('clock_A',0x12345678,{}),('zero_seed',0,{'seconds_i64':0,'microseconds_i32':0}),
      ('one_seed',1,{'seconds_i64':-1,'microseconds_i32':999999}),('max_seed',0xffffffff,{'seconds_i64':0x7fffffffffffffff,'microseconds_i32':999999}),
      ('clock_error_no_write',0x12345678,{'time_status_u32':0xffffffff}),('clock_A_clobber',0x12345678,{'clobber_callers':True}),
      ('static_lock',0x12345678,{'allocation_success':[False,True]}),
      ('zero_stack_clock_error',0x12345678,{'stack_fill_u8':0,'time_status_u32':0xffffffff}),
      ('alternate_stack_clock_error',0x12345678,{'stack_fill_u8':0x5a,'time_status_u32':0xffffffff})]:
        out.append({'label':label,'allocation_success':[True,True],'lock_init_status_u32':[0,0],'continue_to_bootstrap':True,
          'bootstrap_results':[{'status_u32':1102},{'status_u32':0,'write_port_u32':0x5034}],'unlock_status_u32':0,'continue_atomic_to_entropy':True,
          'random_u32':[seed,0x9abcdef0,0x0fedcba9],'seconds_i64':0x123456789abcdef,'microseconds_i32':654321,'time_status_u32':0,**extra})
    return out


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c)
        if 'stack_fill_u8'in c:self.u.mem_write(0x62000000,bytes([c['stack_fill_u8']])*0x20000)
        self.entropy_count=self.clock_count=self.seed_iterations=0;self.constructor_points=[];self.parent_return=None
    def constructor_point(self,label,record=False):
        sp=self.reg('sp');p=int.from_bytes(self.u.mem_read(sp+0x498,8),'little');r=self.reg('x0')
        e={'label':label,'CPU':frame(self.u),'visits_so_far':len(self.visits),'models_so_far':len(self.models)}
        if label=='before_first_entropy':e.update({'token4_hex':bytes(self.u.mem_read(BASE+TOKEN,4)).hex(),'held_lock_model':hex(self.held)})
        if label=='seed_complete':e['state624']=pack(bytes(self.u.mem_read(BASE+STATE,2496)))
        if label=='tuple_complete':e.update({'context_pointer':hex(sp+0x1340),'context128_hex':bytes(self.u.mem_read(sp+0x1340,128)).hex(),
          'tuple_pointer':hex(p),'tuple32_hex':bytes(self.u.mem_read(p,32)).hex()})
        if record:e.update({'record_pointer':hex(r),'record44_hex':bytes(self.u.mem_read(r,44)).hex()})
        self.constructor_points.append(e)
    def code(self,u,pc,n,d):
        self.flush();name=self.imports.get(pc)
        if name in ['_arc4random','_gettimeofday']:
            call=self.reg('lr')-4-BASE
            if name=='_arc4random'and self.entropy_count==0:self.constructor_point('before_first_entropy')
            args=[self.reg('x'+str(j))for j in range(8)];e={'kind':'declared_API','name':name,'before':frame(u),
              'args_x0_x7':list(map(hex,args)),'callsite':hex(call),'memory':[]};self.models.append(e)
            if name=='_arc4random':
                assert self.entropy_count<3 and call==[0x8eb800,0x8eb94c,0x8eb9a4][self.entropy_count]
                value=self.c['random_u32'][self.entropy_count];e['entropy_index']=self.entropy_count;self.entropy_count+=1
            else:
                assert self.clock_count==0 and call==0x8eb8e0 and args[1]==0;self.clock_count+=1;value=self.c['time_status_u32']
                self.touch(args[0],16);e['scratch16_before_hex']=bytes(u.mem_read(args[0],16)).hex()
                if value==0:self.effect(e,args[0],struct.pack('<qi',self.c['seconds_i64'],self.c['microseconds_i32']))
                e['scratch16_after_hex']=bytes(u.mem_read(args[0],16)).hex()
            e['return_u64']=hex(value);self.returned(value);e['after']=frame(u);return
        if pc==BASE+0x8eb824:
            self.seed_iterations+=1
            if self.seed_iterations==1:self.constructor_point('seed_loop_entry')
        if pc==BASE+0x8eb85c:self.constructor_point('seed_complete')
        if pc==BASE+0x8eb9b4:self.constructor_point('tuple_complete')
        for at,label in [(0x1abbe0,'first_predicate_entry'),(0x8ebca4,'first_predicate_return'),(0x439734,'second_predicate_entry'),(0x8ebe38,'second_predicate_return')]:
            if pc==BASE+at:self.constructor_point(label,True)
        if pc==BASE+0x8eba44:
            self.frontier={'reason':'before_optional_input_word_read','CPU':frame(u),'address':hex(self.reg('x12')),
              'held_lock_model':hex(self.held),'token4_hex':bytes(u.mem_read(BASE+TOKEN,4)).hex()};u.emu_stop();return
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=100001);self.flush();assert hasattr(self,'frontier')and not self.once
        assert self.entropy_count==3 and self.clock_count==1 and self.seed_iterations==623 and self.boots==2
        assert not self.transactions and not self.certificate_live and self.parent_return is None
        return {'configuration':self.c,'initial_CPU':self.initial,'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'allocations_attempted':self.allocs,'metadata_returns':self.metadata_returns,'daemon_children':self.children,'bootstrap_calls':self.boots,
          'handoffs':self.handoffs,'lock_events':self.lock_events,'certificate_allocation_attempts':self.certificate_attempts,'parent_return':self.parent_return,
          'transactions':self.transactions,'certificate_events':self.certificate_events,'constructor_points':self.constructor_points,
          'entropy_calls':self.entropy_count,'clock_calls':self.clock_count,'seed_iterations':self.seed_iterations,
          'caller_record48_hex':bytes(self.u.mem_read(PARENT,48)).hex(),'caller_word_u64':hex(int.from_bytes(self.u.mem_read(CURSOR,8),'little'))}


def main():
    s=Pointers();rows=[];spans={}
    for c in configurations():
        run=Run(s,c);p=run.run();rows.append(p);spans.update(run.functions)
    counts={'profiles':len(rows),**{k:sum(len(p[k])for p in rows)for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children',
      'handoffs','lock_events','transactions','certificate_events','constructor_points']},
      **{k:sum(p[k]for p in rows)for k in ['bootstrap_calls','certificate_allocation_attempts','entropy_calls','clock_calls','seed_iterations']}}
    e={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,'daemon_thin_sha256':SHA(SOURCE.read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(spans.values()),'declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()+parent_inputs()+extra_inputs()],
      'profiles':rows,'verified_counts':counts,'source_PC_gap':False,'restored_parent_frame':False,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_cold_seed_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
