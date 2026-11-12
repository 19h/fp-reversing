#!/usr/bin/env python3
"""Original ingress caller slices and coherent metadata/VM-boundary prefixes.

Three local record producers and four conditional bank equations are retained.
Original entry 0x2e4280 runs with declared private inputs and a single bounded
malloc(32) model. Execution stops before vm_allocate; no native API, target,
IPC or IDB mutation occurs. Whole reachability of the later ingress calls is
not established. O(C*(B+P*F+V*J+R)+T+4*256) time/space upper bound;
30000 original visits per profile. T is complete original text size.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
import audit_corefp_lookup_release
from unicorn import arm64_const as A
from recover_corefp_lookup_release import Run as Frozen,DEPS as PREVIOUS_DEPS,parent_inputs
from recover_corefp_lookup_initialization import frame,pack,ROOT,BASE,REC,DONE,BIND,inputs
from recover_corefp_root_ingress import literal_candidates
from corefp_fixups_reader import Pointers,THIN_SHA
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M32=(1<<32)-1
ENTRY=0x2e4280;J=0x63000800;DATA=0x63000900;AUX=0x63000c00;META=0x64000800
DEPS=PREVIOUS_DEPS+['recover_corefp_lookup_release.py','recover_corefp_root_ingress.py']
POINTS={0x2e43e4:'entry_tag_decoded',0x2e469c:'before_metadata_constructor',0x1ae0a4:'metadata_constructor_entry',
 0x1ae264:'metadata_allocator_return',0x1ae2dc:'metadata_constructor_result',0x2e47e4:'before_buffer_builder',
 0x43c4d8:'buffer_builder_entry',0x47e434:'buffer_helper_entry',0x1c9fac:'vm_helper_entry',0x1ca424:'vm_route_entry',
 0x1ca598:'before_vm_allocate_call'}


def configurations():
    rows=[]
    for label,extra in [('metadata_null',{'metadata_success':False}),('first_pointer_null',{'first_pointer':0}),
      ('second_pointer_null',{'second_pointer':0}),('both_pointers_null',{'first_pointer':0,'second_pointer':0}),
      ('vm_frontier',{}),('scalar_4096',{'entry_scalar_u32':4096}),('task_zero',{'task_port_u32':0}),
      ('caller_clobber',{'clobber_callers':True}),('metadata_fill_a5',{'metadata_fill_u8':0xa5})]:
        rows.append({'label':label,'allocation_success':[True,True],'lock_init_status_u32':[0,0],
          'continue_to_bootstrap':True,'bootstrap_results':[],'unlock_status_u32':0,
          'entry_tag_u32':0x9744,'entry_scalar_u32':0,'first_pointer':DATA,'second_pointer':AUX,
          'metadata_success':True,'metadata_fill_u8':0,'task_port_u32':0x4201,**extra})
    return rows


def caller_inputs(s,c):
    key=((J^0xca39defa)*0x01266167)&M32
    b=bytearray(64);struct.pack_into('<I',b,0,c['entry_tag_u32']^key)
    struct.pack_into('<QQ',b,8,c['first_pointer'],c['second_pointer']);struct.pack_into('<I',b,28,c['entry_scalar_u32']^key)
    task=next(r for r in s.imports if r['name']=='_mach_task_self_')
    return [(J,bytes(b)),(META,bytes([c['metadata_fill_u8']])*32),
      (BIND+task['ordinal']*16,c['task_port_u32'].to_bytes(4,'little'))]


def banks(s):
    out=[]
    for name,call,ap,ad,bp,bd,xor,bias in [
      ('caller_22438c',0x22438c,0x1d08e18,0,0x1d077d0,-8,0xe4,0x10378),
      ('caller_2e490c',0x2e490c,0x1d146f0,0,0x1d09f68,-8,0xc8,0x103a4),
      ('caller_4bae24',0x4bae24,0x1d146f0,0,0x1d09f68,-8,0xc8,0x103a4),
      ('sibling_14f2720',0x14f2720,0x1d09500,0,0x1d0b590,-12,0x20,0x10410)]:
        a=s.qword(ap)+ad;b=s.qword(bp)+bd;av=s.read(a,256);bv=s.read(b,256)
        selected=[x^bv[av[x]^xor]for x in range(256)];assert len(set(selected))==1
        ix=bias+selected[0];slot=0x1c81940+8*ix
        out.append({'label':name,'callsite':hex(call),'A_pointer_row':s.decoded[ap],'A_adjust_B':ad,'A_address':hex(a),'A_bytes_hex':av.hex(),
          'B_pointer_row':s.decoded[bp],'B_adjust_B':bd,'B_address':hex(b),'B_bytes_hex':bv.hex(),'xor_u8':hex(xor),
          'index_bias':hex(bias),'selected_low8':selected,'dispatch_base':'0x1c81940','index_u32':hex(ix),'target_row':s.decoded[slot],
          'conditional_on_original_cached_roots_and_dispatch_base':True,'whole_function_executed_to_call':False})
    return out


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c)
        for a,b in caller_inputs(s,c):self.u.mem_write(a,b)
        self.u.reg_write(A.UC_ARM64_REG_PC,BASE+ENTRY);self.initial=frame(self.u)
        self.pages[REC&~4095]=bytes(self.u.mem_read(REC&~4095,4096));self.caller_points=[];self.metadata_allocations=0;self.parent_return=None
    def caller_point(self,label):
        self.touch(J,64);self.touch(META,32)
        row={'label':label,'CPU':frame(self.u),'visits_so_far':len(self.visits),'models_so_far':len(self.models),
          'caller64_hex':bytes(self.u.mem_read(J,64)).hex(),'metadata32_hex':bytes(self.u.mem_read(META,32)).hex()}
        if label in ['before_metadata_constructor','metadata_constructor_entry','before_buffer_builder','buffer_builder_entry','buffer_helper_entry','vm_helper_entry']:
            p=self.reg('x0');self.touch(p,32);row.update({'record_address':hex(p),'record32_hex':bytes(self.u.mem_read(p,32)).hex()})
        return row
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE;name=self.imports.get(pc)
        if at in POINTS:self.caller_points.append(self.caller_point(POINTS[at]))
        if name=='_vm_allocate':
            self.caller_points.append(self.caller_point('vm_import_frontier'))
            args=[self.reg('x'+str(j))for j in range(8)]
            self.frontier={'reason':'before_vm_allocate','CPU':frame(u),'args_x0_x7':list(map(hex,args)),
              'callsite':hex(self.reg('lr')-4-BASE),'output_word_before_hex':bytes(u.mem_read(args[1],8)).hex()}
            u.emu_stop();return
        if name=='_malloc'and self.reg('lr')-4-BASE==0x1ae260:
            assert self.metadata_allocations==0 and self.reg('x0')==32;self.metadata_allocations+=1
            args=[self.reg('x'+str(j))for j in range(8)];e={'kind':'declared_API','name':name,'before':frame(u),'args_x0_x7':list(map(hex,args)),
              'callsite':'0x1ae260','memory':[]};self.models.append(e);value=META if self.c['metadata_success']else 0
            e['return_u64']=hex(value);self.returned(value);e['after']=frame(u);return
        if pc==DONE:self.caller_points.append(self.caller_point('outer_return'))
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=30001);self.flush();assert hasattr(self,'frontier')and not self.once and self.boots==self.allocs==0
        return {'configuration':self.c,'initial_CPU':self.initial,'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'allocations_attempted':self.allocs,'metadata_returns':self.metadata_returns,'daemon_children':self.children,'bootstrap_calls':self.boots,
          'handoffs':self.handoffs,'lock_events':self.lock_events,'certificate_allocation_attempts':self.certificate_attempts,'parent_return':self.parent_return,
          'caller_points':self.caller_points,'metadata_allocation_attempts':self.metadata_allocations}


def main():
    s=Pointers();rows=[];spans={}
    for c in configurations():
        run=Run(s,c);rows.append(run.run());spans.update(run.functions)
    for a in [0x223d10,0x4ba7e4,0x14f1c70]:spans.setdefault(a,s.function(a))
    counts={'profiles':len(rows),'complete_early_returns':sum(p['frontier']['reason']=='parent_return'for p in rows),
      'vm_frontiers':sum(p['frontier']['reason']=='before_vm_allocate'for p in rows),
      **{k:sum(len(p[k])for p in rows)for k in ['visits','reads','writes','PAC_models','models','caller_points']},
      'metadata_allocation_attempts':sum(p['metadata_allocation_attempts']for p in rows)}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,'daemon_thin_sha256':SHA(SOURCE.read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(spans.values()),
      'declared_base_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()+parent_inputs()],
      'profile_caller_inputs':[[{'address':hex(a),'bytes_hex':b.hex()}for a,b in caller_inputs(s,c)]for c in configurations()],
      'ingress_literal_census':literal_candidates(s,0x6073),'conditional_bank_contracts':banks(s),
      'same_diversity_rebase_rows':[r for r in s.decoded.values()if r.get('key')=='IA'and r.get('diversity')=='0x6073'and not r['bind']],
      'profiles':rows,'verified_counts':counts,'source_PC_gap':False,'restored_parent_frame':False,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_ingress_callers_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
