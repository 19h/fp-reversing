#!/usr/bin/env python3
"""Original FPSD1200 allocation and initialization continuation, private only.

The harness owns a global visit budget; inherited local counter guards are
replaced without changing target CPU/memory. Allocator, CF/Security, PAC, once
and locks are declared fixtures. No native target, allocation or IPC executes.
"""
import json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
from recover_fpsd1200_identity import Identity,library,sources,IMAGE,SOURCE,CS,ROOT,SHA,STACK,HALT,PRIVATE
from recover_fpsd1200_admission import fixup_checks,bank_proofs
from verify_daemon_reader_record_payloads_publication import read

HEAP=0x74000000;HEAP_SIZE=0x10000;LIMIT=250000
POINTS={0x10041917c,0x10013ebe0,0x1001b4724,0x100057634,0x10051e068,
 0x100208efc,0x100660230,0x10000468c,0x100630448,
 0x100635670,0x100635680,0x1006356a8,0x1006303ec}


class Arena(Identity):
    def __init__(self,wire,fixture,lib):
        self.heap_writes=[];self.heap_reads=[];self.heap_defined=set();self.boundary=None
        self.atomics=[];self.output_writes=[];self.protected_active=False;self.payload=None
        self.arena_points=[]
        super().__init__(wire,fixture,lib)
        self.u.mem_map(HEAP,HEAP_SIZE);self.u.mem_write(HEAP,bytes([fixture.get('backing',0xa5)])*HEAP_SIZE)
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.heap_write)

    def heap_write(self,u,access,a,n,v,data):
        if self.protected_active and self.payload is not None:
            if any(a<b+z and b<a+n for b,z in [(self.inline,128),(self.payload+72,32)]):
                self.output_writes.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),
                  'width_B':n,'value':hex(v&((1<<(8*n))-1))})
        if HEAP<=a<HEAP+HEAP_SIZE:
            self.heap_writes.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'offset_B':a-HEAP,
              'width_B':n,'value':hex(v&((1<<(8*n))-1))})
            self.heap_defined.update(range(a,a+n))

    def read_hook(self,u,access,a,n,v,data):
        if HEAP<=a<HEAP+HEAP_SIZE:
            self.heap_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'offset_B':a-HEAP,'width_B':n,
              'bytes_hex':bytes(u.mem_read(a,n)).hex(),'all_bytes_defined':all(x in self.heap_defined for x in range(a,a+n))})
        return super().read_hook(u,access,a,n,v,data)

    def hook(self,u,pc,n,data):
        if len(self.visited)>=LIMIT:return self.stop('global_visit_budget_guard')
        if pc in POINTS:
            self.arena_points.append({'pc':hex(pc),'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),
              'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV)),
              'registers31':[hex(self.reg(j))for j in range(31)]})
        if pc==0x10065ffd8:
            self.payload=struct.unpack('<Q',u.mem_read(self.reg(0)+16,8))[0];self.inline=struct.unpack('<Q',u.mem_read(self.payload+64,8))[0]
            self.payload_before=bytes(u.mem_read(self.payload,104)).hex();self.inline_before=bytes(u.mem_read(self.inline,128)).hex();self.protected_active=True
        if pc==0x100660230:self.protected_active=False
        if pc==0x1006009c0:
            a=self.reg(12);old=struct.unpack('<I',u.mem_read(a,4))[0];expect=self.reg(8)&0xffffffff;desired=self.reg(14)&0xffffffff
            e={'pc':hex(pc),'address':hex(a),'old32':hex(old),'expected32':hex(expect),'desired32':hex(desired),
              'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV)),
              'registers31':[hex(self.reg(j))for j in range(31)],'executed':self.fixture.get('atomic_fixture',False)}
            self.atomics.append(e)
            if not e['executed']:return self.stop('before_atomic_boundary')
            if old==expect:u.mem_write(a,struct.pack('<I',desired))
            self.setreg(8,old);e['stored32']=hex(desired if old==expect else old)
            self.visited.append(pc);u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if pc==0x100052440 and self.reg(20)==0:
            self.boundary={'pc':hex(pc),'kind':'write_after_null_allocation','address':hex(self.reg(21)),
              'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]}
            return self.stop('null_allocation_write_guard')
        if pc in self.imports and self.imports[pc]=='libSystem/_malloc'and self.reg(30)-4==0x100419178:
            e={'kind':'import_fixture','name':self.imports[pc],'site':hex(self.reg(30)-4),
              'args':[hex(self.reg(j))for j in range(8)],'model':'disjoint private allocator result; allocation bytes initially undefined'}
            self.events.append(e);assert self.reg(0)==44800
            return self.fixture_return(e,HEAP if self.fixture.get('malloc_nonnull',True)else 0)
        if pc in self.imports and self.imports[pc]=='libSystem/_free'and self.reg(0)==0:
            e={'kind':'import_fixture','name':self.imports[pc],'site':hex(self.reg(30)-4),
              'args':[hex(self.reg(j))for j in range(8)],'model':'record-only free(NULL); no native deallocation'}
            self.events.append(e);return self.fixture_return(e,0)
        # Only an instrumentation counter changes here. Every original opcode,
        # CPU register, target memory byte and event remains continuous.
        self.steps=0
        return super().hook(u,pc,n,data)

    def run_arena(self):
        self.setreg(0,self.req);self.setreg(1,self.reply);self.setreg(30,HALT)
        self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000)
        try:self.u.emu_start(0x100004b80,0,count=LIMIT+10000)
        except uc.UcError as ex:self.stop_reason='private_engine_error:'+str(ex)
        b=bytes(self.u.mem_read(self.reply,212));c=self.carrier_address
        return {'fixture':self.fixture,'stop_reason':self.stop_reason,'last_pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),
          'reply212':b.hex(),'reply_completed':self.stop_reason=='returned_to_fixture','reply_status_u32':None,
          'reply_size_B':struct.unpack_from('<I',b,4)[0]if self.stop_reason=='returned_to_fixture'else None,
          'application_status_u32':(struct.unpack('<I',self.u.mem_read(c+24,4))[0]^0x8b3dc651)if self.stop_reason=='returned_to_fixture'else None,
          'carrier28_final':bytes(self.u.mem_read(c,28)).hex(),'delta8_final':bytes(self.u.mem_read(self.delta_cell,8)).hex(),
          'initial_request128':self.request_initial.hex(),'input_ool_reads':self.ool_reads,'byte_bank_reads':self.bank_reads,
          'final_stack_sha256':SHA(bytes(self.u.mem_read(STACK,0x80000))),'final_private_sha256':SHA(bytes(self.u.mem_read(PRIVATE,0x10000))),
          'events':self.events,'points':self.points,'copies':self.copy_done,'fixup_reads':[hex(a)for a in sorted(self.fixup_reads)],
          'image_reads':[[hex(a),n]for a,n in sorted(self.image_reads)],'visited':[hex(a)for a in self.visited],
          'PAC_bypasses':self.pac,'library_calls':self.library_calls,'identity_points':self.extra_points,
          'provider_reads':self.provider_reads,'cache_context_reads':self.cache_context_reads,'provider_snapshot':self.provider_snapshot,
          'callback_models':self.callback_models,'image_writes':self.writes,
          'final_image_writes':[{'address':e['address'],'width_B':e['size'],'bytes_hex':bytes(self.u.mem_read(int(e['address'],16),e['size'])).hex()}for e in self.writes],
          'heap_reads':self.heap_reads,'heap_writes':self.heap_writes,'heap_defined_bytes':len(self.heap_defined),
          'heap44800_hex':bytes(self.u.mem_read(HEAP,44800)).hex(),'heap_tail_sha256':SHA(bytes(self.u.mem_read(HEAP+44800,HEAP_SIZE-44800))),
          'boundary':self.boundary,'atomics':self.atomics,'protected_output_writes':self.output_writes,
          'arena_points':self.arena_points,'pool_pair16_final':bytes(self.u.mem_read(0x1010c4cd8,16)).hex(),
          'atomic_word32_final':bytes(self.u.mem_read(0x1010b5de0,4)).hex(),
          'payload_address':hex(self.payload),'protected_payload104_before':self.payload_before,
          'protected_payload104_final':bytes(self.u.mem_read(self.payload,104)).hex(),
          'inline128_before':self.inline_before,'inline128_final':bytes(self.u.mem_read(self.inline,128)).hex(),
          'native_messages_emitted':False,'native_target_executed':False}


def fixtures():
    return [
      {'label':'default_A5'}, {'label':'default_3C','backing':0x3c},
      {'label':'default_count756','request_changes':[[40,756,4],[60,756,4]]},
      {'label':'allocation_null','malloc_nonnull':False},
      {'label':'word1_count8','request_changes':[[52,1,4]],'atomic_fixture':True},
      {'label':'word2_count8','request_changes':[[52,2,4]],'atomic_fixture':True},
      {'label':'word3_count8','request_changes':[[52,3,4]]},
      {'label':'word1_atomic_guard','request_changes':[[52,1,4],[40,756,4],[60,756,4]]},
      {'label':'word2_atomic_guard','request_changes':[[52,2,4],[40,756,4],[60,756,4]]},
      {'label':'word1_atomic_fixture','request_changes':[[52,1,4],[40,756,4],[60,756,4]],'atomic_fixture':True},
      {'label':'word2_atomic_fixture','request_changes':[[52,2,4],[40,756,4],[60,756,4]],'atomic_fixture':True},
      {'label':'word3','request_changes':[[52,3,4],[40,756,4],[60,756,4]]}]


def proofs():
    import z3
    rows={}
    def prove(name,expr,scope):
        s=z3.Solver();s.set(timeout=15000);s.add(expr);q=s.to_smt2();assert s.check()==z3.unsat
        rows[name]={'query':q,'result':'unsat','scope':scope}
    i=z3.BitVec('slot_index64',64)
    prove('slot_stride',((i<<10)-(i<<7))!=i*896,'64-bit modular source shift/subtract identity.')
    j=z3.Int('slot_index');field=z3.Int('field_offset');width=z3.Int('field_width')
    prove('slot_field_bounds',z3.And(j>=0,j<50,z3.Or(z3.And(field==876,width==4),
      z3.And(field==880,width==8),z3.And(field==888,width==8)),
      z3.Or(j*896+field<0,j*896+field+width>44800)),
      'Exact owner bounds for the three observed fields and indices 0 through 49.')
    x=z3.BitVec('raw_status32',32)
    prove('outer_zero_status',z3.And(x==0x8b3dc651,(x^0x8b3dc651)!=0),
      'Recorded carrier word and source outer XOR; no semantic/native success theorem.')
    return rows


def main():
    lib=library();wire=sources()[3]
    rows=[]
    for f in fixtures():
        f={'provider_case':0,'execute_once_callback':True,'model_lock':True,**f}
        r=Arena(wire,f,lib).run_arena();rows.append(r)
        assert r['stop_reason']in ['returned_to_fixture','null_allocation_write_guard','before_atomic_boundary','unmodeled_import_boundary']
        print(json.dumps({'label':f['label'],'stop':r['stop_reason'],'pc':r['last_pc'],'visits':len(r['visited']),
          'heap_defined':r['heap_defined_bytes'],'heap_reads':len(r['heap_reads']),'heap_writes':len(r['heap_writes']),
          'last_imports':[e for e in r['events']if e['kind']=='import_fixture'][-4:],'last_source':r['visited'][-8:]}),flush=True)
    sites={int(a,16)for r in rows for a in r['visited']if int(a,16)<0x200000000}
    guards={int(r['last_pc'],16)for r in rows if r['stop_reason']in ['null_allocation_write_guard','before_atomic_boundary']}
    spans=[]
    for a in sorted(sites|guards):
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    banks,pairs,unpaired=bank_proofs(rows)
    out={'scope':__doc__,'daemon_sha256':SHA(SOURCE.read_bytes()),'library':lib,'profiles':rows,
      'spans':[{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':SHA(IMAGE.read(a,z-a)),
      'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans],
      'unretired_guard_sites':[hex(a)for a in sorted(guards)],
      'fixups':fixup_checks({int(a,16)for r in rows for a in r['fixup_reads']}),
      'byte_bank_proofs':banks,'byte_bank_pairs':pairs,'unpaired_byte_bank_reads':unpaired,'proofs':proofs(),
      'generator_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in ['recover_fpsd1200_identity.py','fpsd1200_identity_checks.json',
        'audit_fpsd1200_identity.py','recover_fpsd1200_admission.py','audit_fpsd1200_admission.py',
        'daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_import_bindings.py',
        'daemon_receive_fixups.txt','bootpolicy_cache_reader.py','daemon_object_initialization_context.json']},
      'new_IDA_access':True,'new_IDB_mutations':False,'new_native_execution':False,'full_goal_complete':False}
    out['verified_counts']={'profiles':len(rows),'source_spans':len(spans),'source_instructions_including_guards':len(sites|guards),
      'daemon_visits':sum(sum(int(a,16)<0x200000000 for a in r['visited'])for r in rows),
      'library_visits':sum(sum(int(a,16)>=0x200000000 for a in r['visited'])for r in rows),
      'original_copy_calls':sum(len(r['copies'])for r in rows),'original_once_callbacks':sum(len(r['callback_models'])for r in rows),
      'returned_replies':sum(r['reply_completed']for r in rows),
      'null_allocation_guards':sum(r['stop_reason']=='null_allocation_write_guard'for r in rows),
      'atomic_guards':sum(r['stop_reason']=='before_atomic_boundary'for r in rows),
      'atomic_fixtures':sum(sum(a['executed']for a in r['atomics'])for r in rows),
      'random_import_boundaries':sum(r['stop_reason']=='unmodeled_import_boundary'for r in rows),
      'heap_store_events':sum(len(r['heap_writes'])for r in rows),'heap_load_events':sum(len(r['heap_reads'])for r in rows),
      'protected_output_store_events':sum(len(r['protected_output_writes'])for r in rows),
      'queries_unsat':len(out['proofs']),'format12_rebases':len(out['fixups']['records']),
      'format12_bindings':len(out['fixups']['bindings']),'bank_identities':len(banks),
      'bank_inputs':256*len(banks),'bank_pair_uses':pairs,'unpaired_byte_bank_reads':len(unpaired)}
    (ROOT/'fpsd1200_arena_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']),flush=True)


if __name__=='__main__':main()
