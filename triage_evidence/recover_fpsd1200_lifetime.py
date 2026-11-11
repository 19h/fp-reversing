#!/usr/bin/env python3
"""Original FPSD1200 failed-watch cleanup, queue origin and slot-word flow.

External CF/event/TLS results and source-snapshot joins are explicit private
models. No native queue, TLS, event, right, deallocation, IPC or IOKit executes.
The errno accessor result remains unmapped. Earlier source premises are pinned.
O(B+F+V+E+L) finite observer work; two independent private worker processes.
"""
import base64,gc,json,struct,zlib
from pathlib import Path
from unicorn import arm64_const as A
from recover_fpsd1200_port import Port,fixtures as previous_fixtures,library,sources
from recover_fpsd1200_identity import ROOT,SOURCE,IMAGE,CS,SHA,STACK
from recover_fpsd1200_admission import fixup_checks,bank_proofs
from verify_daemon_reader_record_payloads_publication import read

QUEUE=0x1010c4d20;CELL=0x700663e8;ERR=0x78000000
LPCS={0x1003ae45c,0x1003ae46c,0x1003ae470,0x1003ae4d0,0x1003ae4e4,
 0x100493a58,0x100493a5c,0x10054e848,0x100474eb8,0x1004d8440,
 0x1004d8454,0x10061aa0c,0x1005a7330,0x1005a7340}


def queue_origin(fd):
    e=json.loads(read(ROOT/'daemon_descriptor_source_profiles.json'))
    r=next(x for x in e['setup_cases']if x['configuration']['label']==f'setup_fd{fd}')
    source=next(x for x in r['source_writes']if x['address']==hex(QUEUE))
    raw=bytes.fromhex(r['final_header96_hex'])[72:76]
    assert raw==struct.pack('<I',(fd+0x060ed969)&0xffffffff)and source['after_hex']==raw.hex()
    return {'artifact':'daemon_descriptor_source_profiles.json','case':r['configuration']['label'],
      'source_store':r['source_visits'][source['visit']]['pc'],'source_write':source,
      'composed_address':hex(QUEUE),'composed_bytes_hex':raw.hex(),
      'native_temporal_continuity_established':False}


class Lifetime(Port):
    def __init__(self,*args):
        self.lifetime_points=[];self.slot_word_reads=[];self.slot_word_writes=[];self.error_pointer_reads=[]
        super().__init__(*args)
        self.queue_origin=queue_origin(self.fixture['queue_fd'])
        self.queue_before=bytes(self.u.mem_read(QUEUE,4)).hex()
        self.u.mem_write(QUEUE,bytes.fromhex(self.queue_origin['composed_bytes_hex']))
        self.cell_patch=None
        if 'initial_slot_word'in self.fixture:
            self.cell_patch={'address':hex(CELL),'before_hex':bytes(self.u.mem_read(CELL,4)).hex(),
              'after_hex':struct.pack('<I',self.fixture['initial_slot_word']).hex(),
              'known_before':self.known(CELL,4),'known_after':'01'*4}
            self.u.mem_write(CELL,bytes.fromhex(self.cell_patch['after_hex']));self.stack_known[CELL-STACK:CELL-STACK+4]=b'\x01'*4
        assert all(not a<=ERR<=b for a,b,p in self.u.mem_regions())

    def read_hook(self,u,ac,a,n,v,d):
        if a<CELL+4 and CELL<a+n:
            self.slot_word_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'width_B':n,
              'bytes_hex':bytes(u.mem_read(a,n)).hex(),'known_mask_hex':self.known(a,n)})
        if ERR<=a<ERR+4096:self.error_pointer_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'width_B':n})
        return super().read_hook(u,ac,a,n,v,d)

    def write_hook(self,u,ac,a,n,v,d):
        if a<CELL+4 and CELL<a+n:
            self.slot_word_writes.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'width_B':n,
              'before_hex':bytes(u.mem_read(a,n)).hex(),'known_before':self.known(a,n),'value':hex(v&((1<<(8*n))-1))})
        return super().write_hook(u,ac,a,n,v,d)

    def hook(self,u,pc,n,d):
        if pc in LPCS:self.lifetime_points.append(self.checkpoint(u,pc))
        if pc in self.imports and self.imports[pc]=='libSystem/___error':
            assert self.reg(30)-4==0x100493a58
            e={'kind':'import_fixture','name':self.imports[pc],'site':'0x100493a58',
              'args':[hex(self.reg(j))for j in range(8)],'entry_checkpoint':self.checkpoint(u,pc),
              'model':'explicit accessor result only; unmapped pointer, no native TLS or errno storage'}
            self.events.append(e);return self.fixture_return(e,self.fixture['error_pointer'])
        return super().hook(u,pc,n,d)

    def run_lifetime(self):
        r=self.run_port();r.update(lifetime_points=self.lifetime_points,queue_origin=self.queue_origin,
          queue_word_before_composition=self.queue_before,slot_word_initial_patch=self.cell_patch,
          slot_word_reads=self.slot_word_reads,slot_word_writes=self.slot_word_writes,
          slot_word_final_hex=bytes(self.u.mem_read(CELL,4)).hex(),slot_word_final_known_mask=self.known(CELL,4),
          error_pointer_reads=self.error_pointer_reads,error_pointer_region_mapped=False)
        return r


def fixtures():
    rows=list(previous_fixtures());error=rows[-1];success=rows[-2]
    yield {**error,'label':'error_pointer_NULL','queue_fd':0,'error_pointer':0}
    yield {**error,'label':'error_pointer_opaque','queue_fd':0,'error_pointer':ERR}
    yield {**success,'label':'queue7_success','queue_fd':7}
    yield {**success,'label':'slot_word_control','queue_fd':7,'initial_slot_word':0x11223344}


def proofs():
    import z3
    d=z3.BitVec('descriptor32',32)
    encoded=(d^0x4eefd9fd)+((d<<1)&0x9ddfb3fa)+0xb71eff6c
    decoded=encoded+0xf9f0d0b3+0x55e4
    ret=z3.BitVec('kevent_return32',32);carrier=ret-((ret<<1)&0x167b8ca2)+0x8b3dc651
    queries={}
    for name,l,r,scope in [
      ('queue_setup_to_watch',decoded,d,'All descriptor32 patterns through original setup encoding and selected watch phase W24=0x55e4; not native fd validity or temporal continuity.'),
      ('watch_return_carrier',carrier,ret^0x8b3dc651,'All return32 patterns through the local carrier expression only; no all-domain dispatcher or native return feasibility claim.')]:
        s=z3.Solver();s.set(timeout=10000);s.add(l!=r);q=s.to_smt2();assert s.check()==z3.unsat
        queries[name]={'query':q,'result':'unsat','scope':scope}
    return queries

def run_case(f):
    gc.collect();x=Lifetime(sources()[3],f,library());r=x.run_lifetime()
    summary={'label':f['label'],'stop':r['stop_reason'],'last_pc':r['last_pc'],'visits':len(r['visited']),
      'status':r['application_status_u32'],'reply_size_B':r['reply_size_B'],
      'last_import':next((e for e in reversed(r['events'])if e['kind']=='import_fixture'),None)}
    assert r['stop_reason']in ['returned_to_fixture'],r['stop_reason']
    seq=[int(a,16)for a in r['visited']]
    counts={'profiles':1,'daemon_visits':sum(a<0x200000000 for a in seq),'library_visits':sum(a>=0x200000000 for a in seq),
      'import_events':sum(e['kind']=='import_fixture'for e in r['events']),'returned_replies':int(r['reply_completed']),
      'complex_replies':int(r['reply_completed']and r['reply_size_B']==212),'error_replies':int(r['reply_completed']and r['reply_size_B']==36),
      'vm_allocations':len(r['vm_owners_final']),'vm_store_events':len(r['vm_owner_writes']),
      'output_cell_read_events':len(r['output_cell_reads']),'protected_output_store_events':len(r['protected_output_writes']),
      'heap_read_events':len(r['heap_reads']),'heap_store_events':len(r['heap_writes']),
      'complete_montgomery_calls':sum('returned'in c for c in r['montgomery_calls']),'OOL_read_events':len(r['input_ool_reads']),
      'mode_read_events':len(r['mode_reads']),'mode_guards':int(r['mode_guard']is not None),
      'queue_word_read_events':len(r['queue_word_reads']),'slot_word_reads':len(r['slot_word_reads']),
      'slot_word_writes':len(r['slot_word_writes']),'error_pointer_reads':len(r['error_pointer_reads'])}
    result={'summary':summary,'packed':{**summary,'fixture':f,
      'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode(),9)).decode()},
      'sites':sorted({a for a in seq if a<0x200000000}),
      'guards':[int(r['last_pc'],16)]if r['mode_guard']is not None else [],
      'accesses':[int(a,16)for a in r['fixup_reads']],
      'banks':{'fixture':f,'byte_bank_reads':r['byte_bank_reads']},'counts':counts}
    del x,r,seq;gc.collect();return result


def main():
    from concurrent.futures import ProcessPoolExecutor
    import multiprocessing
    packed=[];sites=set();guards=set();accesses=set();banks=[];counts={}
    with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as pool:
        for result in pool.map(run_case,list(fixtures())):
            print(json.dumps(result['summary']),flush=True);packed.append(result['packed'])
            sites.update(result['sites']);guards.update(result['guards']);accesses.update(result['accesses']);banks.append(result['banks'])
            for k,v in result['counts'].items():counts[k]=counts.get(k,0)+v
            (ROOT/'fpsd1200_lifetime_working.json').write_text(json.dumps({'profiles':packed},indent=2)+'\n')
    spans=[]
    for a in sorted(sites|guards):
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    identities,pairs,unpaired=bank_proofs(banks);fix=fixup_checks(accesses);qs=proofs()
    counts.update(source_spans=len(spans),source_instructions_including_guards=len(sites|guards),
      format12_rebases=len(fix['records']),format12_bindings=len(fix['bindings']),bank_identities=len(identities),
      bank_inputs=256*len(identities),bank_pair_uses=pairs,unpaired_byte_bank_reads=len(unpaired),queries_unsat=len(qs))
    out={'scope':__doc__,'daemon_sha256':SHA(SOURCE.read_bytes()),'generator_sha256':SHA(Path(__file__).read_bytes()),
      'library':library(),'profiles':packed,'verified_counts':counts,'worker_processes':2,
      'spans':[{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':SHA(IMAGE.read(a,z-a)),
        'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans],
      'unretired_guard_sites':[hex(a)for a in sorted(guards)],'fixups':fix,'byte_bank_proofs':identities,
      'byte_bank_pairs':pairs,'unpaired_byte_bank_reads':unpaired,'proofs':qs,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in ['recover_fpsd1200_port.py','audit_fpsd1200_port.py','fpsd1200_port_checks.json','fpsd1200_port_ida_readback.json',
        'daemon_descriptor_source_profiles.json','daemon_descriptor_source_source.json','replay_daemon_descriptor_source.py','recover_daemon_descriptor_source.py',
        'recover_fpsd1200_vm.py','audit_fpsd1200_vm.py',
        'fpsd1200_vm_checks.json','fpsd1200_vm_ida_readback.json','recover_fpsd1200_certificate.py',
        'audit_fpsd1200_certificate.py','recover_fpsd1200_context.py','audit_fpsd1200_context.py',
        'recover_fpsd1200_arena.py','audit_fpsd1200_arena.py','recover_fpsd1200_identity.py','audit_fpsd1200_identity.py',
        'recover_fpsd1200_admission.py','audit_fpsd1200_admission.py','daemon_rpc502_probe.py','daemon_receive_tools.py',
        'daemon_import_bindings.py','daemon_receive_fixups.txt','bootpolicy_cache_reader.py','rpc502_startup_profiles.json',
        'rpc502_startup_contracts.json','rpc502_policy_contracts.json','rpc502_rsa_contracts.json','rpc502_rsa_models.py',
        'rpc502_startup_tools.py','corefp_client_paths_contracts.json']},
      'new_IDA_access':True,'new_IDB_mutations':False,'new_native_execution':False,'full_goal_complete':False}
    (ROOT/'fpsd1200_lifetime_checks.json').write_text(json.dumps(out,indent=2)+'\n');(ROOT/'fpsd1200_lifetime_working.json').unlink()
    print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
