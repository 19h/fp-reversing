#!/usr/bin/env python3
"""Original FPSD1200 CF endpoint, event registration and output continuation.

Opaque CF objects, imported mode data, event returns and VM cleanup are explicit
private API models. No native CF object, right, run loop, kevent, Mach emission,
credential decision or IOKit operation executes. Predecessor premises are pinned.
O(B+F+V+E+L) finite observer work; compression bounds retained profile storage.
"""
import base64,gc,json,struct,zlib
from pathlib import Path
from unicorn import arm64_const as A
from recover_fpsd1200_vm import OutputVM,fixtures as previous_fixtures,library,sources,VM
from recover_fpsd1200_identity import ROOT,SOURCE,IMAGE,CS,SHA,STACK
from recover_fpsd1200_admission import fixup_checks,bank_proofs
from verify_daemon_reader_record_payloads_publication import read

CFPORT=0x77001000;CFSOURCE=0x77002000;RUNLOOP=0x77003000;MODE=0x77004000
PPCS={0x100624eb4,0x100624eb8,0x1005236b0,0x1003ae28c,0x1003ae314,
 0x1003ae330,0x1003ae380,0x1003ae384,0x1003ae3d8,0x1003ae43c,0x1003ae440,0x1003ae458,0x1003ae45c,
 0x100624c68,0x100624c70,0x1005a7340,0x1005a7350,0x1005a7378,0x1005a7394,0x1005a73ac,0x1005a7410,0x1005a7414,0x1005a7458}


class Port(OutputVM):
    def __init__(self,*args):
        self.port_points=[];self.mode_reads=[];self.mode_guard=None;self.queue_reads=[]
        super().__init__(*args)
        self.mode_address=self.import_addresses['CoreFoundation/_kCFRunLoopDefaultMode']
        if self.fixture.get('mode_data'):
            self.u.mem_write(self.mode_address,struct.pack('<Q',MODE));self.allowed_data.add(self.mode_address)

    def read_hook(self,u,access,a,n,v,data):
        if a==self.mode_address:
            self.mode_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),
              'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        if u.reg_read(A.UC_ARM64_REG_PC)==0x1003ae3d8:
            self.queue_reads.append({'pc':'0x1003ae3d8','address':hex(a),'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        return super().read_hook(u,access,a,n,v,data)

    def hook(self,u,pc,n,data):
        if pc in PPCS:self.port_points.append(self.checkpoint(u,pc))
        if pc==0x1003ae314 and not self.fixture.get('mode_data'):
            self.mode_guard={**self.checkpoint(u,pc),'address':hex(self.reg(9)),'width_B':8}
            return self.stop('before_default_mode_data_boundary')
        if pc in self.imports:
            name=self.imports[pc];site=self.reg(30)-4
            results={'CoreFoundation/_CFMachPortCreate':self.fixture['cf_port_result'],
              'CoreFoundation/_CFMachPortCreateRunLoopSource':self.fixture.get('cf_source_result',CFSOURCE),
              'CoreFoundation/_CFRunLoopGetMain':RUNLOOP,'CoreFoundation/_CFRunLoopAddSource':0,
              'CoreFoundation/_CFMachPortGetPort':self.fixture.get('raw_port_name',0x6800),
              'CoreFoundation/_CFMachPortInvalidate':0}
            if name in results:
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(self.reg(j))for j in range(8)],
                  'entry_checkpoint':self.checkpoint(u,pc),
                  'model':'explicit opaque-CF API result or record-only void effect; no native object, source, scheduling or right'}
                if name=='CoreFoundation/_CFMachPortCreate':
                    e.update(context40_hex=bytes(u.mem_read(self.reg(2),40)).hex(),context_known_mask_hex=self.known(self.reg(2),40),
                      shouldFreeInfo_before=bytes(u.mem_read(self.reg(3),1)).hex())
                self.events.append(e);return self.fixture_return(e,results[name])
            if name=='libSystem/_kevent':
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(self.reg(j))for j in range(8)],
                  'entry_checkpoint':self.checkpoint(u,pc),'change32_hex':bytes(u.mem_read(self.reg(1),32)).hex(),
                  'change_known_mask_hex':self.known(self.reg(1),32),
                  'model':'explicit event return; no native queue, process watch, errno or event effect'}
                self.events.append(e)
                if 'kevent_result'not in self.fixture:return self.stop('unmodeled_import_boundary',name=name,site=e['site'])
                return self.fixture_return(e,self.fixture['kevent_result']&0xffffffffffffffff)
            if name=='libSystem/_vm_deallocate'and site!=0x10049e114:
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(self.reg(j))for j in range(8)],
                  'entry_checkpoint':self.checkpoint(u,pc),'model':'record-only subsequent VM cleanup; return0; private backing retained'}
                self.events.append(e);return self.fixture_return(e,0)
        return super().hook(u,pc,n,data)

    def run_port(self):
        r=self.run_vm();r.update(port_points=self.port_points,mode_reads=self.mode_reads,mode_guard=self.mode_guard,
          mode_address=hex(self.mode_address),queue_word_reads=self.queue_reads)
        return r


def fixtures():
    base=list(previous_fixtures())[0]
    cases=[('CF_port_NULL',0,CFSOURCE,False,None),('CF_source_NULL',CFPORT,0,False,None),
      ('default_mode_guard',CFPORT,CFSOURCE,False,None),('kevent_boundary',CFPORT,CFSOURCE,True,None),
      ('endpoint_success',CFPORT,CFSOURCE,True,0),('kevent_error',CFPORT,CFSOURCE,True,-1)]
    for label,cf,source,mode,kr in cases:
        f={**base,'label':label,'cf_port_result':cf,'cf_source_result':source,'mode_data':mode}
        if kr is not None:f['kevent_result']=kr
        yield f


def proofs():
    import z3
    pid=z3.BitVec('audit_pid32',32);x=z3.SignExt(32,pid);k=z3.BitVecVal(0x863abc041240df58,64)
    y=((x-((x<<1)&z3.BitVecVal(0x0c7578082481beb0,64))+k)^k)
    s=z3.Solver();s.set(timeout=10000);s.add(y!=x);query=s.to_smt2();assert s.check()==z3.unsat
    return {'event_ident_signext_PID':{'query':query,'result':'unsat',
      'scope':'Exact 64-bit source shift/mask/subtract/add/XOR maps every signed32 audit PID to its sign extension; not native identity or watch registration.'}}


def run_case(f):
    gc.collect();x=Port(sources()[3],f,library());r=x.run_port()
    summary={'label':f['label'],'stop':r['stop_reason'],'last_pc':r['last_pc'],'visits':len(r['visited']),
      'status':r['application_status_u32'],'reply_size_B':r['reply_size_B'],
      'last_import':next((e for e in reversed(r['events'])if e['kind']=='import_fixture'),None)}
    assert r['stop_reason']in ['unmodeled_import_boundary','returned_to_fixture','before_default_mode_data_boundary'],r['stop_reason']
    seq=[int(a,16)for a in r['visited']]
    counts={'profiles':1,'daemon_visits':sum(a<0x200000000 for a in seq),'library_visits':sum(a>=0x200000000 for a in seq),
      'import_events':sum(e['kind']=='import_fixture'for e in r['events']),'returned_replies':int(r['reply_completed']),
      'complex_replies':int(r['reply_completed']and r['reply_size_B']==212),'error_replies':int(r['reply_completed']and r['reply_size_B']==36),
      'vm_allocations':len(r['vm_owners_final']),'vm_store_events':len(r['vm_owner_writes']),
      'output_cell_read_events':len(r['output_cell_reads']),'protected_output_store_events':len(r['protected_output_writes']),
      'heap_read_events':len(r['heap_reads']),'heap_store_events':len(r['heap_writes']),
      'complete_montgomery_calls':sum('returned'in c for c in r['montgomery_calls']),'OOL_read_events':len(r['input_ool_reads']),
      'mode_read_events':len(r['mode_reads']),'mode_guards':int(r['mode_guard']is not None),
      'queue_word_read_events':len(r['queue_word_reads'])}
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
            (ROOT/'fpsd1200_port_working.json').write_text(json.dumps({'profiles':packed},indent=2)+'\n')
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
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in ['recover_fpsd1200_vm.py','audit_fpsd1200_vm.py',
        'fpsd1200_vm_checks.json','fpsd1200_vm_ida_readback.json','recover_fpsd1200_certificate.py',
        'audit_fpsd1200_certificate.py','recover_fpsd1200_context.py','audit_fpsd1200_context.py',
        'recover_fpsd1200_arena.py','audit_fpsd1200_arena.py','recover_fpsd1200_identity.py','audit_fpsd1200_identity.py',
        'recover_fpsd1200_admission.py','audit_fpsd1200_admission.py','daemon_rpc502_probe.py','daemon_receive_tools.py',
        'daemon_import_bindings.py','daemon_receive_fixups.txt','bootpolicy_cache_reader.py','rpc502_startup_profiles.json',
        'rpc502_startup_contracts.json','rpc502_policy_contracts.json','rpc502_rsa_contracts.json','rpc502_rsa_models.py',
        'rpc502_startup_tools.py','corefp_client_paths_contracts.json']},
      'new_IDA_access':True,'new_IDB_mutations':False,'new_native_execution':False,'full_goal_complete':False}
    (ROOT/'fpsd1200_port_checks.json').write_text(json.dumps(out,indent=2)+'\n');(ROOT/'fpsd1200_port_working.json').unlink()
    print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
