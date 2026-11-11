#!/usr/bin/env python3
"""Original FPSD1200 VM/output continuation with declared private API contracts.

No native VM allocation, deallocation, port/right, Mach transmission, credentials
or IOKit operation executes. VM return codes, pointer output and private zero
owner are explicit fixtures. Earlier certificate/context premises remain pinned.
O(B+F+V+E+L) finite observer work; compressed profiles bound retained memory.
"""
import base64,gc,json,struct,zlib
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
from recover_fpsd1200_certificate import Certificate,fixtures as predecessor_fixtures,library,sources
from recover_fpsd1200_identity import ROOT,SOURCE,IMAGE,CS,SHA,STACK
from recover_fpsd1200_admission import fixup_checks,bank_proofs
from verify_daemon_reader_record_payloads_publication import read

VM=0x76000000;VM_SIZE=0x100000
VPCS={0x10049e05c,0x10049e0f8,0x10049e114,0x10049e118,0x10049e15c,
 0x10049e17c,0x10049e180,0x10049e18c,0x10049e1b0}


class OutputVM(Certificate):
    def __init__(self,*args):
        self.vm_owners=[];self.vm_reads=[];self.vm_writes=[];self.vm_points=[];self.output_reads=[]
        super().__init__(*args)
        self.u.mem_map(VM,VM_SIZE);self.u.mem_write(VM,b'\xa5'*VM_SIZE)
        if 'initial_reply_OOL_address'in self.fixture:
            self.u.mem_write(self.reply+28,struct.pack('<Q',self.fixture['initial_reply_OOL_address']))
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.vm_write)

    def known(self,a,n):
        for o in self.vm_owners:
            b=o['address']
            if b<=a<a+n<=b+o['size_B']:return bytes(o['known'][a-b:a-b+n]).hex()
        return super().known(a,n)

    def vm_write(self,u,access,a,n,v,data):
        if VM<=a<VM+VM_SIZE:
            o=next(o for o in self.vm_owners if o['address']<=a<a+n<=o['address']+o['size_B'])
            off=a-o['address'];o['known'][off:off+n]=b'\x01'*n
            self.vm_writes.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'owner':hex(o['address']),
              'offset_B':off,'width_B':n,'value':hex(v&((1<<(8*n))-1))})

    def read_hook(self,u,access,a,n,v,data):
        if self.payload is not None and a<self.payload+104 and self.payload+72<a+n:
            self.output_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'width_B':n,
              'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        if VM<=a<VM+VM_SIZE:
            o=next(o for o in self.vm_owners if o['address']<=a<a+n<=o['address']+o['size_B']);off=a-o['address']
            self.vm_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'owner':hex(o['address']),
              'offset_B':off,'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),
              'all_bytes_defined':all(o['known'][off:off+n])})
        return super().read_hook(u,access,a,n,v,data)

    def hook(self,u,pc,n,data):
        if pc in VPCS:self.vm_points.append(self.checkpoint(u,pc))
        if pc in self.imports:
            name=self.imports[pc];site=self.reg(30)-4
            if name=='libSystem/_vm_deallocate'and site==0x10049e114:
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(self.reg(j))for j in range(8)],
                  'model':'record-only VM deallocation; explicit return; no native mapping or right effect'}
                self.events.append(e);return self.fixture_return(e,self.fixture['vm_deallocate_return'])
            if name=='libSystem/_vm_allocate'and site==0x10049e17c and 'vm_allocate_return'in self.fixture:
                args=[self.reg(j)for j in range(8)];ret=self.fixture['vm_allocate_return']
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(a)for a in args],
                  'address_cell_before':bytes(u.mem_read(args[1],8)).hex(),
                  'model':'explicit return; on zero, disjoint private zero owner and pointer-cell store; no native VM'}
                self.events.append(e)
                if ret==0:
                    assert 0<args[2]<=VM_SIZE and not self.vm_owners
                    o={'address':VM,'size_B':args[2],'known':bytearray(b'\x01'*args[2])};self.vm_owners.append(o)
                    u.mem_write(VM,b'\0'*args[2]);u.mem_write(args[1],struct.pack('<Q',VM))
                    if STACK<=args[1]<args[1]+8<=STACK+0x80000:self.stack_known[args[1]-STACK:args[1]-STACK+8]=b'\x01'*8
                    e.update(modeled_address64=hex(VM),modeled_zero_extent_B=args[2])
                return self.fixture_return(e,ret)
            if name=='CoreFoundation/_CFMachPortCreate':
                context=self.reg(2);flag=self.reg(3)
                captured={'context40_hex':bytes(u.mem_read(context,40)).hex(),
                  'context_known_mask_hex':self.known(context,40),
                  'shouldFreeInfo_before':bytes(u.mem_read(flag,1)).hex()}
                result=super().hook(u,pc,n,data);self.events[-1].update(captured);return result
        return super().hook(u,pc,n,data)

    def run_vm(self):
        r=self.run_certificate();r.update(vm_points=self.vm_points,output_cell_reads=self.output_reads,
          vm_owner_reads=self.vm_reads,vm_owner_writes=self.vm_writes,
          vm_owners_final=[{'address':hex(o['address']),'size_B':o['size_B'],
            'bytes_hex':bytes(self.u.mem_read(o['address'],o['size_B'])).hex(),'known_mask_hex':bytes(o['known']).hex()}for o in self.vm_owners],
          vm_backing_sha256=SHA(bytes(self.u.mem_read(VM,VM_SIZE))))
        return r


def fixtures():
    base=list(predecessor_fixtures())[2]
    for label,alloc,addr in [('allocation_success',0,None),('allocation_failure',3,None),('zero_address_success',0,0)]:
        f={**base,'label':label,'vm_deallocate_return':0}
        if alloc is not None:f['vm_allocate_return']=alloc
        if addr is not None:f['initial_reply_OOL_address']=addr
        yield f


def main():
    packed=[];sites=set();guards=set();accesses=set();banks=[]
    counts={k:0 for k in ['profiles','daemon_visits','library_visits','import_events','returned_replies',
      'vm_allocations','vm_store_events','vm_read_events','output_cell_read_events','protected_output_store_events',
      'complete_montgomery_calls','OOL_read_events']}
    for f in fixtures():
        x=OutputVM(sources()[3],f,library());r=x.run_vm()
        summary={'label':f['label'],'stop':r['stop_reason'],'last_pc':r['last_pc'],'visits':len(r['visited']),
          'status':r['application_status_u32'],'last_import':next((e for e in reversed(r['events'])if e['kind']=='import_fixture'),None),
          'VM_owners':[(o['size_B'])for o in r['vm_owners_final']]}
        print(json.dumps(summary),flush=True)
        assert r['stop_reason']in ['unmodeled_import_boundary','returned_to_fixture'],r['stop_reason']
        seq=[int(a,16)for a in r['visited']];sites.update(a for a in seq if a<0x200000000)
        accesses.update(int(a,16)for a in r['fixup_reads']);banks.append({'fixture':f,'byte_bank_reads':r['byte_bank_reads']})
        counts['profiles']+=1;counts['daemon_visits']+=sum(a<0x200000000 for a in seq);counts['library_visits']+=sum(a>=0x200000000 for a in seq)
        counts['import_events']+=sum(e['kind']=='import_fixture'for e in r['events']);counts['returned_replies']+=r['reply_completed']
        counts['vm_allocations']+=len(r['vm_owners_final']);counts['vm_store_events']+=len(r['vm_owner_writes']);counts['vm_read_events']+=len(r['vm_owner_reads'])
        counts['output_cell_read_events']+=len(r['output_cell_reads']);counts['protected_output_store_events']+=len(r['protected_output_writes'])
        counts['complete_montgomery_calls']+=sum('returned'in c for c in r['montgomery_calls']);counts['OOL_read_events']+=len(r['input_ool_reads'])
        packed.append({**summary,'fixture':f,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode(),9)).decode()})
        (ROOT/'fpsd1200_vm_working.json').write_text(json.dumps({'profiles':packed},indent=2)+'\n')
        del x,r,seq;gc.collect()
    spans=[]
    for a in sorted(sites|guards):
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    identities,pairs,unpaired=bank_proofs(banks);fix=fixup_checks(accesses)
    counts.update(source_spans=len(spans),source_instructions=len(sites|guards),format12_rebases=len(fix['records']),
      format12_bindings=len(fix['bindings']),bank_identities=len(identities),bank_inputs=256*len(identities),
      bank_pair_uses=pairs,unpaired_byte_bank_reads=len(unpaired))
    out={'scope':__doc__,'daemon_sha256':SHA(SOURCE.read_bytes()),'generator_sha256':SHA(Path(__file__).read_bytes()),
      'library':library(),'profiles':packed,'verified_counts':counts,'spans':[{'start':hex(a),'end':hex(z),
        'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':SHA(IMAGE.read(a,z-a)),
        'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans],
      'fixups':fix,'byte_bank_proofs':identities,'byte_bank_pairs':pairs,'unpaired_byte_bank_reads':unpaired,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in ['recover_fpsd1200_certificate.py','audit_fpsd1200_certificate.py',
        'fpsd1200_certificate_checks.json','fpsd1200_certificate_ida_readback.json','recover_fpsd1200_context.py',
        'audit_fpsd1200_context.py','recover_fpsd1200_arena.py','audit_fpsd1200_arena.py','recover_fpsd1200_identity.py',
        'audit_fpsd1200_identity.py','recover_fpsd1200_admission.py','audit_fpsd1200_admission.py','daemon_rpc502_probe.py',
        'daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','bootpolicy_cache_reader.py',
        'rpc502_startup_profiles.json','rpc502_startup_contracts.json','rpc502_policy_contracts.json','rpc502_rsa_contracts.json',
        'rpc502_rsa_models.py','rpc502_startup_tools.py','corefp_client_paths_contracts.json']},
      'new_IDA_access':True,'new_IDB_mutations':False,'new_native_execution':False,'full_goal_complete':False}
    (ROOT/'fpsd1200_vm_checks.json').write_text(json.dumps(out,indent=2)+'\n');(ROOT/'fpsd1200_vm_working.json').unlink()
    print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
