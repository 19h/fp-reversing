#!/usr/bin/env python3
"""Original FPSD1200 certificate constructors, arithmetic and continuation.

External API results, startup composition, PAC bypasses and scalar atomics are
explicit private fixtures. Public certificate bytes are original input/data.
No native allocation, trust decision, credentials, Mach or IOKit executes.
O(B+F+V+E+L) source/observer work; compressed profiles bound retained memory.
"""
import base64,gc,json,struct,zlib
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
from recover_fpsd1200_context import Context,library,sources,arena_module
from recover_fpsd1200_identity import IMAGE,SOURCE,SHA,CS,ROOT,STACK
from recover_fpsd1200_admission import fixup_checks,bank_proofs
from verify_daemon_reader_record_payloads_publication import read

CAP=24000000;CERT=0x75000000;CERT_SIZE=0x100000
arena_module.LIMIT=CAP
ENTRIES={0x100539ea0:'square',0x10094593c:'product'}
STATUS_PCS={0x100950fd8,0x10095103c,0x100896930,0x1008969a8,0x10097531c,
 0x100633cb4,0x100660230,0x100482d94,0x100482d9c}


class Certificate(Context):
    def __init__(self,*args):
        self.cert_owners=[];self.cert_reads=[];self.cert_writes=[];self.new_atomics=[]
        self.certificate_points=[];self.montgomery_calls=[];self.mont_active=[]
        self.stack_known=bytearray(0x80000);self.null_guard=None;self.scalar_status_stores=[]
        self.task_self_reads=[];self.task_self_guard=None
        super().__init__(*args)
        self.u.mem_map(CERT,CERT_SIZE);self.u.mem_write(CERT,b'\xa5'*CERT_SIZE)
        self.task_self_address=self.import_addresses['libSystem/_mach_task_self_']
        if 'task_self_u32'in self.fixture:
            self.u.mem_write(self.task_self_address,struct.pack('<I',self.fixture['task_self_u32']))
            self.allowed_data.add(self.task_self_address)
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.certificate_write)

    def known(self,a,n):
        if STACK<=a<a+n<=STACK+0x80000:return bytes(self.stack_known[a-STACK:a-STACK+n]).hex()
        for o in self.startup_owners:
            b=o['address']
            if b<=a<a+n<=b+o['size_B']:return bytes(o['known'][a-b:a-b+n]).hex()
        for o in self.cert_owners:
            b=o['address']
            if b<=a<a+n<=b+o['size_B']:return bytes(o['known'][a-b:a-b+n]).hex()
        return '00'*n

    def integer(self,p):
        raw=bytes(self.u.mem_read(p,16));cap,stored,ptr=struct.unpack('<IIQ',raw)
        count=(stored-0x693be708)&0xffffffff;count=count-(1<<32)if count>>31 else count;n=abs(count)
        assert n<=cap and n<=132
        return {'address':hex(p),'header16_hex':raw.hex(),'header_known_mask_hex':self.known(p,16),
          'active_limbs_hex':bytes(self.u.mem_read(ptr,4*n)).hex()if n else '',
          'active_known_mask_hex':self.known(ptr,4*n)if n else ''}

    def math_view(self,p,kind):
        raw=bytes(self.u.mem_read(p,48 if kind=='product'else 40));q=lambda o:struct.unpack_from('<Q',raw,o)[0]
        ctx=q(0);cb=bytes(self.u.mem_read(ctx,20));c0,c8=struct.unpack_from('<QQ',cb)
        return {'argument':hex(p),'argument_hex':raw.hex(),'context':hex(ctx),'context20_hex':cb.hex(),
          'context_known_mask_hex':self.known(ctx,20),'modulus':self.integer(q(32 if kind=='square'else 8)),
          'left':self.integer(q(24)),'right':self.integer(q(24 if kind=='square'else 40)),
          'output':self.integer(q(16)),'radix':self.integer(c0),'precomputation':self.integer(c8)}

    def checkpoint(self,u,pc):
        return {'pc':hex(pc),'visit_index':len(self.visited),'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),
          'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV)),'registers31':[hex(self.reg(j))for j in range(31)]}

    def certificate_write(self,u,access,a,n,v,data):
        v%=1<<(8*n);pc=u.reg_read(A.UC_ARM64_REG_PC)
        if STACK<=a<a+n<=STACK+0x80000:self.stack_known[a-STACK:a-STACK+n]=b'\x01'*n
        if CERT<=a<CERT+CERT_SIZE:
            owner=next(o for o in self.cert_owners if o['address']<=a<a+n<=o['address']+o['size_B'])
            off=a-owner['address'];owner['known'][off:off+n]=b'\x01'*n
            self.cert_writes.append({'pc':hex(pc),'owner':hex(owner['address']),'offset_B':off,'width_B':n,'value':hex(v)})
        if self.cert_owners and n==4 and v in [0x8b3dc651,0x74c29d8a]:
            self.scalar_status_stores.append({**self.checkpoint(u,pc),'address':hex(a),'value32':hex(v)})

    def read_hook(self,u,access,a,n,v,data):
        if a==self.task_self_address:
            assert 'task_self_u32'in self.fixture
            self.task_self_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),
              'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        if CERT<=a<CERT+CERT_SIZE:
            o=next(o for o in self.cert_owners if o['address']<=a<a+n<=o['address']+o['size_B']);off=a-o['address']
            e={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'owner':hex(o['address']),'offset_B':off,'width_B':n,
              'bytes_hex':bytes(u.mem_read(a,n)).hex(),'all_bytes_defined':all(o['known'][off:off+n]),'retired':o['retired']}
            self.cert_reads.append(e);assert e['all_bytes_defined']and not e['retired']
        return super().read_hook(u,access,a,n,v,data)

    def hook(self,u,pc,n,data):
        if pc==0x10049e0f8 and 'task_self_u32'not in self.fixture:
            self.task_self_guard={**self.checkpoint(u,pc),'address':hex(self.reg(28)),'width_B':4}
            return self.stop('before_task_self_data_boundary')
        if self.mont_active and pc==int(self.montgomery_calls[self.mont_active[-1]]['return_pc'],16):
            c=self.montgomery_calls[self.mont_active.pop()]
            c.update(return_checkpoint=self.checkpoint(u,pc),returned=self.math_view(int(c['entry']['argument'],16),c['kind']))
        if pc in ENTRIES:
            c={'kind':ENTRIES[pc],'entry_pc':hex(pc),'return_pc':hex(self.reg(30)),
              'entry_checkpoint':self.checkpoint(u,pc),'entry':self.math_view(self.reg(0),ENTRIES[pc])}
            self.montgomery_calls.append(c);self.mont_active.append(len(self.montgomery_calls)-1)
        if pc in STATUS_PCS:self.certificate_points.append(self.checkpoint(u,pc))
        if pc==0x100482d98:
            a=self.reg(15);old=int.from_bytes(u.mem_read(a,4),'little');expected=self.reg(14)&0xffffffff;desired=self.reg(11)&0xffffffff
            e={**self.checkpoint(u,pc),'address':hex(a),'old32':hex(old),'expected32':hex(expected),'desired32':hex(desired),
              'executed':self.fixture.get('new_atomic_fixture',False)};self.new_atomics.append(e)
            if not e['executed']:return self.stop('before_new_atomic_boundary')
            stored=desired if old==expected else old;u.mem_write(a,stored.to_bytes(4,'little'))
            self.setreg(14,old);e['stored32']=hex(stored);self.visited.append(pc);u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if pc==0x1003f0e5c and self.reg(0)==0:
            self.null_guard={**self.checkpoint(u,pc),'address':hex(self.reg(11)),'width_B':1}
            return self.stop('null_certificate_write_guard')
        if pc in self.imports:
            name=self.imports[pc];site=self.reg(30)-4
            if name=='libSystem/_malloc'and site==0x100346714 and self.reg(0)in[1219,1035,893,723]:
                size=self.reg(0);null=self.fixture.get('first_certificate_null',False)and not self.cert_owners
                p=0 if null else CERT+len(self.cert_owners)*0x10000
                if p:self.cert_owners.append({'address':p,'size_B':size,'known':bytearray(size),'retired':False})
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(self.reg(j))for j in range(8)],
                  'model':'disjoint private certificate allocation or NULL; source-knownness tracked; no native allocator',
                  'requested_size_B':size};self.events.append(e);return self.fixture_return(e,p)
            if name=='libSystem/_free':
                o=next((o for o in self.cert_owners if o['address']==self.reg(0)),None)
                if o is not None:
                    assert not o['retired'];o['retired']=True
                    e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(self.reg(j))for j in range(8)],
                      'model':'record-only certificate retirement; physical guest bytes preserved; no native free'}
                    self.events.append(e);return self.fixture_return(e,0)
        return super().hook(u,pc,n,data)

    def run_certificate(self):
        r=self.run_context();r.update(certificate_owner_reads=self.cert_reads,certificate_owner_writes=self.cert_writes,
          certificate_owners_final=[{'address':hex(o['address']),'size_B':o['size_B'],'bytes_hex':bytes(self.u.mem_read(o['address'],o['size_B'])).hex(),
            'known_mask_hex':bytes(o['known']).hex(),'retired':o['retired']}for o in self.cert_owners],
          certificate_backing_sha256=SHA(bytes(self.u.mem_read(CERT,CERT_SIZE))),
          certificate_points=self.certificate_points,new_atomics=self.new_atomics,null_certificate_guard=self.null_guard,
          montgomery_calls=self.montgomery_calls,incomplete_montgomery_calls=len(self.mont_active),
          scalar_status_stores=self.scalar_status_stores,source_stack_known_sha256=SHA(bytes(self.stack_known)))
        r.update(task_self_reads=self.task_self_reads,task_self_guard=self.task_self_guard,
          task_self_address=hex(self.task_self_address))
        return r


def fixtures():
    for label,atomic,null,task in [('reference_atomic_guard',False,False,None),('reference_task_data_guard',True,False,None),
      ('reference_Mach_boundary',True,False,0x6600),('first_certificate_NULL',True,True,None)]:
        f={'label':label,'provider_case':0,'execute_once_callback':True,'model_lock':True,'atomic_fixture':True,
          'startup_context':True,'startup_globals':True,'certificate_ool':True,'later_atomic_fixture':True,
          'new_atomic_fixture':atomic,'first_certificate_null':null,
          'request_changes':[[52,2,4],[56,2,4],[40,756,4],[60,756,4]]}
        if task is not None:f['task_self_u32']=task
        yield f


def main():
    lib=library();wire=sources()[3];packed=[];sites=set();guards=set();accesses=set();banks=[]
    counts={k:0 for k in ['profiles','daemon_visits','library_visits','import_events','certificate_allocations',
      'certificate_retirements','certificate_store_events','certificate_read_events','montgomery_calls',
      'complete_montgomery_calls','new_atomic_guards','new_atomic_fixtures','returned_replies','OOL_read_events']}
    for f in fixtures():
        x=Certificate(wire,f,lib);r=x.run_certificate()
        summary={'label':f['label'],'stop':r['stop_reason'],'last_pc':r['last_pc'],'visits':len(r['visited']),
          'status':r['application_status_u32'],'owners':[(o['size_B'],o['retired'])for o in r['certificate_owners_final']],
          'montgomery_calls':len(r['montgomery_calls']),'last_import':next((e for e in reversed(r['events'])if e['kind']=='import_fixture'),None)}
        print(json.dumps(summary),flush=True)
        assert r['stop_reason']in ['unmodeled_import_boundary','before_new_atomic_boundary','before_task_self_data_boundary',
          'returned_to_fixture','null_certificate_write_guard'],r['stop_reason']
        seq=[int(a,16)for a in r['visited']];sites.update(a for a in seq if a<0x200000000)
        if r['stop_reason']in['before_new_atomic_boundary','null_certificate_write_guard','before_task_self_data_boundary']:guards.add(int(r['last_pc'],16))
        accesses.update(int(a,16)for a in r['fixup_reads']);banks.append({'fixture':f,'byte_bank_reads':r['byte_bank_reads']})
        counts['profiles']+=1;counts['daemon_visits']+=sum(a<0x200000000 for a in seq);counts['library_visits']+=sum(a>=0x200000000 for a in seq)
        counts['import_events']+=sum(e['kind']=='import_fixture'for e in r['events']);counts['certificate_allocations']+=len(r['certificate_owners_final'])
        counts['certificate_retirements']+=sum(o['retired']for o in r['certificate_owners_final'])
        counts['certificate_store_events']+=len(r['certificate_owner_writes']);counts['certificate_read_events']+=len(r['certificate_owner_reads'])
        counts['montgomery_calls']+=len(r['montgomery_calls']);counts['complete_montgomery_calls']+=sum('returned'in c for c in r['montgomery_calls'])
        counts['new_atomic_guards']+=r['stop_reason']=='before_new_atomic_boundary';counts['new_atomic_fixtures']+=sum(e['executed']for e in r['new_atomics'])
        counts['returned_replies']+=r['reply_completed'];counts['OOL_read_events']+=len(r['input_ool_reads'])
        packed.append({**summary,'fixture':f,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode(),9)).decode()})
        (ROOT/'fpsd1200_certificate_working.json').write_text(json.dumps({'generator_sha256':SHA(Path(__file__).read_bytes()),
          'daemon_sha256':SHA(SOURCE.read_bytes()),'profiles':packed},indent=2)+'\n')
        del x,r,seq;gc.collect()
    spans=[]
    for a in sorted(sites|guards):
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    identities,pairs,unpaired=bank_proofs(banks);fix=fixup_checks(accesses)
    counts.update(source_spans=len(spans),source_instructions_including_guards=len(sites|guards),
      format12_rebases=len(fix['records']),format12_bindings=len(fix['bindings']),
      bank_identities=len(identities),bank_inputs=256*len(identities),bank_pair_uses=pairs,unpaired_byte_bank_reads=len(unpaired))
    out={'scope':__doc__,'daemon_sha256':SHA(SOURCE.read_bytes()),'generator_sha256':SHA(Path(__file__).read_bytes()),
      'library':lib,'profiles':packed,'verified_counts':counts,'visit_limit':CAP,
      'spans':[{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':SHA(IMAGE.read(a,z-a)),
        'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans],
      'unretired_guard_sites':[hex(a)for a in sorted(guards)],'fixups':fix,'byte_bank_proofs':identities,
      'byte_bank_pairs':pairs,'unpaired_byte_bank_reads':unpaired,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in ['recover_fpsd1200_context.py','audit_fpsd1200_context.py',
        'fpsd1200_context_checks.json','recover_fpsd1200_arena.py','audit_fpsd1200_arena.py','recover_fpsd1200_identity.py',
        'audit_fpsd1200_identity.py','recover_fpsd1200_admission.py','audit_fpsd1200_admission.py','daemon_rpc502_probe.py',
        'daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','bootpolicy_cache_reader.py',
        'rpc502_startup_profiles.json','rpc502_startup_contracts.json','rpc502_policy_contracts.json','rpc502_rsa_contracts.json',
        'rpc502_rsa_models.py','rpc502_startup_tools.py','corefp_client_paths_contracts.json']},
      'new_IDA_access':True,'new_IDB_mutations':False,'new_native_execution':False,'full_goal_complete':False}
    (ROOT/'fpsd1200_certificate_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    (ROOT/'fpsd1200_certificate_working.json').unlink()
    print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
