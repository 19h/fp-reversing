#!/usr/bin/env python3
"""Original FPSD1200 PID extraction and identity-policy prefix, private only.

Security/CF results, PAC and stack probing are explicit fixtures. Selected
cached libbsm instructions execute privately under a declared library pairing;
no native target, credential query, file access by target or IPC executes.
"""
import json,struct,subprocess
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
from recover_fpsd1200_admission import Admission,Base,sources,IMAGE,SOURCE,CS,ROOT,SHA,STACK,HALT,PRIVATE,VALUE,fixup_checks,bank_proofs
from bootpolicy_cache_reader import Cache,Dylib
from daemon_receive_tools import qword
from verify_daemon_reader_record_payloads_publication import read

SLOT=0x1010a0500
EXTRA_POINTS={0x100581f30,0x100582074,0x100582078,0x100582090,0x100582178,
 0x100526a54,0x10040a878,0x1004be1b8,0x100525b78,0x100581be8,0x100531728,
 0x10043e280,0x10040ebd4,0x100361df4,0x100419178,
 0x1003c3240,0x100625e8c,0x10058e43c}


def library():
    c=Cache();d=Dylib(c,'/usr/lib/libbsm.0.dylib');a=d.exports['_audit_token_to_au32']['address'];f=d.function(a)
    assert f['sha256']=='76ed6c9a5a2b1b51e22d1fd36ca9802e734187970d71868438eb981b52e613e5'
    return {'cache_uuid':c.uuid,'library_uuid':d.uuid,'logical_name':'/usr/lib/libbsm.0.dylib',
      'export':'_audit_token_to_au32','function':f,'native_runtime_pairing_established':False}


class Identity(Admission):
    def __init__(self,wire,fixture,lib):
        super().__init__(wire,fixture);self.library=lib;f=lib['function'];self.liblo=int(f['start'],16);self.libhi=int(f['end'],16)
        self.u.mem_map(self.liblo&~4095,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC);self.u.mem_write(self.liblo,bytes.fromhex(f['bytes']))
        self.u.mem_write(SLOT,struct.pack('<Q',self.liblo));self.library_calls=[];self.pending_library=None
        self.extra_points=[];self.identity_lookup=False
        self.once_pending=None;self.once_completed=False;self.callback_models=[]
        self.helper_destination=None;self.caller_destination=None
        self.provider_reads=[];self.cache_context_reads=[];self.provider_snapshot=None
        if 'provider_case'in fixture:
            ctx=json.loads(read(ROOT/'daemon_object_initialization_context.json'))
            self.provider_snapshot=ctx['coherent_provider_snapshots'][fixture['provider_case']]
            self.u.mem_write(PRIVATE+0x9000,bytes.fromhex(self.provider_snapshot['published_buffer512_hex']))
            self.u.mem_write(0x1010c8268,struct.pack('<Q',PRIVATE+0x9000));self.u.mem_write(0x1010c67d4,struct.pack('<I',255))

    def read_hook(self,u,access,a,n,v,data):
        if a in [0x1010c8268,0x1010c67d4]:
            self.cache_context_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),
              'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        if PRIVATE+0x9000<=a<a+n<=PRIVATE+0x9200:
            self.provider_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'offset_B':a-PRIVATE-0x9000,
              'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        return super().read_hook(u,access,a,n,v,data)

    def key(self,a):
        return IMAGE.read(qword(a+16),128).split(b'\0')[0].decode()

    def hook(self,u,pc,n,data):
        if pc in EXTRA_POINTS:
            p={'pc':hex(pc),'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),
              'registers31':[hex(self.reg(j))for j in range(31)],'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV))}
            if pc in [0x100582074,0x100582078,0x100582090,0x100582178]:
                a=u.reg_read(A.UC_ARM64_REG_X29)-0xa8;p['record_address']=hex(a);p['record24']=bytes(u.mem_read(a,24)).hex()
                dst=struct.unpack('<Q',u.mem_read(a,8))[0];p['destination']=hex(dst);p['destination256']=bytes(u.mem_read(dst,256)).hex()
                self.helper_destination=dst
                if pc==0x100582178:self.caller_destination=self.reg(9)
            if pc==0x10043e280 and self.caller_destination is not None:
                p['caller_destination']=hex(self.caller_destination);p['caller256']=bytes(u.mem_read(self.caller_destination,256)).hex()
                p['input_record32']=bytes(u.mem_read(self.reg(0),32)).hex()
            self.extra_points.append(p)
        if pc==HALT+0x100:
            p=self.once_pending;assert p is not None and u.reg_read(A.UC_ARM64_REG_SP)==p['sp']-256
            assert [self.reg(j)for j in range(19,30)]==p['saved19_29']
            p['end_visit']=len(self.visited);self.callback_models.append(p);self.once_completed=True;self.once_pending=None
            u.reg_write(A.UC_ARM64_REG_SP,p['sp']);self.setreg(30,p['return_pc'])
            return self.fixture_return(p['event'],0)
        if (pc==0x100625eac and self.reg(17)==0)or(pc==0x1003c3254 and self.reg(10)==0)or(pc==0x10058e484 and self.reg(13)==0):
            self.extra_points.append({'pc':hex(pc),'kind':'unmapped_environment_read','address':'0x0','width_B':8,
              'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),'registers':[hex(self.reg(j))for j in range(29)]})
            return self.stop('unmapped_environment_read_guard',address='0x0',site=hex(pc))
        if self.pending_library and pc==self.pending_library['return_pc']:
            p=self.pending_library;p['output32_after']=bytes(u.mem_read(p['pid_output'],4)).hex();p['registers_after']=[hex(self.reg(j))for j in range(29)]
            self.library_calls.append(p);self.pending_library=None
        if self.liblo<=pc<self.libhi:
            raw=bytes(u.mem_read(pc,4));off=pc-self.liblo;assert raw==bytes.fromhex(self.library['function']['bytes'])[off:off+4]
            if pc==self.liblo:
                sp=u.reg_read(A.UC_ARM64_REG_SP)
                self.pending_library={'site':hex(self.reg(30)-4),'return_pc':self.reg(30),'pid_output':self.reg(6),
                  'token32':bytes(u.mem_read(self.reg(0),32)).hex(),'output32_before':bytes(u.mem_read(self.reg(6),4)).hex(),
                  'registers_before':[hex(self.reg(j))for j in range(29)],'sp':hex(sp),'stack_argument0':bytes(u.mem_read(sp,8)).hex()}
            self.visited.append(pc);return Base.hook(self,u,pc,n,data)
        if 0x100000000<=pc<0x100e2c000:
            raw=IMAGE.read(pc,4);i=next(CS.disasm(raw,pc))
            if i.mnemonic=='paciza':
                assert bytes(u.mem_read(pc,4))==raw;self.visited.append(pc);self.steps+=1
                self.pac.append({'site':hex(pc),'instruction':'paciza','authentication':'skipped; private logical data pointer'})
                u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if pc in self.imports:
            name=self.imports[pc];site=self.reg(30)-4;args=[self.reg(j)for j in range(8)]
            if name=='libSystem/_pthread_once'and self.fixture.get('execute_once_callback'):
                assert args[:2]==[0x1010b8cd0,0x10040ebd4]
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(x)for x in args],
                  'model':'single-thread once invocation fixture; no native synchronization','callback_invoked':not self.once_completed};self.events.append(e)
                if self.once_completed:return self.fixture_return(e,0)
                sp=u.reg_read(A.UC_ARM64_REG_SP)
                self.once_pending={'sp':sp,'return_pc':self.reg(30),'saved19_29':[self.reg(j)for j in range(19,30)],
                  'start_visit':len(self.visited),'event':e}
                u.reg_write(A.UC_ARM64_REG_SP,sp-256);self.setreg(30,HALT+0x100)
                u.reg_write(A.UC_ARM64_REG_PC,0x10040ebd4);return
            if name in ['libSystem/_pthread_rwlock_wrlock','libSystem/_pthread_rwlock_unlock']and self.fixture.get('model_lock'):
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(x)for x in args],
                  'model':'opaque lock fixture; record-only handle, preserve registers, no native lock'};self.events.append(e)
                return self.fixture_return(e,self.fixture.get('lock_status',0))
            if name=='Security/_SecTaskCopyValueForEntitlement'and site==0x100526a50:
                self.identity_lookup=True
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(x)for x in args],
                  'error_cell_before':bytes(u.mem_read(args[2],8)).hex(),'logical_key':'com.apple.private.fairplay.FPDI'}
                self.events.append(e)
                if self.fixture.get('identity_error'):
                    u.mem_write(args[2],struct.pack('<Q',PRIVATE+0x6100));e['modeled_error_object']=hex(PRIVATE+0x6100)
                return self.fixture_return(e,self.fixture.get('identity_value',VALUE+0x1000))
            if name=='CoreFoundation/_CFDictionaryGetTypeID':
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(x)for x in args]};self.events.append(e)
                return self.fixture_return(e,99)
            if name in ['CoreFoundation/_CFArrayGetTypeID','CoreFoundation/_CFArrayGetCount']:
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(x)for x in args]};self.events.append(e)
                return self.fixture_return(e,88 if name.endswith('TypeID')else self.fixture.get('capabilities_count',0))
            if name=='CoreFoundation/_CFGetTypeID'and self.identity_lookup:
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(x)for x in args]};self.events.append(e)
                value=(self.fixture.get('client_type',7)if args[0]==PRIVATE+0x8000 else
                  self.fixture.get('capabilities_type',88)if args[0]==PRIVATE+0x8100 else self.fixture.get('identity_type',99))
                return self.fixture_return(e,value)
            if name=='CoreFoundation/_CFDictionaryCreateCopy':
                e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(x)for x in args]};self.events.append(e)
                return self.fixture_return(e,self.fixture.get('dictionary_copy',PRIVATE+0x7000))
            if name=='CoreFoundation/_CFDictionaryContainsKey':
                key=self.key(args[1]);e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(x)for x in args],'logical_key':key};self.events.append(e)
                result=self.fixture.get('dictionary_contains',1)if key=='client-identifier'else self.fixture.get('capabilities_contains',0)
                return self.fixture_return(e,result)
            if name=='CoreFoundation/_CFDictionaryGetValue':
                key=self.key(args[1]);e={'kind':'import_fixture','name':name,'site':hex(site),'args':[hex(x)for x in args],'logical_key':key};self.events.append(e)
                value=self.fixture.get('client_value',PRIVATE+0x8000)if key=='client-identifier'else self.fixture.get('capabilities_value',PRIVATE+0x8100)
                return self.fixture_return(e,value)
        return super().hook(u,pc,n,data)

    def run_identity(self):
        r=self.run_admission();r.update(library_calls=self.library_calls,identity_points=self.extra_points,
          provider_reads=self.provider_reads,cache_context_reads=self.cache_context_reads,
          provider_snapshot=self.provider_snapshot,callback_models=self.callback_models,image_writes=self.writes,
          final_image_writes=[{'address':e['address'],'width_B':e['size'],'bytes_hex':bytes(self.u.mem_read(int(e['address'],16),e['size'])).hex()}for e in self.writes])
        if r['stop_reason']is None:r['stop_reason']='instruction_budget_guard'
        assert self.pending_library is None
        return r


def fixtures():
    rows=[]
    for pid in [0,1,123,0xffffffff]:
        rows.append({'label':'pid_'+str(pid),'audit32':struct.pack('<8I',0,0,0,0,0,pid,0,0).hex()})
    rows += [{'label':'no_provider_reference'},
      {'label':'identity_absent','identity_value':0},
      {'label':'identity_error','identity_value':0,'identity_error':True},
      {'label':'identity_wrong_type','identity_type':42},
      {'label':'dictionary_copy_null','dictionary_copy':0},
      {'label':'dictionary_key_absent','dictionary_contains':0},
      {'label':'client_value_null_inconsistent_fixture','client_value':0},
      {'label':'client_type_wrong','client_type':42},
      {'label':'client_conversion_false','text_ok':0},
      {'label':'identity_task_null','tasks':[PRIVATE+0x3000,0]},
      {'label':'identity_value_and_error','identity_error':True},
      {'label':'provider_0','provider_case':0},
      {'label':'provider_1','provider_case':1},
      {'label':'provider_once','provider_case':0,'execute_once_callback':True},
      {'label':'provider_lock','provider_case':0,'execute_once_callback':True,'model_lock':True},
      {'label':'provider_pid_123','provider_case':0,'execute_once_callback':True,'model_lock':True,'audit32':struct.pack('<8I',1,2,3,4,5,123,7,8).hex()},
      {'label':'provider_numeric_zero','provider_case':0,'execute_once_callback':True,'model_lock':True,'number':0},
      {'label':'provider_empty_identifier','provider_case':0,'text':''},
      {'label':'capabilities_wrong_type','provider_case':0,'capabilities_contains':1,'capabilities_type':7},
      {'label':'capabilities_empty','provider_case':0,'capabilities_contains':1,'capabilities_count':0},
      {'label':'capabilities_one','provider_case':0,'capabilities_contains':1,'capabilities_count':1}]
    return rows


def constant_strings():
    rows=[]
    for a in [0x1010b1a58,0x1010b1a78,0x1010b1ad8]:
        ptr=qword(a+16);n=qword(a+24);raw=IMAGE.read(ptr,n+1);assert raw[-1]==0
        rows.append({'address':hex(a),'original_object32':IMAGE.read(a,32).hex(),
          'flags64':hex(qword(a+8)),'length_B':n,'literal_address':hex(ptr),'literal':raw[:-1].decode(),
          'literal_hex':raw.hex(),'pointer_binding':fixup_checks({a,a+16})})
    return rows


def sdk_context():
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    specs=[('CFString.h','ed49de9f86adc90f53a2f6d5a10666e1e4b865a15adea1311d8104083d9fac31',
      ['kCFStringEncodingUTF8 = 0x08000100,']),
      ('CFDictionary.h','cde527652ea4af4304bdd53a4ff72cf2c8c5b05988ae9572218e46f2a8c0797b',
      ['CFDictionaryRef CFDictionaryCreateCopy(CFAllocatorRef allocator, CFDictionaryRef theDict);',
       'Boolean CFDictionaryContainsKey(CFDictionaryRef theDict, const void *key);',
       'const void *CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);']),
      ('CFArray.h','a9a30c78f8d10d18db70175cfb803dd622f3e4cfe74ab7fe5c1bf926d712259e',
      ['CFIndex CFArrayGetCount(CFArrayRef theArray);','const void *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);'])]
    rows=[]
    for name,h,declarations in specs:
        raw=(sdk/'System/Library/Frameworks/CoreFoundation.framework/Headers'/name).read_bytes()
        assert SHA(raw)==h and all(d in raw.decode()for d in declarations)
        rows.append({'logical_name':'CoreFoundation/'+name,'sha256':h,'declarations':declarations})
    return rows


def proofs():
    import z3
    rows={};u=z3.BitVec('u32',32);status=z3.BitVec('local_status',32)
    def prove(name,expr):
        s=z3.Solver();s.set(timeout=15000);s.add(expr);q=s.to_smt2();assert s.check()==z3.unsat
        rows[name]={'query':q,'result':'unsat','scope':'Local source arithmetic under the stated mask/phase; no native theorem.'}
    select=z3.If(status==0x3eb38698,z3.BitVecVal(1,32),z3.BitVecVal(0,32))*(0x55e4^0x5bf6^0xe39)^0x7e48
    prove('identity_return_selector',select!=z3.If(status==0x3eb38698,z3.BitVecVal(0x7e63,32),z3.BitVecVal(0x7e48,32)))
    offset=z3.SignExt(32,((u&0xfffffff8)+0x466d4638))&255
    prove('failure_codec_cache_bound',z3.UGT(offset,z3.BitVecVal(248,64)))
    offset=z3.SignExt(32,u&255)&z3.BitVecVal(0xfffffffffffffff8,64)
    prove('identifier_codec_cache_bound',z3.UGT(offset,z3.BitVecVal(248,64)))
    prove('caller_codec_cache_bound',z3.UGT(z3.SignExt(32,u&255)+8,z3.BitVecVal(263,64)))
    token=z3.BitVec('audit_token256',256)
    prove('libbsm_PID_word5',z3.ZeroExt(224,z3.Extract(191,160,token))!=(z3.LShR(token,160)&0xffffffff))
    return rows


def main():
    lib=library();wire=sources()[3];rows=[]
    for f in fixtures():
        r=Identity(wire,f,lib).run_identity();rows.append(r)
        assert r['stop_reason']in ['unmapped_environment_read_guard','unmodeled_import_boundary']
        print(json.dumps({'label':f['label'],'stop':r['stop_reason'],'status':r['reply_status_u32'],'visits':len(r['visited']),
          'last_imports':[e for e in r['events']if e['kind']=='import_fixture'][-3:],'last_source':r['visited'][-6:]}),flush=True)
    sites={int(a,16)for r in rows for a in r['visited']if int(a,16)<0x200000000}
    guards={int(r['last_pc'],16)for r in rows if r['stop_reason']=='unmapped_environment_read_guard'}
    spans=[]
    for a in sorted(sites|guards):
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    att=json.loads(read(ROOT/'fpsd1200_identity_ida_readback.json'))
    assert att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    assert att['spans']==[{'start':hex(a),'size_B':z-a,'sha256':SHA(IMAGE.read(a,z-a))}for a,z in spans]
    banks,pairs,unpaired=bank_proofs(rows)
    out={'scope':__doc__,'daemon_sha256':SHA(SOURCE.read_bytes()),'library':lib,'profiles':rows,
      'spans':[{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':SHA(IMAGE.read(a,z-a)),
      'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans],
      'unretired_guard_sites':[hex(a)for a in sorted(guards)],'constant_strings':constant_strings(),
      'fixups':fixup_checks({int(a,16)for r in rows for a in r['fixup_reads']}),
      'byte_bank_proofs':banks,'byte_bank_pairs':pairs,'unpaired_byte_bank_reads':unpaired,
      'proofs':proofs(),'SDK_context':sdk_context(),'generator_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in ['recover_fpsd1200_admission.py','fpsd1200_admission_checks.json',
        'audit_fpsd1200_admission.py','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_import_bindings.py',
        'daemon_receive_fixups.txt','bootpolicy_cache_reader.py','daemon_object_initialization_context.json','fpsd1200_identity_ida_readback.json']},
      'new_IDA_access':True,'new_IDB_mutations':False,'new_native_execution':False,'full_goal_complete':False}
    out['verified_counts']={'profiles':len(rows),'source_spans':len(spans),'source_instructions_including_guards':len(sites|guards),
      'daemon_visits':sum(sum(int(a,16)<0x200000000 for a in r['visited'])for r in rows),
      'library_visits':sum(sum(int(a,16)>=0x200000000 for a in r['visited'])for r in rows),
      'library_calls':sum(len(r['library_calls'])for r in rows),'original_copy_calls':sum(len(r['copies'])for r in rows),
      'unmapped_read_guards':sum(r['stop_reason']=='unmapped_environment_read_guard'for r in rows),
      'import_boundaries':sum(r['stop_reason']=='unmodeled_import_boundary'for r in rows),
      'original_once_callbacks':sum(len(r['callback_models'])for r in rows),
      'provider_profiles':sum(r['provider_snapshot']is not None for r in rows),
      'provider_reads':sum(len(r['provider_reads'])for r in rows),'queries_unsat':len(out['proofs']),
      'format12_rebases':len(out['fixups']['records']),'format12_bindings':len(out['fixups']['bindings']),
      'bank_identities':len(banks),'bank_inputs':256*len(banks),'bank_pair_uses':pairs,'unpaired_byte_bank_reads':len(unpaired)}
    (ROOT/'fpsd1200_identity_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']),flush=True)


if __name__=='__main__':main()
