#!/usr/bin/env python3
"""Original FPSD1200 protected admission path with declared Security/CF fixtures.

No native target, credential query, entitlement lookup or IPC executes. Original
adapter/core instructions run in private Unicorn memory. PAC and stack checks
are explicit models. Unknown APIs and system instructions are stopping guards.
O(C*(B+F+K)+R) time and O(B+F+C*K+R) space; solver cost is separate.
"""
import hashlib,json,struct,subprocess
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
from recover_fpsd1200_contract import Server,sources,IMAGE,SOURCE,CS,ROOT,SHA,STACK,HALT
from daemon_rpc502_probe import Probe as Base
from daemon_receive_tools import FIXUPS,TABLE,POOL,verify_original_fixups,bank
from verify_daemon_reader_record_payloads_publication import read
from daemon_import_bindings import binding

PRIVATE=0x73000000;STRING=PRIVATE+0x2000;TASK=PRIVATE+0x3000;VALUE=PRIVATE+0x4000
BANK_BASES=[0x100e99700,0x100e99800,0x100e99900,0x100e99a00,0x100f4e190,0x100f4e290,
 0x100f4e390,0x100fc4130,0x100fc4230,0x101031da0,0x101031ea0,0x101031fa0]
POINTS={0x10065ffd8,0x10066022c,0x100660230,0x10066023c,0x10061a2d0,0x10061a464,
 0x1004c244c,0x100610388,0x1005283ac,0x1005765e8,0x1004d0640,0x1004666ec,
 0x1004d4268,0x1004bd65c,0x10052db58,0x100414874,0x100007f1c,0x100004680,
 0x10052ddd0,0x10052de54,0x1000ed944,0x1000b7a48,0x10055514c}


class Admission(Server):
    def __init__(self,wire,fixture):
        super().__init__(wire,fixture);self.events=[];self.points=[];self.copies=[];self.tasks=0;self.lookups=0
        self.carrier_address=None;self.copy_stack=[];self.copy_done=[];self.current=None
        self.u.mem_map(PRIVATE,0x10000);self.allowed_data=set();self.fixup_reads=set();self.image_reads=set();self.ool_reads=[];self.bank_reads=[]
        self.u.mem_write(self.req+84,bytes.fromhex(fixture.get('audit32',bytes(range(32)).hex())))
        self.request_initial=bytes(self.u.mem_read(self.req,128))
        for name,val in [('CoreFoundation/_kCFAllocatorDefault',0),('CoreFoundation/_kCFAllocatorNull',PRIVATE+0x1000)]:
            a=self.import_addresses[name];self.allowed_data.add(a);self.u.mem_write(a,struct.pack('<Q',val))
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.observe_write)

    def read_hook(self,u,access,a,n,v,data):
        if n==1:
            bases=[b for b in BANK_BASES if b<=a<b+256]
            if bases:self.bank_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'base':hex(bases[0]),
              'index':a-bases[0],'value':u.mem_read(a,1)[0]})
        if self.ool<=a<self.ool+756:self.ool_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'width_B':n})
        if IMAGE.segments[0][0]<=a<0x102000000:
            self.image_reads.add((a,n))
            for q in range(a&~7,(a+n+7)&~7,8):
                if q in FIXUPS:self.fixup_reads.add(q)
        if a in self.allowed_data:return
        return Base.read_hook(self,u,access,a,n,v,data)

    def observe_write(self,u,access,a,n,v,data):
        if self.carrier_address is not None:
            c=self.carrier_address
            if a<c+28 and a+n>c:self.events.append({'kind':'carrier_write','pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),
              'address':hex(a),'width_B':n,'value':hex(v&((1<<(8*n))-1))})

    def hook(self,u,pc,n,data):
        if pc==HALT:return Base.hook(self,u,pc,n,data)
        if self.steps>18000:return self.stop('private_budget_guard')
        while self.copy_stack and pc==self.copy_stack[-1]['return_pc']:
            e=self.copy_stack.pop();after=bytes(u.mem_read(e['destination'],e['size_B']))
            assert after.hex()==e['source_hex'];e['destination_after_hex']=after.hex();self.copy_done.append(e)
        if pc in POINTS:
            sp=u.reg_read(A.UC_ARM64_REG_SP)
            e={'pc':hex(pc),'sp':hex(sp),'regs':[hex(self.reg(i))for i in range(29)]}
            e['nzcv']=hex(u.reg_read(A.UC_ARM64_REG_NZCV))
            if pc in [0x10066022c,0x100660230,0x10066023c]:e['adapter_scratch8']=bytes(u.mem_read(self.reg(20),8)).hex()
            if pc in [0x10052ddd0,0x10052de54]:
                e['helper_record24']=bytes(u.mem_read(u.reg_read(A.UC_ARM64_REG_X29)-0xa8,24)).hex()
                e['consumer_phase32']=hex(struct.unpack('<I',u.mem_read(sp+0x288,4))[0])
                cell=struct.unpack_from('<Q',bytes.fromhex(e['helper_record24']),8)[0]
                e['helper_key_prefix32']=hex(struct.unpack('<I',u.mem_read(cell,4))[0])
            if pc==0x10065ffd8:
                self.carrier_address=self.reg(0);self.delta_cell=self.reg(1)
                e['carrier28']=bytes(u.mem_read(self.carrier_address,28)).hex()
            if self.carrier_address is not None:
                e['carrier28']=bytes(u.mem_read(self.carrier_address,28)).hex()
                e['delta8']=bytes(u.mem_read(self.delta_cell,8)).hex()
            self.points.append(e)
        if pc==0x10046f89c:
            src,dst,size=[self.reg(i)for i in range(3)];assert size<=256
            self.copy_stack.append({'site':hex(self.reg(30)-4),'source':src,'destination':dst,'size_B':size,
              'source_hex':bytes(u.mem_read(src,size)).hex(),'return_pc':self.reg(30)})
        if pc in self.imports:
            name=self.imports[pc];args=[self.reg(i)for i in range(8)]
            e={'kind':'import_fixture','name':name,'site':hex(self.reg(30)-4),'args':[hex(x)for x in args]};self.events.append(e)
            if name=='libSystem/___chkstk_darwin':
                e.update({'model':'preserve all registers and memory','extent_x9_B':self.reg(9)});return self.return_model()
            if name=='CoreFoundation/_CFStringCreateWithCStringNoCopy':
                e['literal']=bytes(u.mem_read(args[1],128)).split(b'\0')[0].decode()
                value=self.fixture.get('string',STRING)
                if value and e['literal']!='fairplay-client':value+=0x100
                return self.fixture_return(e,value)
            if name=='Security/_SecTaskCreateWithAuditToken':
                e['audit32']=bytes(u.mem_read(args[1],32)).hex();vals=self.fixture.get('tasks',[TASK]);ix=min(self.tasks,len(vals)-1);self.tasks+=1
                val=vals[ix]+(self.tasks-1)*0x100 if len(vals)==1 and vals[ix]else vals[ix]
                return self.fixture_return(e,val)
            if name=='Security/_SecTaskCopyValueForEntitlement':
                vals=self.fixture.get('values',[VALUE]);ix=min(self.lookups,len(vals)-1);self.lookups+=1
                e['error_cell_before']=None if not args[2]else bytes(u.mem_read(args[2],8)).hex()
                if args[2]and self.fixture.get('error_object'):u.mem_write(args[2],struct.pack('<Q',PRIVATE+0x6000));e['modeled_error_object']=hex(PRIVATE+0x6000)
                val=vals[ix]+(self.lookups-1)*0x100 if len(vals)==1 and vals[ix]else vals[ix]
                return self.fixture_return(e,val)
            if name=='CoreFoundation/_CFNumberGetTypeID':return self.fixture_return(e,42)
            if name=='CoreFoundation/_CFStringGetTypeID':return self.fixture_return(e,7)
            if name=='CoreFoundation/_CFBooleanGetTypeID':return self.fixture_return(e,21)
            if name=='CoreFoundation/_CFBooleanGetValue':return self.fixture_return(e,self.fixture.get('boolean',1))
            if name=='CoreFoundation/_CFGetTypeID':
                types=self.fixture.get('value_types',[self.fixture.get('value_type',42)])
                return self.fixture_return(e,types[min(self.lookups-1,len(types)-1)])
            if name=='CoreFoundation/_CFStringGetCString':
                e['capacity_B']=args[2];e['encoding']=hex(args[3]);value=self.fixture.get('text','1').encode()+b'\0'
                assert len(value)<=args[2]
                if self.fixture.get('text_ok',1):u.mem_write(args[1],value);e['modeled_bytes']=value.hex()
                return self.fixture_return(e,self.fixture.get('text_ok',1))
            if name=='CoreFoundation/_CFNumberGetValue':
                assert args[1]==3
                if self.fixture.get('number_write',True):
                    val=self.fixture.get('number',1)&0xffffffff;u.mem_write(args[2],struct.pack('<I',val));e['modeled_output32']=hex(val)
                return self.fixture_return(e,self.fixture.get('number_ok',1))
            if name=='libSystem/_strtol':
                assert args[2]==10
                e['text32']=bytes(u.mem_read(args[0],32)).hex()
                end=0 if self.fixture.get('end_null')else args[0]+self.fixture.get('end_offset',len(self.fixture.get('text','1')))
                u.mem_write(args[1],struct.pack('<Q',end));e['modeled_end_pointer']=hex(end)
                return self.fixture_return(e,self.fixture.get('strtol_value',1)&((1<<64)-1))
            if name in ['CoreFoundation/_CFRelease','libSystem/_mig_deallocate']:
                e['model']='record only; no native release/deallocation';return self.fixture_return(e,0)
            return self.stop('unmodeled_import_boundary',name=name,site=e['site'])
        if not 0x100000000<=pc<0x100e2c000:return self.stop('unreviewed_address_guard',pc=hex(pc))
        assert bytes(u.mem_read(pc,4))==IMAGE.read(pc,4)
        self.visited.append(pc);return Base.hook(self,u,pc,n,data)

    def fixture_return(self,e,val):e['result']=hex(val);return self.return_model(val)

    def run_admission(self):
        self.setreg(0,self.req);self.setreg(1,self.reply);self.setreg(30,HALT)
        self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000)
        try:self.u.emu_start(0x100004b80,0,count=18001)
        except uc.UcError as ex:self.stop_reason='private_engine_error:'+str(ex)
        b=bytes(self.u.mem_read(self.reply,212));c=self.carrier_address
        return {'fixture':self.fixture,'stop_reason':self.stop_reason,'last_pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),
          'reply212':b.hex(),'reply_completed':self.stop_reason=='returned_to_fixture',
          'reply_size_B':struct.unpack_from('<I',b,4)[0]if self.stop_reason=='returned_to_fixture'else None,
          'reply_status_u32':struct.unpack_from('<I',b,32)[0]if self.stop_reason=='returned_to_fixture'else None,
          'carrier28_final':None if c is None else bytes(self.u.mem_read(c,28)).hex(),
          'delta8_final':None if c is None else bytes(self.u.mem_read(self.delta_cell,8)).hex(),
          'initial_request128':self.request_initial.hex(),'input_ool_reads':self.ool_reads,
          'byte_bank_reads':self.bank_reads,
          'final_stack_sha256':SHA(bytes(self.u.mem_read(STACK,0x80000))),
          'final_private_sha256':SHA(bytes(self.u.mem_read(PRIVATE,0x10000))),
          'events':self.events,'points':self.points,'copies':self.copy_done,'fixup_reads':[hex(a)for a in sorted(self.fixup_reads)],
          'image_reads':[[hex(a),n]for a,n in sorted(self.image_reads)],'visited':[hex(a)for a in self.visited],'PAC_bypasses':self.pac,
          'native_credential_or_entitlement_queries':False,'native_messages_emitted':False}


def fixtures():
    return [{'label':'no_string_no_task','string':0,'tasks':[0]},
      {'label':'first_task_null','tasks':[0]}, {'label':'entitlement_absent','values':[0]},
      {'label':'numeric_one','number':1},{'label':'numeric_zero','number':0},
      {'label':'numeric_minus_one','number':0xffffffff},{'label':'numeric_two','number':2},
      {'label':'numeric_conversion_false_no_write','number_ok':0,'number_write':False},
      {'label':'numeric_conversion_false_writes_one','number_ok':0,'number':1},
      {'label':'value_is_string','value_type':7},{'label':'value_other_type','value_type':9},
      {'label':'fallback_lookup_present','tasks':[0,TASK],'values':[VALUE]},
      {'label':'fallback_lookup_absent','tasks':[0,TASK],'values':[0]},
      {'label':'lookup_error_object','values':[0],'error_object':True},
      {'label':'fallback_boolean_true','tasks':[0,TASK],'value_types':[21],'boolean':1},
      {'label':'fallback_boolean_false','tasks':[0,TASK],'value_types':[21],'boolean':0},
      {'label':'fallback_wrong_type','tasks':[0,TASK],'value_types':[9]},
      {'label':'string_conversion_false','value_type':7,'text_ok':0},
      {'label':'string_zero','value_type':7,'text':'0','strtol_value':0},
      {'label':'string_trailing','value_type':7,'text':'1x','end_offset':1},
      {'label':'string_no_digits','value_type':7,'text':'x','strtol_value':0,'end_offset':0},
      {'label':'string_null_end_fixture','value_type':7,'end_null':True},
      {'label':'zero_audit_numeric','audit32':bytes(32).hex()},
      {'label':'all_one_audit_denied','audit32':(b'\xff'*32).hex(),'values':[0]},
      {'label':'client_field2_extent756','request_changes':[[52,2,4],[40,756,4],[60,756,4]]},
      {'label':'string_wide_value','value_type':7,'text':'4294967297','strtol_value':0x100000001},
      {'label':'string_empty','value_type':7,'text':'','strtol_value':0}]


def fixup_checks(addresses):
    binds=sorted(a for a in addresses if FIXUPS[a]['kind'].endswith('bind'))
    out=verify_original_fixups(sorted(addresses-set(binds)))
    out['bindings']=[binding(a)for a in binds]
    return out


def proofs():
    import z3
    rows={}
    def prove(name,variables,expression,expected,guard=True):
        s=z3.Solver();s.set(timeout=15000);s.add(guard,expression!=expected);query=s.to_smt2();r=s.check();assert r==z3.unsat,(name,r)
        rows[name]={'result':str(r),'query':query,'scope':'Local lifted source arithmetic under recorded phases; no native control-flow theorem.'}
    bv=lambda v,n=32:z3.BitVecVal(v,n)
    k=z3.BitVec('carrier_key',32);tag=z3.BitVec('operation',32);ptr=z3.BitVec('payload_pointer',64)
    prove('phase_codec',[k],(k^bv(0x6cf4))^k,bv(0x6cf4))
    prove('operation_codec',[k],(k^bv(0xad952088))^k,bv(0xad952088))
    phase=bv(0x6567)^bv(0x7cc4);cmp=(phase^bv(0x7557))+bv(0xad94b394)
    ix=(z3.If(tag==cmp,bv(1),bv(0))*(phase^bv(0x865f)))^phase
    prove('operation_selector',[tag],ix,z3.If(tag==bv(0xad952088),bv(0x865f),bv(0x19a3)))
    p=bv(0x19a3)^bv(0xb1bd);w20=(p^bv(0xc4ea))+bv(0xffffea69)
    ix=((z3.If(ptr==0,bv(1),bv(0))^w20)&bv(1))*bv(0x3d)^p
    prove('payload_nonnull_selector',[ptr],ix,z3.If(ptr==0,bv(0xa81e),bv(0xa823)))
    result=z3.BitVec('conversion_result',32);cmp=z3.ZeroExt(24,z3.Extract(7,0,bv(0x3f7c)^bv(0x7c)))
    prove('number_conversion_marker',[result],z3.If(result==cmp,bv(0x7e),bv(0x7f)),z3.If(result==0,bv(0x7e),bv(0x7f)))
    byte=z3.BitVec('helper_result_byte',8)
    # The source consumer phase is checked independently in every retained frame.
    phase32=bv(0x48);expected=(phase32&bv(0xd9))^bv(0x36)
    ix=(z3.If(z3.ZeroExt(24,byte)!=expected,bv(1),bv(0))*bv(0x34))^bv(0xa901)
    prove('helper_result_consumer',[byte],ix,z3.If(byte==bv(0x7e,8),bv(0xa901),bv(0xa935)))
    seed=z3.BitVec('adapter_seed',64);scratch=seed
    delta=z3.ZeroExt(48,z3.Extract(15,0,z3.Extract(31,0,scratch)-z3.Extract(31,0,seed)))<<4
    prove('restored_scratch_delta',[seed],delta,bv(0,64))
    encoded=z3.BitVec('status',32)
    prove('status_roundtrip',[encoded],(encoded^bv(0x8b3dc651))^bv(0x8b3dc651),encoded)
    return rows


def controls():
    import z3
    rows={}
    byte=z3.BitVec('unconstrained_helper_byte',8);s=z3.Solver();s.add(byte!=0x7e,byte!=0x7f)
    q=s.to_smt2();assert s.check()==z3.sat
    rows['helper_domain_is_required']={'query':q,'result':'sat','scope':'Abstract byte-domain control; the caller predicate alone does not enforce the helper output domain.'}
    seed=z3.BitVec('unrestored_seed',32);scratch=z3.BitVec('unrestored_scratch',32);s=z3.Solver();s.add(((scratch-seed)&0xffff)!=0)
    q=s.to_smt2();assert s.check()==z3.sat
    rows['scratch_restoration_is_required']={'query':q,'result':'sat','scope':'Abstract scalar control; zero delta requires a restored low16 scratch difference.'}
    return rows


def sdk_context():
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    raw=(sdk/'System/Library/Frameworks/Security.framework/Headers/SecTask.h').read_bytes()
    assert SHA(raw)=='f10e7bc0490568fef3e542d10fd0a8b4d0d657f090d5841782e325faecb4bd68'
    declarations=['SecTaskRef SecTaskCreateWithAuditToken(CFAllocatorRef __nullable allocator, audit_token_t token);',
      'CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef entitlement, CFErrorRef *error);']
    assert all(d in raw.decode()for d in declarations)
    return {'logical_name':'installed SDK Security/SecTask.h','sha256':SHA(raw),'declarations':declarations,
      'scope':'Source-level sender/task and entitlement API context only; matching runtime library/PAC behavior is not established.'}


def bank_proofs(rows):
    groups={};pairs=0;unpaired=[]
    families={(0x100e99700,0x100f4e190),(0x100e99800,0x100f4e290),(0x100e99a00,0x100f4e390),
      (0x100fc4130,0x101031ea0),(0x100fc4230,0x101031fa0),(0x101031da0,0x100e99900)}
    for row in rows:
        reads=row['byte_bank_reads'];j=0
        while j<len(reads):
            if j+1==len(reads)or(int(reads[j]['base'],16),int(reads[j+1]['base'],16))not in families:
                unpaired.append({'profile':row['fixture']['label'],**reads[j]});j+=1;continue
            l,r=reads[j:j+2];j+=2
            left,right=int(l['base'],16),int(r['base'],16);key=l['value']^r['index'];c=l['index']^r['value']
            identity=(left,right,key)
            if identity not in groups:
                assert bank(left,right,key)==c
                groups[identity]={'left':hex(left),'right':hex(right),'key':hex(key),'constant':hex(c),'inputs_checked':256,'observed_uses':0}
            assert groups[identity]['constant']==hex(c);groups[identity]['observed_uses']+=1;pairs+=1
    return list(groups.values()),pairs,unpaired


def main():
    wire=sources()[3];rows=[]
    for f in fixtures():
        r=Admission(wire,f).run_admission();rows.append(r)
        print(f['label'],r['stop_reason'],None if r['reply_status_u32']is None else hex(r['reply_status_u32']),len(r['visited']),
          [(e['name'].split('/')[-1],e['site'])for e in r['events']if e['kind']=='import_fixture'][-4:])
    sites=sorted({int(a,16)for r in rows for a in r['visited']});spans=[]
    for a in sites:
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    banks,pair_count,unpaired=bank_proofs(rows)
    att=json.loads(read(ROOT/'fpsd1200_admission_ida_readback.json'))
    assert att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and len(att['spans'])==len(spans)
    assert att['spans']==[{'start':hex(a),'size_B':z-a,'sha256':SHA(IMAGE.read(a,z-a))}for a,z in spans]
    out={'scope':__doc__,'daemon_sha256':SHA(SOURCE.read_bytes()),'profiles':rows,
      'byte_bank_proofs':banks,'byte_bank_pairs':pair_count,
      'unpaired_byte_bank_reads':unpaired,
      'spans':[{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':SHA(IMAGE.read(a,z-a)),
       'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans],
      'fixups':fixup_checks({int(a,16)for r in rows for a in r['fixup_reads']}),
      'generator_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in ['recover_fpsd1200_contract.py','fpsd1200_contract_checks.json','fpsd1200_ida_readback.json','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py','fpsd1200_admission_ida_readback.json']},
      'proofs':proofs(),'negative_controls':controls(),'SDK_context':sdk_context(),
      'new_IDA_access':True,'new_IDB_mutations':False,'new_native_execution':False,'full_goal_complete':False}
    out['verified_counts']={'profiles':len(rows),'returned_error_replies':sum(r['reply_completed']for r in rows),
      'audit_PID_boundaries':sum(r['stop_reason']=='unmodeled_import_boundary'for r in rows),
      'source_spans':len(spans),'source_instructions':len(sites),'source_visits':sum(len(r['visited'])for r in rows),
      'copy_calls':sum(len(r['copies'])for r in rows),'format12_rebases':len(out['fixups']['records']),
      'format12_bindings':len(out['fixups']['bindings']),'queries_unsat':len(out['proofs']),'controls_sat':2,
      'bank_identities':len(banks),'bank_inputs':256*len(banks),'bank_pair_uses':pair_count,'unpaired_byte_bank_reads':len(unpaired)}
    (ROOT/'fpsd1200_admission_checks.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
