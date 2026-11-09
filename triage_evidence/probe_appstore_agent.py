#!/usr/bin/env python3
"""Finite private original-byte receiver policy probes; no native target call.

Only four original functions and explicitly identified API stubs may execute.
PAC instructions are bypassed. ObjC, entitlement, account and logging results
are explicit fixture values. No task, port, file, account or entitlement query
is issued to the host. O(cases * instruction_budget) time and O(image) space.
"""
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_LR,UC_ARM64_REG_PC,UC_ARM64_REG_SP
from appstore_agent_reader import Agent,ROOT,THIN_SHA,CS,sha

STACK=0x70000000
HEAP=0x71000000
DONE=0x72000000
MASK=(1<<64)-1


class Probe:
    def __init__(self,fixture):
        self.s=Agent();self.fixture=fixture;self.records=[];self.visited=[];self.steps=0;self.reason=None
        self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for seg in self.s.meta['segments']:
            if not seg['vm_size'] or seg['name']=='__PAGEZERO':continue
            self.u.mem_map(seg['address'],(seg['vm_size']+4095)&~4095)
            if seg['file_size']:self.u.mem_write(seg['address'],self.s.data[seg['file_offset']:seg['file_offset']+seg['file_size']])
        self.u.mem_map(STACK,0x10000);self.u.mem_map(HEAP,0x10000);self.u.mem_map(DONE,4096)
        self.u.reg_write(UC_ARM64_REG_SP,STACK+0xf000);self.u.reg_write(UC_ARM64_REG_LR,DONE)
        contracts=json.loads((ROOT/'appstore_agent_contracts.json').read_text())
        self.stubs={int(x['address'],16):x for x in contracts['stubs']}
        self.allowed={}
        for a in [0x100125684,0x1001285b0,0x10012880c,0x10004c20c]:
            ix=self.s.starts.index(a);z=self.s.starts[ix+1]
            self.allowed.update({i.address:(i.mnemonic,i.op_str) for i in CS.disasm(self.s.read(a,z-a),a)})
        self.u.hook_add(UC_HOOK_CODE,self.hook)
        self.writeq(HEAP+8,HEAP+0x100 if fixture.get('array_present',True) else 0)
        self.writeq(HEAP+16,HEAP+0x200 if fixture.get('task_present',True) else 0)
        self.u.mem_write(HEAP+24,struct.pack('<I',4242))
        self.writeq(HEAP+0x10a8,HEAP+0x2000)

    def reg(self,n):return self.u.reg_read(UC_ARM64_REG_X0+n)
    def writeq(self,a,v):self.u.mem_write(a,struct.pack('<Q',v))
    def ret(self,value):
        self.u.reg_write(UC_ARM64_REG_X0,value&MASK)
        self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))
    def stop(self,why):self.reason=why;self.u.emu_stop()

    def hook(self,u,pc,size,data):
        self.steps+=1
        if self.steps>3000:return self.stop('instruction_budget_guard')
        if pc==DONE:return self.stop('returned_to_private_fixture')
        if pc in self.stubs:
            st=self.stubs[pc];binding=st.get('binding',{}).get('target');sel=st.get('selector');x=[self.reg(j) for j in range(4)]
            event={'pc':hex(pc),'symbol':binding,'selector':sel,'args':[hex(v) for v in x]};result=None
            if binding in ('libobjc/_objc_retain','libobjc/_objc_claimAutoreleasedReturnValue','libobjc/_objc_retainAutorelease','libobjc/_objc_opt_self'):
                result=x[0]
            elif binding in ('libobjc/_objc_release','CoreFoundation/_CFRelease'):
                result=0
            elif binding=='AppStoreDaemon/_ASDLogHandleForCategory':result=HEAP+0x9000
            elif binding=='libSystem/_os_log_type_enabled':result=0
            elif sel=='containsObject:':
                assert x[0] in (0,HEAP+0x100) and x[2]==HEAP+0x300
                result=int(bool(x[0]) and self.fixture.get('array_contains',False))
            elif binding=='Security/_SecTaskCopyValueForEntitlement':
                assert x[0]==HEAP+0x200 and x[1]==HEAP+0x400
                self.writeq(x[2],HEAP+0x600 if self.fixture.get('query_error',False) else 0)
                result=HEAP+0x500 if self.fixture.get('entitlement_value') is not None else 0
                event['error_slot_written']=self.fixture.get('query_error',False)
            elif binding=='CoreFoundation/_CFBooleanGetTypeID':result=11
            elif binding=='CoreFoundation/_CFGetTypeID':
                assert x[0]==HEAP+0x500
                result=11 if isinstance(self.fixture.get('entitlement_value'),bool) else 22
            elif binding=='CoreFoundation/_CFBooleanGetValue':
                assert isinstance(self.fixture.get('entitlement_value'),bool)
                result=int(self.fixture['entitlement_value'])
            elif sel=='ams_sharedAccountStore':result=HEAP+0x8000
            elif sel=='ams_activeiTunesAccount':result=HEAP+0x8100 if self.fixture.get('active_account',True) else 0
            elif sel=='isArcadeApp':
                assert x[0]==HEAP+0x2000
                result=int(self.fixture.get('arcade_app',True))
            elif binding=='libSystem/_os_variant_allows_internal_security_policies':result=0
            elif sel=='fairplayStatus':result=self.fixture['status_u32']&0xffffffff
            if result is None:
                self.records.append(event);return self.stop('unmodeled_API_guard')
            event['modeled_result']=hex(result);self.records.append(event);return self.ret(result)
        if pc not in self.allowed:return self.stop('unapproved_original_function_guard:'+hex(pc))
        self.visited.append(pc);m,ops=self.allowed[pc]
        if m in ('pacibsp','autibsp'):
            self.u.reg_write(UC_ARM64_REG_PC,pc+4)
        elif m in ('retab','retaa'):
            self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))

    def run(self):
        f=self.fixture
        if f['mode']=='gate':
            entry=0x100125684;args=[0 if f.get('context_null') else HEAP,HEAP+0x300,HEAP+0x400 if f.get('alternate_key') else 0]
        else:
            entry=0x1001285b0;args=[HEAP+0x7000,0,HEAP+0x1000,HEAP+0x3000,HEAP+0x4000]
        for j,v in enumerate(args):self.u.reg_write(UC_ARM64_REG_X0+j,v)
        try:self.u.emu_start(entry,DONE+4,count=3001)
        except Exception as e:self.reason='private_emulator_exception:'+str(e)
        h=hashlib.sha256()
        for pc in self.visited:h.update(struct.pack('<Q',pc));h.update(self.s.read(pc,4))
        return {'fixture':f,'stop_reason':self.reason,'result_u32':self.reg(0)&0xffffffff,'steps':self.steps,
            'expected_u32':f['expected_u32'],'matches_expected':self.reg(0)&0xffffffff==f['expected_u32'],
            'original_instruction_visits':len(self.visited),'original_instruction_bytes_sha256':h.hexdigest(),
            'visited_original_instructions':[hex(x) for x in self.visited],'API_records':self.records}


def main():
    fixtures=[]
    def add(label,expected,**f):fixtures.append({'label':label,'mode':'gate','expected_u32':expected,**f})
    add('repair_token_present',1,array_contains=True)
    add('repair_token_missing',0,array_contains=False)
    add('capability_array_absent',0,array_present=False,array_contains=True)
    add('context_absent',0,context_null=True,array_contains=True)
    add('alternate_boolean_true',1,alternate_key=True,entitlement_value=True)
    add('alternate_boolean_false',0,alternate_key=True,entitlement_value=False)
    add('alternate_non_boolean',0,alternate_key=True,entitlement_value='true')
    add('alternate_value_absent',0,alternate_key=True,entitlement_value=None)
    add('alternate_task_absent',0,alternate_key=True,task_present=False,entitlement_value=True)
    add('token_short_circuits_alternate_query',1,array_contains=True,alternate_key=True,entitlement_value=False)
    add('query_error_and_value_absent',0,alternate_key=True,entitlement_value=None,query_error=True)
    add('query_error_and_boolean_true',1,alternate_key=True,entitlement_value=True,query_error=True)
    accepted=[(-0xa65b)&0xffffffff,(-0xa659)&0xffffffff,(-0xa658)&0xffffffff,(-0xa47e)&0xffffffff,(-0xa480)&0xffffffff]
    statuses=accepted+[(-0xa65a)&0xffffffff,(-0xa65c)&0xffffffff,(-0xa657)&0xffffffff,(-42352)&0xffffffff,0,0xffffffff]
    for status in statuses:
        fixtures.append({'label':f'arcade_active_status_{status:08x}','mode':'arcade','expected_u32':int(status in accepted),
            'status_u32':status,'active_account':True,'arcade_app':True})
    fixtures.append({'label':'arcade_no_active_account_daemon_repair_status','mode':'arcade','expected_u32':1,
        'status_u32':(-42352)&0xffffffff,'active_account':False,'arcade_app':True})
    fixtures.append({'label':'non_arcade_no_account','mode':'arcade','expected_u32':0,'status_u32':accepted[0],
        'active_account':False,'arcade_app':False})
    rows=[Probe(f).run() for f in fixtures]
    out={'scope':__doc__,'source_sha256':THIN_SHA,'generator_sha256':sha(Path(__file__).read_bytes()),
        'source_contracts_sha256':sha((ROOT/'appstore_agent_contracts.json').read_bytes()),'profiles':rows,
        'native_target_executed':False,'native_peer_entitlements_observed':False,'hardware_PAC_checked':False,
        'logging_enabled_paths_executed':False,'full_goal_complete':False}
    (ROOT/'appstore_agent_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    assert all(x['matches_expected'] and x['stop_reason']=='returned_to_private_fixture' for x in rows),[(x['fixture']['label'],x['stop_reason'],x['result_u32']) for x in rows]
    print(json.dumps({'cases':len(rows),'all_expected':True,'native_target_executed':False}))


if __name__=='__main__':main()
