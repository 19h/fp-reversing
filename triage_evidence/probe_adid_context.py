#!/usr/bin/env python3
"""Follow original ADID context records and payload-error production.

Extends the frozen request engine; no native target/API/IPC/file operation.
Only original source stores, bounded private record snapshots and declared
fixture continuations are retained. O(C*(B+F+K)) time, O(B+F+C*K) space.
"""
import json
from pathlib import Path
import struct
import plistlib
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_requests import Request
from probe_adid_startup import unpack_records,HEAP
from probe_adid_receiver import DONE
from unicorn import arm64_const as A


class Context(Request):
    def __init__(self,s,f,checkpoint):
        super().__init__(s,f,checkpoint);self.context_record=None;self.bridge_record=None;self.context_cf_cursor=HEAP+0x1a000;self.context_strings={};self.previous_status_register=self.reg('w5');self.previous_pc=None
    def cf_value(self,value):
        ptr=self.context_cf_cursor;self.context_cf_cursor+=64
        if self.context_cf_cursor>HEAP+0x1e000:raise ValueError('context_CF_extent_guard')
        kind='plist_dictionary' if isinstance(value,dict) else 'plist_string' if isinstance(value,str) else 'plist_number' if isinstance(value,int) and not isinstance(value,bool) else 'plist_other'
        self.cf_objects[ptr]={'kind':kind,'value':value};return ptr
    def api(self,im):
        name=im['name'];args=[self.reg('x'+str(i)) for i in range(8)]
        if name=='_CFNumberGetValue' and self.cf_objects.get(args[0],{}).get('kind')=='plist_number':
            value=self.cf_objects[args[0]]['value'];e={'kind':'context_number_conversion_boundary','name':name,'callsite':hex(self.reg('lr')-4),'args_x0_x7':[hex(v) for v in args],'number':value,'initial_output_u32':struct.unpack('<I',self.u.mem_read(args[2],4))[0],'native_API_executed':False};self.records.append(e)
            if not self.fixture.get('model_plist_number'):return self.stop('context_number_conversion_boundary')
            if args[1]!=3 or not -(1<<31)<=value<(1<<31):return self.stop('context_number_width_guard')
            success=self.fixture.get('plist_number_success',True);written=success or self.fixture.get('plist_number_write_on_false',False)
            if written:self.u.mem_write(args[2],struct.pack('<i',value))
            e.update({'kind':'context_modeled_API','result':hex(int(success)),'conversion_output_written':written});return self.finish_api(int(success))
        if name=='_read' and self.fixture.get('file_reads_from_model'):
            fd=struct.unpack('<i',struct.pack('<I',args[0]&0xffffffff))[0];path=self.fds.get(fd);meta=self.fs.get(path,{})
            e={'kind':'context_modeled_API','name':name,'callsite':hex(self.reg('lr')-4),'fd_signed32':fd,'path':path,'requested_bytes':args[2],'native_API_executed':False};self.records.append(e)
            if 'contents_hex' not in meta or args[2]>65536:return self.stop('context_read_shape_guard')
            raw=bytes.fromhex(meta['contents_hex']);off=self.fd_offsets[fd]
            if off>len(raw):return self.stop('context_read_offset_guard')
            raw=raw[off:off+args[2]];self.u.mem_write(args[1],raw) if raw else None;self.fd_offsets[fd]+=len(raw);e.update({'bytes':raw.hex(),'result':hex(len(raw))});return self.finish_api(len(raw))
        cf_type=name=='_CFGetTypeID' and args[0] in self.cf_objects and self.cf_objects[args[0]]['kind'].startswith('plist_')
        if name in ('_CFDataCreateWithBytesNoCopy','_CFPropertyListCreateWithData','_CFDictionaryGetTypeID','_CFDictionaryGetValue') and name in self.fixture.get('model_APIs',[]) or cf_type:
            e={'kind':'context_modeled_API','name':name,'callsite':hex(self.reg('lr')-4),'args_x0_x7':[hex(v) for v in args],'native_API_executed':False};self.records.append(e)
            if name=='_CFDataCreateWithBytesNoCopy':
                if args[2]>65536:return self.stop('context_CFData_extent_guard')
                raw=bytes(self.u.mem_read(args[1],args[2]));e.update({'data_bytes':raw.hex(),'deallocator_pointer':hex(args[3])});result=self.context_cf_cursor;self.context_cf_cursor+=64;self.cf_objects[result]={'kind':'context_data','bytes_hex':raw.hex(),'source_pointer':hex(args[1])}
            elif name=='_CFPropertyListCreateWithData':
                if args[1] not in self.cf_objects or self.cf_objects[args[1]]['kind']!='context_data' or args[2]!=0:return self.stop('context_plist_shape_guard')
                if args[3]:self.u.mem_write(args[3],struct.pack('<q',100))
                if args[4]:self.u.mem_write(args[4],struct.pack('<Q',0))
                raw=bytes.fromhex(self.cf_objects[args[1]]['bytes_hex']);result=0
                if self.fixture.get('plist_result')=='dictionary':
                    try:parsed=plistlib.loads(raw)
                    except (plistlib.InvalidFileException,ValueError):e['analyst_parser_failure']=True
                    else:result=self.cf_value(parsed);e['analyst_parser_value']=parsed
                e['data_bytes']=raw.hex();e['parser_scope']='Explicit fixture; Python plistlib is not native CFPropertyList.'
            elif name=='_CFDictionaryGetTypeID':result=0x41f3
            elif name=='_CFGetTypeID':result={'plist_dictionary':0x41f3,'plist_string':0x41f2,'plist_number':0x41f0}.get(self.cf_objects[args[0]]['kind'],0x41f9)
            else:
                obj=self.cf_objects.get(args[0],{})
                if obj.get('kind')!='plist_dictionary':return self.stop('context_dictionary_shape_guard')
                if args[1] in self.context_strings:key=self.context_strings[args[1]]
                else:
                    try:key=self.s.cstring(self.s.qword(args[1]+16))
                    except Exception:return self.stop('context_dictionary_unknown_key_guard')
                e['key_string']=key;value=obj['value'].get(key);result=0 if value is None else self.cf_value(value)
            e['result']=hex(result);return self.finish_api(result)
        if name=='_CFStringCreateWithCStringNoCopy':
            value=self.string(args[1]);result=super().api(im)
            if not self.reason:self.context_strings[self.reg('x0')]=value
            return result
        return super().api(im)
    def registers(self):return {r:hex(self.reg(r)) for r in ['x'+str(i) for i in range(29)]+['sp','lr']}
    def write(self,u,access,address,size,value,data):
        super().write(u,access,address,size,value,data)
        if self.reason:return
        if ((0x7e000460<=address<0x7e000470) or (0x7e00c930<=address<0x7e00c940) or (self.sp-0x4a8<=address<self.sp-0x468) or (address<=0x7a03082f<address+size) or (address<=0x7a02faac<address+size) or (address<=0x7a02fa4c<address+size) or self.reg('pc') in (0x1002028a8,0x1002028bc,0x1002028c4,0x1002028d0,0x1001fcca8) or (size>=4 and (value&0xffffffff) in (0xffff501f,0x1f50ffff,45025,0xffff4ff2,248))) or (self.context_record and self.context_record<=address<self.context_record+64):
            self.records.append({'kind':'original_context_store','pc':hex(self.reg('pc')),'address':hex(address),'size_bytes':size,'value':hex(value&((1<<(8*size))-1)),'registers':self.registers()})
    def code(self,u,pc,n,data):
        value=self.reg('w5')
        if value!=self.previous_status_register and (value in (0x58748a,0x5874ae,0x59248f) or self.previous_status_register in (0x58748a,0x5874ae,0x59248f)):
            self.records.append({'kind':'original_status_register_change','preceding_pc':hex(self.previous_pc) if self.previous_pc is not None else None,'observed_before_pc':hex(pc),'before_u32':self.previous_status_register,'after_u32':value,'registers':self.registers()})
        self.previous_status_register=value;self.previous_pc=pc
        if pc==0x1001459b0:self.bridge_record=self.reg('x0')
        if pc==0x100104e90:self.context_record=self.reg('x0')
        if pc in (0x1001459b0,0x100104e90,0x100124840,0x100145be4,0x1001bfd64,0x1001bfda0,0x10019bb18,0x10021ab98,0x10021abe8,0x10021ac64,0x10021b8cc,0x1001ca3bc,0x1001ca3fc,0x1001ca424,0x10016a800,0x10021b8d0,0x1001af170,0x10019bde0,0x10019be08):
            e={'kind':'original_context_boundary','pc':hex(pc),'registers':self.registers()}
            if pc in (0x10019bb18,0x10021ab98,0x10021abe8,0x10021ac64,0x10021b8cc):
                sp=self.reg('sp');e['core_stack_fields']={hex(off):bytes(self.u.mem_read(sp+off,n)).hex() for off,n in [(0x12c,4),(0x1634,4),(0x1e9c,4),(0x2c1f,1),(0x3a1c,4)]}
            for k,ptr in [('bridge_record',self.bridge_record),('context_record',self.context_record)]:
                if ptr:e[k]={'address':hex(ptr),'bytes64':bytes(self.u.mem_read(ptr,64)).hex()}
            if pc==0x100104e90:
                raw=bytes(self.u.mem_read(self.context_record,64));value,pointer=struct.unpack_from('<QQ',raw,16)
                mapped=any(a<=pointer and pointer+32<=z+1 for a,z,_ in self.u.mem_regions())
                e['observed_fields16_24']={'opaque_value_u64':value,'pointer_bits':hex(pointer),'observation32_bytes':bytes(self.u.mem_read(pointer,32)).hex() if mapped else None,'observation_address_mapped':mapped,'semantic_type_established':False}
            self.records.append(e)
        return super().code(u,pc,n,data)


def main():
    s=Adid();checkpoint=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());p=json.loads((ROOT/'adid_request_profiles.json').read_text());source=next(r['fixture'] for r in p['profiles'] if r['fixture']['label']=='setup_selector_-8_status_0')
    fixtures=[{**source,'label':'context_error_producer'}]
    for opcode in (0,2,3,4,5,6,7,8):
        f=json.loads(json.dumps(source));f['label']='header_word2_'+str(opcode);f['payload_hex']=struct.pack('>IIIqQ',1,0x632b8d6e,opcode,-8,0).hex();fixtures.append(f)
    for selector in (-8,-6,-5,-4,-3,-2):
        f=json.loads(json.dumps(source));f['label']='header_word2_zero_selector_'+str(selector);f['selector_signed64']=selector;f['payload_hex']=struct.pack('>IIIqQ',1,0x632b8d6e,0,selector,0).hex();fixtures.append(f)
    for first,magic in [(0,0x632b8d6e),(2,0x632b8d6e),(0xffffffff,0x632b8d6e),(1,0),(1,0x632b8d6f)]:
        f=json.loads(json.dumps(source));f['label']=f'header_word0_{first}_magic_{magic:08x}';f['payload_hex']=struct.pack('>IIIqQ',first,magic,1,-8,0).hex();fixtures.append(f)
    for uid in (265,501):
        for db,setup in [(0,0),(-1,0),(-1,-1)]:
            f=json.loads(json.dumps(source));f['label']=f'nonroot_{uid}_markers_{db}_{setup}';f['audit_euid_result']=uid
            f['audit_words'][1]=uid
            f['extra_filesystem']['/var/setup/.AppleSetupUser']={'mode':0o100600,'uid':0,'gid':0,'size':0,'excluded':False}
            f['stat_path_status']={'/var/db/.AppleSetupUser':db,'/var/setup/.AppleSetupUser':setup};fixtures.append(f)
    for uid in (265,501):
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']==f'nonroot_{uid}_markers_-1_-1');f['label']=f'nonroot_ready_record_{uid}'
        f['extra_filesystem'][f'/Users/Shared/adi/adi-{uid:08X}.pb']={'mode':0o100666,'uid':uid,'gid':uid,'size':0,'contents_hex':'','excluded':False};fixtures.append(f)
    for db,setup,path in [(0,0,'/var/db'),(-1,0,'/var/setup')]:
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']==f'nonroot_501_markers_{db}_{setup}');f['label']='nonroot_setup_parent_'+path.rsplit('/',1)[-1]
        f['extra_filesystem'][path]={'mode':0o40755,'uid':0,'gid':0,'size':0,'excluded':False};fixtures.append(f)
    for label in ('nonroot_setup_parent_db','nonroot_setup_parent_setup'):
        for stage in ('data','parse_failure','empty_dictionary'):
            f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']==label);f['label']=label+'_'+stage;f['model_APIs']+=['_CFDataCreateWithBytesNoCopy']
            if stage!='data':f['model_APIs']+=['_CFPropertyListCreateWithData']
            if stage=='empty_dictionary':
                raw=plistlib.dumps({},fmt=plistlib.FMT_XML);path='/var/db/.AppleSetupUser' if label.endswith('_db') else '/var/setup/.AppleSetupUser';f['extra_filesystem'][path].update({'size':len(raw),'contents_hex':raw.hex()});f['file_reads_from_model']=True;f['plist_result']='dictionary';f['model_APIs']+=['_CFDictionaryGetTypeID','_CFDictionaryGetValue']
            fixtures.append(f)
    for value in (265,501,-1,0,'501',True):
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='nonroot_setup_parent_db_empty_dictionary');raw=plistlib.dumps({'kBuddingRunningForUID':value},fmt=plistlib.FMT_XML)
        f['label']='setup_uid_'+str(value)+'_'+type(value).__name__;f['extra_filesystem']['/var/db/.AppleSetupUser'].update({'size':len(raw),'contents_hex':raw.hex()});fixtures.append(f)
    for value in (265,501,-1,0):
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']==f'setup_uid_{value}_int');f['label']='setup_uid_modeled_'+str(value);f['model_plist_number']=True;fixtures.append(f)
    f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='setup_uid_modeled_501');f['label']='setup_uid_conversion_false_unchanged_output';f['plist_number_success']=False;fixtures.append(f)
    f=json.loads(json.dumps(f));f['label']='setup_uid_conversion_false_written_output';f['plist_number_write_on_false']=True;fixtures.append(f)
    for value,uid in [(501,501),(0,248),(-1,0xffffffff)]:
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='setup_uid_modeled_'+str(value));f['label']='setup_uid_ready_'+str(value)
        f['extra_filesystem'][f'/Users/Shared/adi/adi-{uid:08X}.pb']={'mode':0o100666,'uid':uid,'gid':uid,'size':0,'contents_hex':'','excluded':False};fixtures.append(f)
    for label,contents in [('seed_bytes',None),('empty_plist',plistlib.dumps({},fmt=plistlib.FMT_XML))]:
        f=json.loads(json.dumps(source));f['label']='root_record_read_'+label;f['initial_errno']=0;f['file_reads_from_model']=True;f['model_APIs']+=['_CFDataCreateWithBytesNoCopy','_CFPropertyListCreateWithData','_CFDictionaryGetTypeID','_CFDictionaryGetValue'];f['plist_result']='dictionary'
        if contents is not None:f['extra_filesystem']['/var/db/fpsd/adi/adi.pb']={'mode':0o100666,'uid':265,'gid':265,'size':len(contents),'contents_hex':contents.hex(),'excluded':False}
        fixtures.append(f)
    for value in json.loads((ROOT/'adid_receiver_contracts.json').read_text())['classifier']['listed_values_under_XOR_u32']:
        f=json.loads(json.dumps(source));f['label']='full_context_entitlement_'+hex(value);f['entitlement_number']=value;fixtures.append(f)
    rows=[];functions={};instructions={}
    for f in fixtures:
        probe=Context(s,f,checkpoint);r=probe.run_continuation();r['lock_model_final']=probe.lock_models;r['umask_model_final']=probe.umask_value
        for v in r.pop('original_functions'):functions[v['start']]=v
        for v in r.pop('instruction_records'):instructions[v['ea']]=v
        rows.append(r);e=unpack_records(r);print(json.dumps({'label':f['label'],'stop':r['stop_reason'],'steps':r['steps'],'reply_data':[v.get('payload_bytes') for v in e if v.get('name')=='_xpc_dictionary_set_data'],'last':e[-1] if e else None}),flush=True)
    probe=Context(s,{**source,'label':'retained_state_request_0'},checkpoint)
    for index in range(3):
        if index:
            probe.fixture={**source,'label':'retained_state_request_'+str(index),'retained_all_private_memory':True,'sequence_index':index}
            probe.steps=0;probe.reason=None;probe.records=[];probe.visited=[];probe.last_edge=None;probe.context_record=None;probe.bridge_record=None
            probe.u.reg_write(A.UC_ARM64_REG_SP,probe.sp);probe.u.reg_write(A.UC_ARM64_REG_LR,DONE);probe.u.reg_write(A.UC_ARM64_REG_PC,0x100029fc8)
            for j in range(8):probe.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),[HEAP+0x300,HEAP+0xd100][j] if j<2 else 0)
            probe.previous_status_register=probe.reg('w5');probe.previous_pc=None
        r=probe.run_continuation();r['lock_model_final']=json.loads(json.dumps(probe.lock_models));r['umask_model_final']=probe.umask_value
        # Snapshot mutable output dictionaries before the next request runs.
        r['filesystem_model_final']=json.loads(json.dumps(r['filesystem_model_final']));r['open_descriptors_final']=json.loads(json.dumps(r['open_descriptors_final']))
        for v in r.pop('original_functions'):functions[v['start']]=v
        for v in r.pop('instruction_records'):instructions[v['ea']]=v
        rows.append(r);print(json.dumps({'label':r['fixture']['label'],'stop':r['stop_reason'],'steps':r['steps'],'reply_data':[v.get('payload_bytes') for v in unpack_records(r) if v.get('name')=='_xpc_dictionary_set_data']}),flush=True)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_receiver.py','probe_adid_startup.py','probe_adid_requests.py','adid_request_profiles.json','adid_peer_checkpoint.json','adid_receiver_contracts.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_context_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
