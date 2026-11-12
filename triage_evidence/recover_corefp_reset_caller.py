#!/usr/bin/env python3
"""Continuous original reset caller and SystemVersion reader with private APIs.

CF objects/streams, string conversion, scanf, allocation, PAC and sequential
CASAL are declared models. No native target/API/file/IPC or IDB operation.
O(C*(B+P*F+V*J+R)) conservative time/space; 12000 source visits/profile.
"""
import json,re
from pathlib import Path
from hashlib import sha256
from unicorn import arm64_const as A
from recover_corefp_optional_reset import Run as Frozen,overlay as reset_overlay,DEPS as FROZEN_DEPS,BASE,REC,HEAP,DONE,ROOT,frame,pack
from recover_corefp_lookup_initialization import OUT,SP,inputs
from corefp_fixups_reader import Pointers,THIN_SHA
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();ENTRY=0x9a6454;CHILD=SP-0xc8;OUTPUT=SP-0x170
URL=HEAP+0x300;STREAM=HEAP+0x380;PLIST=HEAP+0x400;STRING=HEAP+0x440;CSTR=HEAP+0x480;BUFFER=HEAP+0x500
VERSION=0x1d444c8;PARENT_STATE=0x1d45f80
DEPS=FROZEN_DEPS+['recover_corefp_optional_reset.py']
POINTS={0x9a66e4:'version_call',0x316a98:'version_entry',0x316cc8:'cache_compare',0x9a66e8:'version_return',0x9aa700:'before_reset_record_store',
 0x9aa704:'after_reset_record_store',0x9aa74c:'reset_call',0x1f530c:'reset_entry',0x9aa750:'reset_return',0x9aaa4c:'caller_return'}


def configurations():
    rows=[('url_null',{}),('url_null_clobber',{'clobber_callers':True}),('stream_null',{'stage':'stream'}),
      ('open_false',{'stage':'open'}),('plist_null',{'stage':'plist'}),('key_null',{'stage':'key'}),
      ('cached_tuple',{'initial_version_u64':[17,8,9]}),
      ('cache_minor_zero',{'initial_version_u64':[17,0,9]}),('cache_patch_zero',{'initial_version_u64':[17,8,0]}),
      ('direct_three',{'stage':'parse'}),('direct_partial',{'stage':'parse','version_text':'26.0','initial_version_u64':[0,8,9]}),
      ('direct_invalid',{'stage':'parse','version_text':'bad','initial_version_u64':[0,8,9]}),
      ('copy_malloc_null',{'stage':'parse','string_route':'copy','malloc_success':False}),
      ('copy_false',{'stage':'parse','string_route':'copy','copy_success':False}),
      ('copy_three',{'stage':'parse','string_route':'copy'}),
      ('null_slot',{'selector_u8':1,'count_u32':1,'slot_kinds':['null']}),
      ('backed_slot_clobber',{'stage':'parse','selector_u8':1,'count_u32':1,'slot_kinds':['backed'],'clobber_callers':True,'void_free_x0':0xfeedfacecafebeef}),
      ('busy_token',{'token_u32':0xa94ef}),('raw_slot_frontier',{'selector_u8':1})]
    return [{'label':label,'stage':'url','string_route':'direct','version_text':'14.3.1','malloc_success':True,'copy_success':True,**extra}for label,extra in rows]


def overlay(c):
    rows=reset_overlay(c)
    key=((REC^0x341dc0b1)*0xdb676c6f)&0xffffffff
    record=(0x273ce6b83edff849).to_bytes(8,'little')+((0x84ee-key)&0xffffffff).to_bytes(4,'little')+bytes(20)
    rows.extend([(REC,record),(OUT,bytes(8)),(CSTR,c['version_text'].encode()+b'\0')])
    if 'initial_version_u64'in c:rows.append((BASE+VERSION,b''.join(v.to_bytes(8,'little')for v in c['initial_version_u64'])))
    return rows


def parsed(text):
    rest=text;values=[]
    for j in range(3):
        if j:
            if not rest.startswith('.'):break
            rest=rest[1:]
        m=re.match('[0-9]+',rest)
        if not m:break
        v=int(m[0]);assert v<(1<<64);values.append(v);rest=rest[len(m[0]):]
    return values


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c)
        for a,b in overlay(c):self.touch(a,len(b));self.u.mem_write(a,b)
        for a,n in [(BASE+VERSION,24),(BASE+PARENT_STATE,8),(CHILD,32),(OUTPUT,24),(HEAP+0x300,0x214)]:self.touch(a,n)
        for a in self.pages:self.pages[a]=bytes(self.u.mem_read(a,4096))
        self.u.reg_write(A.UC_ARM64_REG_X1,OUT);self.u.reg_write(A.UC_ARM64_REG_PC,BASE+ENTRY);self.initial=frame(self.u)
        self.caller_points=[];self.cf_live=set();self.cf_events=[];self.buffer_live=False;self.version_allocations=0
    def caller_snapshot(self,label):
        return {'label':label,'CPU':frame(self.u),'child_record32_hex':bytes(self.u.mem_read(CHILD,32)).hex(),
          'output24_hex':bytes(self.u.mem_read(OUTPUT,24)).hex(),'cursor8_hex':bytes(self.u.mem_read(OUT,8)).hex(),
          'version24_hex':bytes(self.u.mem_read(BASE+VERSION,24)).hex(),'parent_state8_hex':bytes(self.u.mem_read(BASE+PARENT_STATE,8)).hex()}
    def effect(self,e,a,b):
        self.touch(a,len(b));e['memory'].append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
    def code(self,u,pc,n,d):
        self.flush();c=self.c;name=self.imports.get(pc);call=self.reg('lr')-4-BASE if name else None
        if pc-BASE in POINTS:self.caller_points.append(self.caller_snapshot(POINTS[pc-BASE]))
        own=name and(name.startswith('_CF')or name=='_sscanf'or name=='_malloc'and call==0x317188 or name=='_free'and call==0x317398)
        if own:
            args=[self.reg('x'+str(j))for j in range(8)];e={'kind':'declared_API','name':name,'callsite':hex(call),'before':frame(u),'args_x0_x7':list(map(hex,args)),'memory':[]};self.models.append(e);value=0
            stages=['url','stream','open','plist','key','parse'];stage=stages.index(c['stage']);created=None
            if name=='_CFURLCreateFromFileSystemRepresentation':
                assert call==0x316de8 and args[:4]==[0,BASE+0x1669194,48,0];self.touch(args[1],48);e['path48_hex']=bytes(u.mem_read(args[1],48)).hex();value=URL if stage>0 else 0;created=value
            elif name=='_CFReadStreamCreateWithFile':assert call==0x1f9dfc and args[:2]==[0,URL]and URL in self.cf_live;value=STREAM if stage>1 else 0;created=value
            elif name=='_CFReadStreamOpen':assert args[0]==STREAM and STREAM in self.cf_live;value=int(stage>2)
            elif name=='_CFPropertyListCreateWithStream':assert call==0x1f9f84 and args[:6]==[0,STREAM,0,0,0,0]and STREAM in self.cf_live;value=PLIST if stage>3 else 0;created=value
            elif name=='_CFReadStreamClose':assert args[0]==STREAM and STREAM in self.cf_live
            elif name=='_CFDictionaryGetValue':assert call==0x316fa4 and args[:2]==[PLIST,BASE+0x1d1c288]and PLIST in self.cf_live;value=STRING if stage>4 else 0
            elif name=='_CFStringGetCStringPtr':assert args[:2]==[STRING,0x08000100];value=CSTR if c['string_route']=='direct'else 0
            elif name=='_malloc':
                assert args[0]==20 and not self.buffer_live and self.version_allocations==0;self.version_allocations+=1;value=BUFFER if c['malloc_success']else 0
                if value:self.buffer_live=True;self.effect(e,BUFFER,b'\xa5'*20)
            elif name=='_CFStringGetCString':
                assert call==0x317254 and args[:4]==[STRING,BUFFER,20,0x08000100]and self.buffer_live;value=int(c['copy_success'])
                if value:self.effect(e,BUFFER,c['version_text'].encode()+b'\0')
            elif name=='_sscanf':
                assert call in [0x317314,0x317410]and args[:2]==[BUFFER if c['string_route']=='copy'else CSTR,BASE+0x1685dc0]
                self.touch(args[1],15);e['format15_hex']=bytes(u.mem_read(args[1],15)).hex();e['input_cstr_hex']=bytes(u.mem_read(args[0],len(c['version_text'])+1)).hex()
                raw=bytes(u.mem_read(self.reg('sp'),24));e['variadic_stack24_hex']=raw.hex();dest=[int.from_bytes(raw[j:j+8],'little')for j in [0,8,16]]
                assert dest==[BASE+VERSION+8*j for j in range(3)];values=parsed(c['version_text'])
                for a,v in zip(dest,values):self.effect(e,a,v.to_bytes(8,'little'))
                value=len(values)
            elif name=='_free':assert args[0]==BUFFER and self.buffer_live;self.buffer_live=False;e['private_buffer20_hex']=bytes(u.mem_read(BUFFER,20)).hex();value=c.get('void_free_x0',0)
            elif name=='_CFRelease':
                assert args[0]in self.cf_live;self.cf_live.remove(args[0]);self.cf_events.append({'kind':'declared_release','pointer':hex(args[0]),'callsite':hex(call)});value=c.get('void_free_x0',0)
            else:raise AssertionError('unmodeled private CF API '+name)
            if created:self.cf_live.add(created);self.cf_events.append({'kind':'declared_create','pointer':hex(created),'callsite':hex(call)})
            e['return_u64']=hex(value);self.returned(value);e['after']=frame(u);return
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=12001);self.flush();assert hasattr(self,'frontier')and not self.cf_live and not self.buffer_live
        return {'configuration':self.c,'declared_overlay':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in overlay(self.c)],'initial_CPU':self.initial,
          'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'private_free_pointers':self.frees,'private_active_pointers':list(map(hex,sorted(self.active))),
          'caller_points':self.caller_points,'caller_final':self.caller_snapshot('frontier'),'CF_events':self.cf_events,'version_allocation_attempts':self.version_allocations}


def main():
    s=Pointers();runs=[Run(s,c)for c in configurations()];profiles=[r.run()for r in runs];spans={}
    for r in runs:spans.update(r.functions)
    fields=['visits','reads','writes','PAC_models','models','points','private_free_pointers','caller_points','CF_events']
    counts={'profiles':len(profiles),**{k:sum(len(p[k])for p in profiles)for k in fields},'version_allocation_attempts':sum(p['version_allocation_attempts']for p in profiles)}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},
      'source_spans':list(spans.values()),'base_declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()], 'profiles':profiles,'verified_counts':counts,
      'native_target_executed':False,'native_API_executed':False,'native_file_read':False,'IDB_mutated':False,'source_PC_gap':False,'child_record_patched':False,'full_goal_complete':False}
    (ROOT/'corefp_reset_caller_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
