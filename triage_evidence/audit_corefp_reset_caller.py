#!/usr/bin/env python3
"""Independent continuous caller replay, CF/scanf effects and record oracles.

Does not import this increment's producer. O(C*(B+P*F+V*J+R)+256*K)
conservative time/space; 12000 visits/profile, 30 s/SMT query. No native
target/API/file/IPC or IDB operation. Frozen reset contracts are rechecked.
"""
import copy,json,struct,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_corefp_optional_reset import Replay as Frozen,source_checks as reset_source,initial_page,declared_inputs,frame,restore,unpack,ret,CS
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M32=(1<<32)-1;M64=(1<<64)-1
ENTRY=0x9a6454;REC=0x63000100;OUT=0x63000300;HEAP=0x64000000;DONE=0x65000000;SP=0x62018000
CHILD=0x62017f38;OUTPUT=0x62017e90;VERSION=0x1d444c8;STATE=0x1d45f80
URL=HEAP+0x300;STREAM=HEAP+0x380;PLIST=HEAP+0x400;STRING=HEAP+0x440;CSTR=HEAP+0x480;BUFFER=HEAP+0x500
POINTS={0x9a66e4:'version_call',0x316a98:'version_entry',0x316cc8:'cache_compare',0x9a66e8:'version_return',0x9aa700:'before_reset_record_store',
 0x9aa704:'after_reset_record_store',0x9aa74c:'reset_call',0x1f530c:'reset_entry',0x9aa750:'reset_return',0x9aaa4c:'caller_return'}


def expected_config(label):
    rows={'url_null':{},'url_null_clobber':{'clobber_callers':True},'stream_null':{'stage':'stream'},'open_false':{'stage':'open'},
      'plist_null':{'stage':'plist'},'key_null':{'stage':'key'},'cached_tuple':{'initial_version_u64':[17,8,9]},
      'cache_minor_zero':{'initial_version_u64':[17,0,9]},'cache_patch_zero':{'initial_version_u64':[17,8,0]},
      'direct_three':{'stage':'parse'},'direct_partial':{'stage':'parse','version_text':'26.0','initial_version_u64':[0,8,9]},
      'direct_invalid':{'stage':'parse','version_text':'bad','initial_version_u64':[0,8,9]},
      'copy_malloc_null':{'stage':'parse','string_route':'copy','malloc_success':False},
      'copy_false':{'stage':'parse','string_route':'copy','copy_success':False},'copy_three':{'stage':'parse','string_route':'copy'},
      'null_slot':{'selector_u8':1,'count_u32':1,'slot_kinds':['null']},
      'backed_slot_clobber':{'stage':'parse','selector_u8':1,'count_u32':1,'slot_kinds':['backed'],'clobber_callers':True,'void_free_x0':0xfeedfacecafebeef},
      'busy_token':{'token_u32':0xa94ef},'raw_slot_frontier':{'selector_u8':1}}
    return {'label':label,'stage':'url','string_route':'direct','version_text':'14.3.1','malloc_success':True,'copy_success':True,**rows[label]}


def overlay(c):
    p=REC&M32;pre=(((p|0x89102e99)-(p&0x89102e99))^0xbd0dee28)*0xdb676c6f&M32;rows=[(REC,struct.pack('<I',pre^0xf7a5))]
    for name,a,n in [('selector_u8',0x1d44409,1),('count_u32',0x1d36090,4),('token_u32',0x1d33108,4)]:
        if name in c:rows.append((BASE+a,c[name].to_bytes(n,'little')))
    for j,kind in enumerate(c.get('slot_kinds',[])):
        ptr=HEAP+256+128*j if kind=='backed'else 0;b=bytearray([49+j]*88);struct.pack_into('<Q',b,8,ptr);rows.append((BASE+0x1d32dd0+88*j,bytes(b)))
        if ptr:rows.append((ptr,bytes([83+j])*64))
    key=((p^0x341dc0b1)*0xdb676c6f)&M32;record=struct.pack('<QI',0x273ce6b83edff849,(0x84ee-key)&M32)+bytes(20)
    rows.extend([(REC,record),(OUT,bytes(8)),(CSTR,c['version_text'].encode()+b'\0')])
    if 'initial_version_u64'in c:rows.append((BASE+VERSION,struct.pack('<3Q',*c['initial_version_u64'])))
    return rows


def caller_snapshot(r,label):
    return {'label':label,'CPU':frame(r.u),'child_record32_hex':r.ram(CHILD,32).hex(),'output24_hex':r.ram(OUTPUT,24).hex(),
      'cursor8_hex':r.ram(OUT,8).hex(),'version24_hex':r.ram(BASE+VERSION,24).hex(),'parent_state8_hex':r.ram(BASE+STATE,8).hex()}


class Replay(Frozen):
    def __init__(self,*args):
        super().__init__(*args);self.ci=0;self.cf_live=set();self.ce=[];self.buffer_live=False;self.va=0
    def code(self,u,pc,n,d):
        self.flush();cfg=self.p['configuration'];name=self.imports.get(pc);call=u.reg_read(A.UC_ARM64_REG_LR)-4-BASE if name else None
        if pc-BASE in POINTS:assert self.p['caller_points'][self.ci]==caller_snapshot(self,POINTS[pc-BASE]);self.ci+=1
        own=name and(name.startswith('_CF')or name=='_sscanf'or name=='_malloc'and call==0x317188 or name=='_free'and call==0x317398)
        if own:
            args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)];e=self.event()
            assert e['kind']=='declared_API'and e['name']==name and e['callsite']==hex(call)and e['args_x0_x7']==list(map(hex,args))
            level={'url':0,'stream':1,'open':2,'plist':3,'key':4,'parse':5}[cfg['stage']];v=0;writes=[];created=0
            if name=='_CFURLCreateFromFileSystemRepresentation':
                assert call==0x316de8 and args[:4]==[0,BASE+0x1669194,48,0]and e['path48_hex']==self.ram(args[1],48).hex()
                assert self.ram(args[1],48)==b'/System/Library/CoreServices/SystemVersion.plist';v=URL if level>=1 else 0;created=v
            elif name=='_CFReadStreamCreateWithFile':assert call==0x1f9dfc and args[:2]==[0,URL]and URL in self.cf_live;v=STREAM if level>=2 else 0;created=v
            elif name=='_CFReadStreamOpen':assert call==0x1f9ec0 and args[0]==STREAM and STREAM in self.cf_live;v=int(level>=3)
            elif name=='_CFPropertyListCreateWithStream':assert call==0x1f9f84 and args[:6]==[0,STREAM,0,0,0,0]and STREAM in self.cf_live;v=PLIST if level>=4 else 0;created=v
            elif name=='_CFReadStreamClose':assert call==0x1fa008 and args[0]==STREAM and STREAM in self.cf_live
            elif name=='_CFDictionaryGetValue':assert call==0x316fa4 and args[:2]==[PLIST,BASE+0x1d1c288]and PLIST in self.cf_live;v=STRING if level>=5 else 0
            elif name=='_CFStringGetCStringPtr':assert call==0x317098 and args[:2]==[STRING,0x08000100];v=CSTR if cfg['string_route']=='direct'else 0
            elif name=='_malloc':
                assert call==0x317188 and args[0]==20 and self.va==0 and not self.buffer_live;self.va+=1;v=BUFFER if cfg['malloc_success']else 0
                if v:self.buffer_live=True;writes=[(BUFFER,b'\xa5'*20)]
            elif name=='_CFStringGetCString':
                assert call==0x317254 and args[:4]==[STRING,BUFFER,20,0x08000100]and self.buffer_live;v=int(cfg['copy_success'])
                if v:writes=[(BUFFER,cfg['version_text'].encode()+b'\0')]
            elif name=='_sscanf':
                assert call==(0x317314 if cfg['string_route']=='copy'else 0x317410)and args[:2]==[BUFFER if cfg['string_route']=='copy'else CSTR,BASE+0x1685dc0]
                assert e['format15_hex']==self.ram(args[1],15).hex()and self.ram(args[1],15)==b'%llu.%llu.%llu\0'
                assert e['input_cstr_hex']==self.ram(args[0],len(cfg['version_text'])+1).hex()==(cfg['version_text'].encode()+b'\0').hex()
                stack=self.ram(u.reg_read(A.UC_ARM64_REG_SP),24);assert e['variadic_stack24_hex']==stack.hex()
                assert list(struct.unpack('<3Q',stack))==[BASE+VERSION+j*8 for j in range(3)]
                values={'14.3.1':[14,3,1],'26.0':[26,0],'bad':[]}[cfg['version_text']];v=len(values);writes=[(BASE+VERSION+8*j,struct.pack('<Q',x))for j,x in enumerate(values)]
            elif name=='_free':assert call==0x317398 and args[0]==BUFFER and self.buffer_live;assert e['private_buffer20_hex']==self.ram(BUFFER,20).hex();self.buffer_live=False;v=cfg.get('void_free_x0',0)
            elif name=='_CFRelease':
                assert args[0]in self.cf_live and call in [0x1fa050,0x31748c,0x31750c];self.cf_live.remove(args[0]);self.ce.append({'kind':'declared_release','pointer':hex(args[0]),'callsite':hex(call)});v=cfg.get('void_free_x0',0)
            else:raise AssertionError(name)
            if created:self.cf_live.add(created);self.ce.append({'kind':'declared_create','pointer':hex(created),'callsite':hex(call)})
            self.effects(e,writes);assert e['return_u64']==hex(v);f=ret(e['before'],v,cfg.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=12001);self.flush();assert self.done and self.attempts==1 and not self.cf_live and not self.buffer_live
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi,self.ci]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points','caller_points']]
        assert self.frees==self.p['private_free_pointers']and list(map(hex,sorted(self.active)))==self.p['private_active_pointers']
        assert self.ce==self.p['CF_events']and self.va==self.p['version_allocation_attempts']and caller_snapshot(self,'frontier')==self.p['caller_final']
        from audit_corefp_optional_reset import snapshot
        assert snapshot(self,'frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,
          'reset_points_checked':self.pi,'caller_points_checked':self.ci,'CF_events_checked':len(self.ce),'version_allocation_attempts_checked':self.va,
          'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(p,r,s):
    cfg=p['configuration'];pts={v['label']:v for v in p['caller_points']};busy=cfg['label']=='busy_token';raw=cfg['label']=='raw_slot_frontier'
    want_labels=list(POINTS.values()) if not busy and not raw else list(POINTS.values())[:-2]
    assert list(pts)==want_labels and len(p['caller_points'])==len(pts)
    first=bytes.fromhex(pts['version_call']['child_record32_hex']);low=CHILD&M32
    helper_key=((((0x4dd92f1e|((low<<1)&M32))-low+0x59136871)&M32)^0xf2c32814)*0x4386951d&M32
    assert int.from_bytes(first[4:8],'little')^helper_key==0x9a6b and int.from_bytes(first[8:16],'little')==OUTPUT
    assert first[:4]==b'\xa5'*4 and pts['version_call']['output24_hex']=='a5'*24
    before=cfg.get('initial_version_u64',[0,0,0]);values=list(before);cache_hit=all(before)
    scanf=[e for e in p['models']if e.get('name')=='_sscanf'];assert len(scanf)<=1
    if scanf:
        parsed={'14.3.1':[14,3,1],'26.0':[26,0],'bad':[]}[cfg['version_text']]
        for j,v in enumerate(parsed):values[j]=v
        assert int(scanf[0]['return_u64'],16)==len(parsed)
    marker=0x40 if cache_hit or scanf else 0x3f
    retpoint=pts['version_return'];returned=bytes.fromhex(retpoint['child_record32_hex']);assert returned==bytes([marker])+first[1:]
    tuple24=struct.pack('<3Q',*values);assert retpoint['output24_hex']==retpoint['version24_hex']==tuple24.hex()
    assert p['caller_final']['output24_hex']==p['caller_final']['version24_hex']==tuple24.hex()
    cache=pts['cache_compare'];assert cache['CPU']['X31'][9]=='0x0'and [int(cache['CPU']['X31'][j],16)for j in [10,11]]==before[1:]
    assert not any(e.get('name','').startswith('_CF')for e in p['models']) if cache_hit else any(e.get('name')=='_CFURLCreateFromFileSystemRepresentation'for e in p['models'])
    stores=[w for w in p['writes']if OUTPUT<=int(w['address'],16)<OUTPUT+24]
    assert [(p['visits'][w['visit']]['pc'],w['address'],w['size_B'],w['after_hex'])for w in stores]==[
      (hex(pc),hex(OUTPUT+8*j),8,tuple24[8*j:8*j+8].hex())for j,pc in enumerate([0x317524,0x31752c,0x317534])]
    reset=pts['reset_entry'];record=bytes.fromhex(reset['child_record32_hex']);key=((CHILD^0x341dc0b1)*0xdb676c6f)&M32
    assert int.from_bytes(record[:4],'little')^key==0xf7a5 and record[4:]==returned[4:]
    assert int(reset['CPU']['X31'][0],16)==CHILD and int(pts['reset_call']['CPU']['X31'][19],16)==0x94ed
    assert int(pts['reset_call']['CPU']['X31'][30],16)==0x1030f and int(pts['reset_call']['CPU']['X31'][28],16)==BASE+0x1c81940
    assert int(reset['CPU']['SP'],16)==0x62017d40 and int(reset['CPU']['X31'][30],16)==BASE+0x9aa750
    reset_store=[w for w in p['writes']if w['address']==hex(CHILD)and w['size_B']==4];assert len(reset_store)==1
    assert p['visits'][reset_store[0]['visit']]['pc']=='0x9aa700'and reset_store[0]['after_hex']==record[:4].hex()
    assert pts['after_reset_record_store']['child_record32_hex']==pts['reset_call']['child_record32_hex']==reset['child_record32_hex']
    child_reads=[v for v in p['reads']if CHILD<=int(v['address'],16)<CHILD+32 and 0x1f530c<=int(p['visits'][v['visit']]['pc'],16)<0x1f5884]
    assert [(v['address'],v['size_B'])for v in child_reads]==[(hex(CHILD),4)]
    edge=[e for e in p['PAC_models']if e['pc']=='0x9aa74c'];assert len(edge)==1 and edge[0]['pointer_row']==s.decoded[0x1d04f48]and edge[0]['target']==hex(BASE+0x1f530c)
    assert p['frontier']['reason']==('before_second_CASAL'if busy else 'before_unbacked_free'if raw else 'ordinary_return')
    if not busy and not raw:assert pts['reset_return']['child_record32_hex']==record.hex()and p['frontier']['CPU']['SP']==hex(SP)
    assert r.ram(OUT,8)==struct.pack('<Q',64)and r.ram(BASE+STATE,8)==bytes(8)
    initial={int(v['address'],16):unpack(v['payload'])for v in p['initial_RAM']}
    fetch=lambda a,n:initial[a&~4095][a%4096:a%4096+n]
    assert r.ram(REC,32)==fetch(REC,32)and p['caller_final']['cursor8_hex']==struct.pack('<Q',64).hex()
    # Recheck the slot bytes independently for these source-produced child calls.
    start=BASE+0x1d32dd0;want=bytearray(fetch(start,264));fields=[(0,8,0x29acdb77),(16,4,0xfb394ce9),(20,4,0x3f74e630),(24,8,0x99960b5a),
      (32,4,0xeb152103),(36,4,0xcbc97b7d),(40,8,0x20a6b15dcc57f527),(48,8,0xeb20c546),(56,8,0x44710b16),(64,8,0x058aaa16),(72,8,0x0176cb4e),(80,8,0x6c426f1a)]
    for j,k in enumerate(cfg.get('slot_kinds',[])):
        if k=='backed':want[j*88+8:j*88+16]=struct.pack('<Q',0x614a2fa7)
        for off,n,v in fields:want[j*88+off:j*88+off+n]=v.to_bytes(n,'little')
    assert r.ram(start,264)==want
    result_scans=[]
    for e in scanf:
        # On each observed post-scanf path, X0 is redefined before any use.
        at=int(e['after']['PC'],16)-BASE;index=next(j for j,v in enumerate(p['visits'])if int(v['pc'],16)==at);checked=0
        for v in p['visits'][index:]:
            ins=next(CS.disasm(s.read(int(v['pc'],16),4),int(v['pc'],16)));reads,writes=ins.regs_access()
            assert not {'x0','w0'}&{CS.reg_name(x)for x in reads};checked+=1
            if {'x0','w0'}&{CS.reg_name(x)for x in writes}:break
        else:raise AssertionError('no reaching X0 overwrite')
        result_scans.append({'callsite':e['callsite'],'source_instructions_before_X0_definition_inclusive':checked,'result_read':False})
    if not busy and not raw:
        f=p['frontier']['CPU'];assert f['X31'][19:]==p['initial_CPU']['X31'][19:]
    return {'label':cfg['label'],'entry_operation_u32':'0x84ee','version_operation_u32':'0x9a6b','reset_operation_u32':'0xf7a5',
      'child_record':hex(CHILD),'output':hex(OUTPUT),'version_cache_hit':bool(cache_hit),'version_marker_u8':hex(marker),'version_tuple_u64':values,
      'scanf_conversions':len(parsed)if scanf else None,'scanf_result_def_use_checks':result_scans,'reset_record_source_store':'0x9aa700',
      'reset_incoming_call':'0x9aa74c','cursor_final_u64':64,'frontier':p['frontier']['reason'],'native_ownership_established':False}


def source_checks(s):
    x=z3.BitVec('record_low32',32);major,minor,patch=z3.BitVecs('major64 minor64 patch64',64)
    source_helper=(((0x4dd92f1e|(x<<1))-x+0x59136871)^0xf2c32814)
    source_caller=(((x|0x08d0b6ac)+0xf72f4953-(x|0xf72f4953))^0x5cff0937)
    reset_caller=(((x|0x4b4fbce7)+0xb4b04318-(x|0xb4b04318))^0x7f527c56)
    claims=[('version_helper_pre_multiply',source_helper,x^0x542fbf9b),('version_caller_pre_multiply',source_caller,x^0x542fbf9b),
      ('reset_caller_pre_multiply',reset_caller,x^0x341dc0b1),
      ('CCMP_cache_partition',z3.If(major!=0,z3.If(minor!=0,patch!=0,z3.BoolVal(False)),z3.BoolVal(False)),z3.And(major!=0,minor!=0,patch!=0))]
    proofs=[]
    for name,left,right in claims:
        q=z3.Solver();q.set(timeout=30000);q.add(left!=right);assert q.check()==z3.unsat;proofs.append({'label':name,'query':q.to_smt2(),'result':'unsat'})
    a=s.read(0x18ac070,256);b=s.read(0x1ac18c0,256);out=[v^b[a[v]^7]for v in range(256)];assert set(out)=={0x61}
    row=0x1c81940+8*(0x1030f+0x61+0x351);assert row==0x1d04f48 and s.decoded[row]['target']=='0x1f530c'
    literals=[]
    for at,n,want in [(0x1669194,48,b'/System/Library/CoreServices/SystemVersion.plist'),(0x1c79e26,14,b'ProductVersion'),(0x1685dc0,15,b'%llu.%llu.%llu\0')]:
        raw=s.read(at,n);assert raw==want;literals.append({'address':hex(at),'size_B':n,'bytes_hex':raw.hex(),'sha256':SHA(raw)})
    assert s.qword(0x1d1c298)==0x1c79e26 and s.qword(0x1d1c2a0)==14
    exact={0x9a6594:('add','x9, x9, #0x40'),0x9a6598:('str','x9, [x1]'),0x9a65a4:('eor','w9, w0, w9'),
      0x9a65a8:('ldr','w10, [x0, #8]'),0x9a65ac:('madd','w13, w9, w13, w10'),0x9a66e4:('blraa','x8, x17'),
      0x9aa688:('add','w19, w6, #0xfff'),0x9aa6f8:('add','w10, w19, w10'),0x9aa700:('stur','w10, [x29, #-0xb8]'),
      0x9aa738:('add','w8, w30, w8, uxtb'),0x9aa73c:('add','w8, w8, #0x351'),0x9aa740:('ldr','x8, [x28, w8, uxtw #3]'),0x9aa74c:('blraa','x8, x17'),
      0x316cb0:('cmp','x9, #0'),0x316cc8:('ccmp','x10, x9, #4, ne'),0x316ccc:('ccmp','x11, #0, #4, ne'),0x316cd0:('cset','w9, ne'),
      0x316ce4:('mov','w27, #0x40'),0x31731c:('mov','w27, #0x40'),0x317418:('mov','w27, #0x40'),
      0x317524:('str','x8, [x1]'),0x31752c:('str','x8, [x1, #8]'),0x317534:('str','x8, [x1, #0x10]'),0x317544:('strb','w27, [x19]')}
    checks=[]
    for at,pair in exact.items():
        raw=s.read(at,4);i=next(CS.disasm(raw,at));assert (i.mnemonic,i.op_str)==pair;checks.append({'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str})
    return {'proofs':proofs,'exact_instructions':checks,'reset_call_bank':{'A':hex(0x18ac070),'B':hex(0x1ac18c0),'A256_hex':a.hex(),'B256_hex':b.hex(),
      'xor_u8':'0x7','constant_u8':'0x61','enumerated_inputs':256,'phase_W30':'0x1030f','bias':'0x351','dispatch_base':'0x1c81940','pointer_row':s.decoded[row]},'literals':literals}


def sdk_checks():
    code='''#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
_Static_assert(sizeof(void*)==8 && sizeof(CFIndex)==8 && sizeof(unsigned long long)==8,"widths64");
_Static_assert(sizeof(Boolean)==1 && sizeof(uint32_t)==4,"widths8_32");
_Static_assert(kCFStringEncodingUTF8==0x08000100,"UTF8");
#define PROTO(n,t) _Static_assert(__builtin_types_compatible_p(__typeof__(&n),t),#n)
PROTO(CFURLCreateFromFileSystemRepresentation,CFURLRef(*)(CFAllocatorRef,const UInt8*,CFIndex,Boolean));
PROTO(CFReadStreamCreateWithFile,CFReadStreamRef(*)(CFAllocatorRef,CFURLRef));
PROTO(CFReadStreamOpen,Boolean(*)(CFReadStreamRef));
PROTO(CFReadStreamClose,void(*)(CFReadStreamRef));
PROTO(CFPropertyListCreateWithStream,CFPropertyListRef(*)(CFAllocatorRef,CFReadStreamRef,CFIndex,CFOptionFlags,CFPropertyListFormat*,CFErrorRef*));
PROTO(CFDictionaryGetValue,const void*(*)(CFDictionaryRef,const void*));
PROTO(CFStringGetCStringPtr,const char*(*)(CFStringRef,CFStringEncoding));
PROTO(CFStringGetCString,Boolean(*)(CFStringRef,char*,CFIndex,CFStringEncoding));
PROTO(CFRelease,void(*)(CFTypeRef));
PROTO(sscanf,int(*)(const char*,const char*,...));
PROTO(free,void(*)(void*));
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-Wno-deprecated-declarations','-fsyntax-only','-x','c','-']
    result=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert result.returncode==0,result.stderr;assert not result.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip());cf='System/Library/Frameworks/CoreFoundation.framework/Versions/A/Headers/'
    headers=[{'SDK_relative_header':n,'size_B':len((sdk/n).read_bytes()),'sha256':SHA((sdk/n).read_bytes())}for n in [cf+'CFURL.h',cf+'CFStream.h',cf+'CFPropertyList.h',cf+'CFString.h',cf+'CFDictionary.h',cf+'CFBase.h','usr/include/stdio.h']]
    return {'command':cmd,'source':code,'source_sha256':SHA(code.encode()),'exit_code':0,'stderr':'','headers':headers,'emitted_artifact':False}


def main():
    e=json.loads(read(ROOT/'corefp_reset_caller_checks.json'));s=Pointers()
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_reset_caller.py').read_bytes())and e['thin_sha256']==THIN_SHA
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['base_declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()]
    for span in e['source_spans']:assert span==s.function(int(span['start'],16))
    totals=Counter();oracles=[]
    for p in e['profiles']:
        cfg=p['configuration'];assert cfg==expected_config(cfg['label']);ov=overlay(cfg);assert p['declared_overlay']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in ov]
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':hex(SP),'PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(REC);cpu['X31'][1]=hex(OUT);cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(initial_page(s,a))
            for at,raw in ov:
                lo=max(a,at);hi=min(a+4096,at+len(raw))
                if lo<hi:b[lo-a:hi-a]=raw[lo-at:hi-at]
            assert unpack(row['payload'])==b;totals['initial_RAM_B_checked']+=4096
        replay=Replay(p,e['source_spans'],s);totals.update(replay.run());oracles.append(oracle(p,replay,s))
    source=source_checks(s);frozen=reset_source(s);sdk=sdk_checks()
    fields=['visits','reads','writes','PAC_models','models','points','private_free_pointers','caller_points','CF_events']
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in fields},'version_allocation_attempts':sum(p['version_allocation_attempts']for p in e['profiles'])}
    assert counts==e['verified_counts']and len(e['source_spans'])==4
    result={'verified_counts':counts,'independent_replay':dict(totals),'compact_oracle_profiles':len(oracles),
      'source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans']),'source_spans':4,
      'new_source_queries_unsat':len(source['proofs']),'frozen_reset_queries_unsat':len(frozen['proofs']),
      'exact_instructions_checked':len(source['exact_instructions'])+len(frozen['exact_instructions']),
      'bank_inputs_checked':256+frozen['bank_inputs_checked'],'common_reset_lifted_instructions':33,'SDK_compile_exit':0,
      'all_checks_pass':True,'native_target_executed':False}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_reset_caller_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'frozen_auditor_dependencies':{n:SHA(read(ROOT/n).encode())for n in ['audit_corefp_optional_reset.py','audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']},
      'oracles':oracles,'source_checks':source,'frozen_reset_source_checks':frozen,'SDK_assertions':sdk,'fresh_replay_completed':True,'process_exit_code':0,
      'native_API_executed':False,'native_file_read':False,'IDB_mutated':False,'new_live_IDA_claim':False,'full_goal_complete':False}
    (ROOT/'corefp_reset_caller_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
