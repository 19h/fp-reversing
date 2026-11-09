#!/usr/bin/env python3
"""Original managed-app/AMS context bridge; read-only static evidence.
O(B+F+I+S) time/space for bytes, fixups, instructions and symbols.
dyld_info inspects temporary original slices; no target execution or IPC.
"""
import bisect,hashlib,json,re,struct,subprocess,tempfile
from pathlib import Path
from resolve_kernel_collection_interfaces import commands,macho,string
from bootpolicy_cache_reader import Cache,Dylib,uleb,CS
P='managed_fairplay_bridge';ROOT=Path(__file__).resolve().parent
FLAGS=['target_executed','target_emulated','FairPlay_requests_sent','IDB_modified','RPC700_receiver_identified','native_exchange_verified','full_goal_complete']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def h(b):return hashlib.sha256(b).hexdigest()
def instructions(raw,a):
 ins=list(CS.disasm(raw,a));assert len(ins)*4==len(raw)
 return [{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]
class Native:
 def __init__(self,inv):
  self.inv=inv;raw=Path(inv['source_path']).read_bytes();assert h(raw)==inv['source_sha256'];sl=inv['selected_slice'];self.data=raw[sl['offset']:sl['offset']+sl['size_bytes']];assert h(self.data)==sl['sha256'];self.meta=macho(self.data,0,'managed-app arm64e');assert self.meta['uuid']==inv['uuid'];self.base=0x100000000;self.starts=[];self.fixups={}
  for at,c,n in commands(self.data,0):
   if c==0x26:
    off,n=struct.unpack_from('<II',self.data,at+8);b=self.data[off:off+n];p=0;a=self.base
    while p<len(b):
     delta,p=uleb(b,p)
     if not delta:break
     a+=delta;self.starts.append(a)
   if c!=0x80000034:continue
   fo,fs=struct.unpack_from('<II',self.data,at+8);ver,st,im,sy,count,fmt,sf=struct.unpack_from('<7I',self.data,fo);assert (ver,sf)==(0,0)and fmt in(1,2);st+=fo;ns=struct.unpack_from('<I',self.data,st)[0]
   for j in range(ns):
    de=struct.unpack_from('<I',self.data,st+4+j*4)[0]
    if not de:continue
    info=st+de;sz,ps,pf,vo,maxp,np=struct.unpack_from('<IHHQIH',self.data,info);assert pf==12
    for page in range(np):
     first=struct.unpack_from('<H',self.data,info+22+page*2)[0]
     if first==65535:continue
     offsets=[]
     if first&32768:
      ix=first&32767
      while True:
       v=struct.unpack_from('<H',self.data,info+22+ix*2)[0];offsets.append(v&32767);ix+=1
       if v&32768:break
     else:offsets=[first]
     for off in offsets:
      a=self.base+vo+page*ps+off
      while True:
       assert a not in self.fixups;word=struct.unpack('<Q',self.read(a,8))[0];bind=bool(word>>62&1);auth=bool(word>>63);r={'address':hex(a),'word':hex(word),'bind':bind,'authenticated':auth,'pointer_format':12,'chain_membership_verified':True}
       if bind:
        ordinal=word&0xffffff;assert ordinal<count;stride=4 if fmt==1 else 8;iw=struct.unpack_from('<I',self.data,fo+im+stride*ordinal)[0];ad=0 if fmt==1 else struct.unpack_from('<i',self.data,fo+im+stride*ordinal+4)[0];symbol=string(self.data,fo+sy+(iw>>9));imp=inv['imports'][ordinal];assert symbol==imp['name'];pa=0 if auth else word>>32&0x7ffff
        if pa&0x40000:pa-=0x80000
        r.update(symbol=symbol,import_ordinal=ordinal,library=imp['library'],total_addend=ad+pa,target=symbol)
       else:r['target']=hex(self.base+(word&0xffffffff)if auth else self.base+(word&((1<<43)-1))+(((word>>43)&255)<<56))
       self.fixups[a]=r;nxt=word>>51&2047
       if not nxt:break
       a+=8*nxt;assert a<self.base+vo+(page+1)*ps
 def read(self,a,n):
  s=next(s for s in self.meta['segments']if s['address']<=a and a+n<=s['address']+s['file_size']);p=s['file_offset']+a-s['address'];return self.data[p:p+n]
 def cstring(self,a):return self.read(a,256).split(b'\0')[0].decode()
 def function(self,a):
  ix=bisect.bisect_right(self.starts,a)-1;assert self.starts[ix]==a,(self.inv['source_path'],hex(a),hex(self.starts[ix]));z=self.starts[ix+1];b=self.read(a,z-a);return {'start':hex(a),'end':hex(z),'bytes':b.hex(),'sha256':h(b),'instructions':instructions(b,a)}
 def stub(self,a,selector=False):
  b=self.read(a,32 if selector else 16);ii=instructions(b,a);at=2 if selector else 0;assert [r['mnemonic']for r in ii[at:at+4]]==['adrp','add','ldr','braa'],(self.inv['source_path'],hex(a),ii);slot=int(ii[at]['operands'].split('#')[1],0)+int(ii[at+1]['operands'].split('#')[1],0);r={'address':hex(a),'bytes':b.hex(),'instructions':ii,'binding':self.fixups[slot]}
  if selector:
   q=int(ii[0]['operands'].split('#')[1],0)+(int(ii[1]['operands'].split('#')[1].split(']')[0],0)if '#'in ii[1]['operands']else 0);sel=self.fixups[q];assert not sel['bind'];r.update(selector_reference=sel,selector=self.cstring(int(sel['target'],16)))
  return r
 def reference(self):
  with tempfile.TemporaryDirectory(prefix=P+'_')as d:
   p=Path(d)/'original.arm64e';p.write_bytes(self.data);r=subprocess.run(['/usr/bin/dyld_info','-fixups',str(p)],capture_output=True,text=True);assert r.returncode==0 and not r.stderr
   found={}
   for l in r.stdout.splitlines():
    m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9A-Fa-f]+)\s+(\S+)\s+(\S+)(.*)',l)
    if m:found[int(m[1],16)]={'kind':m[2],'target':m[3],'annotation':m[4].strip(),'line':l.strip()}
   assert set(found)==set(self.fixups)
   for a,v in self.fixups.items():
    ref=found[a];assert v['authenticated']==ref['kind'].startswith('auth-')and v['bind']==ref['kind'].endswith('bind')
    if v['bind']:
     assert ref['target'].split('/',1)[1]==v['symbol'];ad=re.search(r'\+ (0x[0-9A-Fa-f]+)',ref['annotation']);assert(int(ad[1],16)if ad else 0)==v['total_addend']
    else:assert int(ref['target'],16)==int(v['target'],16)
  return {'command_template':['/usr/bin/dyld_info','-fixups','<temporary original slice>'],'exit_code':r.returncode,'normalized_stdout_sha256':h(r.stdout.replace(str(p),'<temporary original slice>').encode()),'fixups_compared':len(found),'all_chain_memberships_and_targets_match':True,'selected_lines':[found[a]['line']for a in [0x10053ba18,0x100539148,0x100547638,0x100548100]]}
def build():
 old=json.loads((ROOT/'rpc700_namespace_contracts.json').read_text());images=[];helper=0x10040c2dc;callers=[0x1001a29cc,0x1001a3620,0x1001a42e4,0x1003c9fc8]
 for inv in old['candidate_binaries']:
  s=Native(inv);text=next(x for x in s.meta['sections']if x['section']=='__text');direct=[];buffer=[];decoded=0
  raw_text=s.read(text['address'],text['size']);assert len(raw_text)%4==0
  for index,(word,)in enumerate(struct.iter_unpack('<I',raw_text)):
   decoded+=1
   if word&0x7c000000!=0x14000000:continue
   imm=word&0x3ffffff;imm=imm-0x4000000 if imm&0x2000000 else imm;site=text['address']+index*4;target=site+imm*4
   if target==0x10047ddc0:
    ins=instructions(raw_text[index*4:index*4+4],site)[0];assert ins['mnemonic']in('b','bl')and ins['operands']=='#0x10047ddc0';direct.append({'site':hex(site),'containing_start':hex(s.starts[bisect.bisect_right(s.starts,site)-1]),'instruction':ins['mnemonic']})
  assert decoded*4==text['size']
  actual_callers=sorted({int(r['containing_start'],16)for r in direct});assert len(actual_callers)==4;actual_helper=min(s.starts,key=lambda a:abs(a-helper));assert abs(actual_helper-helper)<=16;ranges=[s.function(a)for a in actual_callers+[actual_helper]]
  for r in ranges[:3]:
   for i in r['instructions']:
    if i['mnemonic']=='bl'and i['operands']=='#'+hex(actual_helper):buffer.append({'caller':r['start'],'site':i['ea']})
  runtime=[]
  for guess,symbol in [(0x10047c460,'_objc_opt_self'),(0x10047c470,'_objc_release'),(0x10047c480,'_objc_retain'),(0x10047c4a0,'_objc_retainAutoreleasedReturnValue'),(0x10047ccd0,'_swift_willThrow')]:
   matches=[]
   for a in range(guess-16,guess+17,4):
    try:st=s.stub(a)
    except(AssertionError,ValueError,KeyError,IndexError):continue
    if st['binding'].get('symbol')==symbol:matches.append(st)
   assert len(matches)==1,(inv['source_path'],symbol,matches);runtime+=matches
  images.append({'source_path':inv['source_path'],'source_sha256':inv['source_sha256'],'slice':inv['selected_slice'],'uuid':inv['uuid'],'compiler_starts':len(s.starts),'text_words_scanned':decoded,'text_size_bytes':text['size'],'fixup_count':len(s.fixups),'reference':s.reference(),'class_binding':s.fixups[0x10053ba18],'ranges':ranges,'selector_callers':direct,'buffer_adapter_entry':hex(actual_helper),'selected_buffer_calls':buffer,'stubs':[s.stub(a,True)for a in[0x10047ddc0,0x1004808e0]]+runtime})
 cache=Cache();ams=Dylib(cache,'/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices');assert cache.uuid==old['cache_uuid']and ams.uuid=='1b464993-f0e2-3804-b412-a6cc8091798c';ranges=[]
 for a in[0x19c1ecfcc,0x19c1ed06c,0x19c1ed0a8,0x19c1ed14c,0x19c6491c8,0x19c6000e4,0x19c6006fc]:
  r=ams.function(a);r['original_names']=ams.symbols_at(a);ranges.append(r)
 stubs=[];objc=Dylib(cache,'/usr/lib/libobjc.A.dylib');dispatch=Dylib(cache,'/usr/lib/system/libdispatch.dylib');targets={v['address']:{'symbol':n,'library':d.path,'uuid':d.uuid}for d in[objc,dispatch]for n,v in d.exports.items()}
 for a in[0x1a0025080,0x1a00250a0,0x1a006bf20,0x1a006c010,0x1a006bf90,0x1a006bec0,0x1a006b980]:
  b=cache.read(a,16);ii=instructions(b,a);r={'address':hex(a),'bytes':b.hex(),'instructions':ii}
  if [i['mnemonic']for i in ii[:3]]==['adrp','add','b']:
   sel=int(ii[0]['operands'].split('#')[1],0)+int(ii[1]['operands'].split('#')[1],0);r.update(selector=cache.cstring(sel),selector_address=hex(sel))
  else:
   assert[i['mnemonic']for i in ii]==['adrp','add','ldr','braa'];slot=int(ii[0]['operands'].split('#')[1],0)+int(ii[1]['operands'].split('#')[1],0);r['pointer']=cache.pointer(slot);r['exact_export']=targets[int(r['pointer']['target'],16)]
  stubs.append(r)
 files=[{'path':p,'size_bytes':Path(p).stat().st_size,'uuid':cache.files[p]['uuid'],'sha256':sha(p)}for p in sorted(cache.used)]
 totals={'managed_functions':10,'AMS_functions':7,'managed_instructions':sum(len(r['instructions'])for s in images for r in s['ranges']),'AMS_instructions':sum(len(r['instructions'])for r in ranges),'managed_function_bytes':sum(len(bytes.fromhex(r['bytes']))for s in images for r in s['ranges']),'AMS_function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in ranges),'aligned_selector_branch_candidates':sum(len(s['selector_callers'])for s in images),'selected_buffer_calls':sum(len(s['selected_buffer_calls'])for s in images),'fixups_independently_compared':sum(s['reference']['fixups_compared']for s in images),'cache_files':len(files),'managed_stubs':14,'AMS_stubs':7}
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py','rpc700_namespace_contracts.json','appstore_events_contracts.json','ams_core_contracts.json']},'images':images,'cache_uuid':cache.uuid,'AMS_uuid':ams.uuid,'AMS_path':ams.path,'AMS_classes':{'AMSKeybag':{'address':hex(ams.exports['_OBJC_CLASS_$_AMSKeybag']['address']),'exact_export':'_OBJC_CLASS_$_AMSKeybag'},'AMSFairPlayContext':{'address':'0x1eed15f68','original_names':ams.symbols_at(0x1eed15f68)}},'AMS_ranges':ranges,'AMS_stubs':stubs,'cache_files':files,'inspection_tool':{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')},'verified_source_counts':totals,'corresponding_function_byte_equality':[{'daemon_start':r['start'],'agent_start':images[1]['ranges'][j]['start'],'equal':r['bytes']==images[1]['ranges'][j]['bytes']}for j,r in enumerate(images[0]['ranges'])],**{k:False for k in FLAGS}}
def main():
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']))
if __name__=='__main__':main()
