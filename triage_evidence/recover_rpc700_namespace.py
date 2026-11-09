#!/usr/bin/env python3
"""Read-only special-port kernel contract and bounded RPC700 receiver leads.

Original KC, installed SDK/header/plists, two arm64e executable slices and one
original cached framework. No target/loader/Mach/IOKit/synchronization action.
Imports, GOT targets and header-shaped candidates are bounded search evidence,
not exhaustive server discovery or native endpoint attestation.
O(B+N+F+E) extraction; two timeout-bounded scalar queries; O(B+F) space.
"""
import bisect,hashlib,json,plistlib,re,struct,subprocess
from pathlib import Path
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import commands,macho,string
from bootpolicy_cache_reader import Cache,Dylib,uleb
ROOT=Path(__file__).resolve().parent
SDK=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk')
HEADER=SDK/'usr/include/mach/host_special_ports.h'
MAD=Path('/System/Library/Frameworks/ManagedAppDistribution.framework/Support')
def sha(b):return hashlib.sha256(b).hexdigest()
def header_candidates(data,meta,wanted=700):
 # Common 64-bit MIG subsystem prefix:fnptr8,start32,end32,maxreply32.
 out=[]
 for p in range(8,len(data)-12,8):
  start,end,maxreply=struct.unpack_from('<3I',data,p)
  if 0<=start<=wanted<end<=wanted+4096 and 36<=maxreply<=1048576:out.append({'header_file_offset':p-8,'start':start,'end':end,'max_reply_bytes':maxreply,'verified_MIG_table':False})
 base=next(s['address']for s in meta['segments']if s['name']=='__TEXT');members={};functions=[]
 def readword(a):
  s=next(s for s in meta['segments']if s['address']<=a and a+8<=s['address']+s['file_size']);off=s['file_offset']+a-s['address'];return struct.unpack_from('<Q',data,off)[0]
 for at,cmd,size in commands(data,0):
  if cmd==0x26:
   off,n=struct.unpack_from('<II',data,at+8);buf=data[off:off+n];cur=0;a=base
   while cur<len(buf):
    delta,cur=uleb(buf,cur)
    if not delta:break
    a+=delta;functions.append(a)
  if cmd!=0x80000034:continue
  fo,fs=struct.unpack_from('<II',data,at+8);version,starts,im,sy,count,fmt,sf=struct.unpack_from('<7I',data,fo);st=fo+starts;ns=struct.unpack_from('<I',data,st)[0]
  for j in range(ns):
   delta=struct.unpack_from('<I',data,st+4+j*4)[0]
   if not delta:continue
   info=st+delta;sz,ps,pf,vmoff,maxptr,np=struct.unpack_from('<IHHQIH',data,info);assert pf==12
   for page in range(np):
    start=struct.unpack_from('<H',data,info+22+2*page)[0]
    if start==0xffff:continue
    chain_starts=[]
    if start&0x8000:
     ix=start&0x7fff
     while True:
      v=struct.unpack_from('<H',data,info+22+2*ix)[0];chain_starts.append(v&0x7fff);ix+=1
      if v&0x8000:break
    else:chain_starts=[start]
    for start in chain_starts:
     a=base+vmoff+page*ps+start
     while True:
      assert a not in members;word=readword(a);members[a]=word;nxt=(word>>51)&0x7ff
      if not nxt:break
      a+=8*nxt
 function_set=set(functions)
 for e in out:
  off=e['header_file_offset'];section=next((s for s in meta['sections']if s['file_offset']<=off and off+32<=s['file_offset']+s['size']),None);e['section']=section['section']if section else None;e['first_pointer_hex']=hex(struct.unpack_from('<Q',data,off)[0]);reasons=[]
  if section is None:reasons.append('outside declared file-backed section')
  else:
   a=section['address']+off-section['file_offset'];e['address']=hex(a)
   if section['flags']&(0x80000000|0x400):reasons.append('instruction section')
   if a not in members:reasons.append('no original chained pointer at first field')
   else:
    word=members[a]
    if word>>62&1:reasons.append('first field is import bind')
    else:
     target=base+(word&0xffffffff)if word>>63 else base+(word&((1<<43)-1))+(((word>>43)&255)<<56);e['decoded_first_target']=hex(target)
     if target not in function_set:reasons.append('first field not a declared local compiler start')
   if off+32+40*(e['end']-e['start'])>section['file_offset']+section['size']:reasons.append('descriptor-array extent leaves section')
  e['schema_rejections']=reasons;e['passes_common_header_gates']=not reasons
 return out
def binary(path):
 raw=path.read_bytes();assert raw[:4]==bytes.fromhex('cafebabe');arches=[]
 for j in range(struct.unpack_from('>I',raw,4)[0]):
  cpu,sub,off,n,align=struct.unpack_from('>5I',raw,8+j*20);assert off+n<=len(raw);arches.append({'cpu':hex(cpu),'subtype':hex(sub),'offset':off,'size_bytes':n,'sha256':sha(raw[off:off+n])})
 selected=next(a for a in arches if a['cpu']=='0x100000c'and a['subtype']=='0x80000002');b=raw[selected['offset']:selected['offset']+selected['size_bytes']];meta=macho(b,0,path.name);loads=[];imports=[];entry=None
 for at,cmd,n in commands(b,0):
  if cmd in(0xc,0x80000018,0x8000001f,0x80000023,0x20):loads.append(string(b,at+struct.unpack_from('<I',b,at+8)[0]))
  if cmd==0x80000028:entry=0x100000000+struct.unpack_from('<Q',b,at+8)[0]
  if cmd==0x80000034:
   fo,sz=struct.unpack_from('<II',b,at+8);ver,starts,im,sy,count,fmt,symfmt=struct.unpack_from('<7I',b,fo);assert ver==symfmt==0 and fmt in[1,2]
   for j in range(count):
    iw=struct.unpack_from('<I',b,fo+im+(4 if fmt==1 else 8)*j)[0];ordinal=iw&255;ordinal=ordinal-256 if ordinal&128 else ordinal;name=string(b,fo+sy+(iw>>9));imports.append({'ordinal':j,'name':name,'library_ordinal':ordinal,'library':loads[ordinal-1]if 0<ordinal<=len(loads)else'special ordinal'})
 for e in imports:
  ordinal=e['library_ordinal'];e['library']=loads[ordinal-1]if 0<ordinal<=len(loads)else'special ordinal'
 interesting=[]
 for m in re.finditer(rb'[ -~]{6,}',b):
  if re.search(rb'fairplay|fpsd|unfreed|host_special',m[0],re.I):interesting.append({'slice_file_offset':m.start(),'text':m[0].decode()})
 return {'source_path':str(path),'source_sha256':sha(raw),'source_size_bytes':len(raw),'slices':arches,'selected_slice':selected,'uuid':meta['uuid'],'entry':hex(entry),'segments':meta['segments'],'sections':meta['sections'],'loads':loads,'imports':imports,'direct_Mach_host_MIG_imports':[e for e in imports if re.search(r'host_(get|set)|mach_|mig_',e['name'],re.I)],'related_strings':interesting,'MIG700_header_shape_candidates':header_candidates(b,meta),'candidate_scan_scope':'8-byte-aligned common 32-byte MIG subsystem-prefix/40-byte-descriptor schema in arm64e slice;explicit pointer/compiler/section gates,not complete server discovery.'}
def main():
 k=Kernel();sources=[k.function(a)for a in[0xfffffe000bcf258c,0xfffffe000bcf27ac,0xfffffe000bcd00bc]];head=HEADER.read_bytes();(ROOT/'rpc700_host_special_ports.h').write_bytes(head);plists=[]
 for n in['LaunchDaemons/com.apple.fairplayd.plist','LaunchDaemons/com.apple.managedappdistributiond.plist','LaunchAgents/com.apple.managedappdistributionagent.plist']:
  path=Path('/System/Library')/n;raw=path.read_bytes();plists.append({'path':str(path),'sha256':sha(raw),'raw_hex':raw.hex(),'parsed':plistlib.loads(raw)})
 binaries=[binary(MAD/n)for n in['managedappdistributiond','managedappdistributionagent']]
 control=Path('/Users/___/Downloads/zut/fairplayd.arm64e').read_bytes();positive=header_candidates(control,macho(control,0,'positive-control daemon'),502);assert any(e.get('address')=='0x1010381c0'and e['passes_common_header_gates']for e in positive)
 cache=Cache();d=Dylib(cache,'/System/Library/Frameworks/ManagedAppDistribution.framework/Versions/A/ManagedAppDistribution');names={}
 for path in['/usr/lib/system/libsystem_kernel.dylib','/usr/lib/system/libsystem_c.dylib','/usr/lib/system/libxpc.dylib']:
  lib=Dylib(cache,path)
  for name,v in lib.exports.items():
   if re.search(r'^_(host_|mach_|mig_|xpc_connection_)',name):names.setdefault(v['address'],[]).append({'image':path,'symbol':name,'image_uuid':lib.uuid})
 got=[]
 for section in d.sections:
  if section['name']not in['__got','__auth_got']:continue
  for a in range(section['address'],section['address']+section['size'],8):
   raw=cache.read(a,8)
   if raw==bytes(8):got.append({'address':hex(a),'raw_word_hex':raw.hex(),'null':True});continue
   rec=cache.pointer(a);rec['selected_export_matches']=names.get(int(rec['target'],16),[]);got.append(rec)
 framework={'path':d.path,'base':hex(d.base),'uuid':d.uuid,'functions':len(d.functions),'GOT_records':got,'selected_related_exports':[{'name':n,'address':hex(v['address'])}for n,v in d.exports.items()if re.search('machConnection|ServiceConnection',n)],'selected_export_match_scope':'Original exported host_,mach_,mig_,xpc_connection_ names from libsystem_kernel,libsystem_c,libxpc only.','native_library_loaded':False}
 query={
 'index_range':'''(declare-fun i () (_ BitVec 32))
(define-fun t () (_ BitVec 32) (bvsub i #x00000025))
(define-fun carry () Bool (bvugt (bvadd ((_ zero_extend 1) t) #b000000000000000000000000000100100) #b011111111111111111111111111111111))
(assert (not (= carry (and (bvuge i #x00000001) (bvule i #x00000024)))))''',
 'copy_sentinels':'''(declare-fun p () (_ BitVec 64))
(assert (not (= (bvult (bvadd p #x0000000000000001) #x0000000000000002) (or (= p #x0000000000000000) (= p #xffffffffffffffff)))))'''};proofs=[]
 for name,body in query.items():
  path=ROOT/f'rpc700_namespace_{name}.smt2';path.write_text('(set-option :timeout 60000)\n'+body+'\n(check-sat)\n');r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr);proofs.append({'name':name,'file':path.name,'sha256':sha(path.read_bytes()),'result':'unsat'})
 src=ROOT/'rpc700_host_constants.c';src.write_text('#include <mach/host_special_ports.h>\n_Static_assert(HOST_UNFREED_PORT == 17, "slot17");\n_Static_assert(HOST_FAIRPLAYD_PORT == 31, "slot31");\n_Static_assert(HOST_MANAGEDAPPDISTD_PORT == 34, "slot34");\n_Static_assert(HOST_MAX_SPECIAL_PORT == 36, "maximum");\n');r=subprocess.run(['clang','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-fsyntax-only',str(src)],capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr)
 files=[{'path':p,'uuid':cache.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(Path(p).read_bytes())}for p in sorted(cache.used)]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes())for n in['kernel_native_reader.py','resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py']},'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'kernel_functions':sources,'kernel_exact_symbols':k.symbols([0xfffffe000bcf258c,0xfffffe000bcf27ac,0xfffffe000bcd00bc]),'SDK_header':{'path':str(HEADER),'sha256':sha(head),'snapshot':'rpc700_host_special_ports.h','compiled_constants':{'HOST_UNFREED_PORT':17,'HOST_FAIRPLAYD_PORT':31,'HOST_MANAGEDAPPDISTD_PORT':34,'HOST_MAX_SPECIAL_PORT':36},'compile_exit':r.returncode,'compile_stderr':r.stderr,'probe_sha256':sha(src.read_bytes()),'target_kernel_semantic_name_pairing_verified':False},'plists':plists,'candidate_binaries':binaries,'positive_control':{'source_sha256':sha(control),'message_id':502,'candidates':positive},'cache_uuid':cache.uuid,'cache_files_hashed':files,'framework':framework,'proofs':proofs,'receiver_identified':False,'native_target_executed':False,'native_port_objects_observed':False,'full_goal_complete':False};(ROOT/'rpc700_namespace_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'kernel_functions':3,'proofs_unsat':len(proofs),'candidate_binaries':len(binaries),'candidate_import_counts':[len(b['imports'])for b in binaries],'header_candidates':[len(b['MIG700_header_shape_candidates'])for b in binaries],'passing_header_candidates':[sum(e['passes_common_header_gates']for e in b['MIG700_header_shape_candidates'])for b in binaries],'framework_GOT':len(got),'framework_selected_export_matches':sum(bool(e.get('selected_export_matches'))for e in got),'cache_files_hashed':len(files)}),flush=True)
if __name__=='__main__':main()
