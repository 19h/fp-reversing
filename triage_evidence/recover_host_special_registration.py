#!/usr/bin/env python3
"""Original launchd/libsystem/kernel host-special publication interfaces.
Read-only byte/fixup/SDK capture; no target execution, IPC or registration.
O(B+F+I+W) time/space for bytes, fixups, selected instructions and word scans.
"""
import bisect,json,re,struct,subprocess,tempfile
from pathlib import Path
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache,Dylib
from recover_rpc700_namespace import binary
from recover_managed_fairplay_bridge import Native,sha,h,instructions
ROOT=Path(__file__).resolve().parent;P='host_special_registration'
FLAGS=['target_executed','target_emulated','host_special_port_set','native_port_identity_proved','native_policy_decision_proved','hardware_PAC_checked','native_RPC700_exchange','full_goal_complete']
KERNEL=[0xfffffe000bd83eb8,0xfffffe000bd83f84,0xfffffe000bcf2330,0xfffffe000bcf23cc,0xfffffe000bcf2194,0xfffffe000bcf24b0,0xfffffe000bcf258c,0xfffffe000bcf334c,0xfffffe000bd7e9c4,0xfffffe000bd7deec,0xfffffe000bccb4c0,0xfffffe000c617964,0xfffffe000bcf27ac,0xfffffe000bd41ac4]
LAUNCHD=[0x100003708,0x10002d3a8,0x10002fd84,0x10003012c,0x100035930,0x100046c28,0x10005cb6c,0x1000479cc,0x100047064,0x10005c840,0x100043fd0]
SDK=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
def fixup_reference(n):
 with tempfile.TemporaryDirectory(prefix=P+'_')as directory:
  path=Path(directory)/'original.arm64e';path.write_bytes(n.data);r=subprocess.run(['/usr/bin/dyld_info','-fixups',str(path)],capture_output=True,text=True);assert r.returncode==0 and not r.stderr;seen={}
  for line in r.stdout.splitlines():
   m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9A-Fa-f]+)\s+(\S+)\s+(\S+)(.*)',line)
   if m:seen[int(m[1],16)]=(m[2],m[3],m[4])
  assert seen.keys()==n.fixups.keys()
  for a,v in n.fixups.items():
   kind,target,note=seen[a];assert v['authenticated']==kind.startswith('auth-')and v['bind']==kind.endswith('bind')
   if v['bind']:
    add=re.search(r'\+ (0x[0-9A-Fa-f]+)',note);assert target.split('/',1)[1]==v['symbol']and(int(add[1],16)if add else 0)==v['total_addend']
   else:assert int(target,16)==int(v['target'],16)
  return {'command_template':['/usr/bin/dyld_info','-fixups','<temporary exact arm64e slice>'],'exit_code':r.returncode,'fixups_compared':len(seen),'all_matches':True,'normalized_stdout_sha256':h(r.stdout.replace(str(path),'<temporary exact arm64e slice>').encode())}
def branch_hits(raw,base,targets,starts,reader):
 assert len(raw)%4==0;out=[]
 for j,(word,)in enumerate(struct.iter_unpack('<I',raw)):
  if word&0x7c000000!=0x14000000:continue
  imm=word&0x3ffffff;imm=imm-0x4000000 if imm&0x2000000 else imm;at=base+4*j;target=at+4*imm
  if target not in targets:continue
  index=bisect.bisect_right(starts,at)-1;start=starts[index];a=max(start,at-32);b=reader(a,at-a+8);out.append({'site':hex(at),'target':hex(target),'containing_start':hex(start),'branch_word_hex':hex(word),'window_bytes':b.hex(),'window':instructions(b,a)})
 return out
def build():
 im=Image();k=im.k;sub=next(r for r in im.subsystems()if r['start']==400);mig=[r for r in sub['routines']if r['id']in[412,413]];kr=[k.function(a)for a in KERNEL];seg=next(s for s in k.kernel['segments']if s['name']=='__TEXT_EXEC');raw=k.read(seg['address'],seg['file_size']);kx=branch_hits(raw,seg['address'],{0xfffffe000bcf2194,0xfffffe000bcf2330,0xfffffe000bcf23cc},k.starts,k.read)
 meta=binary(Path('/sbin/launchd'));n=Native(meta);lr=[n.function(a)for a in LAUNCHD];section=next(s for s in meta['sections']if s['section']=='__text');text=n.read(section['address'],section['size']);lx=branch_hits(text,section['address'],{0x10005e260},n.starts,n.read)
 stubs=[n.stub(a)for a in[0x10005e260,0x10005e230,0x10005e340,0x10005f720,0x10005f740,0x10005f870,0x10005edd0,0x10005f500,0x10005f780,0x10005f770,0x10005d870,0x10005e360,0x10005e250]]
 strings=[{'address':hex(a),'text':n.cstring(a)}for a in[0x1000759b0,0x1000759c0,0x10006e8d3,0x10006e90b]];types=[n.fixups[a]for a in[0x100086db8,0x100086d78,0x100086dd8,0x100086d98]]
 cache=Cache();lib=Dylib(cache,'/usr/lib/system/libsystem_kernel.dylib');cr=[]
 for name in['_host_get_special_port','_host_set_special_port']:
  f=lib.function(lib.exports[name]['address']);f['exact_export']=name;cr.append(f)
 constants=[{'address':hex(a),'bytes8_hex':cache.read(a,8).hex()}for a in[0x18057d380,0x18057d468,0x18057d400,0x18057d410,0x18057d470]]
 bindings=[{'exact_export':name,'address':hex(lib.exports[name]['address'])}for name in['_mach_msg2_internal','_mig_get_reply_port','_mig_dealloc_reply_port','_mach_msg_destroy']]
 files=[{'path':p,'uuid':cache.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(cache.used)]
 header_paths=[SDK/'usr/include/mach/host_priv.h',SDK/'usr/include/mach/host_priv.defs',SDK/'usr/include/mach/host_special_ports.h',SDK/'usr/include/mach/message.h',SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/message.h']
 headers=[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in header_paths]
 sdk_text=(SDK/'usr/include/mach/host_priv.h').read_text();assert re.search(r'"host_get_special_port",\s*412',sdk_text)and re.search(r'"host_set_special_port",\s*413',sdk_text)
 fs=kr+lr+cr;counts={'kernel_functions':len(kr),'launchd_functions':len(lr),'cache_functions':len(cr),'original_instructions':sum(len(r['instructions'])for r in fs),'original_function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in fs),'MIG_records':len(mig),'launchd_setter_branch_candidates':len(lx),'kernel_setter_branch_candidates':len(kx),'kernel_text_words_scanned':len(raw)//4,'launchd_text_words_scanned':len(text)//4,'launchd_fixups_compared':len(n.fixups),'selected_launchd_stubs':len(stubs),'SDK_headers':len(headers)}
 return {'generator_sha256':sha(__file__),'dependencies':{p:sha(ROOT/p)for p in['kernel_vm_mig_tools.py','kernel_native_reader.py','bootpolicy_cache_reader.py','resolve_kernel_collection_interfaces.py','recover_rpc700_namespace.py','recover_managed_fairplay_bridge.py','rpc700_namespace_contracts.json','rpc700_publication_observations.json','rpc700_publication_source.json']},'kernel_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'kernel_functions':kr,'kernel_symbols':k.symbols([0xfffffe000bcf258c,0xfffffe000bcf27ac,0xfffffe000bd41ac4,0xfffffe000bcd0448,0xfffffe0007f8b0a0]),'MIG_records':mig,'kernel_setter_branch_candidates':kx,'kernel_strings':[{'address':hex(a),'text':k.read(a,128).split(b'\0')[0].decode()}for a in[0xfffffe000704bb14,0xfffffe000704bb40]],'host_slot_static_words':[{'index':i,'address':hex(0xfffffe000cad0248+8*i),'bytes8_hex':k.read(0xfffffe000cad0248+8*i,8).hex(),'runtime_object':'unknown'}for i in[17,31,34]],'launchd':{'source_path':meta['source_path'],'source_sha256':meta['source_sha256'],'source_size_bytes':meta['source_size_bytes'],'uuid':meta['uuid'],'slices':meta['slices'],'selected_slice':meta['selected_slice'],'imports_count':len(meta['imports']),'fixups_count':len(n.fixups),'reference':fixup_reference(n),'ranges':lr,'stubs':stubs,'strings':strings,'type_bindings':types,'owner_query_jump_table':{'address':'0x100050f84','relative_base':'0x100003744','bytes40_hex':n.read(0x100050f84,40).hex(),'targets':[hex(0x100003744+v)for v in struct.unpack('<10i',n.read(0x100050f84,40))]},'setter_branch_candidates':lx,'runtime_selected_slice':'unknown'},'cache_uuid':cache.uuid,'cache_library_uuid':lib.uuid,'cache_functions':cr,'cache_constants':constants,'cache_exact_bindings':bindings,'cache_files':files,'SDK_headers':headers,'reference_sources':REFERENCE,'inspection_tool':{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')},'verified_source_counts':counts,**{f:False for f in FLAGS}}
REFERENCE=[
  {
    "name": "host",
    "url": "https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/host.c",
    "commit": "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea",
    "size_bytes": 44473,
    "sha256": "a935841c1b49e830c0baa99316e93a6c2004aa7ff65b56790f6a1efacf461198",
    "scope": "Reference-source naming/context only; not exact target-build attestation."
  },
  {
    "name": "ipc_host",
    "url": "https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ipc_host.c",
    "commit": "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea",
    "size_bytes": 19576,
    "sha256": "96cab4d278c3d6eef23fb0b02917d03d5cbcc6ec9a2fc822350c2fc921d3aff4",
    "scope": "Reference-source naming/context only; not exact target-build attestation."
  },
  {
    "name": "policy",
    "url": "https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/security/mac_policy.h",
    "commit": "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea",
    "size_bytes": 236958,
    "sha256": "5e0f5f294319ce005d0ec3de8b6130e9bcf7e1274b89d736fe852a2390db79db",
    "scope": "Reference-source naming/context only; not exact target-build attestation.",
    "policy_pointer_fields": 335,
    "field_126": "mpo_proc_check_set_host_special_port",
    "offset_64bit": 1008
  }
]
def main():
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']))
if __name__=='__main__':main()
