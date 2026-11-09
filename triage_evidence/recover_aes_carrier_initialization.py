#!/usr/bin/env python3
"""Original carrier constructors, typed allocation ABI and bounded status scan.
O(image+text+symbols), O(image+captured text); no target operations.
"""
import json,hashlib,urllib.request,re
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,CS
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import function,starts
P='aes_carrier_initialization';VIEW=0xfffffe000858a4a8
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'aes_command_pool_source.json').read_text());funcs=list(old['functions']);have={int(r['start'],16)for r in funcs};fam=next(e for e in k.entries if e['name']=='com.apple.iokit.IOCryptoAcceleratorFamily')
 for a in [0xfffffe000abfc1cc,0xfffffe000abfc204,0xfffffe000abfc308,0xfffffe000abfc374,0xfffffe000abfc388,0xfffffe000abfc3e4]:
  if a not in have:r=function(k,fam,a);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 for a in [0xfffffe000c4458c4,0xfffffe000bcfeb8c,0xfffffe000bcfe5b8,0xfffffe000bd75c64]:
  if a not in have:r=k.function(a,exact=True);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 texts=[]
 for name in ['com.apple.iokit.IOCryptoAcceleratorFamily','com.apple.driver.AppleS8000AES']:
  e=next(e for e in k.entries if e['name']==name);sect=next(s for s in e['sections']if s['section']=='__text');a=sect['address'];raw=k.read(a,sect['size']);ins=list(CS.disasm(raw,a));assert sum(i.size for i in ins)==len(raw)
  hits=[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins if re.search(r'#0x78(?![0-9a-f])',i.op_str)]
  texts.append({'entry':name,'entry_uuid':e['uuid'],'compiler_function_starts':len(starts(k,e)),'start':hex(a),'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'bytes_hex':raw.hex(),'instruction_count':len(ins),'literal_0x78_operand_hits':hits,'alias_or_indirect_writer_closure_established':False})
 url='https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/zalloc.h';reference=urllib.request.urlopen(url,timeout=30).read();lines=reference.decode().splitlines();excerpt=[{'line':j+1,'text':line.strip()}for j,line in enumerate(lines)if line.strip().startswith(('Z_ZERO          =','Z_NOFAIL        =','Z_WAITOK        ='))];assert len(excerpt)==3 and any('0x0004'in x['text']for x in excerpt)
 slots=[]
 for a in [0xfffffe000858a598,0xfffffe000858a648,0xfffffe000858a678]:
  p=im.pointer(a);slots.append({'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]})
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['aes_command_pool_source.json','aes_command_pool_profiles.json','kernel_vm_mig_tools.py','recover_kext_aes_handoff.py',P+'_prior_manifest.json']},'kernel_sha256':k.sha256,'functions':funcs,'additional_slots':slots,'seed_stubs':old['seed_stubs'],'typed_view':{'address':hex(VIEW),'bytes_hex':k.read(VIEW,64).hex(),'exact_symbols':k.symbols([VIEW])[hex(VIEW)],'encoded_size_low24':int.from_bytes(k.read(VIEW+0x2c,4),'little')&0xffffff,'runtime_zone_identity_established':False},'base_command_vptr':'0xfffffe0007f41558','derived_command_vptr':'0xfffffe0008588d98','typed_backend':'0xfffffe000bcfeb8c','fallback_backend':'0xfffffe000bcfe5b8','allocation_counter':'0xfffffe000cb5b638','allocation_counter_file_hex':k.read(0xfffffe000cb5b638,8).hex(),'status_scan':texts,'separately_versioned_reference':{'url':url,'sha256':hashlib.sha256(reference).hexdigest(),'size_bytes':len(reference),'enum_excerpt':excerpt,'meaning_paraphrase':'Z_ZERO requests zero-initialized returned memory; Z_WAITOK permits waiting. This source revision is not established as the collection build.','matched_collection_source_revision_established':False},'native_target_executed':False,'native_IPC_executed':False,'native_allocation_executed':False,'hardware_PAC_executed':False,'authentic_completion_status_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(r['instructions'])for r in funcs),'scan_instructions':sum(t['instruction_count']for t in texts),'literal_hits':sum(len(t['literal_0x78_operand_hits'])for t in texts)}),flush=True)
if __name__=='__main__':main()
