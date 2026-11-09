#!/usr/bin/env python3
"""Original alternate-certificate continuation and late carrier field views.

O(B+V+E+S+R log F) work/space;SDK compile only. No native target/API/IDB.
Source slices and original compiler ownership do not imply complete routines.
"""
import bisect,hashlib,json,subprocess
from pathlib import Path
from daemon_receive_tools import IMAGE,SOURCE,ROOT,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals,certificate_view

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=json.loads((ROOT/'rpc502_policy_profiles.json').read_text());fix={}
 for w in p['cases']:
  for d in journals(unpack(w)):
   for e in d['original_fixup_reads']:fix[int(e['address'],16)]=e['original_fixup']
 spans=[(0x100747f6c,0x100747fd0),(0x100a7b00c,0x100a7b054),(0x1009192ac,0x100919374),(0x100a21a90,0x100a21b08),(0x100657308,0x100657380),(0x100a8b848,0x100a8b8b0),(0x10097531c,0x100975350),(0x10065f118,0x10065f134)]
 f,meta=starts();owners={}
 for a,z in spans:
  cur=a
  while cur<z:
   j=bisect.bisect_right(f,cur)-1;b,e=f[j:j+2];owners[b]={'start':hex(b),'end':hex(e),'sha256':hashlib.sha256(IMAGE.read(b,e-b)).hexdigest()};cur=min(z,e)
 sdk='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk';cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',sdk,'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'rpc502_policy_layouts.c'),'-o',str(ROOT/'rpc502_policy_layouts.s')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 inv=json.loads((ROOT/'rpc502_auth_certificate_inventory.json').read_text());certs=[]
 for off in [0xee87f4,0xff63a4]:
  e=next(e for e in inv['records']if int(e['file_offset'],16)==off);raw=bytes(x^int(e['XOR_byte'],16)for x in SOURCE.read_bytes()[off:off+e['size_bytes']]);v=certificate_view(raw);assert v==e['certificate'];certs.append({'file_offset':hex(off),'size_bytes':len(raw),'XOR_byte':e['XOR_byte'],'DER_hex':raw.hex(),'certificate':v})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_policy_profiles.json','probe_rpc502_policy_cases.py','probe_rpc502_policy_transition.py','rpc502_auth_certificate_inventory.json','rpc502_rsa_models.py','rpc502_startup_tools.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_ranges':[native(a,z)for a,z in spans],'compiler_ranges':list(owners.values()),'LC_FUNCTION_STARTS':meta,'consumed_pointer_import_records':[binding(a)if f['kind'].endswith('bind')else verify_original_fixups([a])['records'][0]for a,f in sorted(fix.items())],'original_certificates':certs,'late_carrier_fields':{'address_key':'((P_low32 XORc6d66014)*6b86592f) mod2^32','28':{'load_pc':'0x100747f70','intermediate':'stored28+key mod2^32','store':'SP+68 at100747f78','parameter':'intermediate XOR8b3dc651;128 in all three cases','full_semantics_unknown':True},'40':{'load_pc':'0x100747f7c','intermediate':'stored40-key mod2^32','store':'SP+ec at100747fc4','full_semantics_unknown':True},'8':{'load_pc':'0x100747f84','intermediate':'stored8 XORkey','store':'SP+178 at100747f8c','later_call_argument':'intermediate+d51c85f8 mod2^32 at100919318/330','full_semantics_unknown':True},'selected_accessed_extent_bytes':44,'C_layout_extent_including_padding_bytes':48,'complete_type_unknown':True},'sdk_compile':{'command':cmd,'source_sha256':sha(ROOT/'rpc502_policy_layouts.c'),'assembly_sha256':sha(ROOT/'rpc502_policy_layouts.s'),'exit_code':0},'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_policy_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(spans),'compiler_ranges':len(owners),'pointer_records':len(fix),'source_certificates':len(certs)}),flush=True)
if __name__=='__main__':main()
