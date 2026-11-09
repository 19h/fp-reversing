#!/usr/bin/env python3
"""Pin class matching prefix,original class pointer,kext metaclass and SDK ABI.

O(B+I+256R+F+SDK bytes+KC symbols) time/space for bounded primary evidence.
No native daemon/kernel/API executes;service publication remains unknown.
"""
import hashlib,json,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,POOL,TABLE,selected,verify_original_fixups,qword
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from probe_daemon_iokit_class import RANGES,NAME
from kernel_native_reader import Kernel
from recover_carrier_control import span
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from kext_port_tools import SOURCE as KSOURCE,IMAGE as KIMAGE
SPANS=[('main_port_prefix',*RANGES[0]),('class_decoder_and_matching',*RANGES[1]),('null_matching',*RANGES[2])]
RULES=[('main_port',0x4e,0xcc54,TABLE,0),('class_data_cell',0xa3,0x8d8,POOL,0xffffffffeb6011de),('service_matching',0xa3,0xcd35,TABLE,0)]
DIRECT=[0x9a9b,0x9ae1,0x27ce,0x27d5,0x597a]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sdk_check():
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());p=sdk/'System/Library/Frameworks/IOKit.framework/Headers/IOKitLib.h';lines=p.read_text().splitlines();snips=[]
 for word in['IOMainPort(','IOServiceMatching(']:
  j=next(i for i,s in enumerate(lines)if s.lstrip().startswith(word));snips.append({'declaration':word,'first_line':j-8,'last_line':j+6,'text':'\n'.join(lines[j-9:j+6])})
 cmd=['xcrun','clang','-target','arm64e-apple-macos26.0','-isysroot',str(sdk),'-fsyntax-only','-Werror',str(ROOT/'daemon_iokit_class_sdk.c')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr
 return {'header_path':str(p),'header_sha256':sha(p),'snippets':snips,'command':cmd,'source_sha256':sha(ROOT/'daemon_iokit_class_sdk.c'),'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'scope':'Installed user SDK widths/signatures/class-or-subclass semantics;target build equivalence and native API effects unknown.'}
def main():
 spans=[native(*s)for s in SPANS];banks=[]
 for label,key,add,base,bias in RULES:
  row=selected(0x100fc4130,0x101031ea0,key,add,base,bias);row.update(label=label,base=hex(base),left256_hex=IMAGE.read(0x100fc4130,256).hex(),right256_hex=IMAGE.read(0x101031ea0,256).hex());banks.append(row)
 prof=json.loads((ROOT/'daemon_iokit_class_profiles.json').read_text());used={int(x['address'],16)for group in['composed_cases','decoder_cases']for row in prof[group]for x in row['source_fixup_reads']};used|={TABLE+j*8 for j in DIRECT};used|={0x1010b8cc0};used-={0x1010b1e18,0x1010a39c8};fix=verify_original_fixups(used)
 assert qword(0x1010b8cc0)==0x100fd40c0;encoded=IMAGE.read(0x100fd40c0,31);assert bytes(b^0xfc for b in encoded)==NAME
 live=json.loads((ROOT/'daemon_iokit_class_live_ida.json').read_text());matched=[]
 for row in live['disassembly']['results']:
  for i in row['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;matched.append({'pc':i['address'],'size_bytes':len(raw)})
 k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');ctors=[function(k,entry,a)for a in[0xfffffe000a50a834,0xfffffe000a50a978]];ks=[span(k,0xfffffe000a69f174,0xfffffe000a69f184)];pointers=[pointer(k,a)for a in[0xfffffe000847c5d8,0xfffffe000847c3e8]];name=k.read(0xfffffe000790cc00,31);assert name==NAME and KIMAGE.read(0xfffffe000790cc00,31)==name
 for f in ctors:assert KIMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 syms=k.symbols([int(f['start'],16)for f in ctors]+[int(p['target'],16)for p in pointers]+[0xfffffe000a69f174]);prior=Path('/Users/___/Downloads/fpx/analysis');notes=[{'path':str(prior/n),'sha256':sha(prior/n),'contents':(prior/n).read_text(),'used_as':'Prior conditional analysis leads;original global fixup and full selected source paths verified here.'}for n in['arm_iokit_class_decode_evidence.md','arm_iokit_class_decode_proof.py','arm_iokit_predecessor_call_evidence.md','arm_iokit_predecessor_call_proof.py']]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py','recover_daemon_iokit_census.py','probe_daemon_iokit_class.py','daemon_iokit_class_live_ida.json','daemon_iokit_class_sdk.c','kernel_native_reader.py','recover_carrier_control.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','kext_port_tools.py']},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'dispatch_slots':[{'index':hex(j),'slot':hex(TABLE+j*8),'original_word_hex':IMAGE.read(TABLE+j*8,8).hex(),'fixup':FIXUPS[TABLE+j*8]}for j in DIRECT],'original_fixup_records':fix,'bindings':[binding(a)for a in[0x1010a0988,0x1010a0c28]],'class_data':{'pointer_cell':'0x1010b8cc0','source_address':'0x100fd40c0','raw_word_hex':IMAGE.read(0x1010b8cc0,8).hex(),'encoded31_hex':encoded.hex(),'expected_class31_hex':NAME.hex()},'live_IDB_source_rows_matched':matched,'kernel_collection_sha256':k.sha256,'kext_sha256':sha(KSOURCE),'kext_class_name':{'address':'0xfffffe000790cc00','bytes_hex':name.hex()},'kext_constructors':ctors,'kext_spans':ks,'kext_pointers':pointers,'exact_kext_symbols':syms,'SDK':sdk_check(),'retained_prior_sources':notes,'native_target_executed':False,'native_service_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_class_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'banks':len(banks),'fixups':len(fix['records']),'live_IDB_rows':len(matched),'kext_constructors':len(ctors),'SDK_compile_exit':0}),flush=True)
if __name__=='__main__':main()
