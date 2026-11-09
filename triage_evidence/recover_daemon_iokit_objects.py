#!/usr/bin/env python3
"""Pin discovery/object source,import addends,SDK ABI and bounded xref leads.

O(B+I+256R+F+SDK bytes) time,O(B+I+F+SDK snippets) space. No native target.
"""
import hashlib,json,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,POOL,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from probe_daemon_iokit_objects import RANGES
SPANS=[('matching_services',*RANGES[0]),('iterator_next',*RANGES[1]),('service_open_and_release',*RANGES[2]),('empty_iterator',*RANGES[3]),('iterator_release',*RANGES[4]),('cleanup_unknown_pointer',0x100383b00,0x100383b08),('candidate_frame668',0x1002903f8,0x100290414),('candidate_frame80',0x100634b44,0x100634b74)]
RULES=[('matching_services',0x100e99a00,0x100f4e390,0x78,0xcd32,TABLE),('iterator_next',0x100e99800,0x100f4e290,0x61,0xcdd0,TABLE),('task_data_bind',0x100fc4130,0x101031ea0,0x4e,0x30e,POOL),('service_open',0x100fc4230,0x101031fa0,0x6c,0xcd04,TABLE),('service_release',0x100fc4130,0x101031ea0,0xa3,0xcbf8,TABLE),('iterator_release',0x100e99a00,0x100f4e390,0x9c,0xcc3c,TABLE),('candidate_state_root',0x100e99a00,0x100f4e390,0x78,0x1e2,POOL)]
DIRECT=[0xb606,0xb60d,0x6e12,0x6e61,0xab5b,0xab6b,0x4ef4,0x597a]
HEADERS=[('System/Library/Frameworks/IOKit.framework/Headers/IOKitLib.h',[(260,269),(385,394),(434,447),(581,596)]),('System/Library/Frameworks/IOKit.framework/Headers/IOTypes.h',[(155,188)]),('usr/include/mach/port.h',[(130,165)]),('usr/include/mach/mach_init.h',[(73,84)])]
NOTES=['arm_iokit_matching_services_evidence.md','arm_iokit_matching_services_followup_evidence.md','arm_iokit_table_provenance_evidence.md','arm_iokit_open_successors_evidence.md']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sdk_check():
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());rows=[]
 for rel,ranges in HEADERS:
  p=sdk/rel;lines=p.read_text().splitlines();rows.append({'path':str(p),'sha256':sha(p),'snippets':[{'first_line':a,'last_line':z,'text':'\n'.join(lines[a-1:z])}for a,z in ranges]})
 cmd=['xcrun','clang','-target','arm64e-apple-macos26.0','-isysroot',str(sdk),'-fsyntax-only','-Werror',str(ROOT/'daemon_iokit_objects_sdk.c')];p=subprocess.run(cmd,capture_output=True,text=True);assert p.returncode==0,p.stderr
 return {'SDK_path':str(sdk),'headers':rows,'command':cmd,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'source_sha256':sha(ROOT/'daemon_iokit_objects_sdk.c'),'scope':'Installed SDK declaration/width check only;SDK/target build equivalence and native object lifetime unknown.'}
def main():
 spans=[native(*s)for s in SPANS];banks=[]
 for label,l,r,key,add,base in RULES:
  row=selected(l,r,key,add,base,0);row.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex());banks.append(row)
 prof=json.loads((ROOT/'daemon_iokit_objects_profiles.json').read_text());used={int(x['address'],16)for row in prof['cases']for x in row['source_fixup_reads']};used|={TABLE+index*8 for index in DIRECT};used|={int(b['slot'],16)for b in banks};used-={0x1010b1e18,0x1010a39c8};fix=verify_original_fixups(used)
 live=json.loads((ROOT/'daemon_iokit_objects_live_ida.json').read_text());matched=[]
 for r in live['disassembly']['results']:
  for i in r['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;matched.append({'pc':i['address'],'size_bytes':len(raw)})
 prior=Path('/Users/___/Downloads/fpx/analysis');notes=[{'path':str(prior/n),'sha256':sha(prior/n),'contents':(prior/n).read_text(),'used_as':'Analysis leads,not native evidence.'}for n in NOTES]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py','recover_daemon_iokit_census.py','probe_daemon_iokit_objects.py','daemon_iokit_objects_sdk.c','daemon_iokit_objects_live_ida.json']},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'dispatch_slots':[{'index':hex(j),'slot':hex(TABLE+j*8),'original_word_hex':IMAGE.read(TABLE+j*8,8).hex(),'fixup':FIXUPS[TABLE+j*8]}for j in DIRECT],'original_fixup_records':fix,'bindings':[binding(a)for a in[0x1010a0d88,0x1010a0e38,0x1010a0b48,0x1010a0240,0x1010a39c8]],'task_bind_source_bias64':'0xffffffff840ec79d','live_IDB_source_rows_matched':matched,'SDK':sdk_check(),'retained_prior_sources':notes,'candidate_state_pointer_publications':[{'pc':'0x100290400','saved_pointer':'SP+0x668','premise':'X1=POOL and low8(W7)=0x43 selects annotated pool index0x283;upstream bank and subsequent consumer unproved.'},{'pc':'0x100634b60','saved_pointer':'SP+0x80','premise':'Canonical left/right bank pair and table base select annotated pool index0x283;complete entry and subsequent consumer unproved.'}],'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_objects_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'banks':len(banks),'fixups':len(fix['records']),'bindings':5,'live_IDB_rows':len(matched),'SDK_compile_exit':0}),flush=True)
if __name__=='__main__':main()
