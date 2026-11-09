#!/usr/bin/env python3
"""Bounded caller-pattern census and two conditional record/consumer contracts.
O(B+I+N+256R+F) time/space. LC_FUNCTION_STARTS envelopes and exact literal
patterns do not establish semantic owners or caller completeness/native reachability.
"""
import hashlib,json,bisect
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,selected,verify_original_fixups
from recover_daemon_iokit_census import native,text_section
from recover_rpc502_parser_ownership import starts
from probe_daemon_iokit_callers import SITES
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def census():
 a,n=text_section();raw=IMAGE.read(a,n);pattern=bytes.fromhex('914e81d211093fd7');at=0;rows=[];bounds,meta=starts()
 while True:
  at=raw.find(pattern,at)
  if at<0:break
  if at%4==0:
   pc=a+at+4;j=bisect.bisect_right(bounds,pc)-1;s=native('literal_candidate',pc-0x80,pc+0x24);s.update(call_PC=hex(pc),compiler_envelope_start=hex(bounds[j]),compiler_envelope_end=hex(bounds[j+1]),target_proved_by_discriminator=False,upstream_context_roots_proved=False);rows.append(s)
  at+=1
 return {'text_address':hex(a),'text_size_bytes':n,'text_sha256':hashlib.sha256(raw).hexdigest(),'pattern_hex':pattern.hex(),'candidates':rows,'LC_FUNCTION_STARTS':meta,'scope':'Aligned adjacent MOV X17,#0A74;BLRAA X8,X17 only. Computed modifiers,other registers/instruction forms and other code regions are outside census. Compiler envelopes are storage context,not semantic ownership.'}
def main():
 cc=census();assert len(cc['candidates'])==23;spans=[native(n,s['start'],s['end'])for n,s in SITES.items()];banks=[]
 for n,l,r,k,add in [('313',0x100fc4230,0x101031fa0,0xe4,0xcc69),('AF',0x100fc4130,0x101031ea0,0x4e,0xcbc7)]:
  b=selected(l,r,k,add,TABLE);b.update(label=n,base=hex(TABLE),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex());assert b['target']=='0x1004601d0'and b['slot']=='0x1010a0520';banks.append(b)
 p=json.loads((ROOT/'daemon_iokit_callers_profiles.json').read_text());used={int(e['address'],16)for r in p['cases']for e in r['source_fixup_reads']};collisions=[{'address':hex(a),'fixup':r}for a,r in FIXUPS.items()if 'div=0x0A74 'in r['line']];assert len(collisions)==4;used|={int(e['address'],16)for e in collisions};used-={0x1010b1e18,0x1010a39c8};fix=verify_original_fixups(used)
 live=json.loads((ROOT/'daemon_iokit_callers_live_ida.json').read_text());matched=[]
 for row in live['disassembly']['results']:
  for i in row['instructions']:
   b=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(b))==b;matched.append({'pc':i['address'],'size_bytes':len(b)})
 routes=[]
 for index,target,div in [(0x665d,0x100624b74,0x817a),(0x6915,0x10040dba0,0x817a),(0x4468,0x100b01974,0xfdd6),(0x4fa3,0x100b12828,0xfdd6)]:
  a=TABLE+8*index;r=FIXUPS[a];assert r['target']==target and f'div=0x{div:04X} 'in r['line'];routes.append({'index':hex(index),'slot':hex(a),'target':hex(target),'modifier16':hex(div),'original_word_hex':IMAGE.read(a,8).hex(),'fixup':r})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_iokit_callers.py','daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py','recover_rpc502_parser_ownership.py','daemon_iokit_callers_live_ida.json','daemon_iokit_callers_live_xrefs.json','daemon_iokit_sync_contracts.json','daemon_iokit_errors_contracts.json']},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'census':cc,'discriminator_collision_slots':collisions,'original_fixup_records':fix,'caller_continuation_routes':routes,'live_IDB_source_rows_matched':matched,'context_root_premises':{'313':{'caller_SP_190_right':'0x101031fa0','caller_SP_198_left':'0x100fc4230','X25_TABLE':hex(TABLE),'W21':'0x665d','record':'caller_FP-0x98'},'AF':{'X14_left':'0x100fc4130','X15_right':'0x101031ea0','X27_TABLE':hex(TABLE),'caller_SP_2B8_TABLE':hex(TABLE),'W22':'0x4468','record':'caller_FP-0x98'}},'upstream_context_producers_proved':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_callers_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'literal_candidates':23,'collision_slots':4,'banks':2,'fixups':len(fix['records']),'IDB_rows':len(matched)}),flush=True)
if __name__=='__main__':main()
