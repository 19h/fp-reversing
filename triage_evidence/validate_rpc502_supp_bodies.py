#!/usr/bin/env python3
"""Independent original-byte,body-read and complete fresh candidate checks.

O(C*(B+V+E+S)) bounded time/space. No native APIs/target or IDB mutation.
"""
import hashlib,json,struct
from pathlib import Path
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS
from validate_rpc502_supp import unpack,visits
from probe_rpc502_supp_cases import run_case

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=json.loads((ROOT/'rpc502_supp_bodies_profiles.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_rpc502_supp_bodies.py')and p['source_sha256']==sha(SOURCE);checks=2
 for n,h in p['dependencies'].items():assert sha(ROOT/n)==h;checks+=1
 bank={}
 for e in p['original_instruction_pool']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));assert e['bytes']==b.hex()and e['mnemonic']==i.mnemonic and e['operands']==i.op_str;bank[a]=b;checks+=1
 rows=[];total=0
 for w in p['cases']:
  r=unpack(w);raw=bytes.fromhex(w['case']['file_hex']);seq=visits(r);d=hashlib.sha256()
  for a in seq:assert a in bank;d.update(struct.pack('<Q',a));d.update(bank[a]);checks+=1
  assert len(seq)==r['original_visit_count']and d.hexdigest()==r['original_ordered_bytes_sha256']and r['guest_source_opcodes_checked_each_visit'];checks+=1;total+=len(seq)
  for e in r['supplemental_reads']:
   o=e['offset_bytes'];n=e['size_bytes'];assert 0<=o<o+n<=len(raw)and raw[o:o+n].hex()==e['bytes_hex'];checks+=1
  assert len(r['core_argument_calls'])==1 and set(e['offset_bytes']for e in r['core_argument_reads'])=={0,4,16,24,36};assert r['records'][-1]['result']=='0xffff5bde'and r['stop_reason']=='returned_to_fixture';assert not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated'];checks+=3
  f,_=run_case(w['case']);assert f==r;checks+=1;rows.append({'body_hex':w['case']['label'][5:],'steps':r['steps'],'original_visits':len(seq),'mapping_reads':len(r['supplemental_reads']),'carrier_return':'0xffff5bde','carrier_field28_consumed':False})
 assert next(e['steps']for e in rows if e['body_hex']=='3000')>next(e['steps']for e in rows if e['body_hex']=='3100');checks+=1
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['probe_rpc502_supp_bodies.py','rpc502_supp_bodies_profiles.json','probe_rpc502_supp.py','probe_rpc502_supp_cases.py','validate_rpc502_supp.py']},'verified_counts':{'cases':len(rows),'fresh_worker_runs':len(rows),'retained_original_visits':total,'fresh_original_visits':total,'original_instructions':len(bank),'assertions':checks},'case_summaries':rows,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_supp_bodies_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)

if __name__=='__main__':main()
