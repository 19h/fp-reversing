#!/usr/bin/env python3
"""Audit overlapping prior writes behind buffer publication and frame reuse.
O(journal bytes+events) time,O(largest journal) space; no target runs.
"""
import hashlib,json
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from replay_daemon_context_transfer import unpack

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def slice_value(shape,offset,n):
 if'hex'in shape:return {'hex':bytes.fromhex(shape['hex'])[offset:offset+n].hex()}
 return {'terms':shape['terms'][offset:offset+n]}
def main():
 old=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());contracts=json.loads((ROOT/'daemon_prng_output_contracts.json').read_text());rows=[]
 for c in contracts['contexts']:
  index=c['prior_case_index'];t=unpack(next(x for x in old['cases']if x['prior_case_index']==index));F=int(c['frame_SP'],16);D=int(c['data_pointer'],16);addresses={'frame358':F+0x358,'frame1E0':F+0x1e0,'global_buffer_pointer':0x1010c8278,'first_buffer_word':D,'second_buffer_word':D+4};widths={'first_buffer_word':4,'second_buffer_word':4};found={key:[]for key in addresses};byte_writers={key:{}for key in addresses}
  for ordinal,s in enumerate(t['steps']):
   for e in s['events']:
    if e['kind']!='write':continue
    at=int(e['address'],16);n=e['size_bytes']
    for key,address in addresses.items():
     size=widths.get(key,8)
     start=max(at,address);end=min(at+n,address+size)
     if start<end:
      assert IMAGE.read(int(s['pc'],16),4).hex()==s['bytes_hex'];record={'source_visit_index':ordinal,'pc':s['pc'],'write_address':hex(at),'write_size_bytes':n,'selected_address':hex(start),'selected_size_bytes':end-start,'selected_value':slice_value(e['value'],start-at,end-start)};found[key].append(record)
      for a in range(start,end):byte_writers[key][a]={'pc':s['pc'],'source_visit_index':ordinal,'value':slice_value(e['value'],a-at,1)}
  final={}
  for key,address in addresses.items():
   size=widths.get(key,8);assert all(address+j in byte_writers[key]for j in range(size));parts=[byte_writers[key][address+j]['value']for j in range(size)]
   final[key]={'hex':''.join(x['hex']for x in parts)}if all('hex'in x for x in parts)else{'terms':[int(x['hex'],16)if'hex'in x else x['terms'][0]for x in parts]}
  assert found['global_buffer_pointer'][-1]['pc']=='0x1002fb820'and int.from_bytes(bytes.fromhex(final['global_buffer_pointer']['hex']),'little')==D
  assert int.from_bytes(bytes.fromhex(final['frame1E0']['hex']),'little')==0x1010c8278
  for j,key in enumerate(['first_buffer_word','second_buffer_word']):assert int.from_bytes(bytes.fromhex(final[key]['hex']),'little')==c['initial_words'][j]
  rows.append({'prior_case_index':index,'frame_SP':hex(F),'data_pointer':hex(D),'writer_histories':found,'final_values':final,'final_byte_writers':{key:[{'address':hex(a),**v}for a,v in sorted(items.items())]for key,items in byte_writers.items()}})
 deps=['daemon_context_transfer_profiles.json','daemon_prng_output_contracts.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{name:sha(ROOT/name)for name in deps},'source_sha256':sha(SOURCE),'contexts':rows,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_prng_output_provenance.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'contexts':len(rows),'overlapping_writer_histories':sum(len(x['writer_histories'])for x in rows),'all_checks_pass':True,'last_frame1E0_writer':rows[0]['writer_histories']['frame1E0'][-1]['pc'],'buffer_word_writers':[rows[0]['writer_histories'][key][-1]['pc']for key in ['first_buffer_word','second_buffer_word']]}),flush=True)
if __name__=='__main__':main()
