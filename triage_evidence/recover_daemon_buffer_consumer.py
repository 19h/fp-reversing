#!/usr/bin/env python3
"""Recover source-local buffer publication/normalization and reader interfaces.
O(source bytes+256*bank rules+fixups) time, O(source rows+fixups) space.
"""
import hashlib,json
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,selected,POOL,TABLE,verify_original_fixups
SPANS=[('loop_phase',0x1004093fc,0x100409440),('publication_guard',0x100315438,0x10031546c),('cache_read',0x100315470,0x100315474),('pointer_and_word_publication',0x100315478,0x100315488),('buffer_normalization',0x100315488,0x100315648),('frame_and_counter_read',0x100315648,0x100315694),('counter_record_pack',0x100315694,0x1003156e8),('counter_helper_dispatch',0x1003156e8,0x100315738),('counter_route',0x100315750,0x100315764),('publication_failure',0x100315764,0x100315798),('nonzero_continuation',0x1002924ec,0x100292518),('reader_pool_base',0x10008cf88,0x10008cf90),('reader_materializer',0x10008cfac,0x10008d008)]
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 spans=[]
 for label,a,z in SPANS:
  raw=IMAGE.read(a,z-a);ins=list(CS.disasm(raw,a));assert sum(i.size for i in ins)==len(raw);spans.append({'label':label,'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 banks=[selected(0x100e99700,0x100f4e190,0x81,0xcb7e),selected(0x100e99a00,0x100f4e390,0x9c,0x768,base=POOL,bias=-0x30f772e6)]
 dispatch=[{'role':name,'index':hex(index),'slot':hex(TABLE+8*index)}for name,index in [('failure',0x1bcb),('counter_zero',0x16e5),('counter_nonzero',0x16f4)]]
 fixups={int(b['slot'],16)for b in banks}|{int(r['slot'],16)for r in dispatch}|{POOL+0x1658,POOL+0x26a0};fix=verify_original_fixups(fixups)
 ida=json.loads((ROOT/'daemon_buffer_consumer_live_ida.json').read_text());texts=[r['text']for r in ida['content']if r['type']=='text'];data=next(json.loads(t.split('[assist:tool-output]\n',1)[1].split('\n[/assist:tool-output]',1)[0])for t in texts if '[assist:tool-output]'in t);matched=0;unique={}
 for result in data['results']:
  for row in result['instructions']:
   a=int(row['address'],16);raw=bytes.fromhex(row['bytes']);assert IMAGE.read(a,len(raw))==raw;matched+=1;unique[a]=row
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_buffer_consumer_live_ida.json','daemon_buffer_globals_live_ida.json','daemon_context_transfer_proofs.json','daemon_prng_output_checks.json']},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'dispatch_slots':dispatch,'source_fixups':fix,'live_IDB_rows_matched':matched,'unique_live_IDB_rows_matched':len(unique),'interfaces':{'buffer_source_cell':'0x1010c8278','buffer_cache_cell':'0x1010c8268','buffer_cache_store':'0x100315478','constant_word_cell':'0x1010c67d4','constant_word_store':'0x100315484','constant_word_value_u32':255,'normalization_offsets_bytes':list(range(0,256,16)),'normalization_table_offsets_bytes':list(range(0,256,8)),'counter_cell':'0x1010c8258','counter_read':'0x100315690','index_cell':'0x1010c67dc','index_read':'0x100315688','comparison_call':'0x100315734','comparison_target':'0x10041a5e0','reader_address_materialization':'0x10008d004'},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'daemon_buffer_consumer_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(spans),'fixups':len(fix['records']),'bank_inputs':512,'IDB_rows':matched,'unique_IDB_rows':len(unique)}),flush=True)
if __name__=='__main__':main()
