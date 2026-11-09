#!/usr/bin/env python3
"""Original-image record iteration, status gate and linked lookup capture.
Static only. O(B+F+I+256K) time/space; no target execution or native request.
"""
import json,re,struct,subprocess
from recover_daemon_xpc_payload import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,POOL,qword,selected,block,verify_original_fixups,binding,SDK,sha,h,D,FLAGS
P='daemon_xpc_iteration'
FRAGMENTS={
 'helper_status':0x1009e1230,'resume':0x100bd6fd8,'loop_gate':0x100b22fe4,'nonempty':0x100ad9f78,'minimum':0x100ba9504,'extent':0x100a6c060,
 'result':0x100c8f210,'publish_result':0x100c044d4,'outer':0x100c4dc4c,'outer_signed':0x100a61db0,'outer_upper':0x100c8e248,'outer_equal':0x100aac57c,'outer_status':0x100a5b1b4,
 'prepare_lookup':0x100bb0184,'lookup_entry':0x100bb0aa8,'lookup_nonnull':0x100ab1448,'query_setup':0x100a18fe4,
 'search_entry':0x100a53448,'next_node':0x100bb5a9c,'candidate':0x100b090fc,'decode_setup':0x100c4d728,'decode_bytes':0x100c9eefc,'compare':0x100c1c2bc,
 'advance_node':0x100bde374,'output_node':0x100cbae58,'return_search':0x100c0a0d4,'search_status':0x100bac8d0,'found_node':0x100bb00c0,'missing_return':0x100d30ab4,
 'lookup_return':0x100c45c98,'value_continuation':0x100c65c9c,'failure':0x100bd9558,'cleanup':0x100b12c30}
SPECS=[]
CALLS=[]
BRANCHES=[
 ('helper_equal','helper_status',0xa101,0x100bd6fd8),('helper_other','helper_status',0x5c78,0x100bd9558),('resume_loop','resume',0x2282,0x100b22fe4),
 ('remaining_nonzero','loop_gate',0x6b0c,0x100ad9f78),('remaining_zero','loop_gate',0x3b5c,0x100c8f210),
 ('source_present','nonempty',0x5c7f,0x100ba9504),('source_null','nonempty',0x5c78,0x100bd9558),
 ('header_fits','minimum',0x2eba,0x100a6c060),('header_short','minimum',0x2edb,0x100bd9558),('record_fits','extent',0x6aaa,0x100cc0944),('record_exceeds','extent',0x6a6b,0x100bd9558),
 ('result_publish','result',0x5f5a,0x100c044d4),('result_outer','publish_result',0x893a,0x100c4dc4c),('outer_selected','outer',0xc522,0x100a61db0),
 ('control_ge_first','outer_signed',0x67b6,0x100c8e248),('control_ge_second','outer_upper',0x347a,0x100aac57c),('control_equal','outer_equal',0x4100,0x100a5b1b4),
 ('outer_status_equal','outer_status',0x8dde,0x100bb0184),('outer_status_other','outer_status',0x77ae,0x100b12c30),
 ('prepare_query','prepare_lookup',0x66dd,0x100bb0aa8),('lookup_Q_present','lookup_entry',0x6bbb,0x100ab1448),('lookup_Q_null','lookup_entry',0x6bfb,0x100c45c98),
 ('setup_query','lookup_nonnull',0x17e5,0x100a18fe4),('start_search','query_setup',0xb266,0x100a53448),
 ('search_Q_present','search_entry',0x7b2c,0x100bb5a9c),('search_Q_null','search_entry',0xca98,0x100c0a0d4),
 ('node_present','next_node',0x4da8,0x100b090fc),('node_absent','next_node',0x4dba,0x100cbae58),('candidate_decode','candidate',0x1d53,0x100c4d728),
 ('decode_dispatch','decode_setup',0x33a6,0x100c9eefc),('decode_return','decode_bytes',0x1583,0x100c1c2bc),
 ('word_equal','compare',0x4a6a,0x100cbae58),('word_other','compare',0x4a35,0x100bde374),('next_link','advance_node',0x7b2c,0x100bb5a9c),
 ('output_return','output_node',0x5354,0x100c0a0d4),('saved_search_return','return_search',0x261,0x100bac8d0),
 ('search_status_equal','search_status',0xc47d,0x100bb00c0),('search_status_other','search_status',0xa84e,0x100d30ab4),
 ('found_buffer','found_node',0xa885,0x100ca22c0),('found_no_buffer','found_node',0xa84e,0x100d30ab4),('missing_getter_return','missing_return',0x5eb8,0x100c45c98),
 ('saved_getter_return','lookup_return',0x116c,0x100c65c9c),('value_frontier','value_continuation',0x6043,0x100d281ac)]

def build():
 fragments={}
 for name,a in FRAGMENTS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic'] in ('braa','br','b','ret','retab','retaa');f['sha256']=h(bytes.fromhex(f['bytes']));fragments[name]=f
 prior=json.loads((ROOT/'daemon_xpc_records_source.json').read_text())
 for name,old in [('result','result'),('publish_result','publish_result'),('failure','failure')]:assert fragments[name]['bytes']==prior['fragments'][old]['bytes']
 prior=json.loads((ROOT/'daemon_xpc_payload_source.json').read_text())
 for name,old in [('loop_gate','record_loop_gate'),('nonempty','record_nonempty'),('minimum','record_minimum'),('extent','record_extent'),('cleanup','cleanup')]:assert fragments[name]['bytes']==prior['fragments'][old]['bytes']
 banks={}
 for name,pair,key,add in SPECS:
  r=selected(*pair,key,add);l,rr=IMAGE.read(pair[0],256),IMAGE.read(pair[1],256)
  r.update(left_bytes=l.hex(),right_bytes=rr.hex(),results_256=[i^rr[l[i]^key]for i in range(256)]);banks[name]=r
 slots={int(r['slot'],16)for r in banks.values()};calls=[]
 for name,pc in CALLS:
  r=banks[name];slot=int(r['slot'],16);ii=list(CS.disasm(IMAGE.read(pc-4,8),pc-4));assert ii[0].mnemonic=='mov'and ii[1].mnemonic=='blraa'
  mod=int(ii[0].op_str.split('#')[1],0);w=struct.unpack('<Q',IMAGE.read(slot,8))[0]
  assert w>>63 and(w>>32&65535)==mod and not(w>>48&1)and not(w>>49&3)
  calls.append({'role':name,'site':hex(pc),'slot':hex(slot),'target':r['target'],'modifier_u16':mod,'bytes':IMAGE.read(pc-4,8).hex(),'pointer_word':hex(w)})
 branches=[]
 for name,source,ix,target in BRANCHES:
  ii=fragments[source]['instructions'];assert ii[-1]['mnemonic']=='braa'and ii[-2]['mnemonic']=='mov';mod=int(ii[-2]['operands'].split('#')[1],0)
  slot=TABLE+8*ix;w=struct.unpack('<Q',IMAGE.read(slot,8))[0];assert qword(slot)==target and w>>63 and(w>>32&65535)==mod and not(w>>48&1)and not(w>>49&3)
  slots.add(slot);branches.append({'role':name,'source':source,'site':ii[-1]['ea'],'index':hex(ix),'slot':hex(slot),'target':hex(target),'modifier_u16':mod,'pointer_word':hex(w)})
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for a in slots:assert fresh[a]==FIXUPS[a]['line']
 headers=[SDK/'usr/include/stdint.h',SDK/'usr/include/stdlib.h',SDK/'usr/include/stddef.h']
 deps=['recover_daemon_xpc_records.py','daemon_xpc_records_source.json','daemon_xpc_records_checks.json','daemon_xpc_payload_source.json','daemon_xpc_payload_checks.json','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py']
 return {'generator_sha256':sha(__file__),'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},
  'fragments':fragments,'banks':banks,'calls':calls,'branches':branches,'imports':[binding(a)for a in sorted(slots)if isinstance(FIXUPS[a]['target'],str)],
  'selected_pointer_records':[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)],'original_pointer_checks':verify_original_fixups(slots),
  'fixup_reference':{'command':cmd,'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh),'selected_lines':{hex(a):fresh[a]for a in sorted(slots)}},
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],'inspection_tools':[{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')}],
  'verified_source_counts':{'fragments':len(fragments),'instructions':sum(len(f['instructions'])for f in fragments.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'bank_cases':len(banks),'bank_inputs_checked':256*len(banks),'resolved_calls':len(calls),'branch_bindings':len(branches),'imports':0,'selected_pointer_records':len(slots),'fixup_catalog_memberships_compared':len(fresh)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
