#!/usr/bin/env python3
"""Fresh source, byte/record/epoch and complete callback verification.

O(B+F+V+W+R) time/space plus nine bounded original callback executions and
six bounded solver queries. No native target, framework, Mach, driver or file
operation. API response bytes are explicit experiments, not hardware outputs.
"""
import base64
import hashlib
import json
import struct
import subprocess
import zlib
from adid_reader import Adid,ROOT,CS,SOURCE,FIXUPS,THIN_SHA,sha
from probe_adid_avp_packets import Packets,WATCH
from probe_adid_startup import unpack_records

MASK=(1<<32)-1


def independent_records(b):
    result=[];p=0
    while p<len(b):
        if p+10>len(b):return None
        key=int.from_bytes(b[p:p+4],'big');tag=int.from_bytes(b[p+4:p+6],'big');n=int.from_bytes(b[p+6:p+10],'big');q=p+10+n
        if q>len(b) or tag not in (0x50db,0x9777,0x8485) or tag==0x9777 and n!=4 or tag==0x8485 and n!=8:return None
        result.append((p,key,tag,b[p+10:q]));p=q
    return result


class Audit(Packets):
    def __init__(self,s,f,ck):
        self.count_gate_observations=[];self.count_initialization=[];self.before_method_counts=[]
        super().__init__(s,f,ck)
    def write(self,u,access,a,n,value,data):
        if a<=0x7a030954 and 0x7a030958<=a+n:self.count_initialization.append({'pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n,'hook_value':hex(value&((1<<(8*n))-1))})
        return super().write(u,access,a,n,value,data)
    def code(self,u,pc,n,data):
        if pc==0x10024e1d4:self.count_gate_observations.append({'pc':hex(pc),'loaded_u32':self.reg('w8'),'expected_u32':self.reg('w23'),'method_index':self.method_index})
        if pc==0x10024e1f8:self.count_gate_observations[-1]['target']=hex(self.reg('x8'))
        return super().code(u,pc,n,data)
    def packet_api(self,im):
        if im['name']=='_IOConnectCallStructMethod' and self.reg('w1')==100 and not self.method_index:
            ptr=self.caller_records[-1]['count_pointer'];self.before_method_counts.append({'pointer':hex(ptr),'value_u32':int.from_bytes(self.u.mem_read(ptr,4),'little')})
        return super().packet_api(im)


def audit_run(s,f,ck):
    q=Audit(s,json.loads(json.dumps(f)),ck);r=q.result();q.flush_packet_writes(q.reg('pc'));r.update({'packet_write_effects':q.packet_effects,'packet_read_observations':q.packet_reads,'watched_final_snapshots':q.snapshots(),'observed_method100_calls':q.method_index});return q,r


def main():
    checks=[]
    def check(value,label):
        assert value,label
        checks.append(label)
    read=lambda n:json.loads((ROOT/n).read_text());s=Adid();p=read('adid_avp_packet_profiles.json');c=read('adid_avp_packet_contracts.json');rows={r['fixture']['label']:r for r in p['profiles']};instructions={int(i['ea'],16):bytes.fromhex(i['bytes']) for i in p['original_instruction_records']};events={k:unpack_records(r) for k,r in rows.items()}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh provider identity')
    for source,name in [(p,'probe_adid_avp_packets.py'),(c,'recover_adid_avp_packets.py')]:
        check(source['generator_sha256']==sha((ROOT/name).read_bytes()),'generator source pin '+name)
        for n,h in source['dependencies'].items():check(sha((ROOT/n).read_bytes())==h,'dependency '+n)
    run=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(SOURCE)],check=True,capture_output=True);check(run.stdout==FIXUPS.read_bytes(),'independent original fixups')
    for i in p['original_instruction_records']:
        pc=int(i['ea'],16);raw=s.read(pc,4);d=next(CS.disasm(raw,pc));check(raw==instructions[pc] and (d.mnemonic,d.op_str)==(i['mnemonic'],i['operands']),'original instruction '+hex(pc))
    for f in p['original_functions']:
        a,z=int(f['start'],16),int(f['end'],16);check(s.bounds(a)==(a,z) and sha(s.read(a,z-a))==f['sha256'],'complete compiler range '+f['start'])
    for w in c['original_windows']:
        a,z=int(w['start'],16),int(w['end'],16);raw=s.read(a,z-a);ds=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)];check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'] and ds==w['instructions'],'complete source window '+w['start'])
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof source pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain proof '+proof['path'])
    baseline=bytes.fromhex(c['baseline_method100_request']['bytes144']);outer=independent_records(baseline);inner=independent_records(baseline[42:122]);check([(o,k,t,len(b)) for o,k,t,b in outer]==[(0,0x6125a127,0x8485,8),(18,0x7976211a,0x9777,4),(32,0xfd2821c7,0x50db,80),(122,0,0x50db,12)],'independent exact outer144-byte record layout');check([(o,k,t,len(b)) for o,k,t,b in inner]==[(0,0x197aefe2,0x9777,4),(14,0x70bf3591,0x9777,4),(28,0x8d0a2514,0x9777,4),(42,0xf6964e3e,0x9777,4),(56,0,0x50db,14)],'independent exact nested80-byte layout')
    totals={'retained_cases':len(rows),'additional_byte_audit_cases':0,'original_visits':0,'original_watched_writes':0,'declared_API_watched_effects':0,'retained_watched_reads':0,'outgoing_codec_bytes':0,'physical_codec_bytes':0,'parser_copy_bytes':0,'first_method100_calls':0,'subsequent_method100_calls':0,'completed_callbacks':0,'opaque_first_calls':0,'count_gate_cases':0,'typed_scalar_snapshots_checked':0};byte_inputs=set();subsequent=[]
    def validate_row(label,r,es):
        f=r['fixture'];visits=[v[0] for v in struct.iter_unpack('<Q',zlib.decompress(base64.b64decode(r['visited_original_instructions_zlib_base64'])))];h=hashlib.sha256()
        for pc in visits:h.update(struct.pack('<Q',pc));h.update(instructions[pc])
        totals['original_visits']+=len(visits);check(len(visits)==r['visited_original_instruction_count'] and h.hexdigest()==r['ordered_original_instruction_sha256'] and r['steps']<=800001,'complete bounded ordered source '+label)
        check(f['new_entry']==0x100029fc8 and f['instruction_or_frame_overrides'] is False and not any(e['kind'].startswith('analyst_') for e in es),'complete original callback without internal interventions '+label)
        io=[e for e in es if e['kind']=='original_method100_boundary'];check(io and len(io)<=2 and r['observed_method100_calls']==len(io),'bounded method count '+label);first=io[0];raw=bytes.fromhex(first['input_bytes']);x=[int(v,16) for v in first['args_x0_x7']];check(first['callsite']=='0x100058a1c' and x[:5]==[0x5804,100,0x7e000530,144,0x7e000530] and first['output_size_before_u64']==144,'first original shared144-byte Avp method ABI '+label);totals['first_method100_calls']+=1
        check(len([e for e in es if e.get('name')=='_IOServiceOpen'])==1,'one source connection open including follow-up '+label)
        diffs=[i for i,(a,b) in enumerate(zip(raw,baseline)) if a!=b];check(len(raw)==144 and all(94<=i<98 for i in diffs),'time/random finite influence confined to nested four-byte field '+label)
        out=[e for e in es if e['kind']=='original_outgoing_byte_codec'];check(len(out)==144 and [e['offset_bytes'] for e in out]==list(range(144)),'complete outgoing forward-copy extent '+label)
        reads=[e for e in r['packet_read_observations'] if e['watch']=='incoming_staging' and e['pc']=='0x10024b524' and e['method_calls_already_observed']==0];writes=[e for e in r['packet_write_effects'] if e.get('watch')=='outgoing_staging' and e.get('pc')=='0x10024b53c' and e['method_calls_already_observed']==0];check(len(reads)==len(writes)==144 and [e['offset_bytes'] for e in reads]==list(range(143,-1,-1)),'outgoing reverse physical-view extent '+label)
        for e,rd,wr in zip(out,reversed(reads),reversed(writes)):
            i=e['offset_bytes'];check(e['key_u32']==0xe8 and e['input_u8']^0xe8==e['output_u8']==raw[i] and bytes.fromhex(rd['bytes'])==raw[i:i+1] and bytes.fromhex(wr['after_bytes'])==bytes([raw[i]^0xe8]),'original paired outgoing byte representation '+label+' '+str(i));totals['outgoing_codec_bytes']+=1
        # Replay complete write preimages/effects in captured order. Windows
        # explicitly include unrelated allocator/reuse epochs; no object type
        # or single lifetime is inferred from the watched addresses.
        known={}
        def before_bytes(a,b,context):
            check(all(a+i not in known or known[a+i]==v for i,v in enumerate(b)),context)
        for e in r['packet_write_effects']:
            if e['kind']=='original_watched_write':
                totals['original_watched_writes']+=1;a=int(e['address'],16);before=bytes.fromhex(e['before_bytes']);after=bytes.fromhex(e['after_bytes']);check(len(before)==len(after)==e['size_bytes'] and int(e['pc'],16) in instructions,'original write extent/source '+label);before_bytes(a,before,'ordered write preimage '+label+' '+e['pc']);known.update({a+i:v for i,v in enumerate(after)})
            else:
                totals['declared_API_watched_effects']+=1;check(e['native_API_executed'] is False,'declared API effect boundary '+label)
                for name,a,n in WATCH:
                    old=e['before'][name];new=e['after'][name]
                    if old is not None:before_bytes(a,bytes.fromhex(old),'API preimage '+label+' '+name)
                    if new is None:
                        for i in range(n):known.pop(a+i,None)
                    else:known.update({a+i:v for i,v in enumerate(bytes.fromhex(new))})
        for name,a,n in WATCH:
            rawfinal=r['watched_final_snapshots'][name]
            if rawfinal is not None:before_bytes(a,bytes.fromhex(rawfinal),'final watched epoch '+label+' '+name)
        totals['retained_watched_reads']+=len(r['packet_read_observations'])
        responses=[e for e in es if e['kind']=='declared_packet_response_model'];payloads=[e['payload_bytes'] for e in es if e.get('name')=='_xpc_dictionary_set_data']
        if not responses:
            totals['opaque_first_calls']+=1;check(f['packet_response']['kind']=='opaque' and len(io)==1 and r['stop_reason']=='original_method100_opaque_boundary' and payloads==[],'opaque first API boundary '+label);return
        check(len(responses)==1,'one explicit response only '+label);response=bytes.fromhex(responses[0]['response_bytes']);n=len(response);check(responses[0]['result_u32']==0 and n==responses[0]['returned_size_bytes']<=144 and responses[0]['native_driver_response_validated'] is False,'response bytes/status/capacity scope '+label)
        ret=next(e for e in es if e['kind']=='original_packet_caller_return');check(ret['count_raw_u32']==n+0x46d726 and ret['pc']=='0x10002c134','source caller count/status return '+label);idx=visits.index(0x10024e1f8);check(visits[idx+1]==(0x10024e1fc if n==144 else 0x10024e244),'original count dispatch path '+label);totals['count_gate_cases']+=1
        codecs=[e for e in es if e['kind']=='original_physical_byte_codec' and e['method_calls_already_observed']==1];copies=[e for e in es if e['kind']=='original_parser_copy_codec']
        if n==144:
            check(len(codecs)==len(copies)==144 and [int(e['source_address'],16) for e in codecs]==list(range(0x7e010420,0x7e0104b0)) and [e['offset_bytes'] for e in copies]==list(range(143,-1,-1)),'complete received144-byte representation/copy extent '+label)
            for i,e in enumerate(codecs):check(e['mask_u32']==0xd0 and e['input_u8']==response[i] and e['output_u8']==(response[i]^0xe8),'original received physical byte '+label+' '+str(i));byte_inputs.add(e['input_u8']);totals['physical_codec_bytes']+=1
            for e in copies:
                i=e['offset_bytes'];check(e['key_u32']==0xe8 and e['input_u8']==(response[i]^0xe8),'original parser-input XOR byte '+label+' '+str(i));totals['parser_copy_bytes']+=1
            scalar_events=[e for e in es if e['kind']=='original_typed_parser_scalar' and e['method_calls_already_observed']==1];parsed=independent_records(response)
            if parsed is not None:
                for offset,key,tag,body in parsed:
                    length=next(e for e in scalar_events if e['pc']=='0x100260cd0' and int(e['registers']['x12'],16)==offset);keyevent=next(e for e in scalar_events if e['pc']=='0x100260d94' and int(e['registers']['x12'],16)==offset);tagevent=next(e for e in scalar_events if e['pc']=='0x100260e18' and int(e['registers']['x12'],16)==offset);check(int(length['registers']['x13'],16)==len(body) and (int(keyevent['registers']['x11'],16)+int(keyevent['registers']['x10'],16))&MASK==(key+0x46d726)&MASK and int(tagevent['registers']['x11'],16)&65535==((tag^0x5a47)+16)&65535,'original typed header arithmetic '+label+' '+str(offset));totals['typed_scalar_snapshots_checked']+=3
                for tag,pc,width,xor in [(0x8485,'0x100262090',8,0xf048dd51c8511450),(0x9777,'0x100260f28',4,None)]:
                    bodies=[b for _,_,t,b in parsed if t==tag];observed=[e for e in scalar_events if e['pc']==pc]
                    if bodies:
                        expected=int.from_bytes(bodies[0],'big');expected=expected^xor if xor is not None else (expected+0x46d726)&MASK;check(observed and int(observed[0]['registers']['x8'],16)==expected,'original typed scalar encoding '+label+' '+str(width));totals['typed_scalar_snapshots_checked']+=1
        else:check(copies==[],'short count does not reach first response parser-copy '+label)
        if len(io)==2:
            totals['subsequent_method100_calls']+=1;second=io[1];b=bytes.fromhex(second['input_bytes']);x=[int(v,16) for v in second['args_x0_x7']];layout=independent_records(b);check(n<144 and r['stop_reason']=='original_subsequent_method100_boundary' and x[:5]==[0x5804,100,0x7e0004f0,320,0x7e0004f0] and second['output_size_before_u64']==320 and payloads==[],'original source-built320-byte follow-up without response '+label);check([(o,k,t,len(b)) for o,k,t,b in layout]==[(0,0x6125a127,0x8485,8),(18,0x7976211a,0x9777,4),(32,0xfd2821c7,0x50db,256),(298,0,0x50db,12)],'independent320-byte outer framing '+label);subsequent.append({'label':label,'bytes320':b.hex(),'outer_records':[(o,hex(k),hex(t),len(v)) for o,k,t,v in layout],'nested256_records':[(o,hex(k),hex(t),len(v),v.hex()) for o,k,t,v in independent_records(layout[2][3])]})
        else:
            totals['completed_callbacks']+=1;bad=label in ('response_ramp0','response_byte_high144','response_patch_tag0','response_patch_length_max','response_patch_nested_tag0');check(n==144 and r['stop_reason']=='returned_to_private_fixture' and payloads==['ffff5802' if bad else 'ffff5805'],'retained completed response control '+label);check([e['callsite'] for e in es if e.get('name')=='_xpc_dictionary_set_data']==['0x1000aa9fc'] and [e['callsite'] for e in es if e.get('name')=='_xpc_dictionary_send_reply']==['0x1000aaa70'],'original outgoing XPC reply sites '+label)
    for label,r in rows.items():validate_row(label,r,events[label])
    ck=read('adid_peer_checkpoint.json');replays=['packet_opaque','packet_identity','time_0xffffffffffffffff','random_0x7ffffffe','response_prefix_0','response_prefix_143','response_ramp0','response_patch_nested_tag0'];fresh_steps=0;audits=[]
    for label in replays:
        q,r=audit_run(s,rows[label]['fixture'],ck);fresh_steps+=r['steps'];check(r['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and r['stop_reason']==rows[label]['stop_reason'] and unpack_records(r)==events[label] and r['packet_write_effects']==rows[label]['packet_write_effects'] and r['packet_read_observations']==rows[label]['packet_read_observations'] and r['watched_final_snapshots']==rows[label]['watched_final_snapshots'],'fresh full source/event/write/read/epoch replay '+label);check(q.before_method_counts==[{'pointer':'0x7a030954','value_u32':0x46d726}],'fresh original caller count initialized before API '+label)
        for e in q.count_gate_observations:check(e['expected_u32']==0x46d7b6 and e['target']==('0x10024e1fc' if e['loaded_u32']==e['expected_u32'] else '0x10024e244'),'fresh count operands and original target '+label)
        audits.append({'label':label,'count_before_first_method':q.before_method_counts,'original_count_writes':q.count_initialization,'count_gates':q.count_gate_observations})
    f=json.loads(json.dumps(rows['response_ramp0']['fixture']));f['label']='response_byte_high144';f['packet_response']={'kind':'bytes','bytes':(bytes(range(144,256))+bytes(32)).hex()};q,r=audit_run(s,f,ck);fresh_steps+=r['steps'];check(all(int(i['ea'],16) in instructions and bytes.fromhex(i['bytes'])==s.read(int(i['ea'],16),4) for i in r['instruction_records']),'additional byte-audit complete original source membership');validate_row(f['label'],r,unpack_records(r));totals['additional_byte_audit_cases']=1;check(byte_inputs==set(range(256)),'all256 received byte values exercised through original codec');(ROOT/'adid_avp_packet_byte_audit.json').write_text(json.dumps(r,indent=2)+'\n')
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'original input preserved '+row['path'])
    check(len({item['bytes320'] for item in subsequent})==1,'all retained320-byte follow-up packets are identical')
    def shape(rows):return [(o,k,t,len(v)) for o,k,t,v in rows]
    full=independent_records(bytes.fromhex(subsequent[0]['bytes320']));nested256=independent_records(full[2][3]);nested176=independent_records(nested256[3][3]);nested128=independent_records(nested176[1][3])
    check(shape(nested256)==[(0,0x197aefe2,0x9777,4),(14,0x70bf3591,0x9777,4),(28,0x8d0a2514,0x9777,4),(42,0x351bdea7,0x50db,176),(228,0xf6964e3e,0x9777,4),(242,0,0x50db,4)],'complete follow-up256-byte structural nesting')
    check(shape(nested176)==[(0,0x7976211a,0x9777,4),(14,0xfd2821c7,0x50db,128),(152,0,0x50db,14)],'complete follow-up176-byte structural nesting')
    check(shape(nested128)==[(0,0xfa834112,0x9777,4),(14,0xf6964e3e,0x9777,4),(28,0xf8910ace,0x50db,16),(54,0xf547819e,0x50db,32),(96,0xf8819aec,0x9777,4),(110,0,0x50db,8)],'complete follow-up128-byte structural nesting')
    for audit in audits:check(audit['original_count_writes'][0]=={'pc':'0x10016839c','address':'0x7a030954','size_bytes':4,'hook_value':'0x46d726'},'original encoded-zero count initialization store '+audit['label'])
    verified={**totals,'original_instruction_records':len(instructions),'complete_compiler_ranges':len(p['original_functions']),'source_windows':len(c['original_windows']),'new_SMT_unsat':len(c['proofs']),'received_byte_domain':len(byte_inputs),'fresh_callback_runs':len(replays)+1,'fresh_callback_steps':fresh_steps,'assertions':len(checks)}
    out={'scope':__doc__,'verified_counts':verified,'checks':checks,'fresh_count_gate_audits':audits,'source_built_followup_packets':subsequent,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_avp_packet_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    texts=['Descriptive source/packet analysis.','Report P1-P10 state assumptions,dependent results and falsification probes.','Retained full request/packet/response/count interfaces covered;full native architectural goal incomplete.','Full8/16/32/64-bit arithmetic,explicit byte extents and seconds;bounded workflow complexity.','Allocation/reuse epochs,typed framing versus accepted protocol,144 versus320,opaque state and non-native responses separated.','Fresh original bytes/fixups,independent record/byte/ledger oracles,six proofs,nine callbacks and256 received byte values.','Impact-labeled Avp implementation,full command/response schemas,opaque state transform,320-byte continuation,native ports/rights/driver pairing.'];quality={'scope':'Local source-built Avp packet,typed parser and explicit response/control interfaces only.','verified_counts':verified,'native_target_executed':False,'full_goal_complete':False}
    for i,t in enumerate(texts,1):quality['QG'+str(i)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'adid_avp_packet_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(verified))


if __name__=='__main__':main()
