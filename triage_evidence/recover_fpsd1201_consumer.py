#!/usr/bin/env python3
"""CoreFP1201 post-precomputation consumer records and first outgoing call.

Resume twelve independently audited private checkpoints. Prefix instructions
are not rerun in this increment. No target result or new diagnostic operand
is supplied; stop before the first unretained callee. O(I+C*(B+F+V+P*J+R))
time, O(I+B+F+C*(V+J+P+R)) space; SMT cost separate. Native lineage is open.
"""
import json,zlib,base64
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from recover_fpsd1201_reduction import Execute as Previous,sources as previous_sources
from recover_fpsd1201_import import ROOT,local_reference,RAM
from recover_fpsd1201_record import RECORD,OUT
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();WRAP=0x1142c08;CHILD=0x1142154
POINTS=[0x9819c4,WRAP,0x1142e08,CHILD,0x114228c,0x114245c]
DEPS=['fpsd1201_reduction_checks.json','fpsd1201_reduction_audit.json','fpsd1201_reduction_ida_readback.json',
 'recover_fpsd1201_reduction.py','audit_fpsd1201_reduction.py','corefp_library_inventory.json',
 'corefp_lookup_contracts.json','corefp_fixups_inventory.json','fpsd1201_record_checks.json']


def unpack(p):
    b=zlib.decompress(base64.b64decode(p['zlib_base64'],validate=True));assert len(b)==p['size_bytes']and SHA(b)==p['sha256'];return b


def sources():
    code,banks,D=previous_sources();a=json.loads(read(ROOT/'fpsd1201_consumer_ida_readback.json'))
    return code+[{**r,'role':role}for r,role in zip(a['spans'],['consumer_cursor_wrapper','consumer_implementation'])],banks,D


class Execute(Previous):
    def __init__(self,prior,index,code,banks,D):
        super().__init__(prior['configuration'],code[:19],banks,D);self.u.mem_map(0x1142000,4096)
        for r in code[19:]:
            a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        for row,(a,n)in zip(prior['final_RAM'],RAM):
            b=unpack(row['payload']);assert row['address']==hex(a)and len(b)==n;self.u.mem_write(a,b)
        f=prior['terminal']
        for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
        for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
        for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
        assert self.frame()==f and f['pc']=='0x9819c4'
        self.initial=f;self.initial_RAM=prior['final_RAM'];self.prior_index=index
        self.phase='consumer_checkpoint';self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.pac=[];self.points=[];self.used=set();self.consumer_points=[]
        self.consumer_record=self.reg(0);self.consumer_cursor=self.reg(1)
        j=next(j for j in reversed(range(len(prior['source_reads'])))if prior['source_reads'][j]['address']=='0x1d056a0')
        self.checkpoint_load={'prior_read_index':j,'read':prior['source_reads'][j],'source_visit':prior['source_visits'][prior['source_reads'][j]['visit']]}
    def view(self,pc):
        r=self.consumer_record;raw=self.ram(r,48);ptr=lambda j:int.from_bytes(raw[j:j+8],'little');q=ptr(0);pair=self.ram(q,24)
        descriptors={}
        for name,a in [('pair_first',int.from_bytes(pair[:8],'little')),('pair_second',int.from_bytes(pair[8:16],'little')),('output',ptr(8)),('auxiliary',ptr(24)),('input',ptr(32)),('modulus',ptr(40))]:
            d=self.ram(a,16);payload=int.from_bytes(d[8:],'little');valid=any(lo<=payload<payload+512<=lo+n for lo,n in RAM)
            descriptors[name]={'address':hex(a),'descriptor16_hex':d.hex(),'payload512_hex':self.ram(payload,512).hex()if valid else None}
        e={'pc':hex(pc),'CPU':self.frame(),'record_pointer':hex(r),'record48_hex':raw.hex(),'pair_pointer':hex(q),'pair24_hex':pair.hex(),'descriptors':descriptors,
          'caller_cursor_pointer':hex(self.consumer_cursor),'caller_cursor_u64':hex(int.from_bytes(self.ram(self.consumer_cursor,8),'little'))}
        if pc in [CHILD,0x114228c]:e.update({'child_cursor_pointer':hex(self.reg(1)),'child_cursor_u64':hex(int.from_bytes(self.ram(self.reg(1),8),'little'))})
        if pc==0x114245c:e.update({'outgoing_record_pointer':hex(self.reg(0)),'outgoing_record48_hex':self.ram(self.reg(0),48).hex(),'outgoing_cursor_pointer':hex(self.reg(1)),'outgoing_cursor_u64':hex(int.from_bytes(self.ram(self.reg(1),8),'little'))})
        return e
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in POINTS:self.consumer_points.append(self.view(pc))
        if pc==0x9819c4:
            slot=0x1d056a0;row=self.D[slot];assert(row['target'],row['diversity'],row['key'],row['address_diversity'])==('0x1142c08','0x4032','IA',0)
            assert(self.reg(8),self.reg(17))==(WRAP,0x4032)
            self.visits.append({'phase':self.phase,'pc':hex(pc),'bytes_hex':self.ram(pc,4).hex(),'instruction':'blraa x8, x17'})
            self.pac.append({'pc':hex(pc),'kind':'blraa','before':self.frame(),'target':hex(WRAP),'modifier':'0x4032','original_slot':hex(slot)})
            self.used.add(slot);self.setreg(30,pc+4);u.reg_write(A.UC_ARM64_REG_PC,WRAP);return
        return self.continued_hook(u,pc,n,data)
    def run(self):
        self.stop=None;self.frontier=None;self.u.emu_start(0x9819c4,0,count=10000);self.flush()
        assert self.stop=='unretained_callee'and self.frontier['pc']=='0x114245c'
        return {'configuration':self.c,'prior_profile_index':self.prior_index,'initial':self.initial,'initial_RAM':self.initial_RAM,'checkpoint_pointer_load':self.checkpoint_load,
          'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'PAC_models':self.pac,'CPU_points':self.points,
          'consumer_points':self.consumer_points,'terminal':self.terminal,'final_RAM':self.dump(),'stop_reason':self.stop,'frontier':self.frontier,
          'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],'final_delta_cell_u64':hex(int.from_bytes(self.ram(OUT,8),'little')),
          'final_status_u32':hex(int.from_bytes(self.ram(RECORD+0x30,4),'little')),'native_effects':False}


def proofs():
    p=z3.BitVec('consumer_record_low32',32);r=p^0x562bc3c0
    raw=(((r|0xf4a6b85c)-(r&0xf4a6b85c))^0xb5ebb641)*0xb7a7bfff
    s=z3.BitVec('consumer_cursor_seed',64);top=z3.LShR(s*0x2ec5+1,60);pad=((top<<4)+31)&0x1f0
    claims=[('consumer_record_mask',raw==(p^0x1766cddd)*0xb7a7bfff),('consumer_cursor_restore',s-240+240==s),
      ('consumer_padding_exact',pad==16*(top+1)),('consumer_padding_bounds',z3.And(z3.UGE(pad,16),z3.ULE(pad,256))),
      ('consumer_zero_adjustment',z3.Extract(15,0,s-240+240-s)==0)]
    out=[]
    for label,claim in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));result=str(q.check());assert result=='unsat'
        out.append({'label':label,'query':q.sexpr()+'\n(check-sat)\n','result':result,'timeout_ms':60000})
    return out


def main():
    code,banks,D=sources();reference=local_reference(code,banks,D);prior=json.loads(read(ROOT/'fpsd1201_reduction_checks.json'))
    profiles=[Execute(p,j,code,banks,D).run()for j,p in enumerate(prior['profiles'])if p['configuration']['operand_u32']]
    queries=proofs();counts={'profiles':len(profiles),'audited_checkpoints_resumed':len(profiles),'prefix_instructions_rerun':0,
      **{k:sum(len(p[k])for p in profiles)for k in ['source_visits','source_reads','source_writes','PAC_models','consumer_points']},
      'fresh_IDA_spans':2,'fresh_IDA_bytes':3292,'source_code_bytes':34332,'local_queries_unsat':len(queries)}
    e={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':queries,'reference_file_check':reference,'verified_counts':counts,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'generator_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'fpsd1201_consumer_ida_readback.json').encode()),'new_operand_controls_supplied':False,
      'whole_parent_replayed':False,'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_consumer_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
