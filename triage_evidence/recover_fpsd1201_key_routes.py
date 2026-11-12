#!/usr/bin/env python3
"""Pinned post-tuple mixing and selector-byte preparation frontiers.

Original instructions run only in private emulation. Source receipt restorations,
frozen prefix models, the request1200/status gap and selector controls are
explicit. No entropy/time return is newly supplied. O(C*(B+F+V+J+R)) is a
conservative time/space bound including per-case image setup;
each suffix is bounded by 30000 instruction visits. No native target/IPC runs.
"""
import json,copy
from pathlib import Path
from hashlib import sha256
import unicorn as U
from unicorn import arm64_const as A
from recover_fpsd1201_seed import Seed,restore,frame,pack
from audit_fpsd1201_predicates import unpack
from corefp_fixups_reader import Pointers,ROOT
from probe_corefp_client_flow import Flow
from probe_corefp_exports import BASE,BIND
from daemon_receive_tools import CS
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();FLAG=0x1d44409
SEED_SHA='05f265a5a9a3f04b379c83535bc353f51c93411b5c7a870d78dd271c36729ccf'
SEED_AUDIT_SHA='4f798f3a82df17360a8bd2541c0b0524399e95c8073402ffbfa45fd4d5ac575b'
DEPS=['fpsd1201_seed_checks.json','fpsd1201_seed_audit.json','fpsd1201_predicates_checks.json','fpsd1201_predicates_audit.json',
 'recover_fpsd1201_seed.py','audit_fpsd1201_seed.py','recover_fpsd1201_predicates.py','audit_fpsd1201_predicates.py',
 'probe_corefp_client_flow.py','probe_corefp_lookup.py','probe_corefp_mach_requests.py','probe_corefp_exports.py','corefp_library_reader.py',
 'corefp_fixups_reader.py','corefp_fixups_inventory.json','corefp_import_calls.json','fpsd1201_key_routes_ida_availability.json']
RANGES=[(0x8e81c8,0x8fcfa0),(0x1abbe0,0x1abc70),(0x439734,0x4397c0)]
POINTS={0x8ea8b0,0x8ea8ec,0x8eb7a4,0x8eaea0,0x8eaebc,0x8eb9b4,0x8ebb98,0x8ebbd8,
 0x1abbe0,0x8ebca4,0x439734,0x8ebe38,0x8ebe90,0x8eba44}


class Key(Seed):
    def begin(self,old,seed,c):
        self.prepare(old,{'stage':'entropy','token_u32':0x5d96,'random_u32':[]})
        self.c=c;self.prefix_refreshed=True;self.controls=[]
        if c['kind']=='post_tuple':
            q=next(p for p in seed['profiles']if p['configuration']['label']==c['label'])
            assert q['restored_CPU']==self.restored
            for row in q['final_RAM']:self.u.mem_write(int(row['address'],16),unpack(row['payload']))
            restore(self.u,q['frontier']['CPU']);self.restored=frame(self.u)
        else:
            a=BASE+FLAG;before=bytes(self.u.mem_read(a,1));assert before==b'\0'
            self.u.mem_write(a,bytes([c['selector_byte']]))
            self.controls=[{'address':hex(a),'before_hex':before.hex(),'after_hex':bytes([c['selector_byte']]).hex(),'reason':'declared selector-byte sensitivity input'}]
        self.steps=0;self.reason=None;self.pages={};self.trace=[];self.reads=[];self.writes=[];self.pending=[];self.pacs=[];self.points=[];self.models=[]
        self.initial=frame(self.u);self.touch(BASE+FLAG,1)
        sp=int(self.initial['SP'],16);self.touch(sp+0x1340,128);self.touch(sp+0x498,8)
        self.touch(int.from_bytes(self.u.mem_read(sp+0x498,8),'little'),32)
    def code(self,u,pc,n,d):
        if not getattr(self,'active',False):return super().code(u,pc,n,d)
        self.flush();at=pc-BASE
        if pc in self.binds:
            assert self.c['kind']=='selector'and self.binds[pc]['name']=='_arc4random'
            return self.finish('before_first_entropy_call')
        if at in POINTS:
            r=self.reg('x0');self.points.append({'pc':hex(at),'visit':len(self.trace),'CPU':frame(u),
              'record_pointer':hex(r),'record44_hex':bytes(u.mem_read(r,44)).hex()if at in [0x1abbe0,0x439734,0x8ebca4,0x8ebe38]else None})
        if at==0x8eba44:return self.finish('before_optional_key_word_read')
        if at==0x8eaebc:return self.finish('before_preparation_object_field_read')
        assert any(lo<=at<hi for lo,hi in RANGES),'unretained edge'
        raw=bytes(u.mem_read(pc,4));i=next(CS.disasm(raw,at));self.trace.append({'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str})
        if i.mnemonic=='casal':
            assert at==0x8ea868 and i.op_str=='w8, w11, [x12]';a=self.reg('x12');self.touch(a,4);old=int.from_bytes(u.mem_read(a,4),'little')
            compare=self.reg('w8');new=self.reg('w11');assert old==compare==0x5d96 and new==0xa94ef
            e={'kind':'declared_sequential_CASAL','visit':len(self.trace)-1,'address':hex(a),'old_u32':old,'compare_u32':compare,'replacement_u32':new,'before':frame(u)}
            u.mem_write(a,new.to_bytes(4,'little'));u.reg_write(A.UC_ARM64_REG_W8,old);u.reg_write(A.UC_ARM64_REG_PC,pc+4)
            e.update({'after':frame(u),'after4_hex':bytes(u.mem_read(a,4)).hex()});self.models.append(e);return
        if i.mnemonic in ['braa','blraa']:
            rn,mn=i.op_str.split(', ');target=self.reg(rn);modifier=self.reg(mn)
            r=next(r for r in reversed(self.reads)if r['size_B']==8 and int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')==target)
            slot=int(r['address'],16)-BASE;row=self.s.decoded[slot]
            resolved=BIND+row['import']['ordinal']*16+row['pointer_addend']if row['bind']else BASE+int(row['target'],16)
            assert row['key']=='IA'and not row['address_diversity']and int(row['diversity'],16)==modifier and resolved==target
            self.pacs.append({'visit':len(self.trace)-1,'pc':hex(at),'target':hex(target),'modifier':hex(modifier),'slot':hex(slot),'original_pointer_row':row,'CPU':frame(u)})
        return Flow.code(self,u,pc,n,d)
    def run_key(self):
        self.u.emu_start(int(self.initial['PC'],16),0,count=30001);self.flush()
        assert self.reason in ['before_first_entropy_call','before_optional_key_word_read','before_preparation_object_field_read']
        sp=int(self.initial['SP'],16)
        return {'configuration':self.c,'restored_CPU':self.restored,'controls':self.controls,'initial_CPU':self.initial,
          'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.trace,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'context128_hex':bytes(self.u.mem_read(sp+0x1340,128)).hex(),'tuple32_hex':bytes(self.u.mem_read(sp+0x1a30,32)).hex()}


def main():
    seed=json.loads(read(ROOT/'fpsd1201_seed_checks.json'));audit=json.loads(read(ROOT/'fpsd1201_seed_audit.json'))
    assert SHA(read(ROOT/'fpsd1201_seed_checks.json').encode())==SEED_SHA and SHA(read(ROOT/'fpsd1201_seed_audit.json').encode())==SEED_AUDIT_SHA
    assert audit['checks_sha256']==SEED_SHA and audit['fresh_replay_completed']and audit['result']['all_checks_pass']
    old=json.loads(read(ROOT/'fpsd1201_predicates_checks.json'));s=Pointers();out=[]
    configs=[{'kind':'post_tuple','label':label}for label in ['clock_A','clock_B','clock_error_no_write','clock_A_clobber']]
    configs +=[{'kind':'selector','label':'selector_'+str(v),'selector_byte':v}for v in [0,1,2,255]]
    for c in configs:
        p=Key(s,old['fixture']);p.begin(old,seed,c);out.append(p.run_key())
    counts={'profiles':len(out),'post_tuple_profiles':4,'selector_profiles':4,'prefix_original_visits_per_refresh':19717,
      **{k:sum(len(p[k])for p in out)for k in ['visits','reads','writes','PAC_models','models','points']}}
    e={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},
      'source_spans':[s.function(lo)for lo,hi in RANGES],'profiles':out,'verified_counts':counts,'request1200_gap_executed':False,
      'native_target_executed':False,'new_target_IDA_access':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_key_routes_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
