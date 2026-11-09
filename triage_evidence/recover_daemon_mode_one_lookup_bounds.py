#!/usr/bin/env python3
"""Recapture the original word-extension body for its69 byte-lookup bounds."""
import copy,json
from recover_daemon_mode_one_word_schedule import ROOT,FLAGS,build as previous_build
from verify_daemon_reader_record_payloads_publication import read,sha
P='daemon_mode_one_lookup_bounds'
SCOPE='All69 word-extension byte-access addresses bounded to the963-byte private scratch domain by source-linked normalization,checked local range transfers,four reciprocal lemmas and two universal divisor identities. Table values,complete recurrence,algorithm identity,caller publication and native exchange remain unknown.'
def build():
 old=previous_build();assert old==json.loads(read(ROOT/'daemon_mode_one_word_schedule_source.json'));s=copy.deepcopy(old)
 s.update(generator_sha256=sha(__file__),static_scope=SCOPE,parent_source_sha256=sha(ROOT/'daemon_mode_one_word_schedule_source.json'),parent_checks_sha256=sha(ROOT/'daemon_mode_one_word_schedule_checks.json'))
 s['dependencies'].update({n:sha(ROOT/n)for n in['daemon_mode_one_word_schedule_source.json','daemon_mode_one_word_schedule_checks.json','recover_daemon_mode_one_word_schedule.py']})
 return s
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
