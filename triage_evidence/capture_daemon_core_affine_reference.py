#!/usr/bin/env python3
"""Capture the pinned NIST Table 4 from PDF bytes; optional read-only HTTPS.
O(PDF bytes + extracted text) time/space. No target operation.
"""
import argparse
import json
import re
import subprocess
import urllib.request
from hashlib import sha256
from pathlib import Path

URL = 'https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf'
FETCH_URL = 'https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=936594'
PDF_SHA = '62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1'


def capture(data):
    assert len(data) == 1184436 and sha256(data).hexdigest() == PDF_SHA
    text = subprocess.run(['pdftotext', '-layout', '-', '-'], input=data, capture_output=True, check=True).stdout.decode()
    table = text[text.index('Table 4.'):].split('the substitution value', 1)[0]
    rows = []
    for line in table.splitlines():
        words = line.split()
        if words[:1] == ['x']: words = words[1:]
        if len(words) == 17 and re.fullmatch('[0-9a-f]', words[0]) and all(re.fullmatch('[0-9a-f]{2}', w) for w in words[1:]):
            assert int(words[0], 16) == len(rows); rows.append(bytes.fromhex(''.join(words[1:])))
    assert len(rows) == 16
    return {'title': 'FIPS 197-upd1, Advanced Encryption Standard', 'DOI': '10.6028/NIST.FIPS.197-upd1',
            'URL': URL, 'official_alternate_URL': FETCH_URL, 'PDF_sha256': PDF_SHA, 'PDF_bytes': len(data),
            'table': 'Table 4; printed page 14; PDF page index 21', 'table256_hex': b''.join(rows).hex(),
            'rows_parsed_from_pinned_PDF': 16, 'capture_tool_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
            'offline_auditor_refetches_PDF': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--pdf', type=Path); args = parser.parse_args()
    data = args.pdf.read_bytes() if args.pdf else urllib.request.urlopen(
        urllib.request.Request(FETCH_URL, headers={'User-Agent': 'Mozilla/5.0'}), timeout=30).read()
    r = capture(data)
    (Path(__file__).resolve().parent/'daemon_core_affine_reference.json').write_text(json.dumps(r, indent=2)+'\n')
    print(json.dumps({'PDF_sha256': r['PDF_sha256'], 'rows_parsed': len(bytes.fromhex(r['table256_hex']))}), flush=True)
