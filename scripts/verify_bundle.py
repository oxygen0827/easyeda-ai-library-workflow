#!/usr/bin/env python3
"""Offline checks for published artifacts; does not operate the EDA client."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / 'VibeHard_AI_Library_Trial_TPS54331DR_20261111'


def require(condition, message):
    if not condition:
        raise SystemExit('FAIL: ' + message)


def load(name):
    return json.loads((ROOT / name).read_text(encoding='utf-8'))


def records(raw):
    decoder = json.JSONDecoder()
    for line in raw.decode('utf-8').splitlines():
        if not line:
            continue
        require('||' in line, 'native record delimiter')
        header, body = line.split('||', 1)
        json.loads(header)
        if body.startswith('|') or not body.strip():
            continue  # native empty/deletion record
        obj, end = decoder.raw_decode(body)
        require(body[end:].strip() in ('', '|'), 'native record suffix')
        yield obj


def audit(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in {'user', 'owner', 'creator', 'modifier',
                       'owner_uuid', 'creator_uuid', 'modifier_uuid'}:
                require(value in ('', None) or value == {}, 'nonempty author metadata')
            audit(value)
    elif isinstance(obj, list):
        for value in obj:
            audit(value)


def main():
    entries = load('FILE_MANIFEST.json')['files']
    for item in entries:
        path = ROOT / item['file']
        require(path.is_file(), 'missing file: ' + item['file'])
        data = path.read_bytes()
        require(len(data) == item['bytes'], 'file size: ' + item['file'])
        require(hashlib.sha256(data).hexdigest() == item['sha256'],
                'SHA256: ' + item['file'])

    for item in load('project-manifest.json'):
        data = (PROJECT / item['file']).read_bytes()
        require(hashlib.sha256(data).hexdigest() == item['sha256'], 'project SHA')

    with zipfile.ZipFile(ROOT / 'TPS54331DR_AI_TRIAL.elibz2') as z:
        require(z.testzip() is None, 'device ZIP CRC')
        meta = json.loads(z.read('device2.json'))
        require([len(meta[k]) for k in ('devices', 'symbols', 'footprints')] == [1, 1, 1],
                'one Device, one Symbol, one Footprint')
        audit(meta)
        dev = next(iter(meta['devices'].values()))
        require(dev['attributes']['Symbol'] in meta['symbols'], 'symbol reference')
        require(dev['attributes']['Footprint'] in meta['footprints'], 'footprint reference')
        for name in z.namelist():
            if name.endswith('.elibu'):
                for obj in records(z.read(name)):
                    audit(obj)

    with zipfile.ZipFile(ROOT / 'ai-library-builder_v2.9.2_zh-cn.eext') as z:
        require(z.testzip() is None, 'extension ZIP CRC')
    for path in PROJECT.rglob('*'):
        if path.suffix in {'.esch2', '.epcb2', '.ecfg', '.epan2'}:
            for obj in records(path.read_bytes()):
                audit(obj)
        elif path.suffix == '.eprj3':
            audit(json.loads(path.read_text()))

    s = load('symbol-device-associated-api.json')
    require(s['ok'] and s['value']['saved'], 'symbol save evidence')
    pins = s['value']['pins']
    require(len(pins) == 8, 'eight symbol pins')
    require({p['pinNumber']: p['pinName'] for p in pins} == load('test-input.json')['pins'],
            'symbol names and numbering')
    require(s['value']['device']['association']['footprintUuid'] in meta['footprints'],
            'associated footprint evidence')
    p = load('pcb-pins-api.json')
    require(p['ok'] and len(p['value']['components']) == 1, 'one PCB component')
    pads = p['value']['pins']
    require(len(pads) == 8 and {p['padNumber'] for p in pads} == set('12345678'),
            'PCB pad numbers 1-8')
    require(all(abs(p['pad'][1] * .0254 - 1.55) < .003
                and abs(p['pad'][2] * .0254 - .60) < .003 for p in pads),
            'corrected copper dimensions in evidence')
    require(load('schematic-placement-final-api.json')['value']['saved'], 'schematic save')
    require(load('pcb-placement-api.json')['value']['saved'], 'PCB save')

    # Check our portable text, excluding unchanged upstream documentation/package.
    for item in entries:
        name = item['file']
        if name.startswith('third-party/') or Path(name).suffix not in {
                '.json', '.md', '.eprj3', '.esch2', '.epcb2', '.ecfg', '.epan2'}:
            continue
        text = (ROOT / name).read_text()
        require(not re.search(r'/(?:Users|Volumes)/', text), 'absolute local path: ' + name)
        require(not re.search(r'(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,})', text),
                'credential-like string: ' + name)
    print(f'PASS: {len(entries)} file hashes; project hashes; ZIP CRC; native JSON structure;')
    print('      1 Device + 1 Symbol + 1 Footprint; evidence: 8 symbol pins and 8 PCB pads.')
    print('No live client import/open, DRC, or production approval is implied.')


if __name__ == '__main__':
    main()
