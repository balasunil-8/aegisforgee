"""CTF manager: create, list and read simple CTF challenge packages.

This is a lightweight generator intended for PentestLab demos.

Functions:
- generate_challenge(kind, title, seed): create a challenge folder under `ctf_challenges/` and returns metadata
- list_challenges(): return index of created challenges
"""
from pathlib import Path
import json
import os
import uuid
from datetime import datetime

BASE = Path('ctf_challenges')
INDEX = BASE / 'index.json'

def _ensure_base():
    BASE.mkdir(exist_ok=True)
    if not INDEX.exists():
        INDEX.write_text(json.dumps({'challenges': []}, indent=2))

def _append_index(meta: dict):
    data = json.loads(INDEX.read_text())
    data['challenges'].append(meta)
    INDEX.write_text(json.dumps(data, indent=2))

def generate_challenge(kind: str, title: str, seed: str | None = None) -> dict:
    """Generate a simple CTF challenge artifact set.

    kind: one of 'crypto', 'stego', 'forensics', 'misc'
    title: human title
    seed: optional seed for reproducibility
    """
    _ensure_base()
    cid = f"CTF-{uuid.uuid4().hex[:12]}"
    folder = BASE / cid
    folder.mkdir(exist_ok=True)

    meta = {
        'id': cid,
        'title': title,
        'kind': kind,
        'created_at': datetime.utcnow().isoformat(),
        'files': []
    }

    # create sample artifacts per kind
    if kind == 'crypto':
        # create a simple RSA low-exponent challenge (like SmallE)
        ct = "4652121890751460900709921504073694332584482559616458809744327"
        sample_py = f"""# SmallE-style challenge sample\nct = {ct}\n# find integer cube root to recover flag\n"""
        p = folder / 'crypto_challenge.py'
        p.write_text(sample_py)
        meta['files'].append(str(p.name))

    elif kind == 'stego':
        # produce a text file containing base64 start (simulating hq.txt)
        b64 = 'iVBORw0KGgoAAAANSUhEUgAA'  # truncated PNG header
        p = folder / 'hq.txt'
        p.write_text(b64)
        meta['files'].append(str(p.name))

    elif kind == 'forensics':
        # produce an obfuscated-js snippet extracted from a PDF
        js = "var _0x870b='\\x48\\x51\\x58{...}'; // sample"
        p = folder / 'embedded_js.txt'
        p.write_text(js)
        meta['files'].append(str(p.name))

    else:
        p = folder / 'note.txt'
        p.write_text('This is a placeholder CTF challenge created by PentestLab')
        meta['files'].append(str(p.name))

    # write metadata
    with open(folder / 'meta.json', 'w', encoding='utf-8') as fh:
        json.dump(meta, fh, indent=2)

    # update global index
    _append_index(meta)
    return meta

def list_challenges() -> list:
    _ensure_base()
    data = json.loads(INDEX.read_text())
    return data.get('challenges', [])

def read_challenge(cid: str) -> dict | None:
    folder = BASE / cid
    meta = folder / 'meta.json'
    if not meta.exists():
        return None
    return json.loads(meta.read_text())

if __name__ == '__main__':
    print('CTF manager available. Existing challenges:')
    for c in list_challenges():
        print(c['id'], c['title'], c['kind'])
