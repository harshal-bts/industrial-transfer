"""NON-PRODUCTION reference: immutable encrypted chunks, signed manifest and receipt.
Run ONLY against test directories. No delete, format, move, or overwrite operation.
No network transport, USB identity enforcement, malware scanner, or production key vault.
"""
import base64, hashlib, json, os, re, stat, uuid, zlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK = 4 * 1024 * 1024

def b64(x): return base64.b64encode(x).decode('ascii')
def unb64(x): return base64.b64decode(x, validate=True)
def sha(x): return hashlib.sha256(x).hexdigest()
def canonical(obj): return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def assert_plain(path):
    # Basic demo checks only; not a substitute for handle-based OS confinement.
    p = Path(path).absolute()
    for item in (p, *p.parents):
        if item.exists() or item.is_symlink():
            s = item.lstat()
            if item.is_symlink() or getattr(s, 'st_file_attributes', 0) & 0x400:
                raise ValueError('Symlink or reparse point prohibited')
    return p

def create_once(path, data):
    path = assert_plain(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('xb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
    except FileExistsError:
        if not path.is_file() or path.read_bytes() != data:
            raise RuntimeError(f'Existing file differs; preserved: {path}')
    return path

def safe_rel(name):
    parts = name.split('/')
    if not parts or any(not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_. -]*', p) or p.endswith(('.', ' ')) or p.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))} for p in parts):
        raise ValueError('Unsafe filename (demo uses restricted portable names)')
    return Path(*parts)

def seal(obj, signing_key):
    return canonical({'body': obj, 'signature': b64(signing_key.sign(canonical(obj)))})

def verify(blob, public_key):
    doc = json.loads(blob)
    public_key.verify(unb64(doc['signature']), canonical(doc['body']))
    return doc['body']

def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

def package(source, spool, sender_id, sender_sign, receiver_pub):
    source, spool = assert_plain(source), assert_plain(spool)
    if not source.is_dir(): raise ValueError('Source directory missing')
    if source == spool or source in spool.parents or spool in source.parents:
        raise ValueError('Source and spool must be separate directory trees')
    tid = str(uuid.uuid4()); root = spool / tid
    root.mkdir(parents=True, exist_ok=False)
    key = AESGCM.generate_key(bit_length=256); aes = AESGCM(key)
    files = []; index = 0; names = set()
    # Freeze candidate paths before packaging; OEM completion/snapshot still required.
    inventory = sorted(source.rglob('*'))
    for p in inventory:
        assert_plain(p)
        if p.is_dir(): continue
        if not stat.S_ISREG(p.stat().st_mode): raise ValueError('Not a regular file')
        rel = p.relative_to(source).as_posix(); safe_rel(rel)
        if rel.casefold() in names: raise ValueError('Case-insensitive filename collision')
        names.add(rel.casefold()); chunks = []; digest = hashlib.sha256(); size = 0
        before = p.stat()
        with p.open('rb') as f:
            while (raw := f.read(CHUNK)):
                digest.update(raw); size += len(raw)
                compressed = zlib.compress(raw, 1)
                codec, payload = ('zlib', compressed) if len(compressed) < len(raw) else ('none', raw)
                meta = {'index': index, 'codec': codec, 'plainSize': len(raw), 'plainHash': sha(raw)}
                nonce = os.urandom(12)
                ciphertext = aes.encrypt(nonce, payload, canonical({'transferId': tid, **meta}))
                chunk = nonce + ciphertext
                name = f'{index:012d}.bin'
                create_once(root / 'chunks' / name, chunk)
                chunks.append({**meta, 'name': name, 'cipherHash': sha(chunk), 'cipherSize': len(chunk)})
                index += 1
        after = p.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or size != before.st_size:
            raise RuntimeError('Source changed during export; package left uncommitted')
        files.append({'path': rel, 'size': size, 'sha256': digest.hexdigest(), 'chunks': chunks})
    # Manifest is encrypted too, so filenames and plaintext hashes are not on the USB in cleartext.
    inner = canonical({'files': files}); nonce = os.urandom(12)
    encrypted_manifest = nonce + aes.encrypt(nonce, inner, tid.encode())
    outer = {'version': 1, 'transferId': tid, 'senderId': sender_id,
             'wrappedKey': b64(receiver_pub.encrypt(key, oaep())),
             'encryptedManifest': b64(encrypted_manifest),
             'chunks': [{'name': c['name'], 'sha256': c['cipherHash'], 'size': c['cipherSize']} for f in files for c in f['chunks']]}
    create_once(root / 'manifest.signed.json', seal(outer, sender_sign))
    return root

def forward(src, dest_parent, sender_pub):
    src, dest_parent = assert_plain(src), assert_plain(dest_parent)
    blob = assert_plain(src / 'manifest.signed.json').read_bytes(); outer = verify(blob, sender_pub)
    tid = str(uuid.UUID(outer['transferId']))
    dest = assert_plain(dest_parent / tid)
    if dest == src or src in dest.parents or dest in src.parents: raise ValueError('Overlapping paths')
    for c in outer['chunks']:
        if not re.fullmatch(r'\d{12}\.bin', c['name']): raise ValueError('Bad chunk name')
        raw = assert_plain(src / 'chunks' / c['name']).read_bytes()
        if len(raw) != c['size'] or sha(raw) != c['sha256']: raise ValueError('Corrupt chunk')
        create_once(dest / 'chunks' / c['name'], raw)
    create_once(dest / 'manifest.signed.json', blob)
    return dest

def ingest_quarantine(src, quarantine_parent, sender_pub, receiver_key):
    src, quarantine_parent = assert_plain(src), assert_plain(quarantine_parent)
    blob = assert_plain(src / 'manifest.signed.json').read_bytes(); outer = verify(blob, sender_pub)
    tid = str(uuid.UUID(outer['transferId'])); aes = AESGCM(receiver_key.decrypt(unb64(outer['wrappedKey']), oaep()))
    enc = unb64(outer['encryptedManifest']); manifest = json.loads(aes.decrypt(enc[:12], enc[12:], tid.encode()))
    dest = assert_plain(quarantine_parent / tid)
    if dest == src or src in dest.parents or dest in src.parents: raise ValueError('Overlapping paths')
    dest.mkdir(parents=True, exist_ok=True)
    for f in manifest['files']:
        path = assert_plain(dest / safe_rel(f['path'])); path.parent.mkdir(parents=True, exist_ok=True)
        # Existing files are verified, never overwritten. Partial files need a new quarantine attempt directory.
        digest = hashlib.sha256(); size = 0
        def plaintext_chunks():
            for c in f['chunks']:
                if not re.fullmatch(r'\d{12}\.bin', c['name']): raise ValueError('Bad chunk name')
                raw = assert_plain(src / 'chunks' / c['name']).read_bytes()
                if sha(raw) != c['cipherHash'] or len(raw) != c['cipherSize']: raise ValueError('Cipher mismatch')
                meta = {k: c[k] for k in ('index','codec','plainSize','plainHash')}
                data = aes.decrypt(raw[:12], raw[12:], canonical({'transferId': tid, **meta}))
                if c['codec'] == 'zlib':
                    d = zlib.decompressobj(); data = d.decompress(data, CHUNK + 1)
                    if not d.eof or d.unused_data or d.unconsumed_tail: raise ValueError('Invalid compressed chunk')
                elif c['codec'] != 'none': raise ValueError('Unknown codec')
                if len(data) > CHUNK or len(data) != c['plainSize'] or sha(data) != c['plainHash']: raise ValueError('Plain mismatch')
                yield data
        if path.exists():
            with path.open('rb') as existing:
                for data in plaintext_chunks():
                    if existing.read(len(data)) != data: raise RuntimeError('Existing quarantine file differs; preserved')
                    digest.update(data); size += len(data)
                if existing.read(1): raise RuntimeError('Existing file longer than expected')
        else:
            with path.open('xb') as target:
                for data in plaintext_chunks():
                    target.write(data); digest.update(data); size += len(data)
                target.flush(); os.fsync(target.fileno())
        if size != f['size'] or digest.hexdigest() != f['sha256']: raise ValueError('File hash mismatch')
    return {'transferId': tid, 'senderId': outer['senderId'], 'manifestHash': sha(blob), 'status': 'QUARANTINE_VERIFIED'}

def self_test(base):
    base = Path(base).absolute() / str(uuid.uuid4())
    source = base / 'source'; source.mkdir(parents=True)
    create_once(source / 'sample.bin', b'geospatial data demo\x00' * 300000)
    create_once(source / 'empty.txt', b'')
    sign = ed25519.Ed25519PrivateKey.generate(); receiver = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pkg = package(source, base / 'spool', 'DEMO-01', sign, receiver.public_key())
    media = forward(pkg, base / 'simulated_usb', sign.public_key())
    incoming = forward(media, base / 'incoming', sign.public_key())
    assert forward(media, base / 'incoming', sign.public_key()) == incoming
    result = ingest_quarantine(incoming, base / 'quarantine', sign.public_key(), receiver)
    assert ingest_quarantine(incoming, base / 'quarantine', sign.public_key(), receiver) == result
    assert (source / 'sample.bin').read_bytes() == (base / 'quarantine' / result['transferId'] / 'sample.bin').read_bytes()
    try: create_once(source / 'sample.bin', b'overwrite attempt')
    except RuntimeError: pass
    else: raise AssertionError('Overwrite not blocked')
    # A demo signature on quarantine status is NOT a commit receipt and cannot authorize USB cleanup.
    server_sign = ed25519.Ed25519PrivateKey.generate()
    assert verify(seal(result, server_sign), server_sign.public_key()) == result
    print('PASS: encryption, manifest signature, forward retry, quarantine validation, overwrite denial. No cleanup performed.')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('demo_directory', help='A dedicated disposable test directory; files will be retained')
    self_test(parser.parse_args().demo_directory)
