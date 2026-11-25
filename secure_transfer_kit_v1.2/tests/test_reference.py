import unittest, tempfile, sys, uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import transfer_demo as t
from examples.cleanup_policy import Evidence, evaluate, cleanup
from examples.eta import ETA
from examples.usb_probe import sample_probe
from examples.smb_native import copy_verified
from examples.stream_zip import synthetic_demo
from examples.checkpoint import record, read_events
from examples.authentication import hash_password, verify_password
from legacy.ui_v2 import Job
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.exceptions import InvalidSignature

class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Retain all test artifacts; no TemporaryDirectory automatic cleanup.
        cls.root=Path(tempfile.mkdtemp(prefix='industrial-transfer-tests-'))
    def fresh(self):
        p=self.root/uuid.uuid4().hex; p.mkdir(); return p
    def test_roundtrip(self): t.self_test(self.fresh())
    def test_immutable_conflict(self):
        p=self.fresh()/'data'; t.create_once(p,b'original')
        with self.assertRaises(RuntimeError): t.create_once(p,b'changed')
        self.assertEqual(p.read_bytes(),b'original')
    def test_signature_tamper(self):
        s=ed25519.Ed25519PrivateKey.generate(); blob=t.seal({'status':'A'},s)
        with self.assertRaises(InvalidSignature): t.verify(blob.replace(b'"A"',b'"B"'),s.public_key())
    def test_invalid_paths(self):
        for p in ('../escape','a/../../b','C:/a','CON.txt','a\\b','a/','a./b'):
            with self.subTest(p=p), self.assertRaises(ValueError): t.safe_rel(p)
    def test_probe(self):
        p=self.fresh()
        with self.assertRaises(PermissionError): sample_probe(p,1)
        t.create_once(p/'LAB_ONLY.marker',b'test')
        self.assertEqual(sample_probe(p,1)['status'],'SAMPLE_PASSED')
    def test_copy_retry(self):
        p=self.fresh(); src=t.create_once(p/'src',b'payload'); dst=p/'dst'
        self.assertEqual(copy_verified(src,dst,t.sha(b'payload')),'VERIFIED')
        self.assertEqual(copy_verified(src,dst,t.sha(b'payload')),'ALREADY_VERIFIED')
        bad=t.create_once(p/'bad',b'partial')
        with self.assertRaises(FileExistsError): copy_verified(src,bad,t.sha(b'payload'))
        self.assertEqual(bad.read_bytes(),b'partial')
    def test_cleanup_disabled(self):
        self.assertFalse(evaluate(Evidence()))
        with self.assertRaises(PermissionError): cleanup()
    def test_eta(self):
        e=ETA(); e.update(0,0); e.update(10,100)
        self.assertEqual(e.estimate(200),10); self.assertIsNone(e.estimate(200,False))
    def test_stream_zip(self): self.assertGreater(synthetic_demo(),0)
    def test_checkpoint(self):
        p=self.fresh(); t.create_once(p/"LAB_ONLY.marker",b"test"); tid=str(uuid.uuid4())
        record(p,tid,"VERIFIED",100); record(p,tid,"PAUSED",100)
        self.assertEqual(len(read_events(p,tid)),2)
    def test_auth_example(self):
        r=hash_password("test-only"); self.assertTrue(verify_password("test-only",r)); self.assertFalse(verify_password("wrong",r))
    def test_ui_state(self):
        for mode in ("Export to USB","Import from USB","Network transfer"):
            j=Job(mode); j.start(); j.fail_preflight(); self.assertEqual(j.state,"PREFLIGHT_FAILED"); j.resume()
            for _ in j.checks: j.tick(1.3)
            self.assertEqual(j.state,"RUNNING"); j.tick(1); j.request_pause(); j.tick(0); self.assertEqual(j.state,"PAUSED"); j.resume()
            for _ in j.checks: j.tick(1.3)
            j.request_stop(); j.tick(0); self.assertEqual(j.state,"STOPPED")
    def test_corrupt_cipher(self):
        p=self.fresh(); src=p/'src'; src.mkdir(); t.create_once(src/'a.txt',b'abc')
        sign=ed25519.Ed25519PrivateKey.generate(); r=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        pkg=t.package(src,p/'spool','DEMO',sign,r.public_key()); bad=p/'bad'; bad.mkdir(); (bad/'chunks').mkdir()
        t.create_once(bad/'manifest.signed.json',(pkg/'manifest.signed.json').read_bytes())
        chunk=next((pkg/'chunks').iterdir()); t.create_once(bad/'chunks'/chunk.name,b'bad')
        with self.assertRaises(ValueError): t.forward(bad,p/'incoming',sign.public_key())
if __name__=='__main__': unittest.main()
