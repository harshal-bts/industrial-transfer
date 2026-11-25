import unittest, tempfile, uuid
from pathlib import Path
from workflow import Workflow, Mode
from examples.receipt_validation import validate_commit_receipt
from examples.read_only_probe import sample_read
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
import transfer_demo as t

def run_checks(j):
    j.begin()
    for _ in j.checks: j.check()

def complete(j):
    run_checks(j)
    for _ in range(j.total): j.tick()

class WorkflowTests(unittest.TestCase):
    def test_all_modes(self):
        for mode in Mode:
            j=Workflow(mode); complete(j)
            self.assertEqual(j.state,'USB_EXPORTED' if mode==Mode.EXPORT else 'AWAITING_COMMIT')
            self.assertEqual(j.progress,100)
            if mode!=Mode.EXPORT: j.server_result(True); self.assertEqual(j.state,'COMMITTED')
    def test_failed_precheck(self):
        for mode in Mode:
            j=Workflow(mode);j.begin();j.check(False);j.tick();self.assertEqual(j.state,'CHECK_FAILED');self.assertEqual(j.verified,0)
            run_checks(j);self.assertEqual(j.state,'RUNNING')
    def test_pause_resume_stop(self):
        j=Workflow(Mode.NETWORK);run_checks(j);j.tick();j.pause();j.tick();self.assertEqual(j.state,'PAUSED');self.assertIsNone(j.eta); n=j.verified
        run_checks(j);self.assertEqual(j.verified,n);j.stop();j.tick();j.recover();run_checks(j);self.assertEqual(j.verified,n)
    def test_disconnect_during_commit(self):
        j=Workflow(Mode.IMPORT);complete(j);j.disconnect();run_checks(j);self.assertEqual(j.state,'AWAITING_COMMIT');self.assertEqual(j.progress,100)
    def test_no_early_cleanup(self):
        for mode in Mode:
            j=Workflow(mode)
            with self.assertRaises(PermissionError): j.cleanup_preview()
            with self.assertRaises(PermissionError): j.simulate_cleanup()
        j=Workflow(Mode.NETWORK);complete(j);j.server_result(True)
        with self.assertRaises(PermissionError):j.cleanup_preview()
    def test_usb_lifecycle(self):
        a=Workflow(Mode.EXPORT);complete(a)
        with self.assertRaises(PermissionError):a.acknowledge_return(False)
        b=Workflow(Mode.IMPORT);complete(b);b.server_result(True);b.cleanup_preview();b.simulate_cleanup();b.return_media()
        self.assertEqual(b.state,'RETURN_RECEIPT');a.acknowledge_return(True);self.assertEqual(a.state,'ACKNOWLEDGED')
    def test_quarantine_blocks_cleanup(self):
        j=Workflow(Mode.IMPORT);complete(j);j.server_result(False)
        self.assertEqual(j.state,'QUARANTINED');self.assertFalse(j.receipt)
        with self.assertRaises(PermissionError): j.cleanup_preview()
    def test_signed_receipt_binding(self):
        sign=Ed25519PrivateKey.generate();tid=str(uuid.uuid4()); body={'transferId':tid,'senderId':'TEST','manifestHash':'a'*64,'serverId':'SERVER','status':'COMMITTED'}
        kwargs=dict(transfer_id=tid,sender_id='TEST',manifest_hash='a'*64,server_id='SERVER')
        self.assertEqual(validate_commit_receipt(t.seal(body,sign),sign.public_key(),**kwargs),body)
        for key,value in [('transferId',str(uuid.uuid4())),('senderId','OTHER'),('manifestHash','b'*64),('serverId','OTHER'),('status','QUARANTINE_VERIFIED')]:
            with self.subTest(key=key),self.assertRaises(ValueError):validate_commit_receipt(t.seal({**body,key:value},sign),sign.public_key(),**kwargs)
        with self.assertRaises(InvalidSignature):validate_commit_receipt(t.seal(body,Ed25519PrivateKey.generate()),sign.public_key(),**kwargs)
    def test_read_only_probe(self):
        root=Path(tempfile.mkdtemp(prefix='read-probe-test-'));t.create_once(root/'LAB_ONLY.marker',b'test');p=t.create_once(root/'sample.bin',b'data')
        before=set(root.iterdir());result=sample_read(root,p.name,1);self.assertEqual(result['sha256'],t.sha(b'data'));self.assertEqual(set(root.iterdir()),before)
    def test_direct_network_roundtrip(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        root=Path(tempfile.mkdtemp(prefix='direct-transfer-test-')); source=root/'source'; source.mkdir()
        t.create_once(source/'test.csv',b'x,y,z\n1,2,3\n')
        sign=Ed25519PrivateKey.generate(); receiver=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        package=t.package(source,root/'spool','TEST',sign,receiver.public_key())
        incoming=t.forward(package,root/'incoming',sign.public_key())
        result=t.ingest_quarantine(incoming,root/'quarantine',sign.public_key(),receiver)
        self.assertEqual(result['status'],'QUARANTINE_VERIFIED');self.assertEqual((root/'quarantine'/result['transferId']/'test.csv').read_bytes(),(source/'test.csv').read_bytes())
    def test_symlink_rejected(self):
        from examples.smb_native import copy_verified
        root=Path(tempfile.mkdtemp(prefix='symlink-transfer-test-')); source=t.create_once(root/'source',b'data'); target=t.create_once(root/'target',b'data'); link=root/'alias'
        try:link.symlink_to(target)
        except (OSError,NotImplementedError): self.skipTest('Symlinks unavailable in test environment')
        with self.assertRaises(ValueError):copy_verified(source,link,t.sha(b'data'))
        self.assertEqual(target.read_bytes(),b'data')
    def test_screen_inventory(self):
        root=Path(__file__).resolve().parents[1];screens=root/'visuals'/'operator_screens';self.assertEqual(len(list(screens.glob('*.png'))),26)
        for i in range(1,27):self.assertEqual(len(list(screens.glob(f'{i:02d}_*.png'))),1)
if __name__=='__main__':unittest.main()
