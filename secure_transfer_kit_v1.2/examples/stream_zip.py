"""Streaming ZIP64 format option: no plaintext archive on disk.
Demonstration uses synthetic bytes and an in-memory encrypted sink. Production
sink must emit verified immutable ciphertext chunks to approved USB/SMB.
Do not treat this as a complete package format or resume implementation.
"""
import io, zipfile, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class EncryptedZipSink:
    def __init__(self, key, emit, chunk_size=1024*1024):
        self.aes=AESGCM(key); self.emit=emit; self.chunk_size=chunk_size
        self.buffer=bytearray(); self.position=0; self.index=0
    def tell(self): return self.position
    def write(self, data):
        self.position+=len(data); self.buffer.extend(data)
        while len(self.buffer)>=self.chunk_size:
            block=bytes(self.buffer[:self.chunk_size]); del self.buffer[:self.chunk_size]
            self._emit(block)
        return len(data)
    def _emit(self, block):
        nonce=os.urandom(12); aad=self.index.to_bytes(8,'big')
        self.emit(self.index,nonce+self.aes.encrypt(nonce,block,aad)); self.index+=1
    def flush(self): pass  # zipfile calls flush; only finalize emits partial chunk
    def finalize(self):
        if self.buffer: self._emit(bytes(self.buffer)); self.buffer.clear()

def synthetic_demo():
    key=AESGCM.generate_key(bit_length=256); chunks=[]
    sink=EncryptedZipSink(key,lambda i,b: chunks.append((i,b)))
    with zipfile.ZipFile(sink,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True) as z:
        with z.open('measurements.csv','w',force_zip64=True) as out:
            for _ in range(1000): out.write(b'x,y,z\n1,2,3\n')
        z.writestr('metadata.json',b'{"format":"synthetic"}',compress_type=zipfile.ZIP_STORED)
    sink.finalize()  # only after central directory is written
    aes=AESGCM(key); plain=b''.join(aes.decrypt(b[:12],b[12:],i.to_bytes(8,'big')) for i,b in chunks)
    with zipfile.ZipFile(io.BytesIO(plain),'r') as z:
        assert z.read('measurements.csv')==b'x,y,z\n1,2,3\n'*1000
        assert z.read('metadata.json')==b'{"format":"synthetic"}'
    return len(chunks)
if __name__=='__main__': print('Verified synthetic ZIP chunks:',synthetic_demo())
