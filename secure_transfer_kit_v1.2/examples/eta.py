"""Pure progress estimator: verified work units, not just bytes submitted."""
from collections import deque
class ETA:
    def __init__(self, window=30): self.window=window; self.samples=deque()
    def update(self, monotonic_seconds, verified_bytes):
        self.samples.append((monotonic_seconds,verified_bytes))
        while len(self.samples)>2 and monotonic_seconds-self.samples[0][0]>self.window: self.samples.popleft()
    def estimate(self, total_bytes, active=True):
        if not active or len(self.samples)<2: return None
        t0,b0=self.samples[0]; t1,b1=self.samples[-1]
        if t1<=t0 or b1<=b0: return None
        return max(0,total_bytes-b1)/((b1-b0)/(t1-t0))
    def reset(self): self.samples.clear()
