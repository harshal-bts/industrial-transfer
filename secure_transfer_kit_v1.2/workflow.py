"""V1.2 operator workflow simulator. No real media, network, auth or file writes.
All state and receipts are synthetic and in memory; never use to authorize cleanup.
"""
from dataclasses import dataclass, field
from enum import Enum

class Mode(str, Enum):
    NETWORK = 'Option 1 — Direct network (SMB)'
    EXPORT = 'Option 2A — Industrial PC to USB'
    IMPORT = 'Option 2B — USB to server (SMB)'

CHECKS = {
    Mode.NETWORK: ('Approved source & ready inventory', 'Approved VLAN / server identity', 'SMB dialect & encryption policy', 'Destination capacity / create-only policy'),
    Mode.EXPORT: ('Authorized physical USB / volume', 'Filesystem & available health telemetry', 'Read/write sample & SHA-256 (simulated)', 'Capacity / signed prior receipt / application integrity'),
    Mode.IMPORT: ('Authorized USB / filesystem', 'Read-only sample & signed manifest', 'Approved VLAN / server identity', 'SMB encryption / capacity / create-only policy'),
}
# Each stage has a fictional number of equally weighted verified work units.
STAGES = {
    Mode.NETWORK: ('Prepare / compress / encrypt', 'Write encrypted chunks via SMB', 'Verify destination chunks'),
    Mode.EXPORT: ('Prepare / compress / encrypt', 'Write encrypted USB chunks', 'Read-back / verify USB'),
    Mode.IMPORT: ('Verify signed USB package', 'Write encrypted chunks via SMB', 'Verify destination chunks'),
}

@dataclass
class Workflow:
    mode: Mode
    state: str = 'INVENTORY'
    verified: int = 0
    total: int = 60
    check_index: int = 0
    receipt: bool = False  # synthetic only
    receipt_returned: bool = False
    resume_pending: bool = False
    events: list = field(default_factory=list)
    active_seconds: float = 0
    previous_state: str = ''

    def __post_init__(self):
        if self.total != 60 or not isinstance(self.mode, Mode): raise ValueError('Simulator uses 60 fixed work units and a valid mode')

    def _set(self, state):
        self.previous_state = self.state
        self.state = state
        self.events.append(state)

    @property
    def checks(self): return CHECKS[self.mode]
    @property
    def stage(self): return STAGES[self.mode][min(2, self.verified // 20)]
    @property
    def progress(self): return 100 * self.verified / self.total
    @property
    def eta(self):
        return (self.total - self.verified) * .4 if self.state == 'RUNNING' else None
    @property
    def pending(self):
        return self.state not in {'COMMITTED', 'CLEANED', 'ACKNOWLEDGED', 'QUARANTINED'}

    def begin(self):
        if self.state not in {'INVENTORY','PAUSED','STOPPED','INTERRUPTED','CHECK_FAILED','RECOVERY'}:
            raise ValueError('Preflight unavailable from current state')
        self.check_index = 0
        self._set('PREFLIGHT')

    def check(self, passed=True):
        if self.state != 'PREFLIGHT': raise ValueError('No active preflight')
        if not passed: self._set('CHECK_FAILED'); return
        self.check_index += 1
        if self.check_index == len(self.checks):
            self._set('AWAITING_COMMIT' if self.resume_pending else 'RUNNING')
            self.resume_pending = False

    def tick(self):
        if self.state == 'PAUSING': self._set('PAUSED'); return
        if self.state == 'STOPPING': self._set('STOPPED'); return
        if self.state != 'RUNNING': return
        self.verified += 1
        self.active_seconds += .4
        if self.verified == self.total:
            self._set('USB_EXPORTED' if self.mode == Mode.EXPORT else 'AWAITING_COMMIT')

    def pause(self):
        if self.state != 'RUNNING': raise ValueError('Cannot pause')
        self._set('PAUSING')

    def stop(self):
        if self.state not in {'RUNNING','PAUSED','PREFLIGHT','CHECK_FAILED','INTERRUPTED','PAUSING','AWAITING_COMMIT'}:
            raise ValueError('Cannot stop')
        if self.state == 'AWAITING_COMMIT': self.resume_pending = True
        self._set('STOPPING')

    def disconnect(self):
        if self.state not in {'RUNNING','PREFLIGHT','AWAITING_COMMIT'}: raise ValueError('Cannot interrupt')
        if self.state == 'AWAITING_COMMIT': self.resume_pending = True
        self._set('INTERRUPTED')

    def recover(self):
        if self.state not in {'STOPPED','PAUSED','INTERRUPTED','CHECK_FAILED'}: raise ValueError('No resumable job')
        self._set('RECOVERY')

    def server_result(self, accepted):
        if self.state != 'AWAITING_COMMIT': raise ValueError('No pending server commit')
        self.receipt = bool(accepted)
        self._set('COMMITTED' if accepted else 'QUARANTINED')

    def cleanup_preview(self):
        if self.mode != Mode.IMPORT or self.state != 'COMMITTED' or not self.receipt:
            raise PermissionError('Cleanup requires Part B and verified commit')
        self._set('CLEANUP_PREVIEW')

    def simulate_cleanup(self):
        if self.mode != Mode.IMPORT or self.state != 'CLEANUP_PREVIEW' or not self.receipt:
            raise PermissionError('Cleanup unavailable')
        self._set('CLEANED')  # simulation only; no deletion API

    def return_media(self):
        if self.mode != Mode.IMPORT or self.state != 'CLEANED' or not self.receipt:
            raise PermissionError('No simulated return receipt')
        self._set('RETURN_RECEIPT')

    def acknowledge_return(self, verified=False):
        if self.mode != Mode.EXPORT or self.state != 'USB_EXPORTED' or not verified:
            raise PermissionError('Valid returned receipt required')
        self.receipt_returned = True
        self._set('ACKNOWLEDGED')
