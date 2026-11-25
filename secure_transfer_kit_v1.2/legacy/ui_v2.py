"""Secure Data Transfer — operator UI demonstration (Python 3 / Tkinter).
SIMULATION ONLY: no source folders, drives, network, crypto or deletion APIs used.
Includes mandatory simulated USB preflight, failure blocking and retry.
Demo credentials: operator / DemoTransfer2026!
Run: python secure_transfer_ui.py
"""
import tkinter as tk
from tkinter import ttk, messagebox
import time
import hmac
from dataclasses import dataclass

MODES = {
    'Export to USB': ('IND-PC-001', r'D:\IndustrialData\Today', 'Approved USB · USB-003',
                      ('Prepare, compress & encrypt', 'Write encrypted package', 'Verify USB read-back'), (25, 16, 16)),
    'Import from USB': ('XFER-PC-001', 'Approved USB · USB-003', 'Central ingestion server',
                        ('Validate signed package', 'Upload encrypted package', 'Server validation & receipt'), (16, 16, 25)),
    'Network transfer': ('IND-PC-001 / SRC-SRV-01', r'D:\IndustrialData\Today', 'Central ingestion server · VLAN 120',
                         ('Prepare, compress & encrypt', 'Upload encrypted package', 'Server validation & receipt'), (25, 16, 25)),
}
PREFLIGHT = {
    'Export to USB': ('Authorized USB identity & filesystem', 'Dirty bit & available health telemetry', 'Read sample & capacity', 'New USB probe: write / flush / read-back', 'Expected files, app signature & prior receipt'),
    'Import from USB': ('Authorized USB identity & filesystem', 'Dirty bit & available health telemetry', 'Read sample & I/O errors (read-only)', 'Expected files & signed manifest', 'Server availability & capacity'),
    'Network transfer': ('Approved source & destination', 'Network connection & server identity', 'Server capacity & previous checkpoint'),
}
ACTIVE = {'RUNNING', 'PAUSE_REQUESTED', 'STOP_REQUESTED', 'PREFLIGHT'}
@dataclass
class Job:
    mode: str
    state: str = 'READY'
    done: float = 0.0
    active_time: float = 0.0
    check_index: int = 0
    check_elapsed: float = 0.0
    check_failure: bool = False
    speed: float = 1.6  # simulated GB of stage work per wall-clock second
    @property
    def weights(self): return MODES[self.mode][4]
    @property
    def total(self): return sum(self.weights)
    @property
    def stage(self):
        a = self.weights
        return 0 if self.done < a[0] else 1 if self.done < sum(a[:2]) else 2
    @property
    def transferred(self): return min(self.weights[1], max(0., self.done-self.weights[0]))
    @property
    def progress(self): return self.done/self.total*100
    @property
    def eta(self): return max(0., (self.total-self.done)/self.speed)
    @property
    def checks(self): return PREFLIGHT[self.mode]
    def begin_preflight(self):
        self.check_index = 0; self.check_elapsed = 0.; self.check_failure = False
        self.state = 'PREFLIGHT'
    def start(self):
        if self.state == 'READY': self.begin_preflight()
    def fail_preflight(self):
        if self.state == 'PREFLIGHT':
            self.check_failure = True; self.state = 'PREFLIGHT_FAILED' 
    def request_pause(self):
        if self.state == 'RUNNING': self.state = 'PAUSE_REQUESTED'
    def request_stop(self):
        if self.state in {'RUNNING', 'PAUSE_REQUESTED', 'PAUSED', 'INTERRUPTED', 'PREFLIGHT', 'PREFLIGHT_FAILED'}: self.state = 'STOP_REQUESTED'
    def resume(self):
        if self.state in {'PAUSED', 'STOPPED', 'INTERRUPTED', 'PREFLIGHT_FAILED'}: self.begin_preflight()
    def interrupt(self):
        if self.state == 'RUNNING': self.state = 'INTERRUPTED'
    def tick(self, dt):
        # Each simulated tick represents a verified checkpoint. Real workers must
        # acknowledge durable chunk completion before changing state.
        if self.state == 'PREFLIGHT':
            self.check_elapsed += dt
            if self.check_elapsed >= 1.2:
                self.check_elapsed = 0.; self.check_index += 1
                if self.check_index >= len(self.checks): self.state = 'RUNNING'
            return
        if self.state == 'PAUSE_REQUESTED': self.state = 'PAUSED'; return
        if self.state == 'STOP_REQUESTED': self.state = 'STOPPED'; return
        if self.state != 'RUNNING': return
        self.active_time += dt
        self.done = min(self.total, self.done + dt*self.speed)
        if self.done >= self.total:
            self.state = 'AWAITING_RECEIPT' if self.mode == 'Export to USB' else 'COMMITTED'

def duration(seconds):
    s = int(max(0, seconds) + .999)
    return f'{s//60:02d}:{s%60:02d}'

BG='#f1f5f9'; CARD='#ffffff'; INK='#15253a'; MUTED='#536578'; BLUE='#1d4ed8'; GREEN='#166534'; AMBER='#92400e'
class App:
    def __init__(self, root):
        self.root=root; self.root.title('Secure Data Transfer | UI demonstration')
        self.root.geometry('1000x790'); self.root.minsize(900,750); self.root.configure(bg=BG)
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        self.style=ttk.Style(root); self.style.theme_use('clam')
        self.style.configure('TButton',font=('Segoe UI',10),padding=(14,9))
        self.style.configure('Primary.TButton',background=BLUE,foreground='white',font=('Segoe UI',10,'bold'))
        self.style.map('Primary.TButton',background=[('disabled','#aab8cb'),('active','#1e40af')],foreground=[('disabled','#ffffff')])
        self.style.configure('TEntry',padding=8,font=('Segoe UI',11))
        self.style.configure('TCombobox',padding=6)
        self.style.configure('Transfer.Horizontal.TProgressbar',background=BLUE,troughcolor='#dbe5f0',borderwidth=0,thickness=15)
        self.job=None; self.user=None; self.attempts=0; self.lock_until=0.; self.last=time.monotonic(); self.last_state=None
        self.show_login(); self.root.after(150,self.update)
    def clear(self):
        for widget in self.root.winfo_children(): widget.destroy()  # UI widgets only; no file operations.
    def label(self,parent,text='',size=11,bold=False,color=INK,bg=CARD,**kw):
        return tk.Label(parent,text=text,font=('Segoe UI',size,'bold' if bold else 'normal'),fg=color,bg=bg,anchor='w',**kw)
    def top(self):
        bar=tk.Frame(self.root,bg='#142840',height=70); bar.pack(fill='x'); bar.pack_propagate(False)
        self.label(bar,'SECURE DATA TRANSFER',16,True,'white','#142840').pack(side='left',padx=27,pady=17)
        self.label(bar,'DEMONSTRATION  •  No real data operations',10,False,'#cbd5e1','#142840').pack(side='right',padx=24)
    def show_login(self):
        self.clear(); self.top(); self.user=None
        panel=tk.Frame(self.root,bg=CARD,highlightbackground='#d8e2ed',highlightthickness=1,padx=34,pady=25)
        panel.place(relx=.5,rely=.54,anchor='center',width=480)
        self.label(panel,'Operator sign in',24,True).pack(fill='x')
        self.label(panel,'Authenticate to start the configured transfer.',11,color=MUTED).pack(fill='x',pady=(4,20))
        self.label(panel,'Transfer job (demo selection)',10,True).pack(fill='x')
        self.mode=tk.StringVar(value='Export to USB')
        ttk.Combobox(panel,textvariable=self.mode,values=list(MODES),state='readonly').pack(fill='x',pady=(5,14))
        self.label(panel,'Username',10,True).pack(fill='x')
        self.username=ttk.Entry(panel); self.username.pack(fill='x',pady=(5,12)); self.username.focus_set()
        self.label(panel,'Password',10,True).pack(fill='x')
        self.password=ttk.Entry(panel,show='•'); self.password.pack(fill='x',pady=(5,4))
        self.reveal=tk.BooleanVar(value=False)
        tk.Checkbutton(panel,text='Show password',variable=self.reveal,command=lambda:self.password.configure(show='' if self.reveal.get() else '•'),bg=CARD,fg=MUTED,activebackground=CARD,anchor='w').pack(fill='x')
        self.error=self.label(panel,'',10,color='#b91c1c',wraplength=395); self.error.pack(fill='x',pady=(6,6))
        ttk.Button(panel,text='Sign in & begin transfer',style='Primary.TButton',command=self.login).pack(fill='x')
        self.password.bind('<Return>',lambda _:self.login()); self.username.bind('<Return>',lambda _:self.password.focus_set())
        self.label(panel,'Demo: operator / DemoTransfer2026!',9,color=MUTED).pack(fill='x',pady=(12,4))
        self.label(panel,'Original data protected • No deletion or formatting',9,True,GREEN).pack(fill='x')
    def login(self):
        if time.monotonic() < self.lock_until:
            self.error.config(text='Too many attempts. Try again shortly.'); return
        user=self.username.get(); secret=self.password.get(); self.password.delete(0,'end')  # text field only
        if not (hmac.compare_digest(user.encode(),'operator'.encode()) and hmac.compare_digest(secret.encode(),'DemoTransfer2026!'.encode())):
            self.attempts+=1; self.error.config(text='Invalid username or password.')
            if self.attempts>=5:
                self.lock_until=time.monotonic()+30; self.attempts=0; self.error.config(text='Too many attempts. Locked for 30 seconds (demo).')
            return
        self.attempts=0; self.user=user; self.job=Job(self.mode.get()); self.job.start(); self.show_job(); self.event('Authentication successful. Mandatory simulated pre-check started.'); self.refresh()
    def show_job(self):
        self.clear(); self.top(); j=self.job; device,src,dst,_,_=MODES[j.mode]
        head=tk.Frame(self.root,bg=BG,padx=28,pady=18); head.pack(fill='x')
        self.label(head,j.mode,24,True,bg=BG).pack(side='left')
        ttk.Button(head,text='Sign out',command=self.signout).pack(side='right')
        self.label(head,f'Operator: {self.user}',10,color=MUTED,bg=BG).pack(side='right',padx=14)
        main=tk.Frame(self.root,bg=CARD,highlightbackground='#d8e2ed',highlightthickness=1,padx=22,pady=16); main.pack(fill='both',expand=True,padx=28,pady=(0,12))
        self.label(main,f'TR-DEMO-0001  •  {device}',10,True,MUTED).pack(fill='x')
        self.label(main,f'From: {src}',11).pack(fill='x',pady=(8,2))
        self.label(main,f'To:     {dst}',11).pack(fill='x')
        self.preflight=self.label(main,'',10,True,MUTED,wraplength=850); self.preflight.pack(fill='x',pady=(9,0))
        self.status=self.label(main,'',16,True,BLUE); self.status.pack(fill='x',pady=(16,3))
        self.phase=self.label(main,'',11,color=MUTED); self.phase.pack(fill='x')
        self.progress=ttk.Progressbar(main,style='Transfer.Horizontal.TProgressbar',maximum=100); self.progress.pack(fill='x',pady=(9,5))
        self.percent=self.label(main,'',10,True); self.percent.pack(fill='x')
        stats=tk.Frame(main,bg='#edf3f9'); stats.pack(fill='x',pady=11)
        self.metrics=[]
        for i,title in enumerate(['Encrypted payload copied','Current stage rate','Active elapsed','Estimated remaining']):
            f=tk.Frame(stats,bg='#edf3f9',padx=11,pady=9); f.grid(row=0,column=i,sticky='nsew'); stats.columnconfigure(i,weight=1)
            self.label(f,title,9,color=MUTED,bg='#edf3f9').pack(fill='x')
            l=self.label(f,'—',15,True,bg='#edf3f9'); l.pack(fill='x',pady=(3,0)); self.metrics.append(l)
        buttons=tk.Frame(main,bg=CARD); buttons.pack(fill='x',pady=(2,8))
        self.pause=ttk.Button(buttons,text='Pause',command=j.request_pause); self.pause.pack(side='left',padx=(0,7))
        self.resume=ttk.Button(buttons,text='Resume',style='Primary.TButton',command=j.resume); self.resume.pack(side='left',padx=(0,7))
        self.stop=ttk.Button(buttons,text='Stop safely',command=self.stop_job); self.stop.pack(side='left',padx=(0,7))
        self.fail=ttk.Button(buttons,text='Simulate interruption',command=self.simulate_issue); self.fail.pack(side='right')
        self.label(main,'Activity log (demo · in memory)',10,True,MUTED).pack(fill='x')
        self.log=tk.Text(main,height=5,wrap='word',font=('Consolas',10),bg='#f6f8fb',fg=INK,relief='flat',state='disabled',padx=8,pady=5); self.log.pack(fill='both',expand=True,pady=(4,0))
        self.label(self.root,'Source read-only  •  No local deletion or overwrite  •  USB cleanup not available in this demo',10,True,GREEN,BG).pack(fill='x',padx=28,pady=(0,12))
        self.last_state=None
    def event(self,msg):
        self.log.config(state='normal'); self.log.insert('end',f'{time.strftime("%H:%M:%S")}  {msg}\n'); self.log.see('end'); self.log.config(state='disabled')
    def stop_job(self):
        if messagebox.askyesno('Stop transfer safely?','The current checkpoint will be retained. Original files will not be changed. You can resume this job during this demo session.'):
            self.job.request_stop()
    def simulate_issue(self):
        if self.job.state == 'PREFLIGHT': self.job.fail_preflight()
        elif self.job.state == 'RUNNING': self.job.interrupt()
    def refresh(self):
        j=self.job; s=j.state
        labels={'PREFLIGHT':'Checking transfer readiness…','PREFLIGHT_FAILED':'Pre-check failed — transfer blocked','RUNNING':'Transfer in progress','PAUSE_REQUESTED':'Pausing safely…','PAUSED':'Paused — checkpoint retained','STOP_REQUESTED':'Stopping safely…','STOPPED':'Stopped — resumable','INTERRUPTED':'Interrupted — reconnect and resume','AWAITING_RECEIPT':'USB export verified — awaiting server receipt','COMMITTED':'Server committed — receipt verified (simulated)'}
        self.status.config(text=labels.get(s,s),fg=GREEN if s in {'COMMITTED','AWAITING_RECEIPT'} else AMBER if s in {'PAUSED','STOPPED','INTERRUPTED','PREFLIGHT_FAILED'} else BLUE)
        if s in {'PREFLIGHT','PREFLIGHT_FAILED'}:
            check = j.checks[min(j.check_index,len(j.checks)-1)]
            self.preflight.config(text=f'Pre-check {j.check_index+1}/{len(j.checks)} · {check}' + (' — FAILED (demo)' if s=='PREFLIGHT_FAILED' else ' — checking (demo)'),fg=AMBER if s=='PREFLIGHT_FAILED' else BLUE)
        elif j.check_index == len(j.checks):
            self.preflight.config(text='Pre-check passed (simulated) · ' + ('USB quick health / integrity check' if j.mode!='Network transfer' else 'Network readiness check · USB not applicable'),fg=GREEN)
        else:
            self.preflight.config(text='Pre-check incomplete · No new transfer permitted',fg=AMBER)
        self.phase.config(text=f'Stage {j.stage+1} of 3 · {MODES[j.mode][3][j.stage]}')
        self.progress['value']=j.progress; self.percent.config(text=f'{j.progress:.1f}% overall • 600 source files • 25 GB original (simulated)')
        vals=[f'{j.transferred:.1f} / {j.weights[1]} GB', f'{j.speed:.1f} GB/s (demo)' if s=='RUNNING' else '—',duration(j.active_time),duration(j.eta) if s=='RUNNING' else ('00:00' if s in {'COMMITTED','AWAITING_RECEIPT'} else '—')]
        for l,v in zip(self.metrics,vals): l.config(text=v)
        self.pause.config(state='normal' if s=='RUNNING' else 'disabled'); self.resume.config(text='Retry checks' if s=='PREFLIGHT_FAILED' else 'Resume',state='normal' if s in {'PAUSED','STOPPED','INTERRUPTED','PREFLIGHT_FAILED'} else 'disabled')
        self.stop.config(state='normal' if s in {'RUNNING','PAUSED','INTERRUPTED','PREFLIGHT','PREFLIGHT_FAILED'} else 'disabled'); self.fail.config(text='Simulate check failure' if s=='PREFLIGHT' else 'Simulate interruption',state='normal' if s in {'RUNNING','PREFLIGHT'} else 'disabled')
        if self.last_state!=s:
            self.event(labels.get(s,s)); self.last_state=s
    def update(self):
        now=time.monotonic(); dt=min(now-self.last,.3); self.last=now
        if self.user and self.job: self.job.tick(dt); self.refresh()
        self.root.after(150,self.update)
    def signout(self):
        if self.job.state in ACTIVE or self.job.state in {'PAUSED','STOPPED','INTERRUPTED','PREFLIGHT_FAILED'}:
            messagebox.showinfo('Job still pending','Finish or resume this job before signing out. This demonstration has no persistent storage.'); return
        self.job=None; self.show_login()
    def close(self):
        if self.job and self.job.state not in {'COMMITTED','AWAITING_RECEIPT'}:
            if not messagebox.askyesno('Close demonstration?','In-memory simulated progress will be lost. A production application must persist checkpoints before exit.'): return
        self.root.destroy()

if __name__=='__main__':
    root=tk.Tk(); App(root); root.mainloop()
