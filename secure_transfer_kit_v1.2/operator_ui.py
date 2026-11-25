"""V1.2 interactive Tkinter operator simulation and 26-screen design gallery.
No actual file transfers, USB access, network connections or deletion.
Demo login only: operator / DemoTransfer2026!
"""
import hmac, time, tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from workflow import Workflow, Mode

BLUE='#1d4ed8'; NAVY='#172b4d'; MUTED='#52647a'; BG='#f1f5f9'; GREEN='#166534'
SCREENS = Path(__file__).parent / 'visuals' / 'operator_screens'
SCREEN_NAMES = ('Login','Job selection','Network preflight','Network progress','Awaiting server commit','Network complete','USB quick health check','USB export progress','USB export complete','USB import preflight','USB import progress','Server receipt','USB cleanup authorization','Returned receipt','Paused','Stopped safely','Restart recovery','Failed mandatory check','Transfer history','Transfer details','Safe sign-out','Authentication error','Dataset inventory','Connection interrupted','Server quarantine','USB cleanup result')

class App:
    def __init__(self, root):
        self.root=root; root.title('Secure Data Transfer v1.2 | SIMULATION'); root.geometry('1040x760'); root.minsize(850,650); root.configure(bg=BG)
        self.style=ttk.Style(root); self.style.theme_use('clam'); self.style.configure('TButton',padding=(12,8)); self.style.configure('Primary.TButton',background=BLUE,foreground='white'); self.style.configure('TEntry',padding=7)
        self.job=None; self.pending_export=None; self.user=None; self.history=[]; self.attempts=0; self.lock_until=0; self.view='login'; self.gallery=None; self.image=None; self.next_check=0
        root.protocol('WM_DELETE_WINDOW',self.close); self.login_screen(); root.after(400,self.loop)
    def clear(self,view):
        self.view=view
        for child in self.root.winfo_children():
            if child is not self.gallery: child.destroy()
        bar=tk.Frame(self.root,bg=NAVY,padx=24,pady=14); bar.pack(fill='x')
        tk.Label(bar,text='SECURE DATA TRANSFER   /   v1.2',bg=NAVY,fg='white',font=('Segoe UI',15,'bold')).pack(side='left')
        tk.Label(bar,text='SIMULATION ONLY',bg=NAVY,fg='#fbbf24',font=('Segoe UI',11,'bold')).pack(side='right')
        self.panel=tk.Frame(self.root,bg='white',padx=26,pady=20); self.panel.pack(fill='both',expand=True,padx=25,pady=18)
        tk.Label(self.root,text='Original files protected • No real device access • No deletion or formatting',bg=BG,fg=GREEN,font=('Segoe UI',10,'bold')).pack(pady=(0,10))
    def label(self,text,size=12,bold=False,color=NAVY,parent=None):
        return tk.Label(parent or self.panel,text=text,bg='white',fg=color,font=('Segoe UI',size,'bold' if bold else 'normal'),anchor='w',justify='left',wraplength=870)
    def title(self,text,sub=''):
        self.label(text,23,True).pack(fill='x',pady=(0,5))
        if sub:self.label(sub,11,color=MUTED).pack(fill='x',pady=(0,14))
    def button(self,text,fn,parent=None,primary=False):
        b=ttk.Button(parent or self.panel,text=text,command=fn,style='Primary.TButton' if primary else 'TButton'); b.pack(side='left' if parent else 'top',anchor='w',padx=(0,8),pady=4); return b
    def login_screen(self):
        self.clear('login'); self.title('Operator sign in','Enter demonstration credentials to unlock the operator workflow.')
        self.label('Username',11,True).pack(fill='x'); self.username=ttk.Entry(self.panel,width=35); self.username.pack(anchor='w',pady=(4,14))
        self.label('Password',11,True).pack(fill='x'); self.password=ttk.Entry(self.panel,width=35,show='•'); self.password.pack(anchor='w',pady=(4,8))
        visible=tk.BooleanVar(value=False); ttk.Checkbutton(self.panel,text='Show password',variable=visible,command=lambda:self.password.config(show='' if visible.get() else '•')).pack(anchor='w')
        self.error=self.label('',11,color='#b91c1c'); self.error.pack(fill='x',pady=8)
        self.button('Sign in',self.login,primary=True); self.password.bind('<Return>',lambda _:self.login()); self.username.focus_set()
        self.label('Demo: operator / DemoTransfer2026! — not production credentials.',10,color=MUTED).pack(fill='x',pady=14)
    def login(self):
        if time.monotonic()<self.lock_until: self.error.config(text='Too many attempts. Try again shortly.'); return
        user,secret=self.username.get(),self.password.get(); self.password.delete(0,'end') # text field only
        if not (hmac.compare_digest(user.encode(),b'operator') and hmac.compare_digest(secret.encode(),b'DemoTransfer2026!')):
            self.attempts+=1; self.error.config(text='Invalid username or password.')
            if self.attempts>=5: self.lock_until=time.monotonic()+30; self.attempts=0; self.error.config(text='Demo account temporarily locked (30 seconds).')
            return
        self.user=user; self.attempts=0
        if self.job and self.job.state in {'STOPPED','PAUSED','INTERRUPTED','CHECK_FAILED'}: self.job.recover(); self.dashboard()
        elif self.job: self.dashboard()
        else: self.selection()
    def selection(self):
        self.clear('selection'); self.title('Select transfer job','Two transmission options; Option 2 has export and import stages. Start Option 2A for the complete simulated USB lifecycle.')
        for mode in Mode: self.button(mode.value,lambda m=mode:self.select(m),primary=True)
        self.button('Transfer history',self.show_history); self.button('Screen design gallery (26)',self.show_gallery); self.button('Sign out',self.signout)
    def select(self,mode):
        if self.job and self.job.state not in {'COMMITTED','CLEANED','RETURN_RECEIPT','ACKNOWLEDGED','QUARANTINED'}:
            messagebox.showwarning('Pending job','Finish or reconcile the existing job first.'); self.dashboard(); return
        self.job=Workflow(mode); self.dashboard()
    def dashboard(self):
        self.clear('dashboard'); j=self.job; self.title(j.mode.value,'TR-DEMO-001  •  Operator authenticated  •  600 files  /  25 GB source  /  16 GB encrypted (illustrative)')
        self.status=self.label('',17,True,BLUE); self.status.pack(fill='x',pady=5)
        self.detail=self.label('',11,color=MUTED); self.detail.pack(fill='x',pady=5)
        self.progress=ttk.Progressbar(self.panel,maximum=100,length=780); self.progress.pack(fill='x',pady=10)
        self.metric=self.label('',12,True); self.metric.pack(fill='x',pady=8)
        self.actions=tk.Frame(self.panel,bg='white'); self.actions.pack(fill='x',pady=8)
        self.log=tk.Text(self.panel,height=7,bg='#f8fafc',fg=NAVY,state='disabled',font=('Consolas',10),relief='flat'); self.log.pack(fill='both',expand=True,pady=8)
        nav=tk.Frame(self.panel,bg='white'); nav.pack(fill='x'); self.button('History',self.show_history,nav); self.button('Screen gallery',self.show_gallery,nav); self.button('Sign out',self.signout,nav)
        self.render_state()
    def change(self,fn,*args):
        fn(*args); self.render_state()
    def render_state(self):
        if self.view!='dashboard':return
        j=self.job; s=j.state
        self.status.config(text=s.replace('_',' ').title()); self.progress['value']=j.progress
        self.metric.config(text=f'{j.progress:.0f}% verified work  •  {j.verified}/{j.total} units  •  ETA: '+(f'{j.eta:.0f} demo seconds' if j.eta is not None else '—')+f'\nActive elapsed: {j.active_seconds:.0f}s  •  Encrypted payload: {min(16,max(0,(j.verified-20)*.8)):.1f}/16 GB  •  '+('2.5 units/s (demo)' if s=='RUNNING' else 'Rate: —'))
        descriptions={'INVENTORY':'Review ready dataset. Deferred files are excluded.','PREFLIGHT':f'Checking {min(j.check_index+1,len(j.checks))}/{len(j.checks)}: {j.checks[min(j.check_index,len(j.checks)-1)]}', 'CHECK_FAILED':'Mandatory check failed. No bypass. Retry checks.','RUNNING':j.stage,'PAUSED':'Verified work retained. Resume repeats preflight.','STOPPED':'Stopped at safe checkpoint. Resume or sign out.','RECOVERY':'Simulated in-memory restart recovery; repeat checks before resuming.','INTERRUPTED':'Reconnect approved media/network and repeat checks.','USB_EXPORTED':'USB export verified; NOT server committed. Await signed receipt.','AWAITING_COMMIT':'All chunks uploaded. Await verified server receipt.','COMMITTED':'Simulated server receipt verified. No real commit.','QUARANTINED':'Server rejected package. Cleanup blocked. Contact support; linked export remains pending.','CLEANUP_PREVIEW':'Part B only. Receipt and exact USB inventory required; simulation deletes nothing.','CLEANED':'Simulated USB payload cleanup complete. No files deleted.','RETURN_RECEIPT':'Return same USB with signed receipt (simulated).','ACKNOWLEDGED':'Simulated returned receipt accepted.'}
        self.detail.config(text=descriptions.get(s,'Waiting for safe checkpoint.'))
        for w in self.actions.winfo_children():w.destroy()
        def b(text,fn,*args): self.button(text,lambda:self.change(fn,*args),self.actions)
        if s in {'INVENTORY','PAUSED','STOPPED','RECOVERY','INTERRUPTED','CHECK_FAILED'}:b('Begin checks' if s=='INVENTORY' else 'Resume / retry checks',j.begin)
        if s=='PREFLIGHT':b('Simulate failed check',j.check,False); b('Stop safely',j.stop)
        if s=='RUNNING':b('Pause',j.pause); b('Stop safely',j.stop); b('Simulate interruption',j.disconnect)
        if s in {'PAUSED','INTERRUPTED','CHECK_FAILED'}:b('Stop safely',j.stop)
        if s=='AWAITING_COMMIT':b('Simulate valid receipt',j.server_result,True); b('Simulate rejection',j.server_result,False); b('Disconnect',j.disconnect)
        if s=='COMMITTED' and j.mode==Mode.IMPORT:b('Review USB cleanup (demo)',j.cleanup_preview)
        if s=='CLEANUP_PREVIEW':b('Simulate cleanup — no deletion',j.simulate_cleanup)
        if s=='CLEANED':b('Return same USB',j.return_media)
        if s=='RETURN_RECEIPT' and self.pending_export is not None:self.button('Return to Part A and acknowledge',self.complete_return,self.actions)
        if s=='USB_EXPORTED':self.button('Simulate moving USB to Part B',self.move_to_part_b,self.actions)
        if s in {'ACKNOWLEDGED'} or (s in {'RETURN_RECEIPT','QUARANTINED'} and self.pending_export is None) or (s=='COMMITTED' and j.mode!=Mode.IMPORT): self.button('Finish / select another job',self.finish,self.actions)
        self.log.config(state='normal'); self.log.delete('1.0','end'); self.log.insert('end','\n'.join(j.events[-12:])); self.log.config(state='disabled') # text widget only
    def loop(self):
        if self.user and self.job:
            j=self.job; prev=j.state; old=j.verified; old_check=j.check_index
            if j.state=='PREFLIGHT':
                self.next_check+=1
                if self.next_check>=3: j.check(); self.next_check=0
            else: self.next_check=0; j.tick()
            if (prev,old,old_check)!=(j.state,j.verified,j.check_index): self.render_state()
        self.root.after(400,self.loop)
    def move_to_part_b(self):
        if self.job.mode!=Mode.EXPORT or self.job.state!='USB_EXPORTED':return
        self.pending_export=self.job; self.job=Workflow(Mode.IMPORT); self.dashboard()
    def complete_return(self):
        if not self.pending_export or self.job.state!='RETURN_RECEIPT' or not self.job.receipt:return
        self.history.append((self.job.mode.value,self.job.state,self.job.verified))
        self.job=self.pending_export; self.pending_export=None; self.job.acknowledge_return(True); self.dashboard()
    def finish(self):
        self.history.append((self.job.mode.value,self.job.state,self.job.verified)); self.job=None; self.selection()
    def show_history(self):
        self.clear('history'); self.title('Transfer history','Read-only simulation; records are retained during this session only.')
        for m,s,n in self.history+([(self.job.mode.value,self.job.state,self.job.verified)] if self.job else []):
            self.button(f'{m}   |   {s}   |   {n}/60 units',lambda m=m,s=s,n=n:self.show_details(m,s,n))
        self.button('Back',self.dashboard if self.job else self.selection)
    def show_details(self,mode,state,verified):
        self.clear('details'); self.title('Transfer details','Read-only demonstration record; no actual receipt or file data.')
        for item in (mode, f'Status: {state}', f'Verified work: {verified}/60', 'Dataset: 600 files / 25 GB (illustrative)', 'Operator: operator (demo)', 'Original files unchanged; no deletion performed.'):
            self.label(item).pack(fill='x',pady=4)
        self.button('Back to history',self.show_history)
    def signout(self):
        if self.job and self.job.state in {'RUNNING','PREFLIGHT','PAUSING','AWAITING_COMMIT'}:
            messagebox.showinfo('Safe sign-out','Stop safely before signing out.'); return
        if self.job and self.job.state=='STOPPING':return
        if self.job and self.job.state not in {'STOPPED','PAUSED','INTERRUPTED','CHECK_FAILED','COMMITTED','ACKNOWLEDGED','RETURN_RECEIPT','USB_EXPORTED','QUARANTINED','CLEANED'}:
            messagebox.showinfo('Pending job','Complete this step before signing out.'); return
        self.user=None
        if self.gallery is not None and self.gallery.winfo_exists(): self.gallery.destroy(); self.gallery=None
        self.login_screen()
    def show_gallery(self):
        if self.gallery is not None and self.gallery.winfo_exists(): self.gallery.lift();return
        w=tk.Toplevel(self.root); self.gallery=w; w.title('Design gallery — SCR-01 to SCR-26'); w.geometry('1000x730')
        names=tuple(f'SCR-{i:02d} | {n}' for i,n in enumerate(SCREEN_NAMES,1)); var=tk.StringVar(value=names[0]); box=ttk.Combobox(w,values=names,textvariable=var,state='readonly',width=55); box.pack(pady=8)
        image_label=tk.Label(w,text=''); image_label.pack(fill='both',expand=True)
        def display(*_):
            index=names.index(var.get())+1; path=next(SCREENS.glob(f'{index:02d}_*.png'),None)
            if not path: image_label.config(image='',text='Screen image missing');return
            im=tk.PhotoImage(file=str(path)); factor=max(1,(im.width()+940-1)//940,(im.height()+620-1)//620); self.image=im.subsample(factor,factor); image_label.config(image=self.image,text='')
        box.bind('<<ComboboxSelected>>',display); display()
    def close(self):
        if self.job and not messagebox.askyesno('Close simulation?','This demo retains state only in memory. Closing loses simulated progress. Continue?'):return
        self.root.destroy()

if __name__=='__main__':
    root=tk.Tk(); App(root); root.mainloop()
