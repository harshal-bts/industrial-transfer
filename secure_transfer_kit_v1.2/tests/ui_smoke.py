"""GUI smoke checks; needs a desktop display (Linux: xvfb-run -a).
Uses simulated in-memory data, not a real device or server.
"""
import sys, tkinter as tk
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from operator_ui import App, SCREENS, SCREEN_NAMES
from workflow import Mode

def complete(app):
    j=app.job;j.begin()
    for _ in j.checks:j.check()
    for _ in range(j.total):j.tick()
    app.render_state();app.root.update_idletasks()

def run():
    root=tk.Tk();app=App(root);root.update_idletasks()
    try:
        app.username.insert(0,'operator');app.password.insert(0,'wrong');app.login();assert app.view=='login'
        app.password.insert(0,'DemoTransfer2026!');app.login();assert app.view=='selection'
        app.show_gallery();root.update_idletasks();assert app.gallery.winfo_exists()
        for i in range(1,len(SCREEN_NAMES)+1):
            p=next(SCREENS.glob(f'{i:02d}_*.png'));im=tk.PhotoImage(file=str(p));assert im.width()>0 and im.height()>0
        app.gallery.destroy();app.gallery=None
        app.select(Mode.NETWORK);complete(app);app.job.server_result(True);app.render_state();app.finish()
        app.select(Mode.EXPORT);complete(app);assert app.job.state=='USB_EXPORTED';app.move_to_part_b();complete(app);app.job.server_result(True);app.job.cleanup_preview();app.job.simulate_cleanup();app.job.return_media();app.render_state();app.complete_return();assert app.job.state=='ACKNOWLEDGED';app.finish()
        app.show_history();assert len(app.history)==3;app.show_details(*app.history[0]);assert app.view=='details';app.selection()
        app.select(Mode.IMPORT);app.job.begin();app.job.check(False);app.render_state();app.job.stop();app.job.tick();app.render_state();app.signout();assert app.view=='login';app.username.insert(0,'operator');app.password.insert(0,'DemoTransfer2026!');app.login();assert app.job.state=='RECOVERY';app.job.begin();app.render_state()
        root.update_idletasks();print('PASS: Tk UI launch, invalid/valid login, 26 PNG decode, network completion, linked USB export/import/return, history/details, failed preflight, stop/sign-out/re-auth recovery.')
    finally:root.destroy()
if __name__=='__main__':run()
