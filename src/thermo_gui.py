"""
THERMOCRYPT GUI v1.0.0
Licensed under the MIT License.

MIT License

Copyright (c) 2025 Herman Nythe

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

---------------------------------------------------------------------------
DISCLAIMER OF WARRANTY & SCOPE
---------------------------------------------------------------------------

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOSS OF DATA OR CRYPTOGRAPHIC 
FAILURE), OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE 
USE OR OTHER DEALINGS IN THE SOFTWARE.

THIS SOFTWARE IS A RESEARCH PROTOTYPE. IT HAS NOT UNDERGONE A FORMAL 
SECURITY AUDIT. USE FOR CRITICAL SECURITY APPLICATIONS IS AT THE USER'S 
SOLE RISK.

---------------------------------------------------------------------------
DISCLAIMER OF WARRANTY & SCOPE
---------------------------------------------------------------------------
This software is a GUI wrapper for the 'thermo_core' cryptographic utility.
It is provided as a RESEARCH PROTOTYPE "as is", without warranty of any kind.
The author assumes no responsibility for data loss or cryptographic failure.

This wrapper attempts to use 'mlockall' via ctypes on Linux for memory 
protection, but Python's memory management is non-deterministic. For 
critical security applications, usage of the compiled CLI binary is 
recommended over this GUI.
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext, simpledialog
import subprocess
import os
import sys
import datetime
import hashlib
import re
import threading
import queue
import gc
import secrets
import time
import shutil
import resource

if getattr(sys, 'frozen', False):
    APP_PATH = os.path.dirname(sys.executable)
else:
    APP_PATH = os.path.dirname(os.path.abspath(__file__))

BINARY_NAME = os.path.join(APP_PATH, "thermo_core")
if sys.platform == "win32" and not os.path.exists(BINARY_NAME) and os.path.exists(BINARY_NAME + ".exe"):
    BINARY_NAME += ".exe"

CUSTOM_KEY_DIR = os.environ.get('THERMO_KEY_DIR', "")

COLORS = {
    "bg": "#F3F4F6",        
    "fg": "#1F2937",        
    "accent_1": "#FFFFFF",  
    "accent_2": "#E5E7EB",  
    "primary": "#1F2937",   
    "btn_bg": "#1E3A8A",    
    "btn_hover": "#172554", 
    "danger": "#B91C1C",    
    "warning": "#D97706",   
    "success": "#059669",   
    "log_bg": "#FFFFFF",    
    "highlight": "#1E40AF"  
}

FONT_UI = ("Segoe UI", 10)
FONT_UI_BOLD = ("Segoe UI", 10, "bold")
FONT_HEADER = ("Segoe UI", 11, "bold")
FONT_MONO = ("Consolas", 10)

class ToolTip(object):
    def __init__(self, widget, text='widget info'):
        self.waittime = 500
        self.wraplength = 250
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.widget.bind("<ButtonPress>", self.leave)
        self.id = None
        self.tw = None

    def enter(self, event=None):
        self.schedule()
    def leave(self, event=None):
        self.unschedule(); self.hidetip()
    def schedule(self):
        self.unschedule(); self.id = self.widget.after(self.waittime, self.showtip)
    def unschedule(self):
        if self.id: self.widget.after_cancel(self.id); self.id = None
    def showtip(self):
        x, y = self.widget.winfo_rootx() + 25, self.widget.winfo_rooty() + 20
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tw, text=self.text, justify='left',
                         background="#d9d9d9", relief='solid', borderwidth=1,
                         wraplength=self.wraplength, padx=5, pady=3)
        label.pack()
    def hidetip(self):
        if self.tw: self.tw.destroy(); self.tw = None

class ThermoGUI:
    def __init__(self, root):        
        if sys.platform.startswith("linux"):
             try:
                 resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                 import ctypes
                 libc = ctypes.CDLL("libc.so.6")
                 MCL_CURRENT = 1
                 MCL_FUTURE = 2
                 result = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
                 
                 if result != 0:
                     print("Warning: Failed to lock Python process in RAM. (Requires 'ulimit -l unlimited' or Root)")
                 else:
                     print("Security: Python process successfully LOCKED in RAM (No Swap).")
        
             except Exception as e:
                 print(f"Warning: Secure memory setup failed: {e}")
                
        self.root = root
        self.root.title("ThermoCrypt v1.0.0")
        self.root.geometry("950x920")
        self.root.minsize(900, 900)
        self.root.configure(bg=COLORS["bg"])
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1) 

        self.var_rate_limit = tk.BooleanVar(value=False)
        self.var_show_in_memo = tk.BooleanVar(value=False)
        self.var_acknowledge_risk = tk.BooleanVar(value=False)
        self.var_argon_level = tk.StringVar(value="interactive")
        self.var_binding_type = tk.StringVar(value="disk") 

        self.current_process = None
        self.is_cancelling = False

        if not os.path.exists(BINARY_NAME):
            messagebox.showerror("Error", f"Core binary not found:\n{BINARY_NAME}\nMake sure to compile thermo_core.cpp first.")
        
        self.apply_theme()
        
        header_frame = tk.Frame(root, bg=COLORS["btn_bg"], height=60)
        header_frame.grid(row=0, column=0, sticky="ew") 
        header_frame.pack_propagate(False)

        lbl_logo = tk.Label(header_frame, text=" 🛡️ THERMOCRYPT", font=("DejaVu Sans", 20, "bold"), 
                            bg=COLORS["btn_bg"], fg="#FFFFFF")
        lbl_logo.pack(side="left", padx=20, pady=10)
        
        lbl_sub = tk.Label(header_frame, text="v1.0.0", 
                           font=("Segoe UI", 10), bg=COLORS["btn_bg"], fg="#A5B4FC") 
        lbl_sub.pack(side="right", padx=20, pady=15)

        self.notebook = ttk.Notebook(root)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=15, pady=(15, 15))

        self.tab_text = ttk.Frame(self.notebook)
        self.tab_encrypt = ttk.Frame(self.notebook)
        self.tab_decrypt = ttk.Frame(self.notebook)
        self.tab_gen = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_text, text=" 📝 SECURE MEMO ")
        self.notebook.add(self.tab_encrypt, text=" 🔒 FILE LOCK ")
        self.notebook.add(self.tab_decrypt, text=" 🔓 FILE UNLOCK ")
        self.notebook.add(self.tab_gen, text=" 👤 IDENTITY ")

        self.setup_text_tab()
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        self.setup_gen_tab()

        footer_frame = tk.Frame(root, bg=COLORS["bg"])
        footer_frame.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 10))
        footer_frame.columnconfigure(1, weight=1)

        opt_frame = tk.Frame(footer_frame, bg=COLORS["bg"])
        opt_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(opt_frame, text="🛡️ Security Model", command=self.show_security_info).pack(side="left", padx=(0, 5))
        ttk.Button(opt_frame, text="📖 Guide", command=self.show_guide).pack(side="left", padx=(0, 15))

        rl_chk = tk.Checkbutton(opt_frame, text="Rate Limit",
                                variable=self.var_rate_limit, bg=COLORS["bg"], fg=COLORS["primary"],
                                selectcolor=COLORS["accent_1"], activebackground=COLORS["bg"])
        rl_chk.pack(side="left")
        ToolTip(rl_chk, "Adds 1s delay per attempt to slow down brute-force attacks.")

        tk.Label(opt_frame, text="|   Argon2 Cost:", bg=COLORS["bg"], fg=COLORS["fg"]).pack(side="left", padx=(15,5))
        argon_menu = ttk.OptionMenu(opt_frame, self.var_argon_level, "interactive",
                                    "interactive", "moderate", "sensitive")
        argon_menu.pack(side="left")
        
        self.lbl_argon_warn = tk.Label(opt_frame, text="⚠ High RAM Usage", bg=COLORS["bg"], fg=COLORS["warning"], font=("Segoe UI", 9, "bold"))

        prog_frame = tk.Frame(footer_frame, bg=COLORS["bg"])
        prog_frame.pack(fill="x", pady=(0, 5))
        
        self.lbl_progress = tk.Label(prog_frame, text="", bg=COLORS["bg"], fg=COLORS["fg"], font=("Segoe UI", 8))
        self.lbl_progress.pack(anchor="e")

        p_container = tk.Frame(prog_frame, bg=COLORS["bg"])
        p_container.pack(fill="x")
        
        self.progress = ttk.Progressbar(p_container, orient="horizontal", mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True)
        
        self.btn_cancel = tk.Button(p_container, text="🛑 Cancel", font=("Segoe UI", 8, "bold"), 
                                    bg=COLORS["danger"], fg="white", bd=0, padx=10,
                                    command=self.cancel_operation, state="disabled")
        self.btn_cancel.pack(side="left", padx=(5, 0))

        self.log_area = tk.Text(footer_frame, height=6, bg=COLORS["log_bg"], fg=COLORS["fg"],
                                font=("Consolas", 9), relief="flat", state="disabled")
        self.log_area.pack(fill="both", expand=True)
        
        self.status_bar = tk.Label(root, text="System Ready", bg=COLORS["accent_2"], fg=COLORS["fg"], anchor="w", padx=10, font=("Segoe UI", 9))
        self.status_bar.grid(row=3, column=0, sticky="ew")

        self.log("ThermoCrypt v1.0.0 Initialized.")
        self.var_argon_level.trace("w", self.on_argon_change)

    def apply_theme(self):
        style = ttk.Style(); style.theme_use('clam')
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["fg"], font=FONT_UI)
        
        TAB_PADDING = [20, 10] 
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=COLORS["accent_2"], foreground="#6B7280",
                        padding=TAB_PADDING, font=FONT_UI_BOLD, borderwidth=0)
        style.map("TNotebook.Tab", 
                  background=[("selected", COLORS["accent_1"])], 
                  foreground=[("selected", COLORS["primary"])],
                  padding=[("selected", TAB_PADDING)]) 
        
        style.configure("TButton", font=FONT_UI_BOLD, padding=6, 
                        background=COLORS["accent_1"], foreground=COLORS["fg"], 
                        borderwidth=1, bordercolor="#D1D5DB")
        style.map("TButton", background=[("active", COLORS["accent_2"])])
        
        style.configure("Action.TButton", background=COLORS["btn_bg"], foreground="#FFFFFF", borderwidth=0)
        style.map("Action.TButton", background=[("active", COLORS["btn_hover"])])
        
        style.configure("Danger.TButton", background=COLORS["danger"], foreground="#FFFFFF", borderwidth=0)
        style.map("Danger.TButton", background=[("active", "#991B1B")])

        style.configure("TLabelframe", background=COLORS["bg"], foreground=COLORS["fg"])
        style.configure("TLabelframe.Label", background=COLORS["bg"], foreground=COLORS["primary"], font=FONT_HEADER)

        self.root.option_add("*Entry.background", "#FFFFFF") 
        self.root.option_add("*Entry.foreground", "#000000")
        self.root.option_add("*Entry.relief", "solid")
        self.root.option_add("*Entry.borderwidth", 1)
        self.root.option_add("*Entry.font", FONT_MONO)
        
        if hasattr(self, 'log_area'):
            self.log_area.configure(bg=COLORS["log_bg"], fg=COLORS["fg"])

    def log(self, msg):
        self.log_area.configure(state="normal")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_area.insert("end", f"[{ts}] {msg}\n")
        self.log_area.see("end")
        self.log_area.configure(state="disabled")
        self.status_bar.config(text=msg)

    def on_argon_change(self, *args):
        if self.var_argon_level.get() == "sensitive":
            self.lbl_argon_warn.pack(side="left", padx=10)
        else:
            self.lbl_argon_warn.pack_forget()

    def show_security_info(self):
        info_win = tk.Toplevel(self.root)
        info_win.title("Security Model & Architecture")
        info_win.geometry("650x600")
        txt = scrolledtext.ScrolledText(info_win, wrap="word", font=("Segoe UI", 10))
        txt.pack(fill="both", expand=True)
        content = """
📖 THERMOCRYPT USER GUIDE

--- 1. IDENTITY GENERATION (First Step) ---
Before you can encrypt or decrypt, you need a digital identity.
1. Go to the 'IDENTITY' tab.
2. Name: Choose a unique alias (e.g., 'jdoe').
3. Binding:
   - 'Disk': Standard mode. Portable identity protected by a strong password.
   - Note: Hardware Binding (TPM) is available via the Linux Command Line Interface (CLI) only.
4. Password: Set a strong passphrase to protect your private vault.
5. Click 'GENERATE KEYS'.
   -> Result: Creates 'jdoe.thermoid' (Public - Share this!) and 'keys/jdoe/resonance.vault' (Private - Never share!).

--- 2. ENCRYPTING FILES (File Lock) ---
To secure a file for yourself or someone else:
1. Go to the 'FILE LOCK' tab.
2. Select File: Choose the document/image/archive to encrypt.
3. Recipient Identity:
   - To send to someone: Select THEIR public .thermoid file.
   - To store for yourself: Select YOUR OWN public .thermoid file.
4. Click 'ENCRYPT FILE'.
   -> Result: A new file ending in '.thermo' is created. The original file remains untouched.

--- 3. DECRYPTING FILES (File Unlock) ---
To open a file encrypted for you:
1. Go to the 'FILE UNLOCK' tab.
2. Encrypted File: Select the .thermo file.
3. Your Identity: Select your public .thermoid file (this tells the system which private vault to look for).
4. Password: Enter the password you set in Step 1.
5. Mode:
   - Standard: Decrypts the file back to disk.
   - 'View in Secure Memo': Decrypts text files directly to the RAM-only editor (leaves no trace on disk).
6. Click 'UNLOCK & DECRYPT'.

--- 4. SECURE MEMO (RAM-Only Encryption) ---
For quick text notes that should never touch the hard drive as plaintext:
1. Go to 'SECURE MEMO' tab.
2. Type or paste your sensitive text.
3. Select Recipient Identity (yours or others).
4. Click 'ENCRYPT & SAVE'.
   -> Result: Saves directly to an encrypted .thermo file. The text was never saved as a normal .txt file.

--- IMPORTANT NOTES ---

⚠️ NO RECOVERY: There is no "Forgot Password" feature. If you lose your password or your private vault file (resonance.vault), your data is mathematically unrecoverable.

⚠️ PUBLIC VS PRIVATE:
- .thermoid file: Public. Send this to anyone who needs to send you files.
- resonance.vault: Private. Keep this safe. Never share it.

⚠️ ADVANCED FEATURES (CLI):
- TPM Binding (Linux Only) is available via the terminal. This binds your identity to your specific computer's motherboard chip. Ensure you have backups, as motherboard failure could result in permanent data loss.
        """
        txt.insert("1.0", content)
        txt.configure(state="disabled")

    def show_guide(self):
        guide_win = tk.Toplevel(self.root)
        guide_win.title("User Guide & Workflow")
        guide_win.geometry("600x550")
        txt = scrolledtext.ScrolledText(guide_win, wrap="word", font=("Segoe UI", 10))
        txt.pack(fill="both", expand=True)
        content = """
🛡️ THERMOCRYPT v.1.0.0 - SECURITY ARCHITECTURE

1. HYBRID POST-QUANTUM ENCRYPTION (Confidentiality)
   - Algorithms: ML-KEM-768 (NIST FIPS 203) + X25519 (RFC 7748).
   - "Defense in Depth". Data is encapsulated using both a classical Elliptic Curve algorithm and a Post-Quantum Lattice-based algorithm.
   - Even if Quantum Computers break X25519 in the future, the ML-KEM layer remains secure. If a flaw is found in ML-KEM, X25519 protects the data today.

2. CRYPTOGRAPHIC IDENTITY (Authenticity)
   - Algorithm: ML-DSA-65 (NIST FIPS 204 / Dilithium).
   - Every user has a signed identity file (.thermoid).
   - The software verifies the digital signature before encryption. This guarantees you are encrypting for the intended recipient and prevents "Identity Spoofing" or man-in-the-middle key replacements.

3. HARDWARE BINDING (Anti-Clone & Theft Protection)
   - Cryptographic keys are mathematically bound to specific hardware constraints.
   - Status:
     * Disk Mode (Verified): Keys are encrypted with Argon2id and stored on disk. Secure as long as your passphrase is strong.
     * TPM Binding (Linux CLI Verified): Binds the identity to the specific machine's TPM 2.0 chip. This provides 2-Factor Security:
       1. Something you have (The physical computer/TPM).
       2. Something you know (The password).
       Even if the vault file is stolen, it cannot be decrypted on another machine.

4. AUTHENTICATED ENCRYPTION (Integrity)
   - Algorithm: XChaCha20-Poly1305 (IETF).
   - AEAD (Authenticated Encryption with Associated Data).
   - Provides high-speed stream encryption and inherently detects malicious tampering. If a single bit of the encrypted file is altered, decryption will fail immediately to protect the payload.

5. MEMORY HYGIENE & SAFETY
   - Core (C++): Uses `sodium_mlock` to pin sensitive keys in RAM, preventing them from being written to the hard drive (swap/pagefile). Keys are zeroed out (`memzero`) immediately after use.
   - GUI (Python): This interface is a wrapper. While it attempts to lock memory, Python's memory management is non-deterministic. For maximum security in high-risk environments, use the compiled CLI tool directly.

6. KEY DERIVATION (Brute-Force Resistance)
   - Algorithm: Argon2id (v1.3).
   - Converts your password into an encryption key using intensive memory and CPU operations.
   - Makes dictionary and brute-force attacks computationally expensive, resisting GPU and ASIC acceleration.
        """
        txt.insert("1.0", content)
        txt.configure(state="disabled")

    def secure_copy_handler(self, widget=None, event=None):
        try:
            target = widget if widget else self.root.focus_get()
            text = ""
            if isinstance(target, tk.Entry):
                if target.select_present():
                    text = target.get()[target.index("sel.first"):target.index("sel.last")]
            elif isinstance(target, tk.Text) or isinstance(target, scrolledtext.ScrolledText):
                if target.tag_ranges("sel"):
                    text = target.get("sel.first", "sel.last")
            
            if text:
                self.copy_to_clipboard_secure(text)
            
            return "break"
        except:
            return "break"
    
    def secure_cut_handler(self, widget=None, event=None):
        try:
            target = widget if widget else self.root.focus_get()
            text = ""
            
            if isinstance(target, tk.Entry):
                if target.select_present():
                    first = target.index("sel.first")
                    last = target.index("sel.last")
                    text = target.get()[first:last]
                    target.delete(first, last)

            elif isinstance(target, tk.Text) or isinstance(target, scrolledtext.ScrolledText):
                if target.tag_ranges("sel"):
                    text = target.get("sel.first", "sel.last")
                    target.delete("sel.first", "sel.last")
            
            if text:
                self.copy_to_clipboard_secure(text)
                self.log("✂ Secure Cut: Content removed & clipboard will wipe in 30s.")
            
            return "break"
        except:
            return "break"

    def copy_to_clipboard_secure(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        
        self.log("📋 Secure Copy: Clipboard will be wiped in 30s.")
        
        def wipe():
            try:
                curr = self.root.clipboard_get()
                if curr == text:
                    self.root.clipboard_clear()
                    self.log("🧹 Clipboard auto-cleared for security.")
            except: pass
        self.root.after(30000, wipe)
        
    def create_entry_row(self, parent, row, button_text="Browse", filetypes=None, callback=None, tooltip=None):
        frame = tk.Frame(parent, bg=COLORS["bg"])
        frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=4)
        frame.columnconfigure(0, weight=1)
        entry = tk.Entry(frame, font=FONT_MONO)
        entry.grid(row=0, column=0, sticky="ew", ipady=6, padx=(0, 8))
        if tooltip: ToolTip(entry, tooltip)
        self.add_context_menu(entry)
        btn = ttk.Button(frame, text=button_text, command=lambda: self.select_file(entry, filetypes, callback))
        btn.grid(row=0, column=1)
        return entry

    def add_context_menu(self, widget):
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Secure Cut", command=lambda: self.secure_cut_handler(widget))
        menu.add_command(label="Secure Copy", command=lambda: self.secure_copy_handler(widget))
        menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: widget.event_generate("<<SelectAll>>")) 
        
        def show_menu(event):
            menu.tk_popup(event.x_root, event.y_root)
            return "break"
            
        widget.bind("<Button-3>", show_menu) 
        if sys.platform == "darwin":
            widget.bind("<Button-2>", show_menu)
            
        widget.bind("<Control-c>", lambda e: self.secure_copy_handler(widget, e)) 
        widget.bind("<Control-x>", lambda e: self.secure_cut_handler(widget, e))
        
        def show_menu(event):
            menu.tk_popup(event.x_root, event.y_root)
            return "break"
            
        widget.bind("<Button-3>", show_menu) 
        if sys.platform == "darwin":
            widget.bind("<Button-2>", show_menu) 

    def select_file(self, entry_field, filetypes=None, callback=None):
        fn = filedialog.askopenfilename(filetypes=filetypes) if filetypes else filedialog.askopenfilename()
        if fn:
            fn = os.path.abspath(fn)
            entry_field.delete(0, "end"); entry_field.insert(0, fn)
            if callback: callback(fn)

    def get_fingerprint(self, filepath):
        try:
            with open(filepath, "rb") as f:
                digest = hashlib.sha256(f.read(4096)).hexdigest().upper() 
                return digest 
        except: return "ERROR"

    def update_fingerprint_label(self, filepath, label_widget):
        if filepath and os.path.exists(filepath):
            fp = self.get_fingerprint(filepath)
            label_widget.config(text=f"FILE ID: {fp}...", fg=COLORS["primary"])
        else: label_widget.config(text="", fg=COLORS["fg"])
    def copy_to_clipboard_secure(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        
        self.log("📋 Copied to clipboard. Auto-clearing in 30s...")
        
        def wipe():
            try:
                curr = self.root.clipboard_get()
                if curr == text:
                    self.root.clipboard_clear()
                    self.log("🧹 Clipboard auto-cleared for security.")
            except: pass
            
        self.root.after(30000, wipe)
        
    def setup_text_tab(self):
        container = ttk.Frame(self.tab_text, padding=20)
        container.pack(fill='both', expand=True)

        container.columnconfigure(0, weight=1)
        container.rowconfigure(1, weight=1) 

        toolbar = tk.Frame(container, bg=COLORS["bg"])
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        ttk.Button(toolbar, text="📂 Load", command=self.text_load_file).pack(side="left", padx=2)
        ttk.Button(toolbar, text="💾 Save Plain", command=self.text_save_file).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🧹 Clear", command=lambda: self.text_area.delete("1.0", "end")).pack(side="left", padx=2)
        ttk.Button(toolbar, text="✂ Clear Clipboard", command=self.clear_clipboard).pack(side="right", padx=2)

        self.text_area = scrolledtext.ScrolledText(container, bg=COLORS["log_bg"], fg=COLORS["fg"],
                                                  insertbackground=COLORS["btn_bg"], font=("Consolas", 11), relief="flat")
        self.text_area.grid(row=1, column=0, sticky="nsew", pady=(0, 15))
        self.add_context_menu(self.text_area)

        grp = ttk.LabelFrame(container, text=" Encrypt Memo ", padding=15)
        grp.grid(row=2, column=0, sticky="ew") 

        tk.Label(grp, text="Recipient Identity (.thermoid):", bg=COLORS["bg"], fg=COLORS["fg"]).pack(anchor="w")
        recip_row = tk.Frame(grp, bg=COLORS["bg"]); recip_row.pack(fill="x", pady=5)
        self.entry_text_recipient = tk.Entry(recip_row, font=FONT_MONO)
        self.entry_text_recipient.pack(side="left", fill="x", expand=True, ipady=4)
        self.add_context_menu(self.entry_text_recipient)
        
        ttk.Button(recip_row, text="Select ID", command=lambda: self.select_file(self.entry_text_recipient, [("Identity", "*.thermoid")], lambda f: self.update_fingerprint_label(f, self.lbl_text_fp))).pack(side="left", padx=5)
        
        self.lbl_text_fp = tk.Label(grp, text="", bg=COLORS["bg"], font=("Consolas", 9)); self.lbl_text_fp.pack(anchor="w", pady=(0, 10))

        ttk.Button(grp, text="🔒 ENCRYPT & SAVE (.thermo)", style="Action.TButton", command=self.run_text_encrypt_secure).pack(fill="x", pady=0)

    def clear_clipboard(self):
        self.root.clipboard_clear()
        self.log("Clipboard cleared.")

    def text_load_file(self):
        fn = filedialog.askopenfilename()
        if fn:
            try:
                with open(fn, 'r', encoding='utf-8') as f: self.text_area.delete("1.0", "end"); self.text_area.insert("1.0", f.read())
            except Exception as e: messagebox.showerror("Error", str(e))

    def text_save_file(self):
        fn = filedialog.asksaveasfilename()
        if fn:
            try:
                with open(fn, 'w', encoding='utf-8') as f: f.write(self.text_area.get("1.0", "end-1c"))
            except Exception as e: messagebox.showerror("Error", str(e))

    def run_text_encrypt_secure(self):
        recipient = self.entry_text_recipient.get().strip()
        if not recipient: return messagebox.showwarning("Missing", "Select recipient identity.")
        content = self.text_area.get("1.0", "end-1c")
        if not content.strip(): return messagebox.showwarning("Empty", "No content.")
        save_path = filedialog.asksaveasfilename(defaultextension=".thermo", filetypes=[("Thermo Encrypted", "*.thermo")])
        if not save_path: return
        try:
            input_data = bytearray(content, 'utf-8')
        except:
            input_data = bytearray()
        del content

        args = [BINARY_NAME, "--encrypt-text", save_path, recipient]
        
        if CUSTOM_KEY_DIR: args.extend(["--keydir", CUSTOM_KEY_DIR])
        else: args.extend(["--keydir", os.path.join(APP_PATH, "keys")])
        if self.var_rate_limit.get(): args.append("--rate-limit")
        args.extend(["--argon-level", self.var_argon_level.get()])

        self.log("🔒 Encrypting directly from memory...")
        self.progress['value'] = 0
        self.progress['mode'] = 'indeterminate'
        self.progress.start(10)
        self.btn_cancel.config(state="normal")

        def worker(secure_data=input_data):
            try:
                proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, text=False, bufsize=0)
                
                stdout, stderr = proc.communicate(input=secure_data)

                if proc.returncode == 0:
                    self.root.after(0, lambda: messagebox.showinfo("Success", f"Securely encrypted to:\n{os.path.basename(save_path)}"))
                    self.root.after(0, lambda: self.log("Encryption complete."))
                else:
                    err_msg = stderr.decode('utf-8', errors='replace')
                    self.root.after(0, lambda: messagebox.showerror("Core Error", f"{err_msg}"))
                    self.root.after(0, lambda: self.log("Encryption failed."))

            except Exception as e:
                final_error = str(e)
                self.root.after(0, lambda: messagebox.showerror("GUI Error", final_error))
            
            finally:
                if secure_data is not None:
                    try:
                        for i in range(len(secure_data)):
                            secure_data[i] = 0
                    except: pass
                
                gc.collect()
                self.root.after(0, self.progress.stop)
                self.root.after(0, lambda: self.btn_cancel.config(state="disabled"))

        threading.Thread(target=worker, daemon=True).start()



    def setup_encrypt_tab(self):
        container = ttk.Frame(self.tab_encrypt, padding=40)
        container.pack(fill='both', expand=True)
        
        grp = ttk.LabelFrame(container, text=" File Encryption ", padding=20)
        grp.pack(fill="both", expand=True)
        grp.columnconfigure(0, weight=1)

        tk.Label(grp, text="1. Select File:", bg=COLORS["bg"], fg=COLORS["primary"], font=FONT_UI_BOLD).grid(row=0, sticky="w", pady=(10,5))
        self.entry_enc_file = self.create_entry_row(grp, 1)

        tk.Label(grp, text="2. Recipient Identity (.thermoid):", bg=COLORS["bg"], fg=COLORS["primary"], font=FONT_UI_BOLD).grid(row=2, sticky="w", pady=(20,5))
        self.entry_enc_id = self.create_entry_row(grp, 3, button_text="Select ID", filetypes=[("Identity", "*.thermoid")], callback=lambda f: self.update_fingerprint_label(f, self.lbl_enc_fp))
        self.lbl_enc_fp = tk.Label(grp, text="", bg=COLORS["bg"], font=("Consolas", 9)); self.lbl_enc_fp.grid(row=4, sticky="w", pady=(0, 20))

        ttk.Button(grp, text="🔒 ENCRYPT FILE", style="Action.TButton", command=self.run_encrypt).grid(row=5, sticky="ew", ipady=10, pady=20)

    def setup_decrypt_tab(self):
        container = ttk.Frame(self.tab_decrypt, padding=40)
        container.pack(fill='both', expand=True)

        grp = ttk.LabelFrame(container, text=" File Decryption ", padding=20)
        grp.pack(fill="both", expand=True)
        grp.columnconfigure(0, weight=1)

        tk.Label(grp, text="1. Encrypted File (.thermo):", bg=COLORS["bg"], fg=COLORS["primary"], font=FONT_UI_BOLD).grid(row=0, sticky="w", pady=(10,5))
        self.entry_dec_file = self.create_entry_row(grp, 1, filetypes=[("Encrypted", "*.thermo")])

        tk.Label(grp, text="2. Your Identity Name (.thermoid):", bg=COLORS["bg"], fg=COLORS["primary"], font=FONT_UI_BOLD).grid(row=2, sticky="w", pady=(20,5))
        self.entry_dec_name = self.create_entry_row(grp, 3, button_text="Select ID", filetypes=[("Identity", "*.thermoid")])

        pw_frame = tk.Frame(grp, bg=COLORS["bg"])
        pw_frame.grid(row=4, sticky="ew", pady=(20, 0))
        
        tk.Label(pw_frame, text="3. Password:", bg=COLORS["bg"], fg=COLORS["primary"], font=FONT_UI_BOLD).pack(side="left")
        
        entry_frame = tk.Frame(grp, bg=COLORS["bg"])
        entry_frame.grid(row=5, sticky="ew", pady=(5, 20))
        
        self.entry_dec_pass = tk.Entry(entry_frame, show="•", font=FONT_MONO)
        self.entry_dec_pass.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=6)

        chk = tk.Checkbutton(grp, text="View in Secure Memo (RAM-only)", variable=self.var_show_in_memo, bg=COLORS["bg"], fg=COLORS["fg"], selectcolor=COLORS["accent_1"])
        chk.grid(row=6, sticky="w", pady=(10, 15))

        ttk.Button(grp, text="🔓 UNLOCK & DECRYPT", style="Danger.TButton", command=self.run_decrypt).grid(row=7, sticky="ew", ipady=10, pady=(0, 20))

    def setup_gen_tab(self):
        container = ttk.Frame(self.tab_gen, padding=30)
        container.pack(fill='both', expand=True)

        grp = ttk.LabelFrame(container, text=" Generate New Identity ", padding=20)
        grp.pack(fill="both", expand=True)
        grp.columnconfigure(1, weight=1)

        tk.Label(grp, text="Name (No spaces):", bg=COLORS["bg"], fg=COLORS["fg"]).grid(row=0, column=0, sticky="w", pady=(0, 15))
        self.entry_gen_name = tk.Entry(grp, font=FONT_MONO)
        self.entry_gen_name.grid(row=0, column=1, sticky="ew", ipady=6, padx=(10, 0), pady=(0, 15))

        tk.Label(grp, text="Hardware Binding:", bg=COLORS["bg"], fg=COLORS["fg"]).grid(row=1, column=0, sticky="w", pady=(0, 15))
        
        bind_options = ["disk (Standard - Portable)", "tpm (Linux CLI Only)"]
            
        bind_menu = ttk.OptionMenu(grp, self.var_binding_type, bind_options[0], *bind_options)
        bind_menu.grid(row=1, column=1, sticky="ew", ipady=6, padx=(10, 0), pady=(0, 15))
        
        menu_object = bind_menu["menu"]
        menu_object.entryconfigure(1, state="disabled")

        tk.Label(grp, text="Password:", bg=COLORS["bg"], fg=COLORS["fg"]).grid(row=2, column=0, sticky="w")
        self.entry_gen_pass = tk.Entry(grp, show="•", font=FONT_MONO)
        self.entry_gen_pass.grid(row=2, column=1, sticky="ew", ipady=6, padx=(10, 0))
        self.entry_gen_pass.bind("<KeyRelease>", self.check_pw_strength)

        tk.Label(grp, text="Confirm:", bg=COLORS["bg"], fg=COLORS["fg"]).grid(row=3, column=0, sticky="w", pady=(10, 0))
        self.entry_gen_confirm = tk.Entry(grp, show="•", font=FONT_MONO)
        self.entry_gen_confirm.grid(row=3, column=1, sticky="ew", ipady=6, padx=(10, 0), pady=(10, 0))
        self.entry_gen_confirm.bind("<KeyRelease>", self.check_pw_strength)

        self.lbl_pw_strength = tk.Label(grp, text="", bg=COLORS["bg"], font=FONT_UI_BOLD)
        self.lbl_pw_strength.grid(row=6, column=1, sticky="w", pady=5, padx=10)

        self.chk_risk = tk.Checkbutton(grp, text="I understand passwords and bindings are permanent.", variable=self.var_acknowledge_risk, bg=COLORS["bg"], fg=COLORS["danger"], selectcolor=COLORS["accent_1"], command=self.toggle_gen_btn)
        self.chk_risk.grid(row=7, column=0, columnspan=2, sticky="w", pady=20)

        self.btn_gen = ttk.Button(grp, text="👤 GENERATE KEYS", style="Action.TButton", command=self.run_gen, state="disabled")
        self.btn_gen.grid(row=8, column=0, columnspan=2, sticky="ew", ipady=10)

    def check_pw_strength(self, event=None):
        pw = self.entry_gen_pass.get()
        confirm = self.entry_gen_confirm.get()
        if not pw:
            self.lbl_pw_strength.config(text="", fg=COLORS["fg"])
            return
        if confirm and pw != confirm:
            self.lbl_pw_strength.config(text="Passwords do not match", fg=COLORS["danger"])
            return

        score = 0
        if len(pw) >= 8: score += 1
        if len(pw) >= 12: score += 1
        if len(pw) >= 16: score += 1
        if re.search(r"[A-Z]", pw): score += 1
        if re.search(r"[0-9]", pw): score += 1
        if re.search(r"[^A-Za-z0-9]", pw): score += 1 

        if len(pw) < 6:
            self.lbl_pw_strength.config(text="Very Weak (Unsafe)", fg=COLORS["danger"])
        elif score < 3:
            self.lbl_pw_strength.config(text="Weak", fg=COLORS["warning"]) 
        elif score < 5:
            self.lbl_pw_strength.config(text="Strong", fg=COLORS["primary"]) 
        else:
            self.lbl_pw_strength.config(text="Very Strong (Excellent)", fg=COLORS["success"]) 

    def toggle_gen_btn(self):
        self.btn_gen.config(state="normal" if self.var_acknowledge_risk.get() else "disabled")

    def cancel_operation(self):
        if self.current_process and self.current_process.poll() is None:
            self.is_cancelling = True
            self.log("🛑 Cancelling operation...")
            try:
                self.current_process.terminate() 
            except: pass
            self.btn_cancel.config(state="disabled")

    def run_process_threaded(self, args, password_input=None, stdin_content=None, on_success=None, capture_stdout=False):
        if CUSTOM_KEY_DIR: args.extend(["--keydir", CUSTOM_KEY_DIR])
        else: args.extend(["--keydir", os.path.join(APP_PATH, "keys")])
        
        if self.var_rate_limit.get(): args.append("--rate-limit")
        args.extend(["--argon-level", self.var_argon_level.get()])

        self.progress['value'] = 0; self.progress['mode'] = 'indeterminate'; self.progress.start(10)
        self.lbl_progress.config(text="Initializing...")
        
        self.btn_cancel.config(state="normal")
        self.is_cancelling = False
        
        def worker():
            start_time = time.time() 
            try:
                self.current_process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                                                        stderr=subprocess.PIPE, text=False, bufsize=0) 
                
                combined_input = (password_input or "") + "\n" + (stdin_content or "")
                pass_str = (password_input or "") + "\n" + (stdin_content or "")
                input_bytes = bytearray(pass_str, 'utf-8')
                
                def writer():
                    if input_bytes:
                        try: self.current_process.stdin.write(input_bytes); self.current_process.stdin.flush()
                        except: pass
                        for i in range(len(input_bytes)):
                            input_bytes[i] = 0
                    try: self.current_process.stdin.close()
                    except: pass
                
                threading.Thread(target=writer, daemon=True).start()

                q_stderr, q_stdout = queue.Queue(), queue.Queue()
                self.captured_bytes = bytearray() 

                def reader(pipe, q): 
                    try:
                        for line in pipe: q.put(line)
                    except: pass
                    finally: pipe.close()
                
                threading.Thread(target=reader, args=(self.current_process.stderr, q_stderr), daemon=True).start()
                threading.Thread(target=reader, args=(self.current_process.stdout, q_stdout), daemon=True).start()

                last_percent = -1
                
                while True:
                    retcode = self.current_process.poll()
                    stderr_alive = False
                    
                    try:
                        while True:
                            raw_line = q_stderr.get_nowait()
                            line = raw_line.decode('utf-8', errors='replace').strip()
                            stderr_alive = True
                            
                            elapsed = time.time() - start_time
                            
                            if line.startswith("PROGRESS:"):
                                try:
                                    p = int(line.split(":")[1])
                                    if p != last_percent: 
                                        self.root.after(0, lambda v=p: self.progress.configure(mode="determinate", value=v))
                                        last_percent = p
                                except: pass
                            elif line.startswith("PROGRESS_METRICS"):
                                pass
                            elif line:
                                self.root.after(0, lambda m=line: self.log(m))
                    except queue.Empty: pass

                    if capture_stdout:
                        try:
                            while True: 
                                chunk = q_stdout.get_nowait()
                                self.captured_bytes.extend(chunk)
                        except queue.Empty: pass

                    if retcode is not None and not stderr_alive:
                        if capture_stdout and not q_stdout.empty(): continue 
                        if not q_stderr.empty(): continue
                        break
                    
                    threading.Event().wait(0.05)

                self.root.after(0, self.progress.stop)
                self.root.after(0, lambda: self.lbl_progress.configure(text="Idle"))
                self.root.after(0, lambda: self.btn_cancel.config(state="disabled"))
                
                if self.is_cancelling: return

                if retcode == 0:
                    self.root.after(0, lambda: self.log("Success."))
                    if on_success: 
                        if capture_stdout:
                             try:
                                 final_text = self.captured_bytes.decode('utf-8') 
                                 self.root.after(0, lambda: on_success(final_text))
                             except:
                                 self.root.after(0, lambda: messagebox.showerror("Binary Data", "Cannot display binary."))
                        else:
                             self.root.after(0, lambda: on_success())
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Operation failed. Check logs."))

            except Exception as e:
                self.root.after(0, self.progress.stop)
                self.root.after(0, lambda: self.log(f"GUI Error: {str(e)}"))

        threading.Thread(target=worker, daemon=True).start()

    def run_encrypt(self):
        f, i = self.entry_enc_file.get().strip(), self.entry_enc_id.get().strip()
        if not f or not i: return messagebox.showwarning("Missing", "Select file and identity.")
        self.run_process_threaded([BINARY_NAME, "--encrypt", f, i], on_success=lambda: messagebox.showinfo("Success", f"Encrypted:\n{os.path.basename(f)}.thermo"))

    def run_decrypt(self):
        f, n_path, p = self.entry_dec_file.get().strip(), self.entry_dec_name.get().strip(), self.entry_dec_pass.get()
        
        if not all([f, n_path, p]): return messagebox.showwarning("Missing", "Fill all fields.")
        
        n = os.path.basename(n_path).replace(".thermoid", "")
        auth_input = f"{p}\n"
        self.entry_dec_pass.delete(0, "end")
        
        if self.var_show_in_memo.get():
            self.run_process_threaded([BINARY_NAME, "--decrypt-stdout", f, n], password_input=auth_input, capture_stdout=True,
                                      on_success=lambda d: (self.entry_dec_pass.delete(0,"end"), 
                                                            self.notebook.select(self.tab_text), self.text_area.delete("1.0","end"), self.text_area.insert("1.0", d)))
        else:
            self.run_process_threaded([BINARY_NAME, "--decrypt", f, n], password_input=auth_input,
                                      on_success=lambda: (self.entry_dec_pass.delete(0,"end"), messagebox.showinfo("Success", "Decrypted.")))

    def run_gen(self):
        n, p1, p2 = self.entry_gen_name.get().strip(), self.entry_gen_pass.get(), self.entry_gen_confirm.get()
        
        if not n: return messagebox.showwarning("Missing", "Name required.")
        if not p1: return messagebox.showwarning("Missing", "Password required.")
        if p1 != p2: return messagebox.showerror("Error", "Passwords mismatch.")
        
        cmd = [BINARY_NAME, "--gen", n]
        auth_input = f"{p1}\n"
        
        self.entry_gen_pass.delete(0, "end")
        self.entry_gen_confirm.delete(0, "end")
        self.lbl_pw_strength.config(text="")
        
        self.run_process_threaded(cmd, password_input=auth_input,
                                  on_success=lambda: (messagebox.showinfo("Created", f"Identity '{n}' ready."), 
                                                      self.var_acknowledge_risk.set(False), 
                                                      self.toggle_gen_btn()))

if __name__ == "__main__":
    root = tk.Tk()
    app = ThermoGUI(root)
    root.mainloop()