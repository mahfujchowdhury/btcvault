"""
btcpanel.py — Bitcoin tabs for BTCVault (imported by btcvault.py; needs btcv.py alongside).

Networks     : Mainnet, Testnet4, Testnet3, Signet, Regtest
Address types: Legacy (BIP-44), Native SegWit (BIP-84), Nested SegWit (BIP-49), Taproot (BIP-86)

    1. Create Wallet (OFFLINE)      seed -> encrypted keystore
    2. Export Watch-only (OFFLINE)  public key for the online machine / BlueWallet / Sparrow / Electrum
    3. Wallet / Balance             import watch-only key, scan addresses, receive address
    4. Build PSBT                   pick coins, add change, produce UNSIGNED PSBT (+ QR / file)
    5. Sign PSBT (OFFLINE)          independent review, then sign with the keystore
    6. Broadcast                    decode signed PSBT / raw tx, show fee, broadcast

Keystone mode: tab 2 also shows a Keystone-style pairing QR (ur:crypto-multi-accounts / ur:crypto-account) so
UniSat, OKX, Sparrow, BlueWallet … can add BTCVault as a "Keystone" hardware wallet; tab 5 has a hardware-wallet
output mode (signature only, not finalised) which is what those wallets expect back.

Real-money rule: for MAINNET the seed / keystore password are only accepted when BTCVault runs with --offline.
Test networks (signet / testnet) work on a single online machine so you can try the whole flow quickly.
"""

import json
import os
import time
import tkinter as tk
from datetime import datetime
from decimal import Decimal, InvalidOperation
from tkinter import ttk, messagebox, filedialog

import btcv

MONO = ("Consolas", 10)


class BTCPanel:
    T1, T2, T3, T4, T5, T6 = ("1. Create Wallet (OFFLINE)", "2. Export Watch-only (OFFLINE)", "3. Wallet / Balance",
                              "4. Build PSBT", "5. Sign PSBT (OFFLINE)", "6. Broadcast")

    def __init__(self, parent, app, offline: bool):
        self.app, self.offline = app, offline
        self.net_var = tk.StringVar(value=btcv.DEFAULT_NET)
        self.api_var = tk.StringVar(value=btcv.NETWORKS[btcv.DEFAULT_NET]["api"])
        self.script_var = tk.StringVar(value=btcv.script_label(btcv.DEFAULT_SCRIPT))
        self.net_note = tk.StringVar()
        self.watch = None          # btcv.Watch imported on tab 3
        self.scan = None           # result of btcv.scan_wallet
        self.export_watch = None   # Watch produced on tab 2
        self.export_all = None     # btcv.keystone_bundle(): public keys for the Keystone-style pairing QRs
        self.last_psbt = None      # unsigned PSBT built on tab 4
        self.signed = None         # result of btcv.sign_psbt
        self.nb = ttk.Notebook(parent)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tabs = {}
        for name in (self.T1, self.T2, self.T3, self.T4, self.T5, self.T6):
            fr = ttk.Frame(self.nb)
            self.nb.add(fr, text=name)
            self.tabs[name] = fr
        self._on_net_change(initial=True)
        self._create_tab(); self._export_tab(); self._wallet_tab()
        self._build_tab(); self._sign_tab(); self._broadcast_tab()

    # ----------------------------------------------------------- helpers
    def status(self, msg): self.app.set_status(msg)

    def _text(self, parent, height, row, col=0, span=4, pad=10, mono=True):
        box = ttk.Frame(parent)
        box.grid(row=row, column=col, columnspan=span, padx=pad, pady=6, sticky="nsew")
        t = tk.Text(box, height=height, wrap="word", font=MONO if mono else None)
        sb = ttk.Scrollbar(box, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return t

    @staticmethod
    def _set(widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)

    def _copy(self, text):
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(text)
        self.status("Copied to clipboard.")

    def _net_row(self, parent, row, script=False):
        ttk.Label(parent, text="Network:").grid(row=row, column=0, sticky="e", padx=6, pady=3)
        cb = ttk.Combobox(parent, values=list(btcv.NETWORKS), state="readonly", textvariable=self.net_var)
        cb.grid(row=row, column=1, sticky="we", padx=6, pady=3)
        cb.bind("<<ComboboxSelected>>", lambda e: self._on_net_change())
        ttk.Label(parent, textvariable=self.net_note, font=("Segoe UI", 9, "bold")).grid(row=row, column=2, sticky="w", padx=6)
        if script:
            box = ttk.Frame(parent)
            box.grid(row=row, column=3, sticky="w", padx=6)
            ttk.Label(box, text="Address type:").pack(side="left")
            sc = ttk.Combobox(box, values=list(btcv.SCRIPT_LABELS), state="readonly", width=34,
                              textvariable=self.script_var)
            sc.pack(side="left", padx=4)
            sc.bind("<<ComboboxSelected>>", lambda e: self._on_script_change())

    def _on_script_change(self):
        want = btcv.SCRIPT_LABELS[self.script_var.get()]
        if self.watch is not None and self.watch.script != want:
            self.watch = self.scan = None
            self.status("Address type changed — import the watch-only key again on tab 3.")

    def _on_net_change(self, initial=False):
        net = self.net_var.get()
        if net == "Bitcoin Regtest" and not initial:
            self.status("Regtest: set 'Explorer API' to YOUR local Esplora/electrs (default http://127.0.0.1:3002).")
        self.api_var.set(btcv.NETWORKS[net]["api"])
        self.net_note.set("test coins — no value" if btcv.NETWORKS[net]["test"] else "REAL BITCOIN")
        if not initial and self.watch is not None and self.watch.network != net:
            self.watch = self.scan = None
            self.status("Network changed — import the watch-only key again on tab 3.")

    def _guard(self, network, what):
        """Real-money secrets never touch a networked machine."""
        if self.offline or btcv.NETWORKS[network]["test"]:
            return True
        messagebox.showerror("Offline only",
                             f"{what} for MAINNET is only allowed on the air-gapped machine.\n\n"
                             f"Run:  python btcvault.py --offline\n\n(Test networks work online so you can rehearse.)")
        return False

    def _confirm(self, title, text, ok="Sign", danger=False):
        """Modal review window with a scrollable, monospaced report. Returns True if accepted."""
        win = tk.Toplevel(self.app.root)
        win.title(title)
        win.geometry("900x560")
        win.transient(self.app.root)
        tk.Label(win, text="Read every line. The recipient address and amount are what you are agreeing to.",
                 fg="#a00", font=("Segoe UI", 10, "bold")).pack(pady=(8, 2))
        box = ttk.Frame(win)
        box.pack(fill="both", expand=True, padx=10, pady=6)
        t = tk.Text(box, font=MONO, wrap="none")
        ys = ttk.Scrollbar(box, command=t.yview)
        xs = ttk.Scrollbar(win, orient="horizontal", command=t.xview)
        t.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        xs.pack(fill="x", padx=10)
        t.tag_configure("warn", foreground="#b26a00", font=("Consolas", 10, "bold"))
        t.tag_configure("err", foreground="#b00020", font=("Consolas", 10, "bold"))
        t.tag_configure("send", foreground="#b00020")
        t.tag_configure("head", font=("Consolas", 10, "bold"))
        for line in text.splitlines():
            tag = ("warn" if line.startswith("WARNING") else "err" if line.startswith("ERROR")
                   else "send" if "SENDING TO" in line else "head" if line.isupper() or line.startswith(("INPUTS", "OUTPUTS")) else "")
            t.insert("end", line + "\n", tag)
        t.config(state="disabled")
        result = {"ok": False}
        bar = tk.Frame(win)
        bar.pack(pady=8)

        def accept():
            result["ok"] = True
            win.destroy()
        tk.Button(bar, text=f"{ok}", command=accept, bg="#b00020" if danger else "#2e7d32", fg="white",
                  padx=18).pack(side="left", padx=10)
        tk.Button(bar, text="Cancel", command=win.destroy, padx=18).pack(side="left", padx=10)
        win.wait_visibility()
        win.grab_set()
        self.app.root.wait_window(win)
        return result["ok"]

    def _qr_psbt(self, psbt, title):
        try:
            frames = btcv.psbt_ur_frames(psbt, 100)
            self.app.show_qr_window(frames[0], title, frames=frames)
        except ImportError:
            messagebox.showinfo("Standard QR needs cbor2",
                                "pip install cbor2  (and keep ur.py next to btcvault.py) for standard "
                                "ur:crypto-psbt QR codes.\n\nShowing an BTCVault-only QR instead — other wallets "
                                "can't read it; copy the base64 text for them.")
            self.app.show_qr_window(psbt.to_base64(), title)

    # ================================================= TAB 1: CREATE
    def _create_tab(self):
        f = self.tabs[self.T1]
        ttk.Label(f, foreground="#a00", text="Generate a brand-new Bitcoin wallet (pick network + address type). Do this on the OFFLINE "
                  "machine. The 24 words are your backup; the keystore file is your encrypted working copy."
                  ).grid(row=0, column=0, columnspan=4, sticky="w", padx=10, pady=8)
        self._net_row(f, 1, script=True)
        ttk.Label(f, text="Keystore password:").grid(row=2, column=0, sticky="e", padx=8, pady=3)
        self.c_pw1 = ttk.Entry(f, show="*"); self.c_pw1.grid(row=2, column=1, sticky="we", padx=8)
        ttk.Label(f, text="Repeat password:").grid(row=3, column=0, sticky="e", padx=8, pady=3)
        self.c_pw2 = ttk.Entry(f, show="*"); self.c_pw2.grid(row=3, column=1, sticky="we", padx=8)
        ttk.Label(f, text="BIP-39 passphrase (optional):").grid(row=4, column=0, sticky="e", padx=8, pady=3)
        self.c_pass = ttk.Entry(f, show="*"); self.c_pass.grid(row=4, column=1, sticky="we", padx=8)
        ttk.Label(f, foreground="#666", text="Advanced: NOT stored anywhere — lose it and the coins are gone. Leave empty if unsure."
                  ).grid(row=4, column=2, columnspan=2, sticky="w")
        ttk.Button(f, text="Generate 24-word wallet", command=self.create_wallet
                   ).grid(row=5, column=1, sticky="we", padx=8, pady=10)
        ttk.Separator(f).grid(row=6, column=0, columnspan=4, sticky="we", pady=6)
        ttk.Label(f, text="Restore from an existing seed phrase (e.g. to test with a BlueWallet-created seed):"
                  ).grid(row=7, column=0, columnspan=3, sticky="w", padx=8)
        self.c_seed = tk.Text(f, height=3, width=70)
        self.c_seed.grid(row=8, column=0, columnspan=3, sticky="we", padx=8, pady=3)
        ttk.Button(f, text="Restore + encrypt to keystore", command=self.restore_wallet
                   ).grid(row=9, column=1, sticky="we", padx=8, pady=6)
        self.c_out = self._text(f, 12, 10)
        f.columnconfigure(1, weight=1); f.rowconfigure(10, weight=1)

    def _check_pw(self):
        p1, p2 = self.c_pw1.get(), self.c_pw2.get()
        if len(p1) < 8:
            messagebox.showerror("Password", "Password must be at least 8 characters."); return None
        if p1 != p2:
            messagebox.showerror("Password", "Passwords do not match."); return None
        return p1

    def _save_keystore(self, ks):
        fp = ks["fingerprint"]
        tag = ks["network"].replace("Bitcoin ", "").lower()
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"BTC--{tag}--{ks['script']}--{fp}.btcvault.json",
                                            filetypes=[("Bitcoin keystore", "*.json")])
        if path:
            with open(path, "w") as fh:
                json.dump(ks, fh, indent=1)
        return path

    def _create_common(self, mnemonic, restored):
        net = self.net_var.get()
        if not self._guard(net, "Creating a wallet"):
            return
        pw = self._check_pw()
        if not pw:
            return
        passphrase = self.c_pass.get()
        script = btcv.SCRIPT_LABELS[self.script_var.get()]

        def work():
            ks = btcv.keystore_create(mnemonic, pw, net, passphrase, script)
            w = btcv.Wallet(mnemonic, passphrase, net, script=script)
            return ks, w.watch
        def done(res, err):
            if err:
                return messagebox.showerror("Error", str(err))
            ks, watch = res
            path = self._save_keystore(ks)
            if not path:
                return
            out = (f"{'Restored' if restored else 'Wallet created'} {datetime.now():%Y-%m-%d %H:%M}\n"
                   f"Network     : {net}   ({self.net_note.get()})\n"
                   f"Address type: {btcv.script_label(script)}   path {ks['path']}\n"
                   f"Fingerprint : {ks['fingerprint']}\nFirst address: {ks['first_address']}\nKeystore    : {path}\n\n"
                   f"- The keystore is encrypted (scrypt + AES-256-GCM). Copy it only to the OFFLINE signing machine.\n"
                   f"- The 24 words are NOT saved anywhere except inside that encrypted file.\n"
                   f"- BIP-39 passphrase {'IS' if ks['passphrase'] else 'is NOT'} used.\n\n"
                   f"PUBLIC watch-only data (safe for the online machine):\n{watch.export_text()}")
            if not restored:
                self.app.show_seed_dialog(mnemonic, ks["first_address"])
            self._set(self.c_out, out)
            self.c_pw1.delete(0, "end"); self.c_pw2.delete(0, "end"); self.c_pass.delete(0, "end")
            self.status(f"Bitcoin wallet {'restored' if restored else 'created'}: {ks['first_address']}")
        self.status("Encrypting keystore (scrypt)…")
        self.app.async_do(work, done)

    def create_wallet(self):
        self._create_common(btcv.new_mnemonic(24), restored=False)

    def restore_wallet(self):
        words = btcv.normalize_mnemonic(self.c_seed.get("1.0", "end"))
        if not btcv.bip39.mnemonic_is_valid(words):
            return messagebox.showerror("Seed", "Invalid seed phrase (unknown word, wrong count or bad checksum).")
        self.c_seed.delete("1.0", "end")
        self._create_common(words, restored=True)

    # ================================================= TAB 2: EXPORT WATCH-ONLY
    def _export_tab(self):
        f = self.tabs[self.T2]
        ttk.Label(f, foreground="#a00", justify="left", text=(
            "Decrypt your keystore and show the PUBLIC account key, so the online machine — or BlueWallet / Sparrow / Electrum —\n"
            "can watch this wallet and build transactions for it. Nothing secret leaves this screen.")
            ).grid(row=0, column=0, columnspan=4, sticky="w", padx=10, pady=8)
        ttk.Label(f, text="Keystore file:").grid(row=1, column=0, sticky="e", padx=8)
        self.x_ks = ttk.Entry(f); self.x_ks.grid(row=1, column=1, sticky="we", padx=6, pady=3)
        ttk.Button(f, text="Browse…", command=lambda: self._pick_ks(self.x_ks, self.x_info)).grid(row=1, column=2, sticky="w")
        self.x_info = ttk.Label(f, text="", foreground="#345"); self.x_info.grid(row=2, column=1, columnspan=3, sticky="w", padx=6)
        ttk.Label(f, text="Keystore password:").grid(row=3, column=0, sticky="e", padx=8)
        self.x_pw = ttk.Entry(f, show="*"); self.x_pw.grid(row=3, column=1, sticky="we", padx=6, pady=3)
        ttk.Label(f, text="BIP-39 passphrase (if used):").grid(row=4, column=0, sticky="e", padx=8)
        self.x_pass = ttk.Entry(f, show="*"); self.x_pass.grid(row=4, column=1, sticky="we", padx=6, pady=3)
        ttk.Button(f, text="Show watch-only export", command=self.export_show).grid(row=5, column=1, sticky="w", padx=6, pady=8)
        bar = ttk.Frame(f); bar.grid(row=6, column=0, columnspan=4, sticky="w", padx=8)
        ttk.Button(bar, text="QR: extended pubkey  (BlueWallet, Electrum, Sparrow)", command=lambda: self._export_qr("slip")).pack(side="left", padx=4)
        ttk.Button(bar, text="QR: key-origin  (BTCVault online, has fingerprint)", command=lambda: self._export_qr("origin")).pack(side="left", padx=4)
        ttk.Button(bar, text="Save to file…", command=self.export_save).pack(side="left", padx=4)
        ttk.Button(bar, text="Save zpub only (Electrum)", command=self.export_save_key).pack(side="left", padx=4)
        bar2 = ttk.Frame(f); bar2.grid(row=7, column=0, columnspan=4, sticky="w", padx=8, pady=2)
        ttk.Button(bar2, text="QR: UniSat / BlueWallet / Sparrow  (crypto-account)",
                   command=lambda: self._export_ks_qr("account")).pack(side="left", padx=4)
        ttk.Button(bar2, text="QR: OKX Wallet  (Keystone multi-accounts, BTC + ETH keys)",
                   command=lambda: self._export_ks_qr("multi")).pack(side="left", padx=4)
        self.x_out = self._text(f, 12, 8)
        f.columnconfigure(1, weight=1); f.rowconfigure(8, weight=1)

    def _export_ks_qr(self, kind):
        if not self.export_watch or not self.export_all:
            return messagebox.showinfo("Export", "Click 'Show watch-only export' first.")
        w = self.export_watch
        if kind == "multi" and btcv.NETWORKS[w.network]["test"]:
            if not messagebox.askyesno("Test network + OKX",
                                       f"This wallet is on {w.network}. OKX Wallet's Keystone import is built for mainnet and may "
                                       f"reject a test-network QR ('not supported on the current network type').\n\n"
                                       f"UniSat does support test networks — use the UniSat button for that.\n\nShow the OKX QR anyway?"):
                return
        try:
            frames = btcv.keystone_frames(self.export_all, kind)
        except ImportError:
            return messagebox.showinfo("Needs cbor2", "pip install cbor2  (and keep ur.py next to btcvault.py).")
        except ValueError as e:
            return messagebox.showerror("Keystone export", str(e))
        name = "UniSat / crypto-account" if kind == "account" else "OKX / Keystone multi-accounts"
        self.app.show_qr_window(frames[0], f"{name} QR ({w.network})", frames=frames)
        net_hint = (f" In UniSat switch the network to match ({w.network}) after connecting."
                    if btcv.NETWORKS[w.network]["test"] else "")
        self.status(f"Pairing QR shown ({len(frames)} frames — hold the camera on it until the wallet finishes). "
                    f"Signing works for this keystore's type only: {btcv.script_label(w.script)}.{net_hint}")

    def _pick_ks(self, entry, info_label):
        p = filedialog.askopenfilename(filetypes=[("Bitcoin keystore", "*.json"), ("All", "*.*")])
        if not p:
            return
        entry.delete(0, "end"); entry.insert(0, p)
        try:
            i = btcv.keystore_info(json.load(open(p)))
            info_label.config(text=f"{i['network']} · {btcv.script_label(i['script'])} · fingerprint {i['fingerprint']} · first address {i['first_address']} · "
                                   f"passphrase {'YES' if i['passphrase'] else 'no'}")
        except Exception as e:
            info_label.config(text=f"Not a valid keystore: {e}")

    def _open_ks(self, path, pw, passphrase, what):
        ks = json.load(open(path))
        info = btcv.keystore_info(ks)
        if not self._guard(info["network"], what):
            return None
        return btcv.keystore_open(ks, pw, passphrase)

    def export_show(self):
        path = self.x_ks.get().strip()
        if not path or not os.path.exists(path):
            return messagebox.showerror("Keystore", "Choose the keystore file.")
        pw, ph = self.x_pw.get(), self.x_pass.get()
        try:
            ks_net = btcv.keystore_info(json.load(open(path)))["network"]
        except Exception as e:
            return messagebox.showerror("Keystore", str(e))
        if not self._guard(ks_net, "Opening the keystore"):
            return
        def work():
            w = btcv.keystore_open(json.load(open(path)), pw, ph)
            return w.watch, btcv.keystone_bundle(w)               # public keys only
        def done(res, err):
            if err:
                return messagebox.showerror("Cannot open keystore", str(err))
            self.export_watch, self.export_all = res
            res = self.export_watch
            self.x_pw.delete(0, "end"); self.x_pass.delete(0, "end")
            self._set(self.x_out, res.export_text() +
                      "\nCompare the first address with the one shown when the wallet was created.\n"
                      "Use the extended-pubkey QR for BlueWallet-style apps; use the key-origin QR/text for BTCVault's online side.")
            self.status("Watch-only export ready.")
        self.status("Decrypting keystore (scrypt)…")
        self.app.async_do(work, done)

    def _export_qr(self, kind):
        if not self.export_watch:
            return messagebox.showinfo("Export", "Click 'Show watch-only export' first.")
        self.app.show_qr_window(self.export_watch.slip132() if kind == "slip" else self.export_watch.key_origin(),
                                "WATCH-ONLY KEY (public) → scan with the online app")

    def export_save(self):
        if not self.export_watch:
            return messagebox.showinfo("Export", "Click 'Show watch-only export' first.")
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="btc-watch-only.txt",
                                         filetypes=[("Text", "*.txt")])
        if p:
            open(p, "w").write(self.export_watch.export_text())
            self.status(f"Saved {p}")

    def export_save_key(self):
        if not self.export_watch:
            return messagebox.showinfo("Export", "Click 'Show watch-only export' first.")
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="btc-zpub-only.txt",
                                         filetypes=[("Text", "*.txt")])
        if p:
            with open(p, "w") as fh:
                fh.write(self.export_watch.slip132())   # bare zpub/ypub/vpub, nothing else
            self.status(f"Saved key only: {p}")
    # ================================================= TAB 3: WALLET / BALANCE
    def _wallet_tab(self):
        f = self.tabs[self.T3]
        ttk.Label(f, text="ONLINE step — paste / scan / load your PUBLIC watch-only key, then scan the wallet for balance and coins."
                  ).grid(row=0, column=0, columnspan=4, sticky="w", padx=10, pady=6)
        self._net_row(f, 1, script=True)
        ttk.Label(f, text="Explorer API:").grid(row=2, column=0, sticky="e", padx=6)
        ttk.Entry(f, textvariable=self.api_var).grid(row=2, column=1, columnspan=3, sticky="we", padx=6, pady=3)
        ttk.Label(f, text="Watch-only key:").grid(row=3, column=0, sticky="ne", padx=6)
        self.w_text = tk.Text(f, height=4, font=MONO)
        self.w_text.grid(row=3, column=1, columnspan=3, sticky="we", padx=6, pady=3)
        bar = ttk.Frame(f); bar.grid(row=4, column=0, columnspan=4, sticky="w", padx=6, pady=4)
        ttk.Button(bar, text="Load file…", command=self.w_load).pack(side="left", padx=4)
        ttk.Button(bar, text="Scan QR", command=lambda: self.app.scan_qr_dialog(self.w_scanned, accept_plain=True)).pack(side="left", padx=4)
        ttk.Button(bar, text="Import & verify", command=self.w_import).pack(side="left", padx=4)
        ttk.Label(bar, text="  gap limit:").pack(side="left")
        self.w_gap = ttk.Spinbox(bar, from_=3, to=50, width=4); self.w_gap.set(10); self.w_gap.pack(side="left")
        ttk.Button(bar, text="Scan wallet (balance / coins)", command=self.w_scan).pack(side="left", padx=8)
        ttk.Button(bar, text="Receive address QR", command=self.w_receive_qr).pack(side="left", padx=4)
        self.w_out = self._text(f, 14, 5)
        f.columnconfigure(1, weight=1); f.rowconfigure(5, weight=1)

    def w_load(self):
        p = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if p:
            self.w_text.delete("1.0", "end"); self.w_text.insert("1.0", open(p).read())

    def w_scanned(self, text):
        self.w_text.delete("1.0", "end"); self.w_text.insert("1.0", text.strip())
        self.status("Key scanned — click 'Import & verify'.")

    def w_import(self):
        try:
            w = btcv.parse_watch(self.w_text.get("1.0", "end"), self.net_var.get(),
                                 btcv.SCRIPT_LABELS[self.script_var.get()])
        except ValueError as e:
            return messagebox.showerror("Watch-only key", str(e))
        self.watch, self.scan = w, None
        self.script_var.set(btcv.script_label(w.script))
        how = ("detected from the key" if w.detected else
               "ASSUMED from your selection (bare xpub carries no type) — check the first address below")
        fp = w.fp_hex if w.fp != b"\x00" * 4 else "unknown (bare key — fine, BTCVault's signer matches by script)"
        self._set(self.w_out, f"Imported watch-only wallet — {w.network}\nAddress type: {btcv.script_label(w.script)}  ({how})\n"
                  f"Fingerprint : {fp}\nAccount path: {w.path}\n"
                  f"First receive address: {w.address(0, 0)}\n\nVERIFY that first address matches your offline wallet / "
                  f"other app BEFORE sending any funds to this wallet.\nNext: 'Scan wallet'.")
        self.status("Watch-only wallet imported.")

    def w_scan(self):
        if not self.watch:
            return messagebox.showinfo("Wallet", "Import the watch-only key first.")
        watch, url = self.watch, self.api_var.get().strip()
        try:
            gap = max(3, min(50, int(self.w_gap.get())))
        except ValueError:
            gap = 10
        root = self.app.root
        def work():
            return btcv.scan_wallet(watch, btcv.Esplora(url), gap, progress=lambda m: root.after(0, self.status, m))
        def done(res, err):
            if err:
                return messagebox.showerror("Network error", str(err))
            self.scan = res
            lines = [f"{watch.network} · {btcv.script_label(watch.script)}   {datetime.now():%H:%M:%S}",
                     f"Confirmed  : {btcv.to_btc(res['confirmed'])} BTC", f"Unconfirmed: {btcv.to_btc(res['unconfirmed'])} BTC", "",
                     f"Coins (UTXOs): {len(res['utxos'])}"]
            for u in sorted(res["utxos"], key=lambda u: -u["value"]):
                lines.append(f"  {btcv.to_btc(u['value']):>14} BTC  {'conf ' if u['confirmed'] else 'UNCONF'}  "
                             f"{u['txid'][:12]}…:{u['vout']}  {u['address']}")
            lines += ["", f"Next receive address (#{res['next'][0]}): {watch.address(0, res['next'][0])}",
                      f"Next change index   : #{res['next'][1]}",
                      f"Addresses in use    : {len(res['addresses'])}"]
            self._set(self.w_out, "\n".join(lines))
            self.status(f"Scan done: {btcv.to_btc(res['confirmed'])} BTC confirmed, {len(res['utxos'])} coin(s).")
        self.status("Scanning wallet…")
        self.app.async_do(work, done)

    def w_receive_qr(self):
        if not self.watch:
            return messagebox.showinfo("Wallet", "Import the watch-only key first.")
        idx = self.scan["next"][0] if self.scan else 0
        self.app.show_qr_window(self.watch.address(0, idx), f"RECEIVE #{idx}: {self.watch.address(0, idx)}")

    # ================================================= TAB 4: BUILD PSBT
    def _build_tab(self):
        f = self.tabs[self.T4]
        ttk.Label(f, text="ONLINE step — build an UNSIGNED transaction (PSBT) from the coins found on tab 3. No secrets involved."
                  ).grid(row=0, column=0, columnspan=4, sticky="w", padx=10, pady=6)
        ttk.Label(f, text="Send to address:").grid(row=1, column=0, sticky="e", padx=6, pady=3)
        self.b_to = ttk.Entry(f); self.b_to.grid(row=1, column=1, columnspan=3, sticky="we", padx=6)
        ttk.Label(f, text="Amount (BTC):").grid(row=2, column=0, sticky="e", padx=6, pady=3)
        self.b_amt = ttk.Entry(f); self.b_amt.grid(row=2, column=1, sticky="we", padx=6)
        self.b_max = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Send max (sweep everything)", variable=self.b_max).grid(row=2, column=2, sticky="w")
        ttk.Label(f, text="Fee rate (sat/vB):").grid(row=3, column=0, sticky="e", padx=6, pady=3)
        self.b_fee = ttk.Entry(f); self.b_fee.insert(0, "2"); self.b_fee.grid(row=3, column=1, sticky="we", padx=6)
        ttk.Button(f, text="Suggest fee", command=self.b_suggest).grid(row=3, column=2, sticky="w")
        self.b_prev = tk.BooleanVar(value=True); self.b_unconf = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Include full previous transactions (recommended: lets the signer PROVE the amounts)",
                        variable=self.b_prev).grid(row=4, column=1, columnspan=3, sticky="w", padx=6)
        ttk.Checkbutton(f, text="Allow unconfirmed coins", variable=self.b_unconf).grid(row=5, column=1, columnspan=2, sticky="w", padx=6)
        bar = ttk.Frame(f); bar.grid(row=6, column=0, columnspan=4, sticky="w", padx=6, pady=6)
        ttk.Button(bar, text="Build PSBT  →  QR", command=self.b_build).pack(side="left", padx=4)
        ttk.Button(bar, text="Save .psbt file…", command=self.b_save).pack(side="left", padx=4)
        ttk.Button(bar, text="Copy base64", command=lambda: self.last_psbt and self._copy(self.last_psbt.to_base64())).pack(side="left", padx=4)
        ttk.Button(bar, text="Show QR again", command=lambda: self.last_psbt and self._qr_psbt(self.last_psbt, "UNSIGNED PSBT → scan with the OFFLINE signer")).pack(side="left", padx=4)
        self.b_out = self._text(f, 14, 7)
        f.columnconfigure(1, weight=1); f.rowconfigure(7, weight=1)

    def b_suggest(self):
        url = self.api_var.get().strip()
        def work(): return btcv.suggest_fees(btcv.Esplora(url))
        def done(res, err):
            if err:
                return messagebox.showerror("Network error", str(err))
            self.b_fee.delete(0, "end"); self.b_fee.insert(0, str(res["normal"]))
            self.status(f"Fee estimates (sat/vB): fast {res['fast']} · normal {res['normal']} · slow {res['slow']}  — 'normal' filled in.")
        self.app.async_do(work, done)

    def b_build(self):
        if not self.watch or not self.scan:
            return messagebox.showinfo("Build", "Import the watch-only key and scan the wallet on tab 3 first.")
        watch, scan, url = self.watch, self.scan, self.api_var.get().strip()
        try:
            dest = self.b_to.get().strip()
            btcv.address_to_spk(dest, watch.network)
            send_max = self.b_max.get()
            amount = None if send_max else btcv.parse_btc(self.b_amt.get())
            rate = Decimal(self.b_fee.get().strip())
        except (ValueError, InvalidOperation) as e:
            return messagebox.showerror("Input error", str(e) if isinstance(e, ValueError) and str(e) else "Check the fee rate.")
        with_prev, unconf = self.b_prev.get(), self.b_unconf.get()
        def work():
            api = btcv.Esplora(url)
            psbt = btcv.build_psbt(watch, scan, dest, amount, rate, send_max=send_max, allow_unconfirmed=unconf,
                                   get_prev_hex=api.tx_hex if with_prev else None)
            return psbt, btcv.analyze_psbt(psbt, watch)
        def done(res, err):
            if err:
                return messagebox.showerror("Build error", str(err))
            psbt, rv = res
            self.last_psbt = psbt
            b64 = psbt.to_base64()
            self._set(self.b_out, btcv.format_review(rv) + f"\n\nPSBT ({len(psbt.serialize())} bytes, base64):\n{b64}\n")
            self.status("Unsigned PSBT built — take the QR / file to the OFFLINE signer.")
            self._qr_psbt(psbt, "UNSIGNED PSBT → scan with the OFFLINE signer")
        self.status("Building PSBT (fetching previous transactions)…")
        self.app.async_do(work, done)

    def b_save(self):
        if not self.last_psbt:
            return messagebox.showinfo("PSBT", "Build a PSBT first.")
        p = filedialog.asksaveasfilename(defaultextension=".psbt", initialfile="unsigned.psbt", filetypes=[("PSBT", "*.psbt")])
        if p:
            open(p, "wb").write(self.last_psbt.serialize())
            self.status(f"Saved {p}")

    # ================================================= TAB 5: SIGN
    def _sign_tab(self):
        f = self.tabs[self.T5]
        ttk.Label(f, foreground="#a00", text="OFFLINE step — load the unsigned PSBT (QR / file / paste). BTCVault re-checks it "
                  "independently and shows exactly what it will sign.").grid(row=0, column=0, columnspan=4, sticky="w", padx=10, pady=6)
        ttk.Label(f, text="Unsigned PSBT:").grid(row=1, column=0, sticky="w", padx=10)
        self.s_psbt = tk.Text(f, height=4, font=MONO)
        self.s_psbt.grid(row=2, column=0, columnspan=4, sticky="we", padx=10, pady=3)
        bar = ttk.Frame(f); bar.grid(row=3, column=0, columnspan=4, sticky="w", padx=10)
        ttk.Button(bar, text="Load file…", command=self.s_load).pack(side="left", padx=2)
        ttk.Button(bar, text="Scan QR with camera", command=lambda: self.app.scan_qr_dialog(self.s_scanned, accept_plain=True)).pack(side="left", padx=6)
        ttk.Label(f, text="Keystore file:").grid(row=4, column=0, sticky="e", padx=8, pady=(8, 0))
        self.s_ks = ttk.Entry(f); self.s_ks.grid(row=4, column=1, sticky="we", padx=6, pady=(8, 0))
        ttk.Button(f, text="Browse…", command=lambda: self._pick_ks(self.s_ks, self.s_info)).grid(row=4, column=2, sticky="w", pady=(8, 0))
        self.s_info = ttk.Label(f, text="", foreground="#345"); self.s_info.grid(row=5, column=1, columnspan=3, sticky="w", padx=6)
        ttk.Label(f, text="Keystore password:").grid(row=6, column=0, sticky="e", padx=8)
        self.s_pw = ttk.Entry(f, show="*"); self.s_pw.grid(row=6, column=1, sticky="we", padx=6, pady=2)
        ttk.Label(f, text="BIP-39 passphrase (if used):").grid(row=7, column=0, sticky="e", padx=8)
        self.s_pass = ttk.Entry(f, show="*"); self.s_pass.grid(row=7, column=1, sticky="we", padx=6, pady=2)
        self.s_unsafe = tk.BooleanVar(value=False)
        ttk.Style().configure("Danger.TCheckbutton", foreground="#a00")
        ttk.Checkbutton(f, style="Danger.TCheckbutton", variable=self.s_unsafe,
                        text="Allow PSBTs WITHOUT previous transactions (UNSAFE: fee amount can't be verified)"
                        ).grid(row=8, column=1, columnspan=3, sticky="w", padx=6)
        self.s_hw = tk.BooleanVar(value=True)
        ttk.Checkbutton(f, variable=self.s_hw,
                        text="Hardware-wallet (Keystone) mode: return the signature only, NOT finalised "
                             "— tick this for PSBTs coming from UniSat / OKX / Sparrow"
                        ).grid(row=9, column=1, columnspan=3, sticky="w", padx=6)
        ttk.Button(f, text="REVIEW & SIGN", command=self.s_sign).grid(row=10, column=0, columnspan=4, pady=8)
        bar2 = ttk.Frame(f); bar2.grid(row=11, column=0, columnspan=4, sticky="w", padx=10)
        ttk.Button(bar2, text="Show signed QR", command=lambda: self.signed and self._qr_psbt(self.signed["psbt"], "SIGNED PSBT → scan with the ONLINE machine / BlueWallet")).pack(side="left", padx=2)
        ttk.Button(bar2, text="Save signed .psbt…", command=self.s_save_psbt).pack(side="left", padx=6)
        ttk.Button(bar2, text="Save raw tx…", command=self.s_save_raw).pack(side="left", padx=2)
        ttk.Button(bar2, text="Copy signed PSBT", command=lambda: self.signed and self._copy(self.signed["psbt"].to_base64())).pack(side="left", padx=6)
        self.s_out = self._text(f, 10, 12)
        f.columnconfigure(1, weight=1); f.rowconfigure(12, weight=1)

    def s_load(self):
        p = filedialog.askopenfilename(filetypes=[("PSBT", "*.psbt *.txt"), ("All", "*.*")])
        if not p:
            return
        try:
            psbt = btcv.psbt_from_file(p)
        except Exception as e:
            return messagebox.showerror("PSBT", str(e))
        self.s_psbt.delete("1.0", "end"); self.s_psbt.insert("1.0", psbt.to_base64())

    def s_scanned(self, text):
        self.s_psbt.delete("1.0", "end"); self.s_psbt.insert("1.0", text.strip())
        self.status("PSBT scanned.")

    def s_sign(self):
        try:
            psbt = btcv.psbt_from_text(self.s_psbt.get("1.0", "end"))
        except Exception as e:
            return messagebox.showerror("PSBT error", str(e))
        path = self.s_ks.get().strip()
        if not path or not os.path.exists(path):
            return messagebox.showerror("Keystore", "Choose the keystore file.")
        try:
            net = btcv.keystore_info(json.load(open(path)))["network"]
        except Exception as e:
            return messagebox.showerror("Keystore", str(e))
        if not self._guard(net, "Signing"):
            return
        pw, ph, unsafe, hw = self.s_pw.get(), self.s_pass.get(), self.s_unsafe.get(), self.s_hw.get()

        def work():
            wallet = btcv.keystore_open(json.load(open(path)), pw, ph)
            return wallet, btcv.analyze_psbt(psbt, wallet.watch, unsafe)
        def done(res, err):
            if err:
                return messagebox.showerror("Cannot open keystore", str(err))
            wallet, rv = res
            text = btcv.format_review(rv)
            if rv["errors"]:
                hint = ("\n\nPSBTs from UniSat / OKX don't carry the full previous transactions. If you trust that wallet, tick "
                        "'Allow PSBTs WITHOUT previous transactions' — then the amounts/fee come from the online app, so check "
                        "recipient + amount in the review window carefully."
                        if any("previous transaction missing" in e for e in rv["errors"]) else "")
                messagebox.showerror("Refusing to sign", "This PSBT failed the safety checks:\n\n- " + "\n- ".join(rv["errors"]) + hint)
                self._set(self.s_out, "REFUSED\n\n" + text)
                return
            if not self._confirm(f"Confirm signing — {wallet.network}", text, ok="Sign this transaction",
                                 danger=not btcv.NETWORKS[wallet.network]["test"]):
                self.status("Signing cancelled.")
                return
            def work2():
                return btcv.sign_psbt(psbt, wallet, unsafe, finalize=not hw)
            def done2(res2, err2):
                if err2:
                    return messagebox.showerror("Signing failed", str(err2))
                self.signed = res2
                self.s_pw.delete(0, "end"); self.s_pass.delete(0, "end")
                out = (f"SIGNED ✔  {res2['signed']} input(s) signed   txid {res2['txid']}\n"
                       f"{'Transaction is COMPLETE — ready to broadcast.' if res2['complete'] else 'PARTIALLY signed — other inputs need their own signer.'}\n"
                       f"{'' if res2['finalized'] else 'Hardware-wallet mode: signature added, inputs NOT finalised — scan the QR back into UniSat / OKX / Sparrow, which finalises and broadcasts.' + chr(10)}\n"
                       f"Signed PSBT (base64):\n{res2['psbt'].to_base64()}\n")
                if res2["raw"]:
                    out += f"\nRaw transaction hex:\n{res2['raw']}\n"
                self._set(self.s_out, out)
                self.status("Signed. Scan the QR back into the wallet app that made the request." if hw else
                            "Signed. Scan the QR / carry the file to the online machine to broadcast.")
                self._qr_psbt(res2["psbt"], "SIGNED PSBT → scan with the ONLINE machine / BlueWallet")
            self.app.async_do(work2, done2)
        self.status("Decrypting keystore (scrypt)…")
        self.app.async_do(work, done)

    def s_save_psbt(self):
        if not self.signed:
            return messagebox.showinfo("Sign", "Nothing signed yet.")
        p = filedialog.asksaveasfilename(defaultextension=".psbt", initialfile="signed.psbt", filetypes=[("PSBT", "*.psbt")])
        if p:
            open(p, "wb").write(self.signed["psbt"].serialize())
            self.status(f"Saved {p}")

    def s_save_raw(self):
        if not self.signed or not self.signed["raw"]:
            return messagebox.showinfo("Sign", "No complete raw transaction available.")
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="signed-tx.txt", filetypes=[("Text", "*.txt")])
        if p:
            open(p, "w").write(self.signed["raw"])
            self.status(f"Saved {p}")

    # ================================================= TAB 6: BROADCAST
    def _broadcast_tab(self):
        f = self.tabs[self.T6]
        ttk.Label(f, text="ONLINE step — import the SIGNED PSBT (or raw transaction hex), review it, broadcast."
                  ).grid(row=0, column=0, columnspan=4, sticky="w", padx=10, pady=6)
        self._net_row(f, 1)
        ttk.Label(f, text="Explorer API:").grid(row=2, column=0, sticky="e", padx=6)
        ttk.Entry(f, textvariable=self.api_var).grid(row=2, column=1, columnspan=3, sticky="we", padx=6, pady=3)
        self.br_in = tk.Text(f, height=5, font=MONO)
        self.br_in.grid(row=3, column=0, columnspan=4, sticky="we", padx=10, pady=4)
        bar = ttk.Frame(f); bar.grid(row=4, column=0, columnspan=4, sticky="we", padx=10)
        ttk.Button(bar, text="Load file…", command=self.br_load).pack(side="left", padx=2)
        ttk.Button(bar, text="Scan QR with camera", command=lambda: self.app.scan_qr_dialog(self.br_scanned, accept_plain=True)).pack(side="left", padx=6)
        ttk.Button(bar, text="REVIEW & BROADCAST", command=self.br_go).pack(side="right", padx=2)
        self.br_out = self._text(f, 14, 5)
        f.columnconfigure(1, weight=1); f.rowconfigure(5, weight=1)

    def br_load(self):
        p = filedialog.askopenfilename(filetypes=[("PSBT / tx", "*.psbt *.txt"), ("All", "*.*")])
        if not p:
            return
        data = open(p, "rb").read()
        text = btcv.PSBT.parse(data).to_base64() if data.startswith(b"psbt\xff") else data.decode("utf-8", "replace").strip()
        self.br_in.delete("1.0", "end"); self.br_in.insert("1.0", text)

    def br_scanned(self, text):
        self.br_in.delete("1.0", "end"); self.br_in.insert("1.0", text.strip())
        self.status("Scanned.")

    def br_go(self):
        net, url = self.net_var.get(), self.api_var.get().strip()
        text = self.br_in.get("1.0", "end")
        try:
            try:
                psbt = btcv.psbt_from_text(text)
                tx = btcv.extract_tx(psbt)
            except ValueError as e:
                if "not signed" in str(e) or "multi-part" in str(e) or "UR" in str(e):
                    raise
                psbt, tx = None, btcv.parse_tx_text(text)
        except Exception as e:
            return messagebox.showerror("Import error", str(e))
        def work():
            api = btcv.Esplora(url)
            total_in = 0
            for i, vin in enumerate(tx.vin):
                val = None
                if psbt is not None:
                    try:
                        val = psbt.utxo(i).value
                    except Exception:
                        val = None
                if val is None:
                    val = int(api.tx(vin.txid.hex())["vout"][vin.vout]["value"])
                total_in += val
            return total_in
        def done(res, err):
            if err:
                return messagebox.showerror("Network error", f"Could not look up input amounts:\n{err}")
            fee = res - sum(o.value for o in tx.vout)
            txid = tx.txid().hex()
            lines = [f"Network : {net}   ({self.net_note.get()})", f"Txid    : {txid}", f"Size    : {len(tx.serialize())} bytes", "",
                     f"OUTPUTS ({len(tx.vout)})"]
            for i, o in enumerate(tx.vout):
                lines.append(f"  #{i}  {btcv.to_btc(o.value) + ' BTC':>16}  {btcv.spk_to_address(o.script_pubkey, net) or 'script:' + o.script_pubkey.data.hex()}")
            lines += ["", f"Total in : {btcv.to_btc(res)} BTC", f"Fee      : {fee} sat"]
            if fee < 0:
                return messagebox.showerror("Invalid", "Outputs exceed inputs. Not broadcasting.")
            if fee > 100_000 and fee > res // 10:
                lines.append("WARNING : fee is more than 10% of the inputs — is this what you expected?")
            if not self._confirm(f"Confirm broadcast — {net}", "\n".join(lines), ok="BROADCAST",
                                 danger=not btcv.NETWORKS[net]["test"]):
                return
            self._broadcast(tx, url, net)
        self.status("Looking up input amounts…")
        self.app.async_do(work, done)

    def _broadcast(self, tx, url, net):
        raw = tx.serialize().hex()
        def work():
            api = btcv.Esplora(url)
            txid = api.broadcast(raw)
            st = None
            for _ in range(20):
                time.sleep(3)
                try:
                    st = api.tx_status(txid)
                    if st.get("confirmed"):
                        break
                except Exception:
                    pass
            return txid, st
        def done(res, err):
            if err:
                return messagebox.showerror("Broadcast failed", str(err))
            txid, st = res
            state = ("CONFIRMED in block " + str(st.get("block_height"))) if st and st.get("confirmed") else \
                    "IN MEMPOOL (waiting for a block — check the explorer)"
            self.br_out.config(state="normal")
            self.br_out.insert("1.0", f"{datetime.now():%H:%M:%S}  {state}\nTxid: {txid}\n"
                                      f"Explorer: {btcv.NETWORKS[net]['explorer']}{txid}\n\n")
            self.status(f"Broadcast: {txid}")
        self.status("Broadcasting…")
        self.app.async_do(work, done)