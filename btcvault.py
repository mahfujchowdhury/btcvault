#!/usr/bin/env python3
"""
BTCVault — an air-gapped ("cold-style") Bitcoin wallet with a Tkinter GUI (PSBT).
Address types: Legacy (BIP-44), Native SegWit (BIP-84), Nested SegWit (BIP-49), Taproot (BIP-86).
Networks     : Mainnet, Testnet4, Testnet3, Signet, Regtest.

Flow:  CREATE (offline) -> export watch-only key -> BUILD unsigned PSBT (online) -> QR/file
       -> SIGN (offline) -> QR/file -> BROADCAST (online)

Run modes:
    python btcvault.py             # normal (online) machine
    python btcvault.py --offline   # AIR-GAPPED signer: ALL network sockets are blocked
    python btcvault.py --selftest  # verify crypto pipeline without network/GUI

Keystone mode: pair with UniSat / OKX / Sparrow … as a "Keystone" hardware wallet (tab 2 pairing QR) and sign
their ur:crypto-psbt requests (tab 5, hardware-wallet mode). Needs cbor2 + ur.py.

Files (keep together):  btcvault.py  btcpanel.py  btcv.py   (+ ur.py for ur:crypto-psbt QR codes)

Required:  pip install embit pycryptodome
Optional:  pip install qrcode pillow          (QR display)
           pip install cbor2                  (standard ur:crypto-psbt QR; needs ur.py alongside)
           pip install pyzbar opencv-python   (camera QR scanning)

EDUCATIONAL TOOL. Unaudited. Test on signet/testnet with tiny amounts first.
"""

import sys, threading, queue, time

# ----------------------------- offline hard-lock -----------------------------
OFFLINE = "--offline" in sys.argv
if OFFLINE:
    import socket
    # Import everything that subclasses/uses socket BEFORE patching,
    # otherwise ssl / http.client / urllib fail at import time.
    import ssl, http.client, urllib.request  # noqa: F401

    def _blocked(*a, **k):
        raise RuntimeError("NETWORK DISABLED: this instance is running in --offline (air-gapped) mode")

    _RealSocket = socket.socket

    class _BlockedSocket(_RealSocket):
        """Still a real class (so later imports work) but can never connect or listen."""
        def connect(self, *a, **k):     _blocked()
        def connect_ex(self, *a, **k):  _blocked()
        def bind(self, *a, **k):        _blocked()
        def listen(self, *a, **k):      _blocked()
        def sendto(self, *a, **k):      _blocked()

    socket.socket = _BlockedSocket           # type: ignore
    socket.create_connection = _blocked      # type: ignore
    socket.getaddrinfo = _blocked            # type: ignore
    socket.gethostbyname = _blocked          # type: ignore
    socket.gethostbyname_ex = _blocked       # type: ignore

# optional QR support -------------------------------------------------------
try:
    import qrcode
    from PIL import Image, ImageTk
    HAS_QR = True
except ImportError:
    HAS_QR = False

try:
    import cv2
    from pyzbar import pyzbar as _pyzbar
    HAS_CAM = True
except ImportError:
    HAS_CAM = False

try:
    import ur                        # Uniform Resources codec (ur.py next to this file)
    HAS_UR = True
except Exception:
    HAS_UR = False

import tkinter as tk
from tkinter import ttk, messagebox

import btcv, btcpanel
btcv.NETWORK_DISABLED = OFFLINE      # air-gapped mode: the BTC engine refuses network too

FRAME_CHUNK = 700   # chars per animated QR frame (plain-text fallback)


def make_frames(payload: str):
    if len(payload) <= FRAME_CHUNK:
        return [payload]
    chunks = [payload[i:i + FRAME_CHUNK] for i in range(0, len(payload), FRAME_CHUNK)]
    n = len(chunks)
    return [f"EVF:{i+1}/{n}:{c}" for i, c in enumerate(chunks)]


def qr_image(text: str, size=320):
    if not HAS_QR:
        return None
    q = qrcode.QRCode(box_size=8, border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
    q.add_data(text); q.make(fit=True)
    img = q.make_image(fill_color="black", back_color="white").convert("RGB")
    return img.resize((size, size))


# ================================ APPLICATION ================================
class BTCVaultApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("BTCVault [OFFLINE / AIR-GAPPED — network blocked]" if OFFLINE
                   else "BTCVault [ONLINE coordinator]")
        root.geometry("980x760"); root.minsize(900, 680)

        banner_bg = "#7a1f1f" if OFFLINE else "#1f4e7a"
        tk.Label(root, bg=banner_bg, fg="white", pady=6, font=("Segoe UI", 11, "bold"),
                 text=("OFFLINE SIGNER MODE — all network sockets are hard-disabled on this machine. "
                       "Use QR or file transfer only." if OFFLINE else
                       "ONLINE MODE — build unsigned PSBTs and broadcast signed ones. "
                       "NEVER put your keystore/seed on this machine (mainnet).")).pack(fill="x")

        self.status = ttk.Label(root, text="Ready.", anchor="w", relief="sunken")
        self.status.pack(fill="x", side="bottom")

        host = ttk.Frame(root)
        host.pack(fill="both", expand=True)
        self.btc = btcpanel.BTCPanel(host, self, OFFLINE)

    # --------------------------- helpers (used by btcpanel) --------------------------------
    def set_status(self, msg): self.status.config(text=msg)

    def async_do(self, fn, on_done):
        def worker():
            try:
                res = fn(); err = None
            except Exception as e:
                res, err = None, e
            self.root.after(0, lambda: on_done(res, err))
        threading.Thread(target=worker, daemon=True).start()

    def show_qr_window(self, payload: str, title="BTCVault QR", frames=None):
        frames = frames or make_frames(payload)
        win = tk.Toplevel(self.root); win.title(f"{title}  ({len(payload)} chars)")
        win.geometry("420x520")
        lbl = tk.Label(win); lbl.pack(padx=10, pady=10)
        info = tk.Label(win, text="", font=("Consolas", 9)); info.pack()
        tk.Button(win, text="Close", command=win.destroy).pack(pady=4)
        if not HAS_QR:
            info.config(text="QR libs missing (pip install qrcode pillow).\nCopy payload text instead:")
            t = tk.Text(win, height=10, width=46); t.pack(padx=10, pady=6)
            t.insert("1.0", payload)
            return
        state = {"i": 0, "stop": False}
        imgs = []
        for fr in frames:
            imgs.append(ImageTk.PhotoImage(qr_image(fr, 360)))
        def tick():
            if state["stop"] or not win.winfo_exists(): return
            i = state["i"] % len(frames)
            lbl.config(image=imgs[i]); info.config(text=f"Frame {i+1}/{len(frames)}")
            state["i"] += 1
            win.after(300, tick)
        win.protocol("WM_DELETE_WINDOW", lambda: (state.__setitem__("stop", True), win.destroy()))
        tick()
        self._qr_keepalive = imgs  # prevent GC

    def scan_qr_dialog(self, on_result, accept_plain=False):
        if not HAS_CAM:
            messagebox.showinfo("Camera scanning unavailable",
                "Install it with:\n  pip install pyzbar opencv-python\n\n"
                "Or paste the payload text / load from file instead.")
            return
        win = tk.Toplevel(self.root); win.title("Scan QR (multi-frame supported)")
        win.geometry("520x460")
        vid = tk.Label(win); vid.pack(padx=8, pady=8)
        info = tk.Label(win, text="Starting camera…", font=("Consolas", 9)); info.pack()
        tk.Button(win, text="Cancel", command=win.destroy).pack(pady=4)
        q = queue.Queue(); collected = {}
        urdec = ur.URDecoder() if HAS_UR else None

        def grab():
            cap = cv2.VideoCapture(0)
            try:
                while win.winfo_exists():
                    ok, frame = cap.read()
                    if not ok: time.sleep(0.1); continue
                    found = [d.data.decode() for d in _pyzbar.decode(frame)]
                    q.put(("frame", frame.copy()))
                    for txt in found: q.put(("code", txt))
                    time.sleep(0.03)
            except Exception as e:
                q.put(("err", str(e)))
            finally:
                cap.release()

        def handle_code(txt):
            txt = txt.strip()
            if txt[:3].lower() == "ur:":                      # Uniform Resources (ur:crypto-psbt …)
                if not HAS_UR:
                    info.config(text="UR QR seen — pip install cbor2 (and keep ur.py next to btcvault.py)"); return
                try:
                    if urdec.add(txt):
                        t, body = urdec.result(); win.destroy()
                        on_result(ur.ur_encode_single(t, body)); return
                    n, tot = urdec.progress(); info.config(text=f"UR fragments: {n}/{tot}")
                except Exception as e:
                    info.config(text=f"UR scan: {e}")
                return
            if txt.startswith("EVF:"):                         # BTCVault plain multi-frame fallback
                try:
                    _, pos, chunk = txt.split(":", 2)
                    i, n = map(int, pos.split("/"))
                    collected[i] = chunk
                    info.config(text=f"Collected {len(collected)}/{n} frames")
                    if len(collected) == n:
                        win.destroy(); on_result("".join(collected[k] for k in range(1, n + 1)))
                except Exception:
                    pass
                return
            if accept_plain:                                   # plain text QR (base64 PSBT, zpub, key-origin …)
                win.destroy(); on_result(txt)

        def poll():
            if not win.winfo_exists(): return
            try:
                while True:
                    kind, item = q.get_nowait()
                    if kind == "frame":
                        im = Image.fromarray(cv2.cvtColor(item, cv2.COLOR_BGR2RGB)).resize((460, 320))
                        poll.ph = ImageTk.PhotoImage(im); vid.config(image=poll.ph)
                    elif kind == "code":
                        handle_code(item)
                    elif kind == "err":
                        info.config(text=f"Camera error: {item}")
            except queue.Empty:
                pass
            self.root.after(50, poll)

        threading.Thread(target=grab, daemon=True).start()
        poll()

    def show_seed_dialog(self, mnemonic: str, addr: str):
        win = tk.Toplevel(self.root); win.title("SEED PHRASE — write it down NOW")
        win.geometry("640x340")
        tk.Label(win, text="Write these 24 words on paper. Never photograph, copy or store them digitally.",
                 fg="#a00", font=("Segoe UI", 10, "bold")).pack(pady=8)
        t = tk.Text(win, height=6, width=72, font=("Consolas", 12)); t.pack(padx=12)
        t.insert("1.0", mnemonic)
        tk.Label(win, text=f"First address: {addr}").pack(pady=6)
        def close():
            t.delete("1.0", "end")   # wipe from screen
            win.destroy()
        tk.Button(win, text="I have written it down — wipe from screen", command=close,
                  bg="#2e7d32", fg="white").pack(pady=8)


# -------------------------------- self test ----------------------------------
def selftest():
    print("BTCVault self-test (no network needed)…")
    for line in btcv.selftest():
        print("  " + line)
    print("ALL TESTS PASSED ✔")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest(); sys.exit(0)
    if OFFLINE:
        print("OFFLINE MODE: network sockets disabled.")
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    app = BTCVaultApp(root)
    root.mainloop()