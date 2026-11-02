"""
btcv.py — Bitcoin engine for BTCVault (single-sig: Legacy BIP-44, Nested SegWit BIP-49,
Native SegWit BIP-84, Taproot BIP-86 — PSBT / BIP-174).

Pure logic, no GUI. Used by btcpanel.py / btcvault.py. Flow:

    OFFLINE : create wallet  -> encrypted keystore (seed) + watch-only export (xpub)
    ONLINE  : import xpub -> scan balance/UTXOs -> build UNSIGNED PSBT
    OFFLINE : review PSBT -> sign with keystore -> SIGNED PSBT / raw tx
    ONLINE  : broadcast

Interoperable formats (so BlueWallet / Sparrow / Electrum / Keystone-style apps can be on the other side):
    * PSBT as base64 text, binary .psbt file, or BC-UR animated QR (ur:crypto-psbt)  [UR needs cbor2 + ur.py]
    * watch-only key as SLIP-132 zpub/ypub (vpub/upub on test nets) or plain xpub/tpub, key-origin
      "[fp/84h/0h/0h]zpub...", or an output descriptor (wpkh / sh(wpkh) / pkh / tr)

Requires:  pip install embit pycryptodome          (cbor2 optional, for UR QR)

Safety design (the signer does NOT trust the online machine):
    * every input must carry the FULL previous transaction, whose txid is re-hashed and checked, so the
      amounts (and therefore the fee) are proven — this closes the classic SegWit "fee attack".
      (witness_utxo-only PSBTs are refused unless you explicitly allow it.)
    * "change" is decided by re-deriving our own addresses and matching scriptPubKeys; PSBT metadata
      (derivation hints, fingerprints) is only ever used as a hint and is always verified.
    * only SIGHASH_ALL is signed; anything else is refused.
    * the keystore is bound to a network (mainnet / testnet4 / testnet3 / signet / regtest) AND to an
      address type, so coins can't be mixed up.
    * Taproot: key-path spends only (no script trees), SIGHASH_DEFAULT/ALL, BIP-340 signatures that are
      re-verified before anything is exported.

EDUCATIONAL TOOL. Unaudited. Test on signet/testnet with tiny amounts first.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import time
import unicodedata
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation, ROUND_CEILING

from embit import bip32, bip39, ec
from embit import networks as _enet
from embit import script as _escript
from embit.descriptor.checksum import add_checksum
from embit.psbt import PSBT, DerivationPath, PSBTError
from embit.script import Script, Witness
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput

# ------------------------------- AES-256-GCM backend -------------------------------
try:                                                   # pycryptodome
    from Crypto.Cipher import AES as _AES

    def _gcm_encrypt(key, nonce, plaintext, aad):
        c = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
        c.update(aad)
        ct, tag = c.encrypt_and_digest(plaintext)
        return ct + tag

    def _gcm_decrypt(key, nonce, blob, aad):
        c = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
        c.update(aad)
        return c.decrypt_and_verify(blob[:-16], blob[-16:])       # ValueError if wrong key / tampered
except ImportError:                                    # fallback: 'cryptography'
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

        def _gcm_encrypt(key, nonce, plaintext, aad):
            return _AESGCM(key).encrypt(nonce, plaintext, aad)

        def _gcm_decrypt(key, nonce, blob, aad):
            try:
                return _AESGCM(key).decrypt(nonce, blob, aad)
            except Exception:
                raise ValueError("MAC check failed")
    except ImportError:
        raise ImportError("btcv needs an AES-GCM library:  pip install pycryptodome")

# ---------------------------------- constants --------------------------------------
NETWORK_DISABLED = False         # btcvault.py sets this True in --offline mode
SAT = 10**8
HARD = 0x80000000
RBF_SEQUENCE = 0xFFFFFFFD
MAX_SCAN = 100                   # addresses per chain checked when matching scripts to our wallet
KS_VERSION = 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1

NETWORKS = {
    "Bitcoin Mainnet":  {"embit": "main",    "coin": 0, "api": "https://mempool.space/api",
                         "explorer": "https://mempool.space/tx/",          "test": False},
    "Bitcoin Testnet4": {"embit": "test",    "coin": 0, "api": "https://mempool.space/testnet4/api",
                         "explorer": "https://mempool.space/testnet4/tx/", "test": True},
    "Bitcoin Testnet3": {"embit": "test",    "coin": 0, "api": "https://blockstream.info/testnet/api",
                         "explorer": "https://blockstream.info/testnet/tx",  "test": True},
    "Bitcoin Signet":   {"embit": "signet",  "coin": 0, "api": "https://blockstream.info/signet/api",
                         "explorer": "https://blockstream.info/signet/tx/",   "test": True},
    # Regtest has no public explorer: point this at YOUR local Esplora / electrs (editable in the GUI).
    "Bitcoin Regtest":  {"embit": "regtest", "coin": 1, "api": "http://127.0.0.1:3002",
                         "explorer": "http://127.0.0.1:5000/tx/",          "test": True},
}
DEFAULT_NET = "Bitcoin Signet"

# SLIP-132 version bytes (testnet4 / testnet3 / signet / regtest all share the "test" set)
_SLIP = {"main": {"xpub": "0488b21e", "ypub": "049d7cb2", "zpub": "04b24746"},
         "test": {"xpub": "043587cf", "ypub": "044a5262", "zpub": "045f1cf6"}}
_SLIP_TO_SCRIPT = {bytes.fromhex(v): {"xpub": None, "ypub": "p2sh-p2wpkh", "zpub": "p2wpkh"}[k]
                   for grp in _SLIP.values() for k, v in grp.items()}
_KNOWN_VERSIONS = set(_SLIP_TO_SCRIPT)

# Address types.  in_vb = virtual size of one input spending it; dust = minimum output value.
SCRIPTS = {
    "p2pkh":       {"label": "Legacy (P2PKH, BIP-44)",             "purpose": 44, "slip": "xpub", "spk": "p2pkh",
                    "in_vb": Decimal("148"),  "spk_len": 25, "dust": 546, "desc": ("pkh(", ")")},
    "p2wpkh":      {"label": "Native SegWit (P2WPKH, BIP-84)",     "purpose": 84, "slip": "zpub", "spk": "p2wpkh",
                    "in_vb": Decimal("68"),   "spk_len": 22, "dust": 294, "desc": ("wpkh(", ")")},
    "p2sh-p2wpkh": {"label": "Nested SegWit (P2SH-P2WPKH, BIP-49)", "purpose": 49, "slip": "ypub", "spk": "p2sh",
                    "in_vb": Decimal("91"),   "spk_len": 23, "dust": 540, "desc": ("sh(wpkh(", "))")},
    "p2tr":        {"label": "Taproot (P2TR, BIP-86)",             "purpose": 86, "slip": "xpub", "spk": "p2tr",
                    "in_vb": Decimal("57.5"), "spk_len": 34, "dust": 330, "desc": ("tr(", ")")},
}
SCRIPT_LABELS = {v["label"]: k for k, v in SCRIPTS.items()}     # GUI label -> id (display order = dict order)
DEFAULT_SCRIPT = "p2wpkh"
_PURPOSE_TO_SCRIPT = {v["purpose"]: k for k, v in SCRIPTS.items()}


def script_label(script: str) -> str:
    return SCRIPTS[script]["label"]


def net_params(name: str) -> dict:
    return _enet.NETWORKS[NETWORKS[name]["embit"]]


# ----------------------------------- helpers ---------------------------------------
def to_btc(sat: int) -> str:
    s = f"{Decimal(int(sat)) / SAT:.8f}".rstrip("0").rstrip(".")
    return s or "0"


def parse_btc(text: str) -> int:
    try:
        d = Decimal(text.strip())
    except (InvalidOperation, AttributeError):
        raise ValueError("Amount is not a number.")
    if d <= 0:
        raise ValueError("Amount must be greater than zero.")
    if d != d.quantize(Decimal("1E-8")):
        raise ValueError("Bitcoin has at most 8 decimal places.")
    return int(d * SAT)


def _ceil(d) -> int:
    return int(Decimal(d).to_integral_value(rounding=ROUND_CEILING))


def vsize_estimate(n_inputs: int, output_spk_lens, script: str = DEFAULT_SCRIPT) -> int:
    """Estimated vsize: per-input cost depends on the address type; output = 8 value + 1 len + script."""
    return _ceil(Decimal("10.5") + SCRIPTS[script]["in_vb"] * n_inputs + sum(9 + n for n in output_spk_lens))


def dust_limit(spk: Script) -> int:
    t = spk.script_type()
    return {"p2wpkh": 294, "p2wsh": 330, "p2tr": 330, "p2sh": 540, "p2pkh": 546}.get(t, 546)


def address_to_spk(addr: str, network: str) -> Script:
    """Parse + validate an address for THIS network (embit alone does not check the network)."""
    a = (addr or "").strip()
    if not a:
        raise ValueError("Address is empty.")
    low = a.lower()
    is_bech32 = low.startswith(("bc1", "tb1", "bcrt1"))
    if is_bech32 and a != low and a != a.upper():
        raise ValueError("Mixed-case bech32 address is invalid.")
    try:
        spk = _escript.address_to_scriptpubkey(a)
        back = spk.address(net_params(network))
    except Exception:
        raise ValueError(f"Not a valid {network} address.")
    if (back.lower() != low) if is_bech32 else (back != a):
        raise ValueError(f"Address is not valid for {network} (wrong network or bad checksum).")
    return spk


def spk_to_address(spk: Script, network: str):
    try:
        return spk.address(net_params(network))
    except Exception:
        return None


def _path_ints(path: str):
    out = []
    for part in path.strip().split("/")[1:]:
        h = part[-1] in "h'H"
        n = int(part[:-1] if h else part)
        out.append(n | HARD if h else n)
    return out


def _norm_path(path: str) -> str:
    return "m/" + "/".join(p.replace("'", "h").replace("H", "h") for p in path.strip().split("/")[1:])


def default_path(network: str, account: int = 0, script: str = DEFAULT_SCRIPT) -> str:
    return f"m/{SCRIPTS[script]['purpose']}h/{NETWORKS[network]['coin']}h/{account}h"


# ------------------------- Taproot (BIP-340 / BIP-341, key-path only) ---------------------
_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _pt_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    lam = (3 * a[0] * a[0] * pow(2 * a[1], -1, _P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, _P)) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _pt_mul(k, pt=_G):
    r = None
    while k:
        if k & 1:
            r = _pt_add(r, pt)
        pt = _pt_add(pt, pt)
        k >>= 1
    return r


def _tagged_hash(tag: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def _lift_x(x: int):
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if y * y % _P != y2:
        raise ValueError("Not a valid x-only public key.")
    return x, (y if y % 2 == 0 else _P - y)


def taproot_output_key(pub_sec: bytes) -> bytes:
    """BIP-86: 32-byte x-only output key = P + H_TapTweak(P)·G  (no script tree)."""
    px = bytes(pub_sec)[1:33]
    t = int.from_bytes(_tagged_hash("TapTweak", px), "big")
    if t >= _N:
        raise ValueError("Invalid taproot tweak.")
    q = _pt_add(_lift_x(int.from_bytes(px, "big")), _pt_mul(t))
    if q is None:
        raise ValueError("Invalid taproot output key.")
    return q[0].to_bytes(32, "big")


def taproot_tweak_secret(secret: bytes) -> int:
    """BIP-86 tweaked private scalar for the internal key `secret` (32 bytes)."""
    d = int.from_bytes(secret, "big")
    pt = _pt_mul(d)
    if pt[1] % 2:
        d = _N - d
    t = int.from_bytes(_tagged_hash("TapTweak", pt[0].to_bytes(32, "big")), "big")
    return (d + t) % _N


def schnorr_sign(d: int, msg: bytes, aux: bytes) -> bytes:
    pt = _pt_mul(d)
    if pt[1] % 2:
        d = _N - d
    px = pt[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(_tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k = int.from_bytes(_tagged_hash("BIP0340/nonce", t + px + msg), "big") % _N
    if k == 0:
        raise RuntimeError("Nonce generation failed.")
    r = _pt_mul(k)
    if r[1] % 2:
        k = _N - k
    rx = r[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", rx + px + msg), "big") % _N
    return rx + ((k + e * d) % _N).to_bytes(32, "big")


def schnorr_verify(xonly: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        pt = _lift_x(int.from_bytes(xonly, "big"))
    except ValueError:
        return False
    if len(sig) != 64:
        return False
    r, sv = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= _P or sv >= _N:
        return False
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", sig[:32] + xonly + msg), "big") % _N
    q = _pt_add(_pt_mul(sv), _pt_mul(_N - e, pt))
    return q is not None and q[1] % 2 == 0 and q[0] == r


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def taproot_sighash(tx: Transaction, values, spks, index: int, hash_type: int = 0) -> bytes:
    """BIP-341 key-path signature hash. `values` / `spks` cover EVERY input of the transaction."""
    if hash_type not in (0, 1):
        raise ValueError("Only SIGHASH_DEFAULT / SIGHASH_ALL are supported for Taproot.")
    sha = lambda b: hashlib.sha256(b).digest()               # noqa: E731
    prevouts = b"".join(bytes.fromhex(i.txid.hex())[::-1] + int(i.vout).to_bytes(4, "little") for i in tx.vin)
    amounts = b"".join(int(v).to_bytes(8, "little") for v in values)
    scripts = b"".join(_varint(len(s)) + bytes(s) for s in spks)
    seqs = b"".join(int(i.sequence).to_bytes(4, "little") for i in tx.vin)
    outs = b"".join(int(o.value).to_bytes(8, "little") + _varint(len(o.script_pubkey.data)) + o.script_pubkey.data
                    for o in tx.vout)
    msg = (bytes([hash_type]) + int(tx.version).to_bytes(4, "little") + int(tx.locktime).to_bytes(4, "little")
           + sha(prevouts) + sha(amounts) + sha(scripts) + sha(seqs) + sha(outs)
           + b"\x00" + int(index).to_bytes(4, "little"))       # spend_type 0: key path, no annex
    return _tagged_hash("TapSighash", b"\x00" + msg)


def _push(data: bytes) -> bytes:
    assert len(data) < 0x4C
    return bytes([len(data)]) + data


# ----------------------------------- keystore --------------------------------------
def _norm_pw(pw: str) -> bytes:
    return unicodedata.normalize("NFKC", pw).encode()


def _kdf(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if not (2**12 <= n <= 2**20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
        raise ValueError("Keystore has unreasonable scrypt parameters; refusing to open it.")
    return hashlib.scrypt(_norm_pw(password), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=2**30)


def _aad(meta: dict) -> bytes:
    keep = {k: meta[k] for k in ("btcvault", "network", "script", "path", "fingerprint", "passphrase")}
    return json.dumps(keep, sort_keys=True, separators=(",", ":")).encode()


def normalize_mnemonic(words: str) -> str:
    return " ".join(words.lower().split())


def spk_for(script: str, pub) -> Script:
    """scriptPubKey of a single-sig address type for a compressed public key."""
    if script == "p2wpkh":
        return _escript.p2wpkh(pub)
    if script == "p2pkh":
        return _escript.p2pkh(pub)
    if script == "p2sh-p2wpkh":
        return _escript.p2sh(_escript.p2wpkh(pub))
    if script == "p2tr":
        return Script(b"\x51\x20" + taproot_output_key(pub.sec()))
    raise ValueError("Unknown address type.")


class Watch:
    """Public account data (account-level xpub). Safe to keep on an ONLINE machine."""

    def __init__(self, network: str, key: bip32.HDKey, fingerprint=None, path=None, script: str = DEFAULT_SCRIPT):
        if network not in NETWORKS:
            raise ValueError("Unknown network.")
        if script not in SCRIPTS:
            raise ValueError("Unknown address type.")
        self.network = network
        self.script = script
        self.key = key.to_public() if key.is_private else key
        self.fp = bytes(fingerprint) if fingerprint else b"\x00" * 4
        self.path = _norm_path(path) if path else default_path(network, 0, script)
        self._ck = {}
        self._cache = {}

    @property
    def fp_hex(self) -> str:
        return self.fp.hex()

    def _child(self, chain: int, idx: int):
        if (chain, idx) not in self._cache:
            if chain not in self._ck:
                self._ck[chain] = self.key.derive([chain])
            self._cache[(chain, idx)] = self._ck[chain].derive([idx])
        return self._cache[(chain, idx)]

    def pubkey(self, chain: int, idx: int):
        return self._child(chain, idx).get_public_key()

    def spk(self, chain: int, idx: int) -> Script:
        return spk_for(self.script, self._child(chain, idx).get_public_key())

    def address(self, chain: int, idx: int) -> str:
        return self.spk(chain, idx).address(net_params(self.network))

    def derivation(self, chain: int, idx: int):
        return _path_ints(self.path) + [chain, idx]

    # ---- exports ----
    def _version(self, kind: str) -> bytes:
        return bytes.fromhex(_SLIP["main" if NETWORKS[self.network]["embit"] == "main" else "test"][kind])

    def slip132(self) -> str:
        """zpub/vpub (native), ypub/upub (nested), plain xpub/tpub (legacy, taproot)."""
        return self.key.to_base58(version=self._version(SCRIPTS[self.script]["slip"]))

    def xpub(self) -> str:
        return self.key.to_base58(version=self._version("xpub"))

    def key_origin(self) -> str:
        return f"[{self.fp_hex}{self.path[1:]}]{self.slip132()}"

    def descriptors(self):
        op, cl = SCRIPTS[self.script]["desc"]
        base = f"{op}[{self.fp_hex}{self.path[1:]}]{self.xpub()}"
        return add_checksum(base + "/0/*" + cl), add_checksum(base + "/1/*" + cl)

    def export_text(self) -> str:
        ext, chg = self.descriptors()
        return (f"# BTCVault watch-only export — {self.network} — {script_label(self.script)}\n"
                f"# PUBLIC data only. Safe for an online machine, but it reveals ALL your addresses/balance.\n"
                f"key-origin: {self.key_origin()}\n"
                f"ext. pubkey: {self.slip132()}\n"
                f"receive   : {ext}\n"
                f"change    : {chg}\n"
                f"first address: {self.address(0, 0)}\n")


# ------------------------- Keystone / BC-UR key export (pairing QR) -----------------------
# Software wallets (UniSat, OKX, Sparrow, BlueWallet, Nunchuk …) pair with a Keystone by scanning:
#   ur:crypto-multi-accounts   Keystone's own export (registry type 1103) — what UniSat / OKX ask Keystone for
#   ur:crypto-account          BCR-2020-015 (master fingerprint + script descriptors) — Sparrow, BlueWallet, …
# Byte layout mirrors the real device firmware (Keystone-cold-app: URRegistryHelper / OKXWalletViewModel):
#   every hdkey carries use-info (coin type + network), origin WITH depth, parent fingerprint, name "Keystone".
# Signing needs nothing new: both directions are ur:crypto-psbt (already supported).
# NOTE: OKX / UniSat accept MAINNET only — a test-network export is flagged network=1 and OKX rejects it with
#       "This action is not supported on the current network type".
KS_DEVICE = "Keystone Pro"       # what the device reports (DeviceInfoUtil: "Keystone Pro" / "Keystone Essential")
KS_KEY_NAME = "Keystone"         # hdkey name field (URRegistryHelper.KEY_NAME)
KS_DEVICE_VERSION = None         # the Keystone-cold firmware sends none; set e.g. "2.0.0" only if a wallet asks
_UR_OUTPUT_TAG = {"p2pkh": (403,), "p2wpkh": (404,), "p2sh-p2wpkh": (400, 404), "p2tr": (409,)}   # BCR-2020-010


def _comps(ints):
    out = []
    for n in ints:
        out += [n & ~HARD, bool(n & HARD)]
    return out


def keystone_bundle(wallet) -> dict:
    """Everything a Keystone-style pairing needs, as PUBLIC data only (call once while the keystore is open):
         watches : account-0 Watch for every address type (Legacy, Nested, Native, Taproot)
         eth     : the device's Ethereum keys (BIP-44 standard + 10 Ledger-Live accounts) as crypto-hdkey items.
                   OKX's Keystone import expects them (it supports BTC + EVM from one scan)."""
    import cbor2
    watches = []
    for sc in SCRIPTS:
        path = default_path(wallet.network, 0, sc)
        watches.append(Watch(wallet.network, wallet.root.derive(path).to_public(), wallet.fp, path, sc))
    fp = int.from_bytes(wallet.fp, "big")
    net = 1 if NETWORKS[wallet.network]["test"] else 0
    std = wallet.root.derive("m/44h/60h/0h").to_public()
    eth = [cbor2.CBORTag(303, {
        3: bytes(std.get_public_key().sec()), 4: bytes(std.chain_code),
        5: cbor2.CBORTag(305, {1: 60, 2: net}),
        6: cbor2.CBORTag(304, {1: _comps(_path_ints("m/44h/60h/0h")), 2: fp, 3: 3}),
        7: cbor2.CBORTag(304, {1: [0, False, [], False]}),            # BIP-44 standard: m/44'/60'/0'/0/*
        8: int.from_bytes(std.fingerprint, "big"), 9: KS_KEY_NAME, 10: "account.standard"})]
    for i in range(10):                                                # Ledger Live: m/44'/60'/i'/0/0 (bare public keys)
        p = f"m/44h/60h/{i}h/0/0"
        k = wallet.root.derive(p).to_public()
        eth.append(cbor2.CBORTag(303, {
            3: bytes(k.get_public_key().sec()),
            6: cbor2.CBORTag(304, {1: _comps(_path_ints(p)), 2: fp, 3: 5}),
            9: KS_KEY_NAME, 10: "account.ledger_live"}))
    return {"watches": watches, "eth": eth}


def all_account_watches(wallet) -> list:
    return keystone_bundle(wallet)["watches"]


def _hdkey_cbor(watch: Watch, children: bool = False):
    """crypto-hdkey (tag 303), field-for-field like the device: key, chain code, use-info, origin(+depth),
    parent fingerprint, name."""
    import cbor2
    if watch.fp == b"\x00" * 4:
        raise ValueError("This key has no master fingerprint (bare xpub) — export from the wallet's own keystore "
                         "(tab 2) so the QR carries the fingerprint hardware-wallet flows need.")
    ints = _path_ints(watch.path)
    m = {3: bytes(watch.key.get_public_key().sec()), 4: bytes(watch.key.chain_code),
         5: cbor2.CBORTag(305, {1: 0, 2: 1 if NETWORKS[watch.network]["test"] else 0}),       # BTC, network
         6: cbor2.CBORTag(304, {1: _comps(ints), 2: int.from_bytes(watch.fp, "big"), 3: len(ints)})}
    if children:
        m[7] = cbor2.CBORTag(304, {1: [0, False, [], False]})      # .../0/*   (wildcard = empty component)
    m[8] = int.from_bytes(watch.key.fingerprint, "big")           # parent fingerprint
    m[9] = KS_KEY_NAME
    return cbor2.CBORTag(303, m)


def keystone_multi_accounts(bundle, device: str = None, device_id: str = None) -> tuple:
    """(ur_type, cbor_bytes) for ur:crypto-multi-accounts — what the OKX wallet reads from a Keystone.
    Same content and order as the device (OKXWalletViewModel): ETH keys, then BTC 44' / 49' / 84'.
    `bundle`: keystone_bundle() dict, or a Watch / list of Watch for a BTC-only export."""
    import cbor2
    if isinstance(bundle, dict):
        ws, eth = bundle["watches"], bundle.get("eth", [])
    else:
        ws, eth = ([bundle] if isinstance(bundle, Watch) else list(bundle)), []
    ws = [w for w in ws if w.script != "p2tr"] if len(ws) > 1 else ws     # the device exports 44/49/84 only
    order = {"p2pkh": 0, "p2sh-p2wpkh": 1, "p2wpkh": 2}
    ws = sorted(ws, key=lambda w: order.get(w.script, 9))
    fp = ws[0].fp
    if any(w.fp != fp or w.network != ws[0].network for w in ws):
        raise ValueError("All exported accounts must come from the same seed and network.")
    dev_id = device_id or hashlib.sha256(hashlib.sha256(b"keystone" + b"btcvault" + fp).digest()).hexdigest()[:40]
    body = {1: int.from_bytes(fp, "big"), 2: list(eth) + [_hdkey_cbor(w) for w in ws],
            3: device or KS_DEVICE, 4: dev_id}
    if KS_DEVICE_VERSION:
        body[5] = KS_DEVICE_VERSION
    return "crypto-multi-accounts", cbor2.dumps(body)


def keystone_account(watches) -> tuple:
    """(ur_type, cbor_bytes) for ur:crypto-account (BCR-2020-015). This is what UniSat (and BlueWallet / Sparrow)
    parse: ONE descriptor per address type — UniSat looks up m/44'/0'/0' first, so every type must be present."""
    import cbor2
    if isinstance(watches, dict):
        watches = watches["watches"]
    ws = [watches] if isinstance(watches, Watch) else list(watches)
    fp = ws[0].fp
    if any(w.fp != fp or w.network != ws[0].network for w in ws):
        raise ValueError("All exported accounts must come from the same seed and network.")
    outs = []
    for w in ws:
        node = _hdkey_cbor(w, children=True)
        for tag in reversed(_UR_OUTPUT_TAG[w.script]):
            node = cbor2.CBORTag(tag, node)
        outs.append(node)
    return "crypto-account", cbor2.dumps({1: int.from_bytes(fp, "big"), 2: outs})


def keystone_frames(bundle, kind: str = "multi", max_fragment: int = 160):
    """Animated-QR strings. kind: 'multi' (OKX) or 'account' (UniSat, BlueWallet, Sparrow)."""
    import ur
    typ, body = keystone_multi_accounts(bundle) if kind == "multi" else keystone_account(bundle)
    return ur.ur_encode_frames(typ, body, max_fragment)


_ORIGIN = re.compile(r"\[([0-9a-fA-F]{8})((?:/\d+[hH'])*)\]")
_XKEY = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])([xztvyu]pub[1-9A-HJ-NP-Za-km-z]{100,112})(?![1-9A-HJ-NP-Za-km-z])")
_BADKEY = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])([YUZV]pub|[xztvyuXYZTUV]prv)[1-9A-HJ-NP-Za-km-z]{100,112}")
_MAIN_VERSIONS = {bytes.fromhex(v) for v in _SLIP["main"].values()}       # xpub, ypub, zpub


def _descriptor_script(text: str):
    low = text.lower()
    if "sh(wpkh(" in low:
        return "p2sh-p2wpkh"
    if "wpkh(" in low:
        return "p2wpkh"
    if re.search(r"(?<![a-z])pkh\(", low):
        return "p2pkh"
    if re.search(r"(?<![a-z])tr\(", low):
        return "p2tr"
    return None


def parse_watch(text: str, network: str, script: str = None) -> Watch:
    """Accepts: zpub/ypub/xpub (vpub/upub/tpub on test nets), '[fp/84h/0h/0h]zpub…', or a descriptor
    (wpkh / sh(wpkh) / pkh / tr).  The address type is DETECTED from the key version, the origin path
    or the descriptor; `script` is only used when the text is a bare xpub/tpub with nothing to go on."""
    t = (text or "").strip()
    for line in t.splitlines():                           # allow our own export file (comments + labels)
        s = line.strip()
        if s.startswith("key-origin:"):
            t = s.split(":", 1)[1].strip()
            break
    if re.search(r"[xztvyuXYZTUV]prv", t):
        raise ValueError("That looks like a PRIVATE key. Never paste private keys into the online machine.")
    if _BADKEY.search(t) and not _XKEY.search(t):
        raise ValueError("Only single-sig keys are supported (xpub / ypub / zpub, or tpub / upub / vpub).")
    m = _XKEY.search(t)
    if not m:
        raise ValueError("No extended public key (xpub/ypub/zpub/tpub/upub/vpub) found in the text.")
    try:
        key = bip32.HDKey.from_base58(m.group(1))
    except Exception:
        raise ValueError("The extended public key is malformed (bad checksum?).")
    if key.is_private:
        raise ValueError("Refusing a private key.")
    ver = bytes(key.version)
    if ver not in _KNOWN_VERSIONS:
        raise ValueError("Unrecognised extended-key version.")
    is_main_key = ver in _MAIN_VERSIONS
    if is_main_key == NETWORKS[network]["test"]:
        raise ValueError(f"This key belongs to {'mainnet' if is_main_key else 'a test network'}, "
                         f"but you selected {network}.")
    if key.depth != 3:
        raise ValueError("Expected an ACCOUNT-level key (m/purpose'/coin'/account', depth 3).")
    fp, path, from_path = None, None, None
    o = _ORIGIN.search(t)
    if o:
        fp = bytes.fromhex(o.group(1))
        path = "m" + o.group(2)
        ints = _path_ints(path)
        if len(ints) != 3 or not (ints[0] & HARD) or (ints[0] & ~HARD) not in _PURPOSE_TO_SCRIPT:
            raise ValueError("Only BIP-44/49/84/86 account paths (m/purpose'/coin'/account') are supported.")
        from_path = _PURPOSE_TO_SCRIPT[ints[0] & ~HARD]
        if ints[1] != (NETWORKS[network]["coin"] | HARD):
            raise ValueError("The key's coin-type does not match the selected network.")
    hints = {"key version": _SLIP_TO_SCRIPT[ver], "origin path": from_path, "descriptor": _descriptor_script(t)}
    found = {k: v for k, v in hints.items() if v}
    if len(set(found.values())) > 1:
        raise ValueError("The key contradicts itself about its address type: "
                         + ", ".join(f"{k} says {script_label(v)}" for k, v in found.items()))
    detected = next(iter(found.values()), None)
    chosen = detected or script or DEFAULT_SCRIPT
    if chosen not in SCRIPTS:
        raise ValueError("Unknown address type.")
    w = Watch(network, key, fp, path, chosen)
    w.detected = detected is not None                  # False -> bare xpub: type came from the caller's choice
    return w


class Wallet:
    """Signing-capable wallet. OFFLINE machine only."""

    def __init__(self, mnemonic: str, passphrase: str, network: str, account: int = 0, script: str = DEFAULT_SCRIPT):
        if script not in SCRIPTS:
            raise ValueError("Unknown address type.")
        mnemonic = normalize_mnemonic(mnemonic)
        if not bip39.mnemonic_is_valid(mnemonic):
            raise ValueError("Invalid seed phrase (unknown word or bad checksum).")
        seed = bip39.mnemonic_to_seed(mnemonic, unicodedata.normalize("NFKD", passphrase or ""))
        self.network = network
        self.script = script
        self.root = bip32.HDKey.from_seed(seed, version=net_params(network)["xprv"])
        self.path = default_path(network, account, script)
        self.acct = self.root.derive(self.path)
        self.fp = self.root.my_fingerprint
        self.watch = Watch(network, self.acct.to_public(), self.fp, self.path, script)

    def priv(self, chain: int, idx: int):
        return self.acct.derive([chain, idx])


def new_mnemonic(words: int = 24) -> str:
    return bip39.mnemonic_from_bytes(os.urandom({12: 16, 15: 20, 18: 24, 21: 28, 24: 32}[words]))


def keystore_create(mnemonic: str, password: str, network: str, passphrase: str = "",
                    script: str = DEFAULT_SCRIPT) -> dict:
    mnemonic = normalize_mnemonic(mnemonic)
    w = Wallet(mnemonic, passphrase, network, script=script)
    meta = {"btcvault": KS_VERSION, "network": network, "script": script, "path": w.path,
            "fingerprint": w.fp.hex(), "passphrase": bool(passphrase)}
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _kdf(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    blob = _gcm_encrypt(key, nonce, mnemonic.encode(), _aad(meta))
    ks = dict(meta)
    ks.update({"first_address": w.watch.address(0, 0),
               "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": salt.hex()},
               "cipher": {"name": "aes-256-gcm", "nonce": nonce.hex()},
               "ciphertext": blob.hex()})
    return ks


def keystore_info(ks: dict) -> dict:
    if ks.get("btcvault") != KS_VERSION or ks.get("network") not in NETWORKS or ks.get("script") not in SCRIPTS:
        raise ValueError("Not a BTCVault Bitcoin keystore.")
    return {k: ks.get(k) for k in ("network", "script", "path", "fingerprint", "passphrase", "first_address")}


def keystore_open(ks: dict, password: str, passphrase: str = "") -> Wallet:
    keystore_info(ks)
    if ks["kdf"].get("name") != "scrypt" or ks["cipher"].get("name") != "aes-256-gcm":
        raise ValueError("Unsupported keystore encryption.")
    if ks.get("passphrase") and not passphrase:
        raise ValueError("This wallet was created with a BIP-39 passphrase — enter it.")
    key = _kdf(password, bytes.fromhex(ks["kdf"]["salt"]), int(ks["kdf"]["n"]), int(ks["kdf"]["r"]), int(ks["kdf"]["p"]))
    try:
        mnemonic = _gcm_decrypt(key, bytes.fromhex(ks["cipher"]["nonce"]), bytes.fromhex(ks["ciphertext"]),
                                _aad(ks)).decode()
    except ValueError:
        raise ValueError("Wrong password, or the keystore file was modified.")
    w = Wallet(mnemonic, passphrase, ks["network"], script=ks["script"])
    if w.fp.hex() != ks["fingerprint"] or w.path != ks["path"]:
        raise ValueError("The BIP-39 passphrase does not match this wallet (fingerprint differs).")
    return w


# ------------------------------- explorer (Esplora) API -----------------------------
class _Esplora:
    """Minimal client for Esplora-compatible REST APIs (mempool.space, blockstream.info, self-hosted)."""

    def __init__(self, base: str, timeout: int = 20):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def _req(self, path: str, data: bytes = None):
        if NETWORK_DISABLED:
            raise RuntimeError("Offline mode: network is disabled.")
        url = self.base + path
        for attempt in range(3):
            req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET",
                                         headers={"User-Agent": "Mozilla/5.0 (compatible; BTCVault/1.0)",
                                                  "Content-Type": "text/plain"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return r.read()
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="replace")[:400]
                if data is None and e.code in (429, 502, 503, 504) and attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise RuntimeError(f"HTTP {e.code}: {body}") from None
            except urllib.error.URLError as e:
                raise RuntimeError(f"Network error: {e.reason}") from None

    def _json(self, path):
        return json.loads(self._req(path))

    def address(self, addr):      return self._json(f"/address/{addr}")
    def utxos(self, addr):        return self._json(f"/address/{addr}/utxo")
    def tx(self, txid):           return self._json(f"/tx/{txid}")
    def tx_hex(self, txid):       return self._req(f"/tx/{txid}/hex").decode().strip()
    def tx_status(self, txid):    return self._json(f"/tx/{txid}/status")
    def tip_height(self):         return int(self._req("/blocks/tip/height"))
    def fee_estimates(self):      return self._json("/fee-estimates")

    def broadcast(self, raw_hex: str) -> str:
        return self._req("/tx", raw_hex.encode()).decode().strip()


class Blockbook(_Esplora):
    """Client for Trezor Blockbook (API v2). Exposes the same methods/return shapes as the Esplora client,
    so the rest of BTCVault works unchanged.  Base URL e.g.  https://<your-blockbook-host>  (the
    /api/v2 suffix is added automatically)."""

    def __init__(self, base: str, timeout: int = 20):
        base = base.strip().rstrip("/")
        if base.lower().startswith("blockbook:"):
            base = base[len("blockbook:"):]
        if "/api" not in base.split("://", 1)[-1]:
            base += "/api/v2"
        super().__init__(base, timeout)

    @staticmethod
    def _i(v):
        return int(v or 0)

    def address(self, addr):
        d = self._json(f"/address/{addr}?details=basic")
        unconf = self._i(d.get("unconfirmedBalance"))
        return {"chain_stats": {"tx_count": self._i(d.get("txs")),
                                "funded_txo_sum": self._i(d.get("totalReceived")),
                                "spent_txo_sum": self._i(d.get("totalSent"))},
                "mempool_stats": {"tx_count": self._i(d.get("unconfirmedTxs")),
                                  "funded_txo_sum": max(unconf, 0), "spent_txo_sum": max(-unconf, 0)}}

    def utxos(self, addr):
        return [{"txid": u["txid"], "vout": int(u["vout"]), "value": self._i(u["value"]),
                 "status": {"confirmed": self._i(u.get("confirmations")) > 0}}
                for u in self._json(f"/utxo/{addr}")]

    def tx(self, txid):
        d = self._json(f"/tx/{txid}")
        for o in d.get("vout", []):
            o["value"] = self._i(o.get("value"))
        return d

    def tx_hex(self, txid):
        h = self._json(f"/tx/{txid}").get("hex")
        if not h:
            raise RuntimeError("Blockbook returned no raw hex for " + txid)
        return h

    def tx_status(self, txid):
        d = self._json(f"/tx/{txid}")
        conf = self._i(d.get("confirmations")) > 0
        return {"confirmed": conf, "block_height": d.get("blockHeight") if conf else None}

    def tip_height(self):
        return int(self._json("")["blockbook"]["bestHeight"])

    def fee_estimates(self):
        est = {}
        for n in (1, 2, 3, 6, 144):
            try:
                r = float(self._json(f"/estimatefee/{n}")["result"])      # BTC per kB
            except Exception:
                continue
            if r > 0:
                est[str(n)] = r * 1e5                                     # -> sat/vB
        return est

    def broadcast(self, raw_hex: str) -> str:
        r = json.loads(self._req("/sendtx/", raw_hex.encode()))
        if "result" not in r:
            raise RuntimeError(str(r.get("error", r)))
        return r["result"]


def Esplora(base: str, timeout: int = 20):
    """Pick the right client from the URL: Trezor/Blockbook-style URLs -> Blockbook, otherwise Esplora."""
    low = base.lower()
    if "trezor.io" in low or "/api/v2" in low or "blockbook" in low:
        return Blockbook(base, timeout)
    return _Esplora(base, timeout)


def suggest_fees(api) -> dict:
    est = api.fee_estimates()

    def pick(*targets, default):
        for t in targets:
            if str(t) in est:
                return max(1.0, round(float(est[str(t)]) + 0.049, 1))
        return default
    return {"fast": pick(1, 2, default=10.0), "normal": pick(3, 6, default=5.0), "slow": pick(144, 72, default=1.0)}


def scan_wallet(watch: Watch, api: Esplora, gap: int = 10, progress=None) -> dict:
    """Walk both chains until `gap` consecutive unused addresses. Returns balances, UTXOs, next indices."""
    res = {"addresses": [], "utxos": [], "next": {0: 0, 1: 0}, "confirmed": 0, "unconfirmed": 0}
    for chain in (0, 1):
        idx, misses, last_used = 0, 0, -1
        while misses < gap and idx < 2000:
            addr = watch.address(chain, idx)
            info = api.address(addr)
            cs, ms = info["chain_stats"], info["mempool_stats"]
            used = (cs["tx_count"] + ms["tx_count"]) > 0
            conf = cs["funded_txo_sum"] - cs["spent_txo_sum"]
            unconf = ms["funded_txo_sum"] - ms["spent_txo_sum"]
            if used:
                last_used, misses = idx, 0
                res["addresses"].append({"chain": chain, "index": idx, "address": addr,
                                         "confirmed": conf, "unconfirmed": unconf})
                res["confirmed"] += conf
                res["unconfirmed"] += unconf
            else:
                misses += 1
            if conf + unconf > 0:
                for u in api.utxos(addr):
                    res["utxos"].append({"txid": u["txid"], "vout": int(u["vout"]), "value": int(u["value"]),
                                         "confirmed": bool(u["status"].get("confirmed")),
                                         "chain": chain, "index": idx, "address": addr})
            idx += 1
            if progress:
                progress(f"Scanning {'receive' if chain == 0 else 'change'} addresses… {idx}")
        res["next"][chain] = last_used + 1
    return res


# ------------------------------------ PSBT analysis ---------------------------------
class _Owned:
    """Decides which scriptPubKeys belong to this account (verified by re-deriving, never trusted)."""

    def __init__(self, watch: Watch, limit: int = MAX_SCAN):
        self.w, self.limit, self.map = watch, limit, None

    def match(self, spk_bytes: bytes, hints=()):
        for der in hints:                                   # hints only save time; result is verified
            if len(der) >= 2 and der[-2] in (0, 1) and 0 <= der[-1] < HARD:
                if self.w.spk(der[-2], der[-1]).data == spk_bytes:
                    return der[-2], der[-1]
        if self.map is None:
            self.map = {self.w.spk(c, i).data: (c, i) for c in (0, 1) for i in range(self.limit)}
        return self.map.get(spk_bytes)


def _hints(scope):
    return [d.derivation for d in scope.bip32_derivations.values()]


def analyze_psbt(psbt: PSBT, watch: Watch, allow_witness_only: bool = False) -> dict:
    """Independent review of a PSBT. Returns dict with inputs, outputs, fee, errors, warnings."""
    rv = {"network": watch.network, "script": watch.script, "inputs": [], "outputs": [], "errors": [], "warnings": [],
          "fee": None, "vsize": None, "feerate": None, "external_total": 0, "txid": None}
    err, warn = rv["errors"].append, rv["warnings"].append
    tx = psbt.tx
    rv["txid"] = tx.txid().hex()
    if psbt.version not in (None, 0):
        err("PSBT version 2 is not supported.")
    owned = _Owned(watch)
    total_in = 0
    n_mine = 0
    for i, inp in enumerate(psbt.inputs):
        txin = tx.vin[i]
        info = {"txid": txin.txid.hex(), "vout": txin.vout, "value": None, "address": None, "spk": None,
                "mine": False, "chain": None, "index": None, "proven": False}
        utxo = None
        if inp.non_witness_utxo is not None:
            try:
                inp.verify()                                   # re-hash previous tx, compare with outpoint
                if txin.vout >= len(inp.non_witness_utxo.vout):
                    raise PSBTError("output index out of range")
                utxo = inp.non_witness_utxo.vout[txin.vout]
                info["proven"] = True
                w = inp.witness_utxo
                if w is not None and (w.value != utxo.value or w.script_pubkey.data != utxo.script_pubkey.data):
                    err(f"Input {i}: witness_utxo contradicts the previous transaction (tampered PSBT).")
            except PSBTError as e:
                err(f"Input {i}: previous transaction does not match the outpoint ({e}).")
        elif inp.witness_utxo is not None:
            if allow_witness_only:
                utxo = inp.witness_utxo
                warn(f"Input {i}: amount is NOT verified (no full previous tx). A malicious online machine "
                     f"could hide a huge fee. Only proceed if you trust it.")
            else:
                err(f"Input {i}: previous transaction missing — amount can't be verified "
                    f"(fee-attack protection). Rebuild the PSBT with 'include full previous transactions'.")
        else:
            err(f"Input {i}: no UTXO data at all.")
        if utxo is not None:
            info["value"] = utxo.value
            info["spk"] = utxo.script_pubkey.data
            info["address"] = spk_to_address(utxo.script_pubkey, watch.network)
            total_in += utxo.value
            hit = owned.match(utxo.script_pubkey.data, _hints(inp))
            if hit:
                if utxo.script_pubkey.script_type() != SCRIPTS[watch.script]["spk"]:
                    err(f"Input {i}: unsupported script type.")
                else:
                    info["mine"], info["chain"], info["index"] = True, hit[0], hit[1]
                    n_mine += 1
            else:
                warn(f"Input {i} does NOT belong to this wallet — it will not be signed here.")
        st = inp.sighash_type
        if st not in (None, SIGHASH.ALL, SIGHASH.DEFAULT):
            err(f"Input {i}: requests sighash type {st}; only SIGHASH_ALL is signed.")
        rv["inputs"].append(info)
    if psbt.inputs and n_mine == 0:
        err("No input of this PSBT belongs to this wallet.")

    total_out = 0
    for k, out in enumerate(tx.vout):
        spk = out.script_pubkey
        info = {"value": out.value, "address": spk_to_address(spk, watch.network), "kind": "external",
                "chain": None, "index": None, "spk_len": len(spk.data)}
        total_out += out.value
        if spk.data[:1] == b"\x6a":
            info["kind"], info["address"] = "opreturn", "OP_RETURN data: " + spk.data[1:40].hex()
            if out.value:
                warn(f"Output {k}: OP_RETURN burns {out.value} sat.")
        else:
            scope = psbt.outputs[k] if k < len(psbt.outputs) else None
            hit = owned.match(spk.data, _hints(scope) if scope else ())
            if hit and spk.script_type() == SCRIPTS[watch.script]["spk"]:
                info["chain"], info["index"] = hit
                info["kind"] = "change" if hit[0] == 1 else "self"
            if info["address"] is None:
                info["address"] = "script:" + spk.data.hex()
                warn(f"Output {k}: non-standard script.")
        if info["kind"] == "external":
            rv["external_total"] += out.value
        rv["outputs"].append(info)

    if all(i["value"] is not None for i in rv["inputs"]):
        rv["fee"] = total_in - total_out
        if rv["fee"] < 0:
            err("Outputs are larger than inputs.")
        else:
            rv["vsize"] = vsize_estimate(len(rv["inputs"]), [o["spk_len"] for o in rv["outputs"]], watch.script)
            rv["feerate"] = rv["fee"] / rv["vsize"]
            sent = max(rv["external_total"], 1)
            if rv["feerate"] > 300 or (rv["fee"] > 20000 and rv["fee"] > sent // 10):
                warn(f"HIGH FEE: {rv['fee']} sat ({rv['feerate']:.1f} sat/vB) — {100 * rv['fee'] / (sent + rv['fee']):.1f}% "
                     f"of the value leaving your wallet. Check before signing.")
            if rv["feerate"] < 1:
                warn("Fee rate is below 1 sat/vB — the transaction may never confirm.")
    if not [o for o in rv["outputs"] if o["kind"] == "change"] and rv["external_total"] and rv["fee"] is not None:
        warn("No change output: everything not sent to the recipient goes to the miner.")
    return rv


def format_review(rv: dict) -> str:
    net = rv["network"]
    tag = "  (test coins — no real value)" if NETWORKS[net]["test"] else "  ** REAL BITCOIN **"
    lines = [f"Network : {net}{tag}", f"Type    : {script_label(rv['script'])}", f"Txid    : {rv['txid']}", ""]
    lines.append(f"INPUTS ({len(rv['inputs'])})")
    for i, x in enumerate(rv["inputs"]):
        v = to_btc(x["value"]) + " BTC" if x["value"] is not None else "?"
        who = f"yours  m/…/{x['chain']}/{x['index']}" if x["mine"] else "NOT YOURS"
        lines.append(f"  #{i}  {v:>16}  {x['address'] or '?'}  [{who}]")
    lines.append("")
    lines.append(f"OUTPUTS ({len(rv['outputs'])})")
    label = {"external": "SENDING TO", "change": "change (yours)", "self": "yours (receive addr)",
             "opreturn": "OP_RETURN", "unknown": "?"}
    for i, o in enumerate(rv["outputs"]):
        extra = f" m/…/{o['chain']}/{o['index']}" if o["chain"] is not None else ""
        lines.append(f"  #{i}  {to_btc(o['value']) + ' BTC':>16}  {o['address']}   <- {label[o['kind']]}{extra}")
    lines.append("")
    if rv["fee"] is not None and rv["fee"] >= 0:
        lines.append(f"Amount leaving your wallet (to others): {to_btc(rv['external_total'])} BTC")
        lines.append(f"Fee     : {rv['fee']} sat  (~{rv['feerate']:.1f} sat/vB, est. {rv['vsize']} vB)")
    for w in rv["warnings"]:
        lines.append(f"WARNING : {w}")
    for e in rv["errors"]:
        lines.append(f"ERROR   : {e}")
    return "\n".join(lines)


# ------------------------------------- build (online) -------------------------------
def select_coins(utxos, target: int, feerate, dest_spk_len: int, change_spk_len: int = None, send_max: bool = False,
                 script: str = DEFAULT_SCRIPT):
    """Returns (selected, fee, change_value, send_value). change_value == 0 means no change output."""
    feerate = Decimal(str(feerate))
    change_spk_len = change_spk_len or SCRIPTS[script]["spk_len"]
    cands = sorted(utxos, key=lambda u: u["value"])
    if not cands:
        raise ValueError("No spendable (confirmed) coins in this wallet.")
    if send_max:
        fee = _ceil(feerate * vsize_estimate(len(cands), [dest_spk_len], script))
        value = sum(u["value"] for u in cands) - fee
        return cands, fee, 0, value

    def fees(n):
        return (_ceil(feerate * vsize_estimate(n, [dest_spk_len, change_spk_len], script)),
                _ceil(feerate * vsize_estimate(n, [dest_spk_len], script)))

    for u in cands:                                          # smallest single coin that covers it
        fee_c, fee_nc = fees(1)
        if u["value"] >= target + fee_nc:
            return _finish([u], target, fee_c, fee_nc, SCRIPTS[script]["dust"])
    sel, total = [], 0
    for u in reversed(cands):                                # otherwise largest-first
        sel.append(u)
        total += u["value"]
        fee_c, fee_nc = fees(len(sel))
        if total >= target + fee_nc:
            return _finish(sel, target, fee_c, fee_nc, SCRIPTS[script]["dust"])
    raise ValueError(f"Insufficient funds: have {to_btc(total)} BTC (confirmed), need more than {to_btc(target)} BTC + fee.")


def _finish(sel, target, fee_c, fee_nc, change_dust=294):
    total = sum(u["value"] for u in sel)
    change = total - target - fee_c
    if change >= change_dust:
        return sel, fee_c, change, target
    return sel, total - target, 0, target                    # tiny remainder goes to the miner


def build_psbt(watch: Watch, scan: dict, dest_addr: str, amount_sat, fee_rate, *, send_max=False,
               get_prev_hex=None, allow_unconfirmed=False) -> PSBT:
    """Unsigned PSBT. `get_prev_hex(txid)` supplies raw previous txs (strongly recommended)."""
    fee_rate = Decimal(str(fee_rate))
    if not (Decimal("0.1") <= fee_rate <= 1000):
        raise ValueError("Fee rate must be between 0.1 and 1000 sat/vB.")
    dest = address_to_spk(dest_addr, watch.network)
    if watch.script == "p2pkh" and not get_prev_hex:
        raise ValueError("Legacy (P2PKH) inputs can only be signed with the full previous transactions "
                         "— enable 'Include full previous transactions'.")
    utxos = [u for u in scan["utxos"] if u["confirmed"] or allow_unconfirmed]
    if send_max:
        sel, fee, change, value = select_coins(utxos, 0, fee_rate, len(dest.data), send_max=True, script=watch.script)
    else:
        if amount_sat is None or amount_sat < dust_limit(dest):
            raise ValueError("Amount is below the dust limit.")
        sel, fee, change, value = select_coins(utxos, amount_sat, fee_rate, len(dest.data), script=watch.script)
    if value < dust_limit(dest):
        raise ValueError("Nothing left to send after the fee.")

    vin, prevs = [], []
    for u in sel:
        spk = watch.spk(u["chain"], u["index"])
        prev = None
        if get_prev_hex:
            prev = Transaction.parse(bytes.fromhex(get_prev_hex(u["txid"])))
            if (prev.txid().hex() != u["txid"] or u["vout"] >= len(prev.vout)
                    or prev.vout[u["vout"]].value != u["value"]
                    or prev.vout[u["vout"]].script_pubkey.data != spk.data):
                raise RuntimeError("The explorer returned data that doesn't match the coin it listed. Aborting.")
        prevs.append((u, spk, prev))
        vin.append(TransactionInput(bytes.fromhex(u["txid"]), u["vout"], sequence=RBF_SEQUENCE))

    outs = [(TransactionOutput(value, dest), None)]
    if change:
        cidx = scan["next"][1]
        outs.append((TransactionOutput(change, watch.spk(1, cidx)), cidx))
    if len(outs) == 2 and secrets.randbelow(2):
        outs.reverse()                                       # don't always put change last (privacy)
    tx = Transaction(version=2, vin=vin, vout=[o for o, _ in outs], locktime=0)
    psbt = PSBT(tx)
    for i, (u, spk, prev) in enumerate(prevs):
        sc = psbt.inputs[i]
        pub = watch.pubkey(u["chain"], u["index"])
        if watch.script == "p2pkh":                          # legacy: the full previous tx IS the UTXO record
            sc.non_witness_utxo = prev
        else:
            sc.witness_utxo = TransactionOutput(u["value"], spk)
            if prev is not None:
                sc.non_witness_utxo = prev
            if watch.script == "p2sh-p2wpkh":
                sc.redeem_script = _escript.p2wpkh(pub)
        if watch.script != "p2tr":       # taproot uses different (BIP-371) fields; BTCVault's signer matches by script
            sc.bip32_derivations[pub] = DerivationPath(watch.fp, watch.derivation(u["chain"], u["index"]))
    for k, (_, cidx) in enumerate(outs):
        if cidx is not None and watch.script != "p2tr":
            psbt.outputs[k].bip32_derivations[watch.pubkey(1, cidx)] = DerivationPath(
                watch.fp, watch.derivation(1, cidx))
    return psbt


# -------------------------------------- sign (offline) ------------------------------
_TAP_KEY_SIG = b"\x13"          # PSBT_IN_TAP_KEY_SIG (BIP-371). embit 0.8 doesn't parse it: it lives in .unknown


def _tap_key_sig(inp):
    v = getattr(inp, "taproot_key_sig", None) or inp.unknown.get(_TAP_KEY_SIG)
    return bytes(v) if v else None


def _set_tap_key_sig(inp, sig: bytes):
    if hasattr(inp, "taproot_key_sig"):                      # newer embit versions
        inp.taproot_key_sig = sig
    else:
        inp.unknown = dict(inp.unknown)                      # never mutate a dict shared with other inputs
        inp.unknown[_TAP_KEY_SIG] = sig


def _is_signed(inp) -> bool:
    return bool(inp.final_scriptwitness or inp.final_scriptsig or inp.partial_sigs or _tap_key_sig(inp))


def sign_psbt(psbt: PSBT, wallet: Wallet, allow_witness_only: bool = False, finalize: bool = True) -> dict:
    """Re-analyses, signs every input that belongs to the wallet. Returns dict.

    finalize=True  : inputs are finalised (final_scriptwitness / final_scriptsig) — BTCVault's own flow.
    finalize=False : \"hardware-wallet\" output exactly like a Keystone / Coldcard / Jade returns it — only the
                     signature (partial_sigs / taproot key-path sig) is added and everything else is left alone,
                     so the software wallet (UniSat, OKX, Sparrow, BlueWallet …) can finalise it itself.
                     (Finalised PSBTs make bitcoinjs-based wallets throw 'Can not finalize input'.)"""
    rv = analyze_psbt(psbt, wallet.watch, allow_witness_only)
    if rv["errors"]:
        raise ValueError("Refusing to sign:\n- " + "\n- ".join(rv["errors"]))
    script = wallet.script
    txid_before = psbt.tx.txid()
    if script == "p2tr":                                     # BIP-341 commits to ALL inputs' amounts + scripts
        all_values = [i["value"] for i in rv["inputs"]]
        all_spks = [i["spk"] for i in rv["inputs"]]
    signed = 0
    for i, inp in enumerate(psbt.inputs):
        info = rv["inputs"][i]
        if not info["mine"]:
            continue
        key = wallet.priv(info["chain"], info["index"])
        pub = key.get_public_key()

        if script == "p2tr":
            secret = key.secret                              # embit HDKey exposes the 32-byte private scalar as .secret
            if not secret:
                raise RuntimeError("Keystore holds no private key for this input.")
            d = taproot_tweak_secret(secret)
            xonly = taproot_output_key(pub.sec())
            if Script(b"\x51\x20" + xonly).data != info["spk"]:
                raise RuntimeError("Internal error: taproot key does not match the coin's script. Nothing exported.")
            ht = 1 if inp.sighash_type == SIGHASH.ALL else 0
            h = taproot_sighash(psbt.tx, all_values, all_spks, i, ht)
            try:                                             # prefer libsecp256k1 via embit, else pure Python
                sig = ec.PrivateKey(d.to_bytes(32, "big")).schnorr_sign(h).serialize()
            except (AttributeError, TypeError):
                sig = schnorr_sign(d, h, os.urandom(32))
            if not schnorr_verify(xonly, h, sig):
                raise RuntimeError("Internal error: signature failed self-check. Nothing exported.")
            tsig = sig + (bytes([ht]) if ht else b"")
            if finalize:
                inp.final_scriptwitness = Witness([tsig])
            else:
                _set_tap_key_sig(inp, tsig)
        else:
            if script == "p2pkh":
                inp.witness_utxo = None                      # must not look like a SegWit input
            else:
                inp.witness_utxo = TransactionOutput(info["value"], Script(info["spk"]))   # value is proven
                if script == "p2sh-p2wpkh":
                    inp.redeem_script = _escript.p2wpkh(pub)
            h = psbt.sighash(i, sighash=SIGHASH.ALL)
            sig = key.sign(h)
            if not pub.verify(sig, h):
                raise RuntimeError("Internal error: signature failed self-check. Nothing exported.")
            sig_b = sig.serialize() + bytes([SIGHASH.ALL])
            if not finalize:
                inp.partial_sigs.clear()
                inp.partial_sigs[pub] = sig_b
            elif script == "p2wpkh":
                inp.final_scriptwitness = Witness([sig_b, pub.sec()])
            elif script == "p2sh-p2wpkh":
                inp.final_scriptwitness = Witness([sig_b, pub.sec()])
                inp.final_scriptsig = Script(_push(_escript.p2wpkh(pub).data))
            else:
                inp.final_scriptsig = Script(_push(sig_b) + _push(pub.sec()))
        if finalize:
            inp.partial_sigs.clear()
            inp.bip32_derivations.clear()
        signed += 1
    if psbt.tx.txid() != txid_before:
        raise RuntimeError("Internal error: transaction changed while signing. Nothing exported.")
    complete = all(_is_signed(i) for i in psbt.inputs)
    raw = final_txid = None
    if complete:
        try:
            tx = extract_tx(psbt)
            raw, final_txid = tx.serialize().hex(), tx.txid().hex()
        except ValueError:
            pass                                             # e.g. multi-key partial sigs: leave to the other wallet
    # NB: for Legacy / Nested-SegWit the scriptSig is part of the txid, so it changes when signed.
    return {"psbt": psbt, "signed": signed, "complete": complete, "review": rv, "raw": raw,
            "txid": final_txid or txid_before.hex(), "finalized": finalize}


def extract_tx(psbt: PSBT) -> Transaction:
    """Final network transaction from a (fully signed) PSBT. Also finalises simple single-key partial sigs
    (P2WPKH / P2SH-P2WPKH / P2PKH / Taproot key-path) produced by other wallets."""
    tx = Transaction.parse(psbt.tx.serialize())              # fresh copy (unsigned tx has no witness)
    for i, inp in enumerate(psbt.inputs):
        wit, sig_script = inp.final_scriptwitness, inp.final_scriptsig
        if not wit and not sig_script:
            utxo = inp.utxo
            tap = _tap_key_sig(inp)
            if tap and utxo is not None and utxo.script_pubkey.script_type() == "p2tr":
                wit = Witness([bytes(tap)])
            elif len(inp.partial_sigs) == 1 and utxo is not None:
                pub, sig = next(iter(inp.partial_sigs.items()))
                spk = utxo.script_pubkey.data
                if spk == _escript.p2wpkh(pub).data:
                    wit = Witness([sig, pub.sec()])
                elif spk == _escript.p2sh(_escript.p2wpkh(pub)).data:
                    wit = Witness([sig, pub.sec()])
                    sig_script = Script(_push(_escript.p2wpkh(pub).data))
                elif spk == _escript.p2pkh(pub).data:
                    sig_script = Script(_push(sig) + _push(pub.sec()))
        if not wit and not sig_script:
            raise ValueError(f"Input {i} is not signed — this PSBT is not complete.")
        if wit:
            tx.vin[i].witness = wit
        if sig_script:
            tx.vin[i].script_sig = sig_script
    return tx


# ------------------------------- PSBT / tx text formats -----------------------------
def psbt_from_text(text: str) -> PSBT:
    """base64, hex, or ur:crypto-psbt (single string)."""
    t = "".join((text or "").split())
    if not t:
        raise ValueError("Nothing to parse.")
    if t[:3].lower() == "ur:":
        try:
            import cbor2
            import ur
        except ImportError:
            raise ValueError("UR QR needs:  pip install cbor2  (and ur.py next to btcvault.py).")
        d = ur.URDecoder()
        if not d.add(t):
            raise ValueError("That is only ONE fragment of a multi-part QR. Use 'Scan QR with camera'.")
        typ, body = d.result()
        if typ not in ("crypto-psbt", "psbt"):
            raise ValueError(f"Expected a PSBT UR but got ur:{typ}.")
        return PSBT.parse(cbor2.loads(body))
    if t.startswith("cHNidP8"):
        return PSBT.from_base64(t)
    if re.fullmatch(r"[0-9a-fA-F]+", t) and t.lower().startswith("70736274ff"):
        return PSBT.parse(bytes.fromhex(t))
    raise ValueError("Not a PSBT (expected base64 starting 'cHNidP8', hex '70736274ff…' or a ur:crypto-psbt).")


def psbt_from_file(path: str) -> PSBT:
    data = open(path, "rb").read()
    if data.startswith(b"psbt\xff"):
        return PSBT.parse(data)
    return psbt_from_text(data.decode("utf-8", "replace"))


def psbt_ur_frames(psbt: PSBT, max_fragment: int = 200):
    import cbor2
    import ur
    return ur.ur_encode_frames("crypto-psbt", cbor2.dumps(psbt.serialize()), max_fragment)


def parse_tx_text(text: str) -> Transaction:
    t = "".join((text or "").split())
    if re.fullmatch(r"[0-9a-fA-F]+", t or "x") and len(t) >= 20 and not t.lower().startswith("70736274ff"):
        return Transaction.parse(bytes.fromhex(t))
    raise ValueError("Not a raw transaction hex.")


# --------------------------------------- self test ---------------------------------
_ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# first receive address (m/purpose'/0'/0'/0/0) of the standard "abandon … about" seed on mainnet.
# BIP-44 / BIP-84 / BIP-86 are the published test vectors; BIP-49 was derived with an independent implementation.
_VECTORS = {"p2pkh": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
            "p2sh-p2wpkh": "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
            "p2wpkh": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "p2tr": "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"}


def _selftest_flow(script: str, net: str) -> str:
    """create -> keystore -> watch import -> build -> review -> sign -> finalise, for one type on one network."""
    w = keystore_open(keystore_create(new_mnemonic(), "selftest-password", net, script=script), "selftest-password")
    watch = parse_watch(w.watch.key_origin(), net)
    assert watch.script == script and watch.detected, "address type not detected from the key"
    assert watch.address(0, 3) == w.watch.address(0, 3) and watch.fp == w.fp
    assert parse_watch(w.watch.descriptors()[0], net).address(1, 2) == w.watch.address(1, 2)
    bare = parse_watch(watch.slip132(), net, script)                        # bare key + user's choice
    assert bare.script == script and bare.address(0, 1) == w.watch.address(0, 1)

    def fund(idx, value):
        return Transaction(2, [TransactionInput(os.urandom(32), 0)], [TransactionOutput(value, watch.spk(0, idx))], 0)
    f1, f2 = fund(0, 60_000), fund(1, 150_000)
    store = {f.txid().hex(): f.serialize().hex() for f in (f1, f2)}
    scan = {"utxos": [{"txid": f1.txid().hex(), "vout": 0, "value": 60_000, "confirmed": True, "chain": 0, "index": 0},
                      {"txid": f2.txid().hex(), "vout": 0, "value": 150_000, "confirmed": True, "chain": 0, "index": 1}],
            "next": {0: 2, 1: 0}}
    dest = Wallet(new_mnemonic(), "", net).watch.address(0, 0)
    psbt = build_psbt(watch, scan, dest, 100_000, 2, get_prev_hex=store.__getitem__)
    rv = analyze_psbt(psbt, watch)
    assert not rv["errors"], rv["errors"]
    assert rv["external_total"] == 100_000 and rv["fee"] > 0
    assert [o for o in rv["outputs"] if o["kind"] == "change"], "change not detected"
    assert sum(o["value"] for o in rv["outputs"]) + rv["fee"] == 150_000
    b64 = psbt.to_base64()
    res = sign_psbt(psbt_from_text(b64), w)
    assert res["complete"] and res["raw"]
    final = Transaction.parse(bytes.fromhex(res["raw"]))
    assert final.txid().hex() == res["txid"], "reported txid is not the txid of the signed transaction"
    if script in ("p2wpkh", "p2tr"):                         # witness-only types: txid is unchanged by signing
        assert final.txid().hex() == rv["txid"], "signing changed the txid"
    assert extract_tx(psbt_from_text(res["psbt"].to_base64())).serialize().hex() == res["raw"]
    # hardware-wallet style output (what Keystone returns): signature only, NOT finalised
    hw = sign_psbt(psbt_from_text(b64), w, finalize=False)
    assert hw["complete"] and not hw["finalized"]
    for i_ in hw["psbt"].inputs:
        assert not i_.final_scriptwitness and not i_.final_scriptsig, "hardware-wallet mode must not finalise"
        assert i_.partial_sigs or _tap_key_sig(i_), "no signature present"
    again = psbt_from_text(hw["psbt"].to_base64())           # survives serialisation (this is what the QR carries)
    assert extract_tx(again).txid().hex() == hw["txid"]
    if script in ("p2wpkh", "p2tr"):
        assert hw["txid"] == rv["txid"]
    lying = psbt_from_text(b64)
    lying.inputs[0].witness_utxo = TransactionOutput(10**9, watch.spk(0, 1))
    if script != "p2pkh":                                    # legacy inputs carry no witness_utxo to tamper with
        try:
            sign_psbt(lying, w)
            raise AssertionError("fee-attack PSBT was signed")
        except ValueError:
            pass
    thin = psbt_from_text(b64)
    thin.inputs[0].non_witness_utxo = None
    thin.inputs[0].witness_utxo = None if script == "p2pkh" else thin.inputs[0].witness_utxo
    try:
        sign_psbt(thin, w)
        raise AssertionError("PSBT without previous tx was signed")
    except ValueError:
        pass
    return f"{script_label(script):<38} on {net:<17} OK  (fee {rv['fee']} sat)"


def selftest() -> list:
    """Offline checks (no network). Returns status lines; raises AssertionError on failure."""
    out = []
    for script, expected in _VECTORS.items():
        w = Wallet(_ABANDON, "", "Bitcoin Mainnet", script=script)
        assert w.watch.address(0, 0) == expected, f"{script} derivation vector failed: {w.watch.address(0, 0)}"
    assert Wallet(_ABANDON, "", "Bitcoin Mainnet").watch.slip132() == (
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUU"
        "kgDKf31mGDtKsAYz2oz2AGutZYs"), "BIP-84 zpub vector failed"
    out.append("BIP-44/49/84/86 derivation  OK   (Legacy, Nested, Native, Taproot address vectors + zpub)")

    # BIP-340 official vector #0 (secret key 3, zero message, zero aux)
    sig0 = schnorr_sign(3, bytes(32), bytes(32))
    assert sig0.hex().upper() == ("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                                  "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"), "BIP-340 vector failed"
    assert schnorr_verify(_pt_mul(3)[0].to_bytes(32, "big"), bytes(32), sig0)
    out.append("BIP-340 Schnorr             OK   (official test vector)")

    net = "Bitcoin Signet"
    ks = keystore_create(new_mnemonic(), "selftest-password", net)
    w = keystore_open(ks, "selftest-password")
    assert w.watch.address(0, 0) == ks["first_address"]
    try:
        keystore_open(ks, "wrong-password")
        raise AssertionError("wrong password accepted")
    except ValueError:
        pass
    for tamper in (dict(ks, network="Bitcoin Mainnet"), dict(ks, script="p2tr")):
        try:
            keystore_open(tamper, "selftest-password")
            raise AssertionError("tampered keystore accepted")
        except ValueError:
            pass
    out.append("keystore scrypt+AES-GCM   OK   (wrong password / network or address-type tampering rejected)")

    for name in NETWORKS:                                    # every network x every address type validates
        for script in SCRIPTS:
            a = Wallet(_ABANDON, "", name, script=script).watch.address(0, 0)
            address_to_spk(a, name)
    for badaddr in ("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "tb1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "hello"):
        try:
            address_to_spk(badaddr, net)
            raise AssertionError("bad address accepted: " + badaddr)
        except ValueError:
            pass
    reg = Wallet(_ABANDON, "", "Bitcoin Regtest").watch.address(0, 0)
    assert reg.startswith("bcrt1q"), reg
    for other in ("Bitcoin Signet", "Bitcoin Mainnet"):
        try:
            address_to_spk(reg, other)
            raise AssertionError("regtest address accepted on " + other)
        except ValueError:
            pass
    tr = Wallet(_ABANDON, "", "Bitcoin Testnet4", script="p2tr").watch.address(0, 0)
    assert tr.startswith("tb1p"), tr
    out.append("address validation        OK   (5 networks x 4 types; wrong-network / bad-checksum rejected)")

    for script in SCRIPTS:                                   # full pipeline, every type, on a mainnet-free network
        out.append(_selftest_flow(script, net))
    out.append(_selftest_flow("p2tr", "Bitcoin Regtest"))
    out.append(_selftest_flow("p2wpkh", "Bitcoin Regtest"))

    try:
        import cbor2
        import ur
        for kname in ("Bitcoin Mainnet", "Bitcoin Signet"):          # Keystone pairing exports decode back to our keys
            kw = Wallet(_ABANDON, "", kname, script="p2wpkh")
            bun = keystone_bundle(kw)
            fpint = int.from_bytes(kw.fp, "big")
            net_flag = 1 if NETWORKS[kname]["test"] else 0
            # --- OKX: crypto-multi-accounts = ETH standard + 10 Ledger-Live + BTC 44/49/84, like the device ---
            typ, body = keystone_multi_accounts(bun)
            m = cbor2.loads(body)
            assert typ == "crypto-multi-accounts" and m[1] == fpint
            assert m[3] == KS_DEVICE and len(m[4]) == 40 and 5 not in m and len(m[2]) == 11 + 3
            for hd in m[2][11:]:                                                  # the three BTC keys
                f = hd.value
                assert hd.tag == 303 and sorted(f) == [3, 4, 5, 6, 8, 9], sorted(f)
                assert f[9] == KS_KEY_NAME and f[5].tag == 305 and f[5].value == {1: 0, 2: net_flag}
            assert [h.value[6].value[1][0] for h in m[2][11:]] == [44, 49, 84]
            assert m[2][0].value[10] == "account.standard" and m[2][0].value[5].value == {1: 60, 2: net_flag}
            assert all(h.value[10] == "account.ledger_live" and 4 not in h.value for h in m[2][1:11])
            std = bip32.HDKey(ec.PublicKey.parse(m[2][0].value[3]), m[2][0].value[4])
            assert std.derive([0, 3]).get_public_key().sec() == kw.root.derive(f"m/44h/60h/0h/0/3").get_public_key().sec()
            # --- UniSat / BlueWallet / Sparrow: crypto-account, one descriptor per address type ---
            typ, body = keystone_account(bun)
            acc = cbor2.loads(body)
            assert typ == "crypto-account" and acc[1] == fpint and len(acc[2]) == 4
            for script, node in zip(SCRIPTS, acc[2]):
                for tg in _UR_OUTPUT_TAG[script]:
                    assert node.tag == tg, (script, node.tag)
                    node = node.value
                f = node.value
                assert node.tag == 303 and 7 in f and f[9] == KS_KEY_NAME
                comps = f[6].value[1]
                path = "m/" + "/".join(f"{comps[i]}{'h' if comps[i + 1] else ''}" for i in range(0, len(comps), 2))
                sw = Wallet(_ABANDON, "", kname, script=script)
                assert path == default_path(kname, 0, script) and f[6].value[3] == 3 and f[6].value[2] == fpint
                rebuilt = bip32.HDKey(ec.PublicKey.parse(f[3]), f[4])              # what the wallet does with it
                assert spk_for(script, rebuilt.derive([0, 5]).get_public_key()).data == sw.watch.spk(0, 5).data
                assert f[8] == int.from_bytes(sw.watch.key.fingerprint, "big")
            for kind in ("multi", "account"):                                      # animated frames reassemble
                d = ur.URDecoder()
                for fr in keystone_frames(bun, kind):
                    d.add(fr)
                assert d.done and cbor2.loads(d.result()[1])[1] == fpint
        try:
            keystone_account(parse_watch(Wallet(_ABANDON, "", net).watch.slip132(), net))
            raise AssertionError("bare key without fingerprint was exported")
        except ValueError:
            pass
        out.append("Keystone pairing QR        OK   (OKX multi-accounts incl. ETH + UniSat crypto-account with all 4 types, 2 networks)")
        w = Wallet(_ABANDON, "", net)
        watch = w.watch
        t = Transaction(2, [TransactionInput(os.urandom(32), 0)], [TransactionOutput(100_000, watch.spk(0, 0))], 0)
        scan = {"utxos": [{"txid": t.txid().hex(), "vout": 0, "value": 100_000, "confirmed": True, "chain": 0, "index": 0}],
                "next": {0: 1, 1: 0}}
        psbt = build_psbt(watch, scan, Wallet(new_mnemonic(), "", net).watch.address(0, 0), 50_000, 2,
                          get_prev_hex={t.txid().hex(): t.serialize().hex()}.__getitem__)
        text = psbt_ur_frames(psbt, 150)
        d = ur.URDecoder()
        for f in text:
            d.add(f)
        assert d.done
        back = psbt_from_text(ur.ur_encode_single(*d.result()))
        assert back.tx.txid() == psbt.tx.txid()
        out.append(f"ur:crypto-psbt QR codec   OK   ({len(text)} frames)")
    except ImportError:
        out.append("ur:crypto-psbt QR codec   SKIPPED (pip install cbor2; keep ur.py alongside)")
    return out


if __name__ == "__main__":
    for line in selftest():
        print("  " + line)
    print("BTC ENGINE TESTS PASSED ✔")