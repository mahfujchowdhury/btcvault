"""
ur.py — Uniform Resources (BCR-2020-005) codec: bytewords + single/multipart UR encode/decode.

Chain-neutral helper shared by evur.py (Ethereum, EIP-4527) and btcv.py (Bitcoin, ur:crypto-psbt).
Requires: pip install cbor2
"""
import hashlib, struct, zlib
import cbor2

# ------------------------------- bytewords ---------------------------------
_WORDS = ("able acid also apex aqua arch atom aunt away axis back bald barn belt beta bias blue body brag brew "
          "bulb buzz calm cash cats chef city claw code cola cook cost crux curl cusp cyan dark data days deli "
          "dice diet door down draw drop drum dull duty each easy echo edge epic even exam exit eyes fact fair "
          "fern figs film fish fizz flap flew flux foxy free frog fuel fund gala game gear gems gift girl glow "
          "good gray grim guru gush gyro half hang hard hawk heat help high hill holy hope horn huts iced idea "
          "idle inch inky into iris iron item jade jazz join jolt jowl judo jugs jump junk jury keep keno kept "
          "keys kick kiln king kite kiwi knob lamb lava lazy leaf legs liar limp lion list logo loud love luau "
          "luck lung main many math maze memo menu meow mild mint miss monk nail navy need news next noon note "
          "numb obey oboe omit onyx open oval owls paid part peck play plus poem pool pose puff puma purr quad "
          "quiz race ramp real redo rich road rock roof ruby ruin runs rust safe saga scar sets silk skew slot "
          "soap solo song stub surf swan taco task taxi tent tied time tiny toil tomb toys trip tuna twin ugly undo unit "
          "urge user vast very veto vial vibe view visa void vows wall wand warm wasp wave waxy webs what when "
          "whiz wolf work yank yawn yell yoga yurt zaps zero zest zinc zone zoom").split()
assert len(_WORDS) == 256 and _WORDS == sorted(_WORDS), "bytewords table corrupted"
_MINIMAL = [w[0] + w[-1] for w in _WORDS]
assert len(set(_MINIMAL)) == 256, "bytewords minimal table not unique"
_MIN_IDX = {m: i for i, m in enumerate(_MINIMAL)}


def crc32(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF


def bytewords_encode(data: bytes) -> str:
    """Minimal bytewords (2 letters/byte) with CRC32 suffix."""
    d = data + struct.pack(">I", crc32(data))
    return "".join(_MINIMAL[x] for x in d)


def bytewords_decode(s: str) -> bytes:
    s = s.strip().lower()
    if len(s) % 2:
        raise ValueError("bytewords: odd length")
    try:
        d = bytes(_MIN_IDX[s[i:i + 2]] for i in range(0, len(s), 2))
    except KeyError:
        raise ValueError("bytewords: invalid characters")
    if len(d) < 5:
        raise ValueError("bytewords: too short")
    body, chk = d[:-4], struct.unpack(">I", d[-4:])[0]
    if crc32(body) != chk:
        raise ValueError("bytewords: checksum mismatch (bad scan?)")
    return body


# ------------------------------- UR (parts) ---------------------------------
def ur_encode_single(ur_type: str, cbor_bytes: bytes) -> str:
    return f"ur:{ur_type}/{bytewords_encode(cbor_bytes)}"


def ur_encode_frames(ur_type: str, cbor_bytes: bytes, max_fragment=100):
    """Return list of QR strings. One string if it fits, else a looping set of
    pure multipart fragments (seq 1..n) that any UR decoder accepts."""
    if len(cbor_bytes) <= max_fragment:
        return [ur_encode_single(ur_type, cbor_bytes).upper()]
    seq_len = -(-len(cbor_bytes) // max_fragment)
    frag_len = -(-len(cbor_bytes) // seq_len)
    padded = cbor_bytes + b"\x00" * (frag_len * seq_len - len(cbor_bytes))
    chk = crc32(cbor_bytes)
    frames = []
    for i in range(seq_len):
        part = cbor2.dumps([i + 1, seq_len, len(cbor_bytes), chk, padded[i * frag_len:(i + 1) * frag_len]])
        frames.append(f"ur:{ur_type}/{i+1}-{seq_len}/{bytewords_encode(part)}".upper())
    return frames


class _Xoshiro:
    M = (1 << 64) - 1

    def __init__(self, seed32: bytes):
        self.s = [int.from_bytes(seed32[8 * i:8 * i + 8], "big") for i in range(4)]

    @staticmethod
    def _rotl(x, k): return ((x << k) | (x >> (64 - k))) & _Xoshiro.M

    def next(self):
        s, M = self.s, self.M
        r = (self._rotl((s[1] * 5) & M, 7) * 9) & M
        t = (s[1] << 17) & M
        s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t
        s[3] = self._rotl(s[3], 45)
        return r

    def double(self): return self.next() / (self.M + 1)
    def int_(self, lo, hi): return int(self.double() * (hi - lo + 1)) + lo


def _choose_degree(n, rng):
    probs = [1.0 / i for i in range(1, n + 1)]
    tot = sum(probs); probs = [p / tot * n for p in probs]
    small = [i for i in reversed(range(n)) if probs[i] < 1]
    large = [i for i in reversed(range(n)) if probs[i] >= 1]
    P, A = [0.0] * n, [0] * n
    while small and large:
        a = small.pop(); g = large.pop()
        P[a] = probs[a]; A[a] = g
        probs[g] += probs[a] - 1
        (small if probs[g] < 1 else large).append(g)
    for i in large + small: P[i] = 1.0
    r1, r2 = rng.double(), rng.double()
    i = int(n * r1)
    return (i if r2 < P[i] else A[i]) + 1


def _fragments_for(seq, seq_len, chk):
    if seq <= seq_len: return [seq - 1]
    rng = _Xoshiro(hashlib.sha256(struct.pack(">II", seq, chk)).digest())
    degree = _choose_degree(seq_len, rng)
    remaining, out = list(range(seq_len)), []
    while remaining:
        out.append(remaining.pop(rng.int_(0, len(remaining) - 1)))
    return out[:degree]


class URDecoder:
    """Feed scanned strings via add(); check .done / .result() -> (type, cbor_bytes)."""
    def __init__(self):
        self.ur_type = None; self.pure = {}; self.mixed = []; self.meta = None
        self.done = False; self._res = None; self.use_mixed = True

    def progress(self):
        return (len(self.pure), self.meta[0]) if self.meta else (0, 0)

    def add(self, s: str) -> bool:
        s = s.strip().lower()
        if not s.startswith("ur:"): raise ValueError("not a UR string")
        parts = s[3:].split("/")
        t = parts[0]
        if self.ur_type and t != self.ur_type: return False
        self.ur_type = t
        if len(parts) == 2:                                   # single part
            self._res = (t, bytewords_decode(parts[1])); self.done = True; return True
        if len(parts) != 3: raise ValueError("malformed UR")
        seq, n = (int(x) for x in parts[1].split("-"))
        seq_no, seq_len, mlen, chk, data = cbor2.loads(bytewords_decode(parts[2]))
        if (seq_no, seq_len) != (seq, n): raise ValueError("UR header mismatch")
        if self.meta and self.meta[:3] != (seq_len, mlen, chk):
            self.pure.clear(); self.mixed.clear()             # different message: restart
        self.meta = (seq_len, mlen, chk)
        if seq_no <= seq_len:
            self.pure[seq_no - 1] = data
        elif self.use_mixed:
            self.mixed.append((set(_fragments_for(seq_no, seq_len, chk)), data))
        self._try_finish()
        return self.done

    def _assemble(self, pure):
        seq_len, mlen, chk = self.meta
        msg = b"".join(pure[i] for i in range(seq_len))[:mlen]
        return msg if crc32(msg) == chk else None

    def _try_finish(self):
        seq_len = self.meta[0]
        if len(self.pure) == seq_len:
            m = self._assemble(self.pure)
            if m is not None: self._res = (self.ur_type, m); self.done = True; return
        if self.mixed:                                        # fountain reduction
            known = dict(self.pure); changed = True
            while changed and len(known) < seq_len:
                changed = False
                for idxs, data in self.mixed:
                    unk = [i for i in idxs if i not in known]
                    if len(unk) == 1:
                        v = bytearray(data)
                        for i in idxs:
                            if i in known:
                                v = bytearray(a ^ b for a, b in zip(v, known[i]))
                        known[unk[0]] = bytes(v); changed = True
            if len(known) == seq_len:
                m = self._assemble(known)
                if m is not None: self._res = (self.ur_type, m); self.done = True
                else: self.use_mixed = False; self.mixed.clear()   # bad mixed data: rely on pure parts

    def result(self): return self._res