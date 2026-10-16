#!/usr/bin/env python3

"""
for any one reading this, do install: cryptography, websockets, argon2-cffi
"""
import sys, os
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass
import sys, os, re, time, json, base64, hashlib, secrets, random, asyncio, argparse, socket, heapq
from datetime import datetime
from collections import deque
import websockets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import threading
try:
    from pqc_crypto import pqc_keygen, pqc_sign, pqc_verify, PQC_PUB_SIZE, PQC_PRIV_SIZE, PQC_SIG_SIZE
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
_passphrase_cache = None

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(secret=passphrase.encode("utf-8"), salt=salt,
                           time_cost=3, memory_cost=65536, parallelism=4,
                           hash_len=32, type=Type.ID)

def encrypt_secret(plaintext: str, passphrase: str) -> dict:
    salt = secrets.token_bytes(16)
    key = _derive_key(passphrase, salt)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return {"salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode()}

def decrypt_secret(enc: dict, passphrase: str) -> str:
    salt = base64.b64decode(enc["salt"])
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ct"])
    key = _derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")

def _get_passphrase(confirm=False):
    global _passphrase_cache
    if not confirm and _passphrase_cache is not None:
        return _passphrase_cache
    import getpass
    p = getpass.getpass("  Passphrase: ")
    if confirm:
        p2 = getpass.getpass("  Confirm passphrase: ")
        if p != p2:
            print(f"{RED}  Passphrases don't match{RST}")
            return None
    _passphrase_cache = p
    return p
def _encrypt_settings_keys(settings: dict, passphrase: str) -> dict:
    out = dict(settings)
    for field in ("privkey",):
        val = out.get(field, "")
        if val and not isinstance(val, dict):
            out[field] = encrypt_secret(val, passphrase)
    raw_keys = out.get("maze_keys", [])
    enc_keys = []
    for k in raw_keys:
        priv = k.get("priv", "") if isinstance(k, dict) else ""
        pub = k.get("pub", "") if isinstance(k, dict) else ""
        if priv:
            enc_keys.append({"priv": encrypt_secret(priv, passphrase), "pub": pub})
        else:
            enc_keys.append(k)
    out["maze_keys"] = enc_keys
    pqc_priv = out.get("pqc_priv", "")
    if pqc_priv and not isinstance(pqc_priv, dict):
        out["pqc_priv"] = encrypt_secret(pqc_priv, passphrase)
    out["_encrypted"] = True
    return out

def _decrypt_settings_keys(settings: dict, passphrase: str) -> dict:
    out = dict(settings)
    if not out.get("_encrypted"):
        return out
    try:
        for field in ("privkey",):
            val = out.get(field, "")
            if isinstance(val, dict) and "ct" in val:
                out[field] = decrypt_secret(val, passphrase)
        raw_keys = out.get("maze_keys", [])
        dec_keys = []
        for k in raw_keys:
            if isinstance(k, dict) and isinstance(k.get("priv"), dict) and "ct" in k["priv"]:
                dec_keys.append({"priv": decrypt_secret(k["priv"], passphrase), "pub": k.get("pub", "")})
            else:
                dec_keys.append(k)
        out["maze_keys"] = dec_keys
        pqc_priv = out.get("pqc_priv", "")
        if isinstance(pqc_priv, dict) and "ct" in pqc_priv:
            out["pqc_priv"] = decrypt_secret(pqc_priv, passphrase)
    except Exception:
        print(f"{RED}  Wrong passphrase or corrupted keys{RST}")
        return None
    return out

RST = "\033[0m"
BLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GRN = "\033[32m"
YLW = "\033[33m"
BLU = "\033[34m"
MAG = "\033[35m"
CYN = "\033[36m"
WHT = "\033[37m"
BG_R = "\033[41m"
BG_G = "\033[42m"
BG_B = "\033[44m"
BG_M = "\033[45m"
BG_Y = "\033[43m"

def _c(col, txt):
    return f"{col}{txt}{RST}"

BANNER = f"""{_c(MAG, '  ███╗   ███╗██╗   ██╗███╗   ██╗███████╗██╗  ██╗')}{_c(CYN, '     ███╗   ███╗██╗███╗   ██╗███████╗██████╗ ')}
{_c(MAG, '  ████╗ ████║██║   ██║████╗  ██║██╔════╝╚██╗██╔╝')}{_c(CYN, '     ████╗ ████║██║████╗  ██║██╔════╝██╔══██╗')}
{_c(MAG, '  ██╔████╔██║██║   ██║██╔██╗ ██║█████╗   ╚███╔╝ ')}{_c(CYN, '     ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝')}
{_c(MAG, '  ██║╚██╔╝██║██║   ██║██║╚██╗██║██╔══╝   ██╔██╗ ')}{_c(CYN, '     ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗')}
{_c(MAG, '  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║███████╗██╔╝ ██╗')}{_c(CYN, '     ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║')}
{_c(MAG, '  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝')}{_c(CYN, '     ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝')}
{_c(GRN, '  ───  PC Miner · PoG MOVEV1 · PQC ML-DSA-65  ───')}
{_c(DIM, '  Official release — A* + DQN pathfinding · signed nonce moves')}
"""

def _ts():
    return datetime.now().strftime(f"{DIM}%H:%M:%S{RST}")

def safe_int(val, default=0):
    try:
        return int(val)
    except (TypeError, ValueError):
        return default

def log(msg, state="info", tag="sys0"):
    if tag.startswith("net"):
        bg = BG_B
    elif tag.startswith("cpu"):
        bg = BG_Y
    elif tag.startswith("pog"):
        bg = BG_M
    else:
        bg = BG_G
    fg = {"success": GRN, "info": BLU, "error": RED, "warning": YLW}.get(state, WHT)
    print(f"{_ts()} {BLD}{bg} {tag} {RST}{fg}{msg.strip()}{RST}", flush=True)

def move_log(miner_id, accepted, total, pos, movenonce, computetime, ping, balance, share_type="accept", method=""):
    tag = miner_id[-8:]
    if share_type == "accept":
        fg, bg, sym = GRN, BG_G, "accepted"
    elif share_type == "wall":
        fg, bg, sym = YLW, BG_Y, "wall hit"
    elif share_type == "goal":
        fg, bg, sym = CYN, BG_G, " goal!  "
    elif share_type == "ghost":
        fg, bg, sym = RED, BG_R, " ghost! "
    else:
        fg, bg, sym = RED, BG_R, "rejected"

    pos_str = f"({pos[0]}, {pos[1]}, {pos[2]})" if pos else "(0, 0, 0)"
    sr = (accepted / total * 100) if total > 0 else 0
    bal_str = f"{balance/1_000_000:,.1f} MCX"
    pace_str = f"{computetime:.1f}s ∙ {ping:.0f}ms"

    print(f"{_ts()}  {BLD}{bg} {tag} {RST}  {fg}{BLD}{sym:<8}{RST}  {accepted:>2}/{total:<2} {_c(YLW, f'({sr:.0f}%)')}  {_c(WHT+BLD, f'{pos_str:<12}')}  {_c(CYN, f'nonce:{movenonce:<4}')}  {_c(DIM, pace_str):<16}  {_c(BLU+BLD, bal_str)}", flush=True)

def format_5min_status_box(miner_id, uptime_sec, blocks_mined, mcx_earned_subs, balance_subs, goals_reached, moves_acc, moves_att, walls_solved, maze_size, growthcount, diff, block_id, ping_ms):
    hrs = int(uptime_sec // 3600)
    mins = int((uptime_sec % 3600) // 60)
    secs = int(uptime_sec % 60)
    uptime_str = f"{hrs}h {mins:02d}m {secs:02d}s"

    sr = (moves_acc / moves_att * 100) if moves_att > 0 else 100.0
    earned_mcx = mcx_earned_subs / 1_000_000
    bal_mcx = balance_subs / 1_000_000

    def pad_line(label, val_str, total_width=63):
        raw_len = len(label) + len(val_str)
        spaces = max(1, total_width - raw_len)
        return f"{label}{' ' * spaces}{val_str}"

    l1 = pad_line("  ● Miner ID:", miner_id)
    l2 = pad_line("  ● Active Uptime:", f"{uptime_str} (Session active)")
    l3 = pad_line("  ● Blocks Mined:", f"{blocks_mined} blocks won")
    l4 = pad_line("  ● MCX Earned:", f"+{earned_mcx:,.6f} MCX ({mcx_earned_subs:,} subs)")
    l5 = pad_line("  ● Current Balance:", f"{bal_mcx:,.6f} MCX ({balance_subs:,} subs)")
    l6 = pad_line("  ● Mazes Completed:", f"{goals_reached} goals reached")
    l7 = pad_line("  ● Move Shares:", f"{moves_acc:,}/{moves_att:,} ({sr:.1f}% efficiency)")
    l8 = pad_line("  ● PoW Wall Solves:", f"{walls_solved} solutions verified")
    l9 = pad_line("  ● Current State:", f"{maze_size}x{maze_size}x{maze_size} (gc={growthcount}) | Diff: {diff:.1f} | #{block_id}")

    return f"""
{_c(CYN+BLD, '  ╔═════════════════════════════════════════════════════════════════╗')}
{_c(CYN+BLD, '  ║')}            {_c(BG_M+BLD+WHT, ' ★ MCX MINER 5-MINUTE STATUS REPORT ★ ')}            {_c(CYN+BLD, '║')}
{_c(CYN+BLD, '  ╠═════════════════════════════════════════════════════════════════╣')}
{_c(CYN+BLD, '  ║')} {_c(WHT+BLD, l1)} {_c(CYN+BLD, '║')}
{_c(CYN+BLD, '  ║')} {_c(CYN+BLD, l2)} {_c(CYN+BLD, '║')}
{_c(CYN+BLD, '  ║')} {_c(GRN+BLD, l3)} {_c(CYN+BLD, '║')}
{_c(CYN+BLD, '  ║')} {_c(GRN+BLD, l4)} {_c(CYN+BLD, '║')}
{_c(CYN+BLD, '  ║')} {_c(YLW+BLD, l5)} {_c(CYN+BLD, '║')}
{_c(CYN+BLD, '  ║')} {_c(MAG+BLD, l6)} {_c(CYN+BLD, '║')}
{_c(CYN+BLD, '  ║')} {_c(WHT+BLD, l7)} {_c(CYN+BLD, '║')}
{_c(CYN+BLD, '  ║')} {_c(WHT, l8)} {_c(CYN+BLD, '║')}
{_c(CYN+BLD, '  ║')} {_c(DIM, l9)} {_c(CYN+BLD, '║')}
{_c(CYN+BLD, '  ╚═════════════════════════════════════════════════════════════════╝')}
"""

def status_report(miner_id, uptime, steps, accepted, total, balance, size, ghost):
    tag = miner_id[-8:]
    sr = (accepted / total * 100) if total > 0 else 0
    mins = int(uptime // 60)
    secs = int(uptime % 60)
    g_pos = f"({ghost[0]},{ghost[1]},{ghost[2]})" if ghost else "none"
    print(f"{_ts()} {BLD}{BG_B} {tag} {RST}{BLD} STATUS{RST}"
          f" \u2219 {_c(CYN, f'{mins}m {secs}s')} uptime"
          f" \u2219 {steps} steps"
          f" \u2219 {accepted}/{total} ({sr:.0f}%)"
          f" \u2219 {_c(MAG, f'{size}\u00b3')}"
          f" \u2219 ghost:{_c(RED, g_pos)}"
          f" \u2219 {_c(BLU, f'{balance/1_000_000:.1f} MCX')}",
          flush=True)

def title(t):
    if os.name == 'nt':
        os.system('title ' + t)
    else:
        try:
            print('\33]0;' + t + '\a', end='')
            sys.stdout.flush()
        except Exception:
            pass

SETTINGS_FILE = "miner_settings.json"
MINER_PEERS_FILE = "miner_peers.json"
PEER_FAILURE_LIMIT = 5
PEER_CACHE_MAX = 200

DEFAULT_SETTINGS = {
    "wallet": "",
    "privkey": "",
    "maze_keys": [],
    "pqc_pub": "",
    "pqc_priv": "",
    "model_format": "json",
    "node_url": "",
    "dns_seeds": ["munexseed1.duckdns.org"],
    "bootstrap_nodes": [
        "ws://munexseed1.duckdns.org:8080/ws",
    ],
    "fallback_node": "ws://munexseed1.duckdns.org:8080/ws",
    "ws_path": "/ws",
    "ws_port": 8080,
    "move_timeout": 15.0,
    "heartbeat_interval": 5,
    "max_reconnect": 5,
    "state_sync_cooldown": 2.0,
    "pow_difficulty": 16,
    "balance_fetch_interval": 30,
    "idle_timeout": 600,
    "chain_id": 6620,
    "stuck_threshold": 12,
    "core_suffix": "genius",
    "cpu_percent": 50,
}

DNS_SEEDS = ["munexseed1.duckdns.org"]
FALLBACK_NODE = "ws://munexseed1.duckdns.org:8080/ws"
WS_PATH = "/ws"
WS_DEFAULT_PORT = 8080

DIR_NAMES = ["east", "west", "north", "south", "up", "down"]
DIR_OFFSETS = [(1,0,0), (-1,0,0), (0,1,0), (0,-1,0), (0,0,1), (0,0,-1)]
DIR_OFFSET_TO_IDX = {off: i for i, off in enumerate(DIR_OFFSETS)}

MOVE_TIMEOUT = 15.0
HEARTBEAT_INTERVAL = 5
MAX_RECONNECT = 5
STATE_SYNC_COOLDOWN = 2.0
POW_DIFFICULTY = 16
BALANCE_FETCH_INTERVAL = 30
IDLE_TIMEOUT = 600
CHAIN_ID = 6620
STUCK_THRESHOLD = 12
# MINER-PACE-1: adaptive move pacing. The node's mining WS path allows 1200
# requests / 60 s per miner (maze_move + wall_hit_solve share the budget);
# an unpaced loop sends at RTT speed and trips it, and each 429 lands in the
# generic rejection branch and triggers a resync storm that burns MORE
# budget. Pace every maze_move with a delay that adapts to game urgency
# (goal/ghost closeness), to the real per-iteration request cost (a wall hit
# costs ~2 requests: move + solve), and to observed rejections (AIMD
# backoff), plus a rolling client-side budget guard with margin under the
# server limit. Rejected moves count: they consumed a send (window) and bump
# the backoff (mild for gameplay rejects, double for 429s).
PACE_BASE_DELAY = 0.07
PACE_MIN_DELAY = 0.06
PACE_MAX_DELAY = 0.6
PACE_BUDGET = 1000
PACE_WINDOW_S = 60.0
PACE_BACKOFF_MAX = 8.0
PACE_TARGET_RPS = 14.0
PACE_WALL_WINDOW = 20

def canonical_json_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

def sign_bytes(priv_hex, message):
    ec_key = ec.derive_private_key(int(priv_hex, 16), ec.SECP256K1())
    sig = ec_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig)
    # MOVE-SIG-LOW-S: the node rejects high-s signatures (BIP-62) on every
    # path (moves, blocks, registration) — normalize here so ~50% of
    # signatures are not DOA. Same normalization as sign_message below and
    # the node's own sign_bytes.
    SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
    return f"{r:064x}{s:064x}"

def sign_message(priv_hex, msg):
    priv_key = ec.derive_private_key(int(priv_hex, 16), ec.SECP256K1())
    sig = priv_key.sign(msg.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig)
    SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()

def pubkey_from_priv(priv_hex):
    priv_key = ec.derive_private_key(int(priv_hex, 16), ec.SECP256K1())
    pub = priv_key.public_key()
    x = pub.public_numbers().x.to_bytes(32, "big")
    y = pub.public_numbers().y.to_bytes(32, "big")
    return (b"\x04" + x + y).hex()

def _keccak256(data: bytes) -> bytes:
    """Keccak-256 (Ethereum-style), NOT SHA3-256."""
    try:
        from eth_utils import keccak as eth_keccak
        return eth_keccak(data)
    except ImportError:
        pass
    try:
        from Crypto.Hash import keccak as _k
        h = _k.new(digest_bits=256)
        h.update(data)
        return h.digest()
    except ImportError:
        raise ImportError("Install eth_utils or pycryptodome for Keccak-256")

def pubkey_to_address(pub_hex: str) -> str:
    pub_hex = pub_hex.removeprefix("0x")
    if pub_hex.startswith("04"):
        pub_bytes = bytes.fromhex(pub_hex)
        return "0x" + _keccak256(pub_bytes[1:])[-20:].hex()
    return "0x" + pub_hex

def generate_keypair():
    priv = ec.generate_private_key(ec.SECP256K1())
    priv_int = priv.private_numbers().private_value
    priv_hex = priv_int.to_bytes(32, "big").hex()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(serialization.Encoding.X962,
                                 serialization.PublicFormat.UncompressedPoint)
    addr = "0x" + _keccak256(pub_bytes[1:])[-20:].hex()
    pqc_pub, pqc_priv = b"", b""
    if PQC_AVAILABLE:
        pqc_pub, pqc_priv = pqc_keygen()
    return addr, priv_hex, pub_bytes.hex(), pqc_pub.hex(), pqc_priv.hex()

def generate_maze_key():
    priv = ec.generate_private_key(ec.SECP256K1())
    priv_hex = priv.private_numbers().private_value.to_bytes(32, "big").hex()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(serialization.Encoding.X962,
                                 serialization.PublicFormat.UncompressedPoint)
    return priv_hex, pub_bytes.hex()

def _pubkey_from_privkey(priv_hex: str) -> str:
    pk = ec.derive_private_key(int(priv_hex, 16), ec.SECP256K1())
    pub_bytes = pk.public_key().public_bytes(serialization.Encoding.X962,
                                             serialization.PublicFormat.UncompressedPoint)
    return pub_bytes.hex()
def _norm_maze_key(k):
    if isinstance(k, dict):
        priv, pub = k.get("priv", ""), k.get("pub", "")
    elif isinstance(k, (list, tuple)) and len(k) == 2:
        priv, pub = k[0], k[1]
    else:
        return None
    priv, pub = str(priv).strip(), str(pub).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", priv):
        return None
    try:
        derived = pubkey_from_priv(priv)
    except Exception:
        return None
    if pub.lower() not in (derived.lower(), ""):
        return None
    return priv, derived

def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return dict(DEFAULT_SETTINGS)
    with open(SETTINGS_FILE, "r") as f:
        data = json.load(f)
    settings = dict(DEFAULT_SETTINGS)
    settings.update(data)
    return settings
def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)
    try:
        os.chmod(SETTINGS_FILE, 0o600)
    except Exception:
        pass

def load_wallet():
    settings = load_settings()
    if settings.get("_encrypted"):
        passphrase = _get_passphrase()
        if not passphrase:
            print(f"{RED}  No passphrase provided{RST}")
            raise SystemExit(1)
        settings = _decrypt_settings_keys(settings, passphrase)
        if settings is None:
            print(f"{RED}  Wrong passphrase — refusing to continue (your wallet is NOT overwritten){RST}")
            raise SystemExit(1)
    raw = settings.get("maze_keys", [])
    if not raw and settings.get("mazepriv") and settings.get("mazepub"):
        raw = [[settings["mazepriv"], settings["mazepub"]]]
    maze_keys = []
    for k in raw:
        ok = _norm_maze_key(k)
        if ok:
            maze_keys.append({"priv": ok[0], "pub": ok[1]})
    return settings.get("wallet") or "", settings.get("privkey") or "", maze_keys
def load_wallet_full():
    settings = load_settings()
    if settings.get("_encrypted"):
        passphrase = _get_passphrase()
        if not passphrase:
            print(f"{RED}  No passphrase provided{RST}")
            raise SystemExit(1)
        settings = _decrypt_settings_keys(settings, passphrase)
        if settings is None:
            print(f"{RED}  Wrong passphrase — refusing to continue{RST}")
            raise SystemExit(1)
    raw = settings.get("maze_keys", [])
    if not raw and settings.get("mazepriv") and settings.get("mazepub"):
        raw = [[settings["mazepriv"], settings["mazepub"]]]
    maze_keys = []
    for k in raw:
        ok = _norm_maze_key(k)
        if ok:
            maze_keys.append({"priv": ok[0], "pub": ok[1]})
    pqc_pub = bytes.fromhex(settings.get("pqc_pub", "")) if settings.get("pqc_pub") else b""
    pqc_priv = bytes.fromhex(settings.get("pqc_priv", "")) if settings.get("pqc_priv") else b""
    return settings.get("wallet") or "", settings.get("privkey") or "", maze_keys, pqc_pub, pqc_priv

def save_wallet(addr, priv, maze_keys=None, pqc_pub=b"", pqc_priv=b""):
    settings = load_settings()
    keys = []
    seen = set()
    for k in (maze_keys or []):
        ok = _norm_maze_key(k)
        if not ok or ok[0] in seen:
            continue
        seen.add(ok[0])
        keys.append({"priv": ok[0], "pub": ok[1]})
    settings["wallet"] = addr
    settings["privkey"] = priv
    settings["maze_keys"] = keys
    if pqc_pub and pqc_priv:
        settings["pqc_pub"] = pqc_pub.hex() if isinstance(pqc_pub, bytes) else pqc_pub
        settings["pqc_priv"] = pqc_priv.hex() if isinstance(pqc_priv, bytes) else pqc_priv
    passphrase = _get_passphrase(confirm=True)
    if passphrase:
        settings = _encrypt_settings_keys(settings, passphrase)
    save_settings(settings)

def new_maze_key(maze_keys):
    mp, mz = generate_maze_key()
    maze_keys.append({"priv": mp, "pub": mz})
    _persist_maze_keys(maze_keys)
    return mp, mz

def _persist_maze_keys(maze_keys: list) -> None:
    """Write maze_keys to disk without touching privkey/pqc_priv. If the
    on-disk file has an encrypted privkey, preserve the encrypted blob even
    if the in-memory settings object holds a plaintext copy."""
    disk = load_settings()
    disk["maze_keys"] = maze_keys
    save_settings(disk)


def choose_maze_key(maze_keys):
    print(f"\n{_c(CYN, 'Maze key selection')}{RST}")
    print(f"  You have {len(maze_keys)} maze key(s) in {SETTINGS_FILE}."
          f" Each owns ONE maze cube + progress on the node.\n")
    for i, k in enumerate(maze_keys):
        print(f"  #{i+1}: {k['pub'][:20]}... (priv {k['priv'][:8]}...)")
    print(f"\n  N: create a NEW maze key")
    print(f"  E: enter an existing maze private key hex")
    try:
        choice = input(f"\n{_c(CYN, 'Choose maze key [#, N, or E]: ')}{RST}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        choice = ""

    # Default: reuse the first existing key. Only make a new one if the user
    # explicitly asked (choice == "n"), or if there are no keys at all.
    if not choice:
        if maze_keys:
            return maze_keys[0]["priv"], maze_keys[0]["pub"]
        choice = "n"

    if choice == "n":
        return new_maze_key(maze_keys)

    if choice == "e":
        try:
            mp = input(f"{_c(CYN, 'Maze private key hex: ')}{RST}").strip()
        except (EOFError, KeyboardInterrupt):
            mp = ""
        if mp.startswith(("0x", "0X")):
            mp = mp[2:]
        if not re.fullmatch(r"[0-9a-fA-F]{64}", mp):
            print(f"{_c(RED, 'Not a valid 32-byte hex key.')}{RST}")
            if maze_keys:
                print(f"{_c(YLW, 'Reusing first existing maze key.')}{RST}")
                return maze_keys[0]["priv"], maze_keys[0]["pub"]
            return new_maze_key(maze_keys)
        mz = pubkey_from_priv(mp)
        for k in maze_keys:
            if k["priv"] == mp:
                return mp, mz
        maze_keys.append({"priv": mp, "pub": mz})
        _persist_maze_keys(maze_keys)
        print(f"{_c(GRN, 'Maze key added:')} {mz[:20]}...{RST}")
        return mp, mz

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(maze_keys):
            return maze_keys[idx]["priv"], maze_keys[idx]["pub"]
    except (ValueError, TypeError):
        pass

    if maze_keys:
        print(f"{_c(YLW, 'Unrecognized choice; reusing first existing maze key.')}{RST}")
        return maze_keys[0]["priv"], maze_keys[0]["pub"]
    return new_maze_key(maze_keys)

def resolve_dns(domain, port=WS_DEFAULT_PORT):
    urls = []
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        for ip in ips:
            urls.append(f"ws://{ip}:{port}{WS_PATH}")
    except Exception:
        pass
    return urls

async def discover_nodes(settings: dict) -> list:
    """Return a list of candidate WS URLs to try, ordered:
       1. the user-pinned node_url (if any)
       2. hardcoded bootstrap_nodes from settings
       3. cached peers from miner_peers.json (freshest first, dead ones skipped)
       4. DNS seeds as a last resort
    The pinned head stays at position 0; the rest are shuffled so repeated
    attempts don't hammer the same dead URL forever."""
    candidates, seen = [], set()
    def add(u):
        if u and u not in seen:
            seen.add(u); candidates.append(u)

    add(settings.get("node_url"))

    for u in (settings.get("bootstrap_nodes") or []):
        add(u)
    if not candidates:
        add(FALLBACK_NODE)

    for url, meta in sorted(_load_miner_peers().items(),
                            key=lambda kv: kv[1].get("last_seen", 0), reverse=True):
        if int(meta.get("failures", 0)) >= PEER_FAILURE_LIMIT:
            continue
        add(url)

    for seed in settings.get("dns_seeds", DNS_SEEDS):
        host = seed.split("://")[-1].split(":")[0].split("/")[0]
        for u in resolve_dns(host, int(settings.get("ws_port", WS_DEFAULT_PORT))):
            add(u)

    if len(candidates) > 1:
        head, tail = candidates[:1], candidates[1:]
        random.shuffle(tail)
        candidates = head + tail
    return candidates


def _load_miner_peers() -> dict:
    """Read miner_peers.json. Returns {} on missing/corrupt file."""
    try:
        with open(MINER_PEERS_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save_miner_peers(peers: dict) -> None:
    """Atomically write the peer cache, keeping only the PEER_CACHE_MAX most
    recently seen entries."""
    items = sorted(peers.items(), key=lambda kv: kv[1].get("last_seen", 0), reverse=True)
    pruned = dict(items[:PEER_CACHE_MAX])
    tmp = MINER_PEERS_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(pruned, f, indent=2)
        os.replace(tmp, MINER_PEERS_FILE)
    except OSError as e:
        log(f"miner_peers save failed: {e}", "warning", "net0")


def _record_peer_ok(url: str, node_id: str = "") -> None:
    """Mark a URL as recently reachable and reset its failure count."""
    peers = _load_miner_peers()
    e = peers.get(url) or {}
    e["last_seen"] = time.time()
    e["failures"] = 0
    if node_id:
        e["node_id"] = node_id
    peers[url] = e
    _save_miner_peers(peers)


def _record_peer_fail(url: str) -> None:
    """Increment a URL's failure count without touching last_seen."""
    peers = _load_miner_peers()
    e = peers.get(url) or {}
    e.setdefault("last_seen", 0)
    e["failures"] = int(e.get("failures", 0)) + 1
    peers[url] = e
    _save_miner_peers(peers)


def a_star(maze, start, goal, known_walls=None, ghost=None, max_nodes=10000, forbidden=None):
    size = len(maze)
    if known_walls is None:
        known_walls = set()
    if start == goal:
        return []
    if not (0 <= start[0] < size and 0 <= start[1] < size and 0 <= start[2] < size):
        return None
    if not (0 <= goal[0] < size and 0 <= goal[1] < size and 0 <= goal[2] < size):
        return None
    if maze[start[2]][start[1]][start[0]] == 1 or maze[goal[2]][goal[1]][goal[0]] == 1:
        return None
    gx, gy, gz = goal
    # heap holds (f, g, pos)
    open_set = [(0, 0, start)]
    came_from = {}
    g_score = {start: 0}
    visited_count = 0
    ghost_t = tuple(ghost) if ghost else None

    while open_set and visited_count < max_nodes:
        _, cur_g, cur = heapq.heappop(open_set)
        visited_count += 1
        if cur == goal:
            path = []
            while cur in came_from:
                path.append(cur)
                cur = came_from[cur]
            path.reverse()
            return path

        cx, cy, cz = cur
        for dx, dy, dz in DIR_OFFSETS:
            nx, ny, nz = cx+dx, cy+dy, cz+dz
            if not (0 <= nx < size and 0 <= ny < size and 0 <= nz < size):
                continue
            if maze[nz][ny][nx] == 1 or (nx, ny, nz) in known_walls:
                continue

            nxt = (nx, ny, nz)
            step_cost = 1
            if forbidden and nxt in forbidden:
                step_cost += 30          # CPU-TARGET-3: soft-avoid (deep planner)
            if ghost_t:
                gd = abs(nx - ghost_t[0]) + abs(ny - ghost_t[1]) + abs(nz - ghost_t[2])
                if gd == 0:
                    step_cost += 100
                elif gd == 1:
                    step_cost += 20
                elif gd == 2:
                    step_cost += 5

            tentative = cur_g + step_cost
            if tentative < g_score.get(nxt, float('inf')):
                came_from[nxt] = cur
                g_score[nxt] = tentative
                h = abs(nx-gx) + abs(ny-gy) + abs(nz-gz)
                heapq.heappush(open_set, (tentative + h, tentative, nxt))
    return None

def bfs_explore(maze, start, goal, known_walls=None, ghost=None, max_steps=5000):
    size = len(maze)
    if known_walls is None:
        known_walls = set()
    if not (0 <= start[0] < size and 0 <= start[1] < size and 0 <= start[2] < size):
        return None
    if not (0 <= goal[0] < size and 0 <= goal[1] < size and 0 <= goal[2] < size):
        return None
    if maze[start[2]][start[1]][start[0]] == 1 or maze[goal[2]][goal[1]][goal[0]] == 1:
        return None

    queue = deque([start])
    came_from = {}
    visited = {start}
    steps = 0
    best_cell = None
    best_dist = 999999

    while queue and steps < max_steps:
        cur = queue.popleft()
        cx, cy, cz = cur
        steps += 1
        d_goal = abs(cx - goal[0]) + abs(cy - goal[1]) + abs(cz - goal[2])
        if d_goal < best_dist and cur != start:
            best_dist = d_goal
            best_cell = cur

        if cur == goal:
            path = []
            while cur in came_from:
                path.append(cur)
                cur = came_from[cur]
            path.reverse()
            return path

        for dx, dy, dz in DIR_OFFSETS:
            nx, ny, nz = cx+dx, cy+dy, cz+dz
            if not (0 <= nx < size and 0 <= ny < size and 0 <= nz < size):
                continue
            if maze[nz][ny][nx] == 1 or (nx, ny, nz) in known_walls:
                continue
            nxt = (nx, ny, nz)
            if nxt not in visited:
                visited.add(nxt)
                came_from[nxt] = cur
                queue.append(nxt)

    if best_cell and best_cell in came_from:
        path = []
        cur = best_cell
        while cur in came_from:
            path.append(cur)
            cur = came_from[cur]
        path.reverse()
        return path
    return None

def bfs_distance(maze, start, target, known_walls=None, max_steps=100):
    size = len(maze)
    if known_walls is None:
        known_walls = set()
    if start == target:
        return 0
    if not (0 <= start[0] < size and 0 <= start[1] < size and 0 <= start[2] < size):
        return 9999
    if not (0 <= target[0] < size and 0 <= target[1] < size and 0 <= target[2] < size):
        return 9999
    queue = deque([(start, 0)])
    visited = {start}
    while queue:
        cur, dist = queue.popleft()
        if dist >= max_steps:
            continue
        cx, cy, cz = cur
        for dx, dy, dz in DIR_OFFSETS:
            nx, ny, nz = cx+dx, cy+dy, cz+dz
            if not (0 <= nx < size and 0 <= ny < size and 0 <= nz < size):
                continue
            if maze[nz][ny][nx] == 1 or (nx, ny, nz) in known_walls:
                continue
            nxt = (nx, ny, nz)
            if nxt == target:
                return dist + 1
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt, dist + 1))
    return 9999

def random_valid_move(maze, pos, known_walls=None, forbidden_positions=None):
    size = len(maze)
    if known_walls is None:
        known_walls = set()
    if forbidden_positions is None:
        forbidden_positions = set()
    x, y, z = pos
    candidates = []
    fallback_candidates = []
    for idx, (dx, dy, dz) in enumerate(DIR_OFFSETS):
        nx, ny, nz = x+dx, y+dy, z+dz
        if 0 <= nx < size and 0 <= ny < size and 0 <= nz < size:
            if maze[nz][ny][nx] == 0 and (nx, ny, nz) not in known_walls:
                fallback_candidates.append(idx)
                if (nx, ny, nz) not in forbidden_positions:
                    candidates.append(idx)
    if candidates:
        return random.choice(candidates)
    if fallback_candidates:
        return random.choice(fallback_candidates)
    return -1

def solve_pow(seed, difficulty):
    nonce = 0
    while True:
        data = f"{seed}{nonce}".encode()
        digest = hashlib.sha256(data).digest()
        if int.from_bytes(digest, 'big') >> (256 - difficulty) == 0:
            return nonce
        nonce += 1


def _clamp_cpu_percent(v, default=50) -> int:
    """Parse a CPU target out of 100. Garbage/None -> default; clamps 1..100."""
    try:
        n = int(str(v).strip().rstrip("%"))
    except (TypeError, ValueError, AttributeError):
        return default
    return min(100, max(1, n))


def _pow_worker_count(intensity: float, max_workers: int) -> int:
    """Map governor intensity [0,1] to PoW solver threads [1,max_workers]."""
    try:
        f = min(max(float(intensity), 0.0), 1.0)
    except (TypeError, ValueError):
        f = 0.0
    try:
        m = max(1, int(max_workers))
    except (TypeError, ValueError):
        m = 1
    return 1 + round(f * (m - 1))


def _cpu_sample(extra: float = 0.0):
    """One CPU snapshot: (process user+sys seconds [+ `extra` = worker-process
    CPU seconds, CPU-TARGET-3], wall seconds). Never raises."""
    try:
        t = os.times()
        return (float(t[0]) + float(t[1]) + float(extra or 0.0), time.time())
    except Exception:
        return (0.0, time.time())


def _cpu_pct(prev, cur, ncpu: int):
    """Process CPU% between two _cpu_sample() snapshots, normalized by core
    count. prev is None on the first call (no baseline yet) -> None. Pure;
    unit-testable."""
    try:
        if prev is None or cur is None:
            return None
        dproc = float(cur[0]) - float(prev[0])
        dwall = float(cur[1]) - float(prev[1])
        if dwall <= 1e-6:
            return 0.0
        n = max(1, int(ncpu or 1))
        return max(0.0, dproc / dwall / n * 100.0)
    except (TypeError, ValueError, IndexError):
        return None


def _reconcile_block_submission(pending, upd_block_id, balance_now):
    """Confirm a submitted block against node truth (pure; unit-testable).

    pending: None or dict(id, reward, balance_at_submit). upd_block_id: the
    block id from a node block_height_update. balance_now: our latest
    node-reported balance (None when unknown).
    Returns (confirmed, reason) with confirmed True/False/None:
      None + "none-pending"  — nothing submitted.
      None + "waiting"       — chain has not advanced past the submission.
      None + "unknown"       — advanced, but no balance to judge by yet.
      True + "confirmed"     — chain advanced AND balance grew by >= reward
        (minus _CONFIRM_FEE_TOLERANCE for interim move fees).
      False + "unconfirmed"  — chain advanced past it with no such credit
        (rejected or orphaned submission; never counted).
    """
    if not pending:
        return None, "none-pending"
    try:
        bid = int(upd_block_id)
        pid = int(pending.get("id", -1))
    except (TypeError, ValueError):
        return None, "bad-update"
    if bid < pid:
        return None, "waiting"
    if balance_now is None:
        return None, "unknown"
    try:
        bal = int(balance_now)
        base = int(pending.get("balance_at_submit", 0) or 0)
        rew = int(pending.get("reward", 0) or 0)
    except (TypeError, ValueError):
        return None, "unknown"
    if bal >= base + rew - _CONFIRM_FEE_TOLERANCE:
        return True, "confirmed"
    return False, "unconfirmed"


# Balance tolerance for submission confirmation: interim move/fee spend in
# the submit→confirm window is orders of magnitude below one block reward
# (fees are ~1e2 subunits vs 1e6 reward), so a missing full reward means the
# submission was not credited. Documented, not consensus.
_CONFIRM_FEE_TOLERANCE = 100_000


def solve_pow_range(seed, difficulty, start: int, stride: int, stop, duty: float = 1.0) -> object:
    """One parallel PoW worker: nonces start, start+stride, ... Checking
    `stop` every 2048 hashes so a sibling's win cancels promptly. Returns
    the nonce or None. Any valid nonce is accepted by the node (no
    minimality rule), so first-found wins.
    CPU-TARGET-2: `duty` in (0,1] throttles sustained draw for low CPU
    targets — after each 2048-hash block the worker sleeps
    block_time*(1-duty)/duty, converging sustained use toward duty of one
    core. duty=1.0 (default) preserves the unthrottled path exactly."""
    try:
        difficulty = int(difficulty)
    except (TypeError, ValueError):
        return None
    if stride < 1:
        stride = 1
    nonce = int(start)
    since_check = 0
    try:
        _duty = min(max(float(duty), 0.01), 1.0)
    except (TypeError, ValueError):
        _duty = 1.0
    _blk_t0 = time.perf_counter()
    while True:
        data = f"{seed}{nonce}".encode()
        digest = hashlib.sha256(data).digest()
        if int.from_bytes(digest, 'big') >> (256 - difficulty) == 0:
            return nonce
        nonce += stride
        since_check += 1
        if since_check >= 2048:
            since_check = 0
            if _duty < 1.0:
                _blk_dt = time.perf_counter() - _blk_t0
                _sleep = _blk_dt * (1.0 - _duty) / _duty
                if _sleep > 0:
                    time.sleep(min(_sleep, 5.0))
            _blk_t0 = time.perf_counter()
            try:
                if stop.is_set():
                    return None
            except (AttributeError, TypeError):
                pass


class _DummyStop:
    """Never-set stop event for single-worker duty runs."""
    def is_set(self):
        return False


def solve_pow_parallel(seed, difficulty, workers: int, executor, duty: float = 1.0) -> int:
    """Partition the nonce space round-robin across `workers` threads;
    first valid nonce wins, losers are cancelled. workers<=1 (or a broken
    executor) falls back to the single-threaded solve_pow. Returns -1 only
    if nothing was found (practically: never, without an external stop).
    `duty` is forwarded to every worker (CPU-TARGET-2); 1.0 = unthrottled."""
    try:
        workers = max(1, int(workers))
    except (TypeError, ValueError):
        workers = 1
    if executor is None:
        return solve_pow(seed, difficulty)
    if workers <= 1:
        # Single worker still honors duty (CPU-TARGET-2); the dummy stop
        # never fires, so semantics equal solve_pow plus throttling.
        return solve_pow_range(seed, difficulty, 0, 1, _DummyStop(), duty)
    import concurrent.futures as _cf
    stop = threading.Event()
    try:
        futs = [executor.submit(solve_pow_range, seed, difficulty, w, workers, stop, duty)
                for w in range(workers)]
    except (RuntimeError, AttributeError, TypeError):
        return solve_pow(seed, difficulty)
    try:
        for f in _cf.as_completed(futs):
            try:
                r = f.result()
            except Exception:
                continue
            if r is not None:
                stop.set()
                for p in futs:
                    p.cancel()
                return int(r)
    finally:
        stop.set()
    return -1


DQN_MODEL_JSON = "dqn_maze_model.json"
DQN_MODEL_PT = "dqn_maze_model.pt"

class DQNAgent:
    def __init__(self, state_size=40, action_size=6, hidden_size=64, model_format="json"):
        self.state_size = state_size
        self.action_size = action_size
        self.hidden_size = hidden_size
        self.model_format = model_format
        self.epsilon = 1.0
        self.epsilon_min = 0.05
        self.epsilon_decay = 0.9995
        self.gamma = 0.95
        self.lr = 0.001
        self.memory = deque(maxlen=5000)
        self.batch_size = 32
        self.update_target_every = 100
        self.steps_done = 0
        self.lock = threading.Lock()
        self._snapshot = None
        self._init_weights()

    def _init_weights(self):
        s1 = (2.0 / self.state_size) ** 0.5
        s2 = (2.0 / self.hidden_size) ** 0.5
        self.w1 = [[random.gauss(0, s1) for _ in range(self.hidden_size)] for _ in range(self.state_size)]
        self.b1 = [0.0] * self.hidden_size
        self.w2 = [[random.gauss(0, s2) for _ in range(self.action_size)] for _ in range(self.hidden_size)]
        self.b2 = [0.0] * self.action_size
        self.tw1 = [r[:] for r in self.w1]
        self.tb1 = self.b1[:]
        self.tw2 = [r[:] for r in self.w2]
        self.tb2 = self.b2[:]

    def forward(self, state, use_target=False):
        if use_target:
            w1, b1, w2, b2 = self.tw1, self.tb1, self.tw2, self.tb2
        else:
            with self.lock:
                w1 = [r[:] for r in self.w1]
                b1 = self.b1[:]
                w2 = [r[:] for r in self.w2]
                b2 = self.b2[:]
        return self._forward(state, w1, b1, w2, b2)

    def _forward(self, state, w1, b1, w2, b2):
        hidden = []
        for j in range(self.hidden_size):
            s = b1[j]
            for i in range(self.state_size):
                s += state[i] * w1[i][j]
            hidden.append(s if s > 0 else 0.0)
        output = []
        for k in range(self.action_size):
            s = b2[k]
            for j in range(self.hidden_size):
                s += hidden[j] * w2[j][k]
            output.append(s)
        return output, hidden

    def predict(self, state):
        output, _ = self.forward(state)
        return output

    def act(self, state, valid_actions=None):
        if random.random() < self.epsilon:
            if valid_actions:
                return random.choice(valid_actions)
            return random.randrange(self.action_size)
        q_vals = self.predict(state)
        if valid_actions:
            return max(valid_actions, key=lambda a: q_vals[a])
        return max(range(self.action_size), key=lambda a: q_vals[a])

    def remember(self, state, action, reward, next_state, done):
        self.memory.append((state, action, reward, next_state, done))

    def replay(self):
        if len(self.memory) < self.batch_size:
            return
        batch = random.sample(self.memory, self.batch_size)
        with self.lock:
            w1 = [r[:] for r in self.w1]
            b1 = self.b1[:]
            w2 = [r[:] for r in self.w2]
            b2 = self.b2[:]
        dw1 = [[0.0]*self.hidden_size for _ in range(self.state_size)]
        db1 = [0.0]*self.hidden_size
        dw2 = [[0.0]*self.action_size for _ in range(self.hidden_size)]
        db2 = [0.0]*self.action_size
        for state, action, reward, next_state, done in batch:
            q_vals, hidden = self._forward(state, w1, b1, w2, b2)
            target = reward if done else reward + self.gamma * max(self._forward(next_state, self.tw1, self.tb1, self.tw2, self.tb2)[0])
            error = q_vals[action] - target
            for j in range(self.hidden_size):
                dw2[j][action] += hidden[j] * error
            db2[action] += error
            for j in range(self.hidden_size):
                grad = error * w2[j][action] * (1.0 if hidden[j] > 0 else 0.0)
                for i in range(self.state_size):
                    dw1[i][j] += state[i] * grad
                db1[j] += grad
        n = self.batch_size
        clip = 5.0
        with self.lock:
            for i in range(self.state_size):
                for j in range(self.hidden_size):
                    self.w1[i][j] -= self.lr * max(-clip, min(clip, dw1[i][j] / n))
            for j in range(self.hidden_size):
                self.b1[j] -= self.lr * max(-clip, min(clip, db1[j] / n))
            for j in range(self.hidden_size):
                for k in range(self.action_size):
                    self.w2[j][k] -= self.lr * max(-clip, min(clip, dw2[j][k] / n))
            for k in range(self.action_size):
                self.b2[k] -= self.lr * max(-clip, min(clip, db2[k] / n))
            self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
            self.steps_done += 1
            if self.steps_done % self.update_target_every == 0:
                self.tw1 = [r[:] for r in self.w1]
                self.tb1 = self.b1[:]
                self.tw2 = [r[:] for r in self.w2]
                self.tb2 = self.b2[:]

    def save(self, path=None):
        if path is None:
            path = DQN_MODEL_PT if self.model_format == "pt" else DQN_MODEL_JSON
        try:
            with self.lock:
                snap = {"w1": [r[:] for r in self.w1], "b1": self.b1[:],
                        "w2": [r[:] for r in self.w2], "b2": self.b2[:],
                        "epsilon": self.epsilon, "steps": self.steps_done}
            if self.model_format == "pt":
                self._save_pt(path, snap)
            else:
                self._save_json(path, snap)
        except (OSError, json.JSONDecodeError, TypeError) as e:
            log(f"DQN save error: {e}", "warning", "dqn0")

    def _save_json(self, path, snap=None):
        if snap is None:
            with self.lock:
                snap = {"w1": [r[:] for r in self.w1], "b1": self.b1[:],
                        "w2": [r[:] for r in self.w2], "b2": self.b2[:],
                        "epsilon": self.epsilon, "steps": self.steps_done}
        with open(path, "w") as f:
            json.dump(snap, f)

    def _save_pt(self, path, snap=None):
        try:
            import torch
            if snap is None:
                with self.lock:
                    snap = {"w1": [r[:] for r in self.w1], "b1": self.b1[:],
                            "w2": [r[:] for r in self.w2], "b2": self.b2[:],
                            "epsilon": self.epsilon, "steps": self.steps_done}
            state = {
                "w1": torch.tensor(snap["w1"], dtype=torch.float32),
                "b1": torch.tensor(snap["b1"], dtype=torch.float32),
                "w2": torch.tensor(snap["w2"], dtype=torch.float32),
                "b2": torch.tensor(snap["b2"], dtype=torch.float32),
                "epsilon": snap["epsilon"],
                "steps": snap["steps"],
            }
            torch.save(state, path)
        except ImportError:
            self._save_json(DQN_MODEL_JSON, snap)

    def load(self, path=None):
        if path is None:
            if os.path.exists(DQN_MODEL_PT):
                path = DQN_MODEL_PT
                self.model_format = "pt"
            elif os.path.exists(DQN_MODEL_JSON):
                path = DQN_MODEL_JSON
                self.model_format = "json"
            else:
                return False
        try:
            if path.endswith(".pt"):
                self._load_pt(path)
            else:
                self._load_json(path)
            self.tw1 = [r[:] for r in self.w1]
            self.tb1 = self.b1[:]
            self.tw2 = [r[:] for r in self.w2]
            self.tb2 = self.b2[:]
            return True
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
            log(f"DQN load error: {e}", "warning", "dqn0")
            return False

    def _load_json(self, path):
        with open(path, "r") as f:
            data = json.load(f)
        self.w1, self.b1, self.w2, self.b2 = data["w1"], data["b1"], data["w2"], data["b2"]
        self.epsilon = data.get("epsilon", 1.0)
        self.steps_done = data.get("steps", 0)

    def _load_pt(self, path):
        import torch
        data = torch.load(path, map_location="cpu", weights_only=False)
        self.w1 = data["w1"].tolist()
        self.b1 = data["b1"].tolist()
        self.w2 = data["w2"].tolist()
        self.b2 = data["b2"].tolist()
        self.epsilon = data.get("epsilon", 1.0)
        self.steps_done = data.get("steps", 0)

def extract_dqn_state(maze, current, goal, ghost, size):
    if not maze or not current or not goal:
        return [0.0] * 40
    x, y, z = current
    gx, gy, gz = goal
    state = []
    for dz in range(-1, 2):
        for dy in range(-1, 2):
            for dx in range(-1, 2):
                nx, ny, nz = x+dx, y+dy, z+dz
                if 0 <= nx < size and 0 <= ny < size and 0 <= nz < size:
                    state.append(1.0 - maze[nz][ny][nx])
                else:
                    state.append(0.0)
    ddx, ddy, ddz = gx - x, gy - y, gz - z
    dist = max(1, abs(ddx) + abs(ddy) + abs(ddz))
    state.extend([ddx / dist, ddy / dist, ddz / dist])
    if ghost:
        gdx, gdy, gdz = ghost[0] - x, ghost[1] - y, ghost[2] - z
        gd = max(1, abs(gdx) + abs(gdy) + abs(gdz))
        state.extend([gdx / gd, gdy / gd, gdz / gd, max(0.0, 1.0 - (abs(gdx)+abs(gdy)+abs(gdz)) / max(1, size))])
    else:
        state.extend([0.0, 0.0, 0.0, 0.0])
    for dx, dy, dz in DIR_OFFSETS:
        nx, ny, nz = x+dx, y+dy, z+dz
        state.append(1.0 if (0 <= nx < size and 0 <= ny < size and 0 <= nz < size and maze[nz][ny][nx] == 0) else 0.0)
    return state

def get_valid_actions(maze, current, size):
    if not maze or not current:
        return list(range(6))
    x, y, z = current
    return [i for i, (dx, dy, dz) in enumerate(DIR_OFFSETS)
            if 0 <= x+dx < size and 0 <= y+dy < size and 0 <= z+dz < size
            and maze[z+dz][y+dy][x+dx] == 0]

def hybrid_move(maze, current, goal, ghost, size, agent, known_walls=None,
                visited_recent=None, forbidden_positions=None):
    if not maze or not current or not goal:
        return -1, None
    if known_walls is None:
        known_walls = set()
    if visited_recent is None:
        visited_recent = set()
    if forbidden_positions is None:
        forbidden_positions = set()

    valid = get_valid_actions(maze, current, size)
    if not valid:
        return -1, None
    if current == goal:
        return -1, None

    # Filter out known walls
    valid_no_walls = [
        idx for idx in valid
        if (current[0] + DIR_OFFSETS[idx][0], current[1] + DIR_OFFSETS[idx][1], current[2] + DIR_OFFSETS[idx][2]) not in known_walls
    ]
    if not valid_no_walls:
        valid_no_walls = valid

    # goal's one step away, take it
    for idx in valid_no_walls:
        dx, dy, dz = DIR_OFFSETS[idx]
        nxt = (current[0]+dx, current[1]+dy, current[2]+dz)
        if nxt == goal:
            return idx, "goal_reach"

    # ghost is nearby, find a way out
    ghost_danger = False
    ghost_dir_away = None
    if ghost:
        gd = abs(current[0] - ghost[0]) + abs(current[1] - ghost[1]) + abs(current[2] - ghost[2])
        if gd <= 2:
            ghost_danger = True
            best_dist = -1
            for idx in valid_no_walls:
                dx, dy, dz = DIR_OFFSETS[idx]
                nxt = (current[0]+dx, current[1]+dy, current[2]+dz)
                if nxt in forbidden_positions and len(valid_no_walls) > 1:
                    continue
                d = bfs_distance(maze, nxt, tuple(ghost), known_walls, max_steps=8)
                if d > best_dist:
                    best_dist = d
                    ghost_dir_away = idx

    # A* handles the ghost avoidance
    path = a_star(maze, current, goal, known_walls, ghost=ghost, max_nodes=10000)
    if path and len(path) > 0:
        next_pos = path[0]
        dx, dy, dz = next_pos[0] - current[0], next_pos[1] - current[1], next_pos[2] - current[2]
        idx = DIR_OFFSET_TO_IDX.get((dx, dy, dz), -1)
        if idx != -1 and idx in valid_no_walls:
            if next_pos not in forbidden_positions or len(valid_no_walls) == 1:
                return idx, "astar"

    # A* gave nothing, try bfs
    path = bfs_explore(maze, current, goal, known_walls, ghost=ghost, max_steps=5000)
    if path and len(path) > 0:
        next_pos = path[0]
        dx, dy, dz = next_pos[0] - current[0], next_pos[1] - current[1], next_pos[2] - current[2]
        idx = DIR_OFFSET_TO_IDX.get((dx, dy, dz), -1)
        if idx != -1 and idx in valid_no_walls:
            if next_pos not in forbidden_positions or len(valid_no_walls) == 1:
                return idx, "bfs"

    # still stuck and ghost is close — run
    if ghost_danger and ghost_dir_away is not None:
        return ghost_dir_away, "ghost_escape"

    # just move closer to the goal
    best_idx = -1
    best_score = -999999
    for idx in valid_no_walls:
        dx, dy, dz = DIR_OFFSETS[idx]
        nxt = (current[0]+dx, current[1]+dy, current[2]+dz)
        dist_to_goal = abs(nxt[0]-goal[0]) + abs(nxt[1]-goal[1]) + abs(nxt[2]-goal[2])
        score = -dist_to_goal
        if nxt in forbidden_positions:
            score -= 100
        if nxt in visited_recent:
            score -= 5
        if score > best_score:
            best_score = score
            best_idx = idx

    if best_idx != -1:
        return best_idx, "heuristic"

    # pick anything that isn't forbidden
    candidates = [i for i in valid_no_walls if (current[0]+DIR_OFFSETS[i][0], current[1]+DIR_OFFSETS[i][1], current[2]+DIR_OFFSETS[i][2]) not in forbidden_positions]
    if candidates:
        return random.choice(candidates), "random"
    if valid_no_walls:
        return random.choice(valid_no_walls), "random_fallback"
    return -1, None

# ═══════════════════════════════════════════════════════════════════════════
# CPU-TARGET-3  —  make the CPU slider actually move the real CPU usage.
#
# Why the old build barely reacted to the slider:
#   * PoW "workers" were THREADS running a pure-Python hash loop. hashlib only
#     drops the GIL on big buffers, so N threads still burn ~1 core total.
#   * DQN training was pure Python, batch 32, 1-4 replays then a 0.25-4s nap.
#   * The governor measured only this process (os.times), so it could never
#     see work moved into child processes.
# What this block adds:
#   * _ComputePool: persistent worker PROCESSES (real multi-core). Used for
#     PoW nonce search and heavy A*/BFS planning. Workers run below normal
#     priority and report cumulative CPU seconds into shared memory so the
#     governor sees the whole process tree (no psutil needed).
#   * D3QNAgent: Dueling + Double DQN in numpy (Adam, Huber, big batches).
#     numpy matmuls release the GIL and BLAS spreads them over cores, so the
#     batch size is a real CPU knob. Falls back to the legacy DQNAgent if
#     numpy is not installed.
#   * deep planning: A* (with forbidden-cell penalties) and BFS with budgets
#     up to 400k nodes, solved off the event loop in worker processes.
# ═══════════════════════════════════════════════════════════════════════════
import multiprocessing as _mp
from concurrent.futures import ProcessPoolExecutor as _ProcPool

_CW_JOB = None      # worker side: shared job-id (cancel signal for PoW losers)
_CW_SLOTS = None    # worker side: shared cumulative CPU seconds, one slot each
_CW_SLOT = -1

POW_POOL_MIN_DIFFICULTY = 16     # below this a solve is ~ms: IPC would cost more
DEEP_PLAN_MAX_NODES = 400_000


def _lower_priority():
    """Workers must never starve the event loop / websocket: below normal."""
    try:
        if os.name == "nt":
            import ctypes
            k = ctypes.windll.kernel32
            k.SetPriorityClass(k.GetCurrentProcess(), 0x00004000)  # BELOW_NORMAL
        else:
            os.nice(5)
    except Exception:
        pass


def _cw_init(job, slots, counter):
    global _CW_JOB, _CW_SLOTS, _CW_SLOT
    _CW_JOB, _CW_SLOTS = job, slots
    with counter.get_lock():
        _CW_SLOT = counter.value
        counter.value += 1
    _lower_priority()


def _cw_report():
    try:
        if _CW_SLOTS is not None and 0 <= _CW_SLOT < len(_CW_SLOTS):
            _CW_SLOTS[_CW_SLOT] = time.process_time()
    except Exception:
        pass


def _cw_ping(delay):
    time.sleep(delay)
    _cw_report()
    return _CW_SLOT


def _pow_ok(seed, nonce, difficulty) -> bool:
    """Same acceptance test as solve_pow()."""
    try:
        d = int(difficulty)
        digest = hashlib.sha256(f"{seed}{int(nonce)}".encode()).digest()
        return int.from_bytes(digest, 'big') >> (256 - d) == 0
    except (TypeError, ValueError, OverflowError):
        return False


def _cw_pow(seed, difficulty, start, stride, job_id, max_seconds):
    """One PoW worker process: nonces start, start+stride, ... Returns the
    nonce, or None when cancelled (job id changed) or out of time. Hash input
    is byte-identical to solve_pow(): f"{seed}{nonce}"."""
    try:
        d = min(max(int(difficulty), 0), 256)
    except (TypeError, ValueError):
        return None
    base = hashlib.sha256(str(seed).encode())
    shift = 256 - d
    nonce = int(start)
    stride = max(1, int(stride))
    deadline = time.monotonic() + float(max_seconds)
    frm = int.from_bytes
    n = 0
    while True:
        h = base.copy()
        h.update(b"%d" % nonce)
        if frm(h.digest(), 'big') >> shift == 0:
            _cw_report()
            return nonce
        nonce += stride
        n += 1
        if n >= 4096:
            n = 0
            _cw_report()
            try:
                if _CW_JOB is not None and _CW_JOB.value != job_id:
                    return None
            except Exception:
                return None
            if time.monotonic() > deadline:
                return None


def deep_plan_path(maze, start, goal, ghost=None, known_walls=None,
                   forbidden=None, max_nodes=DEEP_PLAN_MAX_NODES):
    """Heavy planner (runs in a worker process). Ghost-aware A* with a large
    node budget and a soft penalty for `forbidden` cells; if A* cannot finish,
    a large BFS that returns the path to the reachable cell closest to goal.
    Returns (path, kind) or (None, None). Pure; unit-testable."""
    kw = set(map(tuple, known_walls)) if known_walls else set()
    fb = set(map(tuple, forbidden)) if forbidden else set()
    start, goal = tuple(start), tuple(goal)
    path = a_star(maze, start, goal, kw, ghost=ghost, max_nodes=int(max_nodes), forbidden=fb)
    if path:
        return path, "astar"
    size = len(maze)
    path = bfs_explore(maze, start, goal, kw, ghost=ghost,
                       max_steps=min(int(max_nodes), max(5000, size ** 3)))
    if path:
        return path, "bfs"
    return None, None


def _cw_plan(maze, start, goal, ghost, known_walls, forbidden, max_nodes):
    t0 = time.process_time()
    try:
        path, kind = deep_plan_path(maze, start, goal, ghost, known_walls, forbidden, max_nodes)
    finally:
        _cw_report()
    if not path:
        return None
    nxt = path[0]
    off = (nxt[0] - start[0], nxt[1] - start[1], nxt[2] - start[2])
    idx = DIR_OFFSET_TO_IDX.get(off, -1)
    if idx < 0:
        return None
    return idx, len(path), kind


class _ComputePool:
    """Persistent worker processes (spawn: Windows-safe). All methods other
    than start()/shutdown() are coroutines or cheap reads; every failure
    degrades to the caller's local fallback instead of raising into the miner."""

    def __init__(self, workers: int):
        self.workers = max(1, int(workers))
        self.ready = False
        self.broken = False
        self._ex = None
        self._job = None
        self._slots = None
        self._job_id = 0

    def start(self):
        ctx = _mp.get_context("spawn")
        self._job = ctx.Value('q', 0)
        self._slots = ctx.Array('d', self.workers + 64, lock=False)
        counter = ctx.Value('i', 0)
        self._ex = _ProcPool(max_workers=self.workers, mp_context=ctx,
                             initializer=_cw_init, initargs=(self._job, self._slots, counter))

    async def warm(self, delay=0.4):
        """Force every worker process to spawn (overlapping sleeps) so the
        first real PoW is not delayed by interpreter start-up."""
        loop = asyncio.get_running_loop()
        try:
            await asyncio.gather(*[loop.run_in_executor(self._ex, _cw_ping, delay)
                                   for _ in range(self.workers)])
            self.ready = True
        except Exception:
            self.broken = True
            self.ready = False

    def usable(self) -> bool:
        return bool(self.ready and not self.broken and self._ex is not None)

    def cpu_seconds(self) -> float:
        """Cumulative CPU seconds of all worker processes (shared memory)."""
        try:
            return float(sum(self._slots[:self.workers + 64])) if self._slots is not None else 0.0
        except Exception:
            return 0.0

    def _next_job(self) -> int:
        self._job_id += 1
        try:
            self._job.value = self._job_id
        except Exception:
            pass
        return self._job_id

    async def pow(self, seed, difficulty, workers, timeout=30.0):
        """Parallel nonce search over `workers` processes. Returns a nonce
        verified in the parent, or -1. Raises only on pool failure (caller
        falls back to the local path)."""
        loop = asyncio.get_running_loop()
        workers = max(1, min(int(workers), self.workers))
        jid = self._next_job()
        futs = [loop.run_in_executor(self._ex, _cw_pow, seed, difficulty, w, workers, jid, timeout)
                for w in range(workers)]
        pending = set(futs)
        try:
            while pending:
                done, pending = await asyncio.wait(pending, timeout=timeout + 1.0,
                                                   return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    break
                for f in done:
                    r = f.result()
                    if r is not None and _pow_ok(seed, r, difficulty):
                        return int(r)
            return -1
        except Exception:
            self.broken = True
            raise
        finally:
            self._next_job()            # losers see a new job id and stop
            for f in futs:
                f.cancel()

    async def deep_plan(self, maze, start, goal, ghost, known_walls, forbidden, max_nodes):
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(
                self._ex, _cw_plan, maze, tuple(start), tuple(goal),
                tuple(ghost) if ghost else None,
                [tuple(w) for w in known_walls], [tuple(f) for f in forbidden], int(max_nodes))
        except Exception:
            self.broken = True
            return None

    def shutdown(self):
        try:
            if self._ex is not None:
                try:
                    self._ex.shutdown(wait=False, cancel_futures=True)
                except TypeError:                       # Python 3.8: no cancel_futures
                    self._ex.shutdown(wait=False)
        except Exception:
            pass
        self.ready = False


# ─── D3QN (Dueling + Double DQN), numpy ─────────────────────────────────────
D3QN_MODEL_JSON = "d3qn_maze_model.json"
_NUMPY_CACHE = [None, False]


def _load_numpy(threads=None):
    """Import numpy lazily so BLAS thread caps can be set first. Returns the
    module or None. Caps only apply if numpy was not imported yet."""
    if _NUMPY_CACHE[1]:
        return _NUMPY_CACHE[0]
    if threads:
        for k in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS",
                  "VECLIB_MAXIMUM_THREADS", "NUMEXPR_NUM_THREADS"):
            os.environ.setdefault(k, str(int(threads)))
    try:
        import numpy as _np
        _NUMPY_CACHE[0] = _np
    except ImportError:
        _NUMPY_CACHE[0] = None
    _NUMPY_CACHE[1] = True
    return _NUMPY_CACHE[0]


class _NPRing:
    """Fixed-size replay buffer in preallocated arrays: sampling a 4k batch is
    one fancy-index (no per-sample Python work)."""

    def __init__(self, np, cap, sdim):
        self.np, self.cap, self.n, self.pos = np, int(cap), 0, 0
        self.S = np.zeros((self.cap, sdim), np.float32)
        self.S2 = np.zeros((self.cap, sdim), np.float32)
        self.A = np.zeros(self.cap, np.int64)
        self.R = np.zeros(self.cap, np.float32)
        self.D = np.zeros(self.cap, np.float32)
        self._lock = threading.Lock()

    def append(self, item):
        s, a, r, s2, d = item
        np = self.np
        # Validate BEFORE writing: numpy would silently turn None into NaN, and
        # one NaN sample poisons every later gradient step.
        s = np.asarray(s, dtype=np.float32)
        s2 = np.asarray(s2, dtype=np.float32)
        a = int(a)
        r = float(r)
        if (s.shape != (self.S.shape[1],) or s2.shape != s.shape
                or not np.isfinite(s).all() or not np.isfinite(s2).all()
                or not np.isfinite(r) or not (0 <= a < 1024)):
            raise ValueError("bad replay sample")
        with self._lock:
            i = self.pos
            self.S[i] = s
            self.S2[i] = s2
            self.A[i] = a
            self.R[i] = r
            self.D[i] = 1.0 if d else 0.0
            self.pos = (i + 1) % self.cap
            self.n = min(self.n + 1, self.cap)

    def __len__(self):
        return self.n

    def sample(self, k):
        idx = self.np.random.randint(0, self.n, size=int(k))
        return self.S[idx], self.A[idx], self.R[idx], self.S2[idx], self.D[idx]


class D3QNAgent:
    """Dueling + Double DQN. Same surface PCMiner uses on DQNAgent:
    memory (len), batch_size, steps_done, epsilon, remember/replay/act/predict/
    save/load. Trunk 40->H1->H2, value head (1) + advantage head (6),
    Q = V + A - mean(A). Double-DQN target (online argmax, target value),
    Huber loss, Adam, global-norm gradient clipping, hard target sync."""
    arch = "d3qn"

    def __init__(self, state_size=40, action_size=6, hidden1=512, hidden2=256,
                 model_format="json", np_mod=None, mem_cap=50000):
        np = np_mod or _load_numpy()
        if np is None:
            raise ImportError("numpy required for D3QNAgent")
        self.np = np
        self.state_size, self.action_size = int(state_size), int(action_size)
        self.h1, self.h2 = int(hidden1), int(hidden2)
        self.model_format = "json"
        self.epsilon, self.epsilon_min, self.epsilon_decay = 1.0, 0.05, 0.9995
        self.gamma, self.lr = 0.95, 5e-4
        self.batch_size = 128
        self.min_memory = 32
        self.update_target_every = 200
        self.steps_done = 0
        self.last_loss = 0.0
        self.lock = threading.Lock()
        self.memory = _NPRing(np, mem_cap, self.state_size)
        self._init_params()

    # -- parameters ---------------------------------------------------------
    def _init_params(self):
        np = self.np
        rng = np.random.default_rng()
        def he(i, o):
            return (rng.standard_normal((i, o)) * (2.0 / i) ** 0.5).astype(np.float32)
        z = lambda n: np.zeros(n, np.float32)
        self.p = {"W1": he(self.state_size, self.h1), "b1": z(self.h1),
                  "W2": he(self.h1, self.h2), "b2": z(self.h2),
                  "Wv": he(self.h2, 1), "bv": z(1),
                  "Wa": he(self.h2, self.action_size), "ba": z(self.action_size)}
        self.tp = {k: v.copy() for k, v in self.p.items()}
        self.m = {k: np.zeros_like(v) for k, v in self.p.items()}
        self.v = {k: np.zeros_like(v) for k, v in self.p.items()}
        self.t = 0

    def _forward(self, x, p):
        np = self.np
        z1 = x @ p["W1"] + p["b1"]
        h1 = np.maximum(z1, 0.0)
        z2 = h1 @ p["W2"] + p["b2"]
        h2 = np.maximum(z2, 0.0)
        v = h2 @ p["Wv"] + p["bv"]
        a = h2 @ p["Wa"] + p["ba"]
        q = v + a - a.mean(axis=1, keepdims=True)
        return q, (x, z1, h1, z2, h2)

    def targets(self, r, s2, d):
        """Double-DQN: action from the ONLINE net, value from the TARGET net."""
        np = self.np
        q_on, _ = self._forward(s2, self.p)
        a_star = np.argmax(q_on, axis=1)
        q_t, _ = self._forward(s2, self.tp)
        nxt = q_t[np.arange(len(a_star)), a_star]
        return r + self.gamma * (1.0 - d) * nxt

    def grads(self, S, A, y, p=None):
        """Huber-loss gradients w.r.t. every parameter (manual backprop)."""
        np = self.np
        p = p if p is not None else self.p
        q, (x, z1, h1, z2, h2) = self._forward(S, p)
        B = S.shape[0]
        idx = np.arange(B)
        err = q[idx, A] - y
        loss = float(np.mean(np.where(np.abs(err) <= 1.0, 0.5 * err * err, np.abs(err) - 0.5)))
        dq = np.zeros_like(q)
        dq[idx, A] = np.clip(err, -1.0, 1.0) / B
        dV = dq.sum(axis=1, keepdims=True)
        dA = dq - dq.sum(axis=1, keepdims=True) / self.action_size
        g = {"Wv": h2.T @ dV, "bv": dV.sum(axis=0), "Wa": h2.T @ dA, "ba": dA.sum(axis=0)}
        dh2 = (dV @ p["Wv"].T + dA @ p["Wa"].T) * (z2 > 0)
        g["W2"], g["b2"] = h1.T @ dh2, dh2.sum(axis=0)
        dh1 = (dh2 @ p["W2"].T) * (z1 > 0)
        g["W1"], g["b1"] = x.T @ dh1, dh1.sum(axis=0)
        return g, loss

    # -- agent API ----------------------------------------------------------
    def remember(self, state, action, reward, next_state, done):
        try:
            self.memory.append((state, action, reward, next_state, done))
        except (ValueError, TypeError, IndexError):
            pass            # malformed sample: skip, never crash the miner

    def predict(self, state):
        np = self.np
        with self.lock:
            q, _ = self._forward(np.asarray(state, np.float32).reshape(1, -1), self.p)
        return q[0].tolist()

    def act(self, state, valid_actions=None):
        if random.random() < self.epsilon:
            return random.choice(valid_actions) if valid_actions else random.randrange(self.action_size)
        q = self.predict(state)
        pool = valid_actions if valid_actions else range(self.action_size)
        return max(pool, key=lambda a: q[a])

    def replay(self, batch_size=None):
        """One gradient step on `batch_size` samples. Returns True if trained."""
        np = self.np
        if len(self.memory) < self.min_memory:
            return False
        B = max(8, int(batch_size or self.batch_size))
        S, A, R, S2, D = self.memory.sample(B)
        with self.lock:
            y = self.targets(R, S2, D)
            g, loss = self.grads(S, A, y)
            gn = float(np.sqrt(sum(float((v * v).sum()) for v in g.values())))
            scale = 1.0 if gn <= 5.0 or gn != gn else 5.0 / gn
            self.t += 1
            b1c, b2c = 1.0 - 0.9 ** self.t, 1.0 - 0.999 ** self.t
            for k, gv in g.items():
                gv = gv * scale
                self.m[k] = 0.9 * self.m[k] + 0.1 * gv
                self.v[k] = 0.999 * self.v[k] + 0.001 * gv * gv
                self.p[k] -= (self.lr * (self.m[k] / b1c) / (np.sqrt(self.v[k] / b2c) + 1e-8)).astype(np.float32)
            self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
            self.steps_done += 1
            self.last_loss = loss
            if self.steps_done % self.update_target_every == 0:
                self.tp = {k: v.copy() for k, v in self.p.items()}
        return True

    # -- persistence --------------------------------------------------------
    def save(self, path=None):
        path = path or D3QN_MODEL_JSON
        try:
            with self.lock:
                snap = {"arch": "d3qn", "h1": self.h1, "h2": self.h2,
                        "state_size": self.state_size, "action_size": self.action_size,
                        "epsilon": self.epsilon, "steps": self.steps_done,
                        "p": {k: v.tolist() for k, v in self.p.items()}}
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(snap, f)
            os.replace(tmp, path)
        except (OSError, TypeError, ValueError) as e:
            log(f"D3QN save error: {e}", "warning", "dqn0")

    def load(self, path=None):
        path = path or D3QN_MODEL_JSON
        if not os.path.exists(path):
            return False
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if (data.get("arch") != "d3qn" or int(data["h1"]) != self.h1 or int(data["h2"]) != self.h2
                    or int(data["state_size"]) != self.state_size
                    or int(data["action_size"]) != self.action_size):
                return False
            np = self.np
            newp = {k: np.asarray(data["p"][k], np.float32) for k in self.p}
            for k in self.p:
                if newp[k].shape != self.p[k].shape:
                    return False
            with self.lock:
                self.p = newp
                self.tp = {k: v.copy() for k, v in newp.items()}
                self.m = {k: np.zeros_like(v) for k, v in newp.items()}
                self.v = {k: np.zeros_like(v) for k, v in newp.items()}
                self.epsilon = float(data.get("epsilon", 1.0))
                self.steps_done = int(data.get("steps", 0))
            return True
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
            log(f"D3QN load error: {e}", "warning", "dqn0")
            return False


def make_agent(model_format="json", threads=None):
    """D3QN when numpy is available, else the legacy pure-Python DQN."""
    np = _load_numpy(threads)
    if np is not None:
        try:
            return D3QNAgent(model_format=model_format, np_mod=np), "D3QN (numpy)"
        except Exception as e:
            log(f"D3QN unavailable ({e}); using legacy DQN", "warning", "dqn0")
    return DQNAgent(model_format=model_format), "legacy DQN (pip install numpy for D3QN + multi-core training)"


class PCMiner:
    def __init__(self, wallet, privkey, miner_id=None, node_url=None, core_suffix="",
                 mazepriv=None, mazepub=None, pqc_pub=None, pqc_priv=None, model_format="json",
                 cpu_percent=None, proc_workers=None):
        self.wallet = wallet
        self.privkey = privkey
        self.pubkey = pubkey_from_priv(privkey)
        self.pqc_pub = pqc_pub or b""
        self.pqc_priv = pqc_priv or b""
        self.mazepriv = mazepriv
        self.mazepub = mazepub
        self.maze_id = mazepub
        if miner_id is None:
            # IDEA5-MAZE-KEY-BINDING-1: stable id derived from the maze key so
            # verifiers can recompute it from the attestation pubkey alone:
            #   PC_ + sha256(pubkey_to_address(mazepub) + "_mcx_miner")[:32]
            # SINGLE-KEY MODE: main() passes the identity keypair as the maze
            # keypair, so this derivation coincides with the identity-key
            # derivation the node requires at register
            # (R5-register-pc-derivation). Do not pass a distinct maze key —
            # registration rejects it.
            if mazepub:
                digest = hashlib.sha256(f"{pubkey_to_address(mazepub)}_mcx_miner".encode()).hexdigest()[:32].upper()
            else:
                rand = secrets.token_hex(8)
                digest = hashlib.sha256(f"{wallet}_{time.time()}_{rand}".encode()).hexdigest()[:24].upper()
            base_id = f"PC_{digest}"
        else:
            base_id = miner_id
        self.miner_id = f"{base_id}_{core_suffix}" if core_suffix else base_id
        self.node_url = node_url
        self._node_candidates = deque()
        self.ws = None
        self.registered = False
        self.balance = 0
        self.running = True

        self.maze = None
        self.size = 0
        self.start = None
        self.current = None
        self.goal = None
        self.ghost = None
        self.block_id = -1
        self.steps = 0
        self.accepted = 0
        self.attempts = 0
        self.round_active = False
        self.difficulty = 1.0

        self.growthcount = 0
        self.movenonce = 0
        self.needs_reinit = False

        self.local_walls = set()
        self._visited_recent = deque(maxlen=15)
        self.session_start_time = time.time()
        self.total_blocks_mined = 0
        self.total_mcx_earned = 0
        self.total_fees_earned = 0
        # BLOCK-CONFIRM-1: total_blocks_mined counts node-CONFIRMED blocks
        # only. _pending_block holds the latest submission awaiting a
        # block_height_update past its id (reconciled by balance growth);
        # total_blocks_submitted counts sends (diagnostic, never presented
        # as mined).
        self._pending_block = None
        self.total_blocks_submitted = 0
        self.total_goals_reached = 0
        self.total_accepted_moves = 0
        self.total_attempted_moves = 0
        self.total_walls_solved = 0
        self.initial_balance = None
        self.status_report_task = None
        self._last_logged_block = None
        self._pos_history = deque(maxlen=8)
        self._oscillation_detected = 0
        self._random_move_cooldown = 0
        self._last_oscillation_log = 0.0
        self._stuck_counter = 0
        # MINER-PACE-1: adaptive pacing state (see PACE_* constants).
        self._pace_backoff = 1.0
        self._pace_window = deque(maxlen=PACE_BUDGET + 200)
        self._pace_walls = deque(maxlen=PACE_WALL_WINDOW)
        self._pace_last_log = 0.0
        self._pace_last_rl_log = 0.0

        # CPU-TARGET-3: numpy D3QN when available (BLAS threads sized from the
        # CPU target; one core stays free below 95% so the websocket loop
        # keeps its latency), else the legacy pure-Python DQN.
        try:
            _nc = int(os.cpu_count() or 4)
        except (TypeError, ValueError):
            _nc = 4
        _tgt = _clamp_cpu_percent(cpu_percent if cpu_percent is not None else 50)
        self.dqn, self._agent_desc = make_agent(model_format, threads=(_nc if _tgt >= 95 else max(1, _nc - 1)))
        self.dqn.load()

        self.nav_task = None
        self.pending_ack = None
        self.heartbeat_task = None
        self.balance_task = None
        self.keepalive_task = None
        self.reconn_attempts = 0
        self.start_time = 0.0
        self.last_move_duration = 0.0
        self.pow_pending = False
        self.last_ping = 0.0
        self.last_message_time = time.time()
        self._last_sync_time = 0.0
        self._consecutive_wall_hits = 0
        self._sync_event = asyncio.Event()
        self._nav_start_time = 0.0
        self._last_move_time = 0.0
        self.prev_state = None
        self.prev_action = None
        self._train_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ai")
        self._pqc_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="pqc")
        self._train_task = None
        # CPU-TARGET-1: user-set CPU budget out of 100%. The governor
        # (_cpu_governor_loop) measures real process usage and scales USEFUL
        # work to approach it: PoW solver parallelism + DQN training
        # intensity. It never burns CPU for its own sake and never touches
        # the network pace budget (rate limits are enforced separately).
        try:
            _cores = int(os.cpu_count() or 4)
        except (TypeError, ValueError):
            _cores = 4
        self._cpu_cores = max(1, _cores)
        self._cpu_max_pow = max(1, min(8, self._cpu_cores - 1))
        self._pow_executor = ThreadPoolExecutor(max_workers=self._cpu_max_pow,
                                                thread_name_prefix="pow")
        # CPU-TARGET-3: worker processes (GIL bypass). proc_workers: None=auto
        # (cores-1 when >=3 cores), 0=off, N>=1=forced.
        if proc_workers is None:
            _auto = max(1, min(32, self._cpu_cores - 1))
            _pw = _auto if _auto >= 2 else 0
        else:
            _pw = max(0, int(proc_workers))
        self._pool = _ComputePool(_pw) if _pw >= 1 else None
        self._pool_task = None
        self._cpu_below_hinted = False
        if self._pool is not None:
            self._cpu_max_pow = max(self._cpu_max_pow, self._pool.workers)
        self.cpu_percent = _clamp_cpu_percent(
            cpu_percent if cpu_percent is not None else 50)
        self._cpu_intensity = 0.5
        self._cpu_last = None
        self._cpu_last_log = 0.0
        self._cpu_actual = 0.0
        self._cpu_task = None

    async def connect(self, url=None):
        if url is None:
            url = self.node_url
        if not url:
            log(f"No node URL to connect to", "error", "net0")
            return False
        try:
            start = time.time()
            self.ws = await websockets.connect(url, ping_interval=20, ping_timeout=60,
                                                open_timeout=30, close_timeout=20, max_size=2**24)
            self.node_url = url
            self.reconn_attempts = 0
            # RECONNECT-RACE-1: fresh socket — no stale move loop may use it.
            self._stop_navigate("connect")
            log(f"{_c(GRN, 'Connected')} to {_c(CYN, url)} (miner {self.miner_id[-8:]})", "info", "net0")
            self.last_ping = (time.time() - start) * 1000
            return True
        except Exception as e:
            log(f"{_c(RED, 'Connect failed')} for {self.miner_id[-8:]}: {e}", "error", "net0")
            return False

    def _stop_navigate(self, why: str):
        # RECONNECT-RACE-1: the navigate loop owns move sends/recvs on
        # self.ws. A stale loop racing a fresh socket breaks registration
        # (pre-auth moves rejected; recv stealing) and double-drives moves.
        # Stop it before any (re)connect/(re)register/disconnect; the
        # maze_init handler restarts exactly one loop after auth.
        try:
            _nt = getattr(self, "nav_task", None)
            if _nt is not None and not _nt.done():
                _nt.cancel()
        except Exception:
            pass

    async def disconnect(self):
        self._stop_navigate("disconnect")
        if self.ws:
            try:
                await self.ws.close()
            except (websockets.exceptions.ConnectionClosed, OSError):
                pass
            self.ws = None

    async def register(self):
        # RECONNECT-RACE-1: no move loop may run while (re)authenticating.
        self._stop_navigate("register")
        ts = int(time.time())
        sig = sign_message(self.privkey, f"{self.miner_id}{self.wallet}{ts}")
        payload = {
            "type": "register", "miner_id": self.miner_id, "wallet": self.wallet,
            "public_key": self.pubkey, "signature": sig, "timestamp": ts,
            "miner_type": "pc", "maze_id": self.maze_id,
            # IDEA5-MAZE-KEY-BINDING-1: blocks are signed with the maze key, so
            # register the maze pub as the block-signing key (the identity pub
            # stays in public_key for the register signature / wallet binding).
            "block_signing_pub": self.mazepub,
            "pqc_pub": self.pqc_pub.hex() if self.pqc_pub else "",
        }
        try:
            await self.ws.send(json.dumps(payload))
            data = None
            t0 = time.time()
            while time.time() - t0 < 30:
                raw = await asyncio.wait_for(self.ws.recv(), timeout=30 - (time.time() - t0))
                cand = json.loads(raw)
                ct = cand.get("type", "")
                if ct in ("memory_challenge_request", "registered", "registration_failed"):
                    data = cand
                    break
                elif ct == "maze_init":
                    data = cand
                    break
                else:
                    continue
            if data is None:
                raise TimeoutError("no registration response")
        except Exception as e:
            log(f"{_c(RED, 'Registration error')} for {self.miner_id[-8:]}: {e}", "error", "net0")
            return False

        if data.get("type") == "maze_init":
            self.registered = True
            log(f"{_c(GRN, 'Registered')} (maze init received during registration)", "info", "sys0")
            await self.handle_message(data)
            asyncio.create_task(self.fetch_balance())
            return True

        if data.get("type") == "registered":
            self.registered = True
            self.balance = data.get("confirmed_balance", 0)
            self.difficulty = data.get("difficulty", 1.0)
            log(f"{_c(GRN, 'Registered')} {self.miner_id[-8:]}  Balance: {_c(YLW, str(self.balance//1_000_000)+' MCX')}  Diff: {_c(CYN, str(self.difficulty))}", "info", "sys0")
            asyncio.create_task(self.fetch_balance())
            return True

        if data.get("type") == "registration_failed":
            err = data.get("error", "unknown")
            log(f"{_c(RED, 'Registration REJECTED by node')}: {err}", "error", "net0")
            return False

        if data.get("type") == "memory_challenge_request":
            seed = base64.b64decode(data["seed"])
            mem_size = min(int(data.get("memory_size", 8 * 1024 * 1024)), 64 * 1024 * 1024)
            log(f"{_c(YLW, 'Memory challenge')} ({mem_size//1024//1024} MB)...", "info", "sys0")
            h = hashlib.sha256()
            counter = 0
            while h.digest_size * counter < mem_size:
                h.update(hashlib.sha256(seed + counter.to_bytes(8, "big")).digest())
                counter += 1
            commitment = h.digest()
            await self.ws.send(json.dumps({
                "type": "memory_challenge_response", "miner_id": self.miner_id,
                "seed": data["seed"], "commitment": base64.b64encode(commitment).decode()
            }))
            deadline_loop = time.time() + 60
            while time.time() < deadline_loop:
                try:
                    raw = await asyncio.wait_for(self.ws.recv(), timeout=deadline_loop - time.time())
                except asyncio.TimeoutError:
                    log(f"{_c(RED, 'Registration timed out after challenge')}", "error", "net0")
                    return False
                final_data = json.loads(raw)
                ft = final_data.get("type")
                if ft == "maze_init":
                    self.registered = True
                    log(f"{_c(GRN, 'Registered')} (in round, maze init received)", "info", "sys0")
                    await self.handle_message(final_data)
                    asyncio.create_task(self.fetch_balance())
                    return True
                elif ft == "registered":
                    self.registered = True
                    self.balance = final_data.get("confirmed_balance", 0)
                    self.difficulty = final_data.get("difficulty", 1.0)
                    log(f"{_c(GRN, 'Registered')}  Balance: {_c(YLW, str(self.balance//1_000_000)+' MCX')}", "info", "sys0")
                    asyncio.create_task(self.fetch_balance())
                elif ft == "registration_failed":
                    log(f"{_c(RED, 'Registration failed after challenge')}", "error", "net0")
                    return False
                elif ft == "error":
                    log(f"{_c(RED, 'NODE ERROR')}: {final_data.get('message')}", "error", "net0")
                    return False
            log(f"{_c(RED, 'Registration failed')}: no maze_init after registered", "error", "net0")
            return False
        log(f"{_c(RED, 'Unexpected registration response')}", "error", "net0")
        return False

    async def fetch_balance(self):
        if self.ws and self.registered:
            try:
                await self.ws.send(json.dumps({"type": "get_balance", "wallet": self.wallet}))
            except (websockets.exceptions.ConnectionClosed, OSError):
                pass

    async def balance_fetch_loop(self):
        while self.running:
            await asyncio.sleep(BALANCE_FETCH_INTERVAL)
            if self.registered and self.ws:
                await self.fetch_balance()

    async def request_state_sync(self):
        if self.ws is None or not self.registered:
            return
        now = time.time()
        if now - self._last_sync_time < STATE_SYNC_COOLDOWN:
            return
        self._last_sync_time = now
        try:
            await self.ws.send(json.dumps({"type": "get_maze_state", "miner_id": self.miner_id, "maze_id": self.maze_id}))
        except (websockets.exceptions.ConnectionClosed, OSError):
            pass

    async def _request_state_sync_wait(self):
        if self.ws is None or not self.registered:
            return
        self._sync_event.clear()
        try:
            self._last_sync_time = time.time()
            await self.ws.send(json.dumps({"type": "get_maze_state", "miner_id": self.miner_id, "maze_id": self.maze_id}))
            await asyncio.wait_for(self._sync_event.wait(), timeout=MOVE_TIMEOUT)
        except asyncio.TimeoutError:
            log(f"State sync timed out for {self.miner_id[-8:]}", "warning", "net0")
        except Exception as e:
            log(f"State sync error for {self.miner_id[-8:]}: {e}", "warning", "net0")

    async def solve_pow_async(self, seed, difficulty):
        loop = asyncio.get_event_loop()
        # CPU-TARGET-1: parallel nonce search across the PoW executor; the
        # worker count follows governor intensity (more target CPU = more
        # threads = faster wall solves = shorter stalls).
        # CPU-TARGET-2: the same intensity throttles sustained draw (duty),
        # so a 1% target converges instead of burning a full core per worker.
        try:
            _inten = min(max(float(getattr(self, "_cpu_intensity", 0.0)), 0.0), 1.0)
        except Exception:
            _inten = 0.0
        try:
            _w = _pow_worker_count(_inten, getattr(self, "_cpu_max_pow", 1))
        except Exception:
            _w = 1
        try:
            _pool = getattr(self, "_pool", None)
            if (_pool is not None and _pool.usable() and _inten >= 0.2
                    and safe_int(difficulty, 0) >= POW_POOL_MIN_DIFFICULTY):
                try:
                    _pw = _pow_worker_count(_inten, _pool.workers)
                    _r = await asyncio.wait_for(_pool.pow(seed, difficulty, _pw, 28.0), timeout=30)
                    if _r != -1:
                        return _r
                except asyncio.TimeoutError:
                    raise
                except Exception as _e:
                    log(f"PoW worker pool failed ({type(_e).__name__}) — falling back to threads", "warning", "net0")
            if _w <= 1 and _inten >= 1.0:
                # Full throttle, one worker: exact legacy path.
                return await asyncio.wait_for(loop.run_in_executor(None, solve_pow, seed, difficulty), timeout=30)
            return await asyncio.wait_for(
                loop.run_in_executor(None, solve_pow_parallel, seed, difficulty,
                                     max(_w, 1), getattr(self, "_pow_executor", None), _inten),
                timeout=30)
        except asyncio.TimeoutError:
            log(f"PoW timed out (diff={difficulty})", "warning", "net0")
            return -1

    def _cpu_step(self, pct) -> float:
        """One governor adjustment (proportional, CPU-TARGET-3): moves the
        intensity by 0.6 x relative error, clamped to [-0.30, +0.20] per tick,
        +-5% deadband; result clamped [0,1]. Returns the intensity.
        Pure apart from attribute reads/writes; unit-testable."""
        try:
            target = float(getattr(self, "cpu_percent", 50))
            inten = float(getattr(self, "_cpu_intensity", 0.5))
        except (TypeError, ValueError):
            return float(getattr(self, "_cpu_intensity", 0.5))
        if pct is None:
            return inten
        try:
            pct = float(pct)
        except (TypeError, ValueError):
            return inten
        # CPU-TARGET-3: proportional control (relative error, +-5% deadband).
        # Fixed +0.10/-0.15 steps took ~20s+ to move and could not follow a
        # continuous knob (training batch/duty).
        err = (target - pct) / max(target, 5.0)
        if abs(err) > 0.05:
            inten = min(1.0, max(0.0, inten + max(-0.30, min(0.20, 0.6 * err))))
        self._cpu_intensity = inten
        return inten

    async def _cpu_governor_loop(self):
        """CPU-TARGET-1: every 2s, measure process CPU% and nudge intensity
        toward the user target (deadband +-10%): below -> +0.10, above ->
        -0.15. Intensity drives PoW parallelism and training rate live.
        Logs actual-vs-target at most once a minute."""
        while self.running:
            try:
                await asyncio.sleep(2.0)
                if not self.running:
                    break
                _pool = getattr(self, "_pool", None)
                cur = _cpu_sample(_pool.cpu_seconds() if _pool is not None else 0.0)
                pct = _cpu_pct(getattr(self, "_cpu_last", None), cur,
                               getattr(self, "_cpu_cores", 1))
                self._cpu_last = cur
                if pct is None:
                    continue
                self._cpu_actual = pct
                _prev = getattr(self, "_cpu_ema", None)
                self._cpu_ema = pct if _prev is None else 0.5 * pct + 0.5 * _prev   # CPU-TARGET-3: smooth bursty samples
                inten = self._cpu_step(self._cpu_ema)
                now = time.time()
                if now - getattr(self, "_cpu_last_log", 0.0) > 30.0:
                    self._cpu_last_log = now
                    try:
                        _w = _pow_worker_count(inten, getattr(self, "_cpu_max_pow", 1))
                        _t = float(getattr(self, "cpu_percent", 50))
                    except Exception:
                        _w, _t = 1, 50.0
                    _pu = bool(_pool is not None and _pool.usable())
                    log(f"CPU {pct:.0f}% / target {_t:.0f}% (intensity {inten:.2f}, "
                        f"PoW x{_w}{' procs' if _pu else ' threads'}, train batch {self._train_batch(inten)})",
                        "info", "sys0")
                    if inten >= 0.99 and pct < _t * 0.85 and not getattr(self, "_cpu_below_hinted", False):
                        self._cpu_below_hinted = True
                        log(f"CPU is below target at max intensity ({pct:.0f}% < {_t:.0f}%): the miner is paced by the "
                            f"node's rate limits, so there is only so much useful work to do. "
                            f"{'' if isinstance(self.dqn, D3QNAgent) else 'Install numpy (pip install numpy) for multi-core D3QN training. '}"
                            f"Raising the target further will not add useful work.", "info", "sys0")
            except (asyncio.CancelledError, GeneratorExit):
                break
            except Exception:
                continue

    def _pace_distances(self):
        """(goal_dist, ghost_dist): Manhattan distances from current, or
        None when the endpoint is unknown. Pure; unit-testable."""
        try:
            cur = tuple(self.current) if self.current else None
        except (TypeError, ValueError):
            cur = None
        if cur is None or len(cur) != 3:
            return None, None
        goal_d = None
        try:
            if self.goal and len(self.goal) == 3:
                goal_d = (abs(cur[0] - self.goal[0]) + abs(cur[1] - self.goal[1])
                          + abs(cur[2] - self.goal[2]))
        except (TypeError, ValueError):
            goal_d = None
        ghost_d = None
        try:
            if self.ghost and len(self.ghost) == 3:
                ghost_d = (abs(cur[0] - self.ghost[0]) + abs(cur[1] - self.ghost[1])
                           + abs(cur[2] - self.ghost[2]))
        except (TypeError, ValueError):
            ghost_d = None
        return goal_d, ghost_d

    def _adaptive_pace(self) -> float:
        """Inter-move delay in seconds for the next maze_move.

        Three layers, cheapest first: (1) rolling client-side budget guard
        mirroring the server's 1200/60s window with margin — over budget
        returns a long recheck delay; (2) the pricier of urgency vs cost:
        urgency from goal/ghost closeness (far goal + no ghost = brisk;
        final steps or ghost on our tail = deliberate), cost from the
        recent wall-hit fraction (each wall hit costs an extra solve
        request, so wall-dense zones pace slower to hold combined
        requests/sec under PACE_TARGET_RPS); both scaled by (3) the AIMD
        backoff multiplier from observed rejections. Pure apart from
        time.time(); unit-testable."""
        now = time.time()
        q = self._pace_window
        while q and now - q[0] > PACE_WINDOW_S:
            q.popleft()
        if len(q) >= PACE_BUDGET:
            return 1.0
        try:
            size = int(self.size or 0)
        except (TypeError, ValueError):
            size = 0
        goal_d, ghost_d = self._pace_distances()
        # Goal urgency: hurry across open distance, take the final steps
        # carefully (a wall-hit PoW stall next to the goal hands the ghost
        # time to close in).
        if goal_d is None or size <= 0:
            f_goal = 1.0
        elif goal_d <= 3:
            f_goal = 1.6
        elif goal_d <= size:
            f_goal = 1.0
        else:
            f_goal = 0.75
        # Ghost urgency: no ghost = brisk; distant = normal; closing in =
        # deliberate (each move is re-evaluated, don't blunder into it).
        if ghost_d is None:
            f_ghost = 0.9
        elif ghost_d <= 2:
            f_ghost = 2.0
        elif ghost_d <= 6:
            f_ghost = 1.5
        else:
            f_ghost = 1.0
        try:
            backoff = float(self._pace_backoff)
        except (TypeError, ValueError):
            backoff = 1.0
        if not 1.0 <= backoff <= PACE_BACKOFF_MAX:
            backoff = min(max(backoff, 1.0), PACE_BACKOFF_MAX)
        # Real per-iteration cost: 1 request per move + ~1 extra per wall
        # hit (the solve). Hold cost/delay under PACE_TARGET_RPS no matter
        # how urgent the game state is.
        try:
            _walls = list(self._pace_walls)
            wall_frac = (sum(_walls) / len(_walls)) if _walls else 0.0
        except (TypeError, ValueError, AttributeError):
            wall_frac = 0.0
        cost_factor = 1.0 + max(0.0, min(wall_frac, 1.0))
        urgency_part = PACE_BASE_DELAY * backoff * f_goal * f_ghost
        cost_part = cost_factor * backoff / PACE_TARGET_RPS
        delay = min(max(max(urgency_part, cost_part), PACE_MIN_DELAY), PACE_MAX_DELAY)
        if delay >= 0.3 and now - self._pace_last_log > 60.0:
            self._pace_last_log = now
            log(f"Pacing moves at {delay:.2f}s (goal_d={goal_d} ghost_d={ghost_d} backoff={backoff:.1f} wall_frac={wall_frac:.2f})",
                "info", "pog0")
        return delay

    def _note_wall_hit(self):
        """A wall hit costs an extra solve request — record it so the cost
        model slows wall-dense zones. Capped deque, never raises."""
        try:
            self._pace_walls.append(1)
        except (AttributeError, TypeError):
            pass

    def _note_clean_move(self):
        """A move with no wall hit — record it for the cost model."""
        try:
            self._pace_walls.append(0)
        except (AttributeError, TypeError):
            pass

    def _note_rate_limited(self):
        """AIMD decrease: a server 429 doubles the pacing backoff (capped).
        Throttled warning so a sustained limit doesn't spam the log."""
        try:
            self._pace_backoff = min(PACE_BACKOFF_MAX, float(self._pace_backoff) * 2.0)
        except (TypeError, ValueError):
            self._pace_backoff = 2.0
        now = time.time()
        if now - self._pace_last_rl_log > 30.0:
            self._pace_last_rl_log = now
            log(f"{_c(YLW, 'Node rate limit hit')} — backing off to ~{PACE_BASE_DELAY * self._pace_backoff:.2f}s/move",
                "warning", "net0")

    def _note_move_rejected(self):
        """Any non-429 rejection (wall/out-of-bounds/nonce/signature):
        the move still consumed budget, and rejects arrive in bursts while
        the local view is stale — bump the backoff mildly so reject loops
        self-throttle instead of spinning at pace speed into a resync
        storm. Sized (+0.1) against the 0.97 accept-decay so mixed
        exploration (~30% rejects) equilibrates near ~1.4, while genuine
        thrash (50%+) still climbs hard. Accepted moves decay it back."""
        try:
            self._pace_backoff = min(PACE_BACKOFF_MAX, float(self._pace_backoff) + 0.1)
        except (TypeError, ValueError):
            self._pace_backoff = 1.1

    def _note_move_accepted(self):
        """AIMD increase: each accepted move recovers a little backoff."""
        try:
            self._pace_backoff = max(1.0, float(self._pace_backoff) * 0.97)
        except (TypeError, ValueError):
            self._pace_backoff = 1.0

    def _train_batch(self, inten) -> int:
        """Batch size follows governor intensity: D3QN 64..4096 (numpy matmuls
        release the GIL and BLAS spreads them across cores); legacy pure-Python
        DQN 32..96 (it is single-threaded, so cost grows linearly)."""
        try:
            f = min(max(float(inten), 0.0), 1.0)
        except (TypeError, ValueError):
            f = 0.0
        if isinstance(self.dqn, D3QNAgent):
            return int(64 + f * (4096 - 64))
        return int(32 + f * 64)

    def _train_loop(self):
        """CPU-TARGET-3: trains in bursts, then idles to hold a duty cycle equal
        to the governor intensity (busy fraction of wall time). The governor
        closes the loop on measured whole-process CPU, so the slider moves the
        real usage. Saves at most every 30 s."""
        _last_save = time.time()
        while self.running:
            _did = False
            _busy = 0.0
            try:
                try:
                    _inten = min(max(float(getattr(self, "_cpu_intensity", 0.0)), 0.0), 1.0)
                except (TypeError, ValueError):
                    _inten = 0.0
                _bs = self._train_batch(_inten)
                _t0 = time.perf_counter()
                if isinstance(self.dqn, D3QNAgent):
                    for _ in range(1 + int(_inten * 3)):
                        if not self.running:
                            break
                        if self.dqn.replay(_bs):
                            _did = True
                else:
                    self.dqn.batch_size = _bs
                    if len(self.dqn.memory) >= self.dqn.batch_size:
                        for _ in range(1 + int(_inten * 3)):
                            self.dqn.replay()
                            _did = True
                            if not self.running:
                                break
                _busy = time.perf_counter() - _t0
                if time.time() - _last_save > 30.0:
                    _last_save = time.time()
                    self.dqn.save()
            except (websockets.exceptions.ConnectionClosed, OSError, json.JSONDecodeError) as e:
                log(f"Training error: {e}", "warning", "dqn0")
            except Exception as e:
                log(f"Training step failed: {type(e).__name__}: {e}", "warning", "dqn0")
                time.sleep(1.0)
            _duty = max(0.02, min(1.0, _inten))
            _sleep = (_busy * (1.0 - _duty) / _duty) if _did else 0.5
            time.sleep(min(max(_sleep, 0.005), 4.0))

    async def _deep_plan_upgrade(self, dir_idx, method, known, forbidden):
        """CPU-TARGET-3: when the fast inline A*/BFS (10k/5k node budgets) could
        only produce a partial or heuristic move, ask the worker pool for a deep
        plan (A* up to 400k nodes, then a big BFS) off the event loop. Waits
        <= 0.35 s; the answer is used only if it is a legal, non-wall move."""
        try:
            pool = getattr(self, "_pool", None)
            inten = min(max(float(getattr(self, "_cpu_intensity", 0.0)), 0.0), 1.0)
            if (pool is None or not pool.usable() or inten < 0.25
                    or method not in ("bfs", "heuristic", "random", "random_fallback")
                    or self.current is None or self.goal is None or self.current == self.goal):
                return dir_idx, method
            budget = int(10_000 + inten * (DEEP_PLAN_MAX_NODES - 10_000))
            res = await asyncio.wait_for(
                pool.deep_plan(self.maze, self.current, self.goal, self.ghost,
                               known or (), forbidden or (), budget), timeout=0.35)
        except Exception:
            return dir_idx, method
        if not res:
            return dir_idx, method
        idx, _plen, kind = res
        if not (kind == "astar" or method in ("heuristic", "random", "random_fallback")):
            return dir_idx, method
        valid = get_valid_actions(self.maze, self.current, self.size)
        if idx not in valid:
            return dir_idx, method
        dx, dy, dz = DIR_OFFSETS[idx]
        nxt = (self.current[0] + dx, self.current[1] + dy, self.current[2] + dz)
        if (known and nxt in known) or (forbidden and nxt in forbidden and len(valid) > 1):
            return dir_idx, method
        return idx, "deep_" + kind

    def start_training(self):
        self._train_task = asyncio.get_event_loop().run_in_executor(self._train_executor, self._train_loop)

    async def navigate(self):
        if self.maze is None or self.current is None or self.goal is None:
            return
        if self._train_task is None:
            self.start_training()
        if self.current == self.goal:
            log(f"Start == goal ({self.current}), waiting for new state", "warning", "pog0")
            await asyncio.sleep(5)
            return

        self.steps = 0
        self.accepted = 0
        self.attempts = 0
        self.local_walls.clear()
        self.start_time = time.time()
        self._nav_start_time = time.time()
        self._last_move_time = time.time()
        self.pow_pending = False
        self._stuck_counter = 0
        self._consecutive_wall_hits = 0
        self.needs_reinit = False

        if self._last_logged_block != self.block_id:
            self._last_logged_block = self.block_id
            log(f"Mining Block #{self.block_id} | Size: {self.size}³ | Miner: {self.miner_id[-8:]}", "info", "pog0")

        try:
            await self._navigate_loop()
        except Exception as e:
            log(f"{_c(RED, 'Navigate crashed')}: {e}", "error", "pog0")

    async def _navigate_loop(self):
        consecutive_timeouts = 0
        last_report_time = time.time()

        while True:
            if not self.ws:
                break

            if self.pow_pending:
                await asyncio.sleep(0.1)
                continue

            now = time.time()

            known = self.local_walls
            forbidden_positions = set()
            is_oscillating = False

            if len(self._pos_history) >= 4:
                a, b, c, d = list(self._pos_history)[-4:]
                if a == c and b == d and a != b:
                    is_oscillating = True
                    forbidden_positions.add(a)

            if not is_oscillating and len(self._pos_history) >= 6:
                p1, p2, p3, p4, p5, p6 = list(self._pos_history)[-6:]
                if p1 == p4 and p2 == p5 and p3 == p6 and len({p1, p2, p3}) == 3:
                    is_oscillating = True
                    forbidden_positions.add(p4)

            if is_oscillating:
                self._oscillation_detected += 1
                if self._oscillation_detected >= 2:
                    now_ts = time.time()
                    if now_ts - self._last_oscillation_log > 5.0:
                        log(f"{_c(YLW, 'Oscillation cycle detected')} at {self.current} — forcing random moves", "warning", "pog0")
                        self._last_oscillation_log = now_ts
                    self._random_move_cooldown = 8
                    self._oscillation_detected = 0
            else:
                self._oscillation_detected = 0
            if self.current == getattr(self, "_last_probe_pos", None):
                self._same_pos_count = getattr(self, "_same_pos_count", 0) + 1
            else:
                self._same_pos_count = 0
            self._last_probe_pos = self.current
            if self._same_pos_count >= 20:
                log(f"Position unchanged for {self._same_pos_count} iterations at {self.current} — full state resync", "warning", "pog0")
                self._same_pos_count = 0
                self._random_move_cooldown = 0
                self._oscillation_detected = 0
                self.local_walls.clear()
                self._pos_history.clear()
                await self._request_state_sync_wait()
                continue

            
            if self._random_move_cooldown > 0:
                self._random_move_cooldown -= 1
                dir_idx = random_valid_move(self.maze, self.current, set(), forbidden_positions)
                if dir_idx == -1:
                    dir_idx = random_valid_move(self.maze, self.current, set())
                if dir_idx == -1:
                    await asyncio.sleep(0.1)
                    continue
                method = "anti_oscillation_random"
            else:
                dir_idx, method = hybrid_move(
                    self.maze, self.current, self.goal, self.ghost,
                    self.size, self.dqn, known_walls=known,
                    visited_recent=set(self._visited_recent),
                    forbidden_positions=forbidden_positions
                )
                dir_idx, method = await self._deep_plan_upgrade(dir_idx, method, known, forbidden_positions)

            if dir_idx == -1:
                self._stuck_counter += 1
                free_move = random_valid_move(self.maze, self.current, set(), forbidden_positions)
                if free_move != -1:
                    if self._stuck_counter >= STUCK_THRESHOLD:
                        log(f"Stuck for {self._stuck_counter} moves at {self.current} — resyncing", "warning", "pog0")
                        self._stuck_counter = 0
                        await self._request_state_sync_wait()
                        known = self.local_walls
                        dir_idx = random_valid_move(self.maze, self.current, known, forbidden_positions)
                        if dir_idx == -1:
                            dir_idx = free_move
                            self.local_walls.clear()
                        method = "stuck_resync"
                    else:
                        dir_idx = free_move
                        method = "trapped_random"
                else:
                    log(f"Fully trapped at {self.current} — resyncing", "warning", "pog0")
                    await self._request_state_sync_wait()
                    known = self.local_walls
                    dir_idx = random_valid_move(self.maze, self.current, known, forbidden_positions)
                    if dir_idx == -1:
                        dir_idx = random_valid_move(self.maze, self.current, set())
                    if dir_idx == -1:
                        await asyncio.sleep(0.5)
                        continue
                    method = "trapped_resync"
            else:
                self._stuck_counter = 0

            direction = DIR_NAMES[dir_idx]
            step = self.steps + 1
            dx, dy, dz = DIR_OFFSETS[dir_idx]
            next_pos = (self.current[0] + dx, self.current[1] + dy, self.current[2] + dz)

            if not (0 <= next_pos[0] < self.size and 0 <= next_pos[1] < self.size and 0 <= next_pos[2] < self.size):
                await self.request_state_sync()
                await asyncio.sleep(0.1)
                continue

            self._visited_recent.append(self.current)
            self.prev_state = extract_dqn_state(self.maze, self.current, self.goal, self.ghost, self.size)
            self.prev_action = dir_idx
            self.attempts += 1
            self.total_attempted_moves += 1
            self.pending_ack = asyncio.get_event_loop().create_future()

            move_nonce = self.movenonce + 1
            auth_msg = canonical_json_bytes({
                "domain": "MCXPOGMOVEV1", "chainid": CHAIN_ID,
                "minerid": self.miner_id, "mazeid": self.maze_id,
                "mazeversion": self.growthcount, "movenonce": move_nonce,
                "direction": direction,
            })
            loop = asyncio.get_event_loop()
            sig = await loop.run_in_executor(None, sign_bytes, self.privkey, auth_msg)
            self.sent_nonce = move_nonce

            payload = {
                "type": "maze_move", "miner_id": self.miner_id, "maze_id": self.maze_id,
                "direction": direction, "signature": sig, "move_nonce": move_nonce,
            }

            ping_start = time.time()
            try:
                if not self.ws:
                    break
                # MINER-PACE-1: adaptive inter-move delay (goal/ghost
                # urgency + AIMD backoff + budget guard) before every send.
                pace = self._adaptive_pace()
                if pace > 0:
                    await asyncio.sleep(pace)
                if not self.ws:
                    break
                await self.ws.send(json.dumps(payload))
                try:
                    self._pace_window.append(time.time())
                except (AttributeError, TypeError):
                    pass
                ack = await asyncio.wait_for(self.pending_ack, timeout=MOVE_TIMEOUT)
                self.last_ping = (time.time() - ping_start) * 1000

                if ack.get("type") == "wall_hit":
                    seed = ack["seed"]
                    difficulty = ack.get("difficulty", POW_DIFFICULTY)
                    # MINER-PACE-1: a wall hit costs an extra solve request —
                    # feed the cost model so wall-dense zones pace slower.
                    self._note_wall_hit()
                    if ack.get("ghost") and self.size > 5:
                        self.ghost = tuple(ack["ghost"])
                    elif self.size <= 5:
                        self.ghost = None
                    if ack.get("position"):
                        self.current = tuple(ack["position"])
                    if ack.get("size") is not None:
                        self.size = safe_int(ack["size"], self.size)
                    if ack.get("movenonce") is not None:
                        self.movenonce = safe_int(ack["movenonce"], self.movenonce)
                    if ack.get("growthcount") is not None:
                        self.growthcount = safe_int(ack["growthcount"], self.growthcount)
                    self.pow_pending = True
                    nonce = await self.solve_pow_async(seed, difficulty)
                    if nonce == -1:
                        self.pow_pending = False
                        continue
                    self.pending_ack = asyncio.get_event_loop().create_future()
                    if not self.ws:
                        break
                    await self.ws.send(json.dumps({
                        "type": "wall_hit_solve", "miner_id": self.miner_id,
                        "maze_id": self.maze_id, "nonce": nonce
                    }))
                    try:
                        self._pace_window.append(time.time())
                    except (AttributeError, TypeError):
                        pass
                    sol_ack = await asyncio.wait_for(self.pending_ack, timeout=MOVE_TIMEOUT)
                    if sol_ack.get("accepted"):
                        self.pow_pending = False
                        caught = sol_ack.get("caught", False)
                        wall_pos = (self.current[0] + dx, self.current[1] + dy, self.current[2] + dz)
                        wx, wy, wz = wall_pos
                        if self.maze and 0 <= wz < self.size and 0 <= wy < self.size and 0 <= wx < self.size:
                            self.maze[wz][wy][wx] = 1
                        self.local_walls.add(wall_pos)
                        self._consecutive_wall_hits += 1
                        self.total_walls_solved += 1
                        if sol_ack.get("sealed_walls"):
                            for w in sol_ack["sealed_walls"]:
                                if len(w) == 3:
                                    wx, wy, wz = safe_int(w[0]), safe_int(w[1]), safe_int(w[2])
                                    self.local_walls.add((wx, wy, wz))
                                    if self.maze and 0 <= wz < self.size and 0 <= wy < self.size and 0 <= wx < self.size:
                                        self.maze[wz][wy][wx] = 1
                        if sol_ack.get("ghost"):
                            self.ghost = tuple(sol_ack["ghost"])
                        if sol_ack.get("position"):
                            self.current = tuple(sol_ack["position"])
                            self._pos_history.append(self.current)
                        if sol_ack.get("goal"):
                            self.goal = tuple(sol_ack["goal"])
                        if sol_ack.get("size") is not None:
                            self.size = safe_int(sol_ack["size"], self.size)
                        if sol_ack.get("movenonce") is not None:
                            self.movenonce = safe_int(sol_ack["movenonce"], self.movenonce)
                        if sol_ack.get("growthcount") is not None:
                            self.growthcount = safe_int(sol_ack["growthcount"], self.growthcount)
                        if caught:
                            log(f"{_c(RED, 'Ghost caught during PoW!')} Maze shrunk to {self.size}\u00b3", "warning", "pog0")
                            self._reset_state()
                            if self.nav_task and not self.nav_task.done():
                                self.nav_task.cancel()
                            self.nav_task = asyncio.create_task(self.navigate())
                            continue
                        if self._consecutive_wall_hits % 10 == 0 or self._consecutive_wall_hits <= 3:
                            log(f"Wall #{self._consecutive_wall_hits} solved", "info", "pog0")
                        self._stuck_counter = 0
                        if self._consecutive_wall_hits >= 5:
                            log(f"{self._consecutive_wall_hits} walls — resyncing state", "warning", "pog0")
                            await self._request_state_sync_wait()
                            self._consecutive_wall_hits = 0
                    else:
                        self.pow_pending = False
                        # MINER-PACE-1: a rate-limited solve still burns
                        # budget — back off so the next moves slow down.
                        try:
                            _sol_err = str(sol_ack.get("error", "") or "").lower()
                        except (AttributeError, TypeError, ValueError):
                            _sol_err = ""
                        if "rate limit" in _sol_err:
                            self._note_rate_limited()
                    continue

                if ack.get("success"):
                    self.steps = step
                    self.accepted += 1
                    self.total_accepted_moves += 1
                    consecutive_timeouts = 0
                    self._note_move_accepted()
                    self._note_clean_move()
                    self._consecutive_wall_hits = 0
                    self._stuck_counter = 0
                    # too many steps without hitting the goal, resync
                    max_steps = self.size ** 3 * 2
                    if self.steps > max_steps and self.steps % max_steps == 0:
                        log(f"{self.steps} steps without goal — resyncing", "warning", "pog0")
                        await self._request_state_sync_wait()
                    st = ack.get("state", {}) or {}
                    if st.get("movenonce") is not None:
                        self.movenonce = safe_int(st["movenonce"], self.movenonce)
                    else:
                        self.movenonce = self.sent_nonce
                    self.current = next_pos
                    self._pos_history.append(self.current)
                    caught = False

                    if ack.get("sealed_walls") and self.maze:
                        for w in ack["sealed_walls"]:
                            wx, wy, wz = safe_int(w[0]), safe_int(w[1]), safe_int(w[2])
                            if 0 <= wz < self.size and 0 <= wy < self.size and 0 <= wx < self.size:
                                self.maze[wz][wy][wx] = 1
                                self.local_walls.add((wx, wy, wz))
                        self._visited_recent.clear()
                    if st.get("opened_walls") and self.maze:
                        for w in st["opened_walls"]:
                            wx, wy, wz = safe_int(w[0]), safe_int(w[1]), safe_int(w[2])
                            if 0 <= wz < self.size and 0 <= wy < self.size and 0 <= wx < self.size:
                                self.maze[wz][wy][wx] = 0

                    if st.get("caught"):
                        caught = True
                        if ack.get("maze"):
                            self.maze = ack["maze"]
                        if ack.get("size") is not None:
                            self.size = safe_int(ack["size"], self.size)
                        if ack.get("start"):
                            self.current = tuple(ack["start"])
                        elif st.get("newspawn"):
                            self.current = tuple(st["newspawn"])
                        if ack.get("goal"):
                            self.goal = tuple(ack["goal"])
                        elif st.get("newgoal"):
                            self.goal = tuple(st["newgoal"])
                        if ack.get("growthcount") is not None:
                            self.growthcount = safe_int(ack["growthcount"], self.growthcount)
                        if ack.get("movenonce") is not None:
                            self.movenonce = safe_int(ack["movenonce"], self.movenonce)
                        if st.get("new_growthcount") is not None:
                            self.growthcount = safe_int(st["new_growthcount"], self.growthcount)
                        if st.get("new_movenonce") is not None:
                            self.movenonce = safe_int(st["new_movenonce"], self.movenonce)
                        if not self.maze or len(self.maze) != self.size:
                            await self.request_state_sync()
                            return
                        self.total_goals_reached += 1
                        self._reset_state()
                        if self.nav_task and not self.nav_task.done():
                            self.nav_task.cancel()
                        self.nav_task = asyncio.create_task(self.navigate())
                        return
                    else:
                        if st.get("goal"):
                            self.goal = tuple(st["goal"])
                        if st.get("newgoal"):
                            self.goal = tuple(st["newgoal"])
                            if st.get("newspawn"):
                                self.current = tuple(st["newspawn"])
                        if st.get("position"):
                            self.current = tuple(st["position"])

                    computetime = time.time() - (self._last_move_time or time.time())
                    self._last_move_time = time.time()
                    share_type = "goal" if caught else "accept"
                    move_log(self.miner_id, self.accepted, self.attempts, self.current, self.movenonce, computetime, self.last_ping, self.balance, share_type, method or "?")

                    if self.prev_state is not None:
                        reward = 10.0 if caught else -0.01
                        if not caught:
                            old_d = abs(self.prev_state[27]*10) + abs(self.prev_state[28]*10) + abs(self.prev_state[29]*10)
                            ns = extract_dqn_state(self.maze, self.current, self.goal, self.ghost, self.size)
                            new_d = abs(ns[27]*10) + abs(ns[28]*10) + abs(ns[29]*10)
                            reward += 0.5 if new_d < old_d else (-0.2 if new_d > old_d else 0)
                            if self.ghost:
                                gd = abs(self.ghost[0]-self.current[0]) + abs(self.ghost[1]-self.current[1]) + abs(self.ghost[2]-self.current[2])
                                if gd <= 2:
                                    reward -= 2.0
                        next_state = extract_dqn_state(self.maze, self.current, self.goal, self.ghost, self.size)
                        self.dqn.remember(self.prev_state, self.prev_action, reward, next_state, caught)
                else:
                    msg_lower = str(ack.get("message", "")).lower()
                    rejection_reason = ack.get("message", ack.get("type", "unknown"))
                    if "wall" in msg_lower:
                        wall_pos = (self.current[0] + dx, self.current[1] + dy, self.current[2] + dz)
                        wx, wy, wz = wall_pos
                        if self.maze and 0 <= wz < self.size and 0 <= wy < self.size and 0 <= wx < self.size:
                            self.maze[wz][wy][wx] = 1
                        self.local_walls.add(wall_pos)
                        # MINER-PACE-1: rejected moves count — map disagreement
                        # comes in bursts; throttle the retry loop mildly.
                        self._note_move_rejected()
                        self._consecutive_wall_hits += 1
                        if self._consecutive_wall_hits >= 3:
                            await self._request_state_sync_wait()
                        computetime = time.time() - (self._last_move_time or time.time())
                        move_log(self.miner_id, self.accepted, self.attempts, self.current, self.movenonce, computetime, self.last_ping, self.balance, "wall", method or "?")
                        if self.prev_state is not None:
                            ns = extract_dqn_state(self.maze, self.current, self.goal, self.ghost, self.size)
                            self.dqn.remember(self.prev_state, self.prev_action, -5.0, ns, False)
                    elif "out of bounds" in msg_lower:
                        log(f"Out of bounds at {next_pos} — resyncing", "warning", "pog0")
                        self._note_move_rejected()
                        await self.request_state_sync()
                        computetime = time.time() - (self._last_move_time or time.time())
                        move_log(self.miner_id, self.accepted, self.attempts, self.current, self.movenonce, computetime, self.last_ping, self.balance, "reject", method or "?")
                    elif "nonce" in msg_lower:
                        log(f"Nonce mismatch: {rejection_reason} — resyncing", "warning", "pog0")
                        # MINER-PACE-1: stale-nonce retries reject in a tight
                        # loop until the sync lands — throttle them.
                        self._note_move_rejected()
                        try:
                            await self._request_state_sync_wait()
                        except (websockets.exceptions.ConnectionClosed, OSError):
                            pass
                        computetime = time.time() - (self._last_move_time or time.time())
                        move_log(self.miner_id, self.accepted, self.attempts, self.current, self.movenonce, computetime, self.last_ping, self.balance, "reject", method or "?")
                    else:
                        log(f"Rejected: {rejection_reason}", "warning", "pog0")
                        # MINER-PACE-1: the node's "Rate limit exceeded"
                        # error arrives here — back off multiplicatively and
                        # yield, instead of resync-spinning into more 429s.
                        if "rate limit" in msg_lower:
                            self._note_rate_limited()
                            await asyncio.sleep(1.0)
                            continue
                        # Any other rejection still consumed budget — bump
                        # mildly so unknown-error loops self-throttle.
                        self._note_move_rejected()
                        computetime = time.time() - (self._last_move_time or time.time())
                        move_log(self.miner_id, self.accepted, self.attempts, self.current, self.movenonce, computetime, self.last_ping, self.balance, "reject", method or "?")
                        # sig or nonce mismatch, resync right away
                        if "signature" in str(rejection_reason).lower() or "nonce" in str(rejection_reason).lower():
                            await self._request_state_sync_wait()
                            self._stuck_counter = 0
                            continue
                        # rejected too many times, back off
                        self._stuck_counter += 1
                        if self._stuck_counter >= 5:
                            log(f"{self._stuck_counter} rejections — resyncing state", "warning", "pog0")
                            await self._request_state_sync_wait()
                            self._stuck_counter = 0
                            await asyncio.sleep(0.5)
                        else:
                            await asyncio.sleep(0.2)

            except asyncio.TimeoutError:
                consecutive_timeouts += 1
                if self.pending_ack and not self.pending_ack.done():
                    self.pending_ack.cancel()
                    self.pending_ack = None
                log(f"Move timeout #{consecutive_timeouts} for {self.miner_id[-8:]} — resyncing", "warning", "net0")
                try:
                    await self._request_state_sync_wait()
                except (websockets.exceptions.ConnectionClosed, OSError):
                    pass
                if consecutive_timeouts >= 5:
                    log(f"Persistent stall ({consecutive_timeouts} timeouts) — attempting recovery", "warning", "net0")
                    try:
                        if self.ws and self.ws.open:
                            await self.ws.close()
                    except Exception:
                        pass
                    self.ws = None
                    self.registered = False
                    self.round_active = False
                    self.needs_reinit = True
                    try:
                        await self.connect()
                        if await self.register():
                            await self.request_state_sync()
                            log(f"Recovery: re-registered with node", "success", "net0")
                            self._recovery_done = True
                    except Exception as e:
                        log(f"Recovery reconnect failed: {e}", "error", "net0")
                    return
                elif consecutive_timeouts >= 3:
                    await asyncio.sleep(1)
                else:
                    await asyncio.sleep(0.3)
            except Exception as e:
                log(f"Move error: {e}", "error", "pog0")
                self.pow_pending = False

            await asyncio.sleep(0.05)

        self.dqn.save()

    def _reset_state(self):
        self.local_walls.clear()
        self._visited_recent.clear()
        self._pos_history.clear()
        self._oscillation_detected = 0
        self._random_move_cooldown = 0
        self._stuck_counter = 0
        self._consecutive_wall_hits = 0
        self.ghost = None
        self.steps = 0
        self.accepted = 0
        self.attempts = 0
        self._last_move_time = time.time()
        self.pow_pending = False

    async def handle_message(self, data):
        self.last_message_time = time.time()
        msg_type = data.get("type")

        if msg_type == "maze_init":
            self.block_id = data["block_id"]
            self.size = data["size"]
            self.maze = data["maze"]
            self.start = tuple(data["start"])
            self.current = self.start
            self.goal = tuple(data["goal"])
            self.difficulty = data.get("difficulty", 1.0)
            self.round_active = True
            self.steps = 0
            self.accepted = 0
            self.attempts = 0
            self._reset_state()
            self.needs_reinit = False
            if data.get("growthcount") is not None:
                self.growthcount = safe_int(data["growthcount"], self.growthcount)
            if data.get("movenonce") is not None:
                self.movenonce = safe_int(data["movenonce"], self.movenonce)
            self.ghost = tuple(data["ghost"]) if data.get("ghost") and self.size > 5 else None
            if data.get("sealed_walls") and self.maze:
                for w in data["sealed_walls"]:
                    wx, wy, wz = safe_int(w[0]), safe_int(w[1]), safe_int(w[2])
                    if 0 <= wz < self.size and 0 <= wy < self.size and 0 <= wx < self.size:
                        self.maze[wz][wy][wx] = 1
            if data.get("opened_walls") and self.maze:
                for w in data["opened_walls"]:
                    wx, wy, wz = safe_int(w[0]), safe_int(w[1]), safe_int(w[2])
                    if 0 <= wz < self.size and 0 <= wy < self.size and 0 <= wx < self.size:
                        self.maze[wz][wy][wx] = 0
            await self.request_state_sync()
            if self.nav_task and not self.nav_task.done():
                self.nav_task.cancel()
            self.nav_task = asyncio.create_task(self.navigate())

        elif msg_type == "maze_state":
            state = data.get("state", {}) or {}
            for key in ("current", "position"):
                if state.get(key):
                    self.current = tuple(state[key])
            if state.get("goal"):
                self.goal = tuple(state["goal"])
            if state.get("block_id"):
                self.block_id = state["block_id"]
            if state.get("difficulty"):
                self.difficulty = state["difficulty"]
            if state.get("movenonce") is not None:
                self.movenonce = safe_int(state["movenonce"], self.movenonce)
            if state.get("growthcount") is not None:
                self.growthcount = safe_int(state["growthcount"], self.growthcount)
            if state.get("size") is not None:
                self.size = safe_int(state["size"], self.size)
            if state.get("ghost") and self.size > 5:
                self.ghost = tuple(state["ghost"])
            else:
                self.ghost = None
            if state.get("maze"):
                self.maze = state["maze"]
                self.size = state.get("size", self.size)
            self._sync_event.set()

        elif msg_type == "maze_move_ack":
            if self.pending_ack and not self.pending_ack.done():
                self.pending_ack.set_result(data)
            if data.get("success"):
                st = data.get("state", {}) or {}
                is_transition = st.get("caught") or st.get("shrink")
                if not is_transition:
                    for key in ("current", "position"):
                        if st.get(key):
                            self.current = tuple(st[key])
                    if st.get("newgoal"):
                        self.goal = tuple(st["newgoal"])
                        if st.get("newspawn"):
                            self.current = tuple(st["newspawn"])
                    if st.get("goal"):
                        self.goal = tuple(st["goal"])
                    if st.get("difficulty"):
                        self.difficulty = st["difficulty"]
                if data.get("ghost") and self.size > 5:
                    self.ghost = tuple(data["ghost"])
                elif self.size <= 5:
                    self.ghost = None
                if data.get("sealed_walls") and self.maze:
                    for w in data["sealed_walls"]:
                        wx, wy, wz = safe_int(w[0]), safe_int(w[1]), safe_int(w[2])
                        if 0 <= wz < self.size and 0 <= wy < self.size and 0 <= wx < self.size:
                            self.maze[wz][wy][wx] = 1
                if data.get("opened_walls") and self.maze:
                    for w in data["opened_walls"]:
                        wx, wy, wz = safe_int(w[0]), safe_int(w[1]), safe_int(w[2])
                        if 0 <= wz < self.size and 0 <= wy < self.size and 0 <= wx < self.size:
                            self.maze[wz][wy][wx] = 0
                if st.get("shrink") and st.get("newsize"):
                    log(f"{_c(RED, 'Ghost caught you!')} Maze shrunk to {st['newsize']}\u00b3", "warning", "pog0")
                    self.size = safe_int(st["newsize"], self.size)
                    if data.get("maze"):
                        self.maze = data["maze"]
                    if data.get("start"):
                        self.current = tuple(data["start"])
                    if data.get("goal"):
                        self.goal = tuple(data["goal"])
                    if data.get("movenonce") is not None:
                        self.movenonce = safe_int(data["movenonce"], self.movenonce)

        elif msg_type == "wall_hit" or msg_type == "wall_hit_solved":
            if self.pending_ack and not self.pending_ack.done():
                self.pending_ack.set_result(data)

        elif msg_type == "balance":
            old = self.balance
            self.balance = data.get("balance", 0)
            if self.initial_balance is None:
                self.initial_balance = self.balance
            if self.balance != old:
                log(f"Balance updated: {_c(YLW, f'{self.balance/1_000_000:,.6f} MCX')}", "info", "sys0")

        elif msg_type == "block_height_update":
            h = data.get("height")
            if h is not None:
                self.block_id = h
            # BLOCK-CONFIRM-1: reconcile a pending submission against node
            # truth (no invented ack type — height + balance are actual
            # server behavior). Confirmed blocks increment the mined
            # counter and booked earnings; orphaned/rejected ones never do.
            try:
                _upd_id = data.get("block_id", h)
                _cf, _cr = _reconcile_block_submission(
                    getattr(self, "_pending_block", None), _upd_id,
                    getattr(self, "balance", None))
            except Exception:
                _cf, _cr = None, "reconcile-error"
            if _cf is True:
                _pb = self._pending_block
                self._pending_block = None
                self.total_blocks_mined += 1
                self.total_mcx_earned += int(_pb.get("reward", 0))
                self.total_fees_earned += int(_pb.get("fees", 0))
                log(
                    f"{_c(GRN+BLD, '★ BLOCK CONFIRMED ★')} Block #{_pb.get('id')} "
                    f"accepted by node "
                    f"(session confirmed: {self.total_mcx_earned/1_000_000:.6f} MCX, "
                    f"blocks: {self.total_blocks_mined})",
                    "success", "sys0",
                )
            elif _cf is False:
                _pb = self._pending_block
                self._pending_block = None
                log(f"Block #{_pb.get('id')} NOT accepted by node ({_cr}) — "
                    f"not counted", "warning", "sys0")

        elif msg_type == "error":
            log(f"Node error: {data.get('message')}", "error", "sys0")
            if self.pending_ack and not self.pending_ack.done():
                self.pending_ack.set_result(data)

        elif msg_type == "peers":
            cache = _load_miner_peers()
            added = 0
            for p in (data.get("peers") or []):
                url = (p.get("url") or "").strip()
                if not url.startswith("ws") or url in cache:
                    continue
                cache[url] = {"last_seen": 0, "failures": 0, "node_id": p.get("node_id", "")}
                added += 1
            if added:
                _save_miner_peers(cache)
                log(f"Learned {added} new peer URL(s)", "info", "net0")

        elif msg_type == "produce_block":
            try:
                block = data.get("block") or {
                    "id": data.get("height"), "phash": data.get("prev_hash"),
                    "winner": self.miner_id, "miners": data.get("miners", []),
                    "tx_hashes": data.get("pending_txs", []),
                    "lottery_proof": data.get("lottery_proof", {}), "timestamp": time.time(), "nonce": 0,
                }
                # IDEA5-MAZE-KEY-BINDING-1: sign with the maze key so
                # producer_pub == attestation pubkey == maze_id.
                if not self.mazepriv or not self.mazepub:
                    log(f"{_c(RED, 'Cannot sign block: no maze key configured')}", "error", "sys0")
                    return
                block["producer_pub"] = self.mazepub
                block["hash"] = hashlib.sha256(canonical_json_bytes(
                    {k: v for k, v in block.items() if k not in ("hash", "signature", "pqc_signature", "finalized")}
                )).hexdigest()
                loop = asyncio.get_event_loop()
                block["signature"] = await loop.run_in_executor(None, sign_bytes, self.mazepriv, bytes.fromhex(block["hash"]))
                _att_sz = (block.get("maze_attestation") or {}).get("size", "?")
                log(f"[IDEA5-MAZE-KEY-BINDING-1] signed block #{block.get('id')} with maze key (att size={_att_sz})", "info", "sys0")
                if self.pqc_priv:
                    pqc_sig = await loop.run_in_executor(self._pqc_executor, pqc_sign, self.pqc_priv, bytes.fromhex(block["hash"]))
                    block["pqc_signature"] = pqc_sig.hex()
                await self.ws.send(json.dumps({"type": "block_signed", "miner_id": self.miner_id, "block": block}))
                # BLOCK-CONFIRM-1: sending is NOT mining. Record the
                # submission with the pre-send balance; confirmation happens
                # in the block_height_update handler via _reconcile_…
                # (balance growth >= reward once the chain advances past it).
                # A failed send (exception above) never records.
                b_id = block.get("id", self.block_id)
                reward = int(block.get("reward", 0))
                fees = int(block.get("total_fees", 0))
                self._pending_block = {"id": b_id, "reward": reward,
                                       "fees": fees,
                                       "balance_at_submit": self.balance,
                                       "sent_at": time.time()}
                self.total_blocks_submitted += 1
                log(
                    f"Block #{b_id} signed & submitted "
                    f"(reward={reward/1_000_000:.6f} MCX, awaiting node acceptance)",
                    "info", "sys0",
                )
                await self.fetch_balance()
            except Exception as e:
                log(f"Block signing failed: {e}", "error", "sys0")


    def print_5min_status_box(self):
        uptime_sec = time.time() - self.session_start_time
        earned = self.total_mcx_earned
        blocks_won = self.total_blocks_mined
        box = format_5min_status_box(
            self.miner_id,
            uptime_sec,
            blocks_won,
            earned,
            self.balance,
            self.total_goals_reached,
            self.total_accepted_moves,
            self.total_attempted_moves,
            self.total_walls_solved,
            self.size,
            self.growthcount,
            self.difficulty,
            self.block_id,
            self.last_ping
        )
        print(box, flush=True)

    async def status_report_loop(self):
        while self.running:
            await asyncio.sleep(300)
            if self.running and self.registered:
                self.print_5min_status_box()

    async def heartbeat(self):
        while self.running:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            if self.ws and self.registered:
                try:
                    await self.ws.send(json.dumps({"type": "uptime_ping", "miner_id": self.miner_id, "uptime_seconds": int(time.time())}))
                except (websockets.exceptions.ConnectionClosed, OSError):
                    pass

    async def keepalive_monitor(self):
        while self.running:
            await asyncio.sleep(10)
            if self.ws and self.registered:
                if time.time() - self.last_message_time > IDLE_TIMEOUT:
                    try:
                        await self.ws.send(json.dumps({"type": "ping"}))
                    except (websockets.exceptions.ConnectionClosed, OSError):
                        await self.disconnect()
                if self.round_active and self.maze and self.current != self.goal:
                    if self.nav_task is None or self.nav_task.done():
                        log(f"Nav task died while round_active — requesting state sync", "warning", "pog0")
                        try:
                            await self.request_state_sync()
                        except Exception:
                            pass

    async def _start_pool(self):
        """Spawn + warm the worker processes in the background (PoW uses the
        thread path until they are ready)."""
        try:
            self._pool.start()
            await asyncio.wait_for(self._pool.warm(), timeout=60)
            if self._pool.usable():
                log(f"Worker pool ready: {self._pool.workers} processes (below-normal priority)", "info", "sys0")
            else:
                log("Worker pool failed to start — using threads", "warning", "sys0")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._pool.broken = True
            log(f"Worker pool unavailable ({type(e).__name__}: {e}) — using threads", "warning", "sys0")

    async def run(self):
        log(f"Starting miner {_c(CYN, self.miner_id)}", "info", "sys0")
        log(f"CPU target {self.cpu_percent}% on {self._cpu_cores} cores (PoW up to x{self._cpu_max_pow}) — governor scales useful work, never the network pace",
            "info", "sys0")
        log(f"Compute: {self._agent_desc}; worker processes: "
            f"{self._pool.workers if self._pool is not None else 'off (threads)'}", "info", "sys0")
        if self._pool is not None and self._pool_task is None:
            self._pool_task = asyncio.create_task(self._start_pool())
        self.heartbeat_task = asyncio.create_task(self.heartbeat())
        self.balance_task = asyncio.create_task(self.balance_fetch_loop())
        self.keepalive_task = asyncio.create_task(self.keepalive_monitor())
        self.status_report_task = asyncio.create_task(self.status_report_loop())
        self._cpu_task = asyncio.create_task(self._cpu_governor_loop())

        while self.running:
            if not self.node_url:
                nodes = await discover_nodes(load_settings())
                if not nodes:
                    log("No node candidates available, retrying...", "warning", "net0")
                    await asyncio.sleep(10)
                    continue
                self._node_candidates = deque(nodes)
                self.node_url = self._node_candidates.popleft()
                log(f"Using node: {_c(CYN, self.node_url)}", "info", "net0")

            if getattr(self, '_recovery_done', False):
                self._recovery_done = False
                if self.ws and self.ws.open and self.registered:
                    log("Recovery connection active, resuming message loop", "info", "net0")
                    try:
                        active_ws = self.ws
                        async for msg in active_ws:
                            if not msg:
                                continue
                            try:
                                await self.handle_message(json.loads(msg))
                            except json.JSONDecodeError:
                                pass
                            except Exception as e:
                                log(f"Message error: {e}", "error", "net0")
                    except websockets.ConnectionClosed:
                        log(f"Connection closed, reconnecting...", "warning", "net0")
                    except Exception as e:
                        log(f"Loop error: {e}", "error", "net0")
                    finally:
                        if self.ws is active_ws:
                            await self.disconnect()
                            self.registered = False
                            self.round_active = False
                            self.pow_pending = False
                            if self.pending_ack and not self.pending_ack.done():
                                self.pending_ack.set_exception(ConnectionError("disconnected"))
                            if self.nav_task and not self.nav_task.done():
                                self.nav_task.cancel()
                                try:
                                    await self.nav_task
                                except (asyncio.CancelledError, Exception):
                                    pass
                            self.nav_task = None
                    await asyncio.sleep(1)
                    continue

            if not await self.connect(self.node_url):
                _record_peer_fail(self.node_url)
                self.reconn_attempts += 1
                if self.reconn_attempts > MAX_RECONNECT:
                    log(f"Giving up on {self.node_url}, trying next...", "warning", "net0")
                    self.node_url = self._node_candidates.popleft() if self._node_candidates else None
                    self.reconn_attempts = 0
                await asyncio.sleep(5)
                continue

            if await self.register():
                _record_peer_ok(self.node_url)
                self.registered = True
                active_ws = self.ws
                try:
                    async for msg in active_ws:
                        if not msg:
                            continue
                        try:
                            await self.handle_message(json.loads(msg))
                        except json.JSONDecodeError:
                            pass
                        except Exception as e:
                            log(f"Message error: {e}", "error", "net0")
                except websockets.ConnectionClosed:
                    log(f"Connection closed, reconnecting...", "warning", "net0")
                except Exception as e:
                    log(f"Loop error: {e}", "error", "net0")
                finally:
                    if self.ws is active_ws:
                        await self.disconnect()
                        self.registered = False
                        self.round_active = False
                        self.pow_pending = False
                        if self.pending_ack and not self.pending_ack.done():
                            self.pending_ack.set_exception(ConnectionError("disconnected"))
                        if self.nav_task and not self.nav_task.done():
                            self.nav_task.cancel()
                            try:
                                await self.nav_task
                            except (asyncio.CancelledError, Exception):
                                pass
                        self.nav_task = None
                    else:
                        log("Old connection closed but recovery active, keeping new connection", "info", "net0")
            else:
                log("Registration failed, retrying...", "warning", "net0")
                await asyncio.sleep(10)
            await asyncio.sleep(1)

        if self.heartbeat_task:
            self.heartbeat_task.cancel()
        if self.balance_task:
            self.balance_task.cancel()
        if self.keepalive_task:
            self.keepalive_task.cancel()

    async def stop(self):
        self.running = False
        for task in (self.nav_task, self.heartbeat_task, self.balance_task, self.keepalive_task,
                     getattr(self, "_cpu_task", None), getattr(self, "_pool_task", None)):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
        self.dqn.save()
        self._train_executor.shutdown(wait=False)
        self._pqc_executor.shutdown(wait=False)
        try:
            if getattr(self, "_pool", None) is not None:
                self._pool.shutdown()
        except Exception:
            pass
        try:
            getattr(self, "_pow_executor", None).shutdown(wait=False)
        except (AttributeError, TypeError):
            pass
        await self.disconnect()

async def main():
    parser = argparse.ArgumentParser(description="PC Miner — Official MCX PoG Miner")
    parser.add_argument("--node", help="WebSocket URL (overrides discovery)")
    parser.add_argument("--wallet", help="Wallet address")
    parser.add_argument("--privkey", help="Private key hex")
    parser.add_argument("--miner-id", help="Custom base miner ID")
    parser.add_argument("--cpu", type=int, default=None,
                        help="Target CPU usage out of 100%% (1-100; overrides prompt/settings)")
    parser.add_argument("--procs", type=int, default=None,
                        help="Worker processes for PoW/deep planning (default: auto = cores-1; 0 = threads only)")
    args = parser.parse_args()

    settings = load_settings()
    first_run = not settings.get("wallet")

    # CPU-TARGET-1: resolve target precedence CLI > prompt > settings > 50.
    # The prompt shows the stored value; Enter keeps it; non-interactive
    # (EOF) keeps it silently.
    _cpu_default = _clamp_cpu_percent(settings.get("cpu_percent", 50))
    if args.cpu is not None:
        cpu_percent = _clamp_cpu_percent(args.cpu, _cpu_default)
        settings["cpu_percent"] = cpu_percent
        save_settings(settings)
    else:
        try:
            _ans = input(f"{_c(CYN, 'Target CPU usage out of 100%')} [{_cpu_default}]: {RST}").strip()
        except (EOFError, KeyboardInterrupt):
            _ans = ""
        cpu_percent = _clamp_cpu_percent(_ans, _cpu_default) if _ans else _cpu_default
        if cpu_percent != settings.get("cpu_percent"):
            settings["cpu_percent"] = cpu_percent
            save_settings(settings)
    print(f"CPU target: {_c(CYN, str(cpu_percent) + '%')} of {os.cpu_count() or '?'} cores")

    if first_run:
        print(f"\n{_c(CYN, '╔══════════════════════════════════════╗')}{RST}")
        print(f"{_c(CYN, '║      PC Miner — First Time Setup     ║')}{RST}")
        print(f"{_c(CYN, '╚══════════════════════════════════════╝')}{RST}\n")

    if not args.wallet or not args.privkey:
        w, pk, existing_keys = load_wallet()
        if w and pk:
            args.wallet, args.privkey = w, pk
            try:
                pub_hex = _pubkey_from_privkey(pk)
                derived_addr = pubkey_to_address(pub_hex)
                if derived_addr.lower() != w.lower():
                    log(f"{_c(RED, 'Wallet address mismatch!')} Stored: {_c(CYN, w)}  Derived: {_c(CYN, derived_addr)}", "error", "sys0")
                    log(f"{_c(YLW, 'Fixing stored wallet to match private key...')}", "warning", "sys0")
                    args.wallet = derived_addr
                    settings["wallet"] = derived_addr
                    if settings.get("_encrypted") and not isinstance(settings.get("privkey"), dict):
                        settings.pop("privkey", None)
                    save_settings(settings)
            except Exception:
                pass
            if not first_run:
                log(f"Loaded wallet: {_c(CYN, args.wallet)}", "info", "sys0")
        else:
            w, pk, _, pqc_pub_hex, pqc_priv_hex = generate_keypair()
            args.wallet, args.privkey = w, pk
            settings["wallet"] = w
            settings["privkey"] = pk
            if pqc_pub_hex and pqc_priv_hex:
                settings["pqc_pub"] = pqc_pub_hex
                settings["pqc_priv"] = pqc_priv_hex
                pqc_pub = bytes.fromhex(pqc_pub_hex)
                pqc_priv = bytes.fromhex(pqc_priv_hex)
            passphrase = _get_passphrase(confirm=True)
            if passphrase:
                settings = _encrypt_settings_keys(settings, passphrase)
            save_settings(settings)
            print(f"{_c(GRN, 'Generated new wallet:')} {_c(CYN, args.wallet)}")
            print(f"{_c(YLW, 'Private key:')} {args.privkey}")
            print(f"{_c(RED, 'SAVE YOUR PRIVATE KEY!')}\n")

    if args.wallet and args.wallet != settings.get("wallet"):
        settings["wallet"] = args.wallet
    _existing_pk = settings.get("privkey")
    # Never clobber an encrypted privkey with a plaintext one. If the on-disk
    # value is a dict (encrypted), leave it alone — the user must decrypt it
    # via passphrase first, not pass --privkey on the command line.
    if args.privkey and not isinstance(_existing_pk, dict) and args.privkey != _existing_pk:
        settings["privkey"] = args.privkey

    _, _, maze_keys, pqc_pub, pqc_priv = load_wallet_full()
    # SINGLE-KEY MODE: the node requires BOTH of these at once —
    #   register: miner_id must derive from the identity key
    #             (R5-register-pc-derivation), and
    #   verify:   the sealed winner must derive from the attestation
    #             (maze) key (IDEA5-MAZE-KEY-BINDING-1).
    # With distinct identity/maze keys no single miner_id satisfies both,
    # so every separate-maze-key registration is rejected with "miner_id
    # does not derive from pub_key". Use the identity keypair for
    # maze/block operations too — the same single-key mode the embedded
    # miner uses (maze_id == identity pubkey). Wallet/balance are
    # unaffected (identity key unchanged); maze progress tracked under a
    # previous separate maze key restarts under the identity key.
    if maze_keys:
        log(f"{_c(YLW, 'Separate maze key(s) ignored:')} single-key mode uses the identity key "
            f"for maze/block operations (node requires identity-derived miner_id). "
            f"Maze progress restarts under {_c(CYN, args.wallet)}.", "warning", "sys0")
    mp = args.privkey
    mz = _pubkey_from_privkey(args.privkey)
    if not pqc_pub or not pqc_priv:
        if PQC_AVAILABLE:
            pqc_pub, pqc_priv = pqc_keygen()
            settings["pqc_pub"] = pqc_pub.hex()
            settings["pqc_priv"] = pqc_priv.hex()
            settings["maze_keys"] = maze_keys
            if not isinstance(settings.get("privkey"), dict):
                settings.pop("privkey", None)
            save_settings(settings)
            log(f"{_c(GRN, 'Generated ML-DSA-65 PQC keys')} ({len(pqc_pub)} bytes)", "info", "sys0")
        else:
            pqc_pub, pqc_priv = b"", b""

    # mp/mz already single-key (identity); do NOT call choose_maze_key —
    # any separate maze key breaks registration (see above).

    model_format = settings.get("model_format", "json")
    core_suffix = settings.get("core_suffix", "genius")

    if args.node:
        settings["node_url"] = args.node
        if not isinstance(settings.get("privkey"), dict):
            settings.pop("privkey", None)
        save_settings(settings)

    miner = PCMiner(args.wallet, args.privkey, miner_id=args.miner_id,
                    node_url=args.node or settings.get("node_url") or None,
                    core_suffix=core_suffix, mazepriv=mp, mazepub=mz,
                    pqc_pub=pqc_pub, pqc_priv=pqc_priv, model_format=model_format,
                    cpu_percent=cpu_percent, proc_workers=args.procs)
    print(BANNER)
    try:
        await miner.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await miner.stop()
        print(f"\n{_c(GRN, '[SHUTDOWN] Miner stopped gracefully')}{RST}")

if __name__ == "__main__":
    _mp.freeze_support()          # CPU-TARGET-3: needed for spawn-based workers in frozen (.exe) builds
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{_c(GRN, '[SHUTDOWN] Miner stopped gracefully')}{RST}")
    sys.exit(0)
