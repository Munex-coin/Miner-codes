#!/usr/bin/env python3
"""show_key.py — show the wallet private key locked in a Munex key file, once.

Works with both files:
  - node wallet.json        (fields: address / private_key_encrypted {salt, nonce, data, argon2_hash})
  - miner miner_settings.json (fields: wallet / privkey {salt, nonce, ct})

The password is asked with getpass: never shown on screen, never saved,
never written to any file. The key is printed once so you can copy it
(e.g. into the website wallet, or a password manager). Do NOT paste it
into a chat, a log, or any file that gets synced or shared.

Usage:
  python show_key.py wallet.json
  python show_key.py miner_settings.json

Needs the same libraries the node/miner already need:
  pip install cryptography argon2-cffi
"""
import base64
import getpass
import hashlib
import hmac
import json
import sys


def b64d(s):
    return base64.b64decode(s)


def node_decrypt(enc, password):
    """Mirror of node encrypt_private_key/decrypt_private_key (v9.3)."""
    try:
        from argon2 import PasswordHasher
        ph = PasswordHasher()
    except ImportError:
        ph = None
    ah = str(enc.get("argon2_hash", ""))
    if ph and ah.startswith("$argon2"):
        ph.verify(ah, password)
    elif "argon2_hash" in enc:
        salt_hex = b64d(enc["salt"]).hex()
        expected = hashlib.sha256((password + salt_hex).encode()).hexdigest()
        if not hmac.compare_digest(ah, expected):
            raise ValueError("Invalid password")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = b64d(enc["salt"])
    data = b64d(enc["data"])
    kdf = PBKDF2HMAC(hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password.encode())
    if "nonce" in enc:
        nonce = b64d(enc["nonce"])
        ct, tag = data[:-16], data[-16:]
        dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        return (dec.update(ct) + dec.finalize()).decode()
    # Legacy CBC variant (same as node decrypt_private_key fallback).
    iv = b64d(enc["iv"])
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = dec.update(data) + dec.finalize()
    return pt[: -pt[-1]].decode()


def miner_decrypt(enc, passphrase):
    """Mirror of PC_Miner.py encrypt_secret/decrypt_secret."""
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = b64d(enc["salt"])
    nonce = b64d(enc["nonce"])
    ct = b64d(enc["ct"])
    key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def main():
    if len(sys.argv) != 2:
        print("Usage: python show_key.py <wallet.json | miner_settings.json>")
        return 2
    try:
        with open(sys.argv[1], "r") as f:
            d = json.load(f)
    except (OSError, ValueError) as e:
        print(f"Cannot read {sys.argv[1]}: {e}")
        return 1
    if not isinstance(d, dict):
        print("Unrecognised file — expected a node wallet.json or a miner miner_settings.json.")
        return 1

    pw = getpass.getpass("Password: ")

    # --- Node wallet.json ---
    enc = d.get("private_key_encrypted")
    if isinstance(enc, str):
        try:
            enc = json.loads(enc)
        except ValueError:
            enc = None
    if isinstance(enc, dict) and "data" in enc:
        try:
            priv = node_decrypt(enc, pw)
        except Exception:
            print("Wrong password or corrupted file.")
            return 1
        print("Address: " + str(d.get("address", "")))
        print("Private key: " + priv)
        return 0
    if "data" in d and "salt" in d:
        try:
            priv = node_decrypt(d, pw)
        except Exception:
            print("Wrong password or corrupted file.")
            return 1
        print("Private key: " + priv)
        return 0

    # --- Miner miner_settings.json ---
    if "privkey" in d or "maze_keys" in d:
        pk = d.get("privkey", "")
        if isinstance(pk, dict) and "ct" in pk:
            try:
                priv = miner_decrypt(pk, pw)
            except Exception:
                print("Wrong passphrase or corrupted keys.")
                return 1
        elif isinstance(pk, str) and pk:
            priv = pk
        else:
            print("No wallet private key in this file.")
            return 1
        print("Address: " + str(d.get("wallet", "")))
        print("Private key: " + priv)
        return 0

    print("Unrecognised file — expected a node wallet.json or a miner miner_settings.json.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
