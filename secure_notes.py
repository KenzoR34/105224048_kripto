"""Secure Notes: demo enkripsi catatan memakai AES-GCM dan PBKDF2-HMAC-SHA256."""
import argparse
import base64
import json
import os
from pathlib import Path
from getpass import getpass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
FORMAT_VERSION = 1


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password tidak boleh kosong.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(plaintext: str, password: str) -> dict:
    if not isinstance(plaintext, str) or not plaintext.strip():
        raise ValueError("Catatan tidak boleh kosong.")
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return {
        "version": FORMAT_VERSION,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": ITERATIONS,
        "cipher": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_text(payload: dict, password: str) -> str:
    try:
        if payload.get("version") != FORMAT_VERSION:
            raise ValueError("Versi format tidak didukung.")
        if payload.get("cipher") != "AES-256-GCM":
            raise ValueError("Algoritma tidak didukung.")
        salt = base64.b64decode(payload["salt"], validate=True)
        nonce = base64.b64decode(payload["nonce"], validate=True)
        ciphertext = base64.b64decode(payload["ciphertext"], validate=True)
        if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
            raise ValueError("Format salt atau nonce tidak valid.")
        key = derive_key(password, salt)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except InvalidTag as exc:
        raise ValueError("Dekripsi gagal: password salah atau data telah diubah.") from exc
    except (KeyError, TypeError, base64.binascii.Error) as exc:
        raise ValueError("Berkas terenkripsi rusak atau formatnya tidak valid.") from exc


def save_payload(payload: dict, output_path: str) -> None:
    Path(output_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_payload(input_path: str) -> dict:
    try:
        return json.loads(Path(input_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Berkas tidak dapat dibaca atau bukan JSON valid.") from exc


def main():
    parser = argparse.ArgumentParser(description="Secure Notes: enkripsi/dekripsi catatan.")
    sub = parser.add_subparsers(dest="command", required=True)
    enc = sub.add_parser("encrypt", help="Enkripsi catatan teks ke berkas JSON.")
    enc.add_argument("--out", default="catatan.enc.json", help="Nama berkas keluaran.")
    dec = sub.add_parser("decrypt", help="Dekripsi berkas JSON.")
    dec.add_argument("--infile", default="catatan.enc.json", help="Berkas masukan.")
    args = parser.parse_args()

    try:
        password = getpass("Password: ")
        if args.command == "encrypt":
            note = input("Masukkan catatan: ")
            payload = encrypt_text(note, password)
            save_payload(payload, args.out)
            print(f"Berhasil dienkripsi. Hasil disimpan di: {args.out}")
        else:
            payload = load_payload(args.infile)
            print("Catatan asli:", decrypt_text(payload, password))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
