from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# --- BAGIAN A: Digital Signature (Ed25519) ---

def generate_signing_keypair():
    """Menghasilkan pasangan kunci privat dan publik Ed25519."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()

def sign_data(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Menandatangani data menggunakan kunci privat."""
    return private_key.sign(data)

def verify_data(public_key: ed25519.Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """Memverifikasi keaslian data dengan kunci publik."""
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False

# --- BAGIAN B: Enkripsi AES-GCM & Rotasi Kunci ---

class DataEncryptor:
    """Fitur enkripsi payload simetris dengan manajemen kunci."""
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def encrypt_payload(self, data: bytes) -> dict:
        """Mengenkripsi data menggunakan kunci aktif terbaru."""
        version, key = self.key_manager.get_active_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return {
            "key_version": version,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

    def decrypt_payload(self, encrypted_obj: dict) -> bytes:
        """Mendekripsi data berdasarkan versi kunci pada payload."""
        version = encrypted_obj["key_version"]
        key = self.key_manager.get_key_by_version(version)
        if key is None:
            raise ValueError(f"Kunci versi {version} telah dicabut atau tidak ditemukan.")
        
        aesgcm = AESGCM(key)
        nonce = bytes.fromhex(encrypted_obj["nonce"])
        ciphertext = bytes.fromhex(encrypted_obj["ciphertext"])
        return aesgcm.decrypt(nonce, ciphertext, None)
