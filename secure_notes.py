"""AES-256-GCM authenticated encryption demo."""
import base64, json, os
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LENGTH_BYTES = 32
NONCE_LENGTH_BYTES = 12
TAG_LENGTH_BYTES = 16
AAD = b"secure-notes:v0.2"
FORMAT_VERSION = 1

class SecureNotesError(Exception):
    """Raised when encrypted data cannot be safely authenticated/decrypted."""

def default_key_path():
    local_app_data = os.environ.get("LOCALAPPDATA")
    root = Path(local_app_data) / "SecureNotes" if local_app_data else Path.home() / ".local" / "share" / "secure-notes"
    return root / "aesgcm.key"

def load_or_create_key(key_path=None):
    path = Path(key_path) if key_path else default_key_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            key = path.read_bytes()
            if len(key) != KEY_LENGTH_BYTES:
                raise SecureNotesError("Panjang file kunci tidak valid.")
            return key
        key = AESGCM.generate_key(bit_length=256)
        with path.open("xb") as f:
            f.write(key)
        return key
    except FileExistsError:
        key = path.read_bytes()
        if len(key) != KEY_LENGTH_BYTES:
            raise SecureNotesError("Panjang file kunci tidak valid.")
        return key
    except OSError as exc:
        raise SecureNotesError("Kunci tidak dapat dibaca atau disimpan.") from exc

def encrypt_text(text, key=None):
    if not isinstance(text, str) or not text:
        raise ValueError("Catatan harus berupa teks yang tidak kosong.")
    key = load_or_create_key() if key is None else key
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH_BYTES:
        raise ValueError("Kunci harus berupa bytes sepanjang 32 byte.")
    nonce = os.urandom(NONCE_LENGTH_BYTES)
    encrypted = AESGCM(key).encrypt(nonce, text.encode("utf-8"), AAD)
    return json.dumps({
        "version": FORMAT_VERSION,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(encrypted).decode("ascii"),
        "aad": AAD.decode("ascii"),
    }, separators=(",", ":"), sort_keys=True)

def decrypt_text(envelope_text, key=None):
    if not isinstance(envelope_text, str) or not envelope_text:
        raise ValueError("Data terenkripsi harus berupa teks yang tidak kosong.")
    key = load_or_create_key() if key is None else key
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH_BYTES:
        raise ValueError("Kunci harus berupa bytes sepanjang 32 byte.")
    try:
        env = json.loads(envelope_text)
        if not isinstance(env, dict) or env.get("version") != FORMAT_VERSION:
            raise SecureNotesError("Format atau versi data tidak valid.")
        if env.get("aad") != AAD.decode("ascii"):
            raise SecureNotesError("AAD tidak valid.")
        nonce = base64.b64decode(env["nonce"], validate=True)
        encrypted = base64.b64decode(env["ciphertext"], validate=True)
        if len(nonce) != NONCE_LENGTH_BYTES or len(encrypted) < TAG_LENGTH_BYTES:
            raise SecureNotesError("Nonce atau ciphertext/tag tidak valid.")
        return AESGCM(key).decrypt(nonce, encrypted, AAD).decode("utf-8")
    except (InvalidTag, KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        if isinstance(exc, SecureNotesError):
            raise
        raise SecureNotesError("Dekripsi gagal: data rusak atau kunci salah.") from exc
