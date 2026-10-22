import pytest
from app.crypto import generate_signing_keypair, sign_data, verify_data

def test_a1_valid_signature():
    """Uji 1 (Positif): Verifikasi berhasil untuk data asli."""
    priv, pub = generate_signing_keypair()
    payload = b"Log Meteran #1001: 450 kWh"
    signature = sign_data(priv, payload)
    assert verify_data(pub, signature, payload) is True

def test_a2_tampered_payload_negative():
    """Uji 2 (Negatif): Verifikasi gagal jika data diubah pihak ketiga."""
    priv, pub = generate_signing_keypair()
    payload = b"Log Meteran #1001: 450 kWh"
    signature = sign_data(priv, payload)
    
    tampered_payload = b"Log Meteran #1001: 0 kWh"
    assert verify_data(pub, signature, tampered_payload) is False

def test_a3_wrong_public_key():
    """Uji 3 (Negatif): Verifikasi gagal jika menggunakan kunci publik pengirim lain."""
    priv1, _ = generate_signing_keypair()
    _, pub2 = generate_signing_keypair()
    payload = b"Log Sensor #1002"
    signature = sign_data(priv1, payload)
    assert verify_data(pub2, signature, payload) is False

def test_a4_tampered_signature():
    """Uji 4 (Negatif): Verifikasi gagal jika bit tanda tangan rusak."""
    priv, pub = generate_signing_keypair()
    payload = b"Log Sensor #1003"
    signature = bytearray(sign_data(priv, payload))
    signature[0] ^= 0xFF  # Merusak byte pertama
    assert verify_data(pub, bytes(signature), payload) is False

def test_a5_empty_payload():
    """Uji 5 (Positif): Verifikasi tetap valid untuk payload kosong/minimal."""
    priv, pub = generate_signing_keypair()
    payload = b""
    signature = sign_data(priv, payload)
    assert verify_data(pub, signature, payload) is True
