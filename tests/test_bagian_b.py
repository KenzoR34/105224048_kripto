import pytest
from app.key_manager import KeyManager
from app.crypto import DataEncryptor

def test_b1_encrypt_decrypt_with_rotation():
    """Uji 1 (Positif): Enkripsi-dekripsi berhasil dan mendukung rotasi kunci."""
    km = KeyManager()
    encryptor = DataEncryptor(km)
    
    # Enkripsi dengan kunci versi 1
    data_v1 = b"Data Rahasia Versi 1"
    enc_obj1 = encryptor.encrypt_payload(data_v1)
    assert enc_obj1["key_version"] == 1
    
    # Rotasi kunci ke versi 2
    km.rotate_key()
    data_v2 = b"Data Rahasia Versi 2"
    enc_obj2 = encryptor.encrypt_payload(data_v2)
    assert enc_obj2["key_version"] == 2
    
    # Dekripsi data lama (v1) dan baru (v2)
    assert encryptor.decrypt_payload(enc_obj1) == data_v1
    assert encryptor.decrypt_payload(enc_obj2) == data_v2

def test_b2_revoked_key_decryption_negative():
    """Uji 2 (Negatif): Dekripsi gagal ketika versi kunci yang digunakan telah dicabut."""
    km = KeyManager()
    encryptor = DataEncryptor(km)
    
    # Enkripsi dengan versi 1
    enc_obj = encryptor.encrypt_payload(b"Data Terenkripsi")
    
    # Cabut kunci versi 1
    km.revoke_key(1)
    
    # Dekripsi harus memicu exception
    with pytest.raises(ValueError, match="telah dicabut atau tidak ditemukan"):
        encryptor.decrypt_payload(enc_obj)
