import copy
import unittest

from secure_notes import encrypt_text, decrypt_text


class SecureNotesTests(unittest.TestCase):
    def test_encrypt_then_decrypt(self):
        note = "Catatan rahasia sintetis"
        self.assertEqual(decrypt_text(encrypt_text(note, "password-kuat"), "password-kuat"), note)

    def test_independent_encryptions_use_different_random_values(self):
        first = encrypt_text("pesan sama", "password-kuat")
        second = encrypt_text("pesan sama", "password-kuat")
        self.assertNotEqual(first["salt"], second["salt"])
        self.assertNotEqual(first["nonce"], second["nonce"])

    def test_wrong_password_is_rejected(self):
        payload = encrypt_text("catatan", "password-benar")
        with self.assertRaisesRegex(ValueError, "password salah atau data telah diubah"):
            decrypt_text(payload, "password-salah")

    def test_tampered_ciphertext_is_rejected(self):
        payload = encrypt_text("catatan", "password-benar")
        changed = copy.deepcopy(payload)
        import base64
        raw = bytearray(base64.b64decode(changed["ciphertext"]))
        raw[0] ^= 1
        changed["ciphertext"] = base64.b64encode(raw).decode("ascii")
        with self.assertRaisesRegex(ValueError, "password salah atau data telah diubah"):
            decrypt_text(changed, "password-benar")

    def test_empty_note_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Catatan tidak boleh kosong"):
            encrypt_text("   ", "password-kuat")

    def test_invalid_nonce_length_is_rejected(self):
        payload = encrypt_text("catatan", "password-kuat")
        payload["nonce"] = "AA=="
        with self.assertRaisesRegex(ValueError, "salt atau nonce"):
            decrypt_text(payload, "password-kuat")


if __name__ == "__main__":
    unittest.main(verbosity=2)
