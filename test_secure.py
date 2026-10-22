import base64
import json
import unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secure_notes import SecureNotesError, decrypt_text, encrypt_text

class SecureNotesTests(unittest.TestCase):
    def setUp(self):
        self.key = AESGCM.generate_key(bit_length=256)

    def test_encrypt_decrypt_round_trip(self):
        text = "Catatan sintetis"
        self.assertEqual(decrypt_text(encrypt_text(text, self.key), self.key), text)

    def test_empty_input_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_text("", self.key)

    def test_modified_ciphertext_rejected(self):
        env = json.loads(encrypt_text("uji", self.key))
        raw = bytearray(base64.b64decode(env["ciphertext"]))
        raw[0] ^= 1
        env["ciphertext"] = base64.b64encode(raw).decode("ascii")
        with self.assertRaises(SecureNotesError):
            decrypt_text(json.dumps(env), self.key)

    def test_wrong_key_rejected(self):
        data = encrypt_text("uji", self.key)
        with self.assertRaises(SecureNotesError):
            decrypt_text(data, AESGCM.generate_key(bit_length=256))

    def test_modified_aad_rejected(self):
        env = json.loads(encrypt_text("uji", self.key))
        env["aad"] = "changed"
        with self.assertRaises(SecureNotesError):
            decrypt_text(json.dumps(env), self.key)

    def test_invalid_key_length_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_text("uji", b"short")

if __name__ == "__main__":
    unittest.main()
