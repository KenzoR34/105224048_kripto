import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class KeyManager:
    """Komponen Manajemen Kunci: Pembangkitan, Penyimpanan Terversi, Rotasi, dan Pencabutan."""
    def __init__(self):
        self._keys = {}
        self._active_version = 0
        self.rotate_key()  # Inisialisasi kunci versi 1

    def rotate_key(self) -> int:
        """Membangkitkan kunci baru (rotasi) dan menetapkannya sebagai kunci aktif."""
        self._active_version += 1
        new_key = AESGCM.generate_key(bit_length=256)
        self._keys[self._active_version] = new_key
        return self._active_version

    def revoke_key(self, version: int):
        """Mencabut/menghapus kunci berdasarkan versi."""
        if version in self._keys:
            del self._keys[version]

    def get_active_key(self) -> tuple[int, bytes]:
        """Mengembalikan (versi, kunci) aktif saat ini."""
        return self._active_version, self._keys[self._active_version]

    def get_key_by_version(self, version: int) -> bytes | None:
        """Mengambil kunci berdasarkan nomor versi."""
        return self._keys.get(version)
