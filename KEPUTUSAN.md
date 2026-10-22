# Keputusan Keamanan — Tugas 2 (v0.2)

## Kebutuhan
Catatan perlu dirahasiakan dan perubahan ciphertext/metadata atau penggunaan kunci salah harus terdeteksi. Masukan tidak valid harus ditolak.

## Mekanisme
Memakai AES-256-GCM melalui pustaka terpelihara `cryptography` (`AESGCM`). AEAD menyediakan kerahasiaan dan autentikasi/integritas dalam satu mekanisme.

## Parameter
- **Kunci:** 256 bit (32 byte), dibuat dengan `AESGCM.generate_key(bit_length=256)` yang menggunakan sumber acak kriptografis sistem operasi (CSPRNG).
- **Penyimpanan kunci:** di luar repository: `%LOCALAPPDATA%\\SecureNotes\\aesgcm.key` pada Windows. Fallback sistem lain: `~/.local/share/secure-notes/aesgcm.key`. Jangan commit file kunci. Untuk produksi gunakan OS key store/secret manager.
- **Nonce:** 96 bit (12 byte), baru pada setiap enkripsi melalui `os.urandom(12)`. Nonce harus unik untuk setiap enkripsi dengan kunci yang sama.
- **AAD:** `secure-notes:v0.2`; tidak dienkripsi tetapi diautentikasi.
- **Tag:** 128 bit (16 byte), dibuat dan ditambahkan oleh `AESGCM` ke ciphertext; tag diverifikasi sebelum plaintext diberikan.
- **Format:** JSON berisi versi, nonce, ciphertext+tag, dan AAD; data biner dikodekan Base64.

## Validasi dan gagal tertutup
Menolak teks kosong/non-teks, kunci salah tipe/panjang, format atau versi tidak valid, AAD berubah, nonce tidak valid, dan ciphertext/tag tidak lengkap. Jika autentikasi gagal (data diubah atau kunci salah), dekripsi gagal dan plaintext tidak dikembalikan.

## Batasan
Kehilangan kunci membuat catatan tidak dapat dipulihkan. Keamanan file kunci bergantung pada izin akun/perangkat. Contoh ini untuk demonstrasi; produksi memerlukan kontrol akses, rotasi, dan pencadangan aman.
