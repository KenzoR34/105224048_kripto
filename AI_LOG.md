# AI_LOG.md

## Penggunaan AI
AI digunakan sebagai bantuan awal untuk menyusun kerangka dokumentasi, contoh implementasi, dan rancangan skenario pengujian Secure Notes.

## Bagian yang dibantu
- Kerangka `README.md` dan tabel kebutuhan keamanan.
- Draf kode enkripsi/dekripsi dengan AES-GCM dan derivasi kunci PBKDF2-HMAC-SHA256.
- Draf pengujian otomatis untuk alur normal, password salah, perubahan ciphertext, dan input batas.

## Verifikasi yang harus dilakukan mahasiswa
- Jalankan `python -m pip install -r requirements.txt`.
- Jalankan `python -m unittest -v` dan periksa hasil aktual.
- Uji perintah enkripsi dan dekripsi secara langsung.
- Pahami fungsi salt, nonce, PBKDF2, AES-GCM, dan penanganan kesalahan.
- Sesuaikan dokumentasi dengan hasil yang benar-benar diperoleh dan aturan dosen.

## Catatan integritas akademik
Dokumentasi ini menyatakan penggunaan AI secara terbuka. Mahasiswa bertanggung jawab memahami, memeriksa, menguji, dan mampu menjelaskan seluruh kode yang dikumpulkan. Jangan mengklaim pengujian berhasil sebelum menjalankannya.
