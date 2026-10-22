# AI Log

- **Alat:** ChatGPT (OpenAI).
- **Tujuan:** Membantu rancangan contoh AEAD AES-256-GCM, dokumentasi keputusan, dan pengujian.
- **Ringkasan perintah:** Meminta implementasi AEAD dengan parameter terdokumentasi, validasi masukan, kunci di luar repository, dan uji manipulasi ciphertext/AAD serta kunci salah.
- **Bagian yang dipakai/diubah:** Draf `secure_notes.py`, `test_secure.py`, dan `KEPUTUSAN.md` dibuat dengan bantuan AI; tinjau dan sesuaikan sebelum dikumpulkan.
- **Cara memeriksa:** Jalankan `python -m unittest -v`, baca dokumentasi `cryptography` untuk `AESGCM`, cek lokasi kunci di luar repository dan pastikan tidak ada secrets yang masuk Git.
- **Data uji:** Data sintetis, bukan data pribadi.
