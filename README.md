# Secure Notes — Fondasi dan Komponen Dasar Kriptografi

## 1. Deskripsi produk
Secure Notes adalah prototipe CLI untuk mengenkripsi catatan teks sebelum disimpan sebagai berkas JSON. Produk ini ditujukan sebagai demonstrasi pembelajaran kriptografi, bukan aplikasi penyimpanan rahasia produksi.

## 2. Kebutuhan keamanan dan prioritas

| Aset/data | Tujuan keamanan | Komponen | Prioritas |
|---|---|---|---|
| Isi catatan | Kerahasiaan | AES-256-GCM | Tinggi |
| Isi catatan terenkripsi | Integritas dan deteksi perubahan | Tag autentikasi AES-GCM | Tinggi |
| Password pengguna | Tidak disimpan dalam berkas | Password hanya dipakai untuk derivasi kunci | Tinggi |
| Kunci enkripsi | Diturunkan dengan cara yang mahal untuk tebakan password | PBKDF2-HMAC-SHA256 dengan salt acak | Tinggi |
| Parameter enkripsi | Format dapat dibaca dan divalidasi | JSON, Base64, versi format | Sedang |

## 3. Rancangan komponen (masukan → proses → keluaran)

- **Masukan enkripsi:** teks catatan dan password.
- **Proses:** buat salt 16 byte dan nonce 12 byte dari `os.urandom`; turunkan kunci 32 byte dengan PBKDF2-HMAC-SHA256 (600.000 iterasi); enkripsi dan autentikasi dengan AES-256-GCM.
- **Keluaran:** JSON berisi versi, nama algoritma, jumlah iterasi, salt, nonce, dan ciphertext beserta tag autentikasi. Nilai biner direpresentasikan dengan Base64.
- **Masukan dekripsi:** berkas JSON dan password.
- **Proses dekripsi:** validasi format, turunkan kunci yang sama dari password dan salt, lalu verifikasi tag AES-GCM.
- **Keluaran:** teks asli hanya jika autentikasi berhasil; password salah atau data yang diubah menghasilkan kesalahan.

### Sumber keacakan
`os.urandom()` menyediakan byte acak dari sumber keacakan sistem operasi untuk salt dan nonce. Salt berbeda membantu mencegah kunci turunan yang sama untuk password yang sama; nonce harus unik untuk setiap enkripsi dengan kunci yang sama.

### Alasan pemilihan pustaka
Pustaka `cryptography` menyediakan implementasi AES-GCM dan PBKDF2 yang terpelihara serta API tingkat tinggi. Implementasi tidak membuat algoritma kriptografi sendiri. AES-GCM dipilih karena memberi kerahasiaan sekaligus autentikasi/integritas.

## 4. Cara menjalankan

Gunakan Python 3.10 atau lebih baru.

```bash
python -m venv .venv
```

Aktifkan lingkungan virtual:
- Windows PowerShell: `.venv\\Scripts\\Activate.ps1`
- macOS/Linux: `source .venv/bin/activate`

Pasang dependensi:

```bash
python -m pip install -r requirements.txt
```

Enkripsi:

```bash
python secure_notes.py encrypt --out catatan.enc.json
```

Masukkan password dan catatan saat diminta. Untuk dekripsi:

```bash
python secure_notes.py decrypt --infile catatan.enc.json
```

Jalankan pengujian otomatis:

```bash
python -m unittest -v
```

## 5. Skenario uji

| ID | Skenario | Hasil yang diharapkan |
|---|---|---|
| T1 | Enkripsi lalu dekripsi catatan normal | Teks kembali sama |
| T2 | Enkripsi dua kali dengan teks/password sama | Salt dan nonce berbeda |
| T3 | Dekripsi menggunakan password salah | Ditolak dengan pesan kesalahan |
| T4 | Satu bit ciphertext diubah | Autentikasi gagal |
| T5 | Catatan kosong atau hanya spasi | Enkripsi ditolak |
| T6 | Panjang nonce tidak valid | Format ditolak |

Jalankan semua skenario dengan `python -m unittest -v`. Catat keluaran aktual pada saat pengujian dan lampirkan tangkapan layar untuk demonstrasi.

## 6. Batasan dan catatan keamanan
- Prototipe ini tidak mengelola akun, backup, atau penyimpanan password.
- Keamanan password bergantung pada kekuatan password yang dipilih.
- Jangan memasukkan data pribadi atau rahasia sungguhan untuk tugas; gunakan data sintetis.
- Jangan commit password, kunci, token, atau data rahasia.
- AES-GCM memerlukan nonce unik untuk setiap enkripsi dengan kunci yang sama; jangan pernah mengulang nonce dengan kunci yang sama.
- Ini prototipe akademik, bukan klaim bahwa aplikasi siap digunakan untuk produksi.

## 7. Kesesuaian tugas
- K1: deskripsi produk dan tabel kebutuhan keamanan.
- K2: masukan–proses–keluaran, representasi data, sumber keacakan, dan alasan pustaka.
- K3: implementasi CLI menggunakan pustaka kriptografi.
- K4: enam skenario pengujian otomatis, termasuk uji negatif dan batas.
- K5: gunakan `AI_LOG.md` untuk mencatat bagian yang dibantu AI dan verifikasi yang dilakukan mahasiswa.
