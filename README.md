# Sistem Manajemen Catatan (Secure Notes)

Aplikasi web manajemen catatan terenkripsi berbasis **PHP 8.3+ Native**, **MySQL (PDO)**, **Tabler UI**, dan kriptografi simetris **AES-256-GCM** dengan derivasi kunci **PBKDF2-HMAC-SHA256**.

---

## Disusun Oleh

<table>
  <tbody>
    <tr>
      <td><strong>Nama</strong></td>
      <td><strong>MUHAMAD DIKRULLOH</strong></td>
    </tr>
    <tr>
      <td><strong>NIM</strong></td>
      <td><strong>2430511076</strong></td>
    </tr>
    <tr>
      <td><strong>Kelas</strong></td>
      <td><strong>5B</strong></td>
    </tr>
    <tr>
      <td><strong>Mata Kuliah</strong></td>
      <td>Keamanan Data dan Informasi</td>
    </tr>
  </tbody>
</table>

---

## Fitur Utama

1. **Enkripsi Penuh Antarmuka & Data (AES-256-GCM)**
   - Seluruh teks statis dashboard (sidebar, navbar, judul halaman, label kartu, header tabel, tombol, placeholder, alert, hingga modal konfirmasi keluar) disimpan dalam bentuk terenkripsi di tabel `ui_texts`.
   - Seluruh judul dan isi catatan dienkripsi menggunakan **AES-256-GCM** dengan **Nonce 12-byte (96-bit)** acak baru dan **Authentication Tag 16-byte (128-bit)** untuk setiap nilai.
2. **Dua Mode Dashboard Berdasarkan Verifikasi Kunci**
   - **Mode Terbuka (Kunci Benar):** Seluruh teks antarmuka dan catatan didekripsi ke Bahasa Indonesia; operasi tambah, lihat detail, pencarian, ubah, dan hapus diaktifkan.
   - **Mode Terkunci (Kunci Salah):** Tetap membuka halaman dashboard dengan tata letak utuh namun seluruh teks antarmuka dan catatan ditampilkan sebagai **ciphertext Base64 asli** dari database. Seluruh operasi tulis (CRUD) dinonaktifkan di antarmuka dan ditolak (`HTTP 403`) di sisi server.
3. **Deteksi Manipulasi Data (Tamper Detection)**
   - Apabila nilai `ciphertext`, `nonce`, atau `tag` di database diubah secara paksa melalui manajemen database, autentikasi GCM 128-bit akan mendeteksi kerusakan integritas, menampilkan peringatan manipulasi data, dan mengunci operasi edit pada baris tersebut.

---

## Struktur Proyek

```text
SecureNotes/
├── assets/
│   ├── app.css              # Desain sistem, tipografi IBM Plex, & tata letak ciphertext
│   └── app.js               # Toggle kunci rahasia & pengisian data modal CRUD
├── includes/
│   ├── app.php              # Koneksi PDO, sesi aman, CSRF, rate limit, helper UI
│   ├── crypto.php           # PBKDF2-HMAC-SHA256 & AES-256-GCM (OpenSSL)
│   └── notes_table.php      # Komponen tabel catatan
├── .htaccess                # Proteksi file konfigurasi & skema SQL
├── auth.php                 # Halaman input Kunci Rahasia
├── config.php               # Konfigurasi koneksi database MySQL & parameter KDF
├── dashboard.php            # Dashboard utama & endpoint CRUD terotorisasi
├── index.php                # Halaman publik (Landing Page)
├── logout.php               # Penghapusan sesi & materi kunci di server
├── secure_notes.sql         # Skema tabel MySQL siap impor
└── setup.php                # Inisialisasi pertama kali (First-Time Setup)
```

---

## Panduan Instalasi & Penggunaan (Laragon)

1. **Salin atau Clone Proyek**
   Letakkan folder proyek di dalam direktori `C:\laragon\www\SecureNotes`.

2. **Jalankan Layanan Laragon**
   Buka **Laragon**, lalu klik **Start All** untuk menjalankan Apache/Nginx dan MySQL/MariaDB.

3. **Impor Database MySQL**
   Jalankan perintah berikut melalui Terminal Laragon atau impor file `secure_notes.sql` menggunakan HeidiSQL / phpMyAdmin:
   ```bash
   mysql -u root < secure_notes.sql
   ```

4. **Konfigurasi Koneksi Database (`config.php`)**
   File `config.php` sudah dikonfigurasi langsung untuk pengaturan standar Laragon (`root` tanpa kata sandi) sehingga tidak memerlukan penyalinan file konfigurasi manual:
   ```php
   return [
      'db_host' => '127.0.0.1',
      'db_port' => 3306,
      'db_name' => 'secure_notes',
      'db_user' => 'root',
      'db_pass' => '',
      'kdf_iterations' => 600000,
      'session_timeout' => 1800,
   ];
   ```

5. **Inisialisasi Pertama Kali (`setup.php`)**
   - Buka `http://localhost/SecureNotes/` di browser dan klik **Inisialisasi Sistem** (atau akses `setup.php`).
   - Buat **Kunci Rahasia** (minimal 8 karakter) beserta konfirmasinya.
   - Sistem akan membuat salt acak, mengenkripsi nilai verifikasi, mengenkripsi katalog teks antarmuka ke tabel `ui_texts`, dan mengenkripsi 3 catatan sampel awal ke tabel `notes`.
   - **Catatan Penting:** Kunci Rahasia tidak pernah disimpan di database dan tidak memiliki fitur pemulihan. Jika Kunci Rahasia hilang, seluruh catatan terenkripsi tidak dapat dipulihkan.

6. **Cara Reset Kunci Rahasia (Ulangi Inisialisasi)**
   Karena catatan dan katalog UI dienkripsi dengan kunci turunan dari Kunci Rahasia, mereset kunci mengharuskan pengosongan tabel agar `setup.php` dapat dijalankan kembali:
   ```bash
   mysql -u root -e "TRUNCATE TABLE secure_notes.settings; TRUNCATE TABLE secure_notes.ui_texts; TRUNCATE TABLE secure_notes.notes;"
   ```
   Setelah perintah di atas dijalankan, buka kembali `setup.php` di browser untuk membuat Kunci Rahasia baru.

---

## Alur Enkripsi dan Dekripsi (AES-256-GCM)

### 1. Derivasi Kunci (`derive_key` di `includes/crypto.php`)
- Saat pengguna memasukkan **Kunci Rahasia**, sistem membaca `kdf_salt` (16 byte) dan `kdf_iterations` (`600.000`) dari tabel `settings`.
- Fungsi `hash_pbkdf2('sha256', $passphrase, $salt, $iterations, 32, true)` menurunkan kunci biner sepanjang **32 byte (256-bit)**.

### 2. Verifikasi Kunci (`verify_secret_key` di `includes/crypto.php`)
- Kunci kandidat 32-byte digunakan untuk mendekripsi `verification_ciphertext` dengan `verification_nonce` dan `verification_tag` menggunakan `openssl_decrypt(..., 'aes-256-gcm', ...)`.
- Jika tag autentikasi GCM cocok dan menghasilkan nilai penanda verifikasi yang sah, sesi diaktifkan sebagai **Mode Terbuka (Unlocked Mode)** dan kunci turunan disimpan sementara hanya di sesi server PHP (`$_SESSION['derived_key']`).
- Jika tag autentikasi gagal, sesi masuk ke **Mode Terkunci (Locked Mode)** dan kunci kandidat tidak disimpan.

### 3. Proses Enkripsi (`encrypt_data` di `includes/crypto.php`)
Setiap kali teks UI atau catatan disimpan:
1. Dibuat **Nonce 12-byte** acak baru menggunakan `random_bytes(12)`.
2. Plaintext dienkripsi menggunakan `openssl_encrypt($plaintext, 'aes-256-gcm', $rawKey, OPENSSL_RAW_DATA, $nonce, $tag, '', 16)`.
3. `ciphertext`, `nonce`, dan `tag` (16-byte) dikodekan ke **Base64** dan disimpan di kolom terpisah pada MySQL.

### 4. Proses Dekripsi (`decrypt_data` di `includes/crypto.php`)
Setiap kali halaman dashboard dirender:
1. Jika sesi berada pada **Mode Terkunci**, fungsi `ui_text()` dan `fetch_all_notes()` langsung mengembalikan string `ciphertext` Base64 asli dari database tanpa membocorkan plaintext apa pun.
2. Jika sesi berada pada **Mode Terbuka**, `openssl_decrypt` memverifikasi keutuhan data terhadap `nonce` dan `tag` autentikasi 16-byte.
3. Apabila `ciphertext`, `nonce`, atau `tag` di database telah dimodifikasi (tampered), verifikasi GCM gagal (`false`), dan sistem menolak menampilkan teks korup.
