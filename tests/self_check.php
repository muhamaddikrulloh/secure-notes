<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/includes/crypto.php';

// 1. Derivasi kunci 32-byte konsisten untuk salt dan passphrase yang sama
$salt = generate_kdf_salt();
$key1 = derive_key('KunciRahasiaUTS2026!', $salt, 600000);
$key2 = derive_key('KunciRahasiaUTS2026!', $salt, 600000);
$wrongKey = derive_key('KunciSalah123!', $salt, 600000);

assert(strlen($key1) === 32, 'Kunci hasil PBKDF2 harus 32 byte');
assert(hash_equals($key1, $key2), 'Derivasi kunci harus deterministik untuk salt yang sama');
assert(!hash_equals($key1, $wrongKey), 'Kunci berbeda harus menghasilkan derived key berbeda');

// 2. Enkripsi menghasilkan Nonce unik pada setiap pemanggilan
$plaintext = 'Catatan Rahasia UTS Keamanan Data dan Informasi';
$encA = encrypt_data($plaintext, $key1);
$encB = encrypt_data($plaintext, $key1);

assert($encA['nonce'] !== $encB['nonce'], 'Nonce tidak boleh digunakan ulang');
assert($encA['ciphertext'] !== $encB['ciphertext'], 'Ciphertext harus berbeda karena Nonce berbeda');

// 3. Dekripsi dengan kunci benar mengembalikan plaintext asli
$decrypted = decrypt_data($encA['ciphertext'], $encA['nonce'], $encA['tag'], $key1);
assert($decrypted === $plaintext, 'Dekripsi dengan kunci benar harus sesuai plaintext');

// 4. Dekripsi dengan kunci salah wajib gagal (null)
$failedWrongKey = decrypt_data($encA['ciphertext'], $encA['nonce'], $encA['tag'], $wrongKey);
assert($failedWrongKey === null, 'Dekripsi dengan kunci salah harus mengembalikan null');

// 5. Ciphertext yang dimodifikasi wajib gagal autentikasi GCM
$rawCipher = base64_decode($encA['ciphertext'], true);
$tamperedCipher = base64_encode($rawCipher ^ str_repeat("\x01", strlen($rawCipher)));
$failedTamperedCipher = decrypt_data($tamperedCipher, $encA['nonce'], $encA['tag'], $key1);
assert($failedTamperedCipher === null, 'Ciphertext yang dimodifikasi harus ditolak oleh AES-GCM');

// 6. Tag autentikasi yang dimodifikasi wajib gagal
$rawTag = base64_decode($encA['tag'], true);
$tamperedTag = base64_encode($rawTag ^ str_repeat("\x01", strlen($rawTag)));
$failedTamperedTag = decrypt_data($encA['ciphertext'], $encA['nonce'], $tamperedTag, $key1);
assert($failedTamperedTag === null, 'Tag GCM yang dimodifikasi harus ditolak');

echo "OK: Seluruh pengujian kriptografi AES-256-GCM lulus.\n";
