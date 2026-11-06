<?php
declare(strict_types=1);

if (basename($_SERVER['PHP_SELF'] ?? '') === basename(__FILE__)) {
    http_response_code(403);
    exit('Akses ditolak.');
}

const CIPHER_METHOD = 'aes-256-gcm';
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const VERIFICATION_MARKER = 'SECURENOTES_AES256GCM_VERIFIED_V1';

function generate_kdf_salt(): string
{
    return base64_encode(random_bytes(SALT_LENGTH));
}

// Turunkan kunci AES 32-byte (256-bit) dari Kunci Rahasia menggunakan PBKDF2-HMAC-SHA256
function derive_key(string $passphrase, string $saltBase64, int $iterations): string
{
    $salt = base64_decode($saltBase64, true);
    if ($salt === false || strlen($salt) < SALT_LENGTH) {
        throw new InvalidArgumentException('Salt KDF tidak valid.');
    }

    return hash_pbkdf2('sha256', $passphrase, $salt, $iterations, KEY_LENGTH, true);
}

// Enkripsi plaintext dengan AES-256-GCM menggunakan Nonce 12-byte baru dan Tag autentikasi 16-byte
function encrypt_data(string $plaintext, string $rawKey): array
{
    if (strlen($rawKey) !== KEY_LENGTH) {
        throw new InvalidArgumentException('Panjang kunci harus 32 byte untuk AES-256-GCM.');
    }

    // Nonce wajib unik untuk setiap proses enkripsi pada kunci yang sama
    $nonce = random_bytes(NONCE_LENGTH);
    $tag = '';

    $ciphertext = openssl_encrypt(
        $plaintext,
        CIPHER_METHOD,
        $rawKey,
        OPENSSL_RAW_DATA,
        $nonce,
        $tag,
        '',
        TAG_LENGTH
    );

    if ($ciphertext === false || strlen($tag) !== TAG_LENGTH) {
        throw new RuntimeException('Gagal melakukan enkripsi AES-256-GCM.');
    }

    return [
        'ciphertext' => base64_encode($ciphertext),
        'nonce' => base64_encode($nonce),
        'tag' => base64_encode($tag),
    ];
}

// Dekripsi terautentikasi AES-256-GCM; mengembalikan null jika kunci salah atau data dimodifikasi
function decrypt_data(string $ciphertextB64, string $nonceB64, string $tagB64, string $rawKey): ?string
{
    if (strlen($rawKey) !== KEY_LENGTH) {
        return null;
    }

    $ciphertext = base64_decode($ciphertextB64, true);
    $nonce = base64_decode($nonceB64, true);
    $tag = base64_decode($tagB64, true);

    if (
        $ciphertext === false ||
        $nonce === false || strlen($nonce) !== NONCE_LENGTH ||
        $tag === false || strlen($tag) !== TAG_LENGTH
    ) {
        return null;
    }

    $plaintext = openssl_decrypt(
        $ciphertext,
        CIPHER_METHOD,
        $rawKey,
        OPENSSL_RAW_DATA,
        $nonce,
        $tag
    );

    return $plaintext === false ? null : $plaintext;
}

// Verifikasi kecocokan kunci kandidat terhadap penanda terenkripsi di tabel settings
function verify_secret_key(array $settings, string $rawKey): bool
{
    $decrypted = decrypt_data(
        (string) ($settings['verification_ciphertext'] ?? ''),
        (string) ($settings['verification_nonce'] ?? ''),
        (string) ($settings['verification_tag'] ?? ''),
        $rawKey
    );

    // Bandingkan secara constant-time untuk mencegah timing attack
    return $decrypted !== null && hash_equals(VERIFICATION_MARKER, $decrypted);
}
