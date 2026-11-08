<?php
declare(strict_types=1);

if (basename($_SERVER['PHP_SELF'] ?? '') === basename(__FILE__)) {
    http_response_code(403);
    exit('Akses ditolak.');
}

require_once __DIR__ . '/crypto.php';

function app_config(): array
{
    static $config = null;
    if ($config === null) {
        $config = require dirname(__DIR__) . '/config.php';
    }
    return $config;
}

function get_db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $cfg = app_config();
    $dsn = sprintf(
        'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
        $cfg['db_host'],
        $cfg['db_port'],
        $cfg['db_name']
    );

    $pdo = new PDO($dsn, $cfg['db_user'], $cfg['db_pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    return $pdo;
}

function init_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $isSecure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_name('SECURENOTES_SESSID');
    session_start();

    // Hentikan sesi otomatis jika melewati batas waktu inaktivitas
    $timeout = (int) (app_config()['session_timeout'] ?? 1800);
    $now = time();

    if (isset($_SESSION['last_activity']) && ($now - (int) $_SESSION['last_activity']) > $timeout) {
        destroy_user_session();
        session_start();
    }

    $_SESSION['last_activity'] = $now;

    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

function destroy_user_session(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }

    // Timpa materi kunci di memori sesi sebelum sesi dihapus
    if (isset($_SESSION['derived_key'])) {
        $_SESSION['derived_key'] = str_repeat('0', strlen((string) $_SESSION['derived_key']));
    }

    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            (bool) $params['secure'],
            (bool) $params['httponly']
        );
    }

    session_destroy();
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrf_token(): string
{
    init_session();
    return (string) $_SESSION['csrf_token'];
}

function verify_csrf(?string $token): bool
{
    init_session();
    if (!is_string($token) || $token === '' || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals((string) $_SESSION['csrf_token'], $token);
}

function set_flash(string $type, string $catalogKey): void
{
    init_session();
    $_SESSION['flash'] = [
        'type' => $type,
        'key' => $catalogKey,
    ];
}

function get_flash(): ?array
{
    init_session();
    if (empty($_SESSION['flash']) || !is_array($_SESSION['flash'])) {
        return null;
    }
    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);
    return $flash;
}

// Batasi percobaan input kunci maksimal 8 kali per 60 detik berdasarkan hash IP
function check_rate_limit(int $maxAttempts = 8, int $windowSeconds = 60): int
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $file = sys_get_temp_dir() . '/sn_rate_' . hash('sha256', $ip) . '.json';
    $now = time();
    $attempts = [];

    if (is_file($file)) {
        $raw = @file_get_contents($file);
        $decoded = is_string($raw) ? json_decode($raw, true) : null;
        if (is_array($decoded)) {
            $attempts = array_values(array_filter(
                $decoded,
                static fn($ts): bool => is_int($ts) && ($now - $ts) < $windowSeconds
            ));
        }
    }

    if (count($attempts) >= $maxAttempts) {
        $oldest = min($attempts);
        return max(1, $windowSeconds - ($now - $oldest));
    }

    return 0;
}

function record_key_attempt(int $windowSeconds = 60): void
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $file = sys_get_temp_dir() . '/sn_rate_' . hash('sha256', $ip) . '.json';
    $now = time();
    $attempts = [];

    if (is_file($file)) {
        $raw = @file_get_contents($file);
        $decoded = is_string($raw) ? json_decode($raw, true) : null;
        if (is_array($decoded)) {
            $attempts = array_values(array_filter(
                $decoded,
                static fn($ts): bool => is_int($ts) && ($now - $ts) < $windowSeconds
            ));
        }
    }

    $attempts[] = $now;
    @file_put_contents($file, json_encode($attempts), LOCK_EX);
}

function get_settings(): ?array
{
    $stmt = get_db()->query('SELECT * FROM settings WHERE id = 1 LIMIT 1');
    $row = $stmt->fetch();
    return $row ?: null;
}

function is_initialized(): bool
{
    return get_settings() !== null;
}

function has_entered_key(): bool
{
    init_session();
    return !empty($_SESSION['has_key_attempt']);
}

function is_unlocked(): bool
{
    init_session();
    return !empty($_SESSION['is_unlocked']) && get_session_key() !== null;
}

function get_session_key(): ?string
{
    init_session();
    if (empty($_SESSION['derived_key']) || !is_string($_SESSION['derived_key'])) {
        return null;
    }

    $raw = base64_decode($_SESSION['derived_key'], true);
    if ($raw === false || strlen($raw) !== KEY_LENGTH) {
        return null;
    }

    return $raw;
}

// Katalog teks awal hanya dipakai saat setup pertama kali untuk dienkripsi ke tabel ui_texts
function get_initial_ui_catalog(): array
{
    return [
        // Identitas Aplikasi & Navigasi
        'app_name' => 'Secure Notes',
        'app_subtitle' => 'Brankas Kriptografi AES-256-GCM',
        'nav_overview' => 'Dashboard',
        'nav_notes' => 'Catatan',
        'nav_security_badge' => 'AES-256-GCM Aktif',
        'nav_mode_unlocked' => 'Kunci Terverifikasi',
        'nav_mode_locked' => 'Mode Terkunci: Pratinjau Ciphertext',
        'sr_logout' => 'Keluar dari Sesi',
        'tooltip_logout' => 'Keluar Sesi',

        // Judul Halaman & Seksi
        'page_pretitle_overview' => 'Panel Kriptografi Simetris',
        'page_title_overview' => 'Ringkasan Keamanan & Catatan',
        'page_pretitle_notes' => 'Penyimpanan Terenkripsi AES-256-GCM',
        'page_title_notes' => 'Manajemen Catatan',
        'section_recent_notes' => 'Catatan Terbaru',
        'section_all_notes' => 'Daftar Catatan',
        'section_crypto_status' => 'Parameter & Status Kriptografi',

        // Kartu Statistik Dashboard
        'stat_notes_label' => 'Total Catatan',
        'stat_notes_sub' => 'Terenkripsi di Database MySQL',
        'stat_count_suffix' => 'Catatan Tersimpan',
        'stat_cipher_label' => 'Algoritma & Mode Cipher',
        'stat_cipher_val' => 'AES-256-GCM (Tag 128-bit)',
        'stat_kdf_label' => 'Derivasi Kunci (KDF)',
        'stat_kdf_val' => 'PBKDF2-HMAC-SHA256',
        'stat_status_label' => 'Status Otentikasi Kunci',
        'stat_status_unlocked' => 'Kunci Valid (Dekripsi Aktif)',
        'stat_status_locked' => 'Kunci Ditolak (Hanya Ciphertext)',

        // Pencarian
        'search_label' => 'Cari Catatan',
        'search_placeholder' => 'Ketik kata kunci judul atau isi catatan...',
        'search_btn' => 'Cari',
        'search_reset' => 'Reset',
        'search_info' => 'Menampilkan hasil pencarian untuk kata kunci:',

        // Tombol & Tooltip
        'btn_add_note' => 'Tambah Catatan',
        'btn_view_all' => 'Kelola Semua Catatan',
        'btn_view' => 'Detail',
        'btn_edit' => 'Edit',
        'btn_delete' => 'Hapus',
        'btn_save' => 'Simpan',
        'btn_update' => 'Simpan Perubahan',
        'btn_cancel' => 'Batal',
        'btn_close' => 'Tutup',
        'tooltip_view' => 'Lihat detail catatan',
        'tooltip_edit' => 'Edit catatan',
        'tooltip_delete' => 'Hapus catatan',
        'tooltip_locked_action' => 'Dinonaktifkan pada Mode Terkunci',

        // Tabel Catatan
        'th_title' => 'Judul Catatan',
        'th_content' => 'Ringkasan Isi',
        'th_created' => 'Waktu Dibuat',
        'th_updated' => 'Diperbarui',
        'th_actions' => 'Aksi',
        'cell_time_locked' => 'Waktu Terenkripsi (AES-GCM)',
        'cell_tampered' => 'Data Dimodifikasi',

        // Formulir & Modal CRUD
        'modal_add_title' => 'Tambah Catatan',
        'modal_edit_title' => 'Edit Catatan',
        'modal_view_title' => 'Detail Catatan',
        'modal_tampered_title' => 'Peringatan Integritas Data',
        'modal_tampered_desc' => 'Tag autentikasi AES-256-GCM tidak valid. Data ini telah dimodifikasi atau rusak di database sehingga hanya ciphertext yang ditampilkan.',
        'form_title_label' => 'Judul Catatan',
        'form_title_placeholder' => 'Masukkan judul catatan...',
        'form_content_label' => 'Isi Catatan',
        'form_content_placeholder' => 'Masukkan isi catatan yang akan dienkripsi...',
        'form_crypto_hint' => 'Data dienkripsi menggunakan AES-256-GCM dengan Nonce 12-byte acak baru sebelum disimpan ke MySQL.',
        'modal_delete_title' => 'Konfirmasi Hapus Catatan',
        'modal_delete_desc' => 'Apakah Anda yakin ingin menghapus catatan ini secara permanen dari database?',

        // Modal Konfirmasi Keluar (Logout)
        'modal_logout_title' => 'Konfirmasi Keluar',
        'modal_logout_desc' => 'Apakah Anda yakin ingin keluar?',
        'btn_confirm_logout' => 'Keluar',

        // Empty State & Alert
        'empty_notes_title' => 'Tidak Ada Catatan',
        'empty_notes_desc' => 'Belum ada catatan yang tersimpan atau cocok dengan pencarian Anda.',
        'alert_unlocked_title' => 'Dekripsi Terautentikasi Berhasil',
        'alert_unlocked_desc' => 'Kunci Rahasia terverifikasi melalui tag autentikasi AES-256-GCM. Seluruh teks antarmuka dan catatan telah didekripsi.',
        'alert_locked_title' => 'Mode Terkunci: Hanya Pratinjau Ciphertext',
        'alert_locked_desc' => 'Kunci Rahasia tidak cocok dengan tag autentikasi AES-256-GCM. Seluruh label antarmuka dan catatan ditampilkan sebagai ciphertext Base64 asli dari database dan operasi tulis dinonaktifkan.',
        'flash_created' => 'Catatan baru berhasil dienkripsi dan disimpan.',
        'flash_updated' => 'Catatan berhasil diperbarui dan dienkripsi ulang dengan Nonce baru.',
        'flash_deleted' => 'Catatan berhasil dihapus secara permanen.',
        'flash_err_locked' => 'Akses ditolak: Operasi perubahan data tidak diizinkan dalam Mode Terkunci.',
        'flash_err_validation' => 'Validasi gagal: Judul dan isi catatan tidak boleh kosong.',
        'flash_err_csrf' => 'Permintaan ditolak: Token keamanan CSRF tidak valid.',
        'flash_err_notfound' => 'Catatan tidak ditemukan.',
    ];
}

function get_initial_sample_notes(): array
{
    return [
        [
            'title' => 'Protokol Cadangan Kunci Server Produksi',
            'content' => 'Kunci cadangan HSM disimpan pada brankas fisik Ruang Server Lantai 3 dengan skema pembagian rahasia Shamir (3-dari-5 pemegang otoritas). Evaluasi integritas dilakukan setiap awal semester.',
        ],
        [
            'title' => 'Konfigurasi Kredensial Database Internal',
            'content' => 'Seluruh koneksi antar-layanan wajib menggunakan TLS 1.3 dan akun dengan hak akses minimum (least privilege). Rotasi kredensial basis data dijadwalkan setiap 90 hari.',
        ],
        [
            'title' => 'Catatan Audit Keamanan Data & Informasi',
            'content' => 'Verifikasi implementasi AES-256-GCM memastikan setiap record memiliki Nonce 96-bit unik dan Authentication Tag 128-bit untuk menjamin kerahasiaan sekaligus keutuhan data.',
        ],
    ];
}

// Inisialisasi pertama kali dalam satu transaksi database agar atomik dan tidak dapat dijalankan ulang
function initialize_application(string $passphrase): void
{
    $pdo = get_db();

    if (is_initialized()) {
        throw new RuntimeException('Aplikasi sudah diinisialisasi sebelumnya.');
    }

    $iterations = (int) (app_config()['kdf_iterations'] ?? 600000);
    $salt = generate_kdf_salt();
    $derivedKey = derive_key($passphrase, $salt, $iterations);
    $verification = encrypt_data(VERIFICATION_MARKER, $derivedKey);

    $pdo->beginTransaction();

    try {
        $stmtCheck = $pdo->query('SELECT COUNT(*) FROM settings');
        if ((int) $stmtCheck->fetchColumn() > 0) {
            throw new RuntimeException('Konfigurasi sudah tersedia.');
        }

        $stmtSettings = $pdo->prepare(
            'INSERT INTO settings (id, kdf_salt, kdf_iterations, verification_ciphertext, verification_nonce, verification_tag)
             VALUES (1, :salt, :iterations, :ciphertext, :nonce, :tag)'
        );
        $stmtSettings->execute([
            ':salt' => $salt,
            ':iterations' => $iterations,
            ':ciphertext' => $verification['ciphertext'],
            ':nonce' => $verification['nonce'],
            ':tag' => $verification['tag'],
        ]);

        // Enkripsi seluruh katalog teks antarmuka ke tabel ui_texts dengan Nonce unik per item
        $pdo->exec('DELETE FROM ui_texts');
        $stmtUi = $pdo->prepare(
            'INSERT INTO ui_texts (text_key, ciphertext, nonce, tag)
             VALUES (:text_key, :ciphertext, :nonce, :tag)'
        );

        foreach (get_initial_ui_catalog() as $textKey => $plaintext) {
            $enc = encrypt_data($plaintext, $derivedKey);
            $stmtUi->execute([
                ':text_key' => $textKey,
                ':ciphertext' => $enc['ciphertext'],
                ':nonce' => $enc['nonce'],
                ':tag' => $enc['tag'],
            ]);
        }

        // Enkripsi catatan sampel awal agar database langsung memiliki ciphertext nyata
        $stmtCountNotes = $pdo->query('SELECT COUNT(*) FROM notes');
        if ((int) $stmtCountNotes->fetchColumn() === 0) {
            $stmtNote = $pdo->prepare(
                'INSERT INTO notes (title_ciphertext, title_nonce, title_tag, content_ciphertext, content_nonce, content_tag)
                 VALUES (:tc, :tn, :tt, :cc, :cn, :ct)'
            );
            foreach (get_initial_sample_notes() as $sample) {
                $encTitle = encrypt_data($sample['title'], $derivedKey);
                $encContent = encrypt_data($sample['content'], $derivedKey);
                $stmtNote->execute([
                    ':tc' => $encTitle['ciphertext'],
                    ':tn' => $encTitle['nonce'],
                    ':tt' => $encTitle['tag'],
                    ':cc' => $encContent['ciphertext'],
                    ':cn' => $encContent['nonce'],
                    ':ct' => $encContent['tag'],
                ]);
            }
        }

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}

function load_encrypted_ui_catalog(): array
{
    static $catalog = null;
    if ($catalog !== null) {
        return $catalog;
    }

    $pdo = get_db();
    $stmt = $pdo->query('SELECT text_key, ciphertext, nonce, tag FROM ui_texts');
    $catalog = [];
    foreach ($stmt->fetchAll() as $row) {
        $catalog[$row['text_key']] = $row;
    }

    if (is_unlocked()) {
        $rawKey = get_session_key();
        if ($rawKey !== null) {
            $expectedCatalog = get_initial_ui_catalog();
            $stmtUpsert = null;
            foreach ($expectedCatalog as $textKey => $plaintext) {
                $needsUpdate = !isset($catalog[$textKey]);
                if (!$needsUpdate) {
                    $currentText = decrypt_data(
                        (string) $catalog[$textKey]['ciphertext'],
                        (string) $catalog[$textKey]['nonce'],
                        (string) $catalog[$textKey]['tag'],
                        $rawKey
                    );
                    $needsUpdate = ($currentText !== null && $currentText !== $plaintext);
                }

                if ($needsUpdate) {
                    if ($stmtUpsert === null) {
                        $stmtUpsert = $pdo->prepare(
                            'INSERT INTO ui_texts (text_key, ciphertext, nonce, tag) VALUES (:text_key, :ciphertext, :nonce, :tag)
                             ON DUPLICATE KEY UPDATE ciphertext = VALUES(ciphertext), nonce = VALUES(nonce), tag = VALUES(tag)'
                        );
                    }
                    $enc = encrypt_data($plaintext, $rawKey);
                    $stmtUpsert->execute([
                        ':text_key' => $textKey,
                        ':ciphertext' => $enc['ciphertext'],
                        ':nonce' => $enc['nonce'],
                        ':tag' => $enc['tag'],
                    ]);
                    $catalog[$textKey] = [
                        'text_key' => $textKey,
                        'ciphertext' => $enc['ciphertext'],
                        'nonce' => $enc['nonce'],
                        'tag' => $enc['tag'],
                    ];
                }
            }
        }
    }

    return $catalog;
}

// Render teks UI: dekripsi saat Mode Terbuka, atau kembalikan ciphertext Base64 asli saat Mode Terkunci
function ui_text(string $key): string
{
    static $resolved = [];
    if (isset($resolved[$key])) {
        return $resolved[$key];
    }

    $catalog = load_encrypted_ui_catalog();
    if (!isset($catalog[$key])) {
        $initial = get_initial_ui_catalog();
        return $resolved[$key] = $initial[$key] ?? '';
    }

    $entry = $catalog[$key];

    if (is_unlocked()) {
        $rawKey = get_session_key();
        if ($rawKey !== null) {
            $decrypted = decrypt_data(
                (string) $entry['ciphertext'],
                (string) $entry['nonce'],
                (string) $entry['tag'],
                $rawKey
            );
            if ($decrypted !== null) {
                return $resolved[$key] = $decrypted;
            }
        }
    }

    return $resolved[$key] = (string) $entry['ciphertext'];
}

function render_note_count(int $count): string
{
    if (is_unlocked()) {
        return $count . ' ' . ui_text('stat_count_suffix');
    }
    return ui_text('stat_count_suffix');
}

function render_note_timestamp(string $timestamp): string
{
    if (!is_unlocked()) {
        return ui_text('cell_time_locked');
    }

    $time = strtotime($timestamp);
    if ($time === false) {
        return $timestamp;
    }

    return date('d M Y, H:i', $time);
}

// Ambil seluruh catatan; dekripsi dan filter pencarian hanya dieksekusi jika Mode Terbuka
function fetch_all_notes(string $searchQuery = ''): array
{
    $stmt = get_db()->query('SELECT * FROM notes ORDER BY updated_at DESC, id DESC');
    $rows = $stmt->fetchAll();

    $unlocked = is_unlocked();
    $rawKey = $unlocked ? get_session_key() : null;
    $results = [];

    foreach ($rows as $row) {
        $title = (string) $row['title_ciphertext'];
        $content = (string) $row['content_ciphertext'];
        $tampered = false;

        if ($unlocked && $rawKey !== null) {
            $decTitle = decrypt_data(
                (string) $row['title_ciphertext'],
                (string) $row['title_nonce'],
                (string) $row['title_tag'],
                $rawKey
            );
            $decContent = decrypt_data(
                (string) $row['content_ciphertext'],
                (string) $row['content_nonce'],
                (string) $row['content_tag'],
                $rawKey
            );

            if ($decTitle !== null && $decContent !== null) {
                $title = $decTitle;
                $content = $decContent;
            } else {
                // Jika ciphertext atau tag di database telah dimodifikasi, tolak hasil korup
                $tampered = true;
            }
        }

        // Pencarian plaintext di PHP hanya dijalankan pada Mode Terbuka untuk catatan yang valid
        if ($unlocked && $searchQuery !== '') {
            if ($tampered) {
                continue;
            }
            $haystackTitle = mb_strtolower($title, 'UTF-8');
            $haystackContent = mb_strtolower($content, 'UTF-8');
            $needle = mb_strtolower($searchQuery, 'UTF-8');

            if (!str_contains($haystackTitle, $needle) && !str_contains($haystackContent, $needle)) {
                continue;
            }
        }

        $results[] = [
            'id' => (int) $row['id'],
            'title' => $title,
            'content' => $content,
            'title_ciphertext' => (string) $row['title_ciphertext'],
            'content_ciphertext' => (string) $row['content_ciphertext'],
            'tampered' => $tampered,
            'created_at' => render_note_timestamp((string) $row['created_at']),
            'updated_at' => render_note_timestamp((string) $row['updated_at']),
        ];
    }

    return $results;
}
