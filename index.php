<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/app.php';
init_session();

$initialized = false;
try {
    $initialized = is_initialized();
} catch (Throwable) {
    $initialized = false;
}

$entryUrl = $initialized ? 'auth.php' : 'setup.php';
$primaryCtaLabel = $initialized ? 'Masukkan Kunci Rahasia' : 'Inisialisasi Sistem';
?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <title>Secure Notes | Manajement Catatan Terenkripsi</title>
    <link rel="icon" type="image/svg+xml" href="assets/logo.svg">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/css/tabler.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
    <link rel="stylesheet" href="assets/app.css?v=<?= (int) @filemtime(__DIR__ . '/assets/app.css') ?>">
</head>
<body class="d-flex flex-column min-vh-100">
    <header class="navbar navbar-expand-md d-print-none topbar-header">
        <div class="container-xl">
            <a href="index.php" class="navbar-brand d-flex align-items-center gap-2 fw-bold text-decoration-none m-0 py-2">
                <img src="assets/logo.svg" alt="Secure Notes" class="brand-logo" width="34" height="34">
                <span class="brand-title">Secure Notes</span>
            </a>
            <div class="navbar-nav flex-row order-md-last">
                <div class="nav-item">
                    <a href="<?= e($entryUrl) ?>" class="btn btn-primary d-inline-flex align-items-center gap-2">
                        <i class="ti ti-key" aria-hidden="true"></i>
                        <span>Masuk</span>
                    </a>
                </div>
            </div>
        </div>
    </header>

    <main class="page-wrapper flex-fill">
        <div class="page-body py-4 py-md-5">
            <div class="container-xl">
                <section class="landing-hero mb-4">
                    <div class="row g-0 align-items-stretch">
                        <div class="col-lg-7 p-4 p-md-5 d-flex flex-column justify-content-center">
                            <h1 class="landing-title mb-3">
                                Sistem Manajemen Catatan
                            </h1>
                            <p class="landing-lead mb-4">
                                Pengelolaan catatan konfidensial berbasis kriptografi kunci simetris AES-256-GCM.
                                Seluruh label antarmuka dashboard dan isi catatan hanya didekripsi di memori server
                                apabila Kunci Rahasia lolos verifikasi tag autentikasi 128-bit.
                            </p>
                            <div class="d-flex flex-wrap align-items-center gap-2">
                                <a href="<?= e($entryUrl) ?>" class="btn btn-primary px-4 py-2 d-inline-flex align-items-center gap-2">
                                    <i class="ti ti-lock-open" aria-hidden="true"></i>
                                    <span><?= e($primaryCtaLabel) ?></span>
                                </a>
                                <?php if (!$initialized): ?>
                                    <a href="auth.php" class="btn btn-outline-secondary px-3 py-2 d-inline-flex align-items-center gap-2">
                                        <i class="ti ti-key" aria-hidden="true"></i>
                                        <span>Halaman Otentikasi</span>
                                    </a>
                                <?php endif; ?>
                            </div>
                        </div>

                        <div class="col-lg-5">
                            <div class="spec-ledger">
                                <div class="d-flex align-items-center gap-3 mb-3 pb-3 border-bottom">
                                    <span class="spec-ledger-icon" aria-hidden="true">
                                        <i class="ti ti-shield-check"></i>
                                    </span>
                                    <div>
                                        <h2 class="h3 mb-0 fw-semibold">Spesifikasi Kriptografi</h2>
                                        <p class="text-secondary small mb-0">Arsitektur Zero-Plaintext di Database</p>
                                    </div>
                                </div>

                                <div class="spec-ledger-row">
                                    <span class="spec-ledger-key">Algoritma Cipher</span>
                                    <span class="spec-ledger-val">AES-256-GCM</span>
                                </div>
                                <div class="spec-ledger-row">
                                    <span class="spec-ledger-key">Derivasi Kunci (KDF)</span>
                                    <span class="spec-ledger-val">PBKDF2-HMAC-SHA256</span>
                                </div>
                                <div class="spec-ledger-row">
                                    <span class="spec-ledger-key">Iterasi KDF Standar</span>
                                    <span class="spec-ledger-val">600.000 Iterasi</span>
                                </div>
                                <div class="spec-ledger-row">
                                    <span class="spec-ledger-key">Ukuran Nonce / IV</span>
                                    <span class="spec-ledger-val">96-bit (12 Byte Acak)</span>
                                </div>
                                <div class="spec-ledger-row">
                                    <span class="spec-ledger-key">Tag Keutuhan Data</span>
                                    <span class="spec-ledger-val">128-bit (16 Byte GCM)</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                <section class="architecture-matrix" aria-label="Pilar Keamanan Sistem">
                    <div class="architecture-col">
                        <div class="d-flex align-items-center gap-2 mb-2">
                            <span class="telemetry-icon" aria-hidden="true">
                                <i class="ti ti-lock-square-rounded"></i>
                            </span>
                            <h2 class="h3 mb-0">Enkripsi Penuh Data &amp; UI</h2>
                        </div>
                        <p class="text-secondary small mb-0">
                            Setiap judul catatan, isi catatan, serta katalog teks antarmuka dashboard dienkripsi
                            dengan Nonce 12-byte unik sebelum disimpan ke tabel MySQL.
                        </p>
                    </div>

                    <div class="architecture-col">
                        <div class="d-flex align-items-center gap-2 mb-2">
                            <span class="telemetry-icon" aria-hidden="true">
                                <i class="ti ti-notebook"></i>
                            </span>
                            <h2 class="h3 mb-0">Operasi CRUD Terautentikasi</h2>
                        </div>
                        <p class="text-secondary small mb-0">
                            Tambah, lihat detail, pencarian, pembaruan dengan Nonce baru, dan penghapusan catatan
                            hanya diaktifkan saat kunci sesi lolos verifikasi tag GCM.
                        </p>
                    </div>

                    <div class="architecture-col">
                        <div class="d-flex align-items-center gap-2 mb-2">
                            <span class="telemetry-icon" aria-hidden="true">
                                <i class="ti ti-lock"></i>
                            </span>
                            <h2 class="h3 mb-0">Mode Pratinjau Terkunci</h2>
                        </div>
                        <p class="text-secondary small mb-0">
                            Kunci yang tidak cocok hanya menampilkan ciphertext Base64 asli dari database dan
                            menolak seluruh permintaan modifikasi data dengan status HTTP 403.
                        </p>
                    </div>
                </section>
            </div>
        </div>
    </main>

    <footer class="footer footer-transparent d-print-none border-top bg-white py-3">
        <div class="container-xl">
            <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 small text-secondary">
                <span>&copy; <?= date('Y') ?> Secure Notes</span>
                <span class="font-monospace">AES-256-GCM &middot; PBKDF2-HMAC-SHA256</span>
            </div>
        </div>
    </footer>
</body>
</html>
