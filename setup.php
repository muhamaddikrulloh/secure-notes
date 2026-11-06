<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/app.php';
init_session();

if (is_initialized()) {
    header('Location: auth.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $error = 'Token keamanan CSRF tidak valid. Silakan muat ulang halaman.';
    } else {
        $passphrase = (string) ($_POST['secret_key'] ?? '');
        $confirm = (string) ($_POST['confirm_key'] ?? '');

        if (trim($passphrase) === '') {
            $error = 'Kunci Rahasia tidak boleh kosong.';
        } elseif (mb_strlen($passphrase, 'UTF-8') < 8) {
            $error = 'Kunci Rahasia minimal harus terdiri dari 8 karakter.';
        } elseif (!hash_equals($passphrase, $confirm)) {
            $error = 'Konfirmasi Kunci Rahasia tidak cocok.';
        } else {
            try {
                initialize_application($passphrase);
                header('Location: auth.php?setup=success');
                exit;
            } catch (Throwable $e) {
                $error = 'Gagal melakukan inisialisasi sistem: ' . $e->getMessage();
            }
        }
    }
}
?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <title>Inisialisasi Sistem | Secure Notes</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%231d4ed8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3'/%3E%3Cpath d='M12 11m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0'/%3E%3Cpath d='M12 12l0 2.5'/%3E%3C/svg%3E">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/css/tabler.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
    <link rel="stylesheet" href="assets/app.css?v=<?= (int) @filemtime(__DIR__ . '/assets/app.css') ?>">
</head>
<body class="d-flex flex-column min-vh-100">
    <main class="page page-center flex-fill">
        <div class="container container-tight py-4">
            <div class="text-center mb-4">
                <a href="index.php" class="navbar-brand d-inline-flex align-items-center gap-2 fw-bold text-decoration-none">
                    <span class="brand-mark" aria-hidden="true">
                        <i class="ti ti-shield-lock"></i>
                    </span>
                    <span class="brand-title">Secure Notes</span>
                </a>
            </div>

            <div class="card card-md auth-card">
                <div class="card-body p-4 p-sm-5">
                    <h1 class="h2 text-center mb-2">Inisialisasi Pertama Kali</h1>
                    <p class="text-secondary text-center small mb-4">
                        Buat Kunci Rahasia utama untuk mengenkripsi katalog antarmuka dashboard dan seluruh catatan menggunakan AES-256-GCM.
                    </p>

                    <div class="alert alert-warning mb-4" role="alert">
                        <div class="d-flex">
                            <div><i class="ti ti-alert-triangle icon alert-icon me-2" aria-hidden="true"></i></div>
                            <div class="small">
                                <strong>Penting:</strong> Kunci Rahasia tidak pernah disimpan di database.
                                Kehilangan Kunci Rahasia akan membuat seluruh catatan terenkripsi tidak dapat dipulihkan.
                            </div>
                        </div>
                    </div>

                    <?php if ($error !== ''): ?>
                        <div class="alert alert-danger mb-4" role="alert">
                            <div class="d-flex">
                                <div><i class="ti ti-alert-circle icon alert-icon me-2" aria-hidden="true"></i></div>
                                <div><?= e($error) ?></div>
                            </div>
                        </div>
                    <?php endif; ?>

                    <form action="setup.php" method="post" autocomplete="off">
                        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                        <div class="mb-3">
                            <label class="form-label required" for="setup-secret-key">Buat Kunci Rahasia</label>
                            <div class="input-group input-group-flat">
                                <input
                                    type="password"
                                    id="setup-secret-key"
                                    name="secret_key"
                                    class="form-control"
                                    placeholder="Minimal 8 karakter..."
                                    required
                                    minlength="8"
                                    autofocus
                                >
                                <span class="input-group-text">
                                    <button
                                        type="button"
                                        class="btn-toggle-secret"
                                        data-toggle-password="setup-secret-key"
                                        aria-label="Tampilkan atau sembunyikan Kunci Rahasia"
                                        title="Tampilkan/Sembunyikan Kunci Rahasia"
                                    >
                                        <i class="ti ti-eye" aria-hidden="true"></i>
                                    </button>
                                </span>
                            </div>
                        </div>

                        <div class="mb-4">
                            <label class="form-label required" for="setup-confirm-key">Konfirmasi Kunci Rahasia</label>
                            <div class="input-group input-group-flat">
                                <input
                                    type="password"
                                    id="setup-confirm-key"
                                    name="confirm_key"
                                    class="form-control"
                                    placeholder="Ulangi Kunci Rahasia..."
                                    required
                                    minlength="8"
                                >
                                <span class="input-group-text">
                                    <button
                                        type="button"
                                        class="btn-toggle-secret"
                                        data-toggle-password="setup-confirm-key"
                                        aria-label="Tampilkan atau sembunyikan Konfirmasi Kunci Rahasia"
                                        title="Tampilkan/Sembunyikan Konfirmasi Kunci"
                                    >
                                        <i class="ti ti-eye" aria-hidden="true"></i>
                                    </button>
                                </span>
                            </div>
                        </div>

                        <div class="form-footer mt-2">
                            <button type="submit" class="btn btn-primary w-100 d-inline-flex align-items-center justify-content-center gap-2">
                                <i class="ti ti-lock-check" aria-hidden="true"></i>
                                <span>Simpan Konfigurasi &amp; Enkripsi Katalog</span>
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <div class="text-center text-secondary mt-3">
                <a href="index.php" class="link-secondary d-inline-flex align-items-center gap-1 py-1 px-2">
                    <i class="ti ti-arrow-left" aria-hidden="true"></i>
                    <span>Kembali ke Halaman Utama</span>
                </a>
            </div>
        </div>
    </main>
    <script src="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/js/tabler.min.js"></script>
    <script src="assets/app.js"></script>
</body>
</html>
