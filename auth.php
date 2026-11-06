<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/app.php';
init_session();

if (!is_initialized()) {
    header('Location: setup.php');
    exit;
}

$error = '';
$setupSuccess = (($_GET['setup'] ?? '') === 'success');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $waitSeconds = check_rate_limit();
    if ($waitSeconds > 0) {
        $error = 'Terlalu banyak percobaan. Silakan tunggu ' . $waitSeconds . ' detik sebelum mencoba kembali.';
    } elseif (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $error = 'Token keamanan sesi tidak valid. Silakan coba kembali.';
    } else {
        $inputKey = (string) ($_POST['secret_key'] ?? '');

        if (trim($inputKey) === '') {
            $error = 'Kunci Rahasia tidak boleh kosong.';
        } else {
            record_key_attempt();
            $settings = get_settings();

            if ($settings === null) {
                header('Location: setup.php');
                exit;
            }

            // Turunkan kandidat kunci 32-byte dari input menggunakan salt dan iterasi di database
            $candidateKey = derive_key(
                $inputKey,
                (string) $settings['kdf_salt'],
                (int) $settings['kdf_iterations']
            );

            $isValidKey = verify_secret_key($settings, $candidateKey);

            // Regenerasi ID sesi setelah pengiriman kunci rahasia untuk mencegah session fixation
            session_regenerate_id(true);
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['last_activity'] = time();
            $_SESSION['has_key_attempt'] = true;

            // Simpan derived key di sesi server hanya jika tag autentikasi GCM valid (Mode Terbuka)
            if ($isValidKey) {
                $_SESSION['is_unlocked'] = true;
                $_SESSION['derived_key'] = base64_encode($candidateKey);
            } else {
                $_SESSION['is_unlocked'] = false;
                unset($_SESSION['derived_key']);
            }

            header('Location: dashboard.php');
            exit;
        }
    }
}
?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <title>Masukkan Kunci Rahasia | Secure Notes</title>
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
                    <h1 class="h2 text-center mb-2">Masukkan Kunci Rahasia</h1>
                    <p class="text-secondary text-center small mb-4">
                        Masukkan Kunci Rahasia simetris untuk mendekripsi antarmuka dan catatan pada dashboard.
                    </p>

                    <?php if ($setupSuccess): ?>
                        <div class="alert alert-success mb-4" role="alert">
                            <div class="d-flex">
                                <div><i class="ti ti-check icon alert-icon me-2" aria-hidden="true"></i></div>
                                <div>Inisialisasi sistem berhasil. Silakan masukkan Kunci Rahasia Anda.</div>
                            </div>
                        </div>
                    <?php endif; ?>

                    <?php if ($error !== ''): ?>
                        <div class="alert alert-danger mb-4" role="alert">
                            <div class="d-flex">
                                <div><i class="ti ti-alert-circle icon alert-icon me-2" aria-hidden="true"></i></div>
                                <div><?= e($error) ?></div>
                            </div>
                        </div>
                    <?php endif; ?>

                    <form action="auth.php" method="post" autocomplete="off">
                        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                        <div class="mb-3">
                            <label class="form-label required" for="secret-key-input">Kunci Rahasia</label>
                            <div class="input-group input-group-flat">
                                <input
                                    type="password"
                                    id="secret-key-input"
                                    name="secret_key"
                                    class="form-control"
                                    placeholder="Masukkan Kunci Rahasia..."
                                    required
                                    autofocus
                                >
                                <span class="input-group-text">
                                    <button
                                        type="button"
                                        class="btn-toggle-secret"
                                        id="btn-toggle-key"
                                        data-toggle-password="secret-key-input"
                                        aria-label="Tampilkan atau sembunyikan Kunci Rahasia"
                                        title="Tampilkan/Sembunyikan Kunci Rahasia"
                                    >
                                        <i class="ti ti-eye" aria-hidden="true"></i>
                                    </button>
                                </span>
                            </div>
                        </div>

                        <div class="form-footer mt-4">
                            <button type="submit" class="btn btn-primary w-100 d-inline-flex align-items-center justify-content-center gap-2" id="btn-submit-key">
                                <i class="ti ti-key" aria-hidden="true"></i>
                                <span>Buka Dashboard</span>
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
