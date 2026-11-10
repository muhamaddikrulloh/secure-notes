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
$ctaLabel = $initialized ? 'Buka Ruang Catatan' : 'Inisialisasi Sistem';
?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <title>Secure Notes | Sistem Informasi Manajemen Catatan</title>
    <link rel="icon" type="image/svg+xml" href="assets/logo.svg">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/css/tabler.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
    <link rel="stylesheet" href="assets/app.css?v=<?= (int) @filemtime(__DIR__ . '/assets/app.css') ?>">
</head>
<body class="d-flex flex-column min-vh-100">
    <header class="navbar navbar-expand-md topbar-header">
        <div class="container-xl">
            <a href="index.php" class="navbar-brand d-flex align-items-center gap-2 fw-bold text-decoration-none m-0 py-2">
                <img src="assets/logo.svg" alt="Secure Notes" class="brand-logo" width="30" height="30">
                <span class="brand-title">Secure Notes</span>
            </a>

            <div class="d-flex align-items-center ms-auto">
                <a href="<?= e($entryUrl) ?>" class="btn btn-primary btn-sm px-3">
                    Masuk
                </a>
            </div>
        </div>
    </header>

    <main class="flex-fill">
        <section class="landing-hero">
            <div class="container-xl">
                <div class="row g-4 g-lg-5 align-items-center">
                    <div class="col-lg-6">
                        <h1 class="landing-title mb-3">
                            Kelola Catatan Harian dan Dokumentasi secara Terpusat
                        </h1>
                        <p class="landing-lead mb-4">
                            Sistem informasi sederhana untuk mencatat, mencari, dan memperbarui dokumen penting dalam satu ruang kerja yang rapi dan terlindungi.
                        </p>
                        <a href="<?= e($entryUrl) ?>" class="btn btn-primary px-4">
                            <?= e($ctaLabel) ?>
                        </a>
                    </div>

                    <div class="col-lg-6">
                        <div class="preview-card" aria-label="Pratinjau Antarmuka Secure Notes">
                            <div class="preview-header">
                                <span class="fw-semibold small">Daftar Catatan</span>
                                <span class="preview-search">Cari judul atau isi catatan...</span>
                            </div>
                            <div class="preview-list">
                                <div class="preview-row">
                                    <div>
                                        <div class="preview-row-title">Notulensi Rapat Koordinasi Tim</div>
                                        <div class="preview-row-meta">Ringkasan evaluasi dan rencana tindak lanjut...</div>
                                    </div>
                                    <span class="preview-row-date">10 Nov</span>
                                </div>
                                <div class="preview-row">
                                    <div>
                                        <div class="preview-row-title">Daftar Inventaris Perangkat Kerja</div>
                                        <div class="preview-row-meta">Pencatatan perangkat operasional dan jadwal...</div>
                                    </div>
                                    <span class="preview-row-date">09 Nov</span>
                                </div>
                                <div class="preview-row">
                                    <div>
                                        <div class="preview-row-title">Rencana Pengembangan Modul Internal</div>
                                        <div class="preview-row-meta">Prioritas pembaruan antarmuka dan laporan...</div>
                                    </div>
                                    <span class="preview-row-date">08 Nov</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="landing-features" id="fitur">
            <div class="container-xl">
                <h2 class="h3 mb-3">Fitur Utama</h2>
                <div class="row g-3">
                    <div class="col-sm-6 col-lg-3">
                        <div class="feature-card h-100">
                            <div class="feature-icon mb-2" aria-hidden="true">
                                <i class="ti ti-plus"></i>
                            </div>
                            <h3 class="h4 mb-1">Buat Catatan</h3>
                            <p class="text-secondary small mb-0">
                                Simpan catatan baru kapan saja melalui formulir yang ringkas dan mudah digunakan.
                            </p>
                        </div>
                    </div>

                    <div class="col-sm-6 col-lg-3">
                        <div class="feature-card h-100">
                            <div class="feature-icon mb-2" aria-hidden="true">
                                <i class="ti ti-search"></i>
                            </div>
                            <h3 class="h4 mb-1">Pencarian Cepat</h3>
                            <p class="text-secondary small mb-0">
                                Temukan catatan secara langsung berdasarkan kata kunci pada judul maupun isi.
                            </p>
                        </div>
                    </div>

                    <div class="col-sm-6 col-lg-3">
                        <div class="feature-card h-100">
                            <div class="feature-icon mb-2" aria-hidden="true">
                                <i class="ti ti-edit"></i>
                            </div>
                            <h3 class="h4 mb-1">Lihat &amp; Edit</h3>
                            <p class="text-secondary small mb-0">
                                Baca isi catatan secara utuh dan perbarui informasi kapan pun diperlukan.
                            </p>
                        </div>
                    </div>

                    <div class="col-sm-6 col-lg-3">
                        <div class="feature-card h-100">
                            <div class="feature-icon mb-2" aria-hidden="true">
                                <i class="ti ti-trash"></i>
                            </div>
                            <h3 class="h4 mb-1">Hapus Catatan</h3>
                            <p class="text-secondary small mb-0">
                                Bersihkan catatan yang sudah tidak diperlukan dengan konfirmasi penghapusan.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <footer class="border-top bg-white py-3">
        <div class="container-xl d-flex align-items-center justify-content-start small text-secondary">
            <span>&copy; <?= date('Y') ?> Secure Notes</span>
        </div>
    </footer>
</body>
</html>
