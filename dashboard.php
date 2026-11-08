<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/app.php';
init_session();

if (!is_initialized()) {
    header('Location: setup.php');
    exit;
}

if (!has_entered_key()) {
    header('Location: auth.php');
    exit;
}

$unlocked = is_unlocked();
$currentView = (($_GET['view'] ?? 'overview') === 'notes') ? 'notes' : 'overview';

// Penanganan operasi CRUD di sisi server (hanya diizinkan saat Mode Terbuka)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Validasi token CSRF untuk mencegah serangan Cross-Site Request Forgery
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        set_flash('danger', 'flash_err_csrf');
    } elseif (!$unlocked || get_session_key() === null) {
        // 2. Tolak seluruh operasi tulis (HTTP 403) apabila kunci rahasia salah (Mode Terkunci)
        http_response_code(403);
        set_flash('danger', 'flash_err_locked');
    } else {
        $action = (string) ($_POST['action'] ?? '');
        $rawKey = get_session_key();
        $pdo = get_db();

        // [CREATE] Tambah catatan baru: enkripsi judul & isi dengan AES-256-GCM (Nonce acak per field)
        if ($action === 'create') {
            $title = trim((string) ($_POST['title'] ?? ''));
            $content = trim((string) ($_POST['content'] ?? ''));

            if ($title === '' || $content === '') {
                set_flash('danger', 'flash_err_validation');
            } else {
                $encTitle = encrypt_data($title, $rawKey);
                $encContent = encrypt_data($content, $rawKey);

                $stmt = $pdo->prepare(
                    'INSERT INTO notes (title_ciphertext, title_nonce, title_tag, content_ciphertext, content_nonce, content_tag)
                     VALUES (:tc, :tn, :tt, :cc, :cn, :ct)'
                );
                $stmt->execute([
                    ':tc' => $encTitle['ciphertext'],
                    ':tn' => $encTitle['nonce'],
                    ':tt' => $encTitle['tag'],
                    ':cc' => $encContent['ciphertext'],
                    ':cn' => $encContent['nonce'],
                    ':ct' => $encContent['tag'],
                ]);

                set_flash('success', 'flash_created');
                header('Location: dashboard.php?view=notes');
                exit;
            }
        // [UPDATE] Ubah catatan: enkripsi ulang dengan Nonce 12-byte baru & Tag 16-byte baru
        } elseif ($action === 'update') {
            $noteId = (int) ($_POST['note_id'] ?? 0);
            $title = trim((string) ($_POST['title'] ?? ''));
            $content = trim((string) ($_POST['content'] ?? ''));

            if ($noteId <= 0 || $title === '' || $content === '') {
                set_flash('danger', 'flash_err_validation');
            } else {
                $stmtCheck = $pdo->prepare('SELECT id FROM notes WHERE id = :id LIMIT 1');
                $stmtCheck->execute([':id' => $noteId]);

                if (!$stmtCheck->fetch()) {
                    set_flash('danger', 'flash_err_notfound');
                } else {
                    // Enkripsi ulang menggunakan Nonce 12-byte baru agar tidak pernah terjadi nonce reuse
                    $encTitle = encrypt_data($title, $rawKey);
                    $encContent = encrypt_data($content, $rawKey);

                    $stmt = $pdo->prepare(
                        'UPDATE notes
                         SET title_ciphertext = :tc,
                             title_nonce = :tn,
                             title_tag = :tt,
                             content_ciphertext = :cc,
                             content_nonce = :cn,
                             content_tag = :ct,
                             updated_at = CURRENT_TIMESTAMP
                         WHERE id = :id'
                    );
                    $stmt->execute([
                        ':tc' => $encTitle['ciphertext'],
                        ':tn' => $encTitle['nonce'],
                        ':tt' => $encTitle['tag'],
                        ':cc' => $encContent['ciphertext'],
                        ':cn' => $encContent['nonce'],
                        ':ct' => $encContent['tag'],
                        ':id' => $noteId,
                    ]);

                    set_flash('success', 'flash_updated');
                    header('Location: dashboard.php?view=notes');
                    exit;
                }
            }
        // [DELETE] Hapus catatan permanen dari tabel notes berdasarkan ID
        } elseif ($action === 'delete') {
            $noteId = (int) ($_POST['note_id'] ?? 0);
            if ($noteId <= 0) {
                set_flash('danger', 'flash_err_notfound');
            } else {
                $stmt = $pdo->prepare('DELETE FROM notes WHERE id = :id');
                $stmt->execute([':id' => $noteId]);

                set_flash('success', 'flash_deleted');
                header('Location: dashboard.php?view=notes');
                exit;
            }
        }
    }
}

// [READ & SEARCH] Ambil catatan dari DB; dekripsi & filter pencarian hanya dieksekusi saat Mode Terbuka
$searchQuery = $unlocked ? trim((string) ($_GET['q'] ?? '')) : '';
$allNotes = fetch_all_notes('');
$totalNotesCount = count($allNotes);
$displayedNotes = ($searchQuery !== '') ? fetch_all_notes($searchQuery) : $allNotes;
$recentNotes = array_slice($allNotes, 0, 5);
$flash = ($currentView === 'notes') ? get_flash() : null;
?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <title><?= e(ui_text('app_name')) ?></title>
    <link rel="icon" type="image/svg+xml" href="assets/logo.svg">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/css/tabler.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
    <link rel="stylesheet" href="assets/app.css?v=<?= (int) @filemtime(__DIR__ . '/assets/app.css') ?>">
</head>
<body class="layout-fluid <?= $unlocked ? 'mode-unlocked' : 'mode-locked' ?>">
    <div class="page">
        <!-- Sidebar Navigasi -->
        <aside class="navbar navbar-vertical navbar-expand-lg" data-bs-theme="light">
            <div class="container-fluid">
                <button
                    class="navbar-toggler"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#sidebar-menu"
                    aria-controls="sidebar-menu"
                    aria-expanded="false"
                    aria-label="<?= e(ui_text('nav_overview')) ?>"
                >
                    <span class="navbar-toggler-icon"></span>
                </button>

                <h1 class="navbar-brand justify-content-start w-100">
                    <a href="dashboard.php?view=overview" class="d-flex align-items-center gap-2 text-decoration-none w-100">
                        <img src="assets/logo.svg" alt="Secure Notes" class="brand-logo" width="34" height="34">
                        <span class="crypto-truncate brand-title fw-bold" title="<?= e(ui_text('app_name')) ?>">
                            <?= e(ui_text('app_name')) ?>
                        </span>
                    </a>
                </h1>

                <div class="collapse navbar-collapse" id="sidebar-menu">
                    <ul class="navbar-nav">
                        <li class="nav-item <?= $currentView === 'overview' ? 'active' : '' ?>">
                            <a class="nav-link" href="dashboard.php?view=overview" id="nav-link-overview">
                                <span class="nav-link-icon" aria-hidden="true">
                                    <i class="ti ti-layout-dashboard"></i>
                                </span>
                                <span class="nav-link-title crypto-truncate" title="<?= e(ui_text('nav_overview')) ?>">
                                    <?= e(ui_text('nav_overview')) ?>
                                </span>
                            </a>
                        </li>
                        <li class="nav-item <?= $currentView === 'notes' ? 'active' : '' ?>">
                            <a class="nav-link" href="dashboard.php?view=notes" id="nav-link-notes">
                                <span class="nav-link-icon" aria-hidden="true">
                                    <i class="ti ti-notebook"></i>
                                </span>
                                <span class="nav-link-title crypto-truncate" title="<?= e(ui_text('nav_notes')) ?>">
                                    <?= e(ui_text('nav_notes')) ?>
                                </span>
                            </a>
                        </li>
                    </ul>

                    <!-- Tombol Logout di Bagian Bawah Sidebar -->
                    <div class="sidebar-footer">
                        <button
                            type="button"
                            id="btn-sidebar-logout"
                            class="btn"
                            data-bs-toggle="modal"
                            data-bs-target="#modal-logout"
                            aria-label="<?= e(ui_text('sr_logout')) ?>"
                            title="<?= e(ui_text('tooltip_logout')) ?>"
                        >
                            <i class="ti ti-logout" aria-hidden="true"></i>
                            <span class="crypto-truncate"><?= e(ui_text('btn_confirm_logout')) ?></span>
                        </button>
                    </div>
                </div>
            </div>
        </aside>

        <div class="page-wrapper">
            <!-- Navbar Atas -->
            <header class="navbar navbar-expand-md d-print-none topbar-header">
                <div class="container-xl">
                    <div class="d-flex align-items-center gap-2 overflow-hidden">
                        <span class="status-pill status-pill-neutral">
                            <i class="ti ti-lock-check" aria-hidden="true"></i>
                            <span class="crypto-truncate" style="max-width: 210px;"><?= e(ui_text('nav_security_badge')) ?></span>
                        </span>
                    </div>
                    <div class="navbar-nav flex-row order-md-last ms-auto">
                        <div class="nav-item">
                            <span class="status-pill <?= $unlocked ? 'status-pill-unlocked' : 'status-pill-locked' ?>">
                                <i class="ti <?= $unlocked ? 'ti-lock-open' : 'ti-lock' ?>" aria-hidden="true"></i>
                                <span class="crypto-truncate" style="max-width: 260px;" id="badge-dashboard-mode">
                                    <?= e(ui_text($unlocked ? 'nav_mode_unlocked' : 'nav_mode_locked')) ?>
                                </span>
                            </span>
                        </div>
                    </div>
                </div>
            </header>

            <main>
                <!-- Header Halaman -->
                <div class="page-header d-print-none mt-3 mb-2">
                    <div class="container-xl">
                        <div class="row g-3 align-items-center">
                            <div class="col overflow-hidden">
                                <h2 class="page-title crypto-truncate mb-1" id="dashboard-page-title">
                                    <?= e(ui_text($currentView === 'notes' ? 'page_title_notes' : 'page_title_overview')) ?>
                                </h2>
                                <div class="text-secondary small crypto-truncate">
                                    <?= e(ui_text($currentView === 'notes' ? 'page_pretitle_notes' : 'page_pretitle_overview')) ?>
                                </div>
                            </div>
                            <div class="col-auto ms-auto d-print-none">
                                <div class="btn-list">
                                    <button
                                        type="button"
                                        id="btn-open-add-modal"
                                        class="btn btn-primary d-inline-flex align-items-center gap-2"
                                        <?php if ($unlocked): ?>
                                            data-bs-toggle="modal"
                                            data-bs-target="#modal-add-note"
                                        <?php else: ?>
                                            disabled
                                            aria-disabled="true"
                                            title="<?= e(ui_text('tooltip_locked_action')) ?>"
                                        <?php endif; ?>
                                    >
                                        <i class="ti ti-plus" aria-hidden="true"></i>
                                        <span class="crypto-truncate" style="max-width: 190px;"><?= e(ui_text('btn_add_note')) ?></span>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Isi Halaman Dashboard -->
                <div class="page-body">
                    <div class="container-xl">
                        <!-- Banner Status Mode Kriptografi -->
                        <div class="alert <?= $unlocked ? 'alert-success' : 'alert-warning' ?> mb-4" role="alert" id="alert-crypto-mode">
                            <div class="d-flex align-items-start gap-2">
                                <div>
                                    <i class="ti <?= $unlocked ? 'ti-shield-check' : 'ti-lock-exclamation' ?> icon alert-icon" aria-hidden="true"></i>
                                </div>
                                <div class="overflow-hidden">
                                    <h3 class="alert-title crypto-truncate">
                                        <?= e(ui_text($unlocked ? 'alert_unlocked_title' : 'alert_locked_title')) ?>
                                    </h3>
                                    <div class="text-secondary small crypto-wrap">
                                        <?= e(ui_text($unlocked ? 'alert_unlocked_desc' : 'alert_locked_desc')) ?>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <?php if ($currentView === 'overview'): ?>
                            <!-- Panel Telemetri Kriptografi Terpadu -->
                            <section class="telemetry-panel mb-4" aria-label="<?= e(ui_text('section_crypto_status')) ?>">
                                <div class="telemetry-grid">
                                    <div class="telemetry-cell">
                                        <div class="telemetry-header">
                                            <span class="telemetry-icon" aria-hidden="true">
                                                <i class="ti ti-notes"></i>
                                            </span>
                                            <span class="telemetry-label crypto-truncate" title="<?= e(ui_text('stat_notes_label')) ?>">
                                                <?= e(ui_text('stat_notes_label')) ?>
                                            </span>
                                        </div>
                                        <div class="telemetry-value crypto-truncate" id="stat-total-notes">
                                            <?= e(render_note_count($totalNotesCount)) ?>
                                        </div>
                                        <div class="telemetry-meta crypto-truncate">
                                            <?= e(ui_text('stat_notes_sub')) ?>
                                        </div>
                                    </div>

                                    <div class="telemetry-cell">
                                        <div class="telemetry-header">
                                            <span class="telemetry-icon" aria-hidden="true">
                                                <i class="ti ti-shield-lock"></i>
                                            </span>
                                            <span class="telemetry-label crypto-truncate" title="<?= e(ui_text('stat_cipher_label')) ?>">
                                                <?= e(ui_text('stat_cipher_label')) ?>
                                            </span>
                                        </div>
                                        <div class="telemetry-value crypto-truncate">
                                            <?= e(ui_text('stat_cipher_val')) ?>
                                        </div>
                                        <div class="telemetry-meta crypto-truncate">
                                            <?= e(ui_text('nav_security_badge')) ?>
                                        </div>
                                    </div>

                                    <div class="telemetry-cell">
                                        <div class="telemetry-header">
                                            <span class="telemetry-icon" aria-hidden="true">
                                                <i class="ti ti-key"></i>
                                            </span>
                                            <span class="telemetry-label crypto-truncate" title="<?= e(ui_text('stat_kdf_label')) ?>">
                                                <?= e(ui_text('stat_kdf_label')) ?>
                                            </span>
                                        </div>
                                        <div class="telemetry-value crypto-truncate">
                                            <?= e(ui_text('stat_kdf_val')) ?>
                                        </div>
                                        <div class="telemetry-meta crypto-truncate">
                                            <?= e(ui_text('section_crypto_status')) ?>
                                        </div>
                                    </div>

                                    <div class="telemetry-cell <?= $unlocked ? 'telemetry-cell-status-unlocked' : 'telemetry-cell-status-locked' ?>">
                                        <div class="telemetry-header">
                                            <span class="telemetry-icon" aria-hidden="true">
                                                <i class="ti <?= $unlocked ? 'ti-lock-open' : 'ti-lock' ?>"></i>
                                            </span>
                                            <span class="telemetry-label crypto-truncate" title="<?= e(ui_text('stat_status_label')) ?>">
                                                <?= e(ui_text('stat_status_label')) ?>
                                            </span>
                                        </div>
                                        <div class="telemetry-value crypto-truncate">
                                            <?= e(ui_text($unlocked ? 'stat_status_unlocked' : 'stat_status_locked')) ?>
                                        </div>
                                        <div class="telemetry-meta crypto-truncate">
                                            <?= e(ui_text($unlocked ? 'nav_mode_unlocked' : 'nav_mode_locked')) ?>
                                        </div>
                                    </div>
                                </div>
                            </section>

                            <!-- Tabel Catatan Terbaru pada Ringkasan Dashboard -->
                            <div class="card">
                                <div class="card-header d-flex align-items-center justify-content-between gap-2">
                                    <h3 class="card-title crypto-truncate mb-0 d-inline-flex align-items-center gap-2">
                                        <i class="ti ti-clock text-secondary" aria-hidden="true"></i>
                                        <span><?= e(ui_text('section_recent_notes')) ?></span>
                                    </h3>
                                    <a href="dashboard.php?view=notes" class="btn btn-sm btn-outline-primary d-inline-flex align-items-center gap-1">
                                        <i class="ti ti-list" aria-hidden="true"></i>
                                        <span class="crypto-truncate" style="max-width: 170px;"><?= e(ui_text('btn_view_all')) ?></span>
                                    </a>
                                </div>
                                <?php $tableRows = $recentNotes; ?>
                                <?php include __DIR__ . '/includes/notes_table.php'; ?>
                            </div>
                        <?php else: ?>
                            <!-- Halaman Manajemen Catatan -->
                            <div class="card">
                                <div class="card-header">
                                    <div class="row w-100 g-2 align-items-center">
                                        <div class="col-md-5">
                                            <h3 class="card-title crypto-truncate mb-0 d-inline-flex align-items-center gap-2">
                                                <i class="ti ti-notebook text-secondary" aria-hidden="true"></i>
                                                <span><?= e(ui_text('section_all_notes')) ?></span>
                                            </h3>
                                        </div>
                                        <div class="col-md-7">
                                            <form action="dashboard.php" method="get" class="d-flex gap-2">
                                                <input type="hidden" name="view" value="notes">
                                                <div class="input-icon flex-fill">
                                                    <span class="input-icon-addon">
                                                        <i class="ti ti-search" aria-hidden="true"></i>
                                                    </span>
                                                    <input
                                                        type="text"
                                                        name="q"
                                                        id="input-search-notes"
                                                        value="<?= e($searchQuery) ?>"
                                                        class="form-control"
                                                        placeholder="<?= e(ui_text('search_placeholder')) ?>"
                                                        aria-label="<?= e(ui_text('search_label')) ?>"
                                                        <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                                                    >
                                                </div>
                                                <button
                                                    type="submit"
                                                    id="btn-search-notes"
                                                    class="btn btn-outline-primary d-inline-flex align-items-center gap-1"
                                                    <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                                                >
                                                    <i class="ti ti-search" aria-hidden="true"></i>
                                                    <span class="crypto-truncate" style="max-width: 100px;"><?= e(ui_text('search_btn')) ?></span>
                                                </button>
                                                <?php if ($unlocked && $searchQuery !== ''): ?>
                                                    <a href="dashboard.php?view=notes" class="btn btn-outline-secondary d-inline-flex align-items-center gap-1">
                                                        <i class="ti ti-x" aria-hidden="true"></i>
                                                        <span class="crypto-truncate" style="max-width: 100px;"><?= e(ui_text('search_reset')) ?></span>
                                                    </a>
                                                <?php endif; ?>
                                            </form>
                                        </div>
                                    </div>
                                </div>

                                <?php if ($unlocked && $searchQuery !== ''): ?>
                                    <div class="card-body py-2 bg-azure-lt border-bottom small">
                                        <i class="ti ti-filter me-1" aria-hidden="true"></i>
                                        <span><?= e(ui_text('search_info')) ?></span>
                                        <strong><?= e($searchQuery) ?></strong>
                                    </div>
                                <?php endif; ?>

                                <?php $tableRows = $displayedNotes; ?>
                                <?php include __DIR__ . '/includes/notes_table.php'; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <?php if ($currentView === 'notes' && $flash !== null): ?>
        <?php $isFlashSuccess = ($flash['type'] === 'success'); ?>
        <div class="toast-container position-fixed top-0 end-0 p-3" id="toast-container-crud">
            <div
                id="toast-flash"
                class="toast fade show sn-toast <?= $isFlashSuccess ? 'sn-toast-success' : 'sn-toast-danger' ?>"
                role="<?= $isFlashSuccess ? 'status' : 'alert' ?>"
                aria-live="<?= $isFlashSuccess ? 'polite' : 'assertive' ?>"
                aria-atomic="true"
                data-bs-autohide="true"
                data-bs-delay="4000"
            >
                <div class="d-flex align-items-start gap-2 p-3">
                    <span class="sn-toast-icon" aria-hidden="true">
                        <i class="ti <?= $isFlashSuccess ? 'ti-circle-check' : 'ti-alert-circle' ?>"></i>
                    </span>
                    <div class="toast-body p-0 flex-fill crypto-wrap" id="toast-flash-message">
                        <?= e(ui_text((string) $flash['key'])) ?>
                    </div>
                    <button
                        type="button"
                        class="btn-close ms-2 mt-1 flex-shrink-0"
                        data-bs-dismiss="toast"
                        aria-label="<?= e(ui_text('btn_close')) ?>"
                        title="<?= e(ui_text('btn_close')) ?>"
                    ></button>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- Modal Detail Catatan -->
    <div class="modal modal-blur fade" id="modal-view-note" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-status bg-danger d-none" id="view-note-tampered-status"></div>
                <div class="modal-header">
                    <h5 class="modal-title crypto-truncate">
                        <i class="ti ti-file-text me-2 text-primary" id="view-note-icon" aria-hidden="true"></i>
                        <span><?= e(ui_text('modal_view_title')) ?></span>
                    </h5>
                </div>
                <div class="modal-body">
                    <div class="alert alert-danger mb-3 d-none" id="view-note-tampered-alert" role="alert">
                        <div class="d-flex align-items-start gap-2">
                            <div>
                                <i class="ti ti-alert-triangle icon alert-icon" aria-hidden="true"></i>
                            </div>
                            <div class="overflow-hidden">
                                <h4 class="alert-title crypto-truncate">
                                    <?= e(ui_text('modal_tampered_title')) ?>
                                </h4>
                                <div class="text-secondary small crypto-wrap">
                                    <?= e(ui_text('modal_tampered_desc')) ?>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="mb-3">
                        <div class="form-label text-secondary small crypto-truncate"><?= e(ui_text('form_title_label')) ?></div>
                        <div class="fw-bold fs-3 crypto-wrap" id="view-note-title"></div>
                    </div>
                    <div class="mb-3">
                        <div class="form-label text-secondary small crypto-truncate"><?= e(ui_text('form_content_label')) ?></div>
                        <div class="p-3 bg-light rounded border crypto-wrap pre-line" id="view-note-content"></div>
                    </div>
                    <div class="text-secondary small d-flex align-items-center gap-1">
                        <i class="ti ti-clock" aria-hidden="true"></i>
                        <span class="crypto-truncate"><?= e(ui_text('th_updated')) ?>:</span>
                        <span class="crypto-truncate" id="view-note-updated"></span>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-secondary d-inline-flex align-items-center justify-content-center" data-bs-dismiss="modal">
                        <span class="crypto-truncate" style="max-width: 140px;"><?= e(ui_text('btn_close')) ?></span>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal Tambah Catatan -->
    <div class="modal modal-blur fade" id="modal-add-note" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <form action="dashboard.php?view=notes" method="post" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="create">
                    <div class="modal-header">
                        <h5 class="modal-title crypto-truncate">
                            <i class="ti ti-plus me-2 text-primary" aria-hidden="true"></i>
                            <span><?= e(ui_text('modal_add_title')) ?></span>
                        </h5>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label required crypto-truncate" for="add-note-title"><?= e(ui_text('form_title_label')) ?></label>
                            <input
                                type="text"
                                class="form-control"
                                id="add-note-title"
                                name="title"
                                placeholder="<?= e(ui_text('form_title_placeholder')) ?>"
                                required
                                <?= $unlocked ? '' : 'disabled' ?>
                            >
                        </div>
                        <div class="mb-3">
                            <label class="form-label required crypto-truncate" for="add-note-content"><?= e(ui_text('form_content_label')) ?></label>
                            <textarea
                                class="form-control"
                                id="add-note-content"
                                name="content"
                                rows="5"
                                placeholder="<?= e(ui_text('form_content_placeholder')) ?>"
                                required
                                <?= $unlocked ? '' : 'disabled' ?>
                            ></textarea>
                        </div>
                        <div class="text-secondary small d-flex align-items-start gap-2">
                            <i class="ti ti-shield-lock text-primary mt-1" aria-hidden="true"></i>
                            <span class="crypto-wrap"><?= e(ui_text('form_crypto_hint')) ?></span>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-secondary d-inline-flex align-items-center justify-content-center" data-bs-dismiss="modal">
                            <span class="crypto-truncate" style="max-width: 120px;"><?= e(ui_text('btn_cancel')) ?></span>
                        </button>
                        <button
                            type="submit"
                            id="btn-submit-create"
                            class="btn btn-primary ms-auto d-inline-flex align-items-center gap-1"
                            <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                        >
                            <i class="ti ti-device-floppy" aria-hidden="true"></i>
                            <span class="crypto-truncate" style="max-width: 150px;"><?= e(ui_text('btn_save')) ?></span>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Modal Edit Catatan -->
    <div class="modal modal-blur fade" id="modal-edit-note" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <form action="dashboard.php?view=notes" method="post" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="note_id" id="edit-note-id" value="">
                    <div class="modal-header">
                        <h5 class="modal-title crypto-truncate">
                            <i class="ti ti-edit me-2 text-primary" aria-hidden="true"></i>
                            <span><?= e(ui_text('modal_edit_title')) ?></span>
                        </h5>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label required crypto-truncate" for="edit-note-title"><?= e(ui_text('form_title_label')) ?></label>
                            <input
                                type="text"
                                class="form-control"
                                id="edit-note-title"
                                name="title"
                                placeholder="<?= e(ui_text('form_title_placeholder')) ?>"
                                required
                                <?= $unlocked ? '' : 'disabled' ?>
                            >
                        </div>
                        <div class="mb-3">
                            <label class="form-label required crypto-truncate" for="edit-note-content"><?= e(ui_text('form_content_label')) ?></label>
                            <textarea
                                class="form-control"
                                id="edit-note-content"
                                name="content"
                                rows="5"
                                placeholder="<?= e(ui_text('form_content_placeholder')) ?>"
                                required
                                <?= $unlocked ? '' : 'disabled' ?>
                            ></textarea>
                        </div>
                        <div class="text-secondary small d-flex align-items-start gap-2">
                            <i class="ti ti-shield-lock text-primary mt-1" aria-hidden="true"></i>
                            <span class="crypto-wrap"><?= e(ui_text('form_crypto_hint')) ?></span>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-secondary d-inline-flex align-items-center justify-content-center" data-bs-dismiss="modal">
                            <span class="crypto-truncate" style="max-width: 120px;"><?= e(ui_text('btn_cancel')) ?></span>
                        </button>
                        <button
                            type="submit"
                            id="btn-submit-update"
                            class="btn btn-primary ms-auto d-inline-flex align-items-center gap-1"
                            <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                        >
                            <i class="ti ti-device-floppy" aria-hidden="true"></i>
                            <span class="crypto-truncate" style="max-width: 160px;"><?= e(ui_text('btn_update')) ?></span>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Modal Konfirmasi Hapus Catatan -->
    <div class="modal modal-blur fade" id="modal-delete-note" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-sm modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-status bg-danger"></div>
                <div class="modal-body text-center py-4">
                    <i class="ti ti-alert-triangle icon mb-2 text-danger icon-lg" aria-hidden="true"></i>
                    <h3 class="crypto-truncate" id="delete-modal-title"><?= e(ui_text('modal_delete_title')) ?></h3>
                    <div class="text-secondary crypto-wrap mb-2"><?= e(ui_text('modal_delete_desc')) ?></div>
                    <div class="fw-semibold small text-danger crypto-truncate" id="delete-note-label"></div>
                </div>
                <div class="modal-footer">
                    <div class="w-100">
                        <div class="row">
                            <div class="col">
                                <button type="button" class="btn btn-outline-secondary w-100 d-inline-flex align-items-center justify-content-center" data-bs-dismiss="modal">
                                    <span class="crypto-truncate" style="max-width: 100px;"><?= e(ui_text('btn_cancel')) ?></span>
                                </button>
                            </div>
                            <div class="col">
                                <form action="dashboard.php?view=notes" method="post">
                                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="note_id" id="delete-note-id" value="">
                                    <button
                                        type="submit"
                                        id="btn-confirm-delete"
                                        class="btn btn-danger w-100 d-inline-flex align-items-center justify-content-center gap-1"
                                        <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                                    >
                                        <i class="ti ti-trash" aria-hidden="true"></i>
                                        <span class="crypto-truncate" style="max-width: 100px;"><?= e(ui_text('btn_delete')) ?></span>
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal Konfirmasi Keluar (Logout): Berfungsi pada Mode Terbuka maupun Mode Terkunci -->
    <div class="modal modal-blur fade" id="modal-logout" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-sm modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-status bg-danger"></div>
                <div class="modal-body text-center py-4">
                    <span class="brand-mark bg-danger mx-auto mb-3" aria-hidden="true">
                        <i class="ti ti-logout"></i>
                    </span>
                    <h3 class="crypto-truncate" id="logout-modal-title"><?= e(ui_text('modal_logout_title')) ?></h3>
                    <div class="text-secondary crypto-wrap" id="logout-modal-desc">
                        <?= e(ui_text('modal_logout_desc')) ?>
                    </div>
                </div>
                <div class="modal-footer">
                    <div class="w-100">
                        <div class="row">
                            <div class="col">
                                <button
                                    type="button"
                                    id="btn-logout-cancel"
                                    class="btn btn-outline-secondary w-100 d-inline-flex align-items-center justify-content-center"
                                    data-bs-dismiss="modal"
                                >
                                    <span class="crypto-truncate" style="max-width: 100px;"><?= e(ui_text('btn_cancel')) ?></span>
                                </button>
                            </div>
                            <div class="col">
                                <form action="logout.php" method="post">
                                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                                    <button
                                        type="submit"
                                        id="btn-logout-confirm"
                                        class="btn btn-danger w-100 d-inline-flex align-items-center justify-content-center gap-1"
                                    >
                                        <i class="ti ti-logout" aria-hidden="true"></i>
                                        <span class="crypto-truncate" style="max-width: 100px;"><?= e(ui_text('btn_confirm_logout')) ?></span>
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/js/tabler.min.js"></script>
    <script src="assets/app.js?v=<?= (int) @filemtime(__DIR__ . '/assets/app.js') ?>"></script>
</body>
</html>
