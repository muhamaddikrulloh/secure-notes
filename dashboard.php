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

// Operasi tulis hanya diizinkan pada Mode Terbuka dengan token CSRF yang valid
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        set_flash('danger', 'flash_err_csrf');
    } elseif (!$unlocked || get_session_key() === null) {
        http_response_code(403);
        set_flash('danger', 'flash_err_locked');
    } else {
        $action = (string) ($_POST['action'] ?? '');
        $rawKey = get_session_key();
        $pdo = get_db();

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
                    // Enkripsi ulang menggunakan Nonce 12-byte baru untuk mencegah nonce reuse
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

$searchQuery = $unlocked ? trim((string) ($_GET['q'] ?? '')) : '';
$allNotes = fetch_all_notes('');
$totalNotesCount = count($allNotes);
$displayedNotes = ($searchQuery !== '') ? fetch_all_notes($searchQuery) : $allNotes;
$recentNotes = array_slice($allNotes, 0, 5);
$latestUpdatedValue = !empty($recentNotes) ? (string) $recentNotes[0]['updated_at'] : ui_text('stat_cipher_val');
$flash = get_flash();
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
                        <img src="assets/logo.svg" alt="Secure Notes" class="brand-logo" width="30" height="30">
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
            <header class="navbar navbar-expand-md d-print-none topbar-header">
                <div class="container-xl d-flex align-items-center justify-content-between gap-3">
                    <span class="text-secondary small crypto-truncate" style="max-width: 300px;">
                        <?= e(ui_text('app_subtitle')) ?>
                    </span>
                    <div class="d-flex align-items-center ms-auto">
                        <span class="sn-status-badge <?= $unlocked ? 'sn-status-unlocked' : 'sn-status-locked' ?>" id="badge-dashboard-mode">
                            <?= e(ui_text($unlocked ? 'nav_mode_unlocked' : 'nav_mode_locked')) ?>
                        </span>
                    </div>
                </div>
            </header>

            <main>
                <div class="page-header d-print-none mt-3 mb-2">
                    <div class="container-xl">
                        <div class="row g-2 align-items-center">
                            <div class="col overflow-hidden">
                                <h2 class="page-title crypto-truncate mb-0" id="dashboard-page-title">
                                    <?= e(ui_text($currentView === 'notes' ? 'page_title_notes' : 'page_title_overview')) ?>
                                </h2>
                            </div>
                            <div class="col-auto ms-auto">
                                <button
                                    type="button"
                                    id="btn-open-add-modal"
                                    class="btn btn-primary d-inline-flex align-items-center gap-1"
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
                                    <span class="crypto-truncate" style="max-width: 180px;"><?= e(ui_text('btn_add_note')) ?></span>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="page-body">
                    <div class="container-xl">
                        <?php if (!$unlocked): ?>
                            <div class="alert alert-warning mb-3" role="alert" id="alert-crypto-mode">
                                <div class="fw-semibold crypto-truncate"><?= e(ui_text('alert_locked_title')) ?></div>
                                <div class="small crypto-wrap"><?= e(ui_text('alert_locked_desc')) ?></div>
                            </div>
                        <?php endif; ?>

                        <?php if ($currentView === 'overview'): ?>
                            <div class="row g-3 mb-4">
                                <div class="col-sm-6 col-lg-3">
                                    <div class="summary-card h-100">
                                        <div class="summary-label crypto-truncate"><?= e(ui_text('stat_notes_label')) ?></div>
                                        <div class="summary-value crypto-truncate" id="stat-total-notes">
                                            <?= e(render_note_count($totalNotesCount)) ?>
                                        </div>
                                    </div>
                                </div>

                                <div class="col-sm-6 col-lg-3">
                                    <div class="summary-card h-100">
                                        <div class="summary-label crypto-truncate"><?= e(ui_text('stat_cipher_label')) ?></div>
                                        <div class="summary-value crypto-truncate">
                                            <?= e($latestUpdatedValue) ?>
                                        </div>
                                    </div>
                                </div>

                                <div class="col-lg-6">
                                    <div class="summary-card h-100 d-flex flex-column justify-content-center">
                                        <form action="dashboard.php" method="get" class="d-flex gap-2">
                                            <input type="hidden" name="view" value="notes">
                                            <input
                                                type="text"
                                                name="q"
                                                class="form-control"
                                                placeholder="<?= e(ui_text('search_placeholder')) ?>"
                                                aria-label="<?= e(ui_text('search_label')) ?>"
                                                <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                                            >
                                            <button
                                                type="submit"
                                                class="btn btn-outline-primary flex-shrink-0"
                                                <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                                            >
                                                <span class="crypto-truncate" style="max-width: 90px;"><?= e(ui_text('search_btn')) ?></span>
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>

                            <div class="card">
                                <div class="card-header d-flex align-items-center justify-content-between gap-2">
                                    <h3 class="card-title crypto-truncate mb-0"><?= e(ui_text('section_recent_notes')) ?></h3>
                                    <a href="dashboard.php?view=notes" class="btn btn-sm btn-outline-secondary">
                                        <span class="crypto-truncate" style="max-width: 160px;"><?= e(ui_text('btn_view_all')) ?></span>
                                    </a>
                                </div>
                                <?php $tableRows = $recentNotes; ?>
                                <?php include __DIR__ . '/includes/notes_table.php'; ?>
                            </div>
                        <?php else: ?>
                            <div class="card">
                                <div class="card-header">
                                    <div class="row w-100 g-2 align-items-center">
                                        <div class="col-md-5">
                                            <h3 class="card-title crypto-truncate mb-0"><?= e(ui_text('section_all_notes')) ?></h3>
                                        </div>
                                        <div class="col-md-7">
                                            <form action="dashboard.php" method="get" class="d-flex gap-2">
                                                <input type="hidden" name="view" value="notes">
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
                                                <button
                                                    type="submit"
                                                    id="btn-search-notes"
                                                    class="btn btn-outline-primary flex-shrink-0"
                                                    <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                                                >
                                                    <span class="crypto-truncate" style="max-width: 90px;"><?= e(ui_text('search_btn')) ?></span>
                                                </button>
                                                <?php if ($unlocked && $searchQuery !== ''): ?>
                                                    <a href="dashboard.php?view=notes" class="btn btn-outline-secondary flex-shrink-0">
                                                        <span class="crypto-truncate" style="max-width: 90px;"><?= e(ui_text('search_reset')) ?></span>
                                                    </a>
                                                <?php endif; ?>
                                            </form>
                                        </div>
                                    </div>
                                </div>

                                <?php if ($unlocked && $searchQuery !== ''): ?>
                                    <div class="card-body py-2 bg-light border-bottom small">
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

    <?php if ($flash !== null): ?>
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

    <div class="modal modal-blur fade" id="modal-view-note" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-status bg-danger d-none" id="view-note-tampered-status"></div>
                <div class="modal-header">
                    <h5 class="modal-title crypto-truncate"><?= e(ui_text('modal_view_title')) ?></h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= e(ui_text('btn_close')) ?>"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-danger mb-3 d-none" id="view-note-tampered-alert" role="alert">
                        <div class="fw-semibold crypto-truncate"><?= e(ui_text('modal_tampered_title')) ?></div>
                        <div class="small crypto-wrap"><?= e(ui_text('modal_tampered_desc')) ?></div>
                    </div>
                    <div class="mb-3">
                        <div class="text-secondary small mb-1 crypto-truncate"><?= e(ui_text('form_title_label')) ?></div>
                        <div class="fw-bold fs-3 crypto-wrap" id="view-note-title"></div>
                    </div>
                    <div class="mb-3">
                        <div class="text-secondary small mb-1 crypto-truncate"><?= e(ui_text('form_content_label')) ?></div>
                        <div class="note-detail-box crypto-wrap pre-line" id="view-note-content"></div>
                    </div>
                    <div class="text-secondary small">
                        <span class="crypto-truncate"><?= e(ui_text('th_updated')) ?>:</span>
                        <span class="crypto-truncate" id="view-note-updated"></span>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <span class="crypto-truncate" style="max-width: 140px;"><?= e(ui_text('btn_close')) ?></span>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal modal-blur fade" id="modal-add-note" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <form action="dashboard.php?view=notes" method="post" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="create">
                    <div class="modal-header">
                        <h5 class="modal-title crypto-truncate"><?= e(ui_text('modal_add_title')) ?></h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= e(ui_text('btn_close')) ?>"></button>
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
                        <div>
                            <label class="form-label required crypto-truncate" for="add-note-content"><?= e(ui_text('form_content_label')) ?></label>
                            <textarea
                                class="form-control"
                                id="add-note-content"
                                name="content"
                                rows="6"
                                placeholder="<?= e(ui_text('form_content_placeholder')) ?>"
                                required
                                <?= $unlocked ? '' : 'disabled' ?>
                            ></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                            <span class="crypto-truncate" style="max-width: 120px;"><?= e(ui_text('btn_cancel')) ?></span>
                        </button>
                        <button
                            type="submit"
                            id="btn-submit-create"
                            class="btn btn-primary ms-auto"
                            <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                        >
                            <span class="crypto-truncate" style="max-width: 160px;"><?= e(ui_text('btn_save')) ?></span>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div class="modal modal-blur fade" id="modal-edit-note" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <form action="dashboard.php?view=notes" method="post" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="note_id" id="edit-note-id" value="">
                    <div class="modal-header">
                        <h5 class="modal-title crypto-truncate"><?= e(ui_text('modal_edit_title')) ?></h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= e(ui_text('btn_close')) ?>"></button>
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
                        <div>
                            <label class="form-label required crypto-truncate" for="edit-note-content"><?= e(ui_text('form_content_label')) ?></label>
                            <textarea
                                class="form-control"
                                id="edit-note-content"
                                name="content"
                                rows="6"
                                placeholder="<?= e(ui_text('form_content_placeholder')) ?>"
                                required
                                <?= $unlocked ? '' : 'disabled' ?>
                            ></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                            <span class="crypto-truncate" style="max-width: 120px;"><?= e(ui_text('btn_cancel')) ?></span>
                        </button>
                        <button
                            type="submit"
                            id="btn-submit-update"
                            class="btn btn-primary ms-auto"
                            <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                        >
                            <span class="crypto-truncate" style="max-width: 160px;"><?= e(ui_text('btn_update')) ?></span>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div class="modal modal-blur fade" id="modal-delete-note" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-sm modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-body py-4">
                    <h3 class="h4 mb-2 crypto-truncate" id="delete-modal-title"><?= e(ui_text('modal_delete_title')) ?></h3>
                    <div class="text-secondary small crypto-wrap mb-2"><?= e(ui_text('modal_delete_desc')) ?></div>
                    <div class="fw-semibold small text-danger crypto-truncate" id="delete-note-label"></div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <span class="crypto-truncate" style="max-width: 100px;"><?= e(ui_text('btn_cancel')) ?></span>
                    </button>
                    <form action="dashboard.php?view=notes" method="post" class="ms-auto">
                        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="action" value="delete">
                        <input type="hidden" name="note_id" id="delete-note-id" value="">
                        <button
                            type="submit"
                            id="btn-confirm-delete"
                            class="btn btn-danger"
                            <?= $unlocked ? '' : 'disabled aria-disabled="true"' ?>
                        >
                            <span class="crypto-truncate" style="max-width: 100px;"><?= e(ui_text('btn_delete')) ?></span>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <div class="modal modal-blur fade" id="modal-logout" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-sm modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-body py-4">
                    <h3 class="h4 mb-2 crypto-truncate" id="logout-modal-title"><?= e(ui_text('modal_logout_title')) ?></h3>
                    <div class="text-secondary small crypto-wrap" id="logout-modal-desc">
                        <?= e(ui_text('modal_logout_desc')) ?>
                    </div>
                </div>
                <div class="modal-footer">
                    <button
                        type="button"
                        id="btn-logout-cancel"
                        class="btn btn-outline-secondary"
                        data-bs-dismiss="modal"
                    >
                        <span class="crypto-truncate" style="max-width: 100px;"><?= e(ui_text('btn_cancel')) ?></span>
                    </button>
                    <form action="logout.php" method="post" class="ms-auto">
                        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                        <button
                            type="submit"
                            id="btn-logout-confirm"
                            class="btn btn-danger"
                        >
                            <span class="crypto-truncate" style="max-width: 100px;"><?= e(ui_text('btn_confirm_logout')) ?></span>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/js/tabler.min.js"></script>
    <script src="assets/app.js?v=<?= (int) @filemtime(__DIR__ . '/assets/app.js') ?>"></script>
</body>
</html>
