<?php
declare(strict_types=1);

if (basename($_SERVER['PHP_SELF'] ?? '') === basename(__FILE__)) {
    http_response_code(403);
    exit('Akses ditolak.');
}

$unlocked = isset($unlocked) ? (bool) $unlocked : is_unlocked();
$tableRows = isset($tableRows) && is_array($tableRows) ? $tableRows : [];
$activeSearchQuery = isset($searchQuery) ? (string) $searchQuery : '';
?>
<?php if (empty($tableRows)): ?>
    <div class="card-body py-5 text-center" id="empty-notes-state">
        <h3 class="h4 mb-1 crypto-truncate"><?= e(ui_text('empty_notes_title')) ?></h3>
        <p class="text-secondary small crypto-wrap mb-3 mx-auto" style="max-width: 420px;">
            <?= e(ui_text('empty_notes_desc')) ?>
        </p>
        <?php if ($unlocked): ?>
            <?php if ($activeSearchQuery !== ''): ?>
                <a href="dashboard.php?view=notes" class="btn btn-sm btn-outline-secondary">
                    <span class="crypto-truncate" style="max-width: 140px;"><?= e(ui_text('search_reset')) ?></span>
                </a>
            <?php else: ?>
                <button
                    type="button"
                    class="btn btn-sm btn-primary"
                    data-bs-toggle="modal"
                    data-bs-target="#modal-add-note"
                >
                    <span class="crypto-truncate" style="max-width: 180px;"><?= e(ui_text('btn_add_note')) ?></span>
                </button>
            <?php endif; ?>
        <?php endif; ?>
    </div>
<?php else: ?>
    <div class="table-responsive">
        <table class="table table-vcenter card-table" id="notes-table">
            <thead>
                <tr>
                    <th class="col-note-no"><span class="crypto-truncate"><?= e(ui_text('th_no')) ?></span></th>
                    <th class="col-note-title"><span class="crypto-truncate"><?= e(ui_text('th_title')) ?></span></th>
                    <th class="col-note-content"><span class="crypto-truncate"><?= e(ui_text('th_content')) ?></span></th>
                    <th class="col-note-time"><span class="crypto-truncate"><?= e(ui_text('th_created')) ?></span></th>
                    <th class="col-note-time"><span class="crypto-truncate"><?= e(ui_text('th_updated')) ?></span></th>
                    <th class="col-note-actions text-end"><span class="crypto-truncate"><?= e(ui_text('th_actions')) ?></span></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tableRows as $index => $note): ?>
                    <?php
                    // Tampilkan ciphertext asli dan nonaktifkan edit jika verifikasi tag GCM gagal
                    $isTampered = !empty($note['tampered']);
                    $displayTitle = $isTampered ? (string) $note['title_ciphertext'] : (string) $note['title'];
                    $displayContent = $isTampered ? (string) $note['content_ciphertext'] : (string) $note['content'];
                    $canModify = $unlocked && !$isTampered;
                    ?>
                    <tr data-note-row="<?= (int) $note['id'] ?>">
                        <td class="col-note-no text-secondary small">
                            <?= $index + 1 ?>
                        </td>
                        <td class="col-note-title">
                            <div class="d-flex align-items-center gap-2 overflow-hidden">
                                <?php if ($isTampered): ?>
                                    <i class="ti ti-alert-triangle text-danger flex-shrink-0" title="<?= e(ui_text('cell_tampered')) ?>"></i>
                                <?php endif; ?>
                                <span class="fw-semibold crypto-cell-title" title="<?= e($displayTitle) ?>">
                                    <?= e($displayTitle) ?>
                                </span>
                            </div>
                        </td>
                        <td class="col-note-content">
                            <div class="crypto-cell-content" title="<?= e($displayContent) ?>">
                                <?= e($displayContent) ?>
                            </div>
                        </td>
                        <td class="col-note-time text-secondary small">
                            <span class="crypto-truncate"><?= e((string) $note['created_at']) ?></span>
                        </td>
                        <td class="col-note-time text-secondary small">
                            <span class="crypto-truncate"><?= e((string) $note['updated_at']) ?></span>
                        </td>
                        <td class="col-note-actions text-end">
                            <div class="btn-list flex-nowrap justify-content-end gap-1">
                                <button
                                    type="button"
                                    class="btn btn-sm btn-outline-secondary btn-view-note"
                                    data-bs-toggle="modal"
                                    data-bs-target="#modal-view-note"
                                    data-note-title="<?= e($displayTitle) ?>"
                                    data-note-content="<?= e($displayContent) ?>"
                                    data-note-updated="<?= e((string) $note['updated_at']) ?>"
                                    data-note-tampered="<?= $isTampered ? '1' : '0' ?>"
                                    title="<?= e(ui_text('tooltip_view')) ?>"
                                >
                                    <span class="crypto-truncate" style="max-width: 60px;"><?= e(ui_text('btn_view')) ?></span>
                                </button>

                                <button
                                    type="button"
                                    class="btn btn-sm btn-outline-primary btn-edit-note"
                                    <?php if ($canModify): ?>
                                        data-bs-toggle="modal"
                                        data-bs-target="#modal-edit-note"
                                        data-note-id="<?= (int) $note['id'] ?>"
                                        data-note-title="<?= e($displayTitle) ?>"
                                        data-note-content="<?= e($displayContent) ?>"
                                        title="<?= e(ui_text('tooltip_edit')) ?>"
                                    <?php else: ?>
                                        disabled
                                        aria-disabled="true"
                                        title="<?= e(ui_text('tooltip_locked_action')) ?>"
                                    <?php endif; ?>
                                >
                                    <span class="crypto-truncate" style="max-width: 52px;"><?= e(ui_text('btn_edit')) ?></span>
                                </button>

                                <button
                                    type="button"
                                    class="btn btn-sm btn-outline-danger btn-delete-note"
                                    <?php if ($unlocked): ?>
                                        data-bs-toggle="modal"
                                        data-bs-target="#modal-delete-note"
                                        data-note-id="<?= (int) $note['id'] ?>"
                                        data-note-title="<?= e($displayTitle) ?>"
                                        title="<?= e(ui_text('tooltip_delete')) ?>"
                                    <?php else: ?>
                                        disabled
                                        aria-disabled="true"
                                        title="<?= e(ui_text('tooltip_locked_action')) ?>"
                                    <?php endif; ?>
                                >
                                    <span class="crypto-truncate" style="max-width: 56px;"><?= e(ui_text('btn_delete')) ?></span>
                                </button>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>
