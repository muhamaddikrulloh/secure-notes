<?php
declare(strict_types=1);

if (basename($_SERVER['PHP_SELF'] ?? '') === basename(__FILE__)) {
    http_response_code(403);
    exit('Akses ditolak.');
}

$unlocked = isset($unlocked) ? (bool) $unlocked : is_unlocked();
$tableRows = isset($tableRows) && is_array($tableRows) ? $tableRows : [];
?>
<?php if (empty($tableRows)): ?>
    <div class="card-body py-5 text-center" id="empty-notes-state">
        <div class="mb-3">
            <span class="telemetry-icon mx-auto" style="width: 44px; height: 44px; font-size: 1.25rem;" aria-hidden="true">
                <i class="ti ti-notes-off"></i>
            </span>
        </div>
        <h3 class="h3 mb-1 crypto-truncate"><?= e(ui_text('empty_notes_title')) ?></h3>
        <p class="text-secondary crypto-wrap mb-0 mx-auto" style="max-width: 520px;">
            <?= e(ui_text('empty_notes_desc')) ?>
        </p>
    </div>
<?php else: ?>
    <div class="table-responsive">
        <table class="table table-vcenter card-table" id="notes-table">
            <thead>
                <tr>
                    <th class="col-note-title"><span class="crypto-truncate"><?= e(ui_text('th_title')) ?></span></th>
                    <th class="col-note-content"><span class="crypto-truncate"><?= e(ui_text('th_content')) ?></span></th>
                    <th class="col-note-time"><span class="crypto-truncate"><?= e(ui_text('th_created')) ?></span></th>
                    <th class="col-note-time"><span class="crypto-truncate"><?= e(ui_text('th_updated')) ?></span></th>
                    <th class="col-note-actions text-end"><span class="crypto-truncate"><?= e(ui_text('th_actions')) ?></span></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tableRows as $note): ?>
                    <?php
                    // Jika integritas tag GCM gagal, paksa tampilkan ciphertext asli dan kunci tombol edit
                    $isTampered = !empty($note['tampered']);
                    $displayTitle = $isTampered ? (string) $note['title_ciphertext'] : (string) $note['title'];
                    $displayContent = $isTampered ? (string) $note['content_ciphertext'] : (string) $note['content'];
                    $canModify = $unlocked && !$isTampered;
                    ?>
                    <tr data-note-row="<?= (int) $note['id'] ?>">
                        <td class="col-note-title">
                            <div class="d-flex align-items-center gap-2 overflow-hidden">
                                <span class="telemetry-icon" aria-hidden="true">
                                    <i class="ti <?= $isTampered ? 'ti-alert-triangle text-danger' : ($unlocked ? 'ti-file-text' : 'ti-lock') ?>"></i>
                                </span>
                                <div class="overflow-hidden w-100">
                                    <?php if ($isTampered): ?>
                                        <span class="badge bg-red-lt d-block mb-1 crypto-truncate note-tampered-badge">
                                            <?= e(ui_text('cell_tampered')) ?>
                                        </span>
                                    <?php endif; ?>
                                    <div class="fw-semibold crypto-cell-title" title="<?= e($displayTitle) ?>">
                                        <?= e($displayTitle) ?>
                                    </div>
                                </div>
                            </div>
                        </td>
                        <td class="col-note-content">
                            <div class="crypto-cell-content" title="<?= e($displayContent) ?>">
                                <?= e($displayContent) ?>
                            </div>
                        </td>
                        <td class="col-note-time text-secondary small">
                            <span class="crypto-truncate">
                                <?= e((string) $note['created_at']) ?>
                            </span>
                        </td>
                        <td class="col-note-time text-secondary small">
                            <span class="crypto-truncate">
                                <?= e((string) $note['updated_at']) ?>
                            </span>
                        </td>
                        <td class="col-note-actions text-end">
                            <div class="btn-list flex-nowrap justify-content-end gap-1">
                                <button
                                    type="button"
                                    class="btn btn-sm btn-outline-secondary d-inline-flex align-items-center gap-1 btn-view-note"
                                    data-bs-toggle="modal"
                                    data-bs-target="#modal-view-note"
                                    data-note-title="<?= e($displayTitle) ?>"
                                    data-note-content="<?= e($displayContent) ?>"
                                    data-note-updated="<?= e((string) $note['updated_at']) ?>"
                                    title="<?= e(ui_text('tooltip_view')) ?>"
                                >
                                    <i class="ti ti-eye" aria-hidden="true"></i>
                                    <span class="crypto-truncate" style="max-width: 56px;"><?= e(ui_text('btn_view')) ?></span>
                                </button>

                                <button
                                    type="button"
                                    class="btn btn-sm btn-outline-primary d-inline-flex align-items-center gap-1 btn-edit-note"
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
                                    <i class="ti ti-edit" aria-hidden="true"></i>
                                    <span class="crypto-truncate" style="max-width: 48px;"><?= e(ui_text('btn_edit')) ?></span>
                                </button>

                                <button
                                    type="button"
                                    class="btn btn-sm btn-outline-danger d-inline-flex align-items-center gap-1 btn-delete-note"
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
                                    <i class="ti ti-trash" aria-hidden="true"></i>
                                    <span class="crypto-truncate" style="max-width: 52px;"><?= e(ui_text('btn_delete')) ?></span>
                                </button>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>
