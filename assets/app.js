document.addEventListener('DOMContentLoaded', function () {
    // Fitur tampilkan/sembunyikan Kunci Rahasia
    const toggleButtons = document.querySelectorAll('[data-toggle-password]');
    toggleButtons.forEach(function (button) {
        button.addEventListener('click', function () {
            const targetId = button.getAttribute('data-toggle-password');
            const input = targetId ? document.getElementById(targetId) : null;
            if (!input) {
                return;
            }

            const isPassword = input.getAttribute('type') === 'password';
            input.setAttribute('type', isPassword ? 'text' : 'password');

            const icon = button.querySelector('i');
            if (icon) {
                icon.className = isPassword ? 'ti ti-eye-off' : 'ti ti-eye';
            }
        });
    });

    // Isi data ke Modal Detail Catatan
    const viewButtons = document.querySelectorAll('.btn-view-note');
    viewButtons.forEach(function (button) {
        button.addEventListener('click', function () {
            const titleEl = document.getElementById('view-note-title');
            const contentEl = document.getElementById('view-note-content');
            const updatedEl = document.getElementById('view-note-updated');

            if (titleEl) {
                titleEl.textContent = button.getAttribute('data-note-title') || '';
            }
            if (contentEl) {
                contentEl.textContent = button.getAttribute('data-note-content') || '';
            }
            if (updatedEl) {
                updatedEl.textContent = button.getAttribute('data-note-updated') || '';
            }
        });
    });

    // Isi data ke Modal Edit Catatan
    const editButtons = document.querySelectorAll('.btn-edit-note');
    editButtons.forEach(function (button) {
        button.addEventListener('click', function () {
            const idInput = document.getElementById('edit-note-id');
            const titleInput = document.getElementById('edit-note-title');
            const contentInput = document.getElementById('edit-note-content');

            if (idInput) {
                idInput.value = button.getAttribute('data-note-id') || '';
            }
            if (titleInput) {
                titleInput.value = button.getAttribute('data-note-title') || '';
            }
            if (contentInput) {
                contentInput.value = button.getAttribute('data-note-content') || '';
            }
        });
    });

    // Isi data ke Modal Konfirmasi Hapus Catatan
    const deleteButtons = document.querySelectorAll('.btn-delete-note');
    deleteButtons.forEach(function (button) {
        button.addEventListener('click', function () {
            const idInput = document.getElementById('delete-note-id');
            const labelEl = document.getElementById('delete-note-label');

            if (idInput) {
                idInput.value = button.getAttribute('data-note-id') || '';
            }
            if (labelEl) {
                labelEl.textContent = button.getAttribute('data-note-title') || '';
            }
        });
    });

    const toastElements = document.querySelectorAll('#toast-container-crud .toast');
    toastElements.forEach(function (toastEl) {
        if (window.bootstrap && typeof window.bootstrap.Toast === 'function') {
            const toast = window.bootstrap.Toast.getOrCreateInstance(toastEl, {
                autohide: true,
                delay: 4000,
            });
            toast.show();
        } else {
            const closeBtn = toastEl.querySelector('[data-bs-dismiss="toast"]');
            if (closeBtn) {
                closeBtn.addEventListener('click', function () {
                    toastEl.classList.remove('show');
                });
            }
            window.setTimeout(function () {
                toastEl.classList.remove('show');
            }, 4000);
        }
    });
});
