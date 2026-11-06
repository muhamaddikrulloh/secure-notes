<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/app.php';
init_session();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (verify_csrf($_POST['csrf_token'] ?? null)) {
        destroy_user_session();
        header('Location: auth.php');
        exit;
    }
}

destroy_user_session();
header('Location: auth.php');
exit;
