<?php
declare(strict_types=1);

if (basename($_SERVER['PHP_SELF'] ?? '') === basename(__FILE__)) {
    http_response_code(403);
    exit('Akses ditolak.');
}

return [
    'db_host' => '127.0.0.1',
    'db_port' => 3306,
    'db_name' => 'secure_notes',
    'db_user' => 'root',
    'db_pass' => '',
    'kdf_iterations' => 600000,
    'session_timeout' => 1800,
];
