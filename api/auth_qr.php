<?php
/**
 * SurveyTrace — /api/auth_qr.php
 *
 * POST body:
 *   { "otpauth_uri": "otpauth://totp/..." }
 *
 * Returns:
 *   image/png QR code rendered locally using `qrencode`.
 */

require_once __DIR__ . '/db.php';

st_auth();
st_method('POST');

$u = st_current_user();
if (($u['id'] ?? 0) <= 0) {
    st_json(['error' => 'QR generation unavailable for legacy account'], 400);
}

$db = st_db();
$srcStmt = $db->prepare("SELECT auth_source FROM users WHERE id=? LIMIT 1");
$srcStmt->execute([(int)$u['id']]);
if ((string)$srcStmt->fetchColumn() !== 'local') {
    st_json(['error' => 'QR generation is available only for local accounts'], 400);
}

$body = st_input();
$uri = trim((string)($body['otpauth_uri'] ?? ''));
if ($uri === '' || stripos($uri, 'otpauth://totp/') !== 0 || strlen($uri) > 2048) {
    st_json(['error' => 'Invalid otpauth_uri'], 400);
}

$qrencode = trim((string)@shell_exec('command -v qrencode 2>/dev/null'));
if ($qrencode === '') {
    st_json(['error' => 'Local QR generation is unavailable: qrencode is not installed'], 501);
}
$png = '';
$stderr = '';
$exit = 1;

// Preferred path: stream URI over stdin (avoids argument-length/encoding surprises).
if (function_exists('proc_open') && is_callable('proc_open')) {
    $cmd = escapeshellcmd($qrencode) . ' -o - -t PNG -s 6 -l M';
    $descriptors = [
        0 => ['pipe', 'w'],
        1 => ['pipe', 'r'],
        2 => ['pipe', 'r'],
    ];
    $proc = @proc_open($cmd, $descriptors, $pipes);
    if (is_resource($proc)) {
        fwrite($pipes[0], $uri);
        fclose($pipes[0]);
        $png = (string)stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = (string)stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        $exit = (int)proc_close($proc);
    }
}

// Fallback path: pass URI as command argument for locked-down PHP runtimes.
if (($exit !== 0 || $png === '') && function_exists('shell_exec') && is_callable('shell_exec')) {
    $tmpErr = @tempnam(sys_get_temp_dir(), 'stqr_');
    $errPath = $tmpErr ?: (sys_get_temp_dir() . '/stqr_err_' . bin2hex(random_bytes(4)));
    $cmd2 = escapeshellcmd($qrencode)
        . ' -o - -t PNG -s 6 -l M '
        . escapeshellarg($uri)
        . ' 2>' . escapeshellarg($errPath);
    $out = @shell_exec($cmd2);
    $png2 = is_string($out) ? $out : '';
    $stderr2 = is_file($errPath) ? (string)@file_get_contents($errPath) : '';
    if (is_file($errPath)) @unlink($errPath);
    if ($png2 !== '') {
        $png = $png2;
        $stderr = $stderr2;
        $exit = 0;
    } elseif ($stderr2 !== '') {
        $stderr = $stderr2;
    }
}

if ($exit !== 0 || $png === '') {
    $detail = trim((string)$stderr);
    if ($detail === '') {
        $detail = 'qrencode execution failed (check PHP disable_functions, AppArmor/SELinux, and web user PATH permissions)';
    }
    st_json([
        'error' => 'QR generation failed',
        'detail' => $detail,
    ], 500);
}

if (!headers_sent()) {
    header('Content-Type: image/png');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
}
echo $png;
exit;

