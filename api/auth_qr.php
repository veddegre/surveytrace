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
if (!function_exists('proc_open') || !is_callable('proc_open')) {
    st_json(['error' => 'Local QR generation is unavailable: proc_open is disabled in PHP'], 501);
}

$cmd = escapeshellcmd($qrencode) . ' -o - -t PNG -s 6 -l M';
$descriptors = [
    0 => ['pipe', 'w'],
    1 => ['pipe', 'r'],
    2 => ['pipe', 'r'],
];
$proc = @proc_open($cmd, $descriptors, $pipes);
if (!is_resource($proc)) {
    st_json(['error' => 'Unable to start local QR generator'], 500);
}

fwrite($pipes[0], $uri);
fclose($pipes[0]);
$png = stream_get_contents($pipes[1]);
fclose($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[2]);
$exit = proc_close($proc);

if ($exit !== 0 || !$png) {
    st_json([
        'error' => 'QR generation failed',
        'detail' => trim((string)$stderr),
    ], 500);
}

if (!headers_sent()) {
    header('Content-Type: image/png');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
}
echo $png;
exit;

