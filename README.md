```
  _________________________________________________________________
 |  ____   ____   ____   ____   ____   ____   ____   ____   ____   |
 | | __ ) |  _ \ / ___| / ___| / ___| / ___| / ___| / ___| / ___|  |
 | |  _ \ | |_) | |     \___ \ \___ \ \___ \ \___ \ \___ \ \___ \   |
 | | |_) ||  _ <| |___   ___) | ___) | ___) | ___) | ___) | ___) |  |
 | |____/ |_| \_\\____| |____/ |____/ |____/ |____/ |____/ |____/   |
 |__________________________________________________________________|
 | SmarteSider.no  -  MagicPassord Module                           |
 | Passwordless + Built-in 2FA  -  Cross-Device Magic Link Login    |
 | Dial: ATDT https://smartesider.no   SYSOP: TD                    |
 |                                                                  |
 |      .----------------.                                          |
 |      |  .-----.  .-.  |   Retro BBS Terminal                     |
 |      |  |  _  | | | | |   (Have fun. Be safe.)                   |
 |      |  | |_| | | | | |                                          |
 |      |  '-----'  '-'  |                                          |
 |      '----------------'                                          |
 |        /  ____  \                                                |
 |       /__/____\__\                                               |
 |        (________)                                                |
 |__________________________________________________________________|
```

# MagicPassord – Passwordless + Built-In 2FA ("Forgot Password" Replacement)

MagicPassord is a modern, production-ready authentication module that eliminates the entire "forgot password" problem by removing passwords entirely. Users enter their phone number, receive a one-time SMS magic link, approve it on their mobile device, and are automatically signed in on the original desktop (or same device). Admins and privileged users get an automatic second factor (SMS OTP or WebAuthn) — delivering passwordless + built‑in 2FA.

---
## Why Replace "Forgot Password" With MagicPassord?
| Traditional Reset Flow | MagicPassord Flow |
|------------------------|-------------------|
| User forgets password, requests reset | User enters phone number |
| Email token or link, phishing risk | Receives short‑lived SMS magic link |
| Must create new password (complexity rules) | Tap link → cross‑device pairing → login |
| Password reuse persists risk | No password stored or reused |
| Support cost (reset tickets) | Lower support (users know phone numbers) |
| Credential stuffing possible | Single‑use hashed tokens + expiry |

Key advantages:
- Zero password resets to manage.
- Fast cross‑device pairing (desktop start → mobile approval → desktop login).
- Strong audit trail (created, sent, used, expired, paired, anomalies).
- Secure by default: short lifetime (10 min), single use, SHA‑256 hashed token, rate limiting, anomaly logging.
- Built-in 2FA posture for admin accounts without extra UX friction.

---
## Feature Highlights
- SMS Magic Link (Twilio) with token hashing (no raw token in storage).
- Cross‑device session pairing (originating session ID vs mobile session ID).
- Optional admin 2FA (SMS OTP / WebAuthn challenge).
- Multi-stack implementation guidance (Laravel, Plain PHP, Python/FastAPI, WordPress).
- Structured metrics and logging hooks.
- Extendable: passkeys, WebSockets/SSE, OIDC bridge, risk scoring, push notifications.

---
## Quick Architecture Overview
```
Desktop -> (POST phone) -> Server: create link + hash token
Server -> Twilio: send SMS (URL w/raw token)
User taps link on mobile
Mobile -> GET /ml/{rawToken}: verify, mark used, pair sessions
Desktop -> polls /api/magic-link/poll every 2–3s
If paired → server logs in desktop; if admin → trigger second factor
```
Security Layers:
1. CSPRNG 64‑hex token, hashed (SHA‑256) in DB.
2. 10‑minute expiry (configurable).
3. Single use (`used_at` recorded).
4. Pairing prevents desktop ever seeing raw token.
5. Rate limits by phone and IP.
6. Anomaly logging (geo/IP, velocity).
7. Admin 2FA (WebAuthn or SMS OTP).
8. Uniform responses (don’t reveal existence of phone/user).

Threat Model Snapshot:
| Risk | Mitigation |
|------|------------|
| SIM swap | Country/IP anomaly alerts + mandatory admin 2FA |
| Token brute force | High entropy + hashing + rate limits |
| SMS sniffing | Short lifetime + single use + pairing |
| Enumeration | Uniform responses + velocity caps |
| Session hijack | HTTPS + SameSite cookies + short token life |

---
## System Requirements
- Linux (Ubuntu 22.04 LTS or similar); macOS for local dev.
- PHP >= 8.2 / Python >= 3.11 / WordPress >= 6.x.
- MySQL 8 / MariaDB 10.6+ / PostgreSQL 14+.
- Twilio account (SID, Token, verified sender).
- HTTPS (HSTS recommended) & NTP sync.
- Session store (Redis recommended for scale).

---
## Laravel Quickstart
1. `composer require twilio/sdk`
2. Migration: create `magic_links` table with fields: token(hash), expires_at, used_at, originating_session_id, paired_session_id, device_paired_at, is_admin_login, etc.
3. Controller endpoints:
   - POST `/login/request-link`
   - GET `/ml/{token}` (verification + pairing)
   - GET `/api/magic-link/poll` (desktop polling)
4. Frontend polling snippet:
```js
const interval = setInterval(async () => {
  const r = await fetch('/api/magic-link/poll');
  if (r.ok) {
    const data = await r.json();
    if (data.status === 'paired') { clearInterval(interval); window.location = data.redirect; }
  }
}, 2500);
```
5. Admin second factor logic after pairing.
6. Env vars: `TWILIO_SID`, `TWILIO_TOKEN`, `TWILIO_FROM`.

Not to do:
- Do not store raw tokens.
- Do not expose why verification failed.
- Do not use predictable token generators.
- Do not disable HTTPS.
- Do not let polling run indefinitely.

Troubleshooting (selected):
| Issue | Cause | Fix |
|-------|-------|-----|
| SMS not delivered | Unverified sender | Verify Twilio number/service |
| Polling runs forever | Pairing fields not set | Ensure `used_at` + `paired_session_id` |
| Invalid token | Hash mismatch | Consistent SHA‑256 usage |
| Early expiry | Clock skew | Enable NTP |

---
## Other Stacks (Summary)
- Plain PHP: `request-link.php`, `verify.php`, `poll.php`; use PDO + `session_start()` early.
- Python FastAPI: endpoints `/auth/request-link`, `/auth/magic/{token}`, `/auth/poll`; Twilio calls in threadpool; server‑side session or signed cookie.
- WordPress Plugin: custom table, shortcode `[magic_link_login]`, REST namespace `magic/v1`, options page for Twilio credentials.

See full details in `MAGICPASSORD.md`.

---
## Example SMS Template
```
Hi {FirstName},

Log in to {AppName}:
{MAGIC_URL}

Valid for 10 minutes. Ignore if you didn’t request this.
```

---
## Operational Checklist
- Metrics: `magic_link_requests_total`, `magic_link_used_total`, `magic_link_expired_total`, `pairing_latency_seconds`.
- Alerts: Twilio failure spikes, admin login geo/IP anomalies.
- Cleanup: scheduled deletion of expired links (cron / scheduler).
- Rotation: annual Twilio credential rotation.
- Scale: Redis sessions + possible SSE/WebSocket for very high concurrency.

---
## Pricing Snapshot
| Model | Range | Includes |
|-------|-------|----------|
| One‑time license | $2,000–$2,800 | Docs + migration + 30 days support |
| Enterprise (extended) | $5,000–$9,000 | Passkeys, dashboards, OIDC, risk scoring |
| Managed subscription | $99–$149/mo | Monitoring, updates, Twilio health checks |

Rationale: Well below rebuild cost (55–85 senior engineer hours) yet reflects real value (support reduction, security uplift, faster onboarding).

---
## Roadmap Ideas
- Passkeys for all users.
- SSE/WebSocket streaming status instead of polling.
- Risk scoring hook (velocity, ASN reputation).
- OIDC bridge for multi‑app identity.
- Push notification fallback (APNs/FCM).

---
## Appendix (Schema Snippet)
```sql
CREATE TABLE magic_links (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  token CHAR(64) NOT NULL UNIQUE,
  phone_number VARCHAR(20) NOT NULL,
  expires_at DATETIME NOT NULL,
  used_at DATETIME NULL,
  ip_address VARCHAR(45) NOT NULL,
  user_agent TEXT NULL,
  country_code CHAR(2) NULL,
  is_admin_login TINYINT(1) NOT NULL DEFAULT 0,
  originating_session_id VARCHAR(128) NULL,
  paired_session_id VARCHAR(128) NULL,
  device_paired_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  INDEX idx_expires (expires_at),
  INDEX idx_user_created (user_id, created_at)
);
```

---
## Full Documentation
For deeper implementation guides, troubleshooting matrices, security model, and licensing strategy see: `MAGICPASSORD.md`.

## Credits
SmarteSider.no – MagicPassord Module (Passwordless + Built-In 2FA)  
Copyright 2025, Kompetanseutleie AS  
https://smartesider.no

---
**Note:** This replaces traditional "forgot password" flows entirely; disable legacy password reset endpoints when deploying MagicPassord.
