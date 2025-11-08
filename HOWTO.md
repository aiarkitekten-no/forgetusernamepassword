# Magic Passwordless / "MagicPassord" Module (SMS Magic Link + Cross‑Device Pairing with Built‑In 2FA)

## Introduction & Value Proposition
"MagicPassord" is a modern authentication module that replaces usernames and passwords with a frictionless, secure, and auditable process: enter a phone number – approve via SMS link – get automatically signed in on the originating device. For administrators or other high‑privilege roles, an extra 2FA layer (e.g., SMS code or WebAuthn) is enforced immediately, delivering practical built‑in two‑factor authentication without user confusion.

What makes it unique:
* Elimination of passwords: no reuse, no password phishing, no “forgot password” flow.
* Natural 2FA for sensitive roles: magic link (possession of SIM/phone) + an additional factor.
* Cross‑device pairing: Start on desktop → approve on the phone in your hand → seamless login on desktop without typing anything else.
* High auditability: All events (created, sent, used, expired, pairing, anomalies) are structured and logged.
* Rapid integration across multiple stacks (Laravel, plain PHP, Python/FastAPI, WordPress) with a common core model.
* Reduced support: Users forget passwords; they rarely forget their own phone number.
* Strong security posture: Short‑lived, single‑use tokens + hashing + rate limiting + anomaly logging + optional WebAuthn.

Executive value summary:
* Increases conversion and reduces login friction.
* Cuts costs tied to password administration and resets.
* Raises security without complex onboarding.
* Easy to position as a premium module / “security accelerator” in client projects.

---

## System Requirements
Minimum for production:
* OS: Linux (Ubuntu 22.04 LTS or similar). macOS fine for local.
* PHP: >= 8.2 (for Laravel / Plain PHP). Python: >= 3.11 for FastAPI. WordPress: >= 6.x.
* Database: MySQL 8 / MariaDB 10.6+ or PostgreSQL 14+. (Index on `expires_at` + composite index on user + created_at.)
* Composer (for PHP), pip + virtualenv/uv (for Python), npm/yarn only if you bundle the frontend poller.
* HTTPS required (HSTS recommended). Never run production over HTTP.
* Clock sync: NTP enabled (consistent “expires_at”). Skew > ±30s should alert.
* Twilio account (SID, AuthToken, verified sender number / messaging service SID).
* Session store: File, Database, or Redis. Redis recommended at scale.
* Logging: Structured (JSON) to file + Sentry/ELK/OpenSearch.
* Optional: Redis for rate limiter / geocountry cache.
* WebAuthn support (optional extra factor) requires HTTPS and a correct origin.

Performance profile:
* Token creation + hashing: <1 ms on modern CPU.
* Polling: typically every 2–3 seconds per active login. Even 500 concurrent sessions is modest with caching and lightweight JSON.

Scaling principles:
* Horizontal app scaling requires sticky sessions OR a shared session store.
* SMS delivery is external: build fallback (email link / push) if SMS SLA is critical.

---

## Technologies & Integrations
* Twilio: SMS sending. HTTP REST – idempotent send, handle errors, optionally listen to status webhooks.
* Session engine: Session ID must be readable on both devices (desktop & mobile) to enable pairing.
* Rate limiting: Prevents mass signups or phone number enumeration.
* IP / Geo module (optional): Country lookup for anomaly logging.
* WebAuthn (optional): Hardware‑backed extra factor for admins.
* Observability: Metrics: `magic_link_requests_total`, `magic_link_used_total`, `magic_link_expired_total`, `pairing_latency_seconds`.
* Security log / audit trail: Separate tables or append‑only store (can be anchored with blockchain hashing if enabled elsewhere).

Integration principles:
* Always store only the token hash – never the raw token in DB after SMS is sent.
* Don’t reveal user existence (same response for “number not found” and “link sent”).
* Fail fast on Twilio errors and return a generic response without leaking internals.

---

## Architecture & Security Model
### Flow (simplified)
```
Desktop -> (POST phone) -> Server: create link
Server -> Twilio: send SMS(url)
User taps SMS URL on mobile
Mobile -> (GET /ml/{rawToken}) -> Server: verify + pair
Desktop -> (poll every 2s) -> Server: paired? yes -> login + (admin? 2FA step)
```

### ASCII Sequence Diagram (cross‑device)
```
UserDesktop        Server                Twilio           UserMobile
    | POST /login(phone)  |                  |                |
    |-------------------->| create token +   |                |
    |                     | hash + store     |                |
    |                     | send SMS -------->| SMS           |
    | show 'sjekk mobilen'|                  |                |
    | poll /poll          |                  |                |
    |<--------------------| not paired yet    |                |
                                                  tap link     |
                                                  -----------> |
                                        GET /ml/{token}        |
                           verify hash + mark used + pair     |
    | poll /poll          |                                  |
    |-------------------->| sees paired -> create session     |
    |<--------------------| redirect (dashboard / admin 2FA)  |
```

### Security Layers
1. One‑time token (64 hex) + SHA‑256 hashing.
2. Short lifetime (default 10 minutes).
3. Single use (`used_at` set).
4. Pairing via separate session IDs – desktop never sees the raw token.
5. Rate limiting (phone + IP + global caps).
6. Anomaly logging (geo/IP deltas, unusual frequency).
7. Admin 2FA (extra factor, WebAuthn or SMS OTP).
8. No direct disclosure of user existence.

### Threat Model (concise)
| Risk | Mitigation |
|------|------------|
| SIM swap | Alert on country/IP delta, extra 2FA for admins, monitoring |
| SMS sniffing | Short life + single use + pairing prevents replay |
| Token brute force | 64 hex (~256 bit) + hashing + rate limit |
| Phone enumeration | Uniform responses + velocity blocking |
| Session hijacking | HTTPS + SameSite + short lifetimes + no token exposure |

---

## Data Model & Lifecycle
Minimum fields: `user_id`, `token(hash)`, `phone_number`, `expires_at`, `used_at`, `originating_session_id`, `paired_session_id`, `device_paired_at`, `ip_address`, `country_code`, `is_admin_login`, timestamps.

State transitions:
* Created → Active → (Used and/or Paired) → Expired.
* Desktop polling stops when: paired & used OR expired.

Indexes:
* `INDEX(expires_at)` for cleanup.
* `INDEX(user_id, created_at)` for history/audit queries.
* Unique `token` (hash) – collisions are practically impossible.

Cleanup cron (Laravel schedule / WP cron / systemd timer): delete expired rows older than X days.

---

## Implementation Guides

### Laravel (Detailed)
#### Quickstart
1. Install Twilio SDK: `composer require twilio/sdk`.
2. Create migration for `magic_links` (including pairing fields).
3. Add `MagicLink` Eloquent model + policy to avoid leaking raw token.
4. Add `MagicLinkController` methods: `request()`, `verify()`, `poll()`.
5. View: `login.blade.php` with phone field + JS poller.
6. Configure rate limiter (`RateLimiter::for('magic_link_request', ...)`).

#### Key code (sketch)
```php
// Generering
$raw = bin2hex(random_bytes(32));
$hash = hash('sha256', $raw);
MagicLink::create([
  'user_id' => $user->id,
  'token' => $hash,
  'expires_at' => now()->addMinutes(10),
  'originating_session_id' => session()->getId(),
  'ip_address' => request()->ip(),
  'country_code' => $geoCountry ?? null,
  'is_admin_login' => $user->isAdmin(),
]);
```
Validation on open:
```php
$record = MagicLink::valid()->where('token', hash('sha256', $rawFromUrl))->first();
if(!$record || $record->isExpired() || $record->isUsed()) { /* uniform respons */ }
// mark used & pair
if(session()->getId() !== $record->originating_session_id) {
  $record->paired_session_id = session()->getId();
  $record->device_paired_at = now();
}
$record->used_at = now();
$record->save();
```

#### Polling JS (minimal)
```js
const interval = setInterval(async () => {
  const r = await fetch('/api/magic-link/poll');
  if (r.ok) {
    const data = await r.json();
    if (data.status === 'paired') { clearInterval(interval); window.location = data.redirect; }
  }
}, 2500);
```

#### Config & Environment
ENV vars: `TWILIO_SID`, `TWILIO_TOKEN`, `TWILIO_FROM`. Timeout in `config/auth.php` or a dedicated `config/magic.php`.

#### Not to do
* Don’t store raw tokens in DB.
* Don’t return detailed reasons for verification failures.
* Don’t use predictable tokens (e.g., `uniqid`).
* Don’t disable HTTPS in production.
* Don’t log request bodies containing raw tokens.
* Don’t let polling run forever (set a max duration / frontend stop after X minutes).

#### Troubleshooting
| Problem | Cause | Fix |
|---------|-------|-----|
| SMS not delivered | Unverified Twilio sender | Check Twilio Console, use verified sender |
| Polling never ends | Missing pairing update | Ensure `used_at` and `paired_session_id` are set |
| Token always invalid | Hash mismatch | Ensure `hash('sha256', $raw)` used consistently |
| Admin 2FA skipped | Role check wrong | Test `isAdmin()` method and session flag |
| Race condition (double use) | Double tap | DB transaction + `isUsed()` check before marking |
| Time skew (early expiry) | Server clock off | Enable NTP, log `created_at` vs `expires_at` |

#### Test strategy
* Unit: token generation, `isExpired()`, `isUsed()`, pairing logic.
* Feature: end‑to‑end (request → verify → poll) with a faked Twilio client.
* Edge: expired links, token reuse, cross‑device pairing, admin 2FA.

### Plain PHP
Structure:
```
public/
  request-link.php
  verify.php
  poll.php
src/
  db.php
  MagicLinkRepository.php
```
Key points: `session_start()` before output, PDO prepared statements, separate cron for deleting expired rows.

Not to do:
* Don’t use `md5()`/`sha1()` for token – use SHA‑256.
* Don’t expose SQL errors to users.
* Don’t forget `SameSite=Lax/Strict` on cookies.
* Don’t let `verify.php` reveal whether a record existed vs expired/invalid.

Troubleshooting:
* “headers already sent” – start session before any output.
* Empty session IDs – ensure cookies are set and not blocked.
* Constantly invalid links – check URL encoding and that you don’t truncate tokens.

### Python (FastAPI)
Dependencies: `fastapi`, `uvicorn`, `sqlalchemy`, `twilio`, `redis`, (optional `phonenumbers`).
Endpoints: `/auth/request-link`, `/auth/magic/{token}`, `/auth/poll`.
Session: sign a JWT in cookie or use server‑side sessions (`itsdangerous` + Redis).

Not to do:
* Don’t keep raw tokens in memory un‑hashed (crashes can leak memory).
* Don’t call Twilio synchronously in async code without `run_in_threadpool`.
* Don’t return 404 for non‑existent phone – respond generically with 200.

Troubleshooting:
* “Event loop blocked” → run Twilio calls in a threadpool.
* “Token mismatch” → double hashing? Store only the hash; verify `sha256(raw)`.
* Polling returns 401 → cookie not sent; check CORS/SameSite.
* High latency → optimize DB indexes and tune polling interval carefully.

Test tips:
* Use `TestClient` and monkey‑patch Twilio client.
* Freeze time with `freezegun` for expiry tests.

### WordPress Plugin
Core:
* Custom table `wp_magic_links` created via `register_activation_hook`.
* Shortcode `[magic_link_login]` → form + JS poller.
* REST API namespace `magic/v1` with routes.
* Options page for Twilio SID/TOKEN/FROM.

Not to do:
* Don’t store tokens in `post_meta` – use a dedicated table.
* Don’t cache Twilio credentials in front‑end JS.
* Don’t forget nonce on the request‑link form.
* Don’t let REST routes expose user existence.

Troubleshooting:
* 403 on REST calls → missing `permission_callback` or `wp_rest` nonce.
* “headers already sent” → output before `wp_set_auth_cookie()`.
* No auto login → ensure `wp_set_current_user()` runs before redirect.
* Cron cleanup fails → ensure wp‑cron is active or use system cron.

---

## Operational Playbook
Monitoring:
* Success rate = `used_total / request_total` (target > 90%).
* Average pairing latency (seconds). Alert if > 120s.
* Count of expired without use – a high ratio may indicate delivery issues.

Alerts:
* High Twilio send failure rate → fallback to email.
* Country/IP anomalies for admin logins → security alert to SOC channel.

Rotation & hygiene:
* Delete expired rows daily.
* Rotate Twilio credentials annually or on suspected leak.
* Test fallback channel quarterly.

Scaling strategy:
* Increase RateLimiter buckets for legitimate volume growth.
* Redis cluster for sessions + limiter beyond ~10k concurrent logins.
* Frontend: consider SSE/WebSocket instead of polling at very large scale.

Backup & recovery:
* Daily database snapshots – magic links are ephemeral, audit logs are more critical.
* Document manual module disable (feature flag) during Twilio outages.

---

## Example SMS Template
```
Hi {FirstName},

Log in to {AppName}:
{MAGIC_URL}

Valid for 10 minutes. Ignore if you didn’t request this.
```
Recommendations: Keep the URL on its own line, simple text, no internal IDs or debug info.

---

## Pricing & Commercial Positioning (Sales Section)
"MagicPassord" can be packaged as a module/add‑on for existing SaaS or consultancy projects.

Value drivers:
* Reduces password‑related support (often 10–30% of helpdesk volume).
* Improves login conversion (less friction = fewer abandoned logins).
* Increases security without expensive training.
* Marketable as “Passwordless with built‑in 2FA.”

Cost / Effort baseline (for comparison): 25–40 hours architecture + 20–30 hours multi‑stack implementation + 10–15 hours security testing/hardening. Total 55–85 senior engineering hours.

Recommended realistic sales price (one‑time license): USD $2,000–$2,800 for integration into one project (includes basic documentation + 30 days support). Annual maintenance/support renewal: ~20% of license (USD $400–$560) provides margin without overpricing.

Alternative subscription (if operated as a service): $99–$149 / month (includes monitoring, security updates, Twilio health checks). Competitive and not inflated.

Rationale: Pricing reflects saved internal hours, security uplift, and reduced ongoing risk (no password database). No hype—just real value.

---

## Appendix – Schemas / Migrations
### Laravel migration (pairing fields)
```php
Schema::table('magic_links', function (Blueprint $table) {
    $table->string('originating_session_id')->nullable()->after('is_admin_login');
    $table->string('paired_session_id')->nullable()->after('originating_session_id');
    $table->timestamp('device_paired_at')->nullable()->after('paired_session_id');
});
```

### Generic SQL
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

Copyright 2025, Kompetanseutleie AS  
Terje Dahl  
Vålerveien 49  
1597 Moss  
https://smartesider.no
