# CyberWarden

**CyberWarden** is a security auditor for AI agent setups **and** production web apps. It's built on [`affaan-m/agentshield`](https://github.com/affaan-m/agentshield), which is MIT-licensed (Copyright © 2026 Affaan M). The original copyright notice is kept in `LICENSE`.

## What CyberWarden adds beyond AgentShield

AgentShield's 15 built-in rule modules (secrets, permissions, hooks, hidden curls and pipes, MCP CVEs, tool poisoning, skills, prompt-injection defense and more) all still run. CyberWarden adds **35 new rules** in two groups, and fixes one noisy false alarm.

### Group 1: Defense-in-Depth rules (12), `src/rules/defense-in-depth.ts`

These run on every file the scanner finds.

1. `defense-db-rls-disabled`: Postgres/Supabase Row-Level Security turned off or wide open, or an exposed `service_role` key.
2. `defense-ssrf-internal-url`: the server fetching cloud metadata (`169.254.169.254`) or unchecked user-supplied URLs.
3. `defense-unsafe-file-upload`: saving uploads under the user's own filename, or allowing runnable file types (`.php`, `.exe`, `.sh`).
4. `defense-race-condition-billing`: credit or balance changes that aren't atomic, so they can be double-spent.
5. `defense-supply-chain-unpinned`: `"*"` or `"latest"` versions in `package.json`.
6. `defense-sensitive-audit-logging`: logging raw passwords or tokens, or turning off TLS checks (`NODE_TLS_REJECT_UNAUTHORIZED=0`).
7. `defense-regional-webhook-unverified`: Paystack, Flutterwave or Meta/WhatsApp webhooks with signature checking explicitly switched off.
8. `defense-ai-chat-history-client-trust`: an AI chatbot trusting chat history sent by the browser.
9. `defense-ndpa-pii-exposure`: unmasked BVN, NIN or passport numbers logged or exposed (Nigeria's NDPA 2023).
10. `defense-mass-assignment`: raw `req.body` saved straight into the database (`"role": "admin"` injection).
11. `defense-default-admin-or-dotfiles`: a static file server set to serve `.env` and `.git`.
12. `defense-otp-or-password-change-unsafe`: unlimited OTP attempts, or email/password changes without the current password.

### Group 2: Web-app rules (23), `src/rules/webapp.ts`

These run on a project's real code when you scan with `--web`.

| Rule | What it catches |
|---|---|
| `webapp-sql-injection` | SQL built by gluing in variables |
| `webapp-xss-html-sink` | `innerHTML` / `document.write` built from variables |
| `webapp-code-injection` | `eval`, `new Function` or shell commands built from input |
| `webapp-secret-env-fallback` | secrets or passwords with a hardcoded fallback (`\|\| 'changeme'`) |
| `webapp-frontend-secret` | API keys inside browser or mobile code |
| `webapp-env-not-gitignored` / `webapp-gitignore-missing-env` / `webapp-secret-file-committed` | `.env` not ignored, or already committed to git |
| `webapp-weak-random-token` | `Math.random()` used for tokens or codes |
| `webapp-weak-password-hash` | MD5/SHA or plain-text passwords |
| `webapp-insecure-cookie` | cookies missing `HttpOnly`, `Secure` or `SameSite` |
| `webapp-cors-wildcard` | `Access-Control-Allow-Origin: *` on private routes |
| `webapp-csp-unsafe` | a Content-Security-Policy allowing `'unsafe-inline'` or `'unsafe-eval'` |
| `webapp-missing-security-headers` | no security headers at all |
| `webapp-large-body-limit` | very large request-body limits |
| `webapp-no-rate-limit` | login, reset or OTP routes with no rate limit |
| `webapp-webhook-no-signature` | webhook handlers (Paystack, Flutterwave, Stripe, Meta) that never verify a signature |
| `webapp-open-redirect` | redirecting to a URL taken from the request |
| `webapp-path-traversal` | user input used in file paths |
| `webapp-error-leak` | stack traces sent to visitors |
| `webapp-payment-trust-client` | price or "paid" status trusted from the browser |
| `webapp-llm-prompt-injection` | user input placed inside the AI's system prompt |
| `webapp-llm-risky-tools` | an AI that can send, delete or pay without approval |

**False-alarm fix:** npm integrity checksums in `package-lock.json` are no longer reported as "Azure storage keys".

**Merged without duplicates:** five Defense-in-Depth rules (client-trusted pricing, weak CSP, insecure cookies, weak password hashes, `Math.random()` tokens) were removed because the web-app rules catch the same problems more thoroughly. Hardcoded fallback passwords moved to `webapp-secret-env-fallback`.

## Quick demo

```bash
npm run build
npx vitest run tests/rules/defense-in-depth.test.ts tests/rules/webapp.test.ts
node dist/index.js scan --path examples/defense-in-depth-demo
node dist/index.js scan --path demo-targets/vulnerable-shop --web
node dist/index.js scan --path demo-targets/fixed-shop --web
```

See `DEMO-EXPLAINER.md` for a plain-English walkthrough and a video script.
