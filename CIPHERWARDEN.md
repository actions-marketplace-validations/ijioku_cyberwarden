# CipherWarden

**CipherWarden** is an extended AI Agent & Production Web Security Auditor built as an **MIT-licensed fork** of [`affaan-m/agentshield`](https://github.com/affaan-m/agentshield) (Copyright © 2026 Affaan M — original `LICENSE` preserved intact).

## What CipherWarden Adds Beyond AgentShield

In addition to all 15 built-in AgentShield rule modules (secrets, permissions, hooks, hidden curls/pipes, MCP CVEs, tool poisoning, skills, prompt injection defense), **CipherWarden** adds **13 Production Defense-in-Depth Rules** (`src/rules/defense-in-depth.ts`):

1. `defense-db-rls-disabled` — Disabled/wide-open Postgres & Supabase Row-Level Security (RLS) or exposed `service_role` keys.
2. `defense-ssrf-internal-url` — SSRF targeting cloud metadata (`169.254.169.254`, `metadata.google.internal`) or unvalidated user fetch URLs.
3. `defense-unsafe-file-upload` — Raw `file.originalname` writes or executable upload extensions (`.php`, `.exe`, `.sh`, `.bat`).
4. `defense-payment-webhook-unverified` — Client-trusted `req.body.price` / `isPaid` or unverified Stripe webhooks.
5. `defense-race-condition-billing` — Non-atomic credit/balance deductions vulnerable to double-spend attacks.
6. `defense-supply-chain-unpinned` — Unpinned `"*"` or `"latest"` versions in `package.json`.
7. `defense-sensitive-audit-logging` — Logging raw passwords/tokens or disabling TLS verification (`NODE_TLS_REJECT_UNAUTHORIZED=0`).
8. `defense-csp-unsafe-inline` — Weak `Content-Security-Policy` headers allowing `'unsafe-inline'` or `'unsafe-eval'`.
9. `defense-regional-webhook-unverified` — Unverified Paystack (`x-paystack-signature`), Flutterwave (`verif-hash`), or Meta/WhatsApp webhooks.
10. `defense-ai-chat-history-client-trust` — AI chatbots trusting client-sent `req.body.messages` / `chatHistory`.
11. `defense-insecure-session-cookie` — Session cookies setting `httpOnly: false` or `secure: false`.
12. `defense-weak-password-hash` — Fast password hashes (`md5`, `sha1`, plain `sha256`) instead of `scrypt` / `Argon2id` / `bcrypt`.
13. `defense-ndpa-pii-exposure` — Unmasked personal identifiers (`BVN`, `NIN`, `SSN`, `passportNumber`) logged or exposed (NDPA 2023 compliance).

## Quick Demo

```bash
npm run build
npx vitest run tests/rules/defense-in-depth.test.ts
node dist/index.js scan --path examples/defense-in-depth-demo
```
