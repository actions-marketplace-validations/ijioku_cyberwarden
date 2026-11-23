---
name: cyberwarden-security-scan
description: Security-check a website, web app, mobile backend or AI coding setup with CyberWarden before it goes live. Runs `cyberwarden scan --web`, separates real problems from false alarms, fixes the real ones in the project's own code, re-scans, makes the offline dashboard, and explains the results in plain English. Use this whenever the user is about to deploy, launch, hand over or sell a site or app; asks "is this secure?", "check my code for security issues", "run a security scan", "audit this project", or "make a security report for my client"; mentions CyberWarden, AgentShield, leaked API keys, hardcoded secrets, prompt injection, hooks or MCP risks; or finishes a big change (logins, payments, databases, AI features, webhooks, uploads). Use it even if they don't name the tool.
---

# CyberWarden security scan

CyberWarden is a scanner built on AgentShield (MIT). It checks three things:

- **AI agent setup** (AgentShield's rules): secrets in configs, permissions, hooks, MCP servers, skills and prompt injection.
- **Defense-in-Depth rules** (every scan): RLS, SSRF, uploads, race conditions, unpinned packages, Paystack/Flutterwave/WhatsApp webhooks, NDPA personal data, mass assignment, dotfiles and OTP safety.
- **Web-app rules** (`--web`): SQL injection, XSS, secrets in code or git, cookies, CORS, CSP, rate limits, payments and AI prompt safety.

Your job is to turn its output into a safer project and an explanation the user understands. Many users of this skill are beginners selling sites to small businesses, so the explanation matters as much as the fixes.

## 1. Make sure the tool is there

Run `cyberwarden --version`. If it's missing:
- If the CyberWarden repo is on the machine, run `npm install && npm run build && npm link` inside it.
- Otherwise, run `npm install -g cyberwarden` once it's published, or clone `github.com/ijioku/cyberwarden` and link it.

## 2. Scan

Scan the project folder, not `~/.claude`. Without `--path` it scans the AI coding setup instead.

```bash
cyberwarden scan --path <project> --web --format json -o <scratch>/cw.json
```

Use JSON for your own triage, because the terminal report is long. Read `score`, `summary` and `findings`. Each finding has `id` (rule id plus file and position), `severity`, `title`, `description`, `file`, `line`, `evidence` and `fix`.

## 3. Triage: real problem or false alarm?

Decide for every critical, high and medium finding before touching code. Fixing false alarms wastes the user's time and clutters their code.

Usually **not** real:
- Findings inside `node_modules/`, `dist/`, build output, test fixtures, `examples/` or attack-sample files. Security tools carry fake keys on purpose, often labelled `CANARY` or `fake`.
- "Missing prompt defense" wording complaints about third-party plugin files.
- MCP servers flagged for "connecting to an external URL" when connecting to their own service is their whole job (Slack, GitHub, Notion…).
- `Access-Control-Allow-Origin: *` on genuinely public routes that use no cookies (a public chat widget API, for example). CyberWarden already marks these as info.
- Example credentials in documentation.

Usually **real**, and worth fixing:
- Any real-looking key in source code, browser code, mobile code or git history.
- A hardcoded fallback password (`process.env.ADMIN_PASSWORD || 'changeme'`), even when a production check guards it. Prefer failing at startup when the variable is missing.
- SQL or HTML built from user input, user input in file paths or redirects, prices or "paid" flags trusted from the browser, webhooks without signature checks, logins without rate limits, weak password hashing, `Math.random()` tokens, and AI features that can send, delete or pay without approval.

When unsure, open the file and look at the code around the line. The finding's `description` explains what the rule looked for.

## 4. Fix the real ones

- Edit only the project's own files. Never edit third-party plugins or `node_modules`.
- Use the finding's `fix.after` as a hint, not as code to paste. Fit the fix to how the project already works: its libraries, its style, its comment rules.
- Don't run `--fix` without first checking what it would change.
- Secrets: move them to `.env` (make sure it's in `.gitignore`), and add a placeholder to `.env.example`. If the secret was ever committed or pushed, tell the user to revoke and replace it at the provider, because git history keeps the old value.
- Keep behaviour the same. If a fix could change what users see (a stricter CSP, a new rate limit), test the affected pages afterwards.

## 5. Re-scan, then make the dashboard

Re-run the JSON scan and confirm the fixed findings are gone and no new ones appeared. Then make the dashboard the user can open, share or put in a client handover:

```bash
cyberwarden scan --path <project> --web --format dashboard -o cyberwarden-report.html
```

It's a single offline HTML file with these tabs: Overview, Findings (with before/after fixes), Security checks (every check: passed, found problems, or not run), Fix plan, Files, Compliance (SOC 2 / PCI / ISO) and Learn. Tell the user where it is. It doesn't belong inside a git repo, so suggest adding it to `.gitignore` if it's saved in the project.

## 6. Explain simply

Report in plain English, short:

```
Grade: <before> → <after>
Fixed: <each real issue, one line each: what it was, why it mattered, what changed>
False alarms (no change needed): <each, one line on why it's safe>
Still open: <anything you couldn't fix or that needs the user, like rotating a key or turning on 2FA>
Dashboard: <path>
```

Be honest about the limits. A scanner is a smoke alarm, not a fire brigade: a clean scan means no known patterns were found, not that the project can't be hacked. Account security (2FA on GitHub, hosting and the domain), backups and testing still matter.
