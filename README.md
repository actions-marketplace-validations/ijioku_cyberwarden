# CyberWarden

A security scanner for **AI coding setups** and **web apps**. It reads your project, finds common security mistakes, explains each one in plain English, shows how to fix it, and gives you a grade from A to F. It can produce an offline dashboard to share with your team or clients.

CyberWarden is built on [AgentShield](https://github.com/affaan-m/agentshield) by Affaan M (MIT licence).

## Quick start

```bash
# Install from this folder (not on npm yet)
npm install
npm run build
npm link

# Scan your AI coding setup (~/.claude, or the current folder)
cyberwarden scan

# Scan a web project's code too
cyberwarden scan --path ./my-app --web

# Make the interactive dashboard
cyberwarden scan --path ./my-app --web --format dashboard -o cyberwarden-report.html
```

## What it checks: 7 security areas, 274 checks

The first 5 areas come from AgentShield (239 checks, all kept). CyberWarden adds 2 new areas (35 checks).

| Area | Checks | Runs | Examples |
|---|---|---|---|
| **1. Secrets** (AgentShield) | 23 | every scan | API keys, tokens and private keys in `CLAUDE.md`, settings, MCP configs, `.npmrc` and webhook URLs; base64-hidden secrets; secrets in transcripts |
| **2. Permissions & settings** (AgentShield) | 67 | every scan | "allow everything" rules, missing deny lists, prompts or sandboxes switched off, destructive git commands allowed, `~/.ssh` access, redirected model endpoints, unpinned plugins (Claude Code, Codex, Gemini CLI, Cursor, OpenCode, Copilot, Hermes) |
| **3. Hooks** (AgentShield) | 51 | every scan | hooks that download and run code (`curl \| sh`), send data out (including over DNS), open reverse shells, add cron jobs, touch SSH keys or password stores, wipe disks, switch off logs or auto-approve tool calls |
| **4. MCP servers** (AgentShield) | 41 | every scan | known malicious or vulnerable packages, unpinned versions, servers that spawn a shell, plain-HTTP connections, auto-approved tools, broad OAuth scopes, tool poisoning |
| **5. Agents, skills & prompt injection** (AgentShield) | 57 | every scan | hidden or invisible-Unicode instructions, data-exfiltration and "ignore your rules" wording, jailbreaks, agents that can browse *and* write, skills that pre-approve broad tools |
| **6. Defense-in-Depth** (new in CyberWarden) | 12 | every scan | database Row-Level Security off, SSRF to cloud metadata, unsafe uploads, double-spend race conditions, unpinned packages, secrets in logs, Paystack/Flutterwave/WhatsApp webhooks with checks disabled, chatbots trusting browser-sent history, unmasked BVN/NIN (NDPA 2023), mass assignment, served `.env`/`.git`, unlimited OTP attempts |
| **7. Web app code** (new in CyberWarden) | 23 | with `--web` | SQL injection, XSS, code injection, secrets in browser code or git, hardcoded fallback passwords, `Math.random()` tokens, weak password hashing, insecure cookies, open CORS, weak CSP, missing headers, huge body limits, unthrottled logins, unsigned webhooks, open redirects, path traversal, leaked stack traces, browser-trusted payments, AI prompt injection and AI tools that act without approval |

`--web` never reads what's inside your `.env` file. It only checks the file's name and whether git ignores it.

## The dashboard

`--format dashboard` writes one HTML file that works offline and makes no network requests. It has:

- **Overview**: grade, score by area, findings by severity, what to fix first, scan details
- **Findings**: every problem, with why it matters, where it is, what was found and a before/after fix, with search and filters
- **Security checks**: every check that ran, and whether it passed, found problems or was skipped
- **Fix plan**: a to-do list in order of urgency, with progress saved in your browser
- **Files**: which files carry the most risk
- **Compliance**: affected SOC 2, PCI DSS and ISO 27001 controls (guidance, not a certified audit)
- **Learn**: what severities, grades and categories mean

It follows your device's light or dark theme (with a System / Dark / Light switch), works on phones, and can be saved as a PDF.

## Other output formats

`--format terminal` (default), `json`, `markdown`, `html`, `sarif` (for GitHub code scanning) and `dashboard`. Add `--fix` to apply the safe automatic fixes after reviewing them.

## Try it on the examples

```bash
cyberwarden scan --path examples/vulnerable-shop --web    # a deliberately broken shop: Grade D
cyberwarden scan --path examples/fixed-shop --web         # the same shop, fixed: Grade A
cyberwarden scan --path examples/defense-in-depth-demo    # triggers every Defense-in-Depth rule
```

## Use it as a GitHub Action

Scan every push and pull request. Add this file to your repository as `.github/workflows/cyberwarden.yml`:

```yaml
name: Security scan
on: [push, pull_request]
permissions:
  contents: read
jobs:
  cyberwarden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ijioku/cyberwarden@v1.0.0
        with:
          web: "true"            # also check website and web-app code
          min-severity: "medium" # report medium, high and critical problems
          fail-on-findings: "true"
```

Leave out `web` (or set it to `"false"`) to scan only the AI coding setup files. The run shows each problem on the line where it was found, and gives you `score`, `grade` and `total-findings` outputs to use in later steps.

## Honest limits

A scanner is a smoke alarm, not a fire brigade. It catches common, clear-cut mistakes quickly, but a clean result means "no known patterns found", not "impossible to hack". Use it alongside code review, testing, and two-factor login on your GitHub, hosting and domain accounts.

## More

- Full CLI, API and GitHub Action reference: [`docs/agentshield-reference.md`](docs/agentshield-reference.md)
- Changes: [`CHANGELOG.md`](CHANGELOG.md)

## Licence

MIT. See [`LICENSE`](LICENSE). The original AgentShield copyright (Affaan M) is kept alongside CyberWarden's.
