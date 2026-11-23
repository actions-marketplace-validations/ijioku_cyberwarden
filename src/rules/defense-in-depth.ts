import type { ConfigFile, Finding, Rule, Severity } from "../types.js";

// The shape of one Defense-in-Depth check.
interface DefensePatternRule {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly severity: Severity;
  readonly category: Finding["category"];
  readonly pattern: RegExp;
  readonly fixDescription: string;
  readonly fixAfter: string;
  readonly fileTypes?: ReadonlyArray<ConfigFile["type"]>;
}

/**
 * Find the 1-based line number where a regex match starts in a file.
 */
function findLineNumber(content: string, matchIndex: number): number {
  return content.slice(0, matchIndex).split("\n").length;
}

// The Defense-in-Depth checks: each one is a pattern plus a plain-English explanation and fix.
const DEFENSE_IN_DEPTH_SPECS: ReadonlyArray<DefensePatternRule> = [
  // Database Row-Level Security (RLS) & least-privilege check.
  {
    id: "defense-db-rls-disabled",
    name: "Database Row-Level Security Disabled or Overly Permissive",
    description:
      "Disabling Row-Level Security (RLS), using wide-open USING (true) policies, or exposing a service_role database key lets any user read or alter other users' rows.",
    severity: "critical",
    category: "misconfiguration",
    pattern:
      /(?:DISABLE\s+ROW\s+LEVEL\s+SECURITY|USING\s*\(\s*true\s*\)|WITH\s+CHECK\s*\(\s*true\s*\)|SUPABASE_SERVICE_ROLE_KEY\s*[:=]\s*["']eyJ)/i,
    fixDescription:
      "Enable Row-Level Security (ENABLE ROW LEVEL SECURITY), scope policies to auth.uid() = user_id, and keep service_role keys strictly in server-side environment variables.",
    fixAfter: "ALTER TABLE items ENABLE ROW LEVEL SECURITY; -- Policy: USING (auth.uid() = user_id)",
  },
  // Server-Side Request Forgery (SSRF) protection.
  {
    id: "defense-ssrf-internal-url",
    name: "SSRF Risk Targeting Internal or Cloud Metadata Address",
    description:
      "Fetching cloud metadata endpoints (169.254.169.254) or passing unvalidated user URLs into fetch/curl lets attackers spy on private internal services and steal cloud credentials.",
    severity: "critical",
    category: "exfiltration",
    pattern:
      /(?:169\.254\.169\.254|metadata\.google\.internal|(?:fetch|axios\.get|axios\.post)\s*\(\s*(?:req\.(?:body|query|params)\.\w+|userUrl))/i,
    fixDescription:
      "Validate outbound URLs against an explicit domain allowlist and block private/link-local IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.169.254).",
    fixAfter: "assertAllowedExternalUrl(userUrl); await fetch(userUrl);",
  },
  // Unsafe file upload handling.
  {
    id: "defense-unsafe-file-upload",
    name: "Unsafe File Upload Using Unsanitized Filename or Executable Types",
    description:
      "Saving uploaded files with their original user-supplied filename or allowing executable extensions (.php, .sh, .exe) enables path traversal and remote code execution.",
    severity: "high",
    category: "injection",
    pattern:
      /(?:writeFile(?:Sync)?\s*\([^)]*(?:file\.originalname|req\.file\.filename)|accept\s*[:=]\s*["'][^"']*(?:\.php|\.exe|\.sh|\.bat))/i,
    fixDescription:
      "Validate MIME type and max file size server-side, generate a random UUID filename, and store uploads in isolated object storage (S3/R2/Storage bucket).",
    fixAfter: "const safeName = `${crypto.randomUUID()}.webp`; await uploadToBucket(safeName, buffer);",
  },
  // Billing / credit race conditions (double-spend).
  {
    id: "defense-race-condition-billing",
    name: "Potential Double-Spend Race Condition in Credit or Balance Update",
    description:
      "Reading a user's credit balance and updating it in a separate non-atomic step allows attackers to send parallel requests and spend the same credits multiple times.",
    severity: "high",
    category: "misconfiguration",
    pattern:
      /(?:user\.(?:credits|balance)\s*(?:-=|=\s*user\.(?:credits|balance)\s*-)\s*\w+)/i,
    fixDescription:
      "Use an atomic database transaction with a conditional check (e.g., UPDATE users SET credits = credits - $1 WHERE id = $2 AND credits >= $1) and an idempotency key.",
    fixAfter: "await db.transaction(async (tx) => tx.execute('UPDATE users SET credits = credits - $1 WHERE id = $2 AND credits >= $1', [cost, userId]));",
  },
  // Supply-chain unpinned dependencies.
  {
    id: "defense-supply-chain-unpinned",
    name: "Unpinned Wildcard Dependency Version in Package Config",
    description:
      "Using wildcard ('*') or 'latest' dependency versions lets a compromised package update pull malicious code into your build automatically.",
    severity: "medium",
    category: "misconfiguration",
    pattern: /"[^"]+"\s*:\s*"(?:\*|latest)"/i,
    fixDescription:
      "Pin dependencies to explicit semantic versions and commit your lockfile (package-lock.json or pnpm-lock.yaml).",
    fixAfter: '"package-name": "^1.2.3"',
    // Only run this check on package manager config files like package.json.
    fileTypes: ["package-manager-config"],
  },
  // Sensitive secret logging & disabled TLS verification.
  {
    id: "defense-sensitive-audit-logging",
    name: "Sensitive Credential Logged or TLS Certificate Verification Disabled",
    description:
      "Logging raw passwords/tokens leaks credentials into log files, and disabling TLS verification (rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED=0) exposes traffic to man-in-the-middle attacks.",
    severity: "high",
    category: "exposure",
    pattern:
      /(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?|rejectUnauthorized\s*:\s*false|(?:console\.log|logger\.(?:info|debug))\s*\([^)]*(?:password|apiKey|accessToken|authorization|secret))/i,
    fixDescription:
      "Redact passwords, tokens, and secrets before logging, and keep TLS certificate verification enabled in all environments.",
    fixAfter: "logger.info({ event: 'user_login', userId }); // Never log raw passwords or tokens",
  },
  // Paystack, Flutterwave & Meta/WhatsApp webhook signature verification.
  {
    id: "defense-regional-webhook-unverified",
    name: "Unverified Paystack, Flutterwave, or WhatsApp/Meta Webhook Handler",
    description:
      "Accepting Paystack, Flutterwave, or Meta/WhatsApp webhooks without verifying x-paystack-signature, verif-hash, or x-hub-signature-256 lets attackers forge fake payments or messages.",
    severity: "critical",
    category: "misconfiguration",
    pattern:
      /(?:(?:paystack|flutterwave|whatsapp).*skip(?:Verify|Signature)|verifySignature\s*[:=]\s*false|x-paystack-signature\s*===\s*undefined)/i,
    fixDescription:
      "Always verify HMAC signatures using timingSafeEqual (x-paystack-signature for Paystack, verif-hash for Flutterwave, x-hub-signature-256 for Meta/WhatsApp).",
    fixAfter: "if (!verifyHmacTimingSafe(rawBody, req.headers['x-paystack-signature'], process.env.PAYSTACK_SECRET)) return res.status(401).end();",
  },
  // Client-controlled AI chat history spoofing.
  {
    id: "defense-ai-chat-history-client-trust",
    name: "AI Chatbot Trusting Client-Sent Chat History or System Messages",
    description:
      "Passing req.body.messages or req.body.chatHistory straight to an LLM lets visitors fake previous assistant replies or inject fake system prompts.",
    severity: "high",
    category: "injection",
    pattern:
      /(?:messages\s*:\s*req\.body\.(?:messages|chatHistory|history)|chatHistory\s*=\s*req\.body\.(?:messages|chatHistory))/i,
    fixDescription:
      "Store conversation history on the server tied to the user's session ID and only accept the latest plain user message text from the client.",
    fixAfter: "const history = await getServerChatHistory(sessionId); history.push({ role: 'user', content: cleanInput });",
  },
  // NDPA 2023 / PII exposure in logs or unmasked dumps.
  {
    id: "defense-ndpa-pii-exposure",
    name: "Unmasked Personal Data (PII / BVN / NIN) Logged or Exposed (NDPA 2023)",
    description:
      "Logging or exposing sensitive personal identifiers (BVN, NIN, SSN, raw phone/email dumps) violates Nigeria's Data Protection Act (NDPA 2023) and global privacy standards.",
    severity: "high",
    category: "exposure",
    pattern:
      /(?:console\.log|logger\.(?:info|debug|warn))\s*\([^)]*(?:\bbvn\b|\bnin\b|\bssn\b|nationalId|passportNumber)/i,
    fixDescription:
      "Mask or redact personal identifiers (BVN, NIN, SSN) before logging, collect only necessary fields, and encrypt stored PII at rest.",
    fixAfter: "logger.info({ event: 'kyc_checked', userId }); // Redact BVN/NIN per NDPA 2023",
  },
  // Mass assignment ("role": "admin" injection).
  {
    id: "defense-mass-assignment",
    name: "Mass Assignment Passing Raw req.body Directly Into Database Write",
    description:
      "Passing raw req.body straight into create/update/Object.assign lets attackers inject hidden fields like role: 'admin' or isAdmin: true.",
    severity: "critical",
    category: "misconfiguration",
    pattern:
      /(?:\.(?:create|update|insert|findByIdAndUpdate)\s*\(\s*req\.body\s*\)|Object\.assign\s*\(\s*user\s*,\s*req\.body\s*\))/i,
    fixDescription:
      "Explicitly allowlist only the fields users are allowed to edit (e.g., const { name, bio } = schema.parse(req.body)) before saving to the database.",
    fixAfter: "const { name, bio } = profileSchema.parse(req.body); await User.update({ name, bio });",
  },
  // Default/fallback admin passwords or exposed dotfiles.
  {
    id: "defense-default-admin-or-dotfiles",
    name: "Static File Server Exposes Dotfiles (.env / .git)",
    description:
      "Serving dotfiles (.env, .git) from a static file server lets automated scanners download your secrets and source code. (Hardcoded fallback passwords are caught by the webapp-secret-env-fallback rule.)",
    severity: "critical",
    category: "exposure",
    pattern:
      /dotfiles\s*:\s*["']allow["']/i,
    fixDescription:
      "Fail startup if required admin secrets are missing from environment variables, and set dotfiles: 'deny' on static file servers.",
    fixAfter: "const adminPass = process.env.ADMIN_PASSWORD; if (!adminPass) throw new Error('ADMIN_PASSWORD required');",
  },
  // Unprotected OTP or password-change flow.
  {
    id: "defense-otp-or-password-change-unsafe",
    name: "Unprotected OTP Verification or Password Change Skipping Current Password",
    description:
      "Allowing unlimited OTP retries (especially on WhatsApp/phone logins) or letting users change email/password without verifying their current password enables account takeover.",
    severity: "high",
    category: "misconfiguration",
    pattern:
      /(?:otpMaxAttempts\s*[:=]\s*(?:0|Infinity|null)|skipCurrentPasswordCheck\s*[:=]\s*true)/i,
    fixDescription:
      "Cap OTP attempts (e.g., max 5 tries with 5–10 min lockout + short 5-minute expiry) and always require the current password before changing email or password.",
    fixAfter: "const otpMaxAttempts = 5; // Lock temporarily after 5 wrong tries and expire OTP in 5 mins",
  },
];

// Turn one check into a scanner rule that reports the first risky match in each file.
function buildRule(spec: DefensePatternRule): Rule {
  return {
    id: spec.id,
    name: spec.name,
    description: spec.description,
    severity: spec.severity,
    category: spec.category,
    check(file: ConfigFile): ReadonlyArray<Finding> {
      // Some checks only apply to certain kinds of file (for example package.json).
      if (spec.fileTypes && !spec.fileTypes.includes(file.type)) {
        return [];
      }

      // Look for the risky pattern; clean files return nothing.
      const match = spec.pattern.exec(file.content);
      if (!match) {
        return [];
      }

      // Turn the match position into a line number, and keep a short snippet as evidence.
      const line = findLineNumber(file.content, match.index);
      const evidence = match[0].trim().slice(0, 120);

      return [
        {
          id: spec.id,
          severity: spec.severity,
          category: spec.category,
          title: spec.name,
          description: spec.description,
          file: file.path,
          line,
          evidence,
          // Attach a guided fix suggestion.
          fix: {
            description: spec.fixDescription,
            before: evidence,
            after: spec.fixAfter,
            auto: false,
          },
        },
      ];
    },
  };
}

// Turn every check into a scanner rule.
export const defenseInDepthRules: ReadonlyArray<Rule> = DEFENSE_IN_DEPTH_SPECS.map(buildRule);
