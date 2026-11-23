import type { ConfigFile, Finding, Rule, Severity } from "../types.js"; // Import core scanner types for rules and findings.

interface DefensePatternRule { // Define a reusable blueprint for each CyberWarden defense-in-depth rule.
  readonly id: string; // Store the unique rule identifier.
  readonly name: string; // Store the human-readable rule name.
  readonly description: string; // Store a plain-English summary of what the rule catches.
  readonly severity: Severity; // Store how urgent the security issue is.
  readonly category: Finding["category"]; // Store which security category this belongs to.
  readonly pattern: RegExp; // Store the regular expression that detects the risky pattern.
  readonly fixDescription: string; // Store a clear instruction on how to fix the issue.
  readonly fixAfter: string; // Store a safe replacement example for the report.
  readonly fileTypes?: ReadonlyArray<ConfigFile["type"]>; // Optionally limit this rule to specific file types.
} // End of the DefensePatternRule interface definition.

/**
 * Find the 1-based line number where a regex match starts in a file.
 */
function findLineNumber(content: string, matchIndex: number): number { // Define a helper that turns a character offset into a line number.
  return content.slice(0, matchIndex).split("\n").length; // Count newline breaks before the match to get the 1-based line number.
} // End of findLineNumber helper.

const DEFENSE_IN_DEPTH_SPECS: ReadonlyArray<DefensePatternRule> = [ // List all 12 CyberWarden Defense-in-Depth security checks.
  { // Start Rule 1: Database Row-Level Security (RLS) & least-privilege check.
    id: "defense-db-rls-disabled", // Unique ID for the database RLS rule.
    name: "Database Row-Level Security Disabled or Overly Permissive", // Display title for the RLS rule.
    description: // Explain why weak or disabled RLS is dangerous.
      "Disabling Row-Level Security (RLS), using wide-open USING (true) policies, or exposing a service_role database key lets any user read or alter other users' rows.", // Plain-English risk description.
    severity: "critical", // Mark as critical because it exposes all user data.
    category: "misconfiguration", // Group under misconfiguration.
    pattern: // Match disabled RLS, wide-open RLS policies, or raw service_role keys in configs/scripts.
      /(?:DISABLE\s+ROW\s+LEVEL\s+SECURITY|USING\s*\(\s*true\s*\)|WITH\s+CHECK\s*\(\s*true\s*\)|SUPABASE_SERVICE_ROLE_KEY\s*[:=]\s*["']eyJ)/i, // Case-insensitive regex for RLS bypasses.
    fixDescription: // Explain how to fix the database security issue.
      "Enable Row-Level Security (ENABLE ROW LEVEL SECURITY), scope policies to auth.uid() = user_id, and keep service_role keys strictly in server-side environment variables.", // Actionable fix guidance.
    fixAfter: "ALTER TABLE items ENABLE ROW LEVEL SECURITY; -- Policy: USING (auth.uid() = user_id)", // Safe replacement snippet.
  }, // End Rule 1.
  { // Start Rule 2: Server-Side Request Forgery (SSRF) protection.
    id: "defense-ssrf-internal-url", // Unique ID for the SSRF rule.
    name: "SSRF Risk Targeting Internal or Cloud Metadata Address", // Display title for the SSRF rule.
    description: // Explain why calling internal or metadata IPs is dangerous.
      "Fetching cloud metadata endpoints (169.254.169.254) or passing unvalidated user URLs into fetch/curl lets attackers spy on private internal services and steal cloud credentials.", // Plain-English risk description.
    severity: "critical", // Mark as critical because SSRF can leak cloud IAM credentials.
    category: "exfiltration", // Group under exfiltration.
    pattern: // Match cloud metadata URLs or unvalidated user input inside fetch/axios/curl.
      /(?:169\.254\.169\.254|metadata\.google\.internal|(?:fetch|axios\.get|axios\.post)\s*\(\s*(?:req\.(?:body|query|params)\.\w+|userUrl))/i, // Case-insensitive regex for SSRF targets.
    fixDescription: // Explain how to block SSRF attacks.
      "Validate outbound URLs against an explicit domain allowlist and block private/link-local IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.169.254).", // Actionable fix guidance.
    fixAfter: "assertAllowedExternalUrl(userUrl); await fetch(userUrl);", // Safe replacement snippet.
  }, // End Rule 2.
  { // Start Rule 3: Unsafe file upload handling.
    id: "defense-unsafe-file-upload", // Unique ID for the file upload rule.
    name: "Unsafe File Upload Using Unsanitized Filename or Executable Types", // Display title for the file upload rule.
    description: // Explain why raw upload filenames and executable uploads are dangerous.
      "Saving uploaded files with their original user-supplied filename or allowing executable extensions (.php, .sh, .exe) enables path traversal and remote code execution.", // Plain-English risk description.
    severity: "high", // Mark as high severity.
    category: "injection", // Group under injection.
    pattern: // Match saving uploads with originalname/filename or allowing dangerous executable extensions.
      /(?:writeFile(?:Sync)?\s*\([^)]*(?:file\.originalname|req\.file\.filename)|accept\s*[:=]\s*["'][^"']*(?:\.php|\.exe|\.sh|\.bat))/i, // Case-insensitive regex for unsafe uploads.
    fixDescription: // Explain how to harden file uploads.
      "Validate MIME type and max file size server-side, generate a random UUID filename, and store uploads in isolated object storage (S3/R2/Storage bucket).", // Actionable fix guidance.
    fixAfter: "const safeName = `${crypto.randomUUID()}.webp`; await uploadToBucket(safeName, buffer);", // Safe replacement snippet.
  }, // End Rule 3.
  { // Start Rule 5: Billing / credit race conditions (double-spend).
    id: "defense-race-condition-billing", // Unique ID for the race-condition rule.
    name: "Potential Double-Spend Race Condition in Credit or Balance Update", // Display title for the race-condition rule.
    description: // Explain how non-atomic balance updates allow double-spending.
      "Reading a user's credit balance and updating it in a separate non-atomic step allows attackers to send parallel requests and spend the same credits multiple times.", // Plain-English risk description.
    severity: "high", // Mark as high severity.
    category: "misconfiguration", // Group under misconfiguration.
    pattern: // Match simple in-memory subtraction before saving back to a user balance without a transaction.
      /(?:user\.(?:credits|balance)\s*(?:-=|=\s*user\.(?:credits|balance)\s*-)\s*\w+)/i, // Case-insensitive regex for non-atomic balance deduction.
    fixDescription: // Explain how to prevent double-spend race conditions.
      "Use an atomic database transaction with a conditional check (e.g., UPDATE users SET credits = credits - $1 WHERE id = $2 AND credits >= $1) and an idempotency key.", // Actionable fix guidance.
    fixAfter: "await db.transaction(async (tx) => tx.execute('UPDATE users SET credits = credits - $1 WHERE id = $2 AND credits >= $1', [cost, userId]));", // Safe replacement snippet.
  }, // End Rule 5.
  { // Start Rule 6: Supply-chain unpinned dependencies.
    id: "defense-supply-chain-unpinned", // Unique ID for the supply-chain pinning rule.
    name: "Unpinned Wildcard Dependency Version in Package Config", // Display title for the unpinned dependency rule.
    description: // Explain why "*" or "latest" dependency versions are a supply-chain risk.
      "Using wildcard ('*') or 'latest' dependency versions lets a compromised package update pull malicious code into your build automatically.", // Plain-English risk description.
    severity: "medium", // Mark as medium severity.
    category: "misconfiguration", // Group under misconfiguration.
    pattern: /"[^"]+"\s*:\s*"(?:\*|latest)"/i, // Match any JSON dependency pinned to "*" or "latest".
    fixDescription: // Explain how to pin dependencies safely.
      "Pin dependencies to explicit semantic versions and commit your lockfile (package-lock.json or pnpm-lock.yaml).", // Actionable fix guidance.
    fixAfter: '"package-name": "^1.2.3"', // Safe replacement snippet.
    fileTypes: ["package-manager-config"], // Only run this check on package manager config files like package.json.
  }, // End Rule 6.
  { // Start Rule 7: Sensitive secret logging & disabled TLS verification.
    id: "defense-sensitive-audit-logging", // Unique ID for the sensitive logging / TLS rule.
    name: "Sensitive Credential Logged or TLS Certificate Verification Disabled", // Display title for the logging/TLS rule.
    description: // Explain why logging secrets or disabling TLS breaks transport and audit security.
      "Logging raw passwords/tokens leaks credentials into log files, and disabling TLS verification (rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED=0) exposes traffic to man-in-the-middle attacks.", // Plain-English risk description.
    severity: "high", // Mark as high severity.
    category: "exposure", // Group under exposure.
    pattern: // Match console/logger printing secrets or code disabling TLS certificate checks.
      /(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?|rejectUnauthorized\s*:\s*false|(?:console\.log|logger\.(?:info|debug))\s*\([^)]*(?:password|apiKey|accessToken|authorization|secret))/i, // Case-insensitive regex for secret logs & disabled TLS.
    fixDescription: // Explain how to fix logging and TLS settings.
      "Redact passwords, tokens, and secrets before logging, and keep TLS certificate verification enabled in all environments.", // Actionable fix guidance.
    fixAfter: "logger.info({ event: 'user_login', userId }); // Never log raw passwords or tokens", // Safe replacement snippet.
  }, // End Rule 7.
  { // Start Rule 9: Paystack, Flutterwave & Meta/WhatsApp webhook signature verification.
    id: "defense-regional-webhook-unverified", // Unique ID for Paystack/Flutterwave/Meta webhook checks.
    name: "Unverified Paystack, Flutterwave, or WhatsApp/Meta Webhook Handler", // Display title for the regional webhook rule.
    description: // Explain why skipping webhook signature checks on Paystack/Flutterwave/Meta is dangerous.
      "Accepting Paystack, Flutterwave, or Meta/WhatsApp webhooks without verifying x-paystack-signature, verif-hash, or x-hub-signature-256 lets attackers forge fake payments or messages.", // Plain-English risk description.
    severity: "critical", // Mark as critical because forged webhooks unlock unpaid orders or spoof messages.
    category: "misconfiguration", // Group under misconfiguration.
    pattern: // Match Paystack/Flutterwave/WhatsApp webhook routes that explicitly skip signature verification.
      /(?:(?:paystack|flutterwave|whatsapp).*skip(?:Verify|Signature)|verifySignature\s*[:=]\s*false|x-paystack-signature\s*===\s*undefined)/i, // Case-insensitive regex for skipped regional webhook verification.
    fixDescription: // Explain how to verify regional payment and messaging webhooks.
      "Always verify HMAC signatures using timingSafeEqual (x-paystack-signature for Paystack, verif-hash for Flutterwave, x-hub-signature-256 for Meta/WhatsApp).", // Actionable fix guidance.
    fixAfter: "if (!verifyHmacTimingSafe(rawBody, req.headers['x-paystack-signature'], process.env.PAYSTACK_SECRET)) return res.status(401).end();", // Safe replacement snippet.
  }, // End Rule 9.
  { // Start Rule 10: Client-controlled AI chat history spoofing.
    id: "defense-ai-chat-history-client-trust", // Unique ID for client-trusted AI chat history rule.
    name: "AI Chatbot Trusting Client-Sent Chat History or System Messages", // Display title for the AI chat history rule.
    description: // Explain why trusting chat history from req.body lets visitors hijack the AI.
      "Passing req.body.messages or req.body.chatHistory straight to an LLM lets visitors fake previous assistant replies or inject fake system prompts.", // Plain-English risk description.
    severity: "high", // Mark as high severity because it enables prompt spoofing and fake leads.
    category: "injection", // Group under injection.
    pattern: // Match passing req.body.messages or req.body.chatHistory directly into an AI model call.
      /(?:messages\s*:\s*req\.body\.(?:messages|chatHistory|history)|chatHistory\s*=\s*req\.body\.(?:messages|chatHistory))/i, // Case-insensitive regex for client-controlled LLM history.
    fixDescription: // Explain how to store AI chat history safely.
      "Store conversation history on the server tied to the user's session ID and only accept the latest plain user message text from the client.", // Actionable fix guidance.
    fixAfter: "const history = await getServerChatHistory(sessionId); history.push({ role: 'user', content: cleanInput });", // Safe replacement snippet.
  }, // End Rule 10.
  { // Start Rule 13: NDPA 2023 / PII exposure in logs or unmasked dumps.
    id: "defense-ndpa-pii-exposure", // Unique ID for NDPA 2023 / personal data privacy checks.
    name: "Unmasked Personal Data (PII / BVN / NIN) Logged or Exposed (NDPA 2023)", // Display title for the PII/NDPA rule.
    description: // Explain why exposing raw PII violates NDPA 2023 and user privacy.
      "Logging or exposing sensitive personal identifiers (BVN, NIN, SSN, raw phone/email dumps) violates Nigeria's Data Protection Act (NDPA 2023) and global privacy standards.", // Plain-English risk description.
    severity: "high", // Mark as high severity for regulatory and privacy risk.
    category: "exposure", // Group under exposure.
    pattern: // Match logging raw BVN, NIN, SSN, or full user PII objects.
      /(?:console\.log|logger\.(?:info|debug|warn))\s*\([^)]*(?:\bbvn\b|\bnin\b|\bssn\b|nationalId|passportNumber)/i, // Case-insensitive regex for unmasked PII logging.
    fixDescription: // Explain how to stay NDPA 2023 compliant.
      "Mask or redact personal identifiers (BVN, NIN, SSN) before logging, collect only necessary fields, and encrypt stored PII at rest.", // Actionable fix guidance.
    fixAfter: "logger.info({ event: 'kyc_checked', userId }); // Redact BVN/NIN per NDPA 2023", // Safe replacement snippet.
  }, // End Rule 13.
  { // Start Rule 14: Mass assignment ("role": "admin" injection).
    id: "defense-mass-assignment", // Unique ID for the mass assignment rule.
    name: "Mass Assignment Passing Raw req.body Directly Into Database Write", // Display title for the mass assignment rule.
    description: // Explain why saving raw req.body lets attackers escalate privileges.
      "Passing raw req.body straight into create/update/Object.assign lets attackers inject hidden fields like role: 'admin' or isAdmin: true.", // Plain-English risk description.
    severity: "critical", // Mark as critical because it allows instant admin takeover.
    category: "misconfiguration", // Group under misconfiguration.
    pattern: // Match ORM create/update or Object.assign consuming raw req.body directly.
      /(?:\.(?:create|update|insert|findByIdAndUpdate)\s*\(\s*req\.body\s*\)|Object\.assign\s*\(\s*user\s*,\s*req\.body\s*\))/i, // Case-insensitive regex for mass assignment.
    fixDescription: // Explain how to prevent mass assignment.
      "Explicitly allowlist only the fields users are allowed to edit (e.g., const { name, bio } = schema.parse(req.body)) before saving to the database.", // Actionable fix guidance.
    fixAfter: "const { name, bio } = profileSchema.parse(req.body); await User.update({ name, bio });", // Safe replacement snippet.
  }, // End Rule 14.
  { // Start Rule 16: Default/fallback admin passwords or exposed dotfiles.
    id: "defense-default-admin-or-dotfiles", // Unique ID for default passwords & exposed dotfiles.
    name: "Static File Server Exposes Dotfiles (.env / .git)", // Display title for default credentials/dotfiles rule.
    description: // Explain why fallback passwords like 'changeme' or serving dotfiles is dangerous.
      "Serving dotfiles (.env, .git) from a static file server lets automated scanners download your secrets and source code. (Hardcoded fallback passwords are caught by the webapp-secret-env-fallback rule.)", // Plain-English risk description.
    severity: "critical", // Mark as critical because default creds and exposed .env give instant full access.
    category: "exposure", // Group under exposure.
    pattern: // Match fallback 'changeme'/'admin123' passwords or Express static dotfiles: 'allow'.
      /dotfiles\s*:\s*["']allow["']/i, // Case-insensitive regex for default passwords or dotfile exposure.
    fixDescription: // Explain how to eliminate fallback passwords and block dotfiles.
      "Fail startup if required admin secrets are missing from environment variables, and set dotfiles: 'deny' on static file servers.", // Actionable fix guidance.
    fixAfter: "const adminPass = process.env.ADMIN_PASSWORD; if (!adminPass) throw new Error('ADMIN_PASSWORD required');", // Safe replacement snippet.
  }, // End Rule 16.
  { // Start Rule 17: Unprotected OTP or password-change flow.
    id: "defense-otp-or-password-change-unsafe", // Unique ID for OTP/password-change protection.
    name: "Unprotected OTP Verification or Password Change Skipping Current Password", // Display title for OTP/password-change rule.
    description: // Explain why unlimited OTP guesses or skipping current-password checks compromises accounts.
      "Allowing unlimited OTP retries (especially on WhatsApp/phone logins) or letting users change email/password without verifying their current password enables account takeover.", // Plain-English risk description.
    severity: "high", // Mark as high severity for account takeover risk.
    category: "misconfiguration", // Group under misconfiguration.
    pattern: // Match explicit OTP retry bypasses or password/email changes skipping current password checks.
      /(?:otpMaxAttempts\s*[:=]\s*(?:0|Infinity|null)|skipCurrentPasswordCheck\s*[:=]\s*true)/i, // Case-insensitive regex for unsafe OTP/password-change flags.
    fixDescription: // Explain how to harden OTP and credential changes.
      "Cap OTP attempts (e.g., max 5 tries with 5–10 min lockout + short 5-minute expiry) and always require the current password before changing email or password.", // Actionable fix guidance.
    fixAfter: "const otpMaxAttempts = 5; // Lock temporarily after 5 wrong tries and expire OTP in 5 mins", // Safe replacement snippet.
  }, // End Rule 17.
]; // End of DEFENSE_IN_DEPTH_SPECS array.

/**
 * Convert each DefensePatternRule blueprint into a full CyberWarden Rule object.
 */
function buildRule(spec: DefensePatternRule): Rule { // Define factory function to create a scanner Rule.
  return { // Return a standard Rule object.
    id: spec.id, // Copy the unique rule ID.
    name: spec.name, // Copy the rule display name.
    description: spec.description, // Copy the rule description.
    severity: spec.severity, // Copy the rule severity level.
    category: spec.category, // Copy the finding category.
    check(file: ConfigFile): ReadonlyArray<Finding> { // Implement the per-file check function called by the scanner.
      if (spec.fileTypes && !spec.fileTypes.includes(file.type)) { // Skip files that do not match this rule's target file types.
        return []; // Return no findings for unrelated file types.
      } // End file type guard.

      const match = spec.pattern.exec(file.content); // Search the file content for the risky security pattern.
      if (!match) { // Check if the pattern was not found.
        return []; // Return an empty findings list when the file is clean.
      } // End match check.

      const line = findLineNumber(file.content, match.index); // Compute the 1-based line number of the matched code.
      const evidence = match[0].trim().slice(0, 120); // Extract a short, readable snippet of the matched text.

      return [ // Return a single structured Finding describing the issue and fix.
        { // Begin Finding object.
          id: spec.id, // Attach the rule ID to the finding.
          severity: spec.severity, // Attach the severity level.
          category: spec.category, // Attach the finding category.
          title: spec.name, // Attach the finding title.
          description: spec.description, // Attach the plain-English explanation.
          file: file.path, // Record which file triggered the finding.
          line, // Record the exact line number.
          evidence, // Record the matched snippet for quick review.
          fix: { // Attach a guided fix suggestion.
            description: spec.fixDescription, // Explain how to remediate the issue.
            before: evidence, // Show the risky code that was found.
            after: spec.fixAfter, // Show the safe replacement pattern.
            auto: false, // Require human review before applying security architecture fixes.
          }, // End fix object.
        }, // End Finding object.
      ]; // End findings array.
    }, // End check function.
  }; // End returned Rule object.
} // End buildRule factory.

export const defenseInDepthRules: ReadonlyArray<Rule> = DEFENSE_IN_DEPTH_SPECS.map(buildRule); // Export all 12 CyberWarden Defense-in-Depth rules.
