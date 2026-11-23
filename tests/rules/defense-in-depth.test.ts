import { describe, it, expect } from "vitest"; // Import Vitest testing utilities.
import { defenseInDepthRules } from "../../src/rules/defense-in-depth.js"; // Import all 13 CipherWarden Defense-in-Depth rules.
import type { ConfigFile } from "../../src/types.js"; // Import the ConfigFile type used by rules.

function runAllDefenseRules(file: ConfigFile) { // Helper function to run all 13 rules on one test file.
  return defenseInDepthRules.flatMap((rule) => rule.check(file)); // Collect every finding returned across all 13 rules.
} // End runAllDefenseRules helper.

describe("CipherWarden defenseInDepthRules (13 rules)", () => { // Group all unit tests for our 13 security rules.
  it("flags disabled database Row-Level Security (RLS)", () => { // Test Rule 1: Database RLS protection.
    const findings = runAllDefenseRules({ // Run rules on a sample file disabling RLS.
      path: "hooks/migrate.sql", // Sample file path.
      type: "hook-script", // Sample file type.
      content: "ALTER TABLE invoices DISABLE ROW LEVEL SECURITY;", // Risky SQL disabling RLS.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-db-rls-disabled")).toBe(true); // Verify Rule 1 fires.
  }); // End Rule 1 test.

  it("flags SSRF targeting cloud metadata endpoint", () => { // Test Rule 2: SSRF protection.
    const findings = runAllDefenseRules({ // Run rules on a sample file fetching AWS/GCP metadata.
      path: "hooks/fetch-preview.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "const res = await fetch('http://169.254.169.254/latest/meta-data/');", // Risky SSRF call.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-ssrf-internal-url")).toBe(true); // Verify Rule 2 fires.
  }); // End Rule 2 test.

  it("flags unsafe file uploads using raw user filenames", () => { // Test Rule 3: Safe file uploads.
    const findings = runAllDefenseRules({ // Run rules on a sample upload handler.
      path: "hooks/upload.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "fs.writeFileSync('/uploads/' + file.originalname, buffer);", // Risky raw filename write.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-unsafe-file-upload")).toBe(true); // Verify Rule 3 fires.
  }); // End Rule 3 test.

  it("flags client-trusted pricing in payment code", () => { // Test Rule 4: Server-side pricing & webhooks.
    const findings = runAllDefenseRules({ // Run rules on a sample checkout handler.
      path: "hooks/checkout.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "const total = req.body.price; if (req.body.isPaid) unlockPro();", // Risky client-trusted price.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-payment-webhook-unverified")).toBe(true); // Verify Rule 4 fires.
  }); // End Rule 4 test.

  it("flags non-atomic credit deduction race condition", () => { // Test Rule 5: Double-spend race condition.
    const findings = runAllDefenseRules({ // Run rules on a sample credit deduction script.
      path: "hooks/credits.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "user.credits -= cost; await saveUser(user);", // Risky non-atomic deduction.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-race-condition-billing")).toBe(true); // Verify Rule 5 fires.
  }); // End Rule 5 test.

  it("flags unpinned wildcard dependency versions in package.json", () => { // Test Rule 6: Supply-chain pinning.
    const findings = runAllDefenseRules({ // Run rules on a sample package.json.
      path: "package.json", // Sample package config path.
      type: "package-manager-config", // Must be package-manager-config type.
      content: '{ "dependencies": { "some-lib": "latest" } }', // Risky unpinned "latest" version.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-supply-chain-unpinned")).toBe(true); // Verify Rule 6 fires.
  }); // End Rule 6 test.

  it("flags logging sensitive credentials or disabling TLS", () => { // Test Rule 7: Audit logging & TLS.
    const findings = runAllDefenseRules({ // Run rules on a sample auth helper.
      path: "hooks/auth.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "console.log('Login debug:', password); process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';", // Risky log + disabled TLS.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-sensitive-audit-logging")).toBe(true); // Verify Rule 7 fires.
  }); // End Rule 7 test.

  it("flags weak CSP allowing 'unsafe-inline' scripts", () => { // Test Rule 8: CSP unsafe-inline check.
    const findings = runAllDefenseRules({ // Run rules on a sample security header.
      path: "hooks/headers.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "res.setHeader('Content-Security-Policy', \"script-src 'self' 'unsafe-inline'\");", // Risky CSP header.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-csp-unsafe-inline")).toBe(true); // Verify Rule 8 fires.
  }); // End Rule 8 test.

  it("flags unverified Paystack/Flutterwave/Meta webhooks", () => { // Test Rule 9: Regional webhook verification.
    const findings = runAllDefenseRules({ // Run rules on a sample Paystack webhook.
      path: "hooks/paystack-webhook.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "const paystackConfig = { verifySignature: false };", // Risky skipped signature check.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-regional-webhook-unverified")).toBe(true); // Verify Rule 9 fires.
  }); // End Rule 9 test.

  it("flags AI chatbot trusting client-sent chat history", () => { // Test Rule 10: Client-controlled AI chat history.
    const findings = runAllDefenseRules({ // Run rules on a sample chatbot route.
      path: "hooks/chat.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "const reply = await llm.chat({ messages: req.body.messages });", // Risky client-sent history.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-ai-chat-history-client-trust")).toBe(true); // Verify Rule 10 fires.
  }); // End Rule 10 test.

  it("flags insecure session cookies with httpOnly: false", () => { // Test Rule 11: Session cookie flags.
    const findings = runAllDefenseRules({ // Run rules on a sample cookie setup.
      path: "hooks/session.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "res.cookie('sid', token, { httpOnly: false, secure: false });", // Risky cookie options.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-insecure-session-cookie")).toBe(true); // Verify Rule 11 fires.
  }); // End Rule 11 test.

  it("flags weak MD5/SHA1/SHA256 password hashing", () => { // Test Rule 12: Weak password hashing.
    const findings = runAllDefenseRules({ // Run rules on a sample login file.
      path: "hooks/login.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "const hashed = crypto.createHash('md5').update(password).digest('hex');", // Risky MD5 password hash.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-weak-password-hash")).toBe(true); // Verify Rule 12 fires.
  }); // End Rule 12 test.

  it("flags unmasked BVN/NIN personal data logging (NDPA 2023)", () => { // Test Rule 13: NDPA 2023 PII logging.
    const findings = runAllDefenseRules({ // Run rules on a sample KYC script.
      path: "hooks/kyc.js", // Sample file path.
      type: "hook-code", // Sample file type.
      content: "console.log('Verified user BVN:', user.bvn);", // Risky unmasked BVN log.
    }); // End rule run.
    expect(findings.some((f) => f.id === "defense-ndpa-pii-exposure")).toBe(true); // Verify Rule 13 fires.
  }); // End Rule 13 test.

  it("produces zero findings on clean, secure code", () => { // Verify clean code has zero false positives.
    const findings = runAllDefenseRules({ // Run rules on a safe example.
      path: "hooks/safe.js", // Safe file path.
      type: "hook-code", // Safe file type.
      content: "const safeId = crypto.randomUUID(); logger.info({ event: 'ok', safeId });", // Clean secure code.
    }); // End rule run.
    expect(findings).toHaveLength(0); // Confirm zero false positives.
  }); // End clean code test.
}); // End CipherWarden defenseInDepthRules test suite.
