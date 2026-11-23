import { describe, it, expect } from "vitest";
import { defenseInDepthRules } from "../../src/rules/defense-in-depth.js";
import type { ConfigFile } from "../../src/types.js";

function runAllDefenseRules(file: ConfigFile) {
  return defenseInDepthRules.flatMap((rule) => rule.check(file));
}

describe("CyberWarden Defense-in-Depth rules", () => {
  it("flags disabled database Row-Level Security (RLS)", () => {
    const findings = runAllDefenseRules({
      path: "hooks/migrate.sql",
      type: "hook-script",
      content: "ALTER TABLE invoices DISABLE ROW LEVEL SECURITY;",
    });
    expect(findings.some((f) => f.id === "defense-db-rls-disabled")).toBe(true);
  });

  it("flags SSRF targeting cloud metadata endpoint", () => {
    const findings = runAllDefenseRules({
      path: "hooks/fetch-preview.js",
      type: "hook-code",
      content: "const res = await fetch('http://169.254.169.254/latest/meta-data/');",
    });
    expect(findings.some((f) => f.id === "defense-ssrf-internal-url")).toBe(true);
  });

  it("flags unsafe file uploads using raw user filenames", () => {
    const findings = runAllDefenseRules({
      path: "hooks/upload.js",
      type: "hook-code",
      content: "fs.writeFileSync('/uploads/' + file.originalname, buffer);",
    });
    expect(findings.some((f) => f.id === "defense-unsafe-file-upload")).toBe(true);
  });

  it("flags non-atomic credit deduction race condition", () => {
    const findings = runAllDefenseRules({
      path: "hooks/credits.js",
      type: "hook-code",
      content: "user.credits -= cost; await saveUser(user);",
    });
    expect(findings.some((f) => f.id === "defense-race-condition-billing")).toBe(true);
  });

  it("flags unpinned wildcard dependency versions in package.json", () => {
    const findings = runAllDefenseRules({
      path: "package.json",
      type: "package-manager-config",
      content: '{ "dependencies": { "some-lib": "latest" } }',
    });
    expect(findings.some((f) => f.id === "defense-supply-chain-unpinned")).toBe(true);
  });

  it("flags logging sensitive credentials or disabling TLS", () => {
    const findings = runAllDefenseRules({
      path: "hooks/auth.js",
      type: "hook-code",
      content: "console.log('Login debug:', password); process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
    });
    expect(findings.some((f) => f.id === "defense-sensitive-audit-logging")).toBe(true);
  });

  it("flags unverified Paystack/Flutterwave/Meta webhooks", () => {
    const findings = runAllDefenseRules({
      path: "hooks/paystack-webhook.js",
      type: "hook-code",
      content: "const paystackConfig = { verifySignature: false };",
    });
    expect(findings.some((f) => f.id === "defense-regional-webhook-unverified")).toBe(true);
  });

  it("flags AI chatbot trusting client-sent chat history", () => {
    const findings = runAllDefenseRules({
      path: "hooks/chat.js",
      type: "hook-code",
      content: "const reply = await llm.chat({ messages: req.body.messages });",
    });
    expect(findings.some((f) => f.id === "defense-ai-chat-history-client-trust")).toBe(true);
  });

  it("flags unmasked BVN/NIN personal data logging (NDPA 2023)", () => {
    const findings = runAllDefenseRules({
      path: "hooks/kyc.js",
      type: "hook-code",
      content: "console.log('Verified user BVN:', user.bvn);",
    });
    expect(findings.some((f) => f.id === "defense-ndpa-pii-exposure")).toBe(true);
  });

  it("flags mass assignment passing raw req.body into DB write", () => {
    const findings = runAllDefenseRules({
      path: "hooks/profile.js",
      type: "hook-code",
      content: "await User.update(req.body);",
    });
    expect(findings.some((f) => f.id === "defense-mass-assignment")).toBe(true);
  });

  it("flags static file servers that expose dotfiles", () => {
    const findings = runAllDefenseRules({
      path: "hooks/server.js",
      type: "hook-code",
      content: "app.use(express.static('.', { dotfiles: 'allow' }));",
    });
    expect(findings.some((f) => f.id === "defense-default-admin-or-dotfiles")).toBe(true);
  });

  it("flags unsafe OTP retry limits or skipped current-password checks", () => {
    const findings = runAllDefenseRules({
      path: "hooks/otp.js",
      type: "hook-code",
      content: "const authCfg = { otpMaxAttempts: Infinity, skipCurrentPasswordCheck: true };",
    });
    expect(findings.some((f) => f.id === "defense-otp-or-password-change-unsafe")).toBe(true);
  });

  // Verify clean code has zero false positives.
  it("produces zero findings on clean, secure code", () => {
    const findings = runAllDefenseRules({
      path: "hooks/safe.js",
      type: "hook-code",
      content: "const safeId = crypto.randomUUID(); logger.info({ event: 'ok', safeId });",
    });
    // Confirm zero false positives.
    expect(findings).toHaveLength(0);
  });
});
