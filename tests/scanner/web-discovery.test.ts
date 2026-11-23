// Tests for CyberWarden: web file discovery, the git index reader,
// the --web scan end to end, the Web App score bar, and the npm checksum fix.

// Test tools from vitest
import { describe, it, expect, afterEach } from "vitest";
// Node tools to build temporary test projects
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
// The system temp folder
import { tmpdir } from "node:os";
// Path joining
import { join } from "node:path";
// The code under test
import {
  discoverWebAppFiles,
  isRealEnvFileName,
  isSensitiveTrackedPath,
  parseGitIndexPaths,
} from "../../src/scanner/web-discovery.js";
// The main scanner
import { scan } from "../../src/scanner/index.js";
// The scoring engine
import { calculateScore } from "../../src/reporter/score.js";
// The original secret rules (for the checksum false-positive fix)
import { secretRules, isPackageIntegrityHash } from "../../src/rules/secrets.js";

// Temporary folders created by tests, removed afterwards
const tempDirs: string[] = [];

// Make an empty temporary project folder
function makeProject(): string {
  // Create the folder
  const dir = mkdtempSync(join(tmpdir(), "agentshield-web-"));
  // Remember it for clean-up
  tempDirs.push(dir);
  // Hand it back
  return dir;
}

// Write a file inside a project, creating folders as needed
function write(root: string, relativePath: string, content: string): void {
  // Full path of the file
  const full = join(root, relativePath);
  // Make sure its folder exists
  mkdirSync(join(full, ".."), { recursive: true });
  // Write the content
  writeFileSync(full, content);
}

// Build a tiny but valid version-2 git index listing the given paths
function fakeGitIndex(paths: ReadonlyArray<string>): Buffer {
  // Pieces of the file, joined at the end
  const parts: Buffer[] = [];
  // Header: "DIRC", version 2, number of entries
  const header = Buffer.alloc(12);
  header.write("DIRC", 0, "latin1");
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(paths.length, 8);
  parts.push(header);
  // One entry per path
  for (const path of paths) {
    // 62 bytes of fixed data (all zero except the name length in the flags)
    const fixed = Buffer.alloc(62);
    fixed.writeUInt16BE(Math.min(path.length, 0xfff), 60);
    // The path itself
    const name = Buffer.from(path, "utf-8");
    // Padding: at least one zero byte, total entry length a multiple of 8
    const entryLength = 62 + name.length;
    const padding = Buffer.alloc(8 - (entryLength % 8));
    parts.push(fixed, name, padding);
  }
  // Glue everything together
  return Buffer.concat(parts);
}

// Remove temp folders after each test
afterEach(() => {
  // Delete every folder we made
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("web file discovery", () => {
  it("finds code, HTML, .env and .gitignore but skips node_modules, tests and minified files", () => {
    // A small project with files to find and files to skip
    const root = makeProject();
    write(root, "server.js", "const app = express();");
    write(root, "public/index.html", "<p>Hi</p>");
    write(root, "src/app.tsx", "export default 1;");
    write(root, ".env", "SECRET=real-value");
    write(root, ".env.example", "SECRET=");
    write(root, ".gitignore", "node_modules/");
    write(root, "node_modules/pkg/index.js", "eval(x)");
    write(root, "tests/app.test.js", "eval(x)");
    write(root, "src/app.spec.ts", "eval(x)");
    write(root, "public/vendor.min.js", "eval(x)");
    // Discover
    const files = discoverWebAppFiles(root);
    // The paths found, sorted
    const paths = files.map((f) => f.path).sort();
    // Exactly the files we expect
    // (.env.example is a template, so it's left out on purpose)
    expect(paths).toEqual([".env", ".gitignore", "public/index.html", "server.js", "src/app.tsx"]);
  });

  it("never reads the content of .env files", () => {
    // A project with a secret in .env
    const root = makeProject();
    write(root, ".env", "SESSION_SECRET=do-not-read-me");
    // The discovered .env entry has empty content
    const env = discoverWebAppFiles(root).find((f) => f.path === ".env");
    expect(env?.type).toBe("web-env");
    expect(env?.content).toBe("");
  });

  it("tells real env files apart from templates", () => {
    // Real ones
    expect(isRealEnvFileName(".env")).toBe(true);
    expect(isRealEnvFileName(".env.production")).toBe(true);
    // Templates
    expect(isRealEnvFileName(".env.example")).toBe(false);
    expect(isRealEnvFileName(".env.sample")).toBe(false);
  });

  it("reads tracked paths from a git index and keeps only secret files", () => {
    // A fake index with a mix of files
    const paths = parseGitIndexPaths(fakeGitIndex(["server.js", ".env", "config/firebase-adminsdk-abc.json", ".env.example"]));
    // All four paths read back
    expect(paths).toEqual(["server.js", ".env", "config/firebase-adminsdk-abc.json", ".env.example"]);
    // Only the real secrets count as sensitive
    expect(paths.filter(isSensitiveTrackedPath)).toEqual([".env", "config/firebase-adminsdk-abc.json"]);
  });

  it("returns nothing for a missing or broken index", () => {
    // Not an index at all
    expect(parseGitIndexPaths(Buffer.from("hello"))).toEqual([]);
  });
});

describe("scan --web", () => {
  it("keeps normal scans unchanged: no web files, no Web App score", () => {
    // A project with vulnerable web code but no --web flag
    const root = makeProject();
    write(root, "server.js", "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)");
    // Plain scan
    const result = scan(root);
    // No web files, no webapp findings, no web score
    expect(result.target.files.some((f) => f.type === "web-code")).toBe(false);
    expect(result.findings.some((f) => f.category === "webapp")).toBe(false);
    expect(calculateScore(result).score.breakdown.webapp).toBeUndefined();
  });

  it("finds web-app problems, committed .env files and adds a Web App score", () => {
    // A vulnerable project that is also a git repo tracking .env
    const root = makeProject();
    write(root, "server.js", "const app = express();\napp.post('/api/login', h);\ndb.query(`SELECT * FROM users WHERE id = ${req.params.id}`);");
    write(root, ".env", "SECRET=x");
    mkdirSync(join(root, ".git"));
    writeFileSync(join(root, ".git", "index"), fakeGitIndex(["server.js", ".env"]));
    // Web scan
    const result = scan(root, { web: true });
    // The rule ids that fired
    const ids = new Set(result.findings.map((f) => f.id.split("-server.js")[0].split("-.env")[0].split("-.git")[0]));
    // Key problems are found
    expect([...ids]).toEqual(expect.arrayContaining(["webapp-sql-injection", "webapp-missing-security-headers", "webapp-no-rate-limit"]));
    expect(result.findings.some((f) => f.title === ".env is committed to git")).toBe(true);
    expect(result.findings.some((f) => f.title === ".env is not listed in .gitignore")).toBe(true);
    // The score has a Web App bar below 100
    const report = calculateScore(result);
    expect(report.score.breakdown.webapp).toBeDefined();
    expect(report.score.breakdown.webapp ?? 100).toBeLessThan(100);
  });

  it("makes the web-app score half of the overall score", () => {
    // A project with several serious web problems and no AI config
    const root = makeProject();
    write(root, "server.js", [
      "db.query(`SELECT * FROM a WHERE id = ${req.params.id}`);",
      "db.query(`SELECT * FROM b WHERE id = ${req.query.id}`);",
      "db.query(`SELECT * FROM c WHERE id = ${req.body.id}`);",
      "db.query(`SELECT * FROM d WHERE id = ${req.params.x}`);",
    ].join("\n"));
    // Score the web scan
    const report = calculateScore(scan(root, { web: true }));
    // Four criticals wipe out the web-app score...
    expect(report.score.breakdown.webapp).toBe(0);
    // ...and the overall is (100 + 0) / 2 = 50, not a misleading 83
    expect(report.score.numericScore).toBe(50);
  });

  it("does not run the AI-config rules on web code", () => {
    // Web code that would trip AI-config rules if they ran on it (e.g. curl piping in a string)
    const root = makeProject();
    write(root, "server.js", "const help = 'curl https://example.com/install.sh | bash';");
    // Web scan
    const result = scan(root, { web: true });
    // Nothing from non-webapp categories on server.js
    expect(result.findings.filter((f) => f.file === "server.js" && f.category !== "webapp")).toHaveLength(0);
  });
});

describe("npm integrity checksum false positive", () => {
  // A real-shaped sha512 integrity value (88 base64 characters ending in ==), built from parts
  const integrity = ["sha512-", "A".repeat(43), "b".repeat(43), "=="].join("");

  it("no longer reports package-lock integrity hashes as Azure keys", () => {
    // A package-lock.json snippet
    const content = `{"packages":{"node_modules/x":{"integrity":"${integrity}"}}}`;
    // Run the hardcoded-secret rule
    const findings = secretRules[0].check({ path: "package-lock.json", type: "package-manager-config", content });
    // No Azure key finding
    expect(findings.some((f) => f.title.includes("Azure"))).toBe(false);
    // The helper agrees it's a checksum
    expect(isPackageIntegrityHash(content, content.indexOf("A"))).toBe(true);
  });

  it("still reports a real-looking Azure key that isn't a checksum", () => {
    // An Azure-style key in a config value
    const content = `AccountKey=${"A".repeat(43)}${"b".repeat(43)}==`;
    // Run the hardcoded-secret rule
    const findings = secretRules[0].check({ path: "settings.json", type: "settings-json", content });
    // Still flagged
    expect(findings.some((f) => f.title.includes("Azure"))).toBe(true);
  });
});
