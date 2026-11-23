// Tests for the CyberWarden web-app rules.
// Every rule gets at least one "vulnerable" sample (must be flagged)
// and one "safe" sample (must NOT be flagged), to keep false alarms low.

// Test tools from vitest
import { describe, it, expect } from "vitest";
// The rules under test, plus the .gitignore matcher
import { webAppRules, isIgnoredByGitignore } from "../../src/rules/webapp.js";
// Type describing a scanned file
import type { ConfigFile, Finding } from "../../src/types.js";

// Make a fake scanned file (defaults to a server-side JS file)
function makeFile(content: string, path = "server.js", type: ConfigFile["type"] = "web-code"): ConfigFile {
  // Return the file object the rules expect
  return { path, type, content };
}

// Run one rule (by id) against a file, giving it the whole project's file list
function run(ruleId: string, file: ConfigFile, allFiles: ReadonlyArray<ConfigFile> = [file]): ReadonlyArray<Finding> {
  // Find the rule
  const rule = webAppRules.find((r) => r.id === ruleId);
  // Fail loudly if the id is wrong
  if (!rule) throw new Error(`No rule ${ruleId}`);
  // Run it
  return rule.check(file, allFiles);
}

// Build strings from parts so this test file itself doesn't contain things that look like real keys
const join = (...parts: string[]): string => parts.join("");

describe("webAppRules", () => {
  // Basic shape checks for the whole module
  it("registers 23 rules, all in the webapp category with unique ids", () => {
    // 23 rules in total
    expect(webAppRules).toHaveLength(23);
    // Every rule uses the webapp category
    expect(webAppRules.every((rule) => rule.category === "webapp")).toBe(true);
    // No two rules share an id
    expect(new Set(webAppRules.map((rule) => rule.id)).size).toBe(webAppRules.length);
  });

  // Webapp rules must never fire on AI config files
  it("ignores non-web files such as CLAUDE.md", () => {
    // A CLAUDE.md that happens to contain risky-looking code
    const file = makeFile("db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)", "CLAUDE.md", "claude-md");
    // No webapp rule reports anything on it
    expect(webAppRules.flatMap((rule) => rule.check(file, [file]))).toHaveLength(0);
  });

  describe("webapp-sql-injection", () => {
    it("flags a template-literal query using request data as critical", () => {
      // Vulnerable: request value inside the SQL text
      const findings = run("webapp-sql-injection", makeFile("const r = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);"));
      // One critical finding
      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe("critical");
    });

    it("flags string concatenation in SQL", () => {
      // Vulnerable: SQL glued together with +
      const findings = run("webapp-sql-injection", makeFile("db.query(\"SELECT * FROM users WHERE email = '\" + email + \"'\");"));
      // Flagged
      expect(findings.length).toBeGreaterThan(0);
    });

    it("does not flag parameterised queries or $${n} placeholders", () => {
      // Safe: parameters, and placeholder building with $${i}
      const code = [
        "await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);",
        "const sql = `UPDATE leads SET status = $${idx} WHERE id = $${idx + 1}`;",
        "const label = `Select a plan from the list, ${name}`;",
      ].join("\n");
      // Nothing flagged
      expect(run("webapp-sql-injection", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-xss-html-sink", () => {
    it("flags innerHTML built from an unescaped variable", () => {
      // Vulnerable: chat message dropped into HTML
      const findings = run("webapp-xss-html-sink", makeFile("box.innerHTML = `<p>${message.text}</p>`;", "public/chat.js"));
      // Flagged
      expect(findings).toHaveLength(1);
    });

    it("flags insertAdjacentHTML, document.write and dangerouslySetInnerHTML with variables", () => {
      // Three different vulnerable sinks
      const code = [
        "list.insertAdjacentHTML('beforeend', row);",
        "document.write(userBio);",
        "<div dangerouslySetInnerHTML={{ __html: post.body }} />",
      ].join("\n");
      // All three flagged
      expect(run("webapp-xss-html-sink", makeFile(code, "public/app.jsx"))).toHaveLength(3);
    });

    it("does not flag static HTML, escaped values, counts or textContent", () => {
      // Safe variations
      const code = [
        "el.innerHTML = '';",
        "el.innerHTML = '<b>Loading...</b>';",
        "el.innerHTML = `<p>${escapeHtml(message)}</p><span>${items.length}</span>`;",
        "el.innerHTML = `<li class=\"${active ? 'on' : ''}\">${DOMPurify.sanitize(html)}</li>`;",
        "el.textContent = message;",
      ].join("\n");
      // Nothing flagged
      expect(run("webapp-xss-html-sink", makeFile(code, "public/app.js"))).toHaveLength(0);
    });
  });

  describe("webapp-code-injection", () => {
    it("flags eval of request data as critical", () => {
      // Vulnerable eval
      const findings = run("webapp-code-injection", makeFile("const result = eval(req.body.formula);"));
      // Critical because it uses request data
      expect(findings[0]?.severity).toBe("critical");
    });

    it("flags child_process exec with a template literal", () => {
      // Vulnerable shell command
      const code = "const { exec } = require('child_process');\nexec(`convert ${req.query.file} out.png`);";
      // Flagged as critical
      expect(run("webapp-code-injection", makeFile(code))[0]?.severity).toBe("critical");
    });

    it("does not flag regex.exec, constant commands or JSON.parse", () => {
      // Safe variations
      const code = [
        "const { execSync } = require('child_process');",
        "execSync('git rev-parse HEAD');",
        "const m = /a(b)/.exec(text);",
        "const data = JSON.parse(body);",
      ].join("\n");
      // Nothing flagged
      expect(run("webapp-code-injection", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-secret-env-fallback", () => {
    it("flags a secret with a hardcoded fallback and masks the value", () => {
      // Vulnerable fallback
      const findings = run("webapp-secret-env-fallback", makeFile("const secret = process.env.SESSION_SECRET || 'super-secret-value-123';"));
      // Flagged, and the evidence doesn't show the full value
      expect(findings).toHaveLength(1);
      expect(findings[0].evidence).not.toContain("super-secret-value-123");
    });

    it("flags destructured defaults from process.env", () => {
      // Vulnerable destructuring default
      const findings = run("webapp-secret-env-fallback", makeFile("const { JWT_SECRET = 'changeme' } = process.env;"));
      // Flagged
      expect(findings).toHaveLength(1);
    });

    it("does not flag non-secret fallbacks or local dev database URLs", () => {
      // Safe variations
      const code = [
        "const port = process.env.PORT || '3000';",
        "const db = process.env.DATABASE_URL || 'postgres://localhost/dev';",
        "const pk = process.env.PAYSTACK_PUBLIC_KEY || 'pk_test_abc';",
        "const secret = process.env.SESSION_SECRET;",
      ].join("\n");
      // Nothing flagged
      expect(run("webapp-secret-env-fallback", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-frontend-secret", () => {
    it("flags a secret key in browser code", () => {
      // Vulnerable: secret in a public JS file
      const code = `const apiKey = "${join("abcd1234", "efgh5678", "ijkl9012")}";`;
      // Flagged as critical
      expect(run("webapp-frontend-secret", makeFile(code, "public/widget.js"))[0]?.severity).toBe("critical");
    });

    it("flags Flutterwave secret keys and secret-named public env vars", () => {
      // Vulnerable: Flutterwave key, and a VITE_ var named SECRET
      const code = [
        `const k = '${join("FLWSECK_TEST-", "abcdef1234567890abcdef1234567890", "-X")}';`,
        "fetch(u, { headers: { Authorization: import.meta.env.VITE_ADMIN_SECRET } });",
      ].join("\n");
      // Both flagged
      expect(run("webapp-frontend-secret", makeFile(code, "src/api.js"))).toHaveLength(2);
    });

    it("does not flag publishable keys, Firebase browser keys or server files", () => {
      // Safe in the browser: publishable and Firebase keys
      const browser = [
        `const publicKey = "${join("pk_live_", "abcdefghijklmnop1234")}";`,
        `const firebaseConfig = { apiKey: "${join("AIza", "SyAbcdefghijklmnop1234567")}" };`,
      ].join("\n");
      // Nothing flagged in the browser file
      expect(run("webapp-frontend-secret", makeFile(browser, "public/app.js"))).toHaveLength(0);
      // A server file reading from the environment is fine
      expect(run("webapp-frontend-secret", makeFile("const apiKey = process.env.OPENAI_API_KEY;", "server/ai.js"))).toHaveLength(0);
    });
  });

  describe("webapp-env-not-gitignored", () => {
    it("flags a .env file with no .gitignore", () => {
      // A .env file and no .gitignore
      const env = makeFile("", ".env", "web-env");
      // Flagged
      expect(run("webapp-env-not-gitignored", env, [env])).toHaveLength(1);
    });

    it("flags a .env file the .gitignore doesn't cover", () => {
      // .gitignore without .env
      const env = makeFile("", ".env", "web-env");
      const gitignore = makeFile("node_modules/\n", ".gitignore", "web-gitignore");
      // Flagged
      expect(run("webapp-env-not-gitignored", env, [env, gitignore])).toHaveLength(1);
    });

    it("does not flag a .env file covered by .gitignore", () => {
      // .gitignore covering .env and its variants
      const env = makeFile("", "server/.env.local", "web-env");
      const gitignore = makeFile("node_modules/\n.env*\n!.env.example\n", ".gitignore", "web-gitignore");
      // Not flagged
      expect(run("webapp-env-not-gitignored", env, [env, gitignore])).toHaveLength(0);
    });
  });

  describe("webapp-gitignore-missing-env", () => {
    it("flags a root .gitignore with no .env rule", () => {
      // .gitignore without .env
      const gitignore = makeFile("node_modules/\n", ".gitignore", "web-gitignore");
      // Flagged as low
      expect(run("webapp-gitignore-missing-env", gitignore)[0]?.severity).toBe("low");
    });

    it("does not flag a .gitignore that ignores .env", () => {
      // .gitignore with /.env
      const gitignore = makeFile("node_modules/\n/.env\n", ".gitignore", "web-gitignore");
      // Not flagged
      expect(run("webapp-gitignore-missing-env", gitignore)).toHaveLength(0);
    });
  });

  describe("webapp-secret-file-committed", () => {
    it("flags each secret file git is tracking", () => {
      // Git tracks two risky files
      const tracked = makeFile(".env\nkeys/server.pem", ".git/index", "web-git-tracked");
      // Two critical findings
      const findings = run("webapp-secret-file-committed", tracked);
      expect(findings).toHaveLength(2);
      expect(findings.every((f) => f.severity === "critical")).toBe(true);
    });

    it("does nothing for ordinary code files", () => {
      // A normal code file
      expect(run("webapp-secret-file-committed", makeFile(".env"))).toHaveLength(0);
    });
  });

  describe("webapp-weak-random-token", () => {
    it("flags Math.random() used for an OTP", () => {
      // Vulnerable OTP
      expect(run("webapp-weak-random-token", makeFile("const otp = Math.floor(Math.random() * 1000000);"))).toHaveLength(1);
    });

    it("downgrades to info when Math.random() is only a fallback after crypto.randomUUID", () => {
      // Fallback pattern seen in real widget code
      const code = "id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random().toString(16); // session";
      // Listed, but at info (no points lost)
      expect(run("webapp-weak-random-token", makeFile(code, "public/widget.js"))[0]?.severity).toBe("info");
    });

    it("does not flag Math.random() for animations or crypto for tokens", () => {
      // Safe variations
      const code = "const delay = Math.random() * 300;\nconst token = crypto.randomBytes(32).toString('hex');";
      // Nothing flagged
      expect(run("webapp-weak-random-token", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-weak-password-hash", () => {
    it("flags MD5 used for passwords", () => {
      // Vulnerable hash
      const code = "const hashed = crypto.createHash('md5').update(password).digest('hex');";
      // Flagged
      expect(run("webapp-weak-password-hash", makeFile(code))).toHaveLength(1);
    });

    it("flags plain-text password storage when no hashing library exists", () => {
      // Vulnerable: password saved as-is
      const code = "await User.create({ email: req.body.email, password: req.body.password });";
      // Flagged
      expect(run("webapp-weak-password-hash", makeFile(code))).toHaveLength(1);
    });

    it("does not flag MD5 for checksums or bcrypt-based projects", () => {
      // Safe: MD5 for an ETag, and bcrypt used for passwords
      const code = [
        "const etag = crypto.createHash('md5').update(fileBuffer).digest('hex');",
        "const hash = await bcrypt.hash(req.body.password, 12);",
        "await User.create({ email, password: req.body.password_hash_placeholder });",
      ].join("\n");
      // Nothing flagged
      expect(run("webapp-weak-password-hash", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-insecure-cookie", () => {
    it("flags res.cookie without security flags", () => {
      // Vulnerable cookie
      const findings = run("webapp-insecure-cookie", makeFile("res.cookie('session', token);"));
      // Flagged and lists all three missing flags
      expect(findings).toHaveLength(1);
      expect(findings[0].title).toContain("httpOnly");
    });

    it("flags tokens written to document.cookie", () => {
      // Vulnerable browser cookie
      expect(run("webapp-insecure-cookie", makeFile("document.cookie = `token=${jwt}`;", "public/app.js"))).toHaveLength(1);
    });

    it("does not flag cookies with all flags or options passed as a variable", () => {
      // Safe variations
      const code = [
        "res.cookie('session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' });",
        "res.cookie('session', token, cookieOptions);",
      ].join("\n");
      // Nothing flagged
      expect(run("webapp-insecure-cookie", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-cors-wildcard", () => {
    it("flags wildcard CORS and origin reflection", () => {
      // Two vulnerable patterns
      const code = "app.use(cors());\nres.setHeader('Access-Control-Allow-Origin', req.headers.origin);";
      // Both flagged; reflection is high
      const findings = run("webapp-cors-wildcard", makeFile(code));
      expect(findings).toHaveLength(2);
      expect(findings.some((f) => f.severity === "high")).toBe(true);
    });

    it("downgrades * to info on a route clearly named public", () => {
      // An intentionally public widget API
      const code = "app.use('/api/public', (req, res, next) => {\n  res.set('Access-Control-Allow-Origin', '*');\n  next();\n});";
      // Listed at info, not medium
      expect(run("webapp-cors-wildcard", makeFile(code))[0]?.severity).toBe("info");
    });

    it("does not flag CORS limited to your own domain", () => {
      // Safe CORS
      const code = "app.use(cors({ origin: ['https://orikella.com'], credentials: true }));";
      // Nothing flagged
      expect(run("webapp-cors-wildcard", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-csp-unsafe", () => {
    it("flags script-src with unsafe-inline (header and helmet styles)", () => {
      // Two vulnerable CSPs
      const code = [
        "res.setHeader('Content-Security-Policy', \"default-src 'self'; script-src 'self' 'unsafe-inline'\");",
        "helmet({ contentSecurityPolicy: { directives: { scriptSrc: [\"'self'\", \"'unsafe-eval'\"] } } });",
      ].join("\n");
      // Both flagged
      expect(run("webapp-csp-unsafe", makeFile(code))).toHaveLength(2);
    });

    it("does not flag unsafe-inline for styles only", () => {
      // Safe enough: inline styles are allowed, scripts are not
      const code = "res.setHeader('Content-Security-Policy', \"script-src 'self'; style-src 'self' 'unsafe-inline'\");";
      // Nothing flagged
      expect(run("webapp-csp-unsafe", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-missing-security-headers", () => {
    it("flags an Express app with no helmet anywhere", () => {
      // Vulnerable Express app
      expect(run("webapp-missing-security-headers", makeFile("const app = express();\napp.listen(3000);"))).toHaveLength(1);
    });

    it("does not flag when any project file uses helmet", () => {
      // App file plus a separate file that adds helmet
      const app = makeFile("const app = express();", "server.js");
      const security = makeFile("app.use(helmet());", "security.js");
      // Not flagged
      expect(run("webapp-missing-security-headers", app, [app, security])).toHaveLength(0);
    });
  });

  describe("webapp-large-body-limit", () => {
    it("flags a 50mb JSON limit", () => {
      // Vulnerable limit
      expect(run("webapp-large-body-limit", makeFile("app.use(express.json({ limit: '50mb' }));"))).toHaveLength(1);
    });

    it("does not flag the default or a small limit", () => {
      // Safe variations
      const code = "app.use(express.json());\napp.use(express.urlencoded({ extended: true, limit: '1mb' }));";
      // Nothing flagged
      expect(run("webapp-large-body-limit", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-no-rate-limit", () => {
    it("flags login and chat routes when the project has no limiter", () => {
      // Vulnerable routes
      const code = "app.post('/api/login', login);\nrouter.post('/api/chat', chat);";
      // Both flagged
      expect(run("webapp-no-rate-limit", makeFile(code))).toHaveLength(2);
    });

    it("does not flag when the project uses express-rate-limit", () => {
      // Routes plus a limiter file
      const routes = makeFile("app.post('/api/login', login);", "routes.js");
      const limiter = makeFile("const rateLimit = require('express-rate-limit');", "limits.js");
      // Not flagged
      expect(run("webapp-no-rate-limit", routes, [routes, limiter])).toHaveLength(0);
    });
  });

  describe("webapp-webhook-no-signature", () => {
    it("flags a Paystack webhook that never checks a signature", () => {
      // Vulnerable webhook
      const code = "app.post('/webhook/paystack', async (req, res) => { await markPaid(req.body.data.reference); res.sendStatus(200); });";
      // Flagged
      expect(run("webapp-webhook-no-signature", makeFile(code))).toHaveLength(1);
    });

    it("does not flag a webhook that verifies the HMAC signature", () => {
      // Safe webhook
      const code = [
        "app.post('/webhook/paystack', (req, res) => {",
        "  const hash = crypto.createHmac('sha512', secret).update(req.rawBody).digest('hex');",
        "  if (hash !== req.headers['x-paystack-signature']) return res.sendStatus(401);",
        "});",
      ].join("\n");
      // Not flagged
      expect(run("webapp-webhook-no-signature", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-open-redirect", () => {
    it("flags res.redirect(req.query.next) and location.href from params", () => {
      // Two vulnerable redirects
      const server = run("webapp-open-redirect", makeFile("res.redirect(req.query.next);"));
      const browser = run("webapp-open-redirect", makeFile("window.location.href = params.get('next');", "public/login.js"));
      // Both flagged
      expect(server).toHaveLength(1);
      expect(browser).toHaveLength(1);
    });

    it("does not flag fixed or validated redirects", () => {
      // Safe variations
      const code = "res.redirect('/dashboard');\nif (next.startsWith('/')) res.redirect(req.query.next);";
      // Nothing flagged
      expect(run("webapp-open-redirect", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-path-traversal", () => {
    it("flags sendFile with a request parameter", () => {
      // Vulnerable file read
      const code = "res.sendFile(path.join(__dirname, 'uploads', req.params.name));";
      // Flagged
      expect(run("webapp-path-traversal", makeFile(code))).toHaveLength(1);
    });

    it("does not flag basename() or sendFile with root", () => {
      // Safe variations
      const code = [
        "res.sendFile(path.basename(req.params.name), { root: uploadsDir });",
        "fs.readFile(path.join(dir, path.basename(req.query.file)), cb);",
      ].join("\n");
      // Nothing flagged
      expect(run("webapp-path-traversal", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-error-leak", () => {
    it("flags stack traces and raw error objects in responses", () => {
      // Two vulnerable responses
      const code = "res.status(500).send(err.stack);\nres.status(500).json({ error: err });";
      // Both flagged
      expect(run("webapp-error-leak", makeFile(code))).toHaveLength(2);
    });

    it("does not flag generic messages or dev-only branches", () => {
      // Safe variations
      const code = [
        "res.status(500).json({ error: 'Something went wrong' });",
        "if (process.env.NODE_ENV === 'development') res.status(500).send(err.stack);",
      ].join("\n");
      // Nothing flagged
      expect(run("webapp-error-leak", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-payment-trust-client", () => {
    it("flags payment status from req.body and amounts from the browser", () => {
      // Two vulnerable payment patterns
      const code = [
        "// paystack checkout",
        "if (req.body.status === 'success') await markOrderPaid(req.body.orderId);",
        "await paystack.transaction.initialize({ email, amount: req.body.amount });",
      ].join("\n");
      // Both flagged
      expect(run("webapp-payment-trust-client", makeFile(code))).toHaveLength(2);
    });

    it("does not flag server-verified payments with server-side prices", () => {
      // Safe payment flow
      const code = [
        "// paystack checkout",
        "const tx = await axios.get(`https://api.paystack.co/transaction/verify/${ref}`);",
        "if (req.body.status === 'success' && tx.data.data.status === 'success') await markOrderPaid(id);",
        "await paystack.transaction.initialize({ email, amount: product.priceKobo });",
      ].join("\n");
      // Nothing flagged
      expect(run("webapp-payment-trust-client", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-llm-prompt-injection", () => {
    it("flags the visitor's message inside the system prompt", () => {
      // Vulnerable AI call
      const code = [
        "import Anthropic from '@anthropic-ai/sdk';",
        "const reply = await client.messages.create({",
        "  model, max_tokens: 300,",
        "  system: `You are Orikella's sales assistant. The customer said: ${message}`,",
        "  messages: [],",
        "});",
      ].join("\n");
      // Flagged
      expect(run("webapp-llm-prompt-injection", makeFile(code))).toHaveLength(1);
    });

    it("does not flag a fixed system prompt with business data and the message as a user turn", () => {
      // Safe AI call
      const code = [
        "import Anthropic from '@anthropic-ai/sdk';",
        "const reply = await client.messages.create({",
        "  system: `You are the assistant for ${business.name}. Prices: ${business.priceList}`,",
        "  messages: [{ role: 'user', content: message }],",
        "});",
      ].join("\n");
      // Not flagged
      expect(run("webapp-llm-prompt-injection", makeFile(code))).toHaveLength(0);
    });

    it("ignores files that don't call an AI model", () => {
      // Looks similar but isn't AI code
      const code = "const cfg = { system: `Hello ${message}` };";
      // Not flagged
      expect(run("webapp-llm-prompt-injection", makeFile(code))).toHaveLength(0);
    });
  });

  describe("webapp-llm-risky-tools", () => {
    it("flags a send/refund tool with no approval step", () => {
      // Vulnerable tool list
      const code = [
        "import OpenAI from 'openai';",
        "const tools = [{ type: 'function', function: { name: 'send_whatsapp_message', description: 'Send', parameters: { type: 'object' } } },",
        "  { name: 'issue_refund', description: 'Refund', input_schema: { type: 'object' } }];",
        "await openai.chat.completions.create({ model, tools, messages });",
      ].join("\n");
      // Both tools flagged
      expect(run("webapp-llm-risky-tools", makeFile(code))).toHaveLength(2);
    });

    it("does not flag read-only tools or files with an approval step", () => {
      // Read-only tool: safe
      const readOnly = [
        "import OpenAI from 'openai';",
        "const tools = [{ name: 'lookup_prices', description: 'Read', parameters: { type: 'object' } }];",
        "await openai.chat.completions.create({ model, tools, messages });",
      ].join("\n");
      // Risky tool, but routed through approval: safe
      const approved = readOnly.replace("lookup_prices", "send_email") + "\nqueueForApproval(call);";
      // Neither flagged
      expect(run("webapp-llm-risky-tools", makeFile(readOnly))).toHaveLength(0);
      expect(run("webapp-llm-risky-tools", makeFile(approved))).toHaveLength(0);
    });
  });

  describe("comments never count as protection", () => {
    it("still flags a webhook whose only 'signature' mention is a comment", () => {
      // The word signature appears only in a comment
      const code = "// TODO: check the x-paystack-signature header\napp.post('/webhook/paystack', (req, res) => res.sendStatus(200));";
      // Flagged
      expect(run("webapp-webhook-no-signature", makeFile(code))).toHaveLength(1);
    });

    it("still flags missing helmet when helmet is only mentioned in a comment", () => {
      // helmet appears only in a comment
      const code = "// we should add helmet later\nconst app = express();";
      // Flagged
      expect(run("webapp-missing-security-headers", makeFile(code))).toHaveLength(1);
    });

    it("does not treat a /confirm route or an approval comment as a human approval step", () => {
      // A risky tool, a route named confirm, and a comment saying "approval"
      const code = [
        "const Anthropic = require('@anthropic-ai/sdk');",
        "app.post('/api/orders/confirm', h); // no human approval yet",
        "const tools = [{ name: 'issue_refund', input_schema: { type: 'object' } }];",
        "await ai.messages.create({ tools });",
      ].join("\n");
      // Flagged
      expect(run("webapp-llm-risky-tools", makeFile(code))).toHaveLength(1);
    });
  });

  describe("isIgnoredByGitignore", () => {
    it("understands the common .env patterns and ! exceptions", () => {
      // Plain name
      expect(isIgnoredByGitignore(".env", ".env")).toBe(true);
      // Wildcard
      expect(isIgnoredByGitignore(".env.production", ".env*")).toBe(true);
      // Exception wins when it comes later
      expect(isIgnoredByGitignore(".env.example", ".env*\n!.env.example")).toBe(false);
      // Nested file matched by name
      expect(isIgnoredByGitignore("server/.env", "**/.env")).toBe(true);
      // Unrelated rules
      expect(isIgnoredByGitignore(".env", "node_modules/\n# .env")).toBe(false);
    });
  });
});
