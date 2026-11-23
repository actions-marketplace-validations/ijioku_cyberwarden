import { basename } from "node:path";
import type { Finding, Rule, SecurityReport } from "../types.js";
import { getBuiltinRules } from "../rules/index.js";
import { COMPLIANCE_FRAMEWORKS, mapFindingsToControls } from "../compliance/index.js";

/**
 * CyberWarden dashboard: one self-contained HTML page built from a scan report.
 *
 * It needs no internet and sends nothing anywhere (its Content-Security-Policy blocks all
 * network requests), so it is safe to email to a client or open offline. All scan data is
 * embedded as JSON and drawn with textContent, so text from scanned files can never run as code.
 */

// Options passed in by the CLI.
export interface DashboardOptions {
  // True when the scan used --web (so the web-app checks actually ran).
  readonly web?: boolean;
  // The CyberWarden version shown in the header.
  readonly version?: string;
  // Extra rules loaded from policies or plugins, listed alongside the built-in ones.
  readonly extraRules?: ReadonlyArray<Rule>;
}

// Which family a rule belongs to, shown as a filter in the dashboard.
type RuleGroup = "agent" | "defense" | "web";

// Work out a rule's family from its ID prefix.
function ruleGroup(id: string): RuleGroup {
  if (id.startsWith("webapp-")) return "web";
  if (id.startsWith("defense-")) return "defense";
  return "agent";
}

// Make JSON safe to place inside a <script> tag (no "</script>" breakouts, no line-separator tricks).
function safeJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

// Build the dashboard HTML for a report.
export function renderDashboard(report: SecurityReport, options: DashboardOptions = {}): string {
  // Every rule that could have run, with its family. Duplicate IDs (from extra rules) are listed once.
  const seen = new Set<string>();
  const rules = [...getBuiltinRules(), ...(options.extraRules ?? [])]
    .filter((rule) => (seen.has(rule.id) ? false : (seen.add(rule.id), true)))
    .map((rule) => ({
      id: rule.id,
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      category: rule.category,
      group: ruleGroup(rule.id),
    }));

  // Map findings to SOC 2, PCI DSS and ISO 27001 controls (guidance, not a certified crosswalk).
  const compliance = COMPLIANCE_FRAMEWORKS.map((framework) =>
    mapFindingsToControls(report.findings as ReadonlyArray<Finding>, framework)
  );

  // Everything the page needs, embedded as one JSON block.
  const data = {
    meta: {
      tool: "CyberWarden",
      version: options.version ?? "unknown",
      target: report.targetPath,
      project: basename(report.targetPath) || report.targetPath,
      timestamp: report.timestamp,
      web: options.web === true,
      // True when the scan found an AI coding setup (Claude Code, Cursor, MCP configs...) for the AI-setup checks to inspect.
      agentSetup: (report.harnessAdapters?.totalMatched ?? 0) > 0,
    },
    report: {
      findings: report.findings,
      score: report.score,
      summary: report.summary,
      defenses: report.defenses,
    },
    rules,
    compliance,
  };

  // Fill in the title first, then the data (so text inside the data can never be mistaken for a placeholder).
  return PAGE.replace("__TITLE__", () => escapeHtml(`CyberWarden: ${data.meta.project} (Grade ${report.score.grade})`)).replace(
    "__DATA__",
    () => safeJson(data)
  );
}

// Escape text for the page <title>.
function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

// The page itself. The script below is plain JavaScript (no template literals) so it fits inside this string.
const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>__TITLE__</title>
<style>
:root{color-scheme:light;--bg:#f6f7f9;--card:#fff;--text:#14161a;--muted:#5f6672;--line:#e3e6eb;--soft:#eef0f4;--accent:#4f46e5;--accent-soft:#eef0ff;
--crit:#c81e1e;--crit-bg:#fdecec;--high:#c2410c;--high-bg:#fff1e7;--med:#a16207;--med-bg:#fdf6dc;--low:#1d4ed8;--low-bg:#e8efff;--info:#4b5563;--info-bg:#eef0f3;--ok:#15803d;--ok-bg:#e7f6ec;--code:#f3f4f7}
:root[data-theme=dark]{color-scheme:dark;--bg:#0d0f13;--card:#161a20;--text:#e8eaee;--muted:#9aa2ae;--line:#272c35;--soft:#1d222a;--accent:#8b85ff;--accent-soft:#23234a;
--crit:#ff7676;--crit-bg:#3a1517;--high:#ff9a5c;--high-bg:#3a2113;--med:#f1c24b;--med-bg:#352c10;--low:#7ea6ff;--low-bg:#172340;--info:#aab2bd;--info-bg:#22272f;--ok:#5fd38a;--ok-bg:#12301e;--code:#1b2027}
@media (prefers-color-scheme:dark){:root[data-theme=system]{color-scheme:dark;--bg:#0d0f13;--card:#161a20;--text:#e8eaee;--muted:#9aa2ae;--line:#272c35;--soft:#1d222a;--accent:#8b85ff;--accent-soft:#23234a;
--crit:#ff7676;--crit-bg:#3a1517;--high:#ff9a5c;--high-bg:#3a2113;--med:#f1c24b;--med-bg:#352c10;--low:#7ea6ff;--low-bg:#172340;--info:#aab2bd;--info-bg:#22272f;--ok:#5fd38a;--ok-bg:#12301e;--code:#1b2027}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}
button,input,select{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px}
header.top{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.bar{display:flex;align-items:center;gap:12px;padding:12px 0;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:17px;margin-right:auto;min-width:0}
.brand small{display:block;font-weight:500;color:var(--muted);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:46vw}
.logo{width:30px;height:30px;border-radius:9px;background:var(--accent);display:grid;place-items:center;color:#fff;flex:none}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:999px;padding:3px;background:var(--card)}
.seg button{border:0;background:none;padding:5px 12px;border-radius:999px;cursor:pointer;font-size:13px;color:var(--muted)}
.seg button[aria-pressed=true]{background:var(--text);color:var(--bg)}
.btn{border:1px solid var(--line);background:var(--card);border-radius:10px;padding:7px 12px;cursor:pointer;font-size:13px}
.btn:hover{border-color:var(--accent)}
nav.tabs{display:flex;gap:4px;overflow-x:auto;padding-bottom:10px;scrollbar-width:none}
nav.tabs button{border:0;background:none;padding:8px 13px;border-radius:10px;cursor:pointer;white-space:nowrap;color:var(--muted);font-weight:600;font-size:14px}
nav.tabs button[aria-selected=true]{background:var(--accent-soft);color:var(--accent)}
nav.tabs .count{font-weight:500;opacity:.8;margin-left:4px}
main{padding:22px 0 60px}
h2{font-size:20px;margin:0 0 4px;letter-spacing:-.01em}
h3{font-size:15px;margin:0 0 10px}
.sub{color:var(--muted);margin:0 0 18px}
.grid{display:grid;gap:14px}
.g-hero{grid-template-columns:minmax(0,320px) minmax(0,1fr)}
.g-sev{grid-template-columns:repeat(5,minmax(0,1fr))}
.g-2{grid-template-columns:repeat(2,minmax(0,1fr))}
.g-3{grid-template-columns:repeat(3,minmax(0,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;min-width:0}
.grade{display:flex;align-items:center;gap:18px}
.ring{width:112px;height:112px;border-radius:50%;display:grid;place-items:center;flex:none}
.ring b{font-size:46px;line-height:1}
.ring span{display:block;font-size:12px;color:var(--muted);text-align:center}
.verdict{font-size:17px;font-weight:600;margin:0 0 6px}
.sevcard{border:1px solid var(--line);border-radius:14px;padding:12px 14px;background:var(--card);cursor:pointer;text-align:left}
.sevcard:hover{border-color:var(--accent)}
.sevcard b{display:block;font-size:26px;line-height:1.1}
.sevcard span{font-size:13px;color:var(--muted)}
.badge{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:700;padding:2px 9px;border-radius:999px;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap}
.dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.critical{color:var(--crit);background:var(--crit-bg)}.high{color:var(--high);background:var(--high-bg)}.medium{color:var(--med);background:var(--med-bg)}
.low{color:var(--low);background:var(--low-bg)}.info{color:var(--info);background:var(--info-bg)}.passed{color:var(--ok);background:var(--ok-bg)}.na,.notrun{color:var(--muted);background:var(--soft)}
.tag{display:inline-block;font-size:12px;padding:2px 8px;border-radius:7px;background:var(--soft);color:var(--muted);margin:0 6px 6px 0;white-space:nowrap}
.meter{height:8px;border-radius:99px;background:var(--soft);overflow:hidden}
.meter i{display:block;height:100%;border-radius:99px}
.row{display:flex;align-items:center;gap:10px}
.between{justify-content:space-between}
.list{display:grid;gap:10px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:14px}
.toolbar input[type=search]{flex:1 1 220px;min-width:0;padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card)}
.toolbar select{padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:var(--card);max-width:100%}
.chip{border:1px solid var(--line);background:var(--card);border-radius:999px;padding:5px 11px;cursor:pointer;font-size:13px}
.chip[aria-pressed=true]{border-color:currentColor}
details.finding{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:12px}
details.finding[open]{box-shadow:0 2px 14px rgba(0,0,0,.06)}
details.finding>summary{list-style:none;cursor:pointer;padding:13px 15px;display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:12px;align-items:center}
details.finding>summary::-webkit-details-marker{display:none}
.ftitle{font-weight:600;overflow-wrap:anywhere}
.floc{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--muted);overflow-wrap:anywhere}
.chev{color:var(--muted);transition:transform .15s}
details[open]>summary .chev{transform:rotate(90deg)}
.fbody{padding:0 15px 15px;border-top:1px solid var(--line)}
.fbody h4{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:16px 0 6px}
pre{margin:0;background:var(--code);border:1px solid var(--line);border-radius:10px;padding:10px 12px;overflow-x:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
.fix{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.fix .lbl{font-size:12px;font-weight:700;margin-bottom:4px}
.bad{color:var(--crit)}.good{color:var(--ok)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
td.mono,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;overflow-wrap:anywhere}
.tablewrap{overflow-x:auto}
.empty{text-align:center;padding:40px 16px;color:var(--muted)}
.check{display:flex;gap:12px;align-items:flex-start;padding:12px 14px;border:1px solid var(--line);border-radius:12px;background:var(--card)}
.check input{width:18px;height:18px;margin-top:3px;accent-color:var(--accent);flex:none}
.check.done .ftitle{text-decoration:line-through;color:var(--muted)}
.note{border:1px dashed var(--line);border-radius:12px;padding:12px 14px;color:var(--muted);font-size:14px;background:var(--card)}
.linkish{border:0;background:none;padding:0;color:var(--accent);cursor:pointer;text-decoration:underline;font-size:inherit}
dl.kv{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 14px;margin:0;font-size:14px}
dl.kv dt{color:var(--muted)}dl.kv dd{margin:0;overflow-wrap:anywhere}
.hide{display:none!important}
.toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:var(--text);color:var(--bg);padding:8px 14px;border-radius:10px;font-size:14px;opacity:0;transition:opacity .2s;pointer-events:none}
.toast.show{opacity:1}
@media (max-width:860px){.g-hero,.g-2,.g-3{grid-template-columns:minmax(0,1fr)}.g-sev{grid-template-columns:repeat(3,minmax(0,1fr))}.fix{grid-template-columns:minmax(0,1fr)}}
@media (max-width:640px){table.stack,table.stack tbody,table.stack tr,table.stack td{display:block;width:100%}table.stack thead{display:none}table.stack tr{padding:12px 4px;border-bottom:1px solid var(--line)}table.stack td{border:0;padding:3px 0}table.stack td.mono{color:var(--muted)}.bar{gap:8px}.brand{flex:1 1 100%}.brand small{max-width:80vw}.btn{padding:6px 10px}}
@media (max-width:480px){.g-sev{grid-template-columns:repeat(2,minmax(0,1fr))}.ring{width:92px;height:92px}.ring b{font-size:38px}details.finding>summary{grid-template-columns:minmax(0,1fr) auto}details.finding>summary .badge{grid-column:1/-1;justify-self:start}}
@media print{header.top{position:static}nav.tabs,.toolbar,.noprint{display:none!important}section.panel{display:block!important;page-break-after:always}details.finding{break-inside:avoid}body{background:#fff}}
</style>
</head>
<body>
<header class="top"><div class="wrap">
  <div class="bar">
    <div class="brand"><div class="logo" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5-3.5 9-8 10-4.5-1-8-5-8-10V6l8-4z"/><path d="M9 12l2 2 4-4"/></svg></div>
      <div>CyberWarden <small id="projline"></small></div></div>
    <div class="seg noprint" role="group" aria-label="Theme"><button data-theme="system">System</button><button data-theme="dark">Dark</button><button data-theme="light">Light</button></div>
    <button class="btn noprint" id="printBtn" title="Print or save as PDF">Save PDF</button>
    <button class="btn noprint" id="jsonBtn" title="Download the raw report as JSON">JSON</button>
  </div>
  <nav class="tabs" role="tablist" aria-label="Dashboard sections"></nav>
</div></header>
<main class="wrap" id="main"></main>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<script type="application/json" id="cw-data">__DATA__</script>
<script>
(function () {
  "use strict";
  // ---------- Data and plain-English explanations ----------
  // The scan data embedded by CyberWarden.
  var DATA = JSON.parse(document.getElementById("cw-data").textContent);
  var R = DATA.report, META = DATA.meta;
  // Most to least urgent.
  var SEVS = ["critical", "high", "medium", "low", "info"];
  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  var SEV_MEANING = {
    critical: "Can be exploited right now and cause serious damage (stolen data, stolen money, full takeover). Fix before going live.",
    high: "A real weakness an attacker could use. Fix soon, ideally before the next deploy.",
    medium: "A weakness that needs other mistakes to be dangerous. Plan a fix.",
    low: "Minor hardening. Fix when convenient.",
    info: "Not a problem by itself: a note or good practice for awareness."
  };
  var GROUPS = { agent: "AI agent setup (AgentShield)", defense: "Defense-in-Depth (CyberWarden)", web: "Web app code (CyberWarden)" };
  var CAT = {
    secrets: ["Secrets", "API keys, passwords or tokens written where others can read them. Anyone who copies a key can spend your money or read your data."],
    permissions: ["Permissions", "What your AI coding tools are allowed to do. Too much freedom lets a tricked AI delete files or run dangerous commands."],
    hooks: ["Hooks", "Scripts that run automatically at set moments. A bad hook can quietly run harmful code or send data out every time it fires."],
    mcp: ["MCP servers", "Tools plugged into your AI (Slack, GitHub, databases). Each one can see and do what you allow, so they must be trusted and limited."],
    skills: ["Skills", "Instruction files your AI follows. A malicious skill can tell the AI to do harmful things."],
    agents: ["Agents", "AI helper definitions. Unrestricted agents can use powerful tools you didn't mean to give them."],
    injection: ["Prompt injection", "Hidden instructions inside content the AI reads (pages, files, tool results) that try to take control of it."],
    exposure: ["Exposure", "Sensitive files or data reachable by people who shouldn't see them, like a served .env file or a default password."],
    exfiltration: ["Data leaks", "Ways data could be sent out of your system, such as requests to unknown servers or tricking the server into fetching internal addresses (SSRF)."],
    misconfiguration: ["Misconfiguration", "Settings that weaken security: disabled database protection, unpinned packages, unsafe uploads, unverified webhooks."],
    webapp: ["Web app code", "Bugs in your site's own code: SQL injection, XSS, insecure cookies, missing rate limits, trusting prices from the browser and more."]
  };
  var GRADES = [["A", "90-100", "Strong. No serious problems found."], ["B", "75-89", "Good, with a few things to tidy up."], ["C", "60-74", "Fair. Real weaknesses to fix."], ["D", "40-59", "Poor. Serious problems: fix before deploying."], ["F", "0-39", "Failing. Critical problems: do not deploy."]];

  // ---------- Small helpers ----------
  // Create an element with attributes and children; text always goes in as text, never HTML.
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    (Array.isArray(kids) ? kids : kids === undefined ? [] : [kids]).forEach(function (c) {
      if (c === null || c === undefined || c === false) return;
      el.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
    });
    return el;
  }
  // A coloured severity badge.
  function sevBadge(s) { return h("span", { class: "badge " + s }, [h("span", { class: "dot" }), SEV_LABEL[s] || s]); }
  // Plural helper: "1 problem" / "3 problems".
  function plural(n, word) { return n + " " + word + (n === 1 ? "" : "s"); }
  // Colour for a 0-100 score.
  function scoreColor(n) { return n >= 90 ? "var(--ok)" : n >= 75 ? "var(--low)" : n >= 60 ? "var(--med)" : n >= 40 ? "var(--high)" : "var(--crit)"; }
  // Show a short message at the bottom of the screen.
  function toast(msg) { var t = document.getElementById("toast"); t.textContent = msg; t.classList.add("show"); clearTimeout(toast.t); toast.t = setTimeout(function () { t.classList.remove("show"); }, 1800); }
  // Copy text to the clipboard, falling back quietly if the browser blocks it.
  function copy(text) { try { navigator.clipboard.writeText(text).then(function () { toast("Copied"); }, function () { toast("Copy blocked by the browser"); }); } catch (e) { toast("Copy blocked by the browser"); } }
  // Read and write browser storage without crashing in private windows.
  function store(key, val) { try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) { return null; } }

  // ---------- Link findings to the checks that produced them ----------
  // Longest rule IDs first, so "webapp-xss-html-sink" wins over a shorter prefix.
  var RULES = DATA.rules.slice().sort(function (a, b) { return b.id.length - a.id.length; });
  var RULE_BY_ID = {};
  DATA.rules.forEach(function (r) { RULE_BY_ID[r.id] = r; r.hits = 0; });
  // Each finding gets its rule, family and a stable key.
  var FINDINGS = R.findings.map(function (f, i) {
    var rule = null;
    for (var j = 0; j < RULES.length; j++) { var id = RULES[j].id; if (f.id === id || f.id.indexOf(id + "-") === 0) { rule = RULES[j]; break; } }
    if (rule) rule.hits++;
    var group = rule ? rule.group : (f.id.indexOf("webapp-") === 0 ? "web" : f.id.indexOf("defense-") === 0 ? "defense" : "agent");
    return { f: f, i: i, rule: rule, group: group, key: f.id + "|" + f.file + "|" + (f.line || 0) };
  }).sort(function (a, b) { return SEVS.indexOf(a.f.severity) - SEVS.indexOf(b.f.severity) || String(a.f.file).localeCompare(String(b.f.file)) || (a.f.line || 0) - (b.f.line || 0); });
  // A check "ran" unless it's a web-app check and the scan didn't use --web.
  function checkStatus(r) { if (r.group === "web" && !META.web) return "notrun"; if (r.hits > 0) return "failed"; if (r.group === "agent" && META.agentSetup === false) return "na"; return "passed"; }

  // ---------- Theme switch (System / Dark / Light) ----------
  function setTheme(t) {
    document.documentElement.dataset.theme = t;
    store("cw-theme", t);
    document.querySelectorAll(".seg button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.theme === t)); });
  }
  document.querySelectorAll(".seg button").forEach(function (b) { b.addEventListener("click", function () { setTheme(b.dataset.theme); }); });
  setTheme(store("cw-theme") || "system");

  // ---------- Header buttons ----------
  document.getElementById("projline").textContent = META.project + " · " + new Date(META.timestamp).toLocaleString();
  document.getElementById("printBtn").addEventListener("click", function () { window.print(); });
  document.getElementById("jsonBtn").addEventListener("click", function () {
    var blob = new Blob([JSON.stringify(R, null, 2)], { type: "application/json" });
    var a = h("a", { href: URL.createObjectURL(blob), download: "cyberwarden-" + META.project + ".json" });
    document.body.appendChild(a); a.click(); a.remove();
  });

  // ---------- Shared filter state for the Findings tab ----------
  var FILTER = { q: "", sev: {}, group: "all", cat: "all", file: "" };

  // ---------- Tabs ----------
  var checksRun = DATA.rules.filter(function (r) { var s = checkStatus(r); return s === "failed" || s === "passed"; }).length;
  var TABS = [
    { id: "overview", label: "Overview", render: renderOverview },
    { id: "findings", label: "Findings", count: FINDINGS.length, render: renderFindings },
    { id: "checks", label: "Security checks", count: checksRun, render: renderChecks },
    { id: "plan", label: "Fix plan", render: renderPlan },
    { id: "files", label: "Files", render: renderFiles },
    { id: "compliance", label: "Compliance", render: renderCompliance },
    { id: "learn", label: "Learn", render: renderLearn }
  ];
  var nav = document.querySelector("nav.tabs"), main = document.getElementById("main");
  TABS.forEach(function (t) {
    nav.appendChild(h("button", { role: "tab", id: "tab-" + t.id, "aria-controls": "panel-" + t.id, onclick: function () { show(t.id); } },
      [t.label, t.count !== undefined ? h("span", { class: "count", text: "(" + t.count + ")" }) : null]));
    main.appendChild(h("section", { class: "panel hide", id: "panel-" + t.id, role: "tabpanel", "aria-labelledby": "tab-" + t.id }));
  });
  // Switch to a tab, drawing its contents fresh.
  function show(id) {
    TABS.forEach(function (t) {
      var on = t.id === id, panel = document.getElementById("panel-" + t.id);
      document.getElementById("tab-" + t.id).setAttribute("aria-selected", String(on));
      panel.classList.toggle("hide", !on);
      if (on) { panel.textContent = ""; t.render(panel); }
    });
    if (location.hash !== "#" + id) history.replaceState(null, "", "#" + id);
    window.scrollTo({ top: 0 });
  }
  // Jump to the Findings tab with some filters already set.
  function openFindings(patch) {
    FILTER = { q: "", sev: {}, group: "all", cat: "all", file: "" };
    for (var k in patch) FILTER[k] = patch[k];
    show("findings");
  }

  // ---------- Overview ----------
  function renderOverview(p) {
    var s = R.summary, sc = R.score;
    var serious = s.critical + s.high;
    var verdict = s.critical > 0 ? plural(s.critical, "critical problem") + " to fix before you deploy."
      : s.high > 0 ? plural(s.high, "high-risk problem") + " to fix soon."
      : s.totalFindings > 0 ? "No serious problems. " + plural(s.totalFindings, "smaller item") + " to review."
      : "No problems found by the checks that ran.";
    var col = scoreColor(sc.numericScore);
    p.appendChild(h("h2", { text: "Security overview" }));
    p.appendChild(h("p", { class: "sub", text: "What CyberWarden found in " + META.project + ", and what to do next." }));

    // Grade and verdict.
    var hero = h("div", { class: "grid g-hero" });
    hero.appendChild(h("div", { class: "card grade" }, [
      h("div", { class: "ring", style: "background:conic-gradient(" + col + " " + sc.numericScore + "%, var(--soft) 0)" },
        h("div", { style: "width:84%;height:84%;border-radius:50%;background:var(--card);display:grid;place-items:center" },
          h("div", null, [h("b", { style: "color:" + col, text: sc.grade }), h("span", { text: sc.numericScore + " / 100" })]))),
      h("div", null, [h("p", { class: "verdict", text: verdict }),
        h("p", { class: "sub", style: "margin:0", text: plural(s.totalFindings, "finding") + " across " + plural(s.filesScanned, "file") + ". " + checksRun + " security checks ran." })])
    ]));
    // Score per area.
    var areas = h("div", { class: "card" }, [h("h3", { text: "Score by area" })]);
    var bd = sc.breakdown || {};
    var names = { secrets: "Secrets", permissions: "Permissions", hooks: "Hooks", mcp: "MCP servers", agents: "Agents", webapp: "Web app code" };
    Object.keys(bd).forEach(function (k) {
      var v = bd[k];
      areas.appendChild(h("div", { style: "margin:10px 0" }, [
        h("div", { class: "row between", style: "font-size:14px;margin-bottom:4px" }, [h("span", { text: names[k] || k }), h("b", { style: "color:" + scoreColor(v), text: v + "" })]),
        h("div", { class: "meter" }, h("i", { style: "width:" + v + "%;background:" + scoreColor(v) }))
      ]));
    });
    hero.appendChild(areas);
    p.appendChild(hero);

    // Severity counts (click to see them).
    p.appendChild(h("h3", { style: "margin:22px 0 10px", text: "Findings by severity" }));
    var sevs = h("div", { class: "grid g-sev" });
    SEVS.forEach(function (sv) {
      var o = {}; o[sv] = true;
      sevs.appendChild(h("button", { class: "sevcard", title: SEV_MEANING[sv], onclick: function () { openFindings({ sev: o }); } },
        [h("b", { class: sv, style: "background:none", text: String(s[sv] || 0) }), h("span", { text: SEV_LABEL[sv] })]));
    });
    p.appendChild(sevs);

    // What to fix first.
    var top = FINDINGS.filter(function (x) { return x.f.severity === "critical" || x.f.severity === "high"; }).slice(0, 5);
    var two = h("div", { class: "grid g-2", style: "margin-top:14px" });
    var first = h("div", { class: "card" }, [h("h3", { text: serious ? "Fix these first" : "Nothing urgent" })]);
    if (!top.length) first.appendChild(h("p", { class: "sub", style: "margin:0", text: "No critical or high findings. Review the smaller items in the Findings tab." }));
    top.forEach(function (x) {
      first.appendChild(h("div", { class: "row", style: "margin:9px 0;align-items:flex-start" }, [sevBadge(x.f.severity),
        h("div", { style: "min-width:0" }, [h("button", { class: "linkish", style: "text-align:left", text: x.f.title, onclick: function () { openFindings({ q: x.f.title }); } }),
          h("div", { class: "floc", text: x.f.file + (x.f.line ? ":" + x.f.line : "") })])]));
    });
    two.appendChild(first);
    // Scan details.
    var groupsHit = {};
    FINDINGS.forEach(function (x) { groupsHit[x.group] = (groupsHit[x.group] || 0) + 1; });
    two.appendChild(h("div", { class: "card" }, [h("h3", { text: "Scan details" }), h("dl", { class: "kv" }, [
      h("dt", { text: "Project" }), h("dd", { class: "mono", text: META.target }),
      h("dt", { text: "Scanned" }), h("dd", { text: new Date(META.timestamp).toLocaleString() }),
      h("dt", { text: "Tool" }), h("dd", { text: "CyberWarden " + META.version }),
      h("dt", { text: "Web-app checks" }), h("dd", { text: META.web ? "On (--web)" : "Off. Add --web to scan your app's code." }),
      h("dt", { text: "Files scanned" }), h("dd", { text: String(s.filesScanned) }),
      h("dt", { text: "Auto-fixable" }), h("dd", { text: s.autoFixable ? s.autoFixable + " (run with --fix after reviewing)" : "0" }),
      h("dt", { text: "By source" }), h("dd", { text: Object.keys(GROUPS).map(function (g) { return GROUPS[g].split(" (")[0] + ": " + (groupsHit[g] || 0); }).join(" · ") })
    ])]));
    p.appendChild(two);

    // Protections already in place.
    if (R.defenses && R.defenses.length) {
      var d = h("div", { class: "card", style: "margin-top:14px" }, [h("h3", { text: "Protections already in place (" + R.defenses.length + ")" })]);
      R.defenses.slice(0, 12).forEach(function (x) { d.appendChild(h("div", { class: "row", style: "margin:6px 0" }, [h("span", { class: "badge passed", text: "OK" }), h("span", { text: x.title || x.name || x.id || "Defense" }), h("span", { class: "floc", text: x.file || "" })])); });
      p.appendChild(d);
    }
    p.appendChild(h("p", { class: "note", style: "margin-top:14px", text: "A scanner is a smoke alarm, not a fire brigade: it catches common, clear-cut mistakes fast, but a clean result means \\"no known patterns found\\", not \\"impossible to hack\\". Pair it with code review, testing and 2FA on your accounts." }));
  }

  // ---------- Findings ----------
  function renderFindings(p) {
    p.appendChild(h("h2", { text: "Findings" }));
    p.appendChild(h("p", { class: "sub", text: "Every problem found, most urgent first. Open one to see why it matters and how to fix it." }));
    var bar = h("div", { class: "toolbar" });
    var q = h("input", { type: "search", placeholder: "Search titles, files, rule IDs…", value: FILTER.q, "aria-label": "Search findings" });
    bar.appendChild(q);
    var chips = {};
    SEVS.forEach(function (sv) {
      var c = h("button", { class: "chip " + sv, "aria-pressed": String(!!FILTER.sev[sv]), text: SEV_LABEL[sv] + " " + (R.summary[sv] || 0) });
      c.addEventListener("click", function () { FILTER.sev[sv] = !FILTER.sev[sv]; c.setAttribute("aria-pressed", String(FILTER.sev[sv])); draw(); });
      chips[sv] = c; bar.appendChild(c);
    });
    var gsel = h("select", { "aria-label": "Source" }, [h("option", { value: "all", text: "All sources" })].concat(Object.keys(GROUPS).map(function (g) { return h("option", { value: g, text: GROUPS[g] }); })));
    gsel.value = FILTER.group;
    var cats = {}; FINDINGS.forEach(function (x) { cats[x.f.category] = 1; });
    var csel = h("select", { "aria-label": "Category" }, [h("option", { value: "all", text: "All categories" })].concat(Object.keys(cats).sort().map(function (c) { return h("option", { value: c, text: (CAT[c] || [c])[0] }); })));
    csel.value = FILTER.cat;
    bar.appendChild(gsel); bar.appendChild(csel);
    p.appendChild(bar);
    var info = h("div", { class: "row between", style: "margin-bottom:10px;font-size:14px;color:var(--muted)" });
    p.appendChild(info);
    var list = h("div", { class: "list" });
    p.appendChild(list);
    q.addEventListener("input", function () { FILTER.q = q.value; draw(); });
    gsel.addEventListener("change", function () { FILTER.group = gsel.value; draw(); });
    csel.addEventListener("change", function () { FILTER.cat = csel.value; draw(); });
    // Redraw the list whenever a filter changes.
    function draw() {
      var anySev = SEVS.some(function (s) { return FILTER.sev[s]; });
      var needle = FILTER.q.trim().toLowerCase();
      var shown = FINDINGS.filter(function (x) {
        if (anySev && !FILTER.sev[x.f.severity]) return false;
        if (FILTER.group !== "all" && x.group !== FILTER.group) return false;
        if (FILTER.cat !== "all" && x.f.category !== FILTER.cat) return false;
        if (FILTER.file && x.f.file !== FILTER.file) return false;
        if (needle && (x.f.title + " " + x.f.file + " " + x.f.id + " " + x.f.description).toLowerCase().indexOf(needle) < 0) return false;
        return true;
      });
      info.textContent = "";
      info.appendChild(h("span", { text: "Showing " + shown.length + " of " + FINDINGS.length }));
      if (FILTER.file || anySev || needle || FILTER.group !== "all" || FILTER.cat !== "all")
        info.appendChild(h("button", { class: "linkish", text: "Clear filters", onclick: function () { openFindings({}); } }));
      list.textContent = "";
      if (!shown.length) { list.appendChild(h("div", { class: "empty", text: FINDINGS.length ? "No findings match these filters." : "No findings. Every check that ran passed." })); return; }
      shown.slice(0, 400).forEach(function (x) { list.appendChild(findingCard(x)); });
      if (shown.length > 400) list.appendChild(h("p", { class: "note", text: (shown.length - 400) + " more: narrow the filters to see them." }));
    }
    draw();
  }
  // One expandable finding.
  function findingCard(x) {
    var f = x.f, loc = f.file + (f.line ? ":" + f.line : "");
    var body = h("div", { class: "fbody" });
    body.appendChild(h("h4", { text: "Why it matters" }));
    body.appendChild(h("p", { style: "margin:0", text: f.description }));
    body.appendChild(h("h4", { text: "Where" }));
    body.appendChild(h("div", { class: "row" }, [h("span", { class: "mono", text: loc }), h("button", { class: "linkish noprint", text: "Copy", onclick: function () { copy(loc); } })]));
    if (f.evidence) { body.appendChild(h("h4", { text: "What was found" })); body.appendChild(h("pre", { text: f.evidence })); }
    if (f.fix) {
      body.appendChild(h("h4", { text: "How to fix" + (f.fix.auto ? " (auto-fixable)" : "") }));
      body.appendChild(h("p", { style: "margin:0 0 8px", text: f.fix.description }));
      if (f.fix.before || f.fix.after) body.appendChild(h("div", { class: "fix" }, [
        f.fix.before ? h("div", null, [h("div", { class: "lbl bad", text: "Before (risky)" }), h("pre", { text: f.fix.before })]) : null,
        f.fix.after ? h("div", null, [h("div", { class: "lbl good", text: "After (safer)" }), h("pre", { text: f.fix.after })]) : null
      ]));
    }
    var cat = CAT[f.category];
    if (cat) { body.appendChild(h("h4", { text: "About " + cat[0].toLowerCase() })); body.appendChild(h("p", { style: "margin:0;color:var(--muted)", text: cat[1] })); }
    body.appendChild(h("h4", { text: "Details" }));
    body.appendChild(h("div", null, [h("span", { class: "tag", text: "Rule: " + (x.rule ? x.rule.id : f.id) }), h("span", { class: "tag", text: GROUPS[x.group] }),
      h("span", { class: "tag", text: "Category: " + (cat ? cat[0] : f.category) }), f.runtimeConfidence ? h("span", { class: "tag", text: "Confidence: " + f.runtimeConfidence }) : null]));
    return h("details", { class: "finding", style: "border-left-color:var(--" + ({ critical: "crit", high: "high", medium: "med", low: "low", info: "info" }[f.severity]) + ")" }, [
      h("summary", null, [sevBadge(f.severity), h("div", { style: "min-width:0" }, [h("div", { class: "ftitle", text: f.title }), h("div", { class: "floc", text: loc })]), h("span", { class: "chev", "aria-hidden": "true", text: "›" })]),
      body
    ]);
  }

  // ---------- Security checks ----------
  function renderChecks(p) {
    var counts = { failed: 0, passed: 0, notrun: 0, na: 0 };
    DATA.rules.forEach(function (r) { counts[checkStatus(r)]++; });
    p.appendChild(h("h2", { text: "Security checks" }));
    p.appendChild(h("p", { class: "sub", text: checksRun + " checks ran: " + counts.passed + " passed, " + counts.failed + " found problems." + (counts.na ? " " + counts.na + " AI-coding-setup checks are not applicable (no Claude Code, Cursor or MCP setup in this project)." : "") + (counts.notrun ? " " + counts.notrun + " web-app checks didn't run (scan with --web to include them)." : "") }));
    var st = { status: "all", group: "all", q: "" };
    var bar = h("div", { class: "toolbar" });
    var q = h("input", { type: "search", placeholder: "Search checks…", "aria-label": "Search checks" });
    bar.appendChild(q);
    var statusChips = [["all", "All"], ["failed", "Found problems " + counts.failed], ["passed", "Passed " + counts.passed], ["na", "Not applicable " + counts.na], ["notrun", "Not run " + counts.notrun]].map(function (s) {
      var c = h("button", { class: "chip", "aria-pressed": String(s[0] === "all"), text: s[1] });
      c.addEventListener("click", function () { st.status = s[0]; statusChips.forEach(function (b) { b.setAttribute("aria-pressed", "false"); }); c.setAttribute("aria-pressed", "true"); draw(); });
      bar.appendChild(c); return c;
    });
    var gsel = h("select", { "aria-label": "Source" }, [h("option", { value: "all", text: "All sources" })].concat(Object.keys(GROUPS).map(function (g) { return h("option", { value: g, text: GROUPS[g] }); })));
    bar.appendChild(gsel);
    p.appendChild(bar);
    var wrap = h("div", { class: "tablewrap card", style: "padding:6px 10px" });
    p.appendChild(wrap);
    q.addEventListener("input", function () { st.q = q.value.trim().toLowerCase(); draw(); });
    gsel.addEventListener("change", function () { st.group = gsel.value; draw(); });
    var order = { failed: 0, passed: 1, notrun: 2, na: 3 };
    // Redraw the table.
    function draw() {
      var rows = DATA.rules.filter(function (r) {
        var s = checkStatus(r);
        if (st.status !== "all" && s !== st.status) return false;
        if (st.group !== "all" && r.group !== st.group) return false;
        if (st.q && (r.name + " " + r.id + " " + r.description).toLowerCase().indexOf(st.q) < 0) return false;
        return true;
      }).sort(function (a, b) { return order[checkStatus(a)] - order[checkStatus(b)] || SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity) || a.name.localeCompare(b.name); });
      wrap.textContent = "";
      if (!rows.length) { wrap.appendChild(h("div", { class: "empty", text: "No checks match." })); return; }
      var tb = h("tbody");
      rows.slice(0, 600).forEach(function (r) {
        var s = checkStatus(r);
        tb.appendChild(h("tr", null, [
          h("td", null, h("span", { class: "badge " + (s === "failed" ? r.severity : s), text: s === "failed" ? plural(r.hits, "finding") : s === "passed" ? "Passed" : s === "na" ? "Not applicable" : "Not run" })),
          h("td", null, [h("div", { style: "font-weight:600", text: r.name }), h("div", { style: "color:var(--muted);font-size:13px", text: r.description })]),
          h("td", { class: "mono", text: r.id }),
          h("td", null, sevBadge(r.severity)),
          h("td", { text: GROUPS[r.group].split(" (")[0] }),
          h("td", null, s === "failed" ? h("button", { class: "linkish", text: "View", onclick: function () { openFindings({ q: r.id }); } }) : "")
        ]));
      });
      wrap.appendChild(h("table", { class: "stack" }, [h("thead", null, h("tr", null, ["Result", "Check", "Rule ID", "Severity", "Source", ""].map(function (t) { return h("th", { text: t }); }))), tb]));
    }
    draw();
  }

  // ---------- Fix plan ----------
  function renderPlan(p) {
    var key = "cw-done:" + META.target + ":" + META.timestamp;
    var done = {};
    try { done = JSON.parse(store(key) || "{}"); } catch (e) { done = {}; }
    p.appendChild(h("h2", { text: "Fix plan" }));
    p.appendChild(h("p", { class: "sub", text: "Work top to bottom. Tick items as you fix them (saved in this browser only), then re-scan to confirm." }));
    if (!FINDINGS.length) { p.appendChild(h("div", { class: "empty card", text: "Nothing to fix. Re-scan after every big change." })); return; }
    var prog = h("div", { class: "card", style: "margin-bottom:14px" });
    p.appendChild(prog);
    // Update the progress bar.
    function progress() {
      var n = FINDINGS.filter(function (x) { return done[x.key]; }).length, pct = Math.round(n / FINDINGS.length * 100);
      prog.textContent = "";
      prog.appendChild(h("div", { class: "row between", style: "margin-bottom:8px" }, [h("b", { text: n + " of " + FINDINGS.length + " fixed" }), h("span", { text: pct + "%" })]));
      prog.appendChild(h("div", { class: "meter" }, h("i", { style: "width:" + pct + "%;background:var(--ok)" })));
    }
    progress();
    SEVS.forEach(function (sv) {
      var items = FINDINGS.filter(function (x) { return x.f.severity === sv; });
      if (!items.length) return;
      p.appendChild(h("div", { class: "row", style: "margin:18px 0 8px" }, [sevBadge(sv), h("span", { style: "color:var(--muted);font-size:14px", text: SEV_MEANING[sv] })]));
      var list = h("div", { class: "list" });
      items.forEach(function (x) {
        var box = h("input", { type: "checkbox", "aria-label": "Mark fixed: " + x.f.title });
        box.checked = !!done[x.key];
        var row = h("label", { class: "check" + (box.checked ? " done" : "") }, [box, h("div", { style: "min-width:0" }, [
          h("div", { class: "ftitle", text: x.f.title }), h("div", { class: "floc", text: x.f.file + (x.f.line ? ":" + x.f.line : "") }),
          x.f.fix ? h("div", { style: "font-size:14px;margin-top:4px", text: "Fix: " + x.f.fix.description }) : null])]);
        box.addEventListener("change", function () { done[x.key] = box.checked; if (!box.checked) delete done[x.key]; row.classList.toggle("done", box.checked); store(key, JSON.stringify(done)); progress(); });
        list.appendChild(row);
      });
      p.appendChild(list);
    });
    var cmd = "cyberwarden scan --path \\"" + META.target + "\\"" + (META.web ? " --web" : "") + " --format dashboard -o cyberwarden-report.html";
    p.appendChild(h("div", { class: "card", style: "margin-top:18px" }, [h("h3", { text: "Re-scan after fixing" }), h("pre", { text: cmd }), h("button", { class: "btn noprint", style: "margin-top:8px", text: "Copy command", onclick: function () { copy(cmd); } })]));
  }

  // ---------- Files ----------
  function renderFiles(p) {
    var byFile = {};
    FINDINGS.forEach(function (x) { var e = byFile[x.f.file] || (byFile[x.f.file] = { file: x.f.file, total: 0 }); e.total++; e[x.f.severity] = (e[x.f.severity] || 0) + 1; });
    var rows = Object.keys(byFile).map(function (k) { return byFile[k]; }).sort(function (a, b) { return (b.critical || 0) - (a.critical || 0) || (b.high || 0) - (a.high || 0) || b.total - a.total; });
    p.appendChild(h("h2", { text: "Files" }));
    p.appendChild(h("p", { class: "sub", text: rows.length ? plural(rows.length, "file") + " with findings, riskiest first. " + R.summary.filesScanned + " files scanned in total." : "No file has findings." }));
    if (!rows.length) return;
    var tb = h("tbody");
    rows.forEach(function (r) {
      tb.appendChild(h("tr", null, [h("td", null, h("button", { class: "linkish mono", style: "text-align:left", text: r.file, onclick: function () { openFindings({ file: r.file }); } }))]
        .concat(SEVS.map(function (s) { return h("td", null, r[s] ? h("span", { class: "badge " + s, text: String(r[s]) }) : h("span", { style: "color:var(--muted)", text: "–" })); }))
        .concat([h("td", { style: "font-weight:700", text: String(r.total) })])));
    });
    p.appendChild(h("div", { class: "tablewrap card", style: "padding:6px 10px" }, h("table", null, [h("thead", null, h("tr", null, ["File"].concat(SEVS.map(function (s) { return SEV_LABEL[s]; })).concat(["Total"]).map(function (t) { return h("th", { text: t }); }))), tb])));
  }

  // ---------- Compliance ----------
  function renderCompliance(p) {
    p.appendChild(h("h2", { text: "Compliance" }));
    p.appendChild(h("p", { class: "sub", text: "Which audit controls your findings touch, for clients who ask about SOC 2, PCI DSS (card payments) or ISO 27001." }));
    var g = h("div", { class: "grid g-3" });
    DATA.compliance.forEach(function (fw) {
      var c = h("div", { class: "card" }, [h("h3", { text: fw.frameworkName }), h("p", { class: "sub", style: "margin:0 0 10px", text: fw.controls.length ? plural(fw.controls.length, "control") + " affected by " + plural(fw.mappedFindingCount, "finding") : "No controls affected." })]);
      fw.controls.forEach(function (ctl) {
        c.appendChild(h("div", { style: "border-top:1px solid var(--line);padding:9px 0" }, [
          h("div", { class: "row between" }, [h("b", { class: "mono", text: ctl.controlId }), sevBadge(ctl.highestSeverity)]),
          h("div", { style: "font-size:14px", text: ctl.controlTitle }),
          h("div", { style: "font-size:13px;color:var(--muted)", text: plural(ctl.findingCount, "finding") + (ctl.exampleFindings.length ? " · e.g. " + ctl.exampleFindings[0] : "") })]));
      });
      g.appendChild(c);
    });
    p.appendChild(g);
    p.appendChild(h("p", { class: "note", style: "margin-top:14px", text: "This mapping is security guidance by finding category, not a certified audit. Nigeria's NDPA 2023 privacy issues (BVN, NIN and other personal data) appear as findings under Data leaks and Exposure." }));
  }

  // ---------- Learn ----------
  function renderLearn(p) {
    p.appendChild(h("h2", { text: "Learn" }));
    p.appendChild(h("p", { class: "sub", text: "What the words and colours in this report mean." }));
    var sev = h("div", { class: "card" }, [h("h3", { text: "Severity levels" })]);
    SEVS.forEach(function (s) { sev.appendChild(h("div", { class: "row", style: "margin:9px 0;align-items:flex-start" }, [h("div", { style: "width:92px;flex:none" }, sevBadge(s)), h("span", { text: SEV_MEANING[s] })])); });
    var gr = h("div", { class: "card" }, [h("h3", { text: "Grades" })]);
    GRADES.forEach(function (x) { gr.appendChild(h("div", { class: "row", style: "margin:9px 0" }, [h("b", { style: "width:22px", text: x[0] }), h("span", { class: "mono", style: "width:64px;color:var(--muted)", text: x[1] }), h("span", { text: x[2] })])); });
    p.appendChild(h("div", { class: "grid g-2" }, [sev, gr]));
    var cats = h("div", { class: "card", style: "margin-top:14px" }, [h("h3", { text: "What each category means" })]);
    Object.keys(CAT).forEach(function (k) { cats.appendChild(h("div", { style: "border-top:1px solid var(--line);padding:10px 0" }, [h("b", { text: CAT[k][0] }), h("div", { style: "color:var(--muted)", text: CAT[k][1] })])); });
    p.appendChild(cats);
    var src = h("div", { class: "card", style: "margin-top:14px" }, [h("h3", { text: "Where the checks come from" })]);
    [["agent", "Checks your AI coding setup (Claude Code and similar): secrets, permissions, hooks, MCP servers, skills and prompt-injection risks. From AgentShield by Affaan M (MIT licence)."],
     ["defense", "CyberWarden's extra layer: database Row-Level Security, SSRF, unsafe uploads, double-spend race conditions, unpinned packages, Paystack/Flutterwave/WhatsApp webhooks, chatbot history, NDPA personal data, mass assignment, exposed dotfiles and OTP safety."],
     ["web", "CyberWarden's checks on your site's own code (scan with --web): SQL injection, XSS, secrets in code or git, weak passwords and tokens, cookies, CORS, CSP, headers, rate limits, webhooks, open redirects, file paths, error leaks, payments and AI prompt safety."]]
      .forEach(function (x) { src.appendChild(h("div", { style: "border-top:1px solid var(--line);padding:10px 0" }, [h("b", { text: GROUPS[x[0]] }), h("div", { style: "color:var(--muted)", text: x[1] })])); });
    p.appendChild(src);
  }

  // ---------- Start ----------
  var start = (location.hash || "").slice(1);
  show(TABS.some(function (t) { return t.id === start; }) ? start : "overview");
})();
</script>
</body>
</html>
`;
