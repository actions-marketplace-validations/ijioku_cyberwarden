import { describe, it, expect } from "vitest";
import { renderDashboard } from "../../src/reporter/dashboard.js";
import type { SecurityReport } from "../../src/types.js";

// A small report to render, with values each test can override.
function makeReport(overrides: Partial<SecurityReport> = {}): SecurityReport {
  return {
    timestamp: "2026-11-23T00:00:00.000Z",
    targetPath: "/tmp/shop",
    findings: [],
    defenses: [],
    score: { grade: "B", numericScore: 80, breakdown: { secrets: 100, permissions: 100, hooks: 100, mcp: 100, agents: 100, webapp: 60 } },
    summary: { totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, filesScanned: 3, autoFixable: 0, defenses: 0 },
    ...overrides,
  };
}

// Pull the embedded JSON back out of the page, the same way the page's own script reads it.
function embeddedData(html: string): any {
  const match = html.match(/<script type="application\/json" id="cw-data">([\s\S]*?)<\/script>/);
  return JSON.parse(match![1]);
}

describe("renderDashboard", () => {
  it("builds a complete page titled with the project and grade", () => {
    const html = renderDashboard(makeReport());
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("<title>CyberWarden: shop (Grade B)</title>");
    expect(html).not.toContain("__DATA__");
    expect(html).not.toContain("__TITLE__");
  });

  it("blocks all network requests with its Content-Security-Policy", () => {
    const html = renderDashboard(makeReport());
    expect(html).toContain("default-src 'none'");
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/<link[^>]+href="https?:/);
  });

  it("can't be broken out of by text inside a finding", () => {
    // A scanned file containing "</script>" must not end the data block early or run as code.
    const evil = '</script><script>alert(1)</script>';
    const html = renderDashboard(
      makeReport({
        findings: [{ id: "webapp-xss-html-sink-a.js-1", severity: "high", category: "webapp", title: evil, description: "x", file: "a.js", line: 1, evidence: evil }],
      })
    );
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(embeddedData(html).report.findings[0].title).toBe(evil);
  });

  it("lists every built-in check, grouped by where it comes from", () => {
    const rules = embeddedData(renderDashboard(makeReport())).rules as Array<{ id: string; group: string }>;
    expect(rules.length).toBeGreaterThan(100);
    expect(rules.find((r) => r.id === "webapp-sql-injection")?.group).toBe("web");
    expect(rules.find((r) => r.id === "defense-db-rls-disabled")?.group).toBe("defense");
    expect(rules.some((r) => r.group === "agent")).toBe(true);
    expect(new Set(rules.map((r) => r.id)).size).toBe(rules.length);
  });

  it("records whether the web-app checks ran", () => {
    expect(embeddedData(renderDashboard(makeReport())).meta.web).toBe(false);
    expect(embeddedData(renderDashboard(makeReport(), { web: true, version: "1.7.0" })).meta).toMatchObject({ web: true, version: "1.7.0" });
  });

  it("includes SOC 2, PCI DSS and ISO 27001 mappings", () => {
    const data = embeddedData(
      renderDashboard(
        makeReport({
          findings: [{ id: "webapp-sql-injection-s.js-9", severity: "critical", category: "webapp", title: "SQL", description: "d", file: "s.js" }],
        })
      )
    );
    expect(data.compliance.map((c: { framework: string }) => c.framework)).toEqual(["soc2", "pci", "iso"]);
    expect(data.compliance[0].mappedFindingCount).toBe(1);
  });
});
