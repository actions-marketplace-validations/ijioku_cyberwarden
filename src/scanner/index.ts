import type {
  ConfigFile,
  DanglingSymlink,
  Finding,
  Rule,
  RuntimeConfidence,
  SkillHealthSummary,
  HarnessAdapterSummary,
  ScanTarget,
  Severity,
} from "../types.js";
import { discoverConfigFiles } from "./discovery.js";
// Finds web-app files for the --web scan
import { discoverWebAppFiles } from "./web-discovery.js";
import { getBuiltinRules } from "../rules/index.js";
import { isExampleLikePath, isPluginCachePath } from "../source-context.js";
import { analyzeSkillHealth } from "../skills/health.js";
import { detectHarnessAdapters } from "../harness-adapters/index.js";

export interface ScanResult {
  readonly target: ScanTarget;
  readonly findings: ReadonlyArray<Finding>;
  readonly skillHealth?: SkillHealthSummary;
  readonly harnessAdapters?: HarnessAdapterSummary;
  // True when the scan also checked web-app code (the --web flag)
  readonly webScan?: boolean;
}

export interface ScanOptions {
  /** Extra rules loaded from external rule packs (`--rule-pack`). */
  readonly extraRules?: ReadonlyArray<Rule>;
  // When true, also scan the project's web-app code with the webapp rules (--web)
  readonly web?: boolean;
}

// File types that only the --web scan produces
const WEB_FILE_TYPES = new Set(["web-code", "web-html", "web-env", "web-gitignore", "web-git-tracked"]);

// The one original rule that is also useful on web code: hardcoded API keys and passwords
const WEB_SHARED_RULE_IDS = new Set(["secrets-hardcoded"]);

/**
 * Main scanner: discovers config files and runs all rules against them.
 * External rule packs (if any) run alongside the built-in rules.
 */
export function scan(targetPath: string, options: ScanOptions = {}): ScanResult {
  const configTarget = discoverConfigFiles(targetPath);
  // With --web, add the project's web-app files (skipping any path already found as AI config)
  const target = options.web ? withWebFiles(configTarget) : configTarget;
  const rules = [...getBuiltinRules(), ...(options.extraRules ?? [])];
  const findings = sortBySeverity([
    ...runRules(target.files, rules, target.path),
    ...buildDanglingSymlinkFindings(target.danglingSymlinks),
  ]);
  const skillHealth = analyzeSkillHealth(target.files);
  const harnessAdapters = detectHarnessAdapters(targetPath);

  // Pass webScan along so the score shows a "Web App" bar
  return { target, findings, skillHealth, harnessAdapters, ...(options.web ? { webScan: true } : {}) };
}

// Add the web-app files to the list of files to scan, without duplicates
function withWebFiles(target: ScanTarget): ScanTarget {
  // Paths already discovered as AI agent config
  const seen = new Set(target.files.map((file) => file.path));
  // Web files whose path hasn't been seen yet
  const webFiles = discoverWebAppFiles(target.path).filter((file) => !seen.has(file.path));
  // Return a new target with both lists combined
  return { ...target, files: [...target.files, ...webFiles] };
}

// Decide whether a rule should run on a file. Web files only get the webapp
// rules plus the hardcoded-secret rule; the AI-config rules would just add noise there.
function ruleAppliesToFile(rule: Rule, file: ConfigFile): boolean {
  // Is this one of the files only the --web scan finds?
  const isWebFile = WEB_FILE_TYPES.has(file.type);
  // Is this one of the new webapp rules?
  const isWebRule = rule.category === "webapp";
  // Webapp rules only ever look at web files
  if (isWebRule) return isWebFile;
  // AI-config rules keep running on AI-config files exactly as before
  if (!isWebFile) return true;
  // On web code and HTML, also run the hardcoded-secret rule (never on .env, whose job is to hold secrets)
  return WEB_SHARED_RULE_IDS.has(rule.id) && (file.type === "web-code" || file.type === "web-html");
}

/**
 * Run all rules against all config files, collecting findings.
 */
function runRules(
  files: ReadonlyArray<ConfigFile>,
  rules: ReadonlyArray<Rule>,
  scanRoot: string
): ReadonlyArray<Finding> {
  const findings: Finding[] = [];

  for (const file of files) {
    for (const rule of rules) {
      // Skip rule/file pairs that don't belong together (see ruleAppliesToFile)
      if (!ruleAppliesToFile(rule, file)) continue;
      const ruleFindings = rule.check(file, files);
      findings.push(...ruleFindings);
    }
  }

  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const annotatedFindings = findings.map((finding) => {
    const annotatedFinding = annotateFindingRuntimeConfidence(finding, filesByPath, scanRoot);
    return adjustFindingForSourceContext(annotatedFinding);
  });

  return sortBySeverity(annotatedFindings);
}

/**
 * Sort findings by severity (critical first). Stable, so input order is
 * preserved within a severity.
 */
function sortBySeverity(findings: ReadonlyArray<Finding>): ReadonlyArray<Finding> {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
}

/**
 * Emit a low finding for each symlink in a scanned config subdirectory that
 * points at a missing target. A dangling skill symlink is a skill the agent
 * believes it has but that resolves to nothing.
 */
function buildDanglingSymlinkFindings(
  danglingSymlinks: ReadonlyArray<DanglingSymlink>
): ReadonlyArray<Finding> {
  return danglingSymlinks.map((link) => {
    const isSkill = link.type === "skill-md";
    const targetLabel = link.target.length > 0 ? link.target : "unknown";
    return {
      id: isSkill
        ? `skills-dangling-symlink-${link.path}`
        : `discovery-dangling-symlink-${link.path}`,
      severity: "low",
      category: isSkill ? "skills" : "misconfiguration",
      title: isSkill ? "Dangling skill symlink" : "Dangling config symlink",
      description:
        `${link.path} is a symlink to ${targetLabel}, which does not exist. ` +
        (isSkill
          ? "The agent will treat this as an installed skill that resolves to nothing. It is usually a leftover from a pruned skill registry. Remove the link or restore its target."
          : "The entry was skipped during discovery. Remove the link or restore its target so the file can be scanned."),
      file: link.path,
      evidence: `${link.path} -> ${targetLabel}`,
    };
  });
}

function classifyRuntimeConfidence(file: ConfigFile, scanRoot: string): RuntimeConfidence | undefined {
  const normalizedPath = file.path.replace(/\\/g, "/").toLowerCase();
  if (normalizedPath === "settings.local.json" || normalizedPath.endsWith("/settings.local.json")) {
    return "project-local-optional";
  }

  if (isPluginCachePath(file.path, scanRoot)) {
    return "plugin-cache";
  }

  if (file.type === "hook-code") {
    return "hook-code";
  }

  if (
    file.type === "settings-json" &&
    /(?:^|\/)(?:\.claude\/)?hooks\/hooks\.json$/i.test(normalizedPath)
  ) {
    return "plugin-manifest";
  }

  if (isExampleLikePath(normalizedPath)) {
    return "docs-example";
  }

  return undefined;
}

function annotateFindingRuntimeConfidence(
  finding: Finding,
  filesByPath: ReadonlyMap<string, ConfigFile>,
  scanRoot: string
): Finding {
  if (finding.runtimeConfidence) {
    return finding;
  }

  const file = filesByPath.get(finding.file);
  const runtimeConfidence = file ? classifyRuntimeConfidence(file, scanRoot) : undefined;
  return runtimeConfidence ? { ...finding, runtimeConfidence } : finding;
}

function adjustFindingForSourceContext(finding: Finding): Finding {
  switch (finding.runtimeConfidence) {
    case "docs-example":
      return adjustDocsExampleFinding(finding);
    case "plugin-cache":
      return adjustPluginCacheFinding(finding);
    case "plugin-manifest":
      return adjustPluginManifestFinding(finding);
    default:
      return finding;
  }
}

function adjustDocsExampleFinding(finding: Finding): Finding {
  if (finding.category === "secrets") {
    return withPrefixedDescription(
      {
        ...finding,
        title: prefixTitle(finding.title, "Example config"),
      },
      "This finding comes from docs or sample configuration in the repository. It indicates risky guidance or example defaults, not confirmed active runtime exposure."
    );
  }

  return withPrefixedDescription(
    {
      ...finding,
      severity: downgradeStructuralSeverity(finding.severity),
      title: prefixTitle(finding.title, "Example config"),
    },
    "This finding comes from docs or sample configuration in the repository. It indicates risky guidance or example defaults, not confirmed active runtime exposure."
  );
}

function adjustPluginCacheFinding(finding: Finding): Finding {
  if (finding.category === "secrets") {
    return withPrefixedDescription(
      {
        ...finding,
        title: prefixTitle(finding.title, "Plugin cache"),
      },
      "This finding comes from an installed Claude plugin cache. It indicates packaged plugin content present on disk, not confirmed top-level runtime configuration."
    );
  }

  return withPrefixedDescription(
    {
      ...finding,
      severity: downgradeStructuralSeverity(finding.severity),
      title: prefixTitle(finding.title, "Plugin cache"),
    },
    "This finding comes from an installed Claude plugin cache. It indicates packaged plugin content present on disk, not confirmed top-level runtime configuration."
  );
}

function adjustPluginManifestFinding(finding: Finding): Finding {
  return withPrefixedDescription(
    {
      ...finding,
      title: prefixTitle(finding.title, "Plugin hook manifest"),
    },
    "This finding comes from a declarative hook manifest. Review the referenced hook implementation to confirm the exact runtime behavior."
  );
}

function downgradeStructuralSeverity(severity: Severity): Severity {
  switch (severity) {
    case "critical":
      return "high";
    case "high":
      return "medium";
    case "medium":
      return "low";
    default:
      return severity;
  }
}

function prefixTitle(title: string, prefix: string): string {
  return title.startsWith(`${prefix}: `) ? title : `${prefix}: ${title}`;
}

function withPrefixedDescription(finding: Finding, prefix: string): Finding {
  return finding.description.startsWith(prefix)
    ? finding
    : { ...finding, description: `${prefix} ${finding.description}` };
}

export { discoverConfigFiles } from "./discovery.js";
