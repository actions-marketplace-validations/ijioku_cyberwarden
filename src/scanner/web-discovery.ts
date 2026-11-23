// CyberWarden addition: finds the web-app files (code, HTML, .env, .gitignore)
// that the --web scan checks. The original discovery.ts only looks at AI agent config.

// Node tools for reading folders and files
import { readFileSync, readdirSync, statSync } from "node:fs";
// Node tools for building and comparing file paths
import { basename, extname, join, relative } from "node:path";
// Shared types that describe a discovered file
import type { ConfigFile, ConfigFileType } from "../types.js";
// Helper that turns Windows back-slashes into forward slashes
import { toPosixPath } from "./paths.js";

// Folders we never walk into: installed packages, build output, caches and AI config
const SKIPPED_DIRS = new Set([
  ".git",
  ".claude",
  "node_modules",
  ".next",
  ".nuxt",
  ".turbo",
  ".cache",
  ".vercel",
  ".netlify",
  ".venv",
  "venv",
  "__pycache__",
  "coverage",
  "dist",
  "build",
  "out",
  "target",
  "vendor",
  // Test folders hold deliberately unsafe samples, so scanning them only adds noise
  "test",
  "tests",
  "__tests__",
  "__mocks__",
  "spec",
  "fixtures",
  "e2e",
  "cypress",
]);

// File endings that count as web-app source code
const CODE_EXTENSIONS = new Set([".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"]);

// Skip very large files (usually bundled or generated code) to keep the scan fast
const MAX_FILE_BYTES = 512 * 1024;

// Stop after this many files so a huge folder can't hang the scan
const MAX_FILES = 4000;

// Stop going deeper than this many folders
const MAX_DEPTH = 14;

/**
 * Walks the project and returns every web-app file the --web rules check.
 * .env files are listed by name only: their content is never read, so the
 * scanner can't leak the real secrets inside them.
 */
export function discoverWebAppFiles(rootPath: string): ReadonlyArray<ConfigFile> {
  // The list of files we find
  const files: ConfigFile[] = [];
  // Walk the folder tree starting at the project root
  walk(rootPath, rootPath, 0, files);
  // Add one extra entry listing secret-looking files that git is tracking
  const tracked = readTrackedSensitiveFiles(rootPath);
  // Only add that entry when git actually tracks something risky
  if (tracked.length > 0) {
    // The "file" content is just the list of risky paths, one per line
    files.push({ path: ".git/index", type: "web-git-tracked", content: tracked.join("\n") });
  }
  // Hand back everything we found
  return files;
}

// Recursively visit one folder and collect web files from it
function walk(scanRoot: string, dirPath: string, depth: number, files: ConfigFile[]): void {
  // Give up on folders that are too deep or when we already have enough files
  if (depth > MAX_DEPTH || files.length >= MAX_FILES) return;

  // Holds the folder's entries
  let entries;
  // Reading a folder can fail (no permission, deleted mid-scan), so guard it
  try {
    // List the folder's contents, including whether each is a file or folder
    entries = readdirSync(dirPath, { withFileTypes: true });
  } catch {
    // Unreadable folder: skip it quietly
    return;
  }

  // Look at each item in the folder
  for (const entry of entries) {
    // Full path of this item
    const fullPath = join(dirPath, entry.name);

    // Folders: walk into them unless they are on the skip list
    if (entry.isDirectory()) {
      // Skip installed packages, build output, tests and so on
      if (SKIPPED_DIRS.has(entry.name.toLowerCase())) continue;
      // Go one level deeper
      walk(scanRoot, fullPath, depth + 1, files);
      continue;
    }

    // Ignore anything that isn't a normal file (sockets, broken links)
    if (!entry.isFile()) continue;

    // Decide what kind of web file this is, if any
    const type = classifyWebFile(entry.name);
    // Not a web file we care about
    if (type === null) continue;

    // Path relative to the project, with forward slashes, used in reports
    const relativePath = toPosixPath(relative(scanRoot, fullPath));

    // For .env files we record the name only and never read the secrets inside
    if (type === "web-env") {
      // Empty content on purpose
      files.push({ path: relativePath, type, content: "" });
      continue;
    }

    // Read the file's text (skipping files that are too big or unreadable)
    const content = readSmallTextFile(fullPath);
    // Couldn't read it or it was too big
    if (content === null) continue;

    // Remember the file for the rules to check
    files.push({ path: relativePath, type, content });
  }
}

// Work out which web file type a file name belongs to, or null if none
function classifyWebFile(fileName: string): ConfigFileType | null {
  // Lower-case name so ".ENV" and ".env" are treated the same
  const name = fileName.toLowerCase();
  // The file's ending, like ".js"
  const ext = extname(name);

  // The .gitignore file
  if (name === ".gitignore") return "web-gitignore";
  // Real environment files like .env or .env.production
  if (isRealEnvFileName(name)) return "web-env";
  // Minified bundles and TypeScript type files are not hand-written code
  if (name.endsWith(".min.js") || name.endsWith(".d.ts")) return null;
  // Test files contain deliberately unsafe samples
  if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(name)) return null;
  // JavaScript and TypeScript source
  if (CODE_EXTENSIONS.has(ext)) return "web-code";
  // HTML pages
  if (ext === ".html" || ext === ".htm") return "web-html";
  // Anything else is not checked
  return null;
}

/**
 * True for real env files (.env, .env.local, prod.env) and false for
 * safe templates like .env.example, .env.sample or .env.template.
 */
export function isRealEnvFileName(fileName: string): boolean {
  // Lower-case the name for comparison
  const name = basename(fileName).toLowerCase();
  // Template files only hold placeholders, so they're allowed in git
  if (/(example|sample|template|dist|defaults?)$/.test(name)) return false;
  // Matches ".env", ".env.local", ".env.production" and "something.env"
  return name === ".env" || name.startsWith(".env.") || name.endsWith(".env");
}

// Read a text file, but return null if it's too big or can't be read
function readSmallTextFile(fullPath: string): string | null {
  // File reads can fail, so guard them
  try {
    // Skip very large files
    if (statSync(fullPath).size > MAX_FILE_BYTES) return null;
    // Read the file as text
    return readFileSync(fullPath, "utf-8");
  } catch {
    // Unreadable: skip it
    return null;
  }
}

/**
 * Reads git's index file (.git/index) to find secret-looking files that are
 * committed. This needs no git command: the index stores tracked paths as
 * plain text. Returns an empty list when the folder isn't a git repo.
 */
export function readTrackedSensitiveFiles(rootPath: string): ReadonlyArray<string> {
  // Holds the raw bytes of the index file
  let buffer: Buffer;
  // The index may not exist (not a git repo), so guard the read
  try {
    // Read the whole index file
    buffer = readFileSync(join(rootPath, ".git", "index"));
  } catch {
    // Not a git repo: nothing is tracked
    return [];
  }
  // Pull out every tracked path, then keep only the risky ones
  return parseGitIndexPaths(buffer).filter(isSensitiveTrackedPath);
}

/**
 * Lists the file paths stored in a git index. Handles the common index
 * versions 2 and 3; for anything else it falls back to a simple text search.
 */
export function parseGitIndexPaths(buffer: Buffer): ReadonlyArray<string> {
  // A valid index starts with the letters "DIRC" and is at least 12 bytes long
  if (buffer.length < 12 || buffer.toString("latin1", 0, 4) !== "DIRC") return [];
  // Index format version number
  const version = buffer.readUInt32BE(4);
  // How many files the index lists
  const count = buffer.readUInt32BE(8);
  // Version 4 compresses paths, so use the simple text fallback for it
  if (version !== 2 && version !== 3) return fallbackPathSearch(buffer);

  // The paths we read out
  const paths: string[] = [];
  // Entries start right after the 12-byte header
  let offset = 12;
  // Read each entry in turn
  for (let i = 0; i < count; i++) {
    // Each entry has 62 bytes of fixed data before its path
    if (offset + 62 > buffer.length) break;
    // The 2-byte flags field sits at byte 60 of the entry
    const flags = buffer.readUInt16BE(offset + 60);
    // In version 3, an "extended" flag adds 2 more bytes before the path
    const pathStart = offset + 62 + (version === 3 && (flags & 0x4000) !== 0 ? 2 : 0);
    // The path ends at the next zero byte
    const pathEnd = buffer.indexOf(0, pathStart);
    // A broken index: stop reading
    if (pathEnd === -1) break;
    // Save the path as text
    paths.push(buffer.toString("utf-8", pathStart, pathEnd));
    // Entries are padded with zero bytes up to a multiple of 8
    const entryLength = pathEnd - offset + 1;
    // Jump to the start of the next entry
    offset += Math.ceil(entryLength / 8) * 8;
  }
  // Hand back all tracked paths
  return paths;
}

// Simple fallback: look for env-like names anywhere in the index bytes
function fallbackPathSearch(buffer: Buffer): ReadonlyArray<string> {
  // Treat the bytes as plain text
  const text = buffer.toString("latin1");
  // Find things that look like file paths ending in .env names or key files
  // (each path in the index ends with a zero byte, which we split on)
  const matches = text
    .split(String.fromCharCode(0))
    .map((chunk) => chunk.match(/[\w./-]*(?:\.env[\w.-]*|\.pem|\.key|id_rsa)$/)?.[0] ?? "")
    .filter((path) => path !== "");
  // Remove duplicates
  return [...new Set(matches)];
}

/**
 * True when a tracked path is a file that should never be in git:
 * real .env files, private keys and cloud credential files.
 */
export function isSensitiveTrackedPath(path: string): boolean {
  // Just the file name, lower-cased
  const name = basename(path).toLowerCase();
  // Real env files (not .env.example)
  if (isRealEnvFileName(name)) return true;
  // Private key files
  if (name.endsWith(".pem") || name.endsWith(".key") || name === "id_rsa" || name === "id_ed25519") {
    return true;
  }
  // Common cloud credential file names (Google service accounts, Firebase admin keys)
  return /^(credentials|service-?account[\w-]*|serviceaccountkey|firebase-adminsdk[\w-]*)\.json$/.test(name);
}
