#!/usr/bin/env node
// secretguard CLI — audit a tree, or test the rules against a string.
import { readdirSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";
import { scanFile, loadConfig, inspectToolCall } from "../lib/inspect.mjs";
import { redact, findSecrets } from "../lib/patterns.mjs";

const argv = process.argv.slice(2);
const cmd = argv[0] && !argv[0].startsWith("-") ? argv[0] : "scan";
const rest = argv.slice(argv[0] && !argv[0].startsWith("-") ? 1 : 0);
const has = (f) => argv.includes(f);

if (has("--help") || has("-h") || cmd === "help") {
  console.log(`secretguard — stop credentials reaching Claude's context

usage:
  secretguard scan [dir]      audit a tree for secrets and secret files
  secretguard check <text>    test the rules against a string
  secretguard redact <text>   print the string with secrets removed
  secretguard test            show what would be blocked, with examples

options:
  --quiet     only print findings
  --json      machine-readable output

exit codes: 0 clean, 1 findings, 2 usage error`);
  process.exit(0);
}

const IGNORE = new Set(["node_modules", ".git", "dist", "build", ".next", "vendor", "__pycache__"]);

if (cmd === "check" || cmd === "redact") {
  const text = rest.filter((a) => !a.startsWith("--")).join(" ");
  if (!text) {
    console.error("secretguard: nothing to check");
    process.exit(2);
  }
  const hits = findSecrets(text);
  if (cmd === "redact") {
    console.log(redact(text).text);
    process.exit(hits.length ? 1 : 0);
  }
  if (has("--json")) {
    console.log(JSON.stringify({ findings: hits.map((h) => ({ type: h.name })) }, null, 2));
  } else if (!hits.length) {
    console.log("clean — nothing that looks like a credential");
  } else {
    for (const h of hits) console.log(`  ! ${h.name}`);
  }
  process.exit(hits.length ? 1 : 0);
}

if (cmd === "test") {
  const cases = [
    ["Read", { file_path: ".env" }],
    ["Read", { file_path: ".env.example" }],
    ["Bash", { command: "cat ~/.ssh/id_rsa" }],
    ["Bash", { command: "cat README.md" }],
    ["Bash", { command: "printenv | grep API" }],
    ["Write", { content: `STRIPE_SECRET="${["sk", "_live_", "abcdefghij1234567890"].join("")}"` }],
    ["Write", { content: 'API_KEY = process.env.API_KEY' }],
    ["Read", { file_path: "src/index.js" }],
  ];
  console.log();
  for (const [tool, input] of cases) {
    const r = inspectToolCall({ tool, input });
    const label = `${tool}(${JSON.stringify(input).slice(0, 52)})`;
    console.log(`  ${r.action === "deny" ? "BLOCK " : "allow "} ${label}`);
  }
  console.log();
  process.exit(0);
}

// scan
const root = rest.find((a) => !a.startsWith("--")) || ".";
if (!existsSync(root)) {
  console.error(`secretguard: no such directory: ${root}`);
  process.exit(2);
}
const config = loadConfig(root);
const results = [];
let files = 0;

// allowPaths from .secretguard.json also applies here, so a repo can exclude
// its own fixtures and example tokens and still get a clean scan in CI.
const allowPaths = (config.allowPaths || []).map((p) => new RegExp(p, "i"));
const allowed = (p) => allowPaths.some((re) => re.test(p.replace(/\\/g, "/")));
let skipped = 0;

const walk = (dir, depth = 0) => {
  if (depth > 12) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (IGNORE.has(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, depth + 1);
    else {
      const rel = relative(root, p) || p;
      if (allowed(rel)) {
        skipped++;
        continue;
      }
      files++;
      const r = scanFile(p, config);
      if (r.pathHit || r.secrets.length) results.push(r);
    }
  }
};
walk(root);

if (has("--json")) {
  console.log(
    JSON.stringify(
      {
        scanned: files,
        findings: results.map((r) => ({
          path: relative(root, r.path),
          secretFile: r.pathHit || null,
          secrets: [...new Set(r.secrets.map((s) => s.name))],
        })),
      },
      null,
      2
    )
  );
  process.exit(results.length ? 1 : 0);
}

console.log();
if (!results.length) {
  const sk = skipped ? `, ${skipped} allowlisted` : "";
  console.log(`  clean — ${files} file(s) scanned${sk}, nothing credential-shaped\n`);
  process.exit(0);
}
for (const r of results) {
  const rel = relative(root, r.path) || r.path;
  if (r.pathHit) console.log(`  ! ${rel}\n      ${r.pathHit} — contents are secret by nature`);
  const kinds = [...new Set(r.secrets.map((s) => s.name))];
  if (kinds.length) {
    if (!r.pathHit) console.log(`  ! ${rel}`);
    for (const k of kinds) console.log(`      ${k}`);
  }
}
console.log(`\n  ${results.length} file(s) with findings, ${files} scanned`);
console.log(`  these are blocked from Claude's context while secretguard is installed\n`);
process.exit(1);
