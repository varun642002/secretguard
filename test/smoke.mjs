#!/usr/bin/env node
// Dependency-free tests. Run: node test/smoke.mjs
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { findSecrets, redact, matchSecretPath } from "../lib/patterns.mjs";
import { inspectToolCall, pathsInCommand, segments, stripHeredocs } from "../lib/inspect.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK = join(HERE, "..", "hooks", "pre-tool-use.mjs");

let passed = 0;
let failed = 0;
const check = (name, fn) => {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}\n      ${e.message}`);
    failed++;
  }
};
const ok = (v, m) => {
  if (!v) throw new Error(m || "expected truthy");
};
const eq = (a, b, m) => {
  if (JSON.stringify(a) !== JSON.stringify(b))
    throw new Error(`${m || "mismatch"}: got ${JSON.stringify(a)}, want ${JSON.stringify(b)}`);
};

const blocks = (tool, input) => inspectToolCall({ tool, input }).action === "deny";

console.log("secret paths");

check("recognises secret files", () => {
  for (const p of [
    ".env",
    ".env.production",
    "config/.env.local",
    "~/.ssh/id_rsa",
    "certs/server.pem",
    "key.p12",
    ".aws/credentials",
    ".npmrc",
    ".netrc",
    "terraform.tfstate",
    "secrets.yaml",
    "my-service-account.json",
  ]) {
    ok(matchSecretPath(p), `should flag ${p}`);
  }
});

check("does NOT flag safe lookalikes", () => {
  for (const p of [
    ".env.example",
    ".env.sample",
    ".env.template",
    ".ssh/known_hosts",
    "src/index.js",
    "README.md",
    "package.json",
    "environment.ts",
    "keyboard.css",
  ]) {
    eq(matchSecretPath(p), null, `should allow ${p}`);
  }
});

console.log("secret content");

check("finds real credential shapes", () => {
  // Assembled at runtime, never written as literals: a file containing real-
  // shaped tokens trips GitHub push protection and every other secret scanner.
  // (secretguard was itself blocked by this on its first push.)
  const J = (...p) => p.join("");
  const samples = [
    [J("AKIA", "IOSFODNN7EXAMPLE"), "AWS access key id"],
    [J("ghp", "_", "1234567890abcdefghijklmnopqrstuvwx"), "GitHub token"],
    [J("sk-", "ant-", "api03-abcdefghijklmnopqrstuvwxyz123"), "Anthropic API key"],
    [J("xoxb", "-123456789012-abcdefghijkl"), "Slack token"],
    [J("sk", "_live_", "abcdefghijklmnopqrstuvwx"), "Stripe key"],
    [J("AIza", "SyA1234567890abcdefghijklmnopqrstuv"), "Google API key"],
    [J("npm", "_", "abcdefghijklmnopqrstuvwxyz0123456789"), "npm token"],
  ];
  for (const [value, name] of samples) {
    const hits = findSecrets(`token = "${value}"`);
    ok(hits.some((h) => h.name === name || h.value === value), `missed ${name}`);
  }
});

check("finds a private key block", () => {
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
  ok(findSecrets(pem).length, "missed PEM");
});

check("finds a password in a connection string", () => {
  ok(findSecrets("postgres://user:hunter2abc@host:5432/db").length, "missed db password");
});

check("finds an assigned secret", () => {
  ok(findSecrets('DATABASE_PASSWORD="s0meRealLooking"').length, "missed assignment");
});

console.log("false positives (the ones that matter)");

check("ignores placeholders and templates", () => {
  for (const s of [
    'API_KEY="your-api-key-here"',
    'SECRET="changeme"',
    'TOKEN="xxxxxxxxxxxx"',
    'PASSWORD="<your password>"',
    'API_KEY="${API_KEY}"',
    'SECRET="{{ secret }}"',
    "API_KEY = process.env.API_KEY",
    'TOKEN="example"',
    'PASSWORD="REDACTED"',
  ]) {
    eq(findSecrets(s).length, 0, `false positive on: ${s}`);
  }
});

check("ignores short values and plain numbers", () => {
  eq(findSecrets('TOKEN="abc"').length, 0, "short");
  eq(findSecrets("TIMEOUT_SECRET=12345678").length, 0, "numeric");
});

check("ignores TypeScript that merely mentions token or secret", () => {
  // Every one of these was a real false positive found by scanning a live
  // TypeScript repo: 50 hits across 1640 files, all of them code.
  for (const s of [
    "async function loadProfile(uid: string, email: string, idToken: string): Promise<View>",
    "const tokens = tokenise(raw).filter((t) => t !== '|');",
    "export function parseNumberToken(token: string): number | null {",
    "const anyIn = (tokens: string[], list: string[]) => tokens.some(",
    "const token = String(req.query.token || '');",
    "const [doc] = await db.select({ token: documents.token }).from(documents)",
    "export function parsePayToken(rawToken: string): { source: PaySource; id: string }",
    "# GEMINI_API_KEY: required for Gemini AI API calls.",
    "interface Props { accessToken: string; refreshToken: string }",
    "let apiKey: string | undefined = undefined;",
  ]) {
    eq(findSecrets(s).length, 0, `false positive on: ${s}`);
  }
});

check("still catches an env-style assignment with a real value", () => {
  ok(findSecrets('DATABASE_PASSWORD="hunter2RealValue"').length, "missed UPPER_SNAKE secret");
  ok(findSecrets("STRIPE_SECRET_KEY=abcdefghijklmnop").length, "missed unquoted");
  ok(findSecrets('API_KEY: "s0meRealLookingValue"').length, "missed colon form");
});

check("ignores ordinary prose and code", () => {
  for (const s of [
    "the secret sauce is good documentation",
    "function getToken() { return fetch('/token') }",
    "# Password reset flow",
    "import { SECRET_KEY } from './config'",
  ]) {
    eq(findSecrets(s).length, 0, `false positive on: ${s}`);
  }
});

console.log("redaction");

check("removes the value but keeps a hint", () => {
  const gh = ["ghp", "_", "1234567890abcdefghijklmnopqrstuvwx"].join("");
  const { text } = redact(`key = "${gh}"`);
  ok(!text.includes("1234567890abcdefghijklmnopqrstuvwx"), "secret survived");
  ok(text.includes("REDACTED"), "no marker");
  ok(text.includes("ghp_"), "lost all context");
});

check("leaves clean text untouched", () => {
  const t = "nothing to see here";
  eq(redact(t).text, t, "changed clean text");
});

check("redacts every occurrence", () => {
  const v = ["sk-", "ant-", "api03-abcdefghijklmnopqrstuvwxyz123"].join("");
  const { text } = redact(`a ${v} b ${v}`);
  ok(!text.includes(v), "a copy survived");
});

console.log("tool inspection");

check("blocks reading a secret file", () => ok(blocks("Read", { file_path: ".env" })));
check("allows reading a normal file", () => ok(!blocks("Read", { file_path: "src/app.js" })));
check("allows .env.example", () => ok(!blocks("Read", { file_path: ".env.example" })));

check("blocks shell commands that print secrets", () => {
  ok(blocks("Bash", { command: "cat .env" }), "cat .env");
  ok(blocks("Bash", { command: "cat ~/.ssh/id_rsa" }), "cat key");
  ok(blocks("Bash", { command: "head -5 secrets.json" }), "head secrets");
  ok(blocks("Bash", { command: "printenv | grep KEY" }), "env dump");
});

check("a reader elsewhere does not implicate an unrelated path", () => {
  // Both of these were real over-blocks hit while using the plugin: the
  // command only inspects git metadata, but contained `head`/`cat` in another
  // segment and the word .env somewhere else.
  ok(!blocks("Bash", { command: "git ls-files --error-unmatch .env; git log | head -4" }), "git + head");
  ok(!blocks("Bash", { command: "git check-ignore -v .env && ls | head -2" }), "check-ignore + head");
  ok(!blocks("Bash", { command: "echo .env >> .gitignore" }), "writing the name, not reading");
});

check("a heredoc body is data, not a file read", () => {
  // Writing a commit message that merely mentions .env was blocked, because
  // the command contained `cat <<EOF` and the word .env.
  const cmd = "git commit -m \"$(cat <<'EOF'\nThe sixth finding was .env, already ignored.\nEOF\n)\"";
  ok(!blocks("Bash", { command: cmd }), "heredoc mentioning .env");
});

check("still blocks a reader actually pointed at a secret", () => {
  ok(blocks("Bash", { command: "cat .env" }), "cat .env");
  ok(blocks("Bash", { command: "git status && cat .env" }), "second segment");
  ok(blocks("Bash", { command: "cat .env | grep KEY" }), "piped");
  ok(blocks("Bash", { command: "head -5 ~/.ssh/id_rsa" }), "head on a key");
});

check("allows ordinary shell commands", () => {
  for (const c of ["ls -la", "cat README.md", "git status", "npm test", "grep -r TODO src/"]) {
    ok(!blocks("Bash", { command: c }), `blocked: ${c}`);
  }
});

check("blocks writing a credential into a file", () => {
  const stripe = ["sk", "_live_", "abcdefghijklmnopqrst"].join("");
  ok(blocks("Write", { content: `STRIPE="${stripe}"` }), "write secret");
});

check("allows writing a variable reference", () => {
  ok(!blocks("Write", { content: "const k = process.env.STRIPE_KEY" }), "env ref");
});

check("respects allowPaths config", () => {
  const r = inspectToolCall({
    tool: "Read",
    input: { file_path: "fixtures/.env" },
    config: { allowPaths: ["fixtures/"] },
  });
  eq(r.action, "allow", "allowPaths ignored");
});

check("extracts paths from a command", () => {
  const p = pathsInCommand("cat ./config/.env > out.txt");
  ok(p.some((x) => x.includes(".env")), "missed the path");
});

console.log("hook behaviour");

const runHook = (payload, env = {}) =>
  execFileSync(process.execPath, [HOOK], {
    input: typeof payload === "string" ? payload : JSON.stringify(payload),
    encoding: "utf8",
    env: { ...process.env, ...env },
  });

check("denies a secret read, with a reason", () => {
  const out = JSON.parse(runHook({ tool_name: "Read", tool_input: { file_path: ".env" } }));
  eq(out.hookSpecificOutput.permissionDecision, "deny", "decision");
  ok(out.hookSpecificOutput.permissionDecisionReason.includes(".env"), "reason names the file");
});

check("allows a normal read", () => {
  const out = JSON.parse(runHook({ tool_name: "Read", tool_input: { file_path: "a.js" } }));
  eq(out.hookSpecificOutput.permissionDecision, "allow", "decision");
});

check("garbage input allows rather than crashing", () => {
  const out = JSON.parse(runHook("this is not json"));
  eq(out.hookSpecificOutput.permissionDecision, "allow", "should fail open, not crash");
});

check("empty input allows", () => {
  eq(JSON.parse(runHook("")).hookSpecificOutput.permissionDecision, "allow");
});

check("SECRETGUARD=0 disables it", () => {
  const out = JSON.parse(
    runHook({ tool_name: "Read", tool_input: { file_path: ".env" } }, { SECRETGUARD: "0" })
  );
  eq(out.hookSpecificOutput.permissionDecision, "allow", "kill switch");
});

check("SECRETGUARD=warn allows but warns", () => {
  const out = JSON.parse(
    runHook({ tool_name: "Read", tool_input: { file_path: ".env" } }, { SECRETGUARD: "warn" })
  );
  eq(out.hookSpecificOutput.permissionDecision, "allow", "warn mode should allow");
});

check("an unknown tool is left alone", () => {
  const out = JSON.parse(runHook({ tool_name: "WebFetch", tool_input: { url: "https://x.com" } }));
  eq(out.hookSpecificOutput.permissionDecision, "allow");
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
