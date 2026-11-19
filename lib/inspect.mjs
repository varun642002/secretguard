// Decide whether a tool call is about to pull a secret into context.
import { readFileSync, existsSync, statSync } from "node:fs";
import { matchSecretPath, findSecrets } from "./patterns.mjs";

/** Shell commands that print file contents. */
const READERS = /^(cat|bat|less|more|head|tail|type|strings|xxd|od|nl|tac)$/;
/**
 * `env` / `printenv` / `set` only count as a dump when they are the command
 * being run. Matching the substring anywhere flagged `echo .env >> .gitignore`,
 * because "env" inside ".env" was followed by ">".
 */
const ENV_DUMP_CMDS = /^(env|printenv|set)$/;

/**
 * Remove heredoc bodies from a command.
 *
 * A commit message or script written with `cat <<'EOF' … EOF` is DATA, not a
 * command reading a file. Without this, writing a commit message that merely
 * mentions .env was blocked, because the command contained both `cat` and the
 * word `.env`.
 */
export function stripHeredocs(cmd) {
  return String(cmd || "").replace(
    /<<-?\s*(['"]?)([A-Za-z_][\w]*)\1[\s\S]*?^\s*\2\s*$/gm,
    "<<HEREDOC"
  );
}

/**
 * Split a command into the segments the shell would run separately, so a
 * reader in one segment does not implicate a path mentioned in another.
 */
export function segments(cmd) {
  return stripHeredocs(cmd)
    .split(/\|\||&&|[|;\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** The leading command word of a segment, ignoring env assignments. */
function leadWord(seg) {
  const words = seg.split(/\s+/).filter(Boolean);
  for (const w of words) {
    if (/^[A-Za-z_][\w]*=/.test(w)) continue; // VAR=value prefix
    return w.replace(/^.*[/\\]/, "").toLowerCase();
  }
  return "";
}

/**
 * Pull candidate file paths out of a shell command segment.
 * Deliberately loose: a path that is not a secret costs nothing to check.
 */
export function pathsInCommand(cmd) {
  if (!cmd) return [];
  const out = [];
  const re = /(?:^|[\s"'=<>|&;])((?:~|\.{0,2}\/|[A-Za-z]:[\\/])?[\w.\-/\\]*\.?[\w.\-]+)/g;
  let m;
  while ((m = re.exec(cmd))) {
    const p = m[1];
    if (p && p.length > 2 && !p.startsWith("-")) out.push(p);
  }
  return out;
}

/** Paths that a reader command in this command would actually print. */
export function pathsBeingRead(cmd) {
  const out = [];
  for (const seg of segments(cmd)) {
    if (!READERS.test(leadWord(seg))) continue;
    out.push(...pathsInCommand(seg.replace(/^\S+/, "")));
  }
  return out;
}

/**
 * Inspect one tool call.
 * Returns { action: "allow"|"deny", reason, findings }.
 */
export function inspectToolCall({ tool, input = {}, config = {} }) {
  const findings = [];
  const extra = config.extraPatterns || [];
  const allowPaths = (config.allowPaths || []).map((p) => new RegExp(p, "i"));
  const allowed = (p) => allowPaths.some((re) => re.test(p));

  const notePath = (p, why) => {
    if (!p || allowed(p)) return;
    const hit = matchSecretPath(p);
    if (hit) findings.push({ kind: "path", path: p, what: hit, why });
  };

  // --- reading a file directly
  if (tool === "Read" || tool === "NotebookRead") {
    notePath(input.file_path || input.notebook_path, "read");
  }

  // --- writing a secret INTO a tracked file is also worth stopping
  if (tool === "Write" || tool === "Edit" || tool === "MultiEdit") {
    const body = [input.content, input.new_string, input.old_string]
      .filter((x) => typeof x === "string")
      .join("\n");
    for (const s of findSecrets(body, extra)) {
      findings.push({ kind: "content", what: s.name, why: "written into a file", value: s.value });
    }
  }

  // --- a shell command that would print one
  if (tool === "Bash" || tool === "PowerShell") {
    const cmd = input.command || "";
    const body = stripHeredocs(cmd);
    if (segments(cmd).some((s) => ENV_DUMP_CMDS.test(leadWord(s)))) {
      findings.push({ kind: "command", what: "environment dump", why: "would print every variable" });
    }
    // Only paths a reader command would actually print — not every path that
    // happens to appear somewhere in the command line.
    for (const p of pathsBeingRead(cmd)) notePath(p, "printed by a shell command");
    // Heredoc bodies are stripped: a credential pasted into one is still
    // caught by the Write/Edit rules when it lands in a file.
    for (const s of findSecrets(body, extra)) {
      findings.push({ kind: "content", what: s.name, why: "inline in a command", value: s.value });
    }
  }

  // --- grep/glob over a secret file
  if (tool === "Grep" || tool === "Glob") {
    notePath(input.path, "searched");
  }

  if (!findings.length) return { action: "allow", findings };

  return {
    action: "deny",
    reason: explain(findings),
    findings,
  };
}

export function explain(findings) {
  const lines = ["secretguard blocked this: it would put credentials into the transcript.", ""];
  const seen = new Set();
  for (const f of findings) {
    const key = `${f.kind}|${f.what}|${f.path || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (f.kind === "path") lines.push(`  • ${f.path} — ${f.what}, ${f.why}`);
    else lines.push(`  • ${f.what} — ${f.why}`);
  }
  lines.push(
    "",
    "Anything read into a session is written to the transcript on disk and may be",
    "summarised by other tools. Ask the user for the value, read a redacted copy,",
    "or reference the variable by name instead.",
    "",
    "If this is a false positive, add the path to allowPaths in .secretguard.json."
  );
  return lines.join("\n");
}

/** Scan a file on disk. Used by the CLI, not the hook. */
export function scanFile(path, config = {}) {
  const out = { path, pathHit: matchSecretPath(path), secrets: [] };
  try {
    if (!existsSync(path) || statSync(path).size > 2_000_000) return out;
    const text = readFileSync(path, "utf8");
    out.secrets = findSecrets(text, config.extraPatterns || []);
  } catch {
    /* unreadable or binary: nothing to report */
  }
  return out;
}

export function loadConfig(dir = process.cwd()) {
  for (const name of [".secretguard.json", ".secretguard"]) {
    const p = `${dir}/${name}`;
    if (!existsSync(p)) continue;
    try {
      const parsed = JSON.parse(readFileSync(p, "utf8"));
      if (!parsed || typeof parsed !== "object") throw new Error("not an object");
      return parsed;
    } catch (e) {
      // A broken config must never disable protection — but failing silently
      // leaves the user believing an allowlist applies when it does not.
      process.stderr.write(`secretguard: ignoring ${name} — ${e.message}\n`);
      return {};
    }
  }
  return {};
}
