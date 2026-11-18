#!/usr/bin/env node
// PreToolUse: deny tool calls that would pull credentials into the transcript.
//
// Nothing here may throw. A hook that crashes disrupts the user's session, and
// a security tool that breaks the thing it protects gets uninstalled.
import { inspectToolCall, loadConfig } from "../lib/inspect.mjs";

let input = {};
try {
  input = JSON.parse((await readStdin()) || "{}") || {};
} catch {
  /* unparseable payload: allow, and stay out of the way */
}

if (process.env.SECRETGUARD === "0") allow();

let result;
try {
  const config = loadConfig(input.cwd || process.cwd());
  result = inspectToolCall({
    tool: input.tool_name || "",
    input: input.tool_input || {},
    config,
  });
} catch {
  allow();
}

if (!result || result.action !== "deny") allow();

// Warn-only mode: let it through, but say so loudly.
if (process.env.SECRETGUARD === "warn") {
  process.stderr.write(result.reason + "\n");
  allow();
}

process.stdout.write(
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: result.reason,
    },
    systemMessage: result.reason,
  })
);
process.exit(0);

function allow() {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" },
    })
  );
  process.exit(0);
}

function readStdin() {
  return new Promise((res) => {
    let d = "";
    if (process.stdin.isTTY) return res("");
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (d += c));
    process.stdin.on("end", () => res(d));
    setTimeout(() => res(d), 5000).unref?.();
  });
}
