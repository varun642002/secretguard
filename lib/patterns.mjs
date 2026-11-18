// What counts as a secret.
//
// Two independent signals: the PATH being read, and the CONTENT coming back.
// Path rules are cheap and catch the obvious cases; content rules catch a key
// pasted into a README. Both are conservative on purpose — a false positive
// costs a redacted line, a false negative leaks a credential into a transcript.

/** Files whose whole contents are secret by nature. */
export const SECRET_PATHS = [
  { name: "dotenv", re: /(^|[/\\])\.env(\.[\w.-]+)?$/i },
  { name: "private key", re: /(^|[/\\])(id_rsa|id_dsa|id_ecdsa|id_ed25519)$/i },
  { name: "pem/key file", re: /\.(pem|key|pfx|p12|jks|keystore)$/i },
  { name: "aws credentials", re: /(^|[/\\])\.aws[/\\](credentials|config)$/i },
  { name: "ssh config", re: /(^|[/\\])\.ssh[/\\](?!known_hosts|config$)/i },
  { name: "kube config", re: /(^|[/\\])\.kube[/\\]config$/i },
  { name: "npm auth", re: /(^|[/\\])\.npmrc$/i },
  { name: "pypi auth", re: /(^|[/\\])\.pypirc$/i },
  { name: "netrc", re: /(^|[/\\])\.netrc$/i },
  { name: "docker auth", re: /(^|[/\\])\.docker[/\\]config\.json$/i },
  { name: "gcloud credentials", re: /application_default_credentials\.json$/i },
  { name: "service account key", re: /(^|[/\\])[\w-]*service[-_]?account[\w-]*\.json$/i },
  { name: "terraform state", re: /\.tfstate(\.backup)?$/i },
  { name: "secrets file", re: /(^|[/\\])(secrets?|credentials?)\.(json|ya?ml|toml|ini)$/i },
];

/** Paths that LOOK secret but are safe and common — checked first. */
export const PATH_ALLOW = [
  /\.env\.example$/i,
  /\.env\.sample$/i,
  /\.env\.template$/i,
  /\.env\.schema$/i,
  /(^|[/\\])\.ssh[/\\]known_hosts$/i,
  /\.pem\.example$/i,
];

/**
 * Content patterns. `redact` replaces the captured secret, keeping enough
 * context that the model still understands the shape of what it read.
 */
export const SECRET_CONTENT = [
  { name: "AWS access key id", re: /\b((?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16})\b/g },
  { name: "AWS secret access key", re: /\b(?:aws_secret_access_key|aws_secret)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi },
  { name: "private key block", re: /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/g },
  { name: "GitHub token", re: /\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,})\b/g },
  { name: "Anthropic API key", re: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g },
  { name: "OpenAI API key", re: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b/g },
  { name: "Slack token", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g },
  { name: "Stripe key", re: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b/g },
  { name: "Google API key", re: /\b(AIza[A-Za-z0-9_-]{35})\b/g },
  { name: "Twilio key", re: /\b(SK[0-9a-fA-F]{32})\b/g },
  { name: "SendGrid key", re: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g },
  { name: "npm token", re: /\b(npm_[A-Za-z0-9]{36})\b/g },
  { name: "JSON Web Token", re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
  { name: "connection string password", re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:([^\s@/]{3,})@/gi },
  {
    name: "assigned secret",
    // KEY = "value" where the key name says secret and the value looks real.
    re: /\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CLIENT_?SECRET)[A-Z0-9_]*)\s*[=:]\s*["']?([^\s"'`,;]{8,})["']?/gi,
    valueGroup: 2,
  },
];

/** Values that match a pattern but are obviously not real credentials. */
export const VALUE_ALLOW = [
  /^(?:x{3,}|\*{3,}|\.{3,}|-{3,})$/i,
  /^(?:your|my|the)[-_]?/i,
  /^(?:changeme|placeholder|example|sample|dummy|test|fake|redacted|none|null|undefined|true|false)$/i,
  /^<[^>]+>$/,
  /^\$\{?[A-Z0-9_]+\}?$/,
  /^\{\{.*\}\}$/,
  /^(?:process\.env|os\.environ|import\.meta\.env)\b/,
  /^[0-9]+$/,
];

export function isAllowedPath(p) {
  return PATH_ALLOW.some((re) => re.test(p));
}

export function matchSecretPath(p) {
  if (!p || isAllowedPath(p)) return null;
  const hit = SECRET_PATHS.find((s) => s.re.test(p));
  return hit ? hit.name : null;
}

function allowedValue(v) {
  if (!v) return true;
  const s = String(v).trim();
  if (s.length < 8) return true;
  return VALUE_ALLOW.some((re) => re.test(s));
}

/**
 * Find secrets in text.
 * Returns [{ name, value, index }], each value a real-looking credential.
 */
export function findSecrets(text, extra = []) {
  if (!text) return [];
  const found = [];
  for (const p of [...SECRET_CONTENT, ...extra]) {
    const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
    let m;
    while ((m = re.exec(text))) {
      const g = p.valueGroup || 1;
      const value = m[g];
      if (!value || allowedValue(value)) continue;
      found.push({ name: p.name, value, index: m.index });
      if (found.length > 200) return found;
    }
  }
  return found;
}

/** Replace every secret value, keeping a short prefix so it stays identifiable. */
export function redact(text, extra = []) {
  const hits = findSecrets(text, extra);
  if (!hits.length) return { text, hits };
  let out = text;
  // Longest first, so a short value inside a longer one cannot corrupt it.
  for (const v of [...new Set(hits.map((h) => h.value))].sort((a, b) => b.length - a.length)) {
    const head = v.length > 12 ? v.slice(0, 4) : "";
    out = out.split(v).join(`${head}…[REDACTED by secretguard]`);
  }
  return { text: out, hits };
}
