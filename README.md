<div align="center">

# 🛡️ secretguard

### Stop Claude Code reading your secrets

*Everything Claude reads is written to a transcript on disk. Keep credentials out of it.*

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-D97757)](https://claude.com/claude-code)
[![Dependencies](https://img.shields.io/badge/dependencies-0-blue.svg)](package.json)
[![Tests](https://img.shields.io/badge/tests-28-success.svg)](test/smoke.mjs)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

## 😬 The problem

Ask Claude to debug your config and it reads `.env`. Reasonable — except that
file now lives in a transcript in `~/.claude/projects`, in plain text, forever.
Memory tools summarise those transcripts. Backups copy them. Support bundles
include them.

One `cat .env` and your production database password is in three places you
weren't thinking about.

## ✨ The fix

A `PreToolUse` hook that inspects every tool call **before** it runs and blocks
the ones that would pull credentials into context.

```text
⛔ secretguard blocked this: it would put credentials into the transcript.

  • .env — dotenv, read

Anything read into a session is written to the transcript on disk and may be
summarised by other tools. Ask the user for the value, read a redacted copy,
or reference the variable by name instead.

If this is a false positive, add the path to allowPaths in .secretguard.json.
```

Claude sees that message, understands why, and works around it instead of
retrying.

## 🚀 Install

```bash
claude plugin marketplace add varun642002/secretguard
```

```bash
claude plugin install secretguard@secretguard
```

Open a new session and it's active. Free, MIT, nothing phones home.

## 🔍 What it blocks

| | Blocked | Allowed |
|---|---|---|
| **Files** | `.env`, `.env.production`, `id_rsa`, `*.pem`, `*.p12`, `.aws/credentials`, `.npmrc`, `.netrc`, `*.tfstate`, `secrets.yaml`, `*service-account.json` | `.env.example`, `.env.sample`, `.env.template`, `known_hosts`, ordinary source |
| **Commands** | `cat .env`, `head secrets.json`, `printenv \| grep KEY` | `cat README.md`, `ls`, `git status`, `npm test` |
| **Writes** | A real `sk_live_…`, `ghp_…`, `AKIA…` or password being written into a file | `process.env.API_KEY`, `${SECRET}`, `your-key-here`, `changeme` |

Content detection covers AWS, GitHub, Anthropic, OpenAI, Slack, Stripe, Google,
Twilio, SendGrid and npm tokens, JWTs, PEM private key blocks, database
connection-string passwords, and generic `SECRET=`/`PASSWORD=` assignments.

## 🧪 Try it before trusting it

```bash
npx github:varun642002/secretguard test
```

```text
  BLOCK  Read({"file_path":".env"})
  allow  Read({"file_path":".env.example"})
  BLOCK  Bash({"command":"cat ~/.ssh/id_rsa"})
  allow  Bash({"command":"cat README.md"})
  BLOCK  Bash({"command":"printenv | grep API"})
  BLOCK  Write({"content":"STRIPE_SECRET=\"sk_live_…\""})
  allow  Write({"content":"API_KEY = process.env.API_KEY"})
  allow  Read({"file_path":"src/index.js"})
```

Audit a repo for what's already exposed:

```bash
npx github:varun642002/secretguard scan .
```

Check or clean a single string:

```bash
npx github:varun642002/secretguard check "token=ghp_abc123..."
```

```bash
npx github:varun642002/secretguard redact "$(cat some-log.txt)"
```

Exit codes: `0` clean, `1` findings, `2` usage error — so `scan` works in CI.

## 🔧 Configuration

Drop a `.secretguard.json` in your project root:

```json
{
  "allowPaths": ["fixtures/", "test/data/.env.test"],
  "extraPatterns": [
    { "name": "internal token", "re": "\\bacme_[a-z0-9]{32}\\b" }
  ]
}
```

| Variable | Effect |
|---|---|
| `SECRETGUARD=0` | Disable entirely |
| `SECRETGUARD=warn` | Allow, but print the warning — good for a trial run |

## ⚠️ What this is and isn't

> [!IMPORTANT]
> **This reduces accidental exposure; it is not a security boundary.** It
> pattern-matches. A credential in an unusual format, or in a file with an
> unexpected name, gets through. Don't let it replace a secret manager, and
> don't treat a clean `scan` as proof a repo is safe to open-source.

> [!NOTE]
> **It fails open, deliberately.** Malformed input, a broken config or an
> internal error all result in *allow*, never a crash. A security tool that
> breaks your session gets uninstalled, and then it protects nothing. The
> trade-off is explicit: availability over enforcement.

**False positives are cheap, false negatives aren't.** The rules lean towards
blocking. When one gets in your way, `allowPaths` takes one line — and please
open an issue, because a bad rule affects everyone.

## 🤝 Contributing

New patterns are the most useful contribution — see [CONTRIBUTING.md](CONTRIBUTING.md).
Every pattern needs a test for what it catches **and** a test for what it must
not catch.

- [ ] More provider token formats
- [ ] Entropy-based detection for unknown formats
- [ ] A `PostToolUse` pass that redacts what slipped through
- [ ] `--staged` mode for a pre-commit hook

## 📄 License

[MIT](LICENSE)
