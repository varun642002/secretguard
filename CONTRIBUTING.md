# Contributing to secretguard

## Every pattern needs two tests

One proving it catches the real thing, and one proving it does **not** catch the
placeholder, the template variable or the prose that looks like it. A noisy rule
gets the whole plugin disabled, which protects nobody.

```bash
node test/smoke.mjs
```

## The rules of this codebase

1. **No dependencies.**
2. **Fail open.** Bad input, broken config or an internal error must result in
   *allow*, never a crash. The hook runs in the user's critical path.
3. **Say why.** A block that doesn't explain itself gets worked around blindly.
   The message names the file, the reason, and the escape hatch.
4. **Never log the secret.** Not in the deny reason, not in debug output.

## Adding a provider token

`lib/patterns.mjs` → `SECRET_CONTENT`. Anchor with `\b`, require the real
length, and capture the value in group 1 (or set `valueGroup`). Then add both
tests. If the format overlaps something common, add the exception to
`VALUE_ALLOW` instead of loosening the pattern.
