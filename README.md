# 🔍 CitrusGlaze Scan

**How many secrets have you leaked to AI? Find out in 15 seconds.**

We scanned one developer's AI chat history. **169 secrets in 30 days.** AWS keys, private keys, database passwords — all sent to AI providers in prompts.

**100% local. No data leaves your machine. Zero dependencies.**

## Install & Run

```bash
pip3 install citrusglaze-scan
python3 -m citrusglaze_scan
```

Or with [pipx](https://pipx.pypa.io/) (no install needed):

```bash
pipx run citrusglaze-scan
```

That's it. Results in 15 seconds.

## What It Finds

| Severity | What | Examples |
|----------|------|---------|
| 🔴 Critical | Cloud credentials, private keys, DB passwords | `AKIA...`, `-----BEGIN RSA PRIVATE KEY-----`, `postgresql://admin:pass@prod` |
| 🟠 High | API tokens, service keys | `ghp_...`, `sk-proj-...`, `sk_live_...`, `xoxb-...` |
| 🟡 Medium | JWTs, generic secrets | `eyJ...`, high-entropy strings |

**200+ detection patterns** covering AWS, OpenAI, Anthropic, GitHub, Stripe, Slack, Google, Azure, database URIs, private keys, and more.

## What It Scans

| Tool | What we check |
|------|--------------|
| **Claude Code** | `~/.claude/` conversations and project histories |
| **Cursor** | `~/.cursor/` and `~/Library/Application Support/Cursor/` |
| **GitHub Copilot** | `~/Library/Application Support/GitHub Copilot Chat/` |
| **Continue.dev** | `~/.continue/` sessions |
| **Windsurf** | `~/.windsurf/` and `~/.codeium/` |
| **Aider** | `~/.aider/` chat logs |
| **Shell history** | `~/.zsh_history`, `~/.bash_history`, `~/.zshrc` |

## CLI Options

```bash
python3 -m citrusglaze_scan                      # All tools, last 30 days
python3 -m citrusglaze_scan --tool claude        # Only Claude Code
python3 -m citrusglaze_scan --days 7             # Last 7 days
python3 -m citrusglaze_scan --days 0             # All time
python3 -m citrusglaze_scan --json               # Machine-readable output
python3 -m citrusglaze_scan --verbose            # Show file paths
python3 -m citrusglaze_scan --path /some/dir     # Scan any directory
```

## Privacy

- **Zero network calls.** Never connects to the internet.
- **No telemetry.** Nothing collected or transmitted.
- **Secrets are redacted** in output — first 4 chars shown, rest masked.
- **Open source.** Read every line: [GitHub](https://github.com/pierretokns/citrusglaze/tree/main/tools/secret-scanner)

## Stop Future Leaks

This scanner finds secrets **after** they've been sent. To catch them **before** they reach AI providers:

**[CitrusGlaze](https://citrusglaze.dev/go/pypi)** is a local MITM proxy that scans every AI request in real-time. 210+ secret patterns. Blocks critical secrets. Redacts the rest. Works with 39+ AI tools.

→ **[Read the State of AI Traffic Report](https://citrusglaze.dev/go/report)** — what 26,000+ intercepted AI requests reveal about leaked secrets.

→ **[Install CitrusGlaze](https://citrusglaze.dev/go/pypi)** — 5-minute setup, no cloud, data never leaves your machine.

## Zero Dependencies

Python standard library only. No pip dependencies. Works on Python 3.9+.

## License

MIT
