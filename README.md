# secrethunter2

**Secret & Credential Scanner for Bug Bounty Recon** — detects 448 token/credential patterns across web responses, JS bundles, and local files.

```
 _____                     _   _   _             _
/  ___|                   | | | | | |           | |
\ '--.  ___  ___ _ __ ___| |_| |_| |_   _ _ __ | |_ ___ _ __
 '--. \/ _ \/ __| '__/ _ \ __|  _  | | | | '_ \| __/ _ \ '__|
/\__/ /  __/ (__| | |  __/ |_| | | | |_| | | | | ||  __/ |
\____/ \___|\___|_|  \___|\__\_| |_/\__,_|_| |_|\__\___|_|
```

## Features

- **448 verified patterns** — AWS, GCP, Azure, OpenAI, Anthropic, NVIDIA, Alibaba, Tencent, Discord, Slack, Stripe, JWT, private keys, DBURIs, and 150+ more
- **JS bundle follower** (`--js-crawl N`) — follow same-host `<script src>` and scan the bundles where frontend secrets actually live
- **Obfuscated-layer decode** — `\x`/`\u` escapes, `String.fromCharCode`, base64 blobs, `"a"+"b"` concat, reversed strings, one-hop constant propagation
- **AST-derived literal gate** — setiap pola diberi daftar literal wajib (AND/OR) dari AST regexp, jadi regex mahal hanya dijalankan bila literalnya ada (±4× lebih cepat, tanpa kehilangan temuan)
- **AI-era tokens** — Cerebras, Voyage, Groq, Perplexity, xAI, OpenRouter, DeepSeek, Fireworks, Replicate, HuggingFace
- **Parallel scanning** — automatic 8-worker regex dispatch for bodies >1MB
- **Evidence-safe output** — `-o` menulis berkas mode `0600` tanpa escape ANSI (aman di-grep, tidak membocorkan warna)
- **CI/pipeline friendly** — `--min-severity` dan `--fail-on-findings` (exit 2)
- **Body-reuse mode** — scan `httpx -json -irr` output without re-fetching (`--httpx-json`)
- **Keyword prefilter** — cheap literal gate before expensive regex, derived conservatively from each pattern
- **FlareSolverr integration** — Cloudflare bypass with automatic cookie refresh on `403/429`
- **Rate limiting** — global requests-per-second (`--rate`) and per-worker delay (`--delay`)
- **Proxy support** — honors `HTTP_PROXY`/`HTTPS_PROXY` environment variables
- **Streaming JSON output** — findings written live to stdout/file, no RAM accumulation
- **Headless-friendly** — quiet, colored, or JSON; output to file; SIGINT-safe flush

## Supported Patterns (partial list)

| Category | Services |
|---|---|
| **Cloud** | AWS (AKIA/ASIA), GCP, Azure, DigitalOcean, Cloudflare, Vercel, Netlify, Fly.io, Render, Heroku, Alibaba (LTAI), Tencent (AKID) |
| **AI/ML** | OpenAI, Anthropic, Groq, Perplexity, xAI, Cerebras, NVIDIA NIM, Voyage AI, Cohere, DeepSeek, Mistral, HuggingFace, Replicate, Stability AI |
| **CI/CD** | GitHub (ghp_/gho_/ghs_/github_pat_), GitLab, Bitbucket, CircleCI, TravisCI, Buildkite, SonarQube |
| **Payments** | Stripe, PayPal, Razorpay, Square, Flutterwave, Shippo |
| **Communication** | Slack, Discord, Telegram, Twilio, SendGrid, Mailgun, Mailchimp, Brevo/SendinBlue |
| **Analytics** | DataDog, New Relic, Sentry, Amplitude, Grafana, Mixpanel, Segment, PostHog, Dynatrace |
| **DevOps** | Terraform Cloud, Vault, 1Password, Doppler, Pulumi, LaunchDarkly, Tailscale |
| **Database** | MongoDB, PostgreSQL, MySQL, Redis, SMTP, Oracle JDBC, generic credential URIs, .pgpass, .netrc |
| **SSH/Keys** | RSA, EC, OpenSSH, DSA, PKCS8, PGP, PuTTY PPK |

Full list: `patterns.go` (401 pola inti) + `patterns_extra.go` (47 pola hasil audit 2026-11).

## Installation

```bash
# Requires Go 1.21+
git clone https://github.com/alb-soul/secrethunter2.git
cd secrethunter2
go build -o secrethunter2 .
```

## Quick Start

```bash
# Single URL
./secrethunter2 -u https://example.com

# List of URLs from file
./secrethunter2 -l urls.txt -t 10

# Rate-limited with FlareSolverr (recommended for recon)
./secrethunter2 -l urls.txt -f http://localhost:8191 --rate 5 -o results.txt

# Scan local files
./secrethunter2 -F config.js
./secrethunter2 -D ./src/ --ext js,json,env,yml

# httpx body-reuse mode (no re-fetch, scan bodies+headers from httpx JSONL)
./secrethunter2 --httpx-json httpx_output.json --scope example.com

# JSON output (streaming)
./secrethunter2 -l urls.txt --json > findings.json

# Skip public-by-design keys (RUM tokens, publishable keys, etc.)
./secrethunter2 -l urls.txt --no-public

# Follow the page's own JS bundles (this is where frontend secrets live)
./secrethunter2 -u https://app.target.com --js-crawl 20

# Authenticated scan using your own test-account cookie
./secrethunter2 -l urls.txt --cookie "session=abc123" -H "X-CSRF: token"

# CI gate: fail the pipeline when a secret shows up
./secrethunter2 -D ./dist --min-severity high --fail-on-findings
```

## Flags

| Flag | Alias | Description | Default |
|---|---|---|---|
| `-u` | `--url` | Single URL to scan | — |
| `-l` | `--list` | File of URLs (one per line) | — |
| `-F` | `--file` | Single local file to scan | — |
| `-fl` | — | File listing local paths | — |
| `-D` | `--dir` | Recursively scan directory | — |
| `--ext` | — | Ext filter for `-fl` / `-D` (comma) | all |
| `--httpx-json` | — | httpx `-json -irr` JSONL body-reuse mode | — |
| `--scope` | — | With `--httpx-json`: restrict to domain | — |
| `-t` | `--threads` | Concurrent workers | 5 |
| `--rate` | — | Global max requests/sec (0=unlimited) | 0 |
| `-d` | `--delay` | Per-worker delay in ms (unused if `--rate` set) | 0 |
| `--timeout` | — | HTTP request timeout (seconds) | 30 |
| `--max-size` | — | Max response body MB to scan | 10 |
| `-f` | `--flaresolverr` | FlareSolverr base URL | — |
| `-ua` | — | Custom User-Agent | Chrome 124 |
| `-H` | `--header` | Extra request header (repeatable) | — |
| `-o` | `--output` | Write findings to file | — |
| `--json` | — | Output findings as JSON (streaming) | false |
| `-s` | `--silent` | Suppress banner & progress | false |
| `-v` | `--verbose` | Show errors & progress | false |
| `--no-color` | — | Disable ANSI color codes | false |
| `--no-public` | — | Skip public-by-design keys | false |
| `--min-severity` | — | Only emit findings at/above: critical, high, medium, low, info | all |
| `--fail-on-findings` | — | Exit code 2 when any finding is emitted (CI) | false |
| `-k` | `--insecure` | Skip TLS certificate verification | false |
| `--proxy` | — | Explicit proxy URL (default: HTTP(S)_PROXY env) | env |
| `--cookie` | — | Cookie `name=value` sent with every request (repeatable) | — |
| `--js-crawl` | — | Follow up to N same-host `<script src>` and scan them | 0 (off) |
| `--no-decode` | — | Disable obfuscated-layer decode pass (±5× faster) | false |
| `--version` | — | Print version and exit | — |

## Severity Levels

| Level | Color | Description |
|---|---|---|
| `CRITICAL` | Red | Server keys, private keys, admin tokens — full compromise |
| `HIGH` | Magenta | User tokens, app secrets, webhooks — significant access |
| `MEDIUM` | Yellow | Test keys, limited-scope tokens |
| `LOW` | Blue | Generic matches, public-by-design keys |
| `INFO` | Dim | Downgraded public-by-design when not filtered |

## Production Usage with FlareSolverr

```bash
# 1. Start FlareSolverr (Docker)
docker run -d --name flaresolverr -p 8191:8191 ghcr.io/flaresolverr/flaresolverr:latest

# 2. Run with rate limiting
./secrethunter2 -l live_subs.txt \
  -f http://localhost:8191 \
  --rate 5 \
  -t 10 \
  -o secrets.txt

# 3. Typical recon pipeline
cat subdomains.txt | httpx -json -irr -o httpx.json
./secrethunter2 --httpx-json httpx.json --scope target.com --json > findings.json
```

## Performance (audit 2026-11)

Ukur di WSL Arch (8 core), korpus JS nyata:

| Target | Sebelum | Sesudah | Catatan |
|---|---|---|---|
| 2.2 MB bundle JS (3 file) | 121 s | 31 s | gate literal + `propagateVars` single-pass |
| 2.2 MB, `--no-decode` | — | 6 s | lewati layer decode |
| 610 KB bundle JS | 70 s | 19 s | findings identik |
| 20 MB single-line blob | 48 s | 19 s | |

Bottleneck yang tersisa adalah 6 lintasan penuh (body asli + 5 varian decode) × 448
regex. Rekomendasi lanjutan ada di `AUDIT.md` (windowed matching per literal).

## License

MIT

## Credits

Pattern references: [keyhacks](https://github.com/streaak/keyhacks), [GitGuardian](https://gitguardian.com), [TruffleHog](https://github.com/trufflesecurity/trufflehog), and extensive OSINT research.
