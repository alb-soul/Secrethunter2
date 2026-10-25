# secrethunter2

**Secret & Credential Scanner for Bug Bounty Recon** — detects 385+ token/credential patterns across web responses and local files.

```
 _____                     _   _   _             _
/  ___|                   | | | | | |           | |
\ '--.  ___  ___ _ __ ___| |_| |_| |_   _ _ __ | |_ ___ _ __
 '--. \/ _ \/ __| '__/ _ \ __|  _  | | | | '_ \| __/ _ \ '__|
/\__/ /  __/ (__| | |  __/ |_| | | | |_| | | | | ||  __/ |
\____/ \___|\___|_|  \___|\__\_| |_/\__,_|_| |_|\__\___|_|
```

## Features

- **385 verified patterns** — AWS, GCP, Azure, OpenAI, Anthropic, NVIDIA, Alibaba, Tencent, Discord, Slack, Stripe, JWT, private keys, DBURIs, and 100+ more
- **AI-era tokens** — Cerebras, Voyage, Groq, Perplexity, xAI, OpenRouter, DeepSeek, Fireworks, Replicate, HuggingFace
- **Parallel scanning** — automatic 8-worker regex dispatch for bodies >1MB
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

Full 385-pattern list: see `patterns.go`.

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

## License

MIT

## Credits

Pattern references: [keyhacks](https://github.com/streaak/keyhacks), [GitGuardian](https://gitguardian.com), [TruffleHog](https://github.com/trufflesecurity/trufflehog), and extensive OSINT research.
