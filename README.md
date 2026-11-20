# secrethunter2

**Secret & Credential Scanner for Bug Bounty Recon** — detects 483 token/credential patterns across web responses, JS bundles, and local files.

```
 _____                     _   _   _             _
/  ___|                   | | | | | |           | |
\ '--.  ___  ___ _ __ ___| |_| |_| |_   _ _ __ | |_ ___ _ __
 '--. \/ _ \/ __| '__/ _ \ __|  _  | | | | '_ \| __/ _ \ '__|
/\__/ /  __/ (__| | |  __/ |_| | | | |_| | | | | ||  __/ |
\____/ \___|\___|_|  \___|\__\_| |_/\__,_|_| |_|\__\___|_|
```

## Features

- **483 verified patterns** — AWS, GCP, Azure, OpenAI, Anthropic, NVIDIA, Alibaba, Tencent, Discord, Slack, Stripe, JWT, private keys, DBURIs, and 150+ more
- **JS bundle follower** (`--js-crawl N`) — follow same-host `<script src>` and scan the bundles where frontend secrets actually live
- **Obfuscated-layer decode** — `\x`/`\u` escapes, `String.fromCharCode`, base64 blobs, `"a"+"b"` concat, reversed strings, one-hop constant propagation
- **Aho-Corasick + windowed regex** (audit 2026-11b) — semua literal wajib dari semua pola dicari dalam satu pass; regex hanya dijalankan di jendela sekitar literal (±12× lebih cepat end-to-end, kesetaraan dengan full scan diuji; `--no-window` untuk debug)
- **JWT-aware** — `alg:none` → CRITICAL, Supabase `role=service_role` → CRITICAL, Supabase anon → INFO
- **AI-era tokens** — Cerebras, Voyage, Groq, Perplexity, xAI, OpenRouter, DeepSeek, Fireworks, Replicate, HuggingFace
- **Parallel scanning** — work-stealing regex dispatch for bodies >1MB
- **Evidence-safe output** — `-o` menulis berkas mode `0600` tanpa escape ANSI (aman di-grep, tidak membocorkan warna)
- **CI/pipeline friendly** — `--min-severity` dan `--fail-on-findings` (exit 2)
- **Body-reuse mode** — scan `httpx -json -irr` output without re-fetching (`--httpx-json`)
- **Keyword prefilter** — cheap literal gate before expensive regex, derived conservatively from each pattern
- **FlareSolverr integration** — Cloudflare bypass with automatic cookie refresh on `403/429`
- **Rate limiting** — global requests-per-second (`--rate`) and per-worker delay (`--delay`)
- **Proxy support** — honors `HTTP_PROXY`/`HTTPS_PROXY` environment variables
- **Streaming JSON output** — findings written live to stdout/file, no RAM accumulation
- **Server/CI-friendly** (tanpa browser) — quiet, colored, or JSON; output to file; SIGINT-safe flush

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

Full list: `patterns.go` (pola inti) + `patterns_extra.go` (47 pola audit 2026-11) + `patterns_2026b.go` (34 pola audit 2026-11b: Anthropic OAuth, OpenAI admin, AWS AppSync/secretAccessKey, Azure Q~/Service Bus/Cosmos/APIM/Logic App, GCP SA JSON, Cloudflare `cfat_`, Heroku `HRKU-`, GitLab `glrt-`/`glagent-`, CircleCI/Buildkite/Docker/Contentful, npm `_auth`, Docker `config.json`, Kafka JAAS, JDBC, PayPal `A21AA`, Plaid, webhook Slack/Google Chat/IFTTT, New Relic `NRII-`, MailerSend, age).

## Installation

Butuh **Go ≥ 1.21** (Arch: `pacman -S go` · Debian/Ubuntu: <https://go.dev/doc/install>).
Tidak ada dependensi lain: Go stdlib murni (`net/http`), **tanpa Chromium/browser headless**.
Cloudflare challenge ditembus lewat FlareSolverr (`-f http://localhost:8191`), bukan browser lokal.

```bash
git clone https://github.com/alb-soul/Secrethunter2.git
cd Secrethunter2
./install.sh
```

`install.sh` mem-build dari source di direktori script lalu memasang **salinan file biasa**
(bukan symlink) ke `/usr/local/bin/secrethunter2`, memakai `sudo` hanya bila direktori tujuan
tidak bisa ditulis. Setelah itu ia memverifikasi `secrethunter2 -version` dan memperingatkan bila
ada salinan lain di `PATH` yang mendahului `/usr/local/bin` (salinan itu tidak dihapus otomatis).

```bash
git pull && ./install.sh                  # update
BINDIR="$HOME/.local/bin" ./install.sh    # tujuan lain (tanpa sudo); atau PREFIX=/opt/x → /opt/x/bin
./install.sh --uninstall                  # hapus $BINDIR/secrethunter2 saja
./install.sh --help
```

Installer tidak meng-install Go, tidak men-download apa pun, dan tidak mengubah `PATH`/shell rc.
Inilah kontrak yang dipakai Recon-wild (`reconin3`/`scantarget3` memanggil `secrethunter2` lewat `PATH`).

Build manual untuk development (tanpa memasang):

```bash
go build -o secrethunter2 .
go vet ./... && go test ./...
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
| `-ua` | — | Custom User-Agent | string UA Chrome 124 (hanya header; tidak memakai browser) |
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
| `--no-decode` | — | Disable obfuscated-layer decode pass | false |
| `--no-window` | — | Run gated regexes over the whole body (debug; slower) | false |
| `--version` | — | Print version and exit | — |

### Output & exit code

- Baris teks (stdout dan `-o`): `[SEVERITY] Nama Layanan | nilai | url` — selalu satu baris
  (newline/tab di dalam nilai, mis. private key PEM, di-escape menjadi `\n`/`\t`); nilai
  dipotong 120 karakter seperti sebelumnya (`--json` memuat nilai penuh s/d 4096).
- Baris identik (url + pola + nilai) hanya ditulis sekali.
- Exit code: `0` normal · `1` error fatal (argumen, input tidak terbaca, **gagal menulis `-o`**) ·
  `2` ada temuan + `--fail-on-findings` · `130` dihentikan Ctrl-C (hasil yang ada tetap di-flush;
  Ctrl-C kedua = paksa keluar).
- `--httpx-json`: baris JSONL raksasa (> 8× `--max-size`) dilewati tanpa menghentikan pembacaan;
  header dibaca dari `raw_header`, atau dari map `header` bila `raw_header` tidak ada; body biner
  (`content_type` image/font/…, atau U+FFFD/NUL dominan) dilewati, header-nya tetap di-scan.

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

## Performance

### audit 2026-11b — corpus sintetis (`tools/gencorpus`, 55 MB JSONL, 1503 record, 3 body 5–9 MB)

Mode kontrak `--httpx-json … --scope target.test -o … -t 8 -silent`, WSL Arch 8 core:

| | v2.4.0 | v2.5.0 |
|---|---|---|
| Waktu | 37.0 s | **3.0 s** |
| Secret tertanam terdeteksi | 738/977 (75.5%) | **977/977 (100%)** |
| FP pada record jebakan | 425 | **0** |
| Baris output rusak (multi-baris) | 50 | **0** |

Reproduksi: `go run ./tools/gencorpus -o /tmp/c.jsonl && tools/bench.sh /tmp/c.jsonl ./secrethunter2`.

### audit 2026-11 — korpus JS nyata

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
