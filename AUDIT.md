# AUDIT — secrethunter2 (November 2026)

> **Lanjutan: audit 2026-11b (v2.5.0)** — lihat [§0](#0-audit-2026-11b-v250) di bawah.
> Bagian §1–§10 adalah audit pertama (v2.4.0) dan dibiarkan sebagai catatan sejarah;
> item OPEN #10 (SIGINT httpx-json) dan #13 (newline di output) kini **FIXED** di 2026-11b.

---

## 0. Audit 2026-11b (v2.5.0)

Kontrak yang dijaga: `--httpx-json <jsonl> --scope <domain> -o secrets.txt -t N -silent`,
fallback `-l <urls> -o … -t N -silent [-rate N] [-ua UA] [-H …]`, format baris
`[SEVERITY] Nama Layanan | nilai | url`. Diverifikasi oleh `TestHTTPXJSONEndToEnd`,
`TestPrintFindingSingleLine` dan uji manual mode `-l` terhadap server lokal.

### 0.1 Hasil terukur (corpus sintetis `tools/gencorpus`, 55 MB, 1503 record)

| | v2.4.0 | v2.5.0 |
|---|---|---|
| Waktu (mode kontrak, -t 8) | 37.0 s | **3.0 s** |
| Recall secret tertanam | 738/977 (75.5%) | **977/977** |
| FP di record jebakan | 425 | **0** |
| Baris output rusak | 50 | **0** |
| File berisi baris 70 MB | berhenti di tengah (28 temuan) | lanjut (43 temuan) |
| `go test -race` | — | bersih |

### 0.2 Bug yang diperbaiki

| # | Tingkat | Masalah | Perbaikan |
|---|---|---|---|
| B1 | P0 | `--httpx-json`: `bufio.Scanner` berhenti total pada baris > 64 MB → semua record sesudahnya tidak di-scan (error hanya tampil dengan `-v`) | `forEachLine`: baris > 8×`--max-size` dilewati & dihitung, pembacaan lanjut |
| B2 | P1 | field `header` (map) httpx diabaikan | fallback `headerMapText` bila `raw_header` kosong |
| B3 | P1 | deteksi biner menghitung byte ≥0x80 sebagai non-printable → halaman CJK/UTF-8 dilewati (FN); mode httpx tidak punya cek biner | `looksBinary` (UTF-8 aware, U+FFFD/NUL) + `content_type` |
| B4 | P1 | private key PEM (berisi `\n`) memecah format satu-baris | `\n`/`\r`/`\t` di-escape |
| B5 | P1 | `isBase64Slice` menghitung char base64 di kanan secara tidak kontigu → token yang diikuti `/path");…` dibuang (Telegram 0% recall) | hitung run kontigu |
| B6 | P1 | 4 entri map guard salah ketik nama pola (Flutterwave/Stytch/Clerk/…) → guard diam-diam tidak aktif | dibetulkan + `TestAudit2GuardMapsReferenceRealPatterns` |
| B7 | P1 | pola konteks `([A-Za-z0-9]{40})['"]?` mengambil 40 char PERTAMA token yang lebih panjang (nilai terpotong menang dedupe) | capture yang berakhir di tengah run alfanumerik dibuang |
| B8 | P2 | salinan `body+"\n"+header` 10 MB per record; channel ber-buffer `-t` record; worker > CPU di mode CPU-bound | header di-scan terpisah, channel tanpa buffer, worker ≤ GOMAXPROCS |
| B9 | P2 | error tulis `-o` ditelan (exit 0); Ctrl-C di mode httpx-json tidak di-handle; `io.MultiWriter` berhenti menulis file bila stdout rusak | exit 1 + pesan; SIGINT flush (exit 130); `teeOut` |
| B10 | P2 | baris duplikat identik (URL ganda di JSONL) | dedup hash url+pola+nilai |
| B11 | P3 | `-H "Host: …"` diabaikan net/http | diset ke `req.Host` |

### 0.3 Pola: presisi & recall

- **FP dihapus**: AWS Key ID `(?i)` (identifier `akia…`), `mongodb://localhost:27017` tanpa kredensial
  (CRITICAL palsu), Telegram `timestamp:hex`, Mailgun `monkey-…`, Mailchimp tanpa batas, Twitch
  `{oauth:handler…}`, Ghost `ObjectId:sha256`, Basic auth yang ter-decode biner, prefix generik
  (`re_`, `rnd_`, `pa-`, `da2-`, …) yang cocok dengan identifier snake/kebab-case.
- **FN diperbaiki**: Telegram (0→100%), Supabase service_role (payload diawali `iss`, kini lewat
  klaim JWT), Asana (format gid 16 digit), Discord ID baru (`O…`), driver SQLAlchemy
  (`postgresql+psycopg2://`), placeholder kata pendek (`none/null/todo/asdf`) kini hanya per-segmen.
- **Severity**: identifier publik diturunkan ke LOW (Twilio SID, Google OAuth Client ID, UUID client
  id, GCP SA email, Algolia App ID, Sentry DSN, Mailgun pubkey); `"type":"service_account"` tanpa
  private key → MEDIUM (dengan private key: pola baru CRITICAL); Square dipisah `sq0csp-` (HIGH) /
  `sq0idp-` (LOW).
- **Coverage**: +34 pola (`patterns_2026b.go`), masing-masing dengan test positif & negatif
  (`audit2_coverage_test.go`).

### 0.4 Performa

Profil v2.4.0: 92% CPU di NFA `regexp` (seluruh body per pola). 57 pola tanpa gate, gate sisanya
lemah (literal ≥4 char tanpa ekspansi). Perbaikan (`engine.go`):

1. Literal wajib diekstrak dengan aljabar exact-set ala RE2 (`api[_-]?key` → {apikey, api_key,
   api-key}; `A(?:KIA|SIA…)` → {AKIA, ASIA, …}; prefix/suffix repetisi `/[0-9]{12,}` → {/0…/9}).
2. Satu pass Aho-Corasick untuk semua literal (lowercase ASCII on-the-fly, tanpa salinan `ToLower`).
3. Regex hanya di jendela sekitar kemunculan literal paling jarang (L = panjang match maks dari AST;
   tepi jendela menembus run repetisi tak-berhingga), fallback full scan bila padat.
4. Body ≥1 MB: pola dibagi dinamis (work-stealing).

Kesetaraan windowed == full scan diuji (`TestEngineWindowEquivalence*`: semua sampel test ×3
konteks + body >1 MB + 400 body corpus). `--no-window` tersedia sebagai escape hatch.

### 0.5 Masih terbuka

- Varian decode (`decodedVariants`) masih memindai ulang seluruh varian (kini murah karena window,
  tapi changed-region scanning masih bisa ±2× lagi pada bundle besar ber-escape).
- Memori puncak saat satu baris JSONL 70 MB: ±300 MB (baris + string hasil decode); di bawah batas
  `--response-size-to-save 10MB` httpx baris tidak akan sebesar itu.
- Rotasi/pembersihan riwayat git untuk secret lama di komentar (§5) tetap tindakan manual.

Audit menyeluruh atas `secrethunter2` (Go, 401 pola awal) mencakup: kebenaran kode,
kualitas pola (false negative / false positive), performa, keamanan/higiene repo,
serta celah fitur untuk menunjang bug-bounty hunting.

- Ruang lingkup: `main.go`, `patterns.go`, seluruh `*_test.go`, `go.mod`, README, riwayat git.
- Metode: baca kode baris-per-baris, `go build`, `go vet`, `staticcheck`, `go test -race`,
  benchmark terukur, korpus nyata (bundle JS hasil hunting sendiri), korpus FP (source Go/Python),
  self-scan (dogfood), `gitleaks` atas riwayat repo, dan uji recall format token per layanan.
- Branch perbaikan: `audit/fixes-2026-11` (semua temuan ber-status **FIXED** di bawah sudah
  diimplementasikan + punya test regresi di `audit_test.go`).

---

## 1. Ringkasan eksekutif

| Area | Sebelum | Sesudah | Catatan |
|---|---|---|---|
| Kebenaran fungsional | 3 cacat perilaku yang menggagalkan penggunaan nyata | 0 | URL tanpa skema, `-o` berisi ANSI, `--scope` diabaikan |
| Performa scan | 121 s untuk 2.2 MB JS | 31 s (`--no-decode`: 6 s) | **≈4×** lebih cepat, findings identik |
| Kualitas pola | 6 bug format (FN) + 4 kelas FP | diperbaiki | lihat §4 |
| Keamanan/higiene repo | 2 token nyata + 1 kunci enkripsi target di komentar file publik | diredaksi | **perlu rotasi** (§5) |
| Cakupan pola | 401 | **448** | 47 pola baru, context-anchored |
| Gate kualitas | `go vet` bersih, `staticcheck` 1 temuan | bersih | +1 perbaikan S1023 |

**5 temuan paling berdampak**

1. **O(n²) di `propagateVars`** — 11.6 s per panggilan untuk bundle 1.1 MB, dipanggil 6× per body
   (≈45 s) sehingga satu file JS bisa memakan ±1 menit. Ini penyebab utama scanner terasa "hang".
2. **`isBase64Slice` membuang token di URL path** — `https://cdn/v1/ghp_…` tidak pernah dilaporkan
   (guard "potongan base64" hanya melihat 1 karakter di kiri).
3. **`-o` menulis escape ANSI + permission 0644** — file hasil (berisi secret!) tidak bisa di-grep
   dan world-readable.
4. **Panjang token yang salah** — `ghr_` (GitHub refresh) di-hardcode 76 char padahal nyata 36,
   Turnstile sitekey di-hardcode ≥37 char padahal nyata 24–27 → dua keluarga token **tidak pernah match**.
5. **Secret nyata tertinggal di komentar `patterns.go`** pada repo **PUBLIC** (New Relic query key,
   PubNub `sec-c-…`, kunci enkripsi custom target) — bukan bug kode, tapi risiko disclosure.

---

## 2. Bug & cacat kode

Status: **FIXED** = sudah diperbaiki di branch ini; **OPEN** = rekomendasi.

| # | Tingkat | Lokasi | Masalah | Bukti | Status |
|---|---|---|---|---|---|
| 1 | **P0** | `propagateVars()` | Untuk setiap deklarasi `var x="…"`, dua regex baru di-`Compile` lalu `FindAllStringIndex` atas **seluruh** body → O(jumlah-deklarasi × panjang-body). Terukur **11.6 s** per panggilan pada bundle 1.19 MB; `decodedVariants` memanggilnya 1+N kali → **44.8 s**. | `go test -run TestAuditPropagate` | **FIXED** — single-pass: satu scan identifier + peta kemunculan + penggantian kiri→kanan. **0.27 s** (≈42×) |
| 2 | **P0** | `isBase64Slice()` | `if isB64(content[startPos-1]) → drop`. Satu karakter `/` (URL path) sudah cukup membuang token: `https://cdn.example.com/v1/ghp_…` → **0 finding**. | `TestAuditTokenInURLPath` | **FIXED** — hanya dianggap potongan blob bila run base64 kiri ≥20 char |
| 3 | **P1** | `main()` output writer | `-o` memakai `io.MultiWriter(os.Stdout, outF)` sehingga **escape ANSI ikut tertulis** ke file (`\033[31m…`), dan file dibuat `0644`. | `od -c out.txt` → `033 [ 3 1 m` | **FIXED** — `ansiStripper` + `os.OpenFile(..., 0600)` |
| 4 | **P1** | `fetchURL()` | URL tanpa skema gagal total: `-u example.com` → `unsupported protocol scheme ""`. Daftar URL recon (subfinder/httpx `-silent`) sering telanjang domain. | uji manual | **FIXED** — `withScheme()` (https default, http untuk loopback) + URL ternormalisasi ikut dilaporkan |
| 5 | **P1** | flag `--scope` | Hanya dipakai di mode `--httpx-json`; pada `-l`/`-u` **diabaikan diam-diam** → risiko memindai host di luar scope. | uji manual | **FIXED** — filter URL + laporan `n/m in scope` |
| 6 | **P1** | `solveDomain()` | `MaxTimeout: 60000` tapi request dikirim lewat `httpClient` yang `Timeout: 30s` → challenge FlareSolverr selalu di-kill sebelum selesai; sesi `nil` lalu di-cache permanen. | analisis kode | **FIXED** — `fsClient` dengan timeout `max(cfg.Timeout, 75s)` |
| 7 | **P1** | `fetchURL()` | Body biner (gambar/zip/pdf) tetap dipindai: 200 KB `/dev/urandom` butuh ±1 s CPU dan berpotensi FP. Pemeriksaan NUL hanya ada di jalur file lokal. | uji manual | **FIXED** — skip bila ada NUL atau printable-ratio < 0.5 |
| 8 | **P2** | `exit code` | Selalu 0 walau ada temuan → tidak bisa dipakai sebagai gate pipeline. | uji manual | **FIXED** — `--fail-on-findings` (exit 2), flag salah → exit 1 |
| 9 | **P2** | dedupe antar-pola | Nilai yang sama bisa dilaporkan 2×: `sk_live_…` oleh pola Stripe **dan** Clerk; URI DB oleh pola spesifik **dan** `URI with embedded credentials`. Selain itu pola generik yang match lebih dulu (mis. `Password assignment`) bisa "menelan" pola spesifik yang lebih parah (MSSQL conn string) karena dedupe lama hanya berbasis teks-match. | `TestAuditNoDuplicateFamily` | **FIXED** — `dedupeOverlapping()` + prioritas pola spesifik vs generik |
| 10 | **P2** | `scanHTTPXJSON()` | Tidak ada penanganan SIGINT → Ctrl-C meninggalkan array JSON terpotong (tidak valid). | analisis kode | **OPEN** (lihat §8) |
| 11 | **P2** | TLS/Proxy/Cookie | Tidak ada opsi `-k` (banyak target BB punya chain TLS rusak), proxy hanya dari env, tidak ada `--cookie` (auth scan harus lewat `-H` manual). | grep kode | **FIXED** — `-k/--insecure`, `--proxy`, `--cookie` (repeatable) |
| 12 | **P2** | `-f` vs `-F` | `-f` = FlareSolverr, `-F` = file. Mudah tertukar; salah pakai tidak menghasilkan error yang jelas. | analisis kode | **OPEN** (saran: alias panjang + peringatan) |
| 13 | **P3** | `printFinding()` | `Match` yang mengandung newline (mis. private key) merusak format satu-baris → output tidak bisa diparse dengan `cut/awk`. | uji manual | **OPEN** (sarankan `strings.ReplaceAll(match,"\n","\\n")` di mode teks) |
| 14 | **P3** | `scanContent()` | Layer decode hanya jalan untuk body < 2 MB dan diam-diam dilewati di atasnya (tanpa log). | analisis kode | **OPEN** (tambahkan `logVerbose`) |
| 15 | **P3** | `-ua` | Didokumentasikan "ignored with flaresolverr" — perilaku sebenarnya: hanya diganti bila solve berhasil. | analisis kode | **OPEN** (perjelas dokumentasi) |

### Catatan desain yang sudah bagus (jangan diubah)

- Mesin regex Go = **RE2** → tidak ada risiko ReDoS dari 448 pola (semua bounded/linear).
- Dedupe hasil paralel sudah deterministik (urutan pattern dipertahankan lewat `mergeCandidates`).
- `jsonStream` melakukan streaming sehingga RAM tidak tumbuh mengikuti jumlah finding.
- Test suite ada property/leak-test per temuan historis (`leaktest_*_test.go`) — ini aset besar,
  pertahankan kebiasaan menambah fixture untuk setiap bug baru.
- `go test -race` bersih (91 s) — tidak ada data race pada pool worker/FS cache.

---

## 3. Performa

### 3.1 Profil sebelum perbaikan (bundle JS 1.19 MB, 1 core)

```
ToLower            :   3.5 ms
decodedVariants    :  44.8 s   ← 5 varian; 6× propagateVars @ 11.6 s
scanSingle (1 pass):   3.2 s   ← 401 regex
scanContent total  :  64.2 s
```

Akar masalah: (a) `propagateVars` O(n·k), (b) 6 lintasan penuh × 448 regex,
(c) 135 pola tanpa gate literal sama sekali (`\b(AKIA|ABIA|…)`, `(?i)recaptcha|site-key…`).

### 3.2 Perbaikan yang diterapkan

1. **`propagateVars` single-pass** — 11.6 s → 0.27 s.
2. **Gate literal dari AST regexp** (`regexp/syntax`) menggantikan prefilter string lama:
   AND antar-group, OR di dalam group. Contoh `\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b` →
   gate `{akia|abia|acca|asia}`; `foo bar` → dua group. Pola tanpa gate turun drastis,
   dan gate **sound** oleh konstruksi (hanya literal yang wajib di semua cabang).
3. **`--no-decode`** sebagai escape hatch (lewati 5 varian) → 6.3 s untuk korpus 2.2 MB.

### 3.3 Hasil terukur (WSL Arch, 8 core)

| Korpus | Sebelum | Sesudah | `--no-decode` | Findings |
|---|---|---|---|---|
| 2.2 MB JS/HTML (`~/xsid`) | 121 s | **31 s** | **6.3 s** | identik dengan baseline |
| 610 KB JS (`~/Testing`) | 70 s | **19.5 s** | — | identik |
| 20 MB blob satu-baris | 48 s | **19.4 s** | — | sama |
| `go test ./...` | 11.0 s | **5.7 s** | — | semua lulus |

Verifikasi "tidak ada regresi recall": hasil text-mode untuk kedua korpus di-`diff` terhadap
output binary lama — **identik**.

### 3.4 Bottleneck yang tersisa + desain optimasi lanjutan (OPEN)

- **Windowed matching per literal** (prioritas tertinggi, ±10× lagi). Karena setiap pola kini
  punya literal wajib, cari posisi literal (`strings.Index`, cap 2 000 kemunculan), lalu jalankan
  regex hanya pada jendela `[pos-512, pos+len(lit)+2048]`. Bila match menyentuh batas jendela →
  fallback full scan untuk pola itu (tetap sound). Ini memotong pola `[^\n]{0,80}?` yang jadi biaya
  dominan pada bundle satu-baris.
- **Changed-window scanning untuk varian decode**: 5 varian berbeda hanya di beberapa byte;
  diff per blok 4 KB + hash, scan hanya blok yang berubah (± 2 KB konteks), fallback full bila
  > 20 % blok berubah.
- **Batasi jumlah varian** bila body > 4 MB, atau jalankan decode per-`<script>` chunk.
- **Worker pool untuk `-D`**: saat ini 8 worker per file (>1 MB) mengalikan pemakaian CPU;
  pertimbangkan semaphore global `GOMAXPROCS`.

---

## 4. Kualitas pola (recall & presisi)

Uji recall dilakukan dengan sampel format-akurat per layanan (panjang & charset sesuai dokumen
resmi/korpus keyhacks), bukan string asal. Hasil yang relevan:

### 4.1 False negative yang ditemukan → FIXED

| Pola | Masalah | Dampak | Perbaikan |
|---|---|---|---|
| `GitHub App Refresh Token (ghr_)` | `ghr_[A-Za-z0-9]{76}` — token nyata 36 char | seluruh token `ghr_` tidak pernah terdeteksi (test internal sendiri memakai sampel 80 char, sehingga bug tidak terlihat) | `\bghr_[A-Za-z0-9]{36,120}\b` |
| `Stripe Live/Test Secret, pk_live_, rk_live_` | `{24,34}` tanpa `\b` → kunci modern (±99 char) **dipotong 34 char** | laporan berisi kunci tidak valid; verifikasi manual gagal | `\b…{24,120}\b` (nilai penuh) |
| `Cloudflare Turnstile Site Key` | `0x4AAAA` + `{30,}` (total ≥37) — sitekey nyata 24–27 char | pola **tidak pernah match** | `{16,25}` |
| `Cloudflare Turnstile Secret Key` | prefiks `0x3AAAA` (tidak dipakai Cloudflare) | pola mati | `0x[34]AAAA…{26,}` (secret lebih panjang) |
| Token di URL/JS concat | `isBase64Slice` (lihat §2 #2) | FN pada pola standalone (ghp_, AIza, dsb.) | guard run-kiri ≥20 char |
| `.pgpass` | tidak ada | — | (lihat FP) |
| `PGP Private Key Block` | hanya header | — | wajib body base64 ≥40 char |

### 4.2 False positive yang ditemukan → FIXED

| Kasus | Bukti | Perbaikan |
|---|---|---|
| `postgres://user:password@…`, `mongodb://admin:secret@…`, `mysql://root:root@…` dilaporkan **CRITICAL** | uji manual | `credPlaceholder()` — tolak password placeholder (`password`, `secret`, `root`, `${DB_PASS}`, `your_…`) |
| Baris IPv6 di `/etc/hosts` dilaporkan sebagai entri `.pgpass` | scan `/usr/lib/go/src/net` | `reIPv6Line` guard |
| `-----BEGIN PGP PRIVATE KEY BLOCK-----` (hanya teks header di dokumentasi) → CRITICAL | self-scan `patterns.go` | wajib body base64 |
| Nilai yang sama dilaporkan oleh 2 pola (Stripe+Clerk, URI spesifik+generik) | `TestCrossTalkDedup` | `dedupeOverlapping()` dengan prioritas pola spesifik |

### 4.3 Presisi pada korpus nyata

- `~/xsid` (2.2 MB JS produksi): 3 finding — reCAPTCHA sitekey (INFO, memang publik),
  2× `OAuth Client ID (UUID)` (MEDIUM, wajar sebagai noise rendah). **0 FP nyata.**
- `~/Testing` (610 KB JS): 8 finding, termasuk **`sec-c-…` PubNub secret yang benar-benar nyata**
  di bundle. Bagus: tidak ada banjir FP.
- `/usr/lib/go/src/net` (source Go): 8 finding, semuanya contoh/dokumentasi (`user:password@…`,
  `.pgpass` IPv6) — 6 di antaranya kini sudah difilter.

Kesimpulan: presisi bagus untuk bundle JS; noise terbesar ada di keluarga "credentials in code"
yang memang berburu di source, bukan di web.

---

## 5. Keamanan & higiene repo (PUBLIC repo!)

1. **Token nyata di komentar `patterns.go`** (branch `main`, publik):
   - komentar pola New Relic Insights Query Key (`NRIQ…`, 40 char) — *"confirmed by real-world finding"*;
   - komentar pola PubNub Secret (`sec-c-…`, base64 UUID) — format resmi;
   - komentar pola Encryption Key (`REDPER="…"`) — kunci enkripsi custom milik target (binus).
   Ketiganya **diredaksi** di branch ini (diganti placeholder / sampel sintetis).
   **Tindakan yang masih perlu kamu lakukan:** anggap ketiga kredensial itu *burned* — cek/rotasi
   (kalau masih hidup) dan bersihkan riwayat git (`git filter-repo --replace-text`) kalau ingin
   benar-benar hilang dari history. Ingat: repo publik + riwayat = sudah ter-crawl (GitHub,
   archive.org, scanner pihak ketiga).
2. `gitleaks git` menemukan 58 hit di riwayat — mayoritas fixture test (aman), tapi jadikan
   `.gitleaks.toml` dengan allowlist `*_test.go` supaya sinyal asli tidak tenggelam.
3. `-o` tadinya `0644` → sudah `0600`. Pertimbangkan juga `--redact` (mask 4 char tengah) untuk
   laporan/screenshot (sejalan dengan skill `evidence-hygiene`).
4. `README` mengklaim **MIT** tetapi tidak ada file `LICENSE` → tambahkan.
5. Tidak ada `.github/workflows` → tidak ada build/test otomatis; tambahkan CI (§9).

---

## 6. Pola/layanan yang DITAMBAHKAN (47 pola baru, `patterns_extra.go`)

Semua context-anchored (`nama-layanan [^\n]{0,80}? key/token = "…"`) supaya tidak menambah FP di
bundle JS; sudah ada test positif di `audit_test.go` + test "tidak noisy di JS".

**Cloud/CI-CD/infra**
`Google OAuth Client Secret (GOCSPX-)` · `AWS Cognito Identity Pool ID` · `AWS Cognito User Pool ID`
· `Azure DevOps PAT` · `Ansible Vault` · `Kubernetes kubeconfig client-key-data` · `Jenkins API Token`
· `Gitea/Forgejo Token` · `Vercel Blob RW Token` · `Dropbox sl. token` · `Slack Signing Secret`
· `OpenAI org-…` (Low)

**Database / messaging / directory**
`amqp/nats/mqtt/redis URI + password` · `ldap/ldaps/imap/pop3 URI + password` ·
`clickhouse/trino/presto URI + password` · `MSSQL/SQL Server connection string`

**Payment (termasuk gateway ID yang jarang ter-cover)**
`Checkout.com sk_sbox_/sk_live_` · `Mollie live_/test_` · `Klarna` · `PayU` · `DOKU` ·
`Nicepay/Faspay` · `Telnyx`

**AI / data / vector DB**
`Azure OpenAI key` · `Qdrant` · `Weaviate` · `Chroma` · `Turso token` · `QuickNode/Helius RPC`

**Auth/identity SaaS**
`FusionAuth/Descope` · `Kinde/Stytch client secret` · `ServiceNow`

**Email / analytics / realtime**
`SparkPost` · `Elastic Email/Customer.io` · `Ably/LiveKit` · `Agora App Certificate` ·
`Speechmatics/LogRocket`

**Feature flags / CMS / e-commerce**
`Split.io/Flagsmith/Unleash` · `Strapi/Prismic` · `BigCommerce/Magento/Wix` · `Canva/Miro/Box/Vimeo`

**Ops / misc**
`Healthchecks.io ping URL` · `UptimeRobot` · `DefectDojo/Codecov` · `Make/Integromat webhook` ·
`bcrypt hash` · `NTLM hash`

---

## 7. Layanan yang MASIH bisa ditambahkan (urutan prioritas untuk hunting)

Prioritas dinilai dari: seberapa sering bocor di JS/APK/repo, dan seberapa langsung bisa
di-chain ke dampak (ambil data / eskalasi / RCE).

### P1 — nilai tinggi, belum ada

| Layanan/format | Bentuk token | Kenapa penting |
|---|---|---|
| **GitHub App private key (PEM)** | `-----BEGIN RSA PRIVATE KEY-----` + `app_id` | sudah ter-cover parsial oleh pola private key; tambahkan **pasangan** `app_id` + key agar bisa langsung dipakai bikin installation token |
| **Google service-account lengkap** | JSON `type=service_account` + `private_key` | pola sekarang memisah field; deteksi objek JSON utuh → langsung bisa `gcloud auth` (chain ke GCS/BigQuery) |
| **AWS trio lengkap** | `AKIA…` + `aws_secret_access_key` di file yang sama | naikkan severity + auto-verify (`sts:GetCallerIdentity`) |
| **Supabase service_role JWT** | JWT dengan `"role":"service_role"` | bypass RLS = dump seluruh DB; sekarang JWT hanya LOW |
| **Firebase Realtime DB yang bisa ditulis** | `*.firebaseio.com` + anon key | chain klasik: baca/tulis DB |
| **NATS / Pulsar / Solace** | `nats://user:pass@`, `pulsar://` | messaging internal, sering terbuka |
| **WalletConnect project ID / Alchemy-Infura key aktif** | sudah ada pola; tambah **verifikasi** | abuse kuota → biaya |
| **Snowflake / BigQuery / ClickHouse Cloud creds** | `account=…;user=…;password=…`, `snowflakecomputing.com` | data warehouse = dampak kritikal |
| **DocuSign / MS Graph / OneDrive token** | `eyJ…` + `graph.microsoft.com` | enumerasi file korban |
| **Telnyx/Twilio sub-account keys** (perluas) | `KEY…`, `SK…` + `subaccount` | SMS bombing / toll fraud (P1 di BB) |
| **Shopify `shpca_` / `shppa_` / `shpat_` varian baru + store domain** | perluas | akses admin store |
| **Cloudflare Origin CA / R2 S3 keys** | `-----BEGIN PRIVATE KEY-----` + R2 endpoint | akses bucket |
| **Okta/Entra service principal secret** | `client_secret` + `tenant_id` | lateral ke M365 |
| **Vault `hvs.` + address** | sudah ada token; tambah pasangan VAULT_ADDR | eksfiltrasi secret store |
| **Stripe `whsec_` + endpoint** | sudah ada | replay webhook (uang) |

### P2 — nilai menengah

`TeamCity`, `Drone CI`, `Codeberg`, `Heap app id`, `FullStory org id`, `Microsoft Clarity`,
`Prismic` (sudah), `Baserow`, `NocoDB`, `Aiven`, `Koyeb`, `Snowflake`, `CockroachDB`,
`BigQuery`, `Pulsar`, `Elastic Cloud API key` (sudah context), `PayPal A21AA…` (bearer modern —
pola lama hanya `access_token$production$`), `Shopify storefront token`, `Shopware`,
`MailerSend`, `Loops.so`, `Resend` (sudah), `Clerk Backend API` (`sk_live_` + `api.clerk.com`),
`Google reCAPTCHA v3 secret` (`6L…` + `secret`), `hCaptcha secret`, `Cloudflare Turnstile` (baru
diperbaiki), `LaunchDarkly client-side ID`, `Statsig` (sudah), `Optimizely`, `Amplitude secret`
(sudah), `Mixpanel secret` (sudah).

### P3 — nice to have

`FTP/FTPS URI`, `SOCKS proxy creds`, `Kafka SASL JAAS`, `MongoDB Atlas API key`, `Pinecone`
(sudah), `Weights&Biases` (sudah), `Kaggle` (sudah), `Notion` (sudah), `Airtable` (sudah),
`Shopify` (sudah), hash format lain (`argon2`, `scrypt`, `sha512crypt`), `JWT` dengan `kid`
anomali, `AWS session token` (sudah).

> Catatan metodologis: tambahkan pola baru **hanya** dengan uji positif format-akurat + uji
> "tidak noisy" pada bundle JS nyata. Semua pola di `patterns_extra.go` memenuhi itu.

---

## 8. Fitur yang masih kurang (roadmap produk)

Urut dari dampak terbesar terhadap hasil hunting:

1. **`--verify` (validasi kredensial live)** — ini pembeda terbesar vs trufflehog/gitleaks.
   Validator read-only per layanan: GitHub `/user`, Slack `auth.test`, Stripe `/v1/balance`,
   SendGrid `/v3/scopes`, OpenAI `/v1/models`, Twilio `/Accounts/{sid}.json`, Supabase anon
   `REST /rest/v1/?apikey=`, AWS `sts:GetCallerIdentity`, Google `tokeninfo`. Output: `VERIFIED` /
   `INVALID` / `UNKNOWN` + naikkan severity bila verified. **Ini yang membuat laporan langsung
   diterima triager.** (Desain: tabel `{pattern → verifier func}`, timeout 5 s, tanpa retry,
   rate-limit global, dan `--verify-max N` agar aman.)
2. **`--js-crawl` sudah ada (1 level)** → kembangkan: kedalaman 2, ekstrak juga `import()`/
   `webpack` chunk map, `sourceMappingURL` → **rekonstruksi `.map`** (source asli sering memuat
   komentar + endpoint + default credential).
3. **Mode git/history** — `--git <repo|url>` untuk scan seluruh history (`git rev-list --objects`
   + `git cat-file`), karena secret yang sudah dihapus tetap hidup di history.
4. **Integrasi dorking/recon pipeline**: `--stdin` (baca URL dari pipe; sekarang harus file),
   `--gau`/`--wayback` ingest, dan format output **JSONL** untuk dikonsumsi `jq → nuclei/dalfox`.
5. **Dedupe/grouping lintas host** (`--group-by secret`): satu bundle dipakai 500 host → sekarang
   500 baris duplikat; grupkan "secret X terlihat di N host" (mempermudah menilai dampak massal).
6. **Allowlist/baseline** (`.secrethunterignore`, `--baseline prev.json`): buang secret yang sudah
   dikenal supaya diff run harian bersih.
7. **`--redact` / `--hash`**: output aman untuk screenshot/laporan (mask nilai, simpan SHA-256
   + 4 char terakhir untuk verifikasi) — sejalan dengan `evidence-hygiene`.
8. **SIGINT-safe di mode `--httpx-json`** (tutup array JSON dengan benar).
9. **`--sarif` + exit code** untuk CI (SARIF bisa langsung masuk GitHub code scanning).
10. **Rate-limit per-host** (sekarang global) — penting saat memindai 10 000 host tapi 1 host
    punya WAF agresif.
11. **`--retry`/backoff** untuk 5xx/timeout (sekarang langsung skip) dan **charset decode**
    (halaman Shift-JIS/GBK tidak ter-decode → bisa FN).
12. **`--login`/cookie jar** (POST form ke halaman login sendiri + simpan cookie) supaya scan
    area terautentikasi tidak perlu `--cookie` manual.
13. **`robots.txt`/`sitemap.xml` crawl** dan `--max-depth` untuk mode web (sekarang hanya 1 URL).
14. **Brotli decode** (kalau nanti ada target yang mengirim `Content-Encoding: br`).
15. **`--json-summary`**: ringkasan per layanan/severity + top host, untuk dashboard.

---

## 9. CI/CD & higiene repo (rekomendasi konkret)

```yaml
# .github/workflows/ci.yml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.21' }
      - run: go vet ./...
      - run: go test -race ./...
      - uses: dominikh/staticcheck-action@v1
      - uses: securego/gosec@master
        with: { args: ./... }
      - uses: golang/govulncheck-action@v1
```

Tambahan:

- `LICENSE` (MIT, sesuai klaim README).
- `.gitleaks.toml` — allowlist `*_test.go` + pola sampel, supaya `gitleaks` di CI tidak
  berteriak 58×.
- Setiap bug baru → satu test baru (kebiasaan bagus yang sudah ada, lanjutkan; lihat `audit_test.go`).
- `goreleaser` untuk rilis binary (Linux/macOS/Windows) — memudahkan pemakaian di WSL/Arch.
- `CHANGELOG.md` + tag (versi sekarang masih `2.3.3` walau ada penambahan besar).

---

## 10. Lampiran — reproduksi

```bash
# build + kualitas
go build -o secrethunter2 .
go vet ./... && staticcheck ./... && go test -race ./...

# benchmark korpus nyata
time ./secrethunter2 -D <dir-bundle-js> -s --no-color
time ./secrethunter2 -D <dir-bundle-js> -s --no-color --no-decode

# uji perilaku yang diperbaiki
./secrethunter2 -u 127.0.0.1:8899/index.html --js-crawl 5     # JS bundle follower
./secrethunter2 -F secrets.txt -o out.txt                     # tanpa ANSI, mode 600
./secrethunter2 -F secrets.txt --fail-on-findings; echo $?     # 2 bila ada temuan
./secrethunter2 -F secrets.txt --min-severity high
./secrethunter2 -l urls.txt --scope target.com --cookie "s=..." -k

# self-scan (dogfood)
./secrethunter2 -D . --ext go -s --no-color

# regresi audit
go test -run TestAudit -v ./...
```

Semua angka di dokumen ini berasal dari eksekusi nyata di mesin kamu (WSL Arch, 8 core),
bukan estimasi.
