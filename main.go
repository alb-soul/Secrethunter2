package main

// ============================================================
// secrethunter2 — main.go (patched)
//
// Build: taruh file ini sebagai main.go di project secrethunter (patterns.go
//        TIDAK berubah), lalu:  go build -o secrethunter2 .
//
// PERUBAHAN vs v1:
//   * --httpx-json <file> : baca URL+body dari output httpx (-json -irr) dan
//     scan body TANPA fetch ulang (body-reuse dari scantarget2). Streaming,
//     aman untuk baris besar (body inline s/d 10MB).
//   * --scope <domain>    : hanya scan record yang host-nya == domain atau
//     subdomain-nya (dipakai saat mode --httpx-json).
//   * Keyword prefilter   : contentLower dihitung sekali; tiap pola di-gate
//     literal wajib (diturunkan aman dari regex) sebelum FindAll → potong CPU.
//   * Shared HTTP transport (keep-alive per-host) → kurangi handshake TLS.
//   * FlareSolverr re-solve saat 403/429 di tengah run (cookie expired).
//   * Buang dead code (maxInt, var _ = regexp.MustCompile).
// ============================================================

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	version   = "2.5.0"
	defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	maxBodyMB = 10
	banner    = `
 _____                     _   _   _             _
/  ___|                   | | | | | |           | |
\ '--.  ___  ___ _ __ ___| |_| |_| |_   _ _ __ | |_ ___ _ __
 '--. \/ _ \/ __| '__/ _ \ __|  _  | | | | '_ \| __/ _ \ '__|
/\__/ /  __/ (__| | |  __/ |_| | | | |_| | | | | ||  __/ |
\____/ \___|\___|_|  \___|\__\_| |_/\__,_|_| |_|\__\___|_|

  Secret & Credential Scanner for Bug Bounty  v%s
`
)

// ─── ANSI Colors ──────────────────────────────────────────────────────────────

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
)

// ─── Config ───────────────────────────────────────────────────────────────────

type Config struct {
	URLs          []string
	Threads       int
	DelayMs       int
	RatePerSec    float64
	UserAgent     string
	FlareSolvrURL string
	OutputFile    string
	OutputJSON    bool
	Timeout       int
	Silent        bool
	Verbose       bool
	NoColor       bool
	MaxBodyBytes  int64
	ExtraHeaders  []string
	Files         []string
	HTTPXJSON     string // v2: file JSONL dari httpx -json -irr
	Scope         string // v2: batasi scan ke domain/subdomain ini

	// ─── v3.1 (audit 2026-11) ───
	MinSeverity    string   // "" = semua; buang finding di bawah level ini
	FailOnFindings bool     // exit 2 bila ada finding (integrasi CI/pipeline)
	Insecure       bool     // -k: lewati verifikasi sertifikat TLS
	ProxyURL       string   // --proxy eksplisit (default: env HTTP(S)_PROXY)
	Cookies        []string // --cookie name=value (repeatable)
	NoDecode       bool     // matikan layer decode/obfuscation (perf)
	JSCrawl        int      // --js-crawl: ikuti <script src> di HTML (maks N, 0=off)
}

// sevRank dipakai untuk filter --min-severity.
var sevRank = map[string]int{
	SevCritical: 5,
	SevHigh:     4,
	SevMedium:   3,
	SevLow:      2,
	SevInfo:     1,
}

// severityAtLeast melaporkan apakah sev >= min (min kosong = selalu lolos).
func severityAtLeast(min, sev string) bool {
	if min == "" {
		return true
	}
	return sevRank[sev] >= sevRank[min]
}

// ─── Finding ──────────────────────────────────────────────────────────────────

type Finding struct {
	URL      string `json:"url"`
	Pattern  string `json:"pattern"`
	Match    string `json:"match"`
	Severity string `json:"severity"`
	Line     int    `json:"line,omitempty"`
}

// ─── FlareSolverr ─────────────────────────────────────────────────────────────

type fsRequest struct {
	Cmd        string `json:"cmd"`
	URL        string `json:"url"`
	MaxTimeout int    `json:"maxTimeout"`
}

type fsResponse struct {
	Status   string     `json:"status"`
	Solution fsSolution `json:"solution"`
	Message  string     `json:"message"`
}

type fsSolution struct {
	UserAgent string     `json:"userAgent"`
	Cookies   []fsCookie `json:"cookies"`
	Response  string     `json:"response"`
}

type fsCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type FSSession struct {
	Cookies   string
	UserAgent string
}

type FSCache struct {
	mu       sync.RWMutex
	sessions map[string]*FSSession
	solving  map[string]*sync.Once
}

func newFSCache() *FSCache {
	return &FSCache{
		sessions: make(map[string]*FSSession),
		solving:  make(map[string]*sync.Once),
	}
}

func (fc *FSCache) Resolve(cfg *Config, domain string) *FSSession {
	fc.mu.RLock()
	if s, ok := fc.sessions[domain]; ok {
		fc.mu.RUnlock()
		return s
	}
	fc.mu.RUnlock()

	fc.mu.Lock()
	if _, ok := fc.solving[domain]; !ok {
		fc.solving[domain] = &sync.Once{}
	}
	once := fc.solving[domain]
	fc.mu.Unlock()

	once.Do(func() {
		sess := solveDomain(cfg, domain)
		fc.mu.Lock()
		fc.sessions[domain] = sess
		fc.mu.Unlock()
	})

	fc.mu.RLock()
	s := fc.sessions[domain]
	fc.mu.RUnlock()
	return s
}

// Invalidate menghapus sesi domain agar Resolve berikutnya solve ulang (v2).
func (fc *FSCache) Invalidate(domain string) {
	fc.mu.Lock()
	delete(fc.sessions, domain)
	delete(fc.solving, domain)
	fc.mu.Unlock()
}

func solveDomain(cfg *Config, domain string) *FSSession {
	targetURL := "https://" + domain
	logVerbose(cfg, "[FS] Solving: %s", domain)

	body, _ := json.Marshal(fsRequest{
		Cmd:        "request.get",
		URL:        targetURL,
		MaxTimeout: 60000,
	})

	req, err := http.NewRequest("POST", cfg.FlareSolvrURL+"/v1", bytes.NewReader(body))
	if err != nil {
		logVerbose(cfg, "[FS] Error solving %s: %v", domain, err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := fsClient.Do(req)
	if err != nil {
		logVerbose(cfg, "[FS] Error solving %s: %v", domain, err)
		return nil
	}
	defer resp.Body.Close()

	var fsResp fsResponse
	if err := json.NewDecoder(resp.Body).Decode(&fsResp); err != nil {
		logVerbose(cfg, "[FS] JSON decode error for %s: %v", domain, err)
		return nil
	}
	if fsResp.Status != "ok" {
		logVerbose(cfg, "[FS] Solve failed for %s: %s", domain, fsResp.Message)
		return nil
	}

	var cookieParts []string
	for _, c := range fsResp.Solution.Cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	sess := &FSSession{
		Cookies:   strings.Join(cookieParts, "; "),
		UserAgent: fsResp.Solution.UserAgent,
	}
	logVerbose(cfg, "[FS] ✓ Solved %s (UA: %s...)", domain, truncate(sess.UserAgent, 30))
	return sess
}

// ─── HTTP Fetcher ─────────────────────────────────────────────────────────────

// httpClient dibagi (keep-alive per-host). Diinisialisasi di main().
var httpClient *http.Client

// fsClient: klien khusus FlareSolverr. Timeout-nya HARUS lebih besar dari
// maxTimeout request FS (60s) — sebelumnya solve selalu di-kill oleh timeout
// 30s milik httpClient (audit 2026-11).
var fsClient *http.Client

// withScheme menambahkan https:// bila URL belum punya skema. Output recon
// (subfinder / httpx tanpa -full) sering berupa domain telanjang.
func withScheme(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	if s == "" || strings.Contains(s, "://") {
		return s
	}
	if strings.HasPrefix(s, "//") {
		return "https:" + s
	}
	if strings.HasPrefix(s, "localhost") || strings.HasPrefix(s, "127.0.0.1") ||
		strings.HasPrefix(s, "[::1]") || strings.HasPrefix(s, "0.0.0.0") {
		return "http://" + s
	}
	return "https://" + s
}

// ansiStripper menulis ke file tanpa escape code ANSI, supaya -o menghasilkan
// teks bersih yang bisa di-grep/di-parse (audit 2026-11).
type ansiStripper struct{ w io.Writer }

var reANSI = regexp.MustCompile("\x1b\\[[0-9;]*m")

// teeOut menulis ke primary (file -o) dan secondary (stdout). Hanya error
// primary yang dikembalikan.
type teeOut struct{ primary, secondary io.Writer }

func (t teeOut) Write(p []byte) (int, error) {
	n, err := t.primary.Write(p)
	_, _ = t.secondary.Write(p)
	return n, err
}

func (a ansiStripper) Write(p []byte) (int, error) {
	if bytes.IndexByte(p, 0x1b) < 0 {
		return a.w.Write(p)
	}
	if _, err := a.w.Write(reANSI.ReplaceAll(p, nil)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func buildClient(cfg *Config) *http.Client {
	perHost := cfg.Threads + 10
	if perHost > 256 {
		perHost = 256
	}
	tlsCfg := &tls.Config{}
	if cfg.Insecure {
		tlsCfg.InsecureSkipVerify = true // #nosec G402 — opt-in via -k untuk target cert rusak
	}
	proxyFn := http.ProxyFromEnvironment
	if cfg.ProxyURL != "" {
		if pu, perr := url.Parse(cfg.ProxyURL); perr == nil {
			proxyFn = http.ProxyURL(pu)
		}
	}
	return &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig:       tlsCfg,
			Proxy:                 proxyFn,
			MaxIdleConns:          512,
			MaxIdleConnsPerHost:   perHost,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 25 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

func fetchURL(cfg *Config, rawURL string, fsCache *FSCache) (string, error) {
	rawURL = withScheme(rawURL)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	domain := parsed.Hostname()

	// hingga 2 attempt: attempt ke-2 hanya jika 403/429 & FlareSolverr aktif
	for attempt := 0; attempt < 2; attempt++ {
		ua := cfg.UserAgent
		var cookie string
		if cfg.FlareSolvrURL != "" && fsCache != nil {
			sess := fsCache.Resolve(cfg, domain)
			if sess != nil {
				ua = sess.UserAgent
				cookie = sess.Cookies
			}
		}

		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		if len(cfg.Cookies) > 0 {
			// gabungkan --cookie dengan cookie FlareSolverr (nama sama: terakhir menang)
			merged := strings.Join(cfg.Cookies, "; ")
			if cookie != "" {
				merged = cookie + "; " + merged
			}
			req.Header.Set("Cookie", merged)
		}
		for _, h := range cfg.ExtraHeaders {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				name, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				if strings.EqualFold(name, "Host") {
					req.Host = val // net/http mengabaikan Header["Host"]
					continue
				}
				req.Header.Set(name, val)
			}
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", err
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			resp.Body.Close()
			// v2: cookie mungkin expired → invalidate & solve ulang, retry sekali
			if cfg.FlareSolvrURL != "" && fsCache != nil && attempt == 0 {
				logVerbose(cfg, "[FS] %d di %s → re-solve cookies & retry", resp.StatusCode, domain)
				fsCache.Invalidate(domain)
				continue
			}
			return "", fmt.Errorf("HTTP %d: blocked (consider --flaresolverr)", resp.StatusCode)
		}
		if resp.StatusCode >= 400 {
			resp.Body.Close()
			return "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		limited := io.LimitReader(resp.Body, cfg.MaxBodyBytes)
		data, err := io.ReadAll(limited)
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		if int64(len(data)) >= cfg.MaxBodyBytes {
			logVerbose(cfg, "[!] %s body kena cap %d MB — mungkin terpotong", rawURL, cfg.MaxBodyBytes/(1024*1024))
		}
		// v3.1: body biner (NUL byte / mayoritas non-printable) tidak mungkin
		// berisi secret tekstual — skip supaya tidak buang CPU & memicu FP.
		if len(data) > 0 && (binaryContentType(resp.Header.Get("Content-Type")) ||
			bytes.IndexByte(data, 0) >= 0 || looksBinary(string(data))) {
			logVerbose(cfg, "[!] %s body biner — dilewati", rawURL)
			return "", fmt.Errorf("skipped (binary body)")
		}
		// v3: scan response headers juga (mirip mode httpx yang menggabung raw_header).
		// Header seperti Set-Cookie, X-Api-Key, Authorization, X-Amz-* sering
		// membawa secret/token di sisi respons.
		if len(resp.Header) > 0 {
			data = append(data, '\n')
			for k, vs := range resp.Header {
				for _, v := range vs {
					data = append(data, k...)
					data = append(data, ':', ' ')
					data = append(data, v...)
					data = append(data, '\n')
				}
			}
		}
		return string(data), nil
	}
	return "", fmt.Errorf("HTTP blocked after retry")
}

// ─── JWT Helper ───────────────────────────────────────────────────────────────

func jwtAlgIsNone(token string) bool {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		padded := parts[0]
		switch len(padded) % 4 {
		case 2:
			padded += "=="
		case 3:
			padded += "="
		}
		decoded, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return false
		}
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return false
	}
	return strings.EqualFold(header.Alg, "none")
}

// ─── Literal gate ────────────────────────────────────────────────────────────
//
// Gate literal per pola (DNF: AND antar-group, OR di dalam group) diturunkan
// dari AST regexp dan dicocokkan dengan satu pass Aho-Corasick — lihat engine.go.
type needLit struct {
	lit  string
	fold bool // case-insensitive (lit sudah lowercase ASCII)
}
type litGroup []needLit // OR

// patternIndex: nama pola → urutan deklarasi. Dipakai dedupeOverlapping sebagai
// tie-break (pola yang dideklarasikan lebih awal = keluarga yang lebih spesifik:
// pola kontekstual regional/vertikal ada di depan, pola bare-prefix di belakang).
var patternIndex map[string]int

// genericPatterns: pola "senjata terakhir" yang menangkap hampir semua bentuk
// rahasia. Kalau pola ini bersaing dengan pola spesifik untuk nilai yang sama,
// pola spesifik yang menang (supaya laporan menyebut layanannya).
var genericPatterns = map[string]bool{
	"Generic Secret / Password in code":                  true,
	"Generic API Key in code":                            true,
	"Password assignment (quoted or bare)":               true,
	"Password assignment bare (env/config)":              true,
	"Password assignment (pass/pwd)":                     true,
	"URI with embedded credentials":                      true,
	"Bearer Token in code":                               true,
	"Freeform credentials near keyword (user:pass)":      true,
	"HTML comment credentials (user:pass)":               true,
	"JS/line comment credentials (user:pass)":            true,
	"Block comment credentials (user:pass)":              true,
	"Username + Password pair assignment":                true,
	"Hardcoded password input value":                     true,
	"Hardcoded password input value (value before type)": true,
	"Encryption Key in code":                             true,
}

func init() {
	patterns = append(patterns, extraPatterns...)
	patterns = append(patterns, coveragePatterns2026b...)
	patternIndex = make(map[string]int, len(patterns))
	for i, p := range patterns {
		if _, dup := patternIndex[p.Name]; !dup {
			patternIndex[p.Name] = i
		}
	}
	buildEngine()
}

// betterFinding melaporkan apakah temuan a lebih disukai daripada b.
// Urutan preferensi: pola spesifik > pola generik, lalu urutan deklarasi pola
// (pola kontekstual/vertikal dideklarasikan lebih dulu daripada pola bare-prefix),
// lalu severity, lalu match terpanjang.
func betterFinding(a, b Finding) bool {
	ga := genericPatterns[strings.TrimSuffix(a.Pattern, " (decoded)")]
	gb := genericPatterns[strings.TrimSuffix(b.Pattern, " (decoded)")]
	if ga != gb {
		return !ga
	}
	if ia, ib := patternIndexOf(a.Pattern), patternIndexOf(b.Pattern); ia != ib {
		return ia < ib
	}
	if sevRank[a.Severity] != sevRank[b.Severity] {
		return sevRank[a.Severity] > sevRank[b.Severity]
	}
	return len(a.Match) >= len(b.Match)
}

func patternIndexOf(patternName string) int {
	name := strings.TrimSuffix(patternName, " (decoded)")
	if i, ok := patternIndex[name]; ok {
		return i
	}
	return len(patterns)
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

type lineIndex struct{ starts []int }

func buildLineIndex(content string) *lineIndex {
	starts := []int{0}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &lineIndex{starts: starts}
}

func (li *lineIndex) lineAt(pos int) int {
	lo, hi := 0, len(li.starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if li.starts[mid] <= pos {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1
}

func (li *lineIndex) lineTextOf(content string, n int) string {
	if n < 1 || n > len(li.starts) {
		return ""
	}
	start := li.starts[n-1]
	end := len(content)
	if n < len(li.starts) {
		end = li.starts[n] - 1
	}
	if end < start {
		end = start
	}
	return content[start:end]
}

// v3: public-by-design keys → downgrade to INFO (filter out with --no-public)
var noPublicGlobal bool

// noDecodeGlobal mematikan layer decode/obfuscation (--no-decode).
var noDecodeGlobal bool
var publicByDesign = map[string]bool{
	"Stripe Live Publishable Key":                       true,
	"Midtrans Client Key (public)":                      true,
	"Langfuse Public Key (public)":                      true,
	"Flutterwave Public Key (FLWPUBK...)":               true,
	"Omise Public Key (public)":                         true,
	"Toss Payments Client Key (public)":                 true,
	"Wompi Public Key (public)":                         true,
	"Paystack Public Key (context, public)":             true,
	"Pagar.me Public Key (context, public)":             true,
	"PayMongo Public Key (context, public)":             true,
	"Culqi Public Key (context, public)":                true,
	"Clerk Publishable Key (pk_live_/pk_test_)":         true,
	"PubNub Subscribe Key":                              true,
	"Google reCAPTCHA Site Key":                         true,
	"Mapbox Public Token":                               true,
	"Mapbox Temporary Token":                            true,
	"Algolia Search-Only API Key":                       true,
	"Supabase Publishable Key (sb_publishable_)":        true,
	"PostHog Project API Key (phc_)":                    true,
	"Segment Write Key (context)":                       true,
	"Amplitude API Key":                                 true,
	"Firebase API Key / Config":                         true,
	"Cloudflare Turnstile Site Key (0x4AAAA)":           true,
	"Shopify Storefront Access Token (context, public)": true,
}

// ─── Scanner v3 (parallel-aware) ─────────────────────────────────────────────
//
// Body besar (>1MB) di-scan paralel: pattern dibagi rata ke 8 worker, tiap
// worker mengumpulkan kandidat match MENTAH, lalu digabung dengan URUTAN
// PATTERN YANG SAMA seperti versi serial + dedup global by match (dicatat
// SEBELUM filter placeholder/panjang) → output deterministik & identik dengan
// perilaku lama. Body kecil memakai jalur serial agar overhead goroutine 0.
// Bonus: pattern tanpa capture group (MatchGroup==0) memakai FindAllStringIndex
// (tanpa biaya capture group), dan line-index hanya dibangun bila ada kandidat.

const (
	parallelScanMinBytes = 1024 * 1024
	parallelScanWorkers  = 8
)

type patternCandidate struct {
	pi       int
	startPos int
	endPos   int
}

// ─── Obfuscated-layer decode ──────────────────────────────────────────────
// Bundle minified menyembunyikan secret di balik \x escapes, String.fromCharCode(),
// blob base64, split "a"+"b", dan string reversed. decodedVariants mengembalikan
// rewrite yg ekuivalen scr semantik; scanContent memindai tiap varian dan menggabung
// temuan (dedupe by pattern+match, ditandai " (decoded)", Line=0).
// Guard presisi: transformasi identik-kecuali-base64 (digate printable-ratio +
// skip payload data:-URI); varian hanya dibangun bila sinyalnya ada; cap 2MB.
var (
	reHexEsc    = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	reUniEsc    = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	reCharCode  = regexp.MustCompile(`String\.fromCharCode\(\s*([0-9][0-9\s,]*)\s*\)`)
	reB64Blob   = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	reReversed  = regexp.MustCompile(`"([^"\\\n]{16,})"\.split\(\s*""\s*\)\.reverse\(\)|'([^'\\\n]{16,})'\.split\(\s*''\s*\)\.reverse\(\)`)
	reConcat    = regexp.MustCompile(`"([^"\\\n]*)"\s*\+\s*"([^"\\\n]*)"`)
	reVarAssign = regexp.MustCompile(`(?:(?:var|let|const)\s+|,)([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*("([^"\\\n]{6,200})"|'([^'\\\n]{6,200})')`)
	reIdent     = regexp.MustCompile(`\b[A-Za-z_$][A-Za-z0-9_$]*\b`)
)

func unescapeJS(s string) string {
	s = reHexEsc.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:], 16, 8)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
	return reUniEsc.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:], 16, 16)
		if err != nil || v >= 0xD800 && v <= 0xDFFF {
			return m
		}
		return string(rune(v))
	})
}

func evalCharCodes(s string) string {
	return reCharCode.ReplaceAllStringFunc(s, func(m string) string {
		open := strings.Index(m, "(")
		inner := m[open+1 : len(m)-1]
		parts := strings.Split(inner, ",")
		if len(parts) < 6 || len(parts) > 300 {
			return m
		}
		var b strings.Builder
		for _, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 32 || n > 126 {
				return m
			}
			b.WriteByte(byte(n))
		}
		return `"` + b.String() + `"`
	})
}

func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	ok := 0
	for _, c := range b {
		if c >= 32 && c <= 126 || c == '\n' || c == '\r' || c == '\t' {
			ok++
		}
	}
	return float64(ok) / float64(len(b))
}

func decodeB64Blobs(s string) string {
	var out strings.Builder
	rest := s
	for {
		loc := reB64Blob.FindStringIndex(rest)
		if loc == nil {
			out.WriteString(rest)
			break
		}
		start, end := loc[0], loc[1]
		// skip payload data:-URI (font/gambar/svg — biner atau markup, bukan secret)
		if start >= 7 && rest[start-7:start] == "base64," {
			out.WriteString(rest[:end])
			rest = rest[end:]
			continue
		}
		blob := rest[start:end]
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(blob)
		}
		if err != nil || len(raw) < 8 || printableRatio(raw) < 0.7 {
			out.WriteString(rest[:end])
			rest = rest[end:]
			continue
		}
		out.WriteString(rest[:start])
		out.WriteString(string(raw))
		rest = rest[end:]
	}
	return out.String()
}

func evalReversed(s string) string {
	// grup 1 = varian quote-ganda, grup 2 = quote-tunggal (satu selalu kosong).
	// ReplaceAllString tak bisa membalik — pakai Func + reverse manual.
	return reReversed.ReplaceAllStringFunc(s, func(m string) string {
		sub := reReversed.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		r := []rune(sub[1] + sub[2])
		if len(r) < 16 {
			return m
		}
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return `"` + string(r) + `"`
	})
}

func joinConcat(s string) string {
	for i := 0; i < 5; i++ {
		n := reConcat.ReplaceAllString(s, `"$1$2"`)
		if n == s {
			break
		}
		s = n
	}
	return s
}

// propagateVars: one-hop constant propagation for minified JS — versi single-pass.
//
// Versi lama O(decl × n): tiap deklarasi meng-compile 2 regex baru lalu men-scan
// SELURUH body (terukur 11.6 s untuk bundle JS 1.1 MB, dipanggil sekali per
// varian decode → ~45 s/body). Versi ini memindai identifier satu kali,
// menghitung kemunculan per nama, lalu mengganti dari kiri ke kanan — syarat
// keamanan tetap sama (nama muncul tepat 2x: 1 deklarasi + 1 pemakaian bernilai).
func propagateVars(s string) string {
	if !(strings.Contains(s, "var ") || strings.Contains(s, "let ") || strings.Contains(s, "const ")) {
		return s
	}
	type decl struct {
		lit        string
		isAmbiguos bool
	}
	decls := make(map[string]*decl, 64)
	for _, loc := range reVarAssign.FindAllStringSubmatchIndex(s, -1) {
		if loc[2] < 0 || loc[4] < 0 {
			continue
		}
		name := s[loc[2]:loc[3]]
		lit := s[loc[4]:loc[5]]
		if strings.Contains(lit, "\n") {
			continue
		}
		if d, ok := decls[name]; ok {
			if d.lit != lit {
				d.isAmbiguos = true
			}
			continue
		}
		decls[name] = &decl{lit: lit}
	}
	for name, d := range decls {
		if d.isAmbiguos {
			delete(decls, name)
		}
	}
	if len(decls) == 0 {
		return s
	}

	// satu pass: posisi semua kemunculan identifier yang relevan
	type pos struct{ start, end int }
	occ := make(map[string][]pos, len(decls))
	for _, loc := range reIdent.FindAllStringIndex(s, -1) {
		if _, want := decls[s[loc[0]:loc[1]]]; !want {
			continue
		}
		occ[s[loc[0]:loc[1]]] = append(occ[s[loc[0]:loc[1]]], pos{loc[0], loc[1]})
	}

	type repl struct {
		start, end int
		lit        string
	}
	repls := make([]repl, 0, len(decls))
	for name, d := range decls {
		ps := occ[name]
		if len(ps) != 2 {
			continue // 0x (dead) atau >1x (tidak aman) → skip, sama seperti versi lama
		}
		declIdx, useIdx := -1, -1
		for i, p := range ps {
			j := p.end
			for j < len(s) && isSpaceByte(s[j]) {
				j++
			}
			if j < len(s) && s[j] == '=' {
				if j+1 < len(s) && (s[j+1] == '=' || s[j+1] == '>') {
					// == / === / => : bukan deklarasi
				} else {
					if declIdx != -1 {
						declIdx = -2
						break
					}
					declIdx = i
					continue
				}
			}
			if useIdx != -1 {
				useIdx = -2
				break
			}
			useIdx = i
		}
		if declIdx < 0 || useIdx < 0 {
			continue
		}
		u := ps[useIdx]
		// konteks kiri harus posisi nilai, bukan key/identifier lain
		pi := u.start - 1
		for pi >= 0 && isSpaceByte(s[pi]) {
			pi--
		}
		if pi < 0 {
			continue
		}
		switch s[pi] {
		case ':', '=', '(', '[', '!':
		default:
			continue
		}
		ni := u.end
		for ni < len(s) && isSpaceByte(s[ni]) {
			ni++
		}
		if ni < len(s) && (s[ni] == ':' || s[ni] == '=' || s[ni] == '(') {
			continue
		}
		repls = append(repls, repl{u.start, u.end, d.lit})
	}
	if len(repls) == 0 {
		return s
	}
	sort.Slice(repls, func(i, j int) bool { return repls[i].start < repls[j].start })
	out := make([]byte, 0, len(s))
	prev := 0
	for _, r := range repls {
		if r.start < prev {
			continue // overlap (tidak mestinya terjadi)
		}
		out = append(out, s[prev:r.start]...)
		out = append(out, r.lit...)
		prev = r.end
	}
	out = append(out, s[prev:]...)
	return string(out)
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func decodedVariants(content string) []string {
	if len(content) == 0 || len(content) > 2000000 {
		return nil
	}
	var out []string
	if strings.Contains(content, "\\x") || strings.Contains(content, "\\u") {
		if v := unescapeJS(content); v != content {
			out = append(out, v)
		}
	}
	if strings.Contains(content, "fromCharCode") {
		if v := evalCharCodes(content); v != content {
			out = append(out, v)
		}
	}
	if strings.Contains(content, "reverse()") {
		if v := evalReversed(content); v != content {
			out = append(out, v)
		}
	}
	if strings.Contains(content, `+"`) || strings.Contains(content, `"+`) {
		if v := joinConcat(content); v != content {
			out = append(out, v)
		}
	}
	if strings.Contains(content, "atob(") || reB64Blob.MatchString(content) {
		if v := decodeB64Blobs(content); v != content {
			out = append(out, v)
		}
	}
	// propagasi konstanta: pada raw + pada tiap varian (literal hasil decode ikut ter-link).
	// cth: var n=fromCharCode(..) + {key:n}; var e="ghp_"+".." + {token:e}.
	if p := propagateVars(content); p != content {
		out = append(out, p)
	}
	var linked []string
	for _, v := range out {
		if p := propagateVars(v); p != v {
			linked = append(linked, p)
		}
	}
	return append(out, linked...)
}

func scanContent(rawURL, content string) []Finding {
	base := scanSingle(rawURL, content)
	if noDecodeGlobal {
		return dedupeOverlapping(base)
	}
	vars := decodedVariants(content)
	if len(vars) == 0 {
		return dedupeOverlapping(base)
	}
	seen := make(map[string]struct{}, len(base)*2+8)
	for _, f := range base {
		seen[f.Pattern+"\x00"+f.Match] = struct{}{}
	}
	out := base
	for _, v := range vars {
		for _, f := range scanSingle(rawURL, v) {
			if _, dup := seen[f.Pattern+"\x00"+f.Match]; dup {
				continue
			}
			f.Pattern += " (decoded)"
			f.Line = 0
			k := f.Pattern + "\x00" + f.Match
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, f)
		}
	}
	return dedupeOverlapping(out)
}

// dedupeOverlapping membuang temuan yang teksnya saling mengandung pada URL yang
// sama — mis. `sk_live_…` dilaporkan dua kali (pola Stripe + pola Clerk), atau URI
// database dilaporkan oleh pola spesifik DAN pola generik "URI with embedded
// credentials". Yang dipertahankan: severity tertinggi; bila seri, match terpanjang.
func dedupeOverlapping(in []Finding) []Finding {
	if len(in) < 2 {
		return in
	}
	keep := make([]bool, len(in))
	for i := range keep {
		keep[i] = true
	}
	for i := 0; i < len(in); i++ {
		for j := i + 1; j < len(in); j++ {
			a, b := in[i].Match, in[j].Match
			if a == "" || b == "" || in[i].URL != in[j].URL {
				continue
			}
			if !strings.Contains(a, b) && !strings.Contains(b, a) {
				continue
			}
			// hanya dedupe bila kedua match praktis nilai yang sama (rasio
			// panjang >= 0.85). Tanpa guard ini, match "password saja" dari pola
			// spesifik (mis. Messaging URI) bisa termakan match URI generik yang
			// lebih panjang.
			short, long := len(a), len(b)
			if short > long {
				short, long = long, short
			}
			if float64(short)/float64(long) < 0.85 {
				continue
			}
			wi, wj := sevRank[in[i].Severity], sevRank[in[j].Severity]
			_ = wi
			_ = wj
			if betterFinding(in[i], in[j]) {
				keep[j] = false
			} else {
				keep[i] = false
			}
		}
	}
	out := in[:0]
	for i, f := range in {
		if keep[i] {
			out = append(out, f)
		}
	}
	return out
}

// scanSingle memindai satu teks: satu pass Aho-Corasick (engine.go) lalu regex
// per pola (window/full). Body ≥1 MB: pola dibagi ke beberapa goroutine.
func scanSingle(rawURL, content string) []Finding {
	if len(content) >= parallelScanMinBytes && len(patterns) > 1 {
		return scanContentPar(rawURL, content)
	}
	return scanContentSeq(rawURL, content)
}

func scanContentSeq(rawURL, content string) []Finding {
	occ := engAC.find(content)
	defer occ.release()
	return mergeCandidates(rawURL, content, [][]patternCandidate{collectCandidates(content, occ, 0, len(patterns))})
}

// finalizeCandidate menjalankan seluruh guard pasca-regex untuk satu kandidat
// match dan mengembalikan Finding final. Satu-satunya implementasi (dipakai
// jalur serial, paralel, dan windowed) supaya perilakunya identik.
func finalizeCandidate(rawURL, content string, li *lineIndex, pi, startPos, endPos int) (Finding, bool) {
	p := &patterns[pi]
	match := content[startPos:endPos]
	// v3.1: dedupe by teks-match dipindah ke dedupeOverlapping() (satu tempat)
	// agar pola kontekstual tidak kalah oleh pola generik yang match lebih dulu.
	if len(match) < 6 || isPlaceholder(match) || credPlaceholderWords[strings.ToLower(match)] {
		return Finding{}, false
	}
	// audit-2026-11b: pola konteks `…([A-Za-z0-9]{40})['"]?` (penutup opsional)
	// bisa mengambil 40 char PERTAMA dari token yang lebih panjang (mis. `bkua_…`
	// 45 char → nilai terpotong yang lalu menang dedupe). Capture group yang
	// berakhir di tengah run alfanumerik = nilai terpotong → buang.
	if p.MatchGroup > 0 && endPos < len(content) && isAlnumByte(content[endPos]) && isAlnumByte(content[endPos-1]) {
		return Finding{}, false
	}
	lineNum := li.lineAt(startPos)
	lt := li.lineTextOf(content, lineNum)
	if dropFinding(p, match, lt) {
		return Finding{}, false
	}
	if p.Name == "Twitter/X Bearer Token" || strings.HasPrefix(p.Name, "Square") {
		if strings.Contains(lt, "base64,") || strings.Contains(lt, "data:") {
			return Finding{}, false
		}
	}
	if standaloneTokenPatterns[p.Name] && isBase64Slice(content, startPos, endPos) {
		return Finding{}, false
	}
	if identifierPronePatterns[p.Name] && looksLikeIdentifier(match) {
		return Finding{}, false
	}
	if basicAuthPatterns[p.Name] && !basicAuthValid(match) {
		return Finding{}, false
	}
	if humanCredPatterns[p.Name] && isHumanCredFP(p.Name, match, lt) {
		return Finding{}, false
	}
	patternName := p.Name
	severity := p.Severity
	if publicByDesign[p.Name] {
		if noPublicGlobal {
			return Finding{}, false
		}
		severity = SevInfo
	}
	if p.Name == "JSON Web Token (JWT)" {
		patternName, severity = classifyJWT(match)
		if severity == SevInfo && noPublicGlobal {
			return Finding{}, false
		}
	}
	return Finding{
		URL:      rawURL,
		Pattern:  patternName,
		Match:    match,
		Severity: severity,
		Line:     lineNum,
	}, true
}

// identifierPronePatterns: token berprefiks pendek/generik (re_, rnd_, pa-, fc-, …)
// yang prefiksnya juga lazim sebagai awalan identifier snake/kebab-case di bundle
// JS/CSS (`re_render_component`, `pa-container-wrapper`). Token asli berisi
// karakter acak base62 sehingga hampir pasti memuat digit atau huruf campuran.
var identifierPronePatterns = map[string]bool{
	"Resend API Key (re_)":                             true,
	"Render API Key (rnd_)":                            true,
	"Xata API Key (xau_)":                              true,
	"Jina AI API Key (jina_)":                          true,
	"Voyage AI API Key (pa-)":                          true,
	"Cerebras API Key (csk-)":                          true,
	"NVIDIA NIM API Key (nvapi-)":                      true,
	"Fireworks AI Key (fw_)":                           true,
	"Tavily API Key (tvly-)":                           true,
	"Firecrawl API Key (fc-)":                          true,
	"LlamaCloud / LlamaIndex Key (llx-)":               true,
	"Apify API Token (apify_api_)":                     true,
	"n8n Personal API Key (n8n_api_)":                  true,
	"RunPod API Key (rpa_)":                            true,
	"Honeybadger API Key (hbp_)":                       true,
	"Weglot API Key":                                   true,
	"Mailgun Private API Key":                          true,
	"Mailgun Public API Key":                           true,
	"crates.io API Token (cio)":                        true,
	"Typeform Personal Token (tfp_)":                   true,
	"Docker Hub Personal Access Token (dckr_pat_)":     true,
	"Cal.com API Key (cal_live/cal_test)":              true,
	"Grafana Cloud Access Policy Token (glc_)":         true,
	"Axiom.co Dataset Token (xaat-)":                   true,
	"GitLab OAuth App Secret (gloas-)":                 true,
	"GitLab Pipeline Trigger Token (glptt-)":           true,
	"GitLab Feed Token (glfeed-)":                      true,
	"Figma Access Token (figd_/figu_/figr_)":           true,
	"Pinecone API Key (pcsk_)":                         true,
	"Ory API Key (ory_pat_/ory_apikey_/ory_wak_)":      true,
	"Supabase Publishable Key (sb_publishable_)":       true,
	"Supabase Secret Key (sb_secret_)":                 true,
	"PostHog Personal API Key (phx_)":                  true,
	"PostHog Project API Key (phc_)":                   true,
	"Vercel Access Token (vcp_)":                       true,
	"Stytch Live Secret (secret-live-)":                true,
	"Stytch Test Secret (secret-test-)":                true,
	"PlanetScale Service Token (pscale_tkn_)":          true,
	"PlanetScale DB Password (pscale_pw_)":             true,
	"PlanetScale OAuth Token (pscale_oauth_)":          true,
	"Vault Service Token (hvs.)":                       true,
	"Vault Batch Token (hvb.)":                         true,
	"Vault Recovery Token (hvr.)":                      true,
	"Midtrans Server Key":                              true,
	"Midtrans Client Key (public)":                     true,
	"Mercado Pago Credential (APP_USR-)":               true,
	"Omise Secret Key":                                 true,
	"Omise Public Key (public)":                        true,
	"Toss Payments Secret Key":                         true,
	"Toss Payments Client Key (public)":                true,
	"Wompi Private Key":                                true,
	"Wompi Integrity/Events Secret":                    true,
	"Wompi Public Key (public)":                        true,
	"Vercel Blob Read-Write Token":                     true,
	"WorkOS Secret Key (sk_test/sk_prod/sk_live)":      true,
	"Netlify Personal Access Token (nfp_)":             true,
	"Sentry Auth Token (sntrys_/sntryu_)":              true,
	"Tailscale Auth/API Key (tskey-)":                  true,
	"GitLab Runner Authentication Token (glrt-)":       true,
	"GitLab Agent Token (glagent-)":                    true,
	"AWS AppSync API Key (da2-)":                       true,
	"Docker Hub Organization Access Token (dckr_oat_)": true,
}

// looksLikeIdentifier: bagian SETELAH prefix tanpa digit DAN huruf satu jenis
// (semua kecil / semua besar) → identifier/kata (snake/kebab-case), bukan token
// acak. Prefix (s.d. separator pertama dalam 12 char) diabaikan supaya digit di
// prefix seperti `da2-`/`n8n_` tidak menyamarkan identifier.
func looksLikeIdentifier(m string) bool {
	for i := 0; i < len(m) && i < 12; i++ {
		if c := m[i]; c == '-' || c == '_' || c == '.' || c == ':' {
			m = m[i+1:]
			break
		}
	}
	var digit, up, low bool
	for i := 0; i < len(m); i++ {
		c := m[i]
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= 'a' && c <= 'z':
			low = true
		}
	}
	return !digit && !(up && low)
}

// basicAuthPatterns: nilai = base64(user:pass); divalidasi dengan decode.
var basicAuthPatterns = map[string]bool{
	"Authorization: Basic header":         true,
	"Basic Auth Token in code":            true,
	"Docker config.json auth (base64)":    true,
	"npm legacy _auth (base64 user:pass)": true,
}

// basicAuthValid: base64 harus ter-decode menjadi teks printable (UTF-8 valid,
// tanpa karakter kontrol). Umumnya `user:pass`, tapi ':' TIDAK diwajibkan —
// kasus nyata (binus-2026-09) memakai `Basic base64(UUID)`. Yang ditolak:
// base64 yang ter-decode menjadi biner (nonce, hash, id acak).
func basicAuthValid(b64 string) bool {
	s := strings.TrimSpace(b64)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return false
		}
	}
	if len(raw) < 4 || !utf8.Valid(raw) {
		return false
	}
	for _, r := range string(raw) {
		if r < 32 || r == 0x7f || r == utf8.RuneError {
			return false
		}
	}
	return true
}

// classifyJWT menentukan nama & severity temuan JWT dari header/payload:
// alg:none → CRITICAL; Supabase service_role → CRITICAL (bypass RLS);
// Supabase anon → INFO (publik by design); lainnya LOW.
func classifyJWT(token string) (string, string) {
	if jwtAlgIsNone(token) {
		return "JWT with alg:none (Forgeable — Auth Bypass)", SevCritical
	}
	claims := jwtClaims(token)
	role, _ := claims["role"].(string)
	iss, _ := claims["iss"].(string)
	switch {
	case role == "service_role":
		return "Supabase Service Role Key (JWT role=service_role)", SevCritical
	case role == "anon" && strings.Contains(strings.ToLower(iss), "supabase"):
		return "Supabase Anon Key (JWT, public)", SevInfo
	}
	return "JSON Web Token (JWT)", SevLow
}

func jwtClaims(token string) map[string]any {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return nil
	}
	seg := strings.TrimRight(parts[1], "=")
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// collectCandidates menjalankan regex untuk rentang pattern [s,e) dan
// mengembalikan kandidat mentah (belum di-filter / dedup global).
func collectCandidates(content string, occ *occTable, s, e int) []patternCandidate {
	var out []patternCandidate
	for pi := s; pi < e; pi++ {
		out = patternCandidates(pi, content, occ, out)
	}
	return out
}

// scanContentPar: body besar — pola dibagikan dinamis (work-stealing lewat
// counter atomik) karena biaya per pola sangat timpang (window vs full scan).
// Kandidat disimpan per indeks pola lalu digabung berurutan → hasil identik
// dengan versi serial.
func scanContentPar(rawURL, content string) []Finding {
	occ := engAC.find(content)
	defer occ.release()
	np := len(patterns)
	workers := parallelScanWorkers
	if n := runtime.GOMAXPROCS(0); workers > n {
		workers = n
	}
	perPat := make([][]patternCandidate, np)
	var next atomic.Int32
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				pi := int(next.Add(1)) - 1
				if pi >= np {
					return
				}
				perPat[pi] = patternCandidates(pi, content, occ, nil)
			}
		}()
	}
	wg.Wait()
	return mergeCandidates(rawURL, content, perPat)
}

// mergeCandidates meniru persis post-processing serial dan menjaga total order:
// kelompok worker dikunjungi sesuai urutan slot (≈ urutan indeks pattern naik),
// sehingga hasilnya identik dengan versi non-parallel.
func mergeCandidates(rawURL, content string, groups [][]patternCandidate) []Finding {
	var total int
	for _, g := range groups {
		total += len(g)
	}
	if total == 0 {
		return nil
	}
	li := buildLineIndex(content) // dibangun hanya jika ada kandidat (lazy)
	var findings []Finding
	for _, g := range groups {
		for _, c := range g {
			if f, ok := finalizeCandidate(rawURL, content, li, c.pi, c.startPos, c.endPos); ok {
				findings = append(findings, f)
			}
		}
	}
	return findings
}

// standaloneTokenPatterns: bare-prefix token patterns that must stand alone,
// not be a slice of a longer base64 run (inline images, data URIs, Blogger
// photo URLs, Cloudflare challenge blobs). Go RE2 has no lookarounds, so the
// adjacency check is done here in code.
// Deliberately excluded: Telegram Bot Token (real tokens glue to 'bot' in
// /bot<token>/ URLs), JWT family (own alg:none logic), URI/key-block/context
// patterns (already anchored).
var standaloneTokenPatterns = map[string]bool{
	"Adyen API Key (AQE\u2026)":                        true,
	"Google API Key":                                   true,
	"GitHub Personal Access Token (ghp_)":              true,
	"GitHub Fine-grained PAT":                          true,
	"GitHub OAuth Access Token (gho_)":                 true,
	"GitHub App User-to-Server Token (ghu_)":           true,
	"GitHub App Server-to-Server Token (ghs_)":         true,
	"GitHub App Refresh Token (ghr_)":                  true,
	"GitLab Personal Access Token":                     true,
	"GitLab Runner Registration Token":                 true,
	"GitLab CI/CD Job Token":                           true,
	"GitLab Deploy Token":                              true,
	"GitLab OAuth App Secret (gloas-)":                 true,
	"GitLab Pipeline Trigger Token (glptt-)":           true,
	"GitLab Feed Token (glfeed-)":                      true,
	"Grafana API Key":                                  true,
	"Stripe Live Secret Key":                           true,
	"Stripe Test Secret Key":                           true,
	"Stripe Live Publishable Key":                      true,
	"Stripe Restricted Key":                            true,
	"Stripe Webhook Secret":                            true,
	"Slack Bot Token (xoxb-)":                          true,
	"Slack User Token (xoxp-)":                         true,
	"Slack App-level Token (xapp-)":                    true,
	"Slack OAuth v2 Token (xoxe-)":                     true,
	"Square Access Token":                              true,
	"Square OAuth Client Secret (sq0csp-)":             true,
	"Square Application ID (sq0idp-)":                  true,
	"Square Sandbox Token":                             true,
	"Twitter/X Bearer Token":                           true,
	"Twilio Account SID":                               true,
	"Twilio API Key SID":                               true,
	"Mailgun Private API Key":                          true,
	"Mailgun Public API Key":                           true,
	"Shopify Admin API Access Token":                   true,
	"Shopify Partner API Token":                        true,
	"Shopify Custom App Token":                         true,
	"Shopify Shared Secret":                            true,
	"Mapbox Secret Token":                              true,
	"Mapbox Public Token":                              true,
	"Mapbox Temporary Token":                           true,
	"Razorpay Live Key":                                true,
	"Razorpay Test Key":                                true,
	"AWS Access Key ID":                                true,
	"AWS STS / Assumed Role Token":                     true,
	"Alibaba Cloud AccessKey ID (LTAI)":                true,
	"Tencent Cloud SecretId (AKID)":                    true,
	"Scaleway Access Key (SCW)":                        true,
	"Google OAuth Access Token":                        true,
	"Firebase Cloud Messaging (FCM) Server Key":        true,
	"Facebook / Meta Access Token":                     true,
	"Instagram Graph API Token (EAAJj...)":             true,
	"WhatsApp Cloud API Token (EAAG)":                  true,
	"OpenAI API Key (legacy)":                          true,
	"OpenAI API Key (project)":                         true,
	"OpenAI Service Account Key":                       true,
	"Anthropic API Key":                                true,
	"Anthropic Admin Key (sk-ant-admin01-)":            true,
	"Replicate API Token":                              true,
	"Hugging Face Access Token":                        true,
	"Cerebras API Key (csk-)":                          true,
	"NVIDIA NIM API Key (nvapi-)":                      true,
	"Voyage AI API Key (pa-)":                          true,
	"Groq API Key (gsk_)":                              true,
	"OpenRouter API Key (sk-or-v1-)":                   true,
	"Fireworks AI Key (fw_)":                           true,
	"Perplexity API Key (pplx-)":                       true,
	"xAI API Key (xai-)":                               true,
	"LangSmith API Key (lsv2_)":                        true,
	"Pinecone API Key (pcsk_)":                         true,
	"Tavily API Key (tvly-)":                           true,
	"Firecrawl API Key (fc-)":                          true,
	"LlamaCloud / LlamaIndex Key (llx-)":               true,
	"Fly.io Token (fm2_)":                              true,
	"Fly.io Legacy Token (fo1_)":                       true,
	"Figma Access Token (figd_/figu_/figr_)":           true,
	"New Relic User API Key (NRAK-)":                   true,
	"New Relic Insights Query Key (NRIQ)":              true,
	"Dynatrace Token":                                  true,
	"PubNub Subscribe Key":                             true,
	"PubNub Publish Key":                               true,
	"PubNub Secret Key (sec-c-)":                       true,
	"PostHog Personal API Key (phx_)":                  true,
	"PostHog Project API Key (phc_)":                   true,
	"Axiom.co Dataset Token (xaat-)":                   true,
	"Dropbox Long-lived Token":                         true,
	"NPM Access Token":                                 true,
	"PyPI Upload Token (pypi-)":                        true,
	"RubyGems API Key (rubygems_)":                     true,
	"SonarQube User Token":                             true,
	"SonarQube Project Analysis Token":                 true,
	"SonarCloud Token":                                 true,
	"Linear API Key":                                   true,
	"Notion Integration Token":                         true,
	"Notion Internal Integration Token (ntn_)":         true,
	"Airtable Personal Access Token":                   true,
	"Sentry Auth Token (sntrys_/sntryu_)":              true,
	"Postman API Key (PMAK-)":                          true,
	"Tailscale Auth/API Key (tskey-)":                  true,
	"Doppler Token (dp.xx.)":                           true,
	"Databricks Personal Access Token (dapi)":          true,
	"DigitalOcean Personal Access Token":               true,
	"DigitalOcean OAuth Token":                         true,
	"DigitalOcean Refresh Token":                       true,
	"DigitalOcean Functions Token (dof_v1_)":           true,
	"DigitalOcean Spaces Access Key (DO00)":            true,
	"Vault Service Token (hvs.)":                       true,
	"Vault Batch Token (hvb.)":                         true,
	"Vault Recovery Token (hvr.)":                      true,
	"Vercel Access Token (vcp_)":                       true,
	"PlanetScale Service Token (pscale_tkn_)":          true,
	"PlanetScale DB Password (pscale_pw_)":             true,
	"PlanetScale OAuth Token (pscale_oauth_)":          true,
	"Supabase Publishable Key (sb_publishable_)":       true,
	"Supabase Secret Key (sb_secret_)":                 true,
	"Clerk Secret Key (sk_live_)":                      true,
	"Clerk Secret Key (sk_test_)":                      true,
	"Clerk Publishable Key (pk_live_/pk_test_)":        true,
	"WorkOS Secret Key (sk_test/sk_prod/sk_live)":      true,
	"Cal.com API Key (cal_live/cal_test)":              true,
	"SendGrid API Key":                                 true,
	"Brevo API Key (xkeysib-)":                         true,
	"Brevo SMTP Key (xsmtpsib-)":                       true,
	"Flutterwave Secret Key (FLWSECK...)":              true, // audit-2026-11b: nama lama salah ketik → guard tak aktif
	"Flutterwave Public Key (FLWPUBK...)":              true,
	"Shippo API Key":                                   true,
	"Typeform Personal Token (tfp_)":                   true,
	"Adafruit IO Key (aio_)":                           true,
	"Resend API Key (re_)":                             true,
	"Docker Hub Personal Access Token (dckr_pat_)":     true,
	"Render API Key (rnd_)":                            true,
	"Pulumi Access Token (pul-)":                       true,
	"Xata API Key (xau_)":                              true,
	"Ory API Key (ory_pat_/ory_apikey_/ory_wak_)":      true,
	"Jina AI API Key (jina_)":                          true,
	"Apify API Token (apify_api_)":                     true,
	"n8n Personal API Key (n8n_api_)":                  true,
	"Weglot API Key":                                   true,
	"Netlify Personal Access Token (nfp_)":             true,
	"JFrog Access Token (AKCp)":                        true,
	"Atlassian API Token (ATATT3)":                     true,
	"Atlassian Scoped Access Token (ATCTT3)":           true,
	"Bitbucket App Password (ATBB)":                    true,
	"Twitch OAuth Token":                               true,
	"Salesforce Access Token":                          true,
	"Yandex API Key (AQVN)":                            true,
	"ClickUp Personal Token (pk_<id>_)":                true,
	"Stytch Live Secret (secret-live-)":                true,
	"Stytch Test Secret (secret-test-)":                true,
	"crates.io API Token (cio)":                        true,
	"Cloudflare Turnstile Secret Key (0x4AAAA, long)":  true,
	"Cloudflare Turnstile Site Key (0x4AAAA)":          true,
	"RunPod API Key (rpa_)":                            true,
	"LaunchDarkly SDK/Mobile/API Key (sdk-/mob-/api-)": true,
	"1Password Service Account Token (ops_)":           true,
	"Terraform Cloud / HCP Token (atlasv1)":            true,
	"Fal.ai API Key (key_id:sk_live_...)":              true,
	"PayPal / Braintree Access Token":                  true,
	"HubSpot Private App Token":                        true,
	"Discord Bot Token":                                true,
	"Google Cloud Service Account (type field)":        true,
	"Supabase Service Role Key":                        true,
	"Slack Webhook URL":                                true,
	"Mailchimp API Key":                                true,
	"Microsoft Teams Webhook":                          true,
	"Azure SAS Token":                                  true,
	"Asana Personal Access Token":                      true,
	"Cloudinary URL":                                   true,
	"Grafana Cloud Access Policy Token (glc_)":         true,
	"Amazon MWS Auth Token":                            true,
	"Ghost Admin API Key (id:secret)":                  true,
	"DeepL API Key (free :fx)":                         true,
	"Honeybadger API Key (hbp_)":                       true,
	// audit-2026-11b (patterns_2026b.go)
	"Anthropic OAuth Token (sk-ant-oat01-/ort01-)":     true,
	"OpenAI Admin Key (sk-admin-)":                     true,
	"Hugging Face Org Token (api_org_)":                true,
	"Prefect API Key (pnu_)":                           true,
	"Cloudflare API Token (cfut_/cfat_/cfk_)":          true,
	"Heroku API Key v2 (HRKU-)":                        true,
	"CircleCI Personal API Token (CCIPAT_)":            true,
	"Buildkite User Access Token (bkua_)":              true,
	"Contentful Personal Access Token (CFPAT-)":        true,
	"PayPal OAuth Access Token (A21AA)":                true,
	"New Relic Insert Key (NRII-)":                     true,
	"MailerSend API Token (mlsn.)":                     true,
	"GitLab Runner Authentication Token (glrt-)":       true,
	"GitLab Agent Token (glagent-)":                    true,
	"Docker Hub Organization Access Token (dckr_oat_)": true,
}

// isBase64Slice reports whether the match at [startPos,endPos) is a slice of a
// longer base64/base64url run (inline images, data URIs, Blogger photo URLs,
// Cloudflare challenge blobs) rather than a standalone token.
// Left: any base64 char means glued (a left '=' as in key=... is allowed).
// Right: a short overhang is tolerated (real token longer than the pattern
// cap, e.g. 47-char pk_live_ vs a 34-char cap); a long continuation means
// the pattern cap cut a blob mid-run.
func isBase64Slice(content string, startPos, endPos int) bool {
	isB64 := func(c byte) bool {
		return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '+' || c == '/' || c == '_' || c == '-'
	}
	if startPos > 0 && isB64(content[startPos-1]) {
		// v3.1: sebelumnya karakter b64 TUNGGAL di kiri sudah cukup untuk
		// membuang match → token di dalam URL path (…/v1/ghp_xxx) hilang total.
		// Sekarang hanya dianggap potongan blob bila run b64 di kiri panjang.
		left := 0
		for i := startPos - 1; i >= 0 && left < 32; i-- {
			if isB64(content[i]) || content[i] == '=' {
				left++
				continue
			}
			break
		}
		if left >= 20 {
			return true
		}
	}
	if endPos < len(content) {
		if c := content[endPos]; isB64(c) || c == '=' {
			// BUGFIX audit-2026-11b: dulu menghitung karakter b64 di jendela 128
			// char secara TIDAK kontigu, sehingga token yang diikuti `/path");
			// hook="https://…` (teks biasa) dianggap potongan blob dan dibuang.
			// Yang menandai blob adalah RUN kontigu yang panjang.
			n := 0
			for i := endPos; i < len(content) && n < 64; i++ {
				if !isB64(content[i]) && content[i] != '=' {
					break
				}
				n++
			}
			if n >= 64 {
				return true
			}
		}
	}
	return false
}

// ─── Guard tambahan per-pola (audit 2026-11) ──────────────────────────────────

// reIPv6Line mendeteksi baris berisi alamat IPv6 (≥4 kolom) — baris seperti
// `fe80:0000:...:0001` di /etc/hosts sebelumnya dilaporkan sebagai entri .pgpass.
var reIPv6Line = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){4,}[0-9a-f]{0,4}\b`)

// credPlaceholderWords: nilai password di URI contoh/dokumentasi.
var credPlaceholderWords = map[string]bool{
	"password": true, "passwd": true, "pass": true, "pwd": true,
	"secret": true, "changeme": true, "user": true, "username": true,
	"root": true, "admin": true, "test": true, "example": true,
	"xxx": true, "xxxx": true, "your_password": true, "yourpassword": true,
	"password123": true, "secret123": true, "123456": true, "123456789": true,
	"qwerty": true, "mypassword": true, "password1": true,
}

// credPlaceholder melaporkan apakah password di dalam URI hanya placeholder
// (`postgres://user:password@localhost/db` → bukan temuan).
func credPlaceholder(match string) bool {
	i := strings.Index(match, "://")
	if i < 0 {
		return false
	}
	rest := match[i+3:]
	at := strings.IndexByte(rest, '@')
	if at <= 0 {
		return false
	}
	ui := rest[:at]
	if strings.Contains(ui, "${") || strings.Contains(ui, "{{") ||
		strings.Contains(ui, "%s") || strings.Contains(ui, "<your") {
		return true
	}
	colon := strings.IndexByte(ui, ':')
	if colon < 0 {
		return false
	}
	pw := strings.ToLower(strings.TrimSpace(ui[colon+1:]))
	if credPlaceholderWords[pw] {
		return true
	}
	return strings.HasPrefix(pw, "your_") || strings.HasPrefix(pw, "your-")
}

// dropFinding menampung guard per-pola tambahan (audit 2026-11). Dipakai di jalur
// serial maupun paralel agar perilakunya identik.
func dropFinding(p *Pattern, match, lineText string) bool {
	if p.Name == "PostgreSQL .pgpass entry" && reIPv6Line.MatchString(lineText) {
		return true
	}
	if (strings.Contains(p.Name, "URI") || strings.Contains(p.Name, "URL")) && credPlaceholder(match) {
		return true
	}
	return false
}

// humanCredPatterns marks pattern names that need extra anti-FP checks.
var humanCredPatterns = map[string]bool{
	"HTML comment credentials (user:pass)":               true,
	"JS/line comment credentials (user:pass)":            true,
	"Block comment credentials (user:pass)":              true,
	"Freeform credentials near keyword (user:pass)":      true,
	"Password assignment (quoted or bare)":               true,
	"Password assignment bare (env/config)":              true,
	"Username + Password pair assignment":                true,
	"Hardcoded password input value":                     true,
	"Hardcoded password input value (value before type)": true,
	"Generic Secret / Password in code":                  true,
	"Password assignment (pass/pwd)":                     true,
}

// uiNoiseWords: values that look like secrets but are HTML/JS/UI/CSS noise.
var uiNoiseWords = map[string]bool{
	"required": true, "true": true, "false": true, "null": true, "undefined": true,
	"password": true, "passwd": true, "username": true, "user": true, "login": true,
	"email": true, "text": true, "submit": true, "button": true, "hidden": true,
	"checkbox": true, "radio": true, "number": true, "search": true, "tel": true,
	"url": true, "file": true, "image": true, "reset": true, "range": true,
	"type": true, "name": true, "value": true, "placeholder": true, "autocomplete": true,
	"current-password": true, "new-password": true, "one-time-code": true,
	"password123": true, "secret123": true, "changeme": true, "example": true,
	"string": true, "object": true, "function": true, "return": true, "const": true,
	"let": true, "var": true, "this": true, "self": true, "none": true, "empty": true,
	"default": true, "optional": true, "disabled": true, "enabled": true, "readonly": true,
	"http": true, "https": true, "www": true, "html": true, "head": true, "body": true,
	"void": true, "fill": true, "stroke": true, "width": true, "height": true,
	"color": true, "class": true, "classname": true, "style": true, "props": true,
	"state": true, "children": true, "component": true, "export": true,
	"import": true, "from": true, "async": true, "await": true, "promise": true,
	"error": true, "success": true, "loading": true, "pending": true, "data": true,
	"item": true, "index": true, "length": true, "array": true,
	"boolean": true, "symbol": true, "bigint": true,
	"left": true, "right": true, "top": true, "bottom": true, "center": true,
	"start": true, "end": true, "middle": true, "auto": true, "inherit": true,
	"initial": true, "unset": true, "solid": true, "dashed": true, "dotted": true,
	"absolute": true, "relative": true, "fixed": true, "sticky": true, "static": true,
	"block": true, "inline": true, "flex": true, "grid": true,
	"row": true, "column": true, "wrap": true, "nowrap": true,
	"pointer": true, "cursor": true, "hover": true, "focus": true, "active": true,
	"visible": true, "collapse": true, "scroll": true,
	"px": true, "em": true, "rem": true, "vh": true, "vw": true,
	"src": true, "href": true, "alt": true, "title": true, "role": true,
	"key": true, "ref": true, "id": true, "target": true, "rel": true,
	"method": true, "action": true, "enctype": true, "novalidate": true,
	"selected": true, "checked": true, "multiple": true, "pattern": true,
	"min": true, "max": true, "step": true, "rows": true, "cols": true,
	"transport": true, "template": true, "variant": true, "status": true,
	"timezone": true, "locale": true, "theme": true, "mode": true, "view": true,
	"roomjid": true, "room": true, "jid": true, "peer": true, "socket": true,
	"strokewidth": true, "background": true, "border": true, "margin": true,
	"padding": true, "display": true, "position": true, "opacity": true,
	"transform": true, "transition": true, "animation": true, "filter": true,
	"overflow": true, "zindex": true, "z-index": true, "fontsize": true,
	"fontweight": true, "lineheight": true, "textalign": true,
	"onclick": true, "onchange": true, "onsubmit": true, "onload": true,
	"errorcode": true,
}

// jsPropNoise: common minified / CSS / framework names used as fake "user" side
var jsPropNoise = map[string]bool{
	"src": true, "href": true, "type": true, "name": true, "value": true, "id": true,
	"key": true, "ref": true, "to": true, "from": true, "as": true, "of": true,
	"status": true, "state": true, "props": true, "style": true, "class": true,
	"classname": true, "children": true, "variant": true, "template": true,
	"transport": true, "timezone": true, "strokewidth": true, "errorcode": true,
	"background-color": true, "background": true, "border-color": true,
	"color": true, "fill": true, "stroke": true, "width": true, "height": true,
	"margin": true, "padding": true, "display": true, "position": true,
	"opacity": true, "cursor": true, "overflow": true, "z-index": true,
	"font-size": true, "font-weight": true, "line-height": true, "text-align": true,
	"error": true, "code": true, "message": true, "data": true, "method": true,
	"action": true, "target": true, "content": true, "title": true, "label": true,
	"sheet": true, "headers": true, "body": true, "query": true, "params": true,
	"config": true, "options": true, "context": true, "result": true, "response": true,
	"request": true, "callback": true, "handler": true, "event": true, "element": true,
	"index": true, "length": true, "count": true, "total": true, "size": true,
	"model": true, "view": true, "module": true, "exports": true, "require": true,
	"function": true, "return": true, "const": true, "async": true, "await": true,
	"selected": true, "active": true, "disabled": true, "visible": true,
	"success": true, "pending": true, "loading": true, "empty": true, "ready": true,
	"string": true, "number": true, "boolean": true, "object": true, "array": true,
	"promise": true, "path": true, "host": true, "port": true, "url": true,
	"window": true, "document": true, "console": true, "default": true,
	"roomjid": true, "room": true, "jid": true, "peer": true, "socket": true,
	"selectedsections": true, "onselectedsectionschange": true, "triggerloader": true,
}

// normalizeCredValue strips trailing punctuation often glued by bare assignments.
func normalizeCredValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = s[1 : len(s)-1]
		}
	}
	for {
		if s == "" {
			break
		}
		last := s[len(s)-1]
		if last == ';' || last == ',' || last == '.' || last == ')' || last == ']' || last == '}' || last == ':' {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	return strings.TrimSpace(s)
}

func splitUserPass(s string) (user, pass string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i >= len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// looksLikeMinifiedJS: long dense line typical of webpack/min bundles.
func looksLikeMinifiedJS(line string) bool {
	if len(line) < 200 {
		return false
	}
	// density of JS punctuation
	n := 0
	for _, r := range line {
		switch r {
		case '{', '}', '(', ')', ';', ',', '=', ':':
			n++
		}
	}
	return n > 30 && (n*100)/len(line) > 8
}

// looksLikeSecretValue: password side should not be plain JS identifier / CSS.
func looksLikeSecretValue(pass string) bool {
	if len(pass) < 6 {
		return false
	}
	pl := strings.ToLower(pass)
	if uiNoiseWords[pl] || jsPropNoise[pl] {
		return false
	}
	// reject JS member chains / calls
	if strings.Contains(pass, "this.") || strings.Contains(pass, "function") ||
		strings.ContainsAny(pass, "(){}[]<>") || strings.Contains(pass, "=>") {
		return false
	}
	// CSS color
	if strings.HasPrefix(pass, "#") {
		return false
	}
	// pure single-case short identifier without digit/special → likely JS prop value
	hasDigit := false
	hasSpecial := false
	hasUpper := false
	hasLower := false
	for _, r := range pass {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r == '_' || r == '-' || r == '.' || r == '+' || r == '/' || r == '=' ||
			r == '!' || r == '@' || r == '#' || r == '$' || r == '%' || r == '^' ||
			r == '&' || r == '*':
			hasSpecial = true
		}
	}
	// Accept if: has digit, OR special, OR mixed case (HiddenInPlainSight), OR long enough
	if hasDigit || hasSpecial {
		return true
	}
	if hasUpper && hasLower && len(pass) >= 8 {
		return true // CamelCase secrets like HiddenInPlainSight
	}
	// all-lower or all-upper without digit/special — weak, reject unless long random-looking
	if len(pass) >= 16 {
		return true
	}
	return false
}

// isHumanCredFP returns true if a human-cred match should be discarded.
func isHumanCredFP(patternName, match, lineText string) bool {
	m := normalizeCredValue(strings.TrimSpace(match))
	ml := strings.ToLower(m)
	ll := strings.ToLower(lineText)

	if m == "" || uiNoiseWords[ml] {
		return true
	}
	// never keep JS/CSS plumbing
	if strings.Contains(m, "this.") || strings.ContainsAny(m, "(){}[]") ||
		strings.Contains(m, "=>") || strings.Contains(m, "function") {
		return true
	}

	// Minified bundles: human leftover creds almost never live on 10KB one-liners
	// without being real comments — still allow HTML comments (multi-line safe).
	if looksLikeMinifiedJS(lineText) {
		switch patternName {
		case "JS/line comment credentials (user:pass)",
			"Block comment credentials (user:pass)",
			"Freeform credentials near keyword (user:pass)",
			"Password assignment (quoted or bare)",
			"Password assignment bare (env/config)",
			"Username + Password pair assignment":
			return true
		}
	}

	// user:pass family
	if strings.Contains(patternName, "user:pass") || strings.Count(m, ":") == 1 {
		user, pass, ok := splitUserPass(m)
		if ok {
			ul, pl := strings.ToLower(user), strings.ToLower(pass)
			if uiNoiseWords[ul] || uiNoiseWords[pl] || jsPropNoise[ul] || jsPropNoise[pl] {
				return true
			}
			// Bare pattern: require strong entropy (digit or @!#$%^&*), dot/_/- alone not enough
			// This kills JS prop chains like o.default.bool, selection:o.default.bool
			if patternName == "Bare high-entropy credentials (user:pass)" {
				hasDigit := false
				hasStrong := false
				for _, r := range pass {
					if r >= '0' && r <= '9' {
						hasDigit = true
					}
					if r == '@' || r == '!' || r == '#' || r == '$' || r == '%' || r == '^' || r == '&' || r == '*' {
						hasStrong = true
					}
				}
				if !hasDigit && !hasStrong {
					return true
				}
			}
			// scheme-like (including javascript: URIs and CSS !important)
			if strings.Contains(pl, "!important") {
				return true
			}
			if ul == "http" || ul == "https" || ul == "ftp" || ul == "mailto" || ul == "ws" || ul == "wss" || ul == "file" || ul == "javascript" {
				return true
			}
			// path / color
			if strings.HasPrefix(pass, "/") || strings.HasPrefix(pass, "#") || strings.HasPrefix(pl, "//") {
				return true
			}
			// single-letter / tiny minified values (src:i, type:n)
			if len(pass) <= 3 {
				return true
			}
			// pure numeric password
			allNum := true
			for _, r := range pass {
				if r < '0' || r > '9' {
					allNum = false
					break
				}
			}
			if allNum {
				return true
			}
			if !looksLikeSecretValue(pass) {
				return true
			}
			// camelCase JS prop as user (onSelectedSectionsChange, strokeWidth)
			if len(user) > 2 {
				hasLower, hasUpper := false, false
				for _, r := range user {
					if r >= 'a' && r <= 'z' {
						hasLower = true
					}
					if r >= 'A' && r <= 'Z' {
						hasUpper = true
					}
				}
				// camelCase user + short/simple pass → FP
				if hasLower && hasUpper && !looksLikeSecretValue(pass) {
					return true
				}
				// long camelCase identifier as username is almost never a login user
				if hasLower && hasUpper && len(user) > 12 {
					return true
				}
			}
		}
	}

	// Password assignment patterns
	if patternName == "Password assignment (quoted or bare)" ||
		patternName == "Password assignment bare (env/config)" ||
		patternName == "Generic Secret / Password in code" {
		if !looksLikeSecretValue(m) && !strings.ContainsAny(m, "0123456789!@#$%^&*") {
			// allow mixed-case long secrets without digit
			if !(len(m) >= 8 && hasMixedCase(m)) {
				return true
			}
		}
		if strings.HasPrefix(ml, "this.") || strings.Contains(ml, "function") {
			return true
		}
		// UI form lines
		if strings.Contains(ll, "type") && strings.Contains(ll, "password") &&
			!strings.Contains(ll, "value=") &&
			(strings.Contains(ll, "<input") || strings.Contains(ll, "<label") ||
				strings.Contains(ll, "placeholder") || strings.Contains(ll, "autocomplete")) {
			return true
		}
		if strings.Contains(ll, "[type") || strings.Contains(ll, "input[") {
			return true
		}
		uiLineMarkers := []string{
			"forgot password", "reset password", "change password", "enter your password",
			"confirm password", "password must", "password should", "password is required",
		}
		for _, mk := range uiLineMarkers {
			if strings.Contains(ll, mk) {
				return true
			}
		}
	}

	if strings.HasPrefix(patternName, "Hardcoded password input") {
		if uiNoiseWords[ml] || strings.HasPrefix(ml, "{{") || strings.HasPrefix(ml, "${") {
			return true
		}
		if !looksLikeSecretValue(m) && len(m) < 8 {
			return true
		}
	}

	if patternName == "Username + Password pair assignment" {
		if strings.Contains(ll, "<input") && !strings.Contains(ll, "value=") {
			return true
		}
	}

	return false
}

func hasMixedCase(s string) bool {
	var lower, upper bool
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			lower = true
		}
		if r >= 'A' && r <= 'Z' {
			upper = true
		}
	}
	return lower && upper
}

// placeholderWords: substring yang menandai nilai contoh/dokumentasi. Kata ≥5
// huruf hampir mustahil muncul kebetulan di token acak, jadi cukup substring.
var placeholderWords = []string{
	"your_", "yourkey", "yourapikey", "your-api", "example",
	"changeme", "replace", "xxxxxxxx", "aaaaaaaa", "11111111",
	"00000000", "test123", "password123", "secret123",
	"<api", "api_key>", "token>", "{api", "{key", "${",
	"xxxx", "yyyy", "zzzz", "undefined",
	"placeholder", "insert_", "insert-", "redacted", "dummy",
	"sample", "lorem", "qwerty", "abc123", "string", "fixme",
}

// placeholderShortWords: kata 4 huruf yang ±1/1000 token base62 acak
// memuatnya secara kebetulan (BUGFIX audit-2026-11b: dulu substring → key asli
// seperti `…xNuLl7…` dibuang). Kini hanya placeholder bila berdiri sebagai
// segmen: diapit non-alfanumerik / awal / akhir (`sk_live_none`, `TODO-key`).
var placeholderShortWords = []string{"none", "null", "todo", "asdf"}

func isAlnumByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func containsSegment(lower, w string) bool {
	for i := 0; ; {
		j := strings.Index(lower[i:], w)
		if j < 0 {
			return false
		}
		s, e := i+j, i+j+len(w)
		if (s == 0 || !isAlnumByte(lower[s-1])) && (e == len(lower) || !isAlnumByte(lower[e])) {
			return true
		}
		i = s + 1
	}
}

func isPlaceholder(s string) bool {
	lower := strings.ToLower(s)
	for _, p := range placeholderWords {
		if strings.Contains(lower, p) {
			return true
		}
	}
	for _, w := range placeholderShortWords {
		if containsSegment(lower, w) {
			return true
		}
	}
	// BUGFIX leaktest-2026-10: fragmen pendek xxx/yyy/zzz sbg substring membunuh
	// kunci ASLI yg kebetulan mengandungnya (mis. AKIA...ZZZZ...). Hanya anggap
	// placeholder bila fragmen MENDOMINASI nilai (sisa non-fragmen < 8 char).
	stripped := lower
	for _, p := range []string{"xxx", "yyy", "zzz"} {
		stripped = strings.ReplaceAll(stripped, p, "")
	}
	if stripped != lower && len(stripped) < 8 {
		return true
	}
	if len(s) > 4 {
		allSame := true
		for _, c := range s[1:] {
			if c != rune(s[0]) {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

type RateLimiter struct {
	ticker *time.Ticker
	ch     <-chan time.Time
}

func newRateLimiter(ratePerSec float64) *RateLimiter {
	if ratePerSec <= 0 {
		return nil
	}
	interval := time.Duration(float64(time.Second) / ratePerSec)
	t := time.NewTicker(interval)
	return &RateLimiter{ticker: t, ch: t.C}
}

func (rl *RateLimiter) Wait() {
	if rl == nil {
		return
	}
	<-rl.ch
}

func (rl *RateLimiter) Stop() {
	if rl != nil {
		rl.ticker.Stop()
	}
}

// ─── Worker Pool (mode URL/file) ───────────────────────────────────────────────

type Job struct {
	URL    string
	IsFile bool
}

func worker(id int, jobs <-chan Job, results chan<- Finding, cfg *Config, fsCache *FSCache, rl *RateLimiter, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		rl.Wait()
		// v3: --rate dan --delay tidak lagi digabung (double-limiting).
		// Jika rate global aktif, itu yang menegakkan throughput; --delay hanya
		// berlaku ketika rate limiter tidak dipakai.
		if cfg.DelayMs > 0 && rl == nil {
			time.Sleep(time.Duration(cfg.DelayMs) * time.Millisecond)
		}
		var content string
		var err error
		if job.IsFile {
			logVerbose(cfg, "[W%d] Reading file: %s", id, job.URL)
			content, err = readLocalFile(cfg, job.URL)
		} else {
			job.URL = withScheme(job.URL) // laporkan URL ternormalisasi
			logVerbose(cfg, "[W%d] Fetching: %s", id, job.URL)
			content, err = fetchURL(cfg, job.URL, fsCache)
		}
		if err != nil {
			logVerbose(cfg, "[W%d] Error on %s: %v", id, job.URL, err)
			continue
		}
		findings := scanContent(job.URL, content)
		for _, f := range findings {
			results <- f
		}
		if len(findings) > 0 {
			logVerbose(cfg, "[W%d] ✓ %s → %d finding(s)", id, job.URL, len(findings))
		}
		if !job.IsFile {
			crawlScripts(cfg, job.URL, content, rl, fsCache, results, id)
		}
	}
}

// ─── JS bundle follower (--js-crawl) ────────────────────────────────────────────
//
// Secret paling sering ada di bundle JS, bukan di HTML halaman. Tanpa langkah ini
// `-u https://app.tld` hanya memindai HTML dan melewatkan seluruh JS-nya.
// Dibatasi: same-host saja, satu level, maksimum N script (--js-crawl), dedupe global
// per URL, dan tetap melewati rate limiter.

var (
	reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+?src\s*=\s*["']([^"'>]+)["']`)
	seenScripts sync.Map // URL script yang sudah pernah di-scan
)

func looksLikeHTML(s string) bool {
	head := s
	if len(head) > 8192 {
		head = head[:8192]
	}
	l := strings.ToLower(head)
	return strings.Contains(l, "<script") || strings.Contains(l, "<!doctype") || strings.Contains(l, "<html")
}

func crawlScripts(cfg *Config, pageURL, content string, rl *RateLimiter, fsCache *FSCache, results chan<- Finding, id int) {
	if cfg.JSCrawl <= 0 || !looksLikeHTML(content) {
		return
	}
	base, err := url.Parse(withScheme(pageURL))
	if err != nil || base.Hostname() == "" {
		return
	}
	taken := 0
	for _, m := range reScriptSrc.FindAllStringSubmatch(content, -1) {
		if taken >= cfg.JSCrawl { // batas keras per halaman
			break
		}
		ref := strings.TrimSpace(m[1])
		if ref == "" || strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "javascript:") {
			continue
		}
		su, err := base.Parse(ref)
		if err != nil || su.Hostname() == "" {
			continue
		}
		if su.Hostname() != base.Hostname() { // jangan keluar host (scope)
			continue
		}
		su.Fragment = ""
		key := su.String()
		if _, dup := seenScripts.LoadOrStore(key, struct{}{}); dup {
			continue
		}
		taken++
		rl.Wait()
		if cfg.DelayMs > 0 && rl == nil {
			time.Sleep(time.Duration(cfg.DelayMs) * time.Millisecond)
		}
		body, err := fetchURL(cfg, key, fsCache)
		if err != nil {
			logVerbose(cfg, "[W%d] JS skip %s: %v", id, key, err)
			continue
		}
		if len(body) > int(cfg.MaxBodyBytes) {
			body = body[:cfg.MaxBodyBytes]
		}
		fs := scanContent(key, body)
		logVerbose(cfg, "[W%d] ✓ JS %s (%d bytes) → %d finding(s)", id, key, len(body), len(fs))
		for _, f := range fs {
			results <- f
		}
	}
}

// ─── httpx JSONL mode (v2, body-reuse) ─────────────────────────────────────────

type httpxRecord struct {
	URL         string          `json:"url"`
	StatusCode  int             `json:"status_code"`
	Body        string          `json:"body"`
	RawHeader   string          `json:"raw_header"`
	Header      json.RawMessage `json:"header"` // map ternormalisasi httpx (fallback bila raw_header kosong)
	ContentType string          `json:"content_type"`
}

type jsonJob struct{ url, body, header string }

// hostInScope: host == scope atau *.scope (case-insensitive, abaikan titik akhir,
// scope boleh ditulis sebagai URL).
func hostInScope(rawURL, scope string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	scope = strings.ToLower(strings.TrimSpace(scope))
	if strings.Contains(scope, "://") {
		if su, err := url.Parse(scope); err == nil {
			scope = su.Hostname()
		}
	}
	scope = strings.TrimSuffix(strings.TrimPrefix(scope, "*."), ".")
	if host == "" || scope == "" {
		return false
	}
	return host == scope || strings.HasSuffix(host, "."+scope)
}

// headerMapText meratakan field `header` httpx (map[string]string|[]string) menjadi
// teks "k: v" per baris. Dipakai hanya bila raw_header tidak ada.
func headerMapText(raw json.RawMessage) string {
	if len(raw) == 0 || raw[0] != '{' {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			b.WriteString(k + ": " + v + "\n")
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					b.WriteString(k + ": " + s + "\n")
				}
			}
		}
	}
	return b.String()
}

// binaryContentType: tipe konten yang tidak mungkin memuat secret tekstual.
func binaryContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" || strings.Contains(ct, "svg") {
		return false
	}
	for _, p := range []string{"image/", "font/", "audio/", "video/", "application/octet-stream",
		"application/zip", "application/gzip", "application/x-gzip", "application/pdf",
		"application/wasm", "application/x-font", "application/font", "application/vnd.ms-fontobject",
		"application/x-shockwave-flash", "application/x-7z", "application/x-rar", "application/x-tar"} {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

// looksBinary memeriksa 64 KB pertama: NUL byte, atau >10% rune tidak valid /
// U+FFFD (body biner yang dijadikan string oleh httpx) / kontrol. UTF-8 valid
// (CJK, emoji) dihitung sebagai teks — versi lama menghitung byte ≥0x80 sebagai
// non-printable sehingga halaman Jepang/Cina bisa dilewati sebagai "biner".
func looksBinary(s string) bool {
	n := len(s)
	if n > 64<<10 {
		n = 64 << 10
	}
	sample := s[:n]
	if strings.IndexByte(sample, 0) >= 0 {
		return true
	}
	bad, total := 0, 0
	for i := 0; i < len(sample); {
		r, size := utf8.DecodeRuneInString(sample[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			if n < len(s) && len(sample)-i < utf8.UTFMax {
				i = len(sample) // rune terpotong di batas sampel
				continue
			}
			bad++
		case r == utf8.RuneError:
			bad++ // U+FFFD literal
		case r < 32 && r != '\n' && r != '\r' && r != '\t' && r != '\f':
			bad++
		}
		total++
		i += size
	}
	return total > 0 && bad*10 > total
}

// forEachLine memanggil fn untuk setiap baris tak-kosong. Baris yang melebihi
// maxLine DILEWATI (dihitung) — pembacaan berlanjut ke baris berikutnya.
// BUGFIX audit-2026-11b: bufio.Scanner lama berhenti total pada ErrTooLong
// sehingga semua record setelah satu baris raksasa tidak pernah di-scan.
func forEachLine(r io.Reader, maxLine int, stop <-chan struct{}, fn func([]byte)) (skipped int, err error) {
	br := bufio.NewReaderSize(r, 1<<20)
	buf := make([]byte, 0, 1<<20)
	tooLong := false
	for {
		select {
		case <-stop:
			return skipped, nil
		default:
		}
		frag, e := br.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(frag) > maxLine {
				tooLong = true
				buf = buf[:0]
			} else {
				buf = append(buf, frag...)
			}
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if tooLong {
			skipped++
		} else if line := bytes.TrimSpace(buf); len(line) > 0 {
			fn(line)
		}
		if cap(buf) > 16<<20 {
			buf = make([]byte, 0, 1<<20) // lepas buffer baris raksasa
		} else {
			buf = buf[:0]
		}
		tooLong = false
		if e != nil {
			if e == io.EOF {
				return skipped, nil
			}
			return skipped, e
		}
	}
}

// scanRecord memindai body dan header secara terpisah (tanpa menyalin body
// 10 MB hanya untuk menempelkan header) lalu menggabung + dedupe.
func scanRecord(rawURL, body, header string) []Finding {
	out := scanContent(rawURL, body)
	if header != "" {
		out = append(out, scanContent(rawURL, header)...)
		out = dedupeOverlapping(out)
	}
	return out
}

// scanHTTPXJSON membaca JSONL httpx (-json -irr) dan men-scan body tanpa fetch.
// Streaming: hanya satu record yang di-decode oleh producer, worker menahan
// maksimal satu record masing-masing (channel tanpa buffer).
func scanHTTPXJSON(cfg *Config, outWriter io.Writer, js *jsonStream, stats *outputStats) error {
	f, err := os.Open(cfg.HTTPXJSON)
	if err != nil {
		return fmt.Errorf("opening httpx-json: %w", err)
	}
	defer f.Close()

	// Mode ini murni CPU-bound (tanpa jaringan): worker > jumlah CPU hanya
	// menambah memori (tiap worker memegang body s/d 10 MB + salinannya).
	workers := cfg.Threads
	if ncpu := runtime.GOMAXPROCS(0); workers > ncpu {
		logVerbose(cfg, "[httpx-json] -t %d dibatasi ke %d worker (CPU-bound)", workers, ncpu)
		workers = ncpu
	}

	jobs := make(chan jsonJob)
	results := make(chan Finding, 500)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				for _, fd := range scanRecord(j.url, j.body, j.header) {
					results <- fd
				}
			}
		}()
	}

	var done = make(chan struct{})
	go func() {
		defer close(done)
		for fd := range results {
			emit(cfg, fd, outWriter, js, stats)
		}
	}()

	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		if _, ok := <-sigCh; !ok {
			return
		}
		logWarn(cfg, "Interrupted — menyelesaikan record yang sedang diproses lalu flush (Ctrl-C lagi = paksa keluar)...")
		interrupted.Store(true)
		close(stop)
		if _, ok := <-sigCh; ok {
			os.Exit(130)
		}
	}()

	// Batas satu baris JSONL: body s/d MaxBodyBytes bisa membengkak ±6× saat
	// di-escape JSON (\u00XX), plus header/request.
	maxLine := int(8*cfg.MaxBodyBytes) + (4 << 20)
	if maxLine < 64<<20 {
		maxLine = 64 << 20
	}
	count, bad, binSkip := 0, 0, 0
	skipped, rerr := forEachLine(f, maxLine, stop, func(line []byte) {
		var rec httpxRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			bad++
			return
		}
		hdr := rec.RawHeader
		if hdr == "" {
			hdr = headerMapText(rec.Header)
		}
		if rec.URL == "" || (rec.Body == "" && hdr == "") {
			return
		}
		if cfg.Scope != "" && !hostInScope(rec.URL, cfg.Scope) {
			return
		}
		body := rec.Body
		if binaryContentType(rec.ContentType) || (body != "" && looksBinary(body)) {
			binSkip++
			body = "" // header tetap di-scan
			if hdr == "" {
				return
			}
		}
		if int64(len(body)) > cfg.MaxBodyBytes {
			// salin potongan supaya string hasil decode (bisa puluhan MB) bisa
			// segera di-GC, bukan tertahan selama worker memindai 10 MB pertama.
			body = strings.Clone(body[:cfg.MaxBodyBytes])
		}
		count++
		select {
		case jobs <- jsonJob{rec.URL, body, hdr}:
		case <-stop:
		}
	})
	close(jobs)
	wg.Wait()
	close(results)
	<-done
	logInfo(cfg, "httpx-json: %d record discan (in-scope), %d body biner dilewati", count, binSkip)
	if bad > 0 {
		logWarn(cfg, "httpx-json: %d baris bukan JSON valid dilewati", bad)
	}
	if skipped > 0 {
		logWarn(cfg, "httpx-json: %d baris > %d MB dilewati (pembacaan tetap berlanjut)", skipped, maxLine>>20)
	}
	if rerr != nil {
		return fmt.Errorf("reading httpx-json: %w", rerr)
	}
	return nil
}

// ─── Output ───────────────────────────────────────────────────────────────────

var mu sync.Mutex

func colorSeverity(cfg *Config, sev string) string {
	if cfg.NoColor {
		return "[" + sev + "]"
	}
	switch sev {
	case SevCritical:
		return colorRed + colorBold + "[CRITICAL]" + colorReset
	case SevHigh:
		return colorMagenta + colorBold + "[HIGH]" + colorReset
	case SevMedium:
		return colorYellow + "[MEDIUM]" + colorReset
	case SevLow:
		return colorBlue + "[LOW]" + colorReset
	case SevInfo:
		return colorDim + "[INFO]" + colorReset
	default:
		return "[" + sev + "]"
	}
}

// oneLine meng-escape karakter yang akan memecah format satu-baris
// `[SEV] Nama | nilai | url` (mis. private key PEM berisi newline).
var oneLine = strings.NewReplacer("\r", `\r`, "\n", `\n`, "\t", `\t`)

func printFinding(cfg *Config, f Finding, w io.Writer) error {
	line := fmt.Sprintf("%s %s | %s | %s\n",
		colorSeverity(cfg, f.Severity),
		colorize(cfg, colorCyan, oneLine.Replace(f.Pattern)),
		colorize(cfg, colorGreen, oneLine.Replace(truncate(f.Match, 120))),
		colorize(cfg, colorDim, oneLine.Replace(f.URL)),
	)
	_, err := io.WriteString(w, line)
	return err
}

func colorize(cfg *Config, color, s string) string {
	if cfg.NoColor {
		return s
	}
	return color + s + colorReset
}

// ─── Output streaming v3 ─────────────────────────────────────────────────────
//
// --json: finding ditulis SATU PER SATU ke outWriter (live, hemat RAM untuk
// volume besar) dalam bentuk array JSON compact `[...]`, bukan menumpuk semua
// temuan lalu marshal di akhir. Text mode tidak berubah.

type jsonStream struct {
	mu     sync.Mutex
	w      io.Writer
	opened bool
	wrote  bool
	closed bool
}

func (js *jsonStream) emit(fd Finding) {
	b, err := json.Marshal(fd)
	if err != nil {
		return
	}
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.closed {
		return
	}
	if !js.opened {
		fmt.Fprint(js.w, "[")
		js.opened = true
	} else if js.wrote {
		fmt.Fprint(js.w, ",")
	}
	js.wrote = true
	if _, err := js.w.Write(b); err != nil {
		noteWriteErr(err)
	}
}

func (js *jsonStream) end() {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.closed {
		return
	}
	var err error
	if !js.opened {
		_, err = fmt.Fprint(js.w, "[]\n")
	} else {
		_, err = fmt.Fprint(js.w, "]\n")
	}
	if err != nil {
		noteWriteErr(err)
	}
	js.closed = true
}

// ─── Status global (exit code) ──────────────────────────────────────────────
//
// Exit code: 0 = selesai normal; 1 = error fatal (argumen, input tak terbaca,
// GAGAL MENULIS output); 2 = ada temuan dan --fail-on-findings; 130 = dihentikan
// Ctrl-C (hasil yang sudah ada tetap di-flush).
var (
	writeErrMu  sync.Mutex
	writeErrV   error // error pertama saat menulis output
	interrupted atomic.Bool
)

func noteWriteErr(err error) {
	writeErrMu.Lock()
	defer writeErrMu.Unlock()
	if writeErrV == nil {
		writeErrV = err
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
	}
}

func firstWriteErr() error {
	writeErrMu.Lock()
	defer writeErrMu.Unlock()
	return writeErrV
}

// findingDedup membuang baris output yang identik (url+pola+nilai) — mis. URL
// yang muncul dua kali di JSONL httpx (re-probe/redirect) atau -l dengan
// variasi skema. Hanya hash 64-bit yang disimpan (hemat RAM).
type findingDedup struct {
	mu   sync.Mutex
	seen map[uint64]struct{}
}

func (d *findingDedup) first(f Finding) bool {
	h := fnv.New64a()
	h.Write([]byte(f.URL))
	h.Write([]byte{0})
	h.Write([]byte(f.Pattern))
	h.Write([]byte{0})
	h.Write([]byte(f.Match))
	k := h.Sum64()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = make(map[uint64]struct{}, 1024)
	}
	if _, dup := d.seen[k]; dup {
		return false
	}
	d.seen[k] = struct{}{}
	return true
}

var emitDedup findingDedup

// outputStats menggantikan akumulasi []Finding untuk ringkasan, sehingga RAM
// tidak membesar seiring jumlah temuan.
type outputStats struct {
	mu    sync.Mutex
	count map[string]int
}

func newOutputStats() *outputStats {
	return &outputStats{count: make(map[string]int)}
}

func (s *outputStats) Add(sev string) {
	s.mu.Lock()
	s.count[sev]++
	s.mu.Unlock()
}

func (s *outputStats) Total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.count {
		n += c
	}
	return n
}

func (s *outputStats) BySeverity(sev string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count[sev]
}

// emit menulis satu finding: JSON streaming bila --json, otherwise teks warna.
func emit(cfg *Config, fd Finding, outWriter io.Writer, js *jsonStream, stats *outputStats) {
	if !severityAtLeast(cfg.MinSeverity, fd.Severity) {
		return
	}
	if !emitDedup.first(fd) {
		return
	}
	if cfg.OutputJSON && js != nil {
		capped := fd
		if len(capped.Match) > 4096 && len([]rune(capped.Match)) > 4096 {
			capped.Match = truncate(capped.Match, 4096)
		}
		js.emit(capped)
	} else {
		mu.Lock()
		err := printFinding(cfg, fd, outWriter)
		mu.Unlock()
		if err != nil {
			noteWriteErr(err)
		}
	}
	if stats != nil {
		stats.Add(fd.Severity)
	}
}

func logVerbose(cfg *Config, format string, args ...any) {
	if cfg.Verbose {
		mu.Lock()
		fmt.Fprint(os.Stderr, colorize(cfg, colorDim, fmt.Sprintf(format, args...))+"\n")
		mu.Unlock()
	}
}

func logInfo(cfg *Config, format string, args ...any) {
	if !cfg.Silent {
		mu.Lock()
		fmt.Fprint(os.Stderr, colorize(cfg, colorCyan, "[*]")+" "+fmt.Sprintf(format, args...)+"\n")
		mu.Unlock()
	}
}

func logWarn(cfg *Config, format string, args ...any) {
	if !cfg.Silent {
		mu.Lock()
		fmt.Fprint(os.Stderr, colorize(cfg, colorYellow, "[!]")+" "+fmt.Sprintf(format, args...)+"\n")
		mu.Unlock()
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

func extractDomain(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func loadURLsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; !ok {
			seen[line] = struct{}{}
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}

func readLocalFile(cfg *Config, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	limited := io.LimitReader(f, cfg.MaxBodyBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	// v3: cek NUL byte di SELURUH buffer (bukan hanya 8KB pertama) sehingga
	// file binary besar (PNG/JPEG/zip) tetap terdeteksi & dilewati.
	if bytes.IndexByte(data, 0) != -1 {
		return "", fmt.Errorf("skipped (binary file)")
	}
	return string(data), nil
}

func parseExts(spec string) []string {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	var out []string
	for _, e := range strings.Split(spec, ",") {
		e = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(e), "."))
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

func extAllowed(path string, exts []string) bool {
	if len(exts) == 0 {
		return true
	}
	lp := strings.ToLower(path)
	for _, e := range exts {
		if strings.HasSuffix(lp, "."+e) {
			return true
		}
	}
	return false
}

func collectDir(cfg *Config, dir string, exts []string) ([]string, error) {
	var out []string
	skipDirs := map[string]struct{}{".git": {}, ".svn": {}, ".hg": {}}
	err := filepath.Walk(dir, func(pth string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if _, bad := skipDirs[info.Name()]; bad {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > cfg.MaxBodyBytes {
			logVerbose(cfg, "[!] skip %s (> max-size)", pth)
			return nil
		}
		if extAllowed(pth, exts) {
			out = append(out, pth)
		}
		return nil
	})
	return out, err
}

func checkFlareSolverr(baseURL string) bool {
	candidates := []string{baseURL}
	if trimmed := strings.TrimSuffix(baseURL, "/v1"); trimmed != baseURL {
		candidates = append(candidates, trimmed+"/")
	}
	for _, u := range candidates {
		resp, err := httpClient.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(body), "FlareSolverr") {
			return true
		}
	}
	return false
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	var (
		flagURL         = flag.String("u", "", "Single URL to scan")
		flagURLLong     = flag.String("url", "", "Single URL to scan (alias for -u)")
		flagList        = flag.String("l", "", "File containing list of URLs (one per line)")
		flagListLong    = flag.String("list", "", "File containing list of URLs (alias for -l)")
		flagThreads     = flag.Int("t", 5, "Number of concurrent workers")
		flagThreadsLong = flag.Int("threads", 5, "Number of concurrent workers (alias for -t)")
		flagDelay       = flag.Int("d", 0, "Delay between requests per worker in milliseconds")
		flagDelayLong   = flag.Int("delay", 0, "Delay between requests per worker in ms (alias for -d)")
		flagRate        = flag.Float64("rate", 0, "Global max requests per second (0 = unlimited)")
		flagUA          = flag.String("ua", defaultUA, "Custom User-Agent string (ignored with -flaresolverr)")
		flagFS          = flag.String("flaresolverr", "", "FlareSolverr base URL (e.g. http://localhost:8191)")
		flagFSShort     = flag.String("f", "", "FlareSolverr base URL, short alias for -flaresolverr")
		flagOutput      = flag.String("o", "", "Write findings to this file")
		flagOutputLong  = flag.String("output", "", "Write findings to this file (alias for -o)")
		flagJSON        = flag.Bool("json", false, "Output findings in JSON format")
		flagTimeout     = flag.Int("timeout", 30, "HTTP request timeout in seconds")
		flagSilent      = flag.Bool("s", false, "Silent mode: suppress all output except findings")
		flagSilentLong  = flag.Bool("silent", false, "Silent mode (alias for -s)")
		flagVerbose     = flag.Bool("v", false, "Verbose mode: show errors and progress")
		flagVerboseLong = flag.Bool("verbose", false, "Verbose mode (alias for -v)")
		flagNoColor     = flag.Bool("no-color", false, "Disable colored output")
		flagMaxSize     = flag.Int("max-size", 10, "Max response body size to scan (MB)")
		flagVersion     = flag.Bool("version", false, "Print version and exit")
		flagFile        = flag.String("file", "", "Single local file to scan")
		flagFileShort   = flag.String("F", "", "Single local file to scan (alias for -file)")
		flagFileList    = flag.String("fl", "", "File containing a list of local file paths (one per line)")
		flagDir         = flag.String("dir", "", "Directory to scan recursively")
		flagDirShort    = flag.String("D", "", "Directory to scan recursively (alias for -dir)")
		flagExt         = flag.String("ext", "", "Restrict -dir/-fl to these extensions (comma-separated)")
		flagHTTPXJSON   = flag.String("httpx-json", "", "Scan bodies from httpx -json -irr JSONL (body-reuse, no re-fetch)")
		flagScope       = flag.String("scope", "", "With --httpx-json: only scan records whose host == domain or *.domain")
		flagNoPublic    = flag.Bool("no-public", false, "Skip public-by-design keys (RUM/publishable/site/storefront/algolia-search)")
		flagMinSev      = flag.String("min-severity", "", "Only emit findings at or above this level: critical|high|medium|low|info")
		flagFailOn      = flag.Bool("fail-on-findings", false, "Exit with code 2 when at least one finding is emitted (CI/pipeline)")
		flagInsecure    = flag.Bool("k", false, "Skip TLS certificate verification (target dengan sertifikat rusak)")
		flagInsecureL   = flag.Bool("insecure", false, "Skip TLS certificate verification (alias for -k)")
		flagProxy       = flag.String("proxy", "", "Explicit proxy URL (default: HTTP(S)_PROXY env)")
		flagNoDecode    = flag.Bool("no-decode", false, "Disable obfuscated-layer decode pass (faster, fewer findings)")
		flagNoWindow    = flag.Bool("no-window", false, "Run each gated regex over the whole body instead of literal windows (slower; debugging)")
		flagJSCrawl     = flag.Int("js-crawl", 0, "On HTML targets, also fetch and scan up to N same-host <script src> files (0=off)")
	)
	var headers multiFlag
	var cookies multiFlag
	flag.Var(&headers, "H", "Custom request header (repeatable)")
	flag.Var(&headers, "header", "Custom request header, alias for -H")
	flag.Var(&cookies, "cookie", "Cookie 'name=value' to send with every request (repeatable)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\nUsage: secrethunter2 [options] -u <url> | -l <file> | --httpx-json <file>\n", fmt.Sprintf(banner, version))
		flag.PrintDefaults()
	}

	flag.Parse()
	noPublicGlobal = *flagNoPublic
	noDecodeGlobal = *flagNoDecode
	noWindowGlobal = *flagNoWindow

	if *flagVersion {
		fmt.Printf("secrethunter2 v%s\n", version)
		os.Exit(0)
	}

	minSev := strings.ToUpper(strings.TrimSpace(*flagMinSev))
	if minSev != "" {
		if _, ok := sevRank[minSev]; !ok {
			fmt.Fprintf(os.Stderr, "Error: invalid --min-severity %q (use critical|high|medium|low|info)\n", *flagMinSev)
			os.Exit(1)
		}
	}

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	// Conflicting short/long aliases set with different values: warn, short wins.
	// (Long-only use already works via first()/setFlags branches below.)
	checkAlias := func(short, long, vs, vl string) {
		if setFlags[short] && setFlags[long] && vs != vl {
			fmt.Fprintf(os.Stderr, "%s[!] both -%s and --%s set with different values; using -%s=%q%s\n",
				colorYellow, short, long, short, vs, colorReset)
		}
	}
	threads := *flagThreads
	if setFlags["threads"] && !setFlags["t"] {
		threads = *flagThreadsLong
	}
	delayMs := *flagDelay
	if setFlags["delay"] && !setFlags["d"] {
		delayMs = *flagDelayLong
	}
	checkAlias("u", "url", *flagURL, *flagURLLong)
	checkAlias("l", "list", *flagList, *flagListLong)
	checkAlias("t", "threads", fmt.Sprint(*flagThreads), fmt.Sprint(*flagThreadsLong))
	checkAlias("d", "delay", fmt.Sprint(*flagDelay), fmt.Sprint(*flagDelayLong))
	checkAlias("s", "silent", fmt.Sprint(*flagSilent), fmt.Sprint(*flagSilentLong))
	checkAlias("v", "verbose", fmt.Sprint(*flagVerbose), fmt.Sprint(*flagVerboseLong))
	checkAlias("o", "output", *flagOutput, *flagOutputLong)
	checkAlias("F", "file", *flagFileShort, *flagFile)
	checkAlias("D", "dir", *flagDirShort, *flagDir)
	if threads < 1 {
		threads = 1
	}

	cfg := &Config{
		Threads:        threads,
		DelayMs:        delayMs,
		RatePerSec:     *flagRate,
		UserAgent:      *flagUA,
		OutputJSON:     *flagJSON,
		Timeout:        *flagTimeout,
		Silent:         *flagSilent || *flagSilentLong,
		Verbose:        *flagVerbose || *flagVerboseLong,
		NoColor:        *flagNoColor,
		MaxBodyBytes:   int64(max(*flagMaxSize, 1)) * 1024 * 1024,
		ExtraHeaders:   []string(headers),
		HTTPXJSON:      *flagHTTPXJSON,
		Scope:          *flagScope,
		MinSeverity:    minSev,
		FailOnFindings: *flagFailOn,
		Insecure:       *flagInsecure || *flagInsecureL,
		ProxyURL:       *flagProxy,
		Cookies:        []string(cookies),
		NoDecode:       *flagNoDecode,
		JSCrawl:        *flagJSCrawl,
	}
	if cfg.Insecure {
		logWarn(cfg, "TLS verification disabled (-k) — jangan pakai saat mengirim kredensial")
	}
	cfg.OutputFile = first(*flagOutput, *flagOutputLong)
	fsURL := first(*flagFS, *flagFSShort)
	if fsURL != "" {
		cfg.FlareSolvrURL = strings.TrimRight(fsURL, "/")
	}

	// Shared HTTP client (keep-alive)
	httpClient = buildClient(cfg)
	// FlareSolverr butuh timeout > maxTimeout request FS (60s).
	fsTimeout := cfg.Timeout
	if fsTimeout < 75 {
		fsTimeout = 75
	}
	fsClient = buildClient(cfg)
	fsClient.Timeout = time.Duration(fsTimeout) * time.Second

	// ── Output writer ──
	// v3.1: file ditulis 0600 (berisi secret!) dan TANPA escape ANSI, sedangkan
	// stdout tetap berwarna. Sebelumnya file hasil -o penuh kode warna.
	var outWriter io.Writer = os.Stdout
	var outF *os.File
	if cfg.OutputFile != "" {
		var err error
		outF, err = os.OpenFile(cfg.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outF.Close()
		// file = keluaran utama (error-nya dilaporkan → exit 1); stdout hanya
		// salinan, sehingga stdout yang rusak tidak menghentikan penulisan file
		// (io.MultiWriter berhenti pada writer pertama yang gagal).
		outWriter = teeOut{primary: ansiStripper{w: outF}, secondary: os.Stdout}
	}

	// ── Banner ──
	if !cfg.Silent {
		if cfg.NoColor {
			fmt.Printf(banner, version)
		} else {
			fmt.Printf(colorCyan+colorBold+banner+colorReset, version)
		}
		logInfo(cfg, "Workers       : %d", cfg.Threads)
		logInfo(cfg, "Patterns      : %d", len(patterns))
	}

	var js *jsonStream
	if cfg.OutputJSON {
		js = &jsonStream{w: outWriter}
	}
	stats := newOutputStats()

	// ── MODE 1: httpx-json (body-reuse) ──
	if cfg.HTTPXJSON != "" {
		logInfo(cfg, "Mode          : httpx-json body-reuse (%s)", cfg.HTTPXJSON)
		if cfg.Scope != "" {
			logInfo(cfg, "Scope         : %s", cfg.Scope)
		}
		if err := scanHTTPXJSON(cfg, outWriter, js, stats); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if cfg.OutputJSON && js != nil {
				js.end()
			}
			os.Exit(1)
		}
	} else {
		// ── MODE 2: fetch/local (perilaku v1) ──
		singleURL := first(*flagURL, *flagURLLong)
		listFile := first(*flagList, *flagListLong)
		singleFile := first(*flagFile, *flagFileShort)
		dirPath := first(*flagDir, *flagDirShort)
		fileListPath := *flagFileList
		exts := parseExts(*flagExt)

		if singleURL == "" && listFile == "" && singleFile == "" && dirPath == "" &&
			fileListPath == "" && flag.NArg() > 0 {
			arg := flag.Arg(0)
			if fi, err := os.Stat(arg); err == nil {
				if fi.IsDir() {
					dirPath = arg
				} else {
					singleFile = arg
				}
			} else {
				singleURL = arg
			}
		}

		if singleURL == "" && listFile == "" && singleFile == "" && dirPath == "" && fileListPath == "" {
			fmt.Fprintln(os.Stderr, "Error: provide a target — -u, -l, -file, -fl, -dir, or --httpx-json")
			flag.Usage()
			os.Exit(1)
		}

		if singleURL != "" {
			cfg.URLs = append(cfg.URLs, singleURL)
		}
		if listFile != "" {
			urls, err := loadURLsFromFile(listFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading URL list file: %v\n", err)
				os.Exit(1)
			}
			cfg.URLs = append(cfg.URLs, urls...)
		}
		if singleFile != "" {
			cfg.Files = append(cfg.Files, singleFile)
		}
		if fileListPath != "" {
			files, err := loadURLsFromFile(fileListPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading file list: %v\n", err)
				os.Exit(1)
			}
			cfg.Files = append(cfg.Files, files...)
		}
		if dirPath != "" {
			files, err := collectDir(cfg, dirPath, exts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning directory: %v\n", err)
				os.Exit(1)
			}
			cfg.Files = append(cfg.Files, files...)
		}
		if len(cfg.URLs) == 0 && len(cfg.Files) == 0 {
			fmt.Fprintln(os.Stderr, "Error: no targets to scan")
			os.Exit(1)
		}

		// v3.1: --scope sebelumnya hanya berlaku untuk --httpx-json dan diabaikan
		// diam-diam di mode -l/-u. Sekarang URL di luar scope difilter (dan jumlahnya
		// dilaporkan) supaya tidak ada target nyasar yang dipindai.
		if cfg.Scope != "" && len(cfg.URLs) > 0 {
			before := len(cfg.URLs)
			kept := cfg.URLs[:0]
			for _, u := range cfg.URLs {
				if hostInScope(withScheme(u), cfg.Scope) {
					kept = append(kept, u)
				}
			}
			cfg.URLs = kept
			logInfo(cfg, "Scope         : %s (%d/%d URL in scope)", cfg.Scope, len(cfg.URLs), before)
			if len(cfg.URLs) == 0 && len(cfg.Files) == 0 {
				fmt.Fprintln(os.Stderr, "Error: no targets left after --scope filter")
				os.Exit(1)
			}
		}

		// FlareSolverr
		var fsCache *FSCache
		if cfg.FlareSolvrURL != "" {
			logInfo(cfg, "FlareSolverr  : checking %s...", cfg.FlareSolvrURL)
			if checkFlareSolverr(cfg.FlareSolvrURL) {
				logInfo(cfg, "FlareSolverr  : ✓ active")
				fsCache = newFSCache()
			} else {
				logWarn(cfg, "FlareSolverr not reachable at %s — continuing without it", cfg.FlareSolvrURL)
			}
		}
		if fsCache != nil && len(cfg.URLs) > 0 {
			domains := uniqueDomains(cfg.URLs)
			logInfo(cfg, "Pre-resolving %d unique domain(s) via FlareSolverr...", len(domains))
			domCh := make(chan string, len(domains))
			for _, d := range domains {
				domCh <- d
			}
			close(domCh)
			maxFSWorkers := cfg.Threads
			if maxFSWorkers > 3 {
				maxFSWorkers = 3
			}
			var fsWG sync.WaitGroup
			for i := 0; i < maxFSWorkers; i++ {
				fsWG.Add(1)
				go func() {
					defer fsWG.Done()
					for domain := range domCh {
						fsCache.Resolve(cfg, domain)
					}
				}()
			}
			fsWG.Wait()
		}

		runFetchMode(cfg, fsCache, outWriter, js, stats)
	}

	// ── JSON output ──
	if cfg.OutputJSON && js != nil {
		js.end()
	}

	// ── Summary ──
	if !cfg.Silent {
		fmt.Fprintln(os.Stderr)
		logInfo(cfg, "Scan complete — %d finding(s)", stats.Total())
		for _, sev := range []string{SevCritical, SevHigh, SevMedium, SevLow, SevInfo} {
			if n := stats.BySeverity(sev); n > 0 {
				logInfo(cfg, "  %s: %d", colorSeverity(cfg, sev), n)
			}
		}
		if cfg.OutputFile != "" {
			logInfo(cfg, "Results saved : %s", cfg.OutputFile)
		}
	}
	// v3.1: exit code untuk integrasi pipeline (sebelumnya selalu 0).
	if outF != nil {
		if err := outF.Close(); err != nil {
			noteWriteErr(err)
		}
	}
	if firstWriteErr() != nil {
		os.Exit(1)
	}
	if interrupted.Load() {
		os.Exit(130)
	}
	if cfg.FailOnFindings && stats.Total() > 0 {
		os.Exit(2)
	}
}

// runFetchMode menjalankan worker pool mode URL/file (perilaku v1).
func runFetchMode(cfg *Config, fsCache *FSCache, outWriter io.Writer, js *jsonStream, stats *outputStats) {
	jobs := make(chan Job, len(cfg.URLs)+len(cfg.Files))
	results := make(chan Finding, 500)

	rl := newRateLimiter(cfg.RatePerSec)
	defer rl.Stop()

	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go worker(i+1, jobs, results, cfg, fsCache, rl, &wg)
	}

	stopCh := make(chan struct{})
	go func() {
		defer close(jobs)
		for _, u := range cfg.URLs {
			select {
			case <-stopCh:
				return
			case jobs <- Job{URL: u, IsFile: false}:
			}
		}
		for _, fpath := range cfg.Files {
			select {
			case <-stopCh:
				return
			case jobs <- Job{URL: fpath, IsFile: true}:
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range results {
			emit(cfg, f, outWriter, js, stats)
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		if _, ok := <-sigCh; !ok {
			return
		}
		logWarn(cfg, "Interrupted — flushing results... (Ctrl-C lagi = paksa keluar)")
		interrupted.Store(true)
		close(stopCh)
		if _, ok := <-sigCh; ok {
			os.Exit(130)
		}
	}()

	wg.Wait()
	close(results)
	<-done
}

// ─── Misc Helpers ─────────────────────────────────────────────────────────────

func uniqueDomains(urls []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, u := range urls {
		d := extractDomain(u)
		if d != "" {
			if _, ok := seen[d]; !ok {
				seen[d] = struct{}{}
				out = append(out, d)
			}
		}
	}
	return out
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
