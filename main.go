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
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	version   = "2.2.1"
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
	resp, err := httpClient.Do(req)
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

func buildClient(cfg *Config) *http.Client {
	perHost := cfg.Threads + 10
	if perHost > 256 {
		perHost = 256
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
			Proxy:                  http.ProxyFromEnvironment,
			MaxIdleConns:           512,
			MaxIdleConnsPerHost:    perHost,
			IdleConnTimeout:        90 * time.Second,
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  25 * time.Second,
			ExpectContinueTimeout:  1 * time.Second,
			ForceAttemptHTTP2:      true,
		},
	}
}

func fetchURL(cfg *Config, rawURL string, fsCache *FSCache) (string, error) {
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
		for _, h := range cfg.ExtraHeaders {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
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

// ─── Keyword prefilter (v2) ────────────────────────────────────────────────────
//
// patternPrefilter[i] = literal lowercase yang WAJIB ada di konten agar pola i
// bisa match. Diturunkan AMAN dari regex.String() (tidak akan false-negative):
// hanya diambil bila literal itu benar-benar prefix wajib dari match.

var patternPrefilter []string

func init() {
	patternPrefilter = make([]string, len(patterns))
	for i, p := range patterns {
		patternPrefilter[i] = derivePrefilter(p.Regex.String())
	}
}

// derivePrefilter mengembalikan substring literal wajib (lowercase) atau "".
// Konservatif: jika ada keraguan (quantifier/alternation di ujung literal),
// kembalikan "" agar pola tetap dijalankan (tidak melewatkan finding).
func derivePrefilter(src string) string {
	s := src
	s = strings.TrimPrefix(s, "(?i)")
	s = strings.TrimPrefix(s, "\\b")
	const meta = "[](){}.*+?|\\^$"
	runes := []rune(s)
	var lit []rune
	i := 0
	for ; i < len(runes); i++ {
		if strings.ContainsRune(meta, runes[i]) {
			break
		}
		lit = append(lit, runes[i])
	}
	// Char tepat setelah literal: '?','*','|','{' membuat char terakhir
	// opsional / cabang alternasi → literal tak lagi wajib penuh → tolak.
	if i < len(runes) {
		switch runes[i] {
		case '?', '*', '|', '{':
			return ""
		}
	}
	kw := strings.ToLower(string(lit))
	if len(kw) < 4 {
		return ""
	}
	return kw
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
var publicByDesign = map[string]bool{
	"Stripe Live Publishable Key":                true,
	"Clerk Publishable Key (pk_live_/pk_test_)":  true,
	"PubNub Subscribe Key":                       true,
	"Google reCAPTCHA Site Key":                  true,
	"Mapbox Public Token":                        true,
	"Mapbox Temporary Token":                     true,
	"Algolia Search-Only API Key":                true,
	"Supabase Publishable Key (sb_publishable_)": true,
	"PostHog Project API Key (phc_)":             true,
	"Segment Write Key (context)":                true,
	"Amplitude API Key":                          true,
	"Firebase API Key / Config":                  true,
	"Cloudflare Turnstile Site Key (0x4AAAA)":    true,
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

func scanContent(rawURL, content string) []Finding {
	contentLower := strings.ToLower(content) // v3/v2: sekali, untuk prefilter
	if len(content) >= parallelScanMinBytes && len(patterns) > 1 {
		return scanContentPar(rawURL, content, contentLower)
	}
	return scanContentSeq(rawURL, content, contentLower)
}

func scanContentSeq(rawURL, content, contentLower string) []Finding {
	var findings []Finding
	seen := make(map[string]struct{})
	li := buildLineIndex(content)

	for pi, p := range patterns {
		// v2: prefilter murah sebelum regex mahal
		if kw := patternPrefilter[pi]; kw != "" && !strings.Contains(contentLower, kw) {
			continue
		}
		locs := p.Regex.FindAllStringSubmatchIndex(content, -1)
		for _, loc := range locs {
			var startPos, endPos int
			if p.MatchGroup == 0 {
				startPos, endPos = loc[0], loc[1]
			} else {
				gi := 2 * p.MatchGroup
				if gi+1 >= len(loc) || loc[gi] < 0 {
					continue
				}
				startPos, endPos = loc[gi], loc[gi+1]
			}
			match := content[startPos:endPos]
			if match == "" {
				continue
			}
			if _, dup := seen[match]; dup {
				continue
			}
			seen[match] = struct{}{}
			if len(match) < 6 {
				continue
			}
			if isPlaceholder(match) {
				continue
			}
			lineNum := li.lineAt(startPos)
			lt := li.lineTextOf(content, lineNum)
			if p.Name == "Twitter/X Bearer Token" || strings.HasPrefix(p.Name, "Square") {
				if strings.Contains(lt, "base64,") || strings.Contains(lt, "data:") {
					continue
				}
			}
			if humanCredPatterns[p.Name] && isHumanCredFP(p.Name, match, lt) {
				continue
			}
			patternName := p.Name
			severity := p.Severity
			if publicByDesign[p.Name] {
				if noPublicGlobal {
					continue
				}
				severity = SevInfo
			}
			if p.Name == "JSON Web Token (JWT)" {
				if jwtAlgIsNone(match) {
					patternName = "JWT with alg:none (Forgeable — Auth Bypass)"
					severity = SevCritical
				} else {
					severity = SevLow
				}
			}
			findings = append(findings, Finding{
				URL:      rawURL,
				Pattern:  patternName,
				Match:    truncate(match, 120),
				Severity: severity,
				Line:     lineNum,
			})
		}
	}
	return findings
}

// collectCandidates menjalankan regex untuk rentang pattern [s,e) dan
// mengembalikan kandidat mentah (belum di-filter / dedup global).
func collectCandidates(content, contentLower string, s, e int) []patternCandidate {
	var out []patternCandidate
	for pi := s; pi < e; pi++ {
		p := &patterns[pi]
		if kw := patternPrefilter[pi]; kw != "" && !strings.Contains(contentLower, kw) {
			continue
		}
		if p.MatchGroup == 0 {
			for _, loc := range p.Regex.FindAllStringIndex(content, -1) {
				if loc[1] > loc[0] {
					out = append(out, patternCandidate{pi: pi, startPos: loc[0], endPos: loc[1]})
				}
			}
		} else {
			for _, loc := range p.Regex.FindAllStringSubmatchIndex(content, -1) {
				gi := 2 * p.MatchGroup
				if gi+1 >= len(loc) || loc[gi] < 0 {
					continue
				}
				if loc[gi+1] > loc[gi] {
					out = append(out, patternCandidate{pi: pi, startPos: loc[gi], endPos: loc[gi+1]})
				}
			}
		}
	}
	return out
}

func scanContentPar(rawURL, content, contentLower string) []Finding {
	np := len(patterns)
	workers := parallelScanWorkers
	if workers > np {
		workers = np
	}
	groups := make([][]patternCandidate, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		s := w * np / workers
		e := (w + 1) * np / workers
		if s >= e {
			continue
		}
		wg.Add(1)
		go func(w, s, e int) {
			defer wg.Done()
			groups[w] = collectCandidates(content, contentLower, s, e)
		}(w, s, e)
	}
	wg.Wait()
	return mergeCandidates(rawURL, content, groups)
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
	seen := make(map[string]struct{})
	for _, g := range groups {
		for _, c := range g {
			match := content[c.startPos:c.endPos]
			if _, dup := seen[match]; dup {
				continue
			}
			seen[match] = struct{}{}
			if len(match) < 6 {
				continue
			}
			if isPlaceholder(match) {
				continue
			}
			p := &patterns[c.pi]
			lineNum := li.lineAt(c.startPos)
			lt := li.lineTextOf(content, lineNum)
			if p.Name == "Twitter/X Bearer Token" || strings.HasPrefix(p.Name, "Square") {
				if strings.Contains(lt, "base64,") || strings.Contains(lt, "data:") {
					continue
				}
			}
			if humanCredPatterns[p.Name] && isHumanCredFP(p.Name, match, lt) {
				continue
			}
			patternName := p.Name
			severity := p.Severity
			if publicByDesign[p.Name] {
				if noPublicGlobal {
					continue
				}
				severity = SevInfo
			}
			if p.Name == "JSON Web Token (JWT)" {
				if jwtAlgIsNone(match) {
					patternName = "JWT with alg:none (Forgeable — Auth Bypass)"
					severity = SevCritical
				} else {
					severity = SevLow
				}
			}
			findings = append(findings, Finding{
				URL:      rawURL,
				Pattern:  patternName,
				Match:    truncate(match, 120),
				Severity: severity,
				Line:     lineNum,
			})
		}
	}
	return findings
}



// humanCredPatterns marks pattern names that need extra anti-FP checks.
var humanCredPatterns = map[string]bool{
	"HTML comment credentials (user:pass)":              true,
	"JS/line comment credentials (user:pass)":            true,
	"Block comment credentials (user:pass)":              true,
	"Freeform credentials near keyword (user:pass)":      true,
	"Password assignment (quoted or bare)":               true,
	"Password assignment bare (env/config)":              true,
	"Username + Password pair assignment":                true,
	"Hardcoded password input value":                     true,
	"Hardcoded password input value (value before type)": true,
	"Generic Secret / Password in code":                  true,
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
			// CSS property names (background-color, font-size, …)
			if strings.Contains(user, "-") {
				return true
			}
			// scheme-like
			if ul == "http" || ul == "https" || ul == "ftp" || ul == "mailto" || ul == "ws" || ul == "wss" || ul == "file" {
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

func isPlaceholder(s string) bool {
	lower := strings.ToLower(s)
	placeholders := []string{
		"your_", "yourkey", "yourapikey", "your-api", "example",
		"changeme", "replace", "xxxxxxxx", "aaaaaaaa", "11111111",
		"00000000", "test123", "password123", "secret123",
		"<api", "api_key>", "token>", "{api", "{key", "${",
		"xxxx", "yyyy", "zzzz", "none", "undefined", "null",
		"placeholder", "insert_", "insert-", "redacted", "dummy",
		"sample", "lorem", "asdf", "qwerty", "abc123", "string",
		"todo", "fixme", "xxx", "yyy", "zzz",
	}
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
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
	}
}

// ─── httpx JSONL mode (v2, body-reuse) ─────────────────────────────────────────

type httpxRecord struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"`
	RawHeader  string `json:"raw_header"`
}

type jsonJob struct{ url, body string }

// hostInScope: host == scope atau *.scope
func hostInScope(rawURL, scope string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	scope = strings.ToLower(strings.TrimPrefix(scope, "*."))
	return host == scope || strings.HasSuffix(host, "."+scope)
}

// scanHTTPXJSON membaca JSONL httpx (-json -irr) dan men-scan body tanpa fetch.
func scanHTTPXJSON(cfg *Config, outWriter io.Writer, js *jsonStream, stats *outputStats) {
	f, err := os.Open(cfg.HTTPXJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening httpx-json: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	jobs := make(chan jsonJob, cfg.Threads)
	results := make(chan Finding, 500)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				body := j.body
				if int64(len(body)) > cfg.MaxBodyBytes {
					body = body[:cfg.MaxBodyBytes]
				}
				for _, fd := range scanContent(j.url, body) {
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

	// Producer: baca JSONL baris demi baris (buffer besar utk body inline)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024) // s/d 64MB per baris
	count := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec httpxRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.URL == "" || (rec.Body == "" && rec.RawHeader == "") {
			continue
		}
		if cfg.Scope != "" && !hostInScope(rec.URL, cfg.Scope) {
			continue
		}
		count++
		// v3: scan body + response headers (CSP/Set-Cookie often carry hosts/secrets)
		combined := rec.Body
		if rec.RawHeader != "" {
			combined = rec.Body + "\n" + rec.RawHeader
		}
		jobs <- jsonJob{rec.URL, combined}
	}
	if err := sc.Err(); err != nil {
		logVerbose(cfg, "[httpx-json] scanner error: %v", err)
	}
	close(jobs)
	wg.Wait()
	close(results)
	<-done
	logInfo(cfg, "httpx-json: %d record discan (in-scope)", count)
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

func printFinding(cfg *Config, f Finding, w io.Writer) {
	line := fmt.Sprintf("%s %s | %s | %s\n",
		colorSeverity(cfg, f.Severity),
		colorize(cfg, colorCyan, f.Pattern),
		colorize(cfg, colorGreen, f.Match),
		colorize(cfg, colorDim, f.URL),
	)
	fmt.Fprint(w, line)
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
	js.w.Write(b)
}

func (js *jsonStream) end() {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.closed {
		return
	}
	if !js.opened {
		fmt.Fprint(js.w, "[]\n")
	} else {
		fmt.Fprint(js.w, "]\n")
	}
	js.closed = true
}

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
	if cfg.OutputJSON && js != nil {
		js.emit(fd)
	} else {
		mu.Lock()
		printFinding(cfg, fd, outWriter)
		mu.Unlock()
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
	resp, err := httpClient.Get(baseURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.Contains(string(body), "FlareSolverr")
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
	)
	var headers multiFlag
	flag.Var(&headers, "H", "Custom request header (repeatable)")
	flag.Var(&headers, "header", "Custom request header, alias for -H")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\nUsage: secrethunter2 [options] -u <url> | -l <file> | --httpx-json <file>\n", fmt.Sprintf(banner, version))
		flag.PrintDefaults()
	}

	flag.Parse()
	noPublicGlobal = *flagNoPublic

	if *flagVersion {
		fmt.Printf("secrethunter2 v%s\n", version)
		os.Exit(0)
	}

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	threads := *flagThreads
	if setFlags["threads"] && !setFlags["t"] {
		threads = *flagThreadsLong
	}
	delayMs := *flagDelay
	if setFlags["delay"] && !setFlags["d"] {
		delayMs = *flagDelayLong
	}
	if threads < 1 {
		threads = 1
	}

	cfg := &Config{
		Threads:      threads,
		DelayMs:      delayMs,
		RatePerSec:   *flagRate,
		UserAgent:    *flagUA,
		OutputJSON:   *flagJSON,
		Timeout:      *flagTimeout,
		Silent:       *flagSilent || *flagSilentLong,
		Verbose:      *flagVerbose || *flagVerboseLong,
		NoColor:      *flagNoColor,
		MaxBodyBytes: int64(max(*flagMaxSize, 1)) * 1024 * 1024,
		ExtraHeaders: []string(headers),
		HTTPXJSON:    *flagHTTPXJSON,
		Scope:        *flagScope,
	}
	cfg.OutputFile = first(*flagOutput, *flagOutputLong)
	fsURL := first(*flagFS, *flagFSShort)
	if fsURL != "" {
		cfg.FlareSolvrURL = strings.TrimRight(fsURL, "/")
	}

	// Shared HTTP client (keep-alive)
	httpClient = buildClient(cfg)

	// ── Output writer ──
	var outWriter io.Writer = os.Stdout
	var outF *os.File
	if cfg.OutputFile != "" {
		var err error
		outF, err = os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outF.Close()
		outWriter = io.MultiWriter(os.Stdout, outF)
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
		scanHTTPXJSON(cfg, outWriter, js, stats)
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
	return
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logWarn(cfg, "Interrupted — flushing results...")
		close(stopCh)
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
