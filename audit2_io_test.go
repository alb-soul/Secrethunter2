package main

// audit2_io_test.go — regresi audit 2026-11b: jalur I/O mode --httpx-json,
// format output, exit/dedup. Token sampel DIRAKIT saat runtime (cat(...)) agar
// file test tidak memuat literal yang diblokir GitHub push protection.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// cat menggabung potongan string — dipakai untuk merakit token sampel.
func cat(parts ...string) string { return strings.Join(parts, "") }

// rep mengulang pola s hingga panjang n.
func rep(s string, n int) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(s)
	}
	return b.String()[:n]
}

func TestForEachLineSkipsOversizeAndContinues(t *testing.T) {
	in := "first\n" + strings.Repeat("x", 5000) + "\nthird\nlast-no-newline"
	var got []string
	skipped, err := forEachLine(strings.NewReader(in), 1000, nil, func(b []byte) { got = append(got, string(b)) })
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Fatalf("skipped=%d, want 1", skipped)
	}
	want := []string{"first", "third", "last-no-newline"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestForEachLineLongButAllowed(t *testing.T) {
	// baris lebih panjang dari buffer bufio (1 MB) tapi di bawah batas → tetap utuh
	long := strings.Repeat("a", 3<<20)
	var n int
	_, err := forEachLine(strings.NewReader(long+"\nb\n"), 4<<20, nil, func(b []byte) {
		if len(b) == len(long) || string(b) == "b" {
			n++
		}
	})
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestHeaderMapText(t *testing.T) {
	raw := json.RawMessage(`{"x_debug_token":"abc","set_cookie":["a=1","b=2"],"n":5}`)
	got := headerMapText(raw)
	for _, w := range []string{"x_debug_token: abc\n", "set_cookie: a=1\n", "set_cookie: b=2\n"} {
		if !strings.Contains(got, w) {
			t.Fatalf("headerMapText missing %q in %q", w, got)
		}
	}
	// httpx lama kadang menulis header sebagai array nama → abaikan
	if headerMapText(json.RawMessage(`["content_type"]`)) != "" {
		t.Fatal("array header harus diabaikan")
	}
}

func TestLooksBinary(t *testing.T) {
	cjk := strings.Repeat("商品の説明です。送料無料でお届けします。", 2000)
	if looksBinary(cjk) {
		t.Fatal("halaman CJK (UTF-8 valid) terdeteksi biner — FN")
	}
	if looksBinary(`var a="x";function f(){return 1}` + "\n") {
		t.Fatal("JS terdeteksi biner")
	}
	png := "\x89PNG\r\n" + strings.Repeat("\ufffd\x01\ufffd", 3000)
	if !looksBinary(png) {
		t.Fatal("body biner (U+FFFD dominan) tidak terdeteksi")
	}
	raw := make([]byte, 4096)
	for i := range raw {
		raw[i] = byte(i*131 + 7)
	}
	if !looksBinary(string(raw)) {
		t.Fatal("byte acak tidak terdeteksi biner")
	}
	// rune multibyte terpotong di batas sampel 64 KB bukan tanda biner
	edge := strings.Repeat("a", 64<<10-1) + "日本"
	if looksBinary(edge) {
		t.Fatal("rune terpotong di batas sampel dianggap biner")
	}
}

func TestBinaryContentType(t *testing.T) {
	for _, ct := range []string{"image/png", "font/woff2", "application/octet-stream", "Video/MP4"} {
		if !binaryContentType(ct) {
			t.Fatalf("%s seharusnya biner", ct)
		}
	}
	for _, ct := range []string{"", "text/html; charset=utf-8", "application/javascript", "image/svg+xml", "application/json"} {
		if binaryContentType(ct) {
			t.Fatalf("%s seharusnya teks", ct)
		}
	}
}

func TestHostInScopeVariants(t *testing.T) {
	cases := []struct {
		u, scope string
		want     bool
	}{
		{"https://a.Target.com/x", "target.com", true},
		{"https://target.com./x", "TARGET.COM", true},
		{"https://a.target.com/x", "*.target.com", true},
		{"https://a.target.com/x", "https://target.com", true},
		{"https://eviltarget.com/x", "target.com", false},
		{"https://target.com.evil.io/x", "target.com", false},
		{"https://a.target.com/x", "", false},
	}
	for _, c := range cases {
		if got := hostInScope(c.u, c.scope); got != c.want {
			t.Fatalf("hostInScope(%q,%q)=%v want %v", c.u, c.scope, got, c.want)
		}
	}
}

func TestPrintFindingSingleLine(t *testing.T) {
	cfg := &Config{NoColor: true}
	var buf bytes.Buffer
	f := Finding{URL: "https://x/app.js", Pattern: "RSA Private Key", Severity: SevCritical,
		Match: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7bq9uG3vKx8Lm\tNp"}
	if err := printFinding(cfg, f, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("output pecah jadi beberapa baris: %q", out)
	}
	re := regexp.MustCompile(`^\[CRITICAL\] RSA Private Key \| -----BEGIN RSA PRIVATE KEY-----\\nMIIE\S+\\tNp \| https://x/app\.js\n$`)
	if !re.MatchString(out) {
		t.Fatalf("format baris berubah: %q", out)
	}
}

// End-to-end mode kontrak: --httpx-json + --scope + -o (teks).
func TestHTTPXJSONEndToEnd(t *testing.T) {
	dir := t.TempDir()
	ghHeader := cat("gh", "p_", rep("Hk2Lm9Pq4Rs7Tv1Wx3Yz5", 36))
	ghBody := cat("gh", "p_", rep("Qa8Zb2Xc6Vd0Nf4Mg7Jh1", 36))
	ghOOS := cat("gh", "p_", rep("Ww1Ee2Rr3Tt4Yy5Uu6Ii7", 36))
	recs := []map[string]any{
		// secret hanya di map `header` (tanpa raw_header) — dulu FN
		{"url": "https://a.target.test/api", "status_code": 200, "body": `{"ok":true}`,
			"header": map[string]any{"content_type": "application/json", "x_debug_token": ghHeader}},
		// record yang sama muncul dua kali → satu baris output
		{"url": "https://b.target.test/app.js", "status_code": 200, "body": `const t="` + ghBody + `";`, "content_type": "application/javascript"},
		{"url": "https://b.target.test/app.js", "status_code": 200, "body": `const t="` + ghBody + `";`, "content_type": "application/javascript"},
		// di luar scope
		{"url": "https://cdn.other.example/x.js", "status_code": 200, "body": `const t="` + ghOOS + `";`},
		// biner berlabel image/png → dilewati walau isinya mirip token
		{"url": "https://c.target.test/i.png", "status_code": 200, "body": `const t="` + ghOOS + `";`, "content_type": "image/png"},
	}
	var in bytes.Buffer
	for _, r := range recs {
		b, _ := json.Marshal(r)
		in.Write(b)
		in.WriteByte('\n')
	}
	in.WriteString("{not json}\n")
	jl := filepath.Join(dir, "in.jsonl")
	if err := os.WriteFile(jl, in.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "secrets.txt")
	outF, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{HTTPXJSON: jl, Scope: "target.test", Threads: 4, Silent: true, NoColor: true, MaxBodyBytes: 10 << 20}
	emitDedup = findingDedup{}
	if err := scanHTTPXJSON(cfg, teeOut{primary: ansiStripper{w: outF}, secondary: &bytes.Buffer{}}, nil, newOutputStats()); err != nil {
		t.Fatal(err)
	}
	outF.Close()
	data, _ := os.ReadFile(outPath)
	out := string(data)
	lineRe := regexp.MustCompile(`^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\] [^|]+ \| .+ \| \S+$`)
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !lineRe.MatchString(l) {
			t.Fatalf("baris tidak sesuai kontrak: %q", l)
		}
	}
	if !strings.Contains(out, ghHeader+" | https://a.target.test/api") {
		t.Fatalf("secret di map header tidak terdeteksi:\n%s", out)
	}
	if strings.Count(out, ghBody) != 1 {
		t.Fatalf("record duplikat harus menghasilkan 1 baris, got %d:\n%s", strings.Count(out, ghBody), out)
	}
	if strings.Contains(out, ghOOS) {
		t.Fatalf("record di luar scope / biner ikut dilaporkan:\n%s", out)
	}
	if fi, _ := os.Stat(outPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode file -o = %v, want 0600", fi.Mode().Perm())
	}
}

func TestHTTPXJSONMissingFileIsError(t *testing.T) {
	cfg := &Config{HTTPXJSON: filepath.Join(t.TempDir(), "nope.jsonl"), Threads: 1, Silent: true, MaxBodyBytes: 1 << 20}
	if err := scanHTTPXJSON(cfg, &bytes.Buffer{}, nil, newOutputStats()); err == nil {
		t.Fatal("file input tidak ada harus mengembalikan error (exit 1)")
	}
}

type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) { return 0, os.ErrClosed }

func resetWriteErr() {
	writeErrMu.Lock()
	writeErrV = nil
	writeErrMu.Unlock()
}

func TestWriteErrorRecorded(t *testing.T) {
	resetWriteErr()
	defer resetWriteErr()
	emitDedup = findingDedup{}
	cfg := &Config{NoColor: true}
	emit(cfg, Finding{URL: "u", Pattern: "p", Match: "m-123456", Severity: SevHigh}, teeOut{primary: failWriter{}, secondary: &bytes.Buffer{}}, nil, newOutputStats())
	if firstWriteErr() == nil {
		t.Fatal("error tulis ke -o harus dicatat (exit 1)")
	}
}
