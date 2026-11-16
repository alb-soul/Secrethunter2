package main

// engine_test.go — kebenaran engine prefilter (engine.go):
//   - ekstraksi literal (exact set / product)
//   - Aho-Corasick == pencarian brute force
//   - windowed scan == full scan (--no-window) pada sampel test + corpus

import (
	"fmt"
	"regexp/syntax"
	"sort"
	"strings"
	"testing"
)

func groupsOf(t *testing.T, src string) []string {
	t.Helper()
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, g := range requiredGroups(re) {
		var ls []string
		for _, l := range g {
			ls = append(ls, fmt.Sprintf("%s/%v", l.lit, l.fold))
		}
		out = append(out, strings.Join(ls, "|"))
	}
	return out
}

func TestEngineRequiredGroups(t *testing.T) {
	cases := map[string]string{
		// faktorisasi prefix parser (A(?:KIA|BIA…)) dulu menghilangkan gate
		`\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b`: "ABIA/false|ACCA/false|AKIA/false|ASIA/false",
		// perkalian potongan opsional kecil
		`(?i)(?:api[_\-]?key|apikey)["']?\s*[=:]`:             "api-key/true|api_key/true|apikey/true",
		`ghp_[A-Za-z0-9]{36}`:                                 "ghp_/false",
		`(?i)(?:deepseek|kimi|moonshot|zhipu|glm)[_\-\s]*key`: "deepseek/true|glm/true|kimi/true|moonshot/true|zhipu/true ; key/true",
	}
	for src, want := range cases {
		got := strings.Join(groupsOf(t, src), " ; ")
		if got != want {
			t.Errorf("requiredGroups(%s)\n got: %s\nwant: %s", src, got, want)
		}
	}
	// opsional total / terlalu pendek → tanpa gate (bukan gate yang salah)
	for _, src := range []string{`(?:abc)?[0-9]+`, `[A-Z]{3}`, `(?i)x?y`} {
		if g := groupsOf(t, src); len(g) != 0 {
			t.Errorf("%s seharusnya tanpa gate, got %v", src, g)
		}
	}
}

func TestEngineAhoCorasickMatchesBruteForce(t *testing.T) {
	content := strings.Repeat("xx AKIA akia Password=token SECRET ghp_ re_ api-key ApiKey sk-ant- ", 50) + "tail"
	occ := engAC.find(content)
	defer occ.release()
	for vid, l := range engLits {
		hay, needle := content, l.lit
		if l.fold {
			hay = asciiLower(content)
		}
		want := 0
		for i := 0; ; {
			j := strings.Index(hay[i:], needle)
			if j < 0 {
				break
			}
			want++
			i += j + 1
		}
		if int(occ.count[vid]) != want {
			t.Fatalf("literal %q (fold=%v): AC=%d brute=%d", l.lit, l.fold, occ.count[vid], want)
		}
	}
}

// findingKeys: representasi kanonik hasil scan untuk perbandingan.
func findingKeys(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s\x00%s\x00%s\x00%d", f.Pattern, f.Match, f.Severity, f.Line))
	}
	sort.Strings(out)
	return out
}

func assertWindowEquivalent(t *testing.T, label, content string) {
	t.Helper()
	win := findingKeys(scanContent("t://x", content))
	noWindowGlobal = true
	full := findingKeys(scanContent("t://x", content))
	noWindowGlobal = false
	if strings.Join(win, "\n") != strings.Join(full, "\n") {
		t.Fatalf("%s: windowed != full scan\nwindowed: %q\nfull:     %q", label, win, full)
	}
}

// Semua sampel positif/negatif dari test lain + konteks padding (literal di
// awal/akhir/tengah body, body besar → jalur paralel).
func TestEngineWindowEquivalenceSamples(t *testing.T) {
	samples := engineSamples()
	pad := strings.Repeat(`function r(e,t){return e.dispatch(t)}var ab=12345;"state":"qwmzpe";`, 400)
	for i, s := range samples {
		assertWindowEquivalent(t, fmt.Sprintf("sample#%d", i), s)
		assertWindowEquivalent(t, fmt.Sprintf("sample#%d+pad", i), pad+"\n"+s+"\n"+pad)
		assertWindowEquivalent(t, fmt.Sprintf("sample#%d+inline", i), pad+s+pad)
	}
	// satu body >1 MB berisi semua sampel (jalur paralel + jendela bergabung)
	var b strings.Builder
	for b.Len() < 1100<<10 {
		for _, s := range samples {
			b.WriteString(pad[:500])
			b.WriteString(s)
			b.WriteString("\n")
		}
	}
	assertWindowEquivalent(t, "big", b.String())
}

// Corpus gencorpus (opsional, SH2_CORPUS): windowed == full untuk setiap body.
func TestEngineWindowEquivalenceCorpus(t *testing.T) {
	bodies := loadCorpusBodies(t, 400)
	for i, s := range bodies {
		assertWindowEquivalent(t, fmt.Sprintf("corpus#%d", i), s)
	}
}

func engineSamples() []string {
	gh := cat("gh", "p_", rep("Hk2Lm9Pq4Rs7Tv1Wx3Yz5", 36))
	return []string{
		`aws_access_key_id = "AKIA4H8K2M5P7Q1W3E6R"`,
		cat(`{region:"us-east-1",secretAccessKey:"`, tk(csB64, 40, 8), `"}`),
		`const t="` + gh + `";`,
		`fetch("https://cdn.example.com/` + gh + `/sendMessage");`,
		cat("7012345678", ":AAH", rep("dqTcvCH1vGWJxfSeofSAs0K5PALDsaw", 32)),
		`postgres://bob:s3cretPass@db.internal:5432/app`,
		cat("mongodb://svc_app:", "Kq7Zt2Lm9Xw4", "@db1.internal:27017,db2.internal:27017/app"),
		`password = "S3cretPass99"`,
		`<!-- TODO: remove test credentials admin:HiddenInPlainSight -->`,
		`// credentials admin:HiddenInPlainSight`,
		`machine api.example.com login deploy password S3cretDeploy99`,
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7bq9uG3vKx8LmNpQrStUvWxYz01" + rep("Ab3+", 300) + "\n",
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.` + b64u(`{"iss":"supabase","role":"service_role","pad":"`+rep("x1", 1500)+`"}`) + `.` + rep("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", 43),
		cat("CF_API_TOKEN=cf", "at_", tk(csA62, 40, 20), tk(csHex, 8, 21), "\n"),
		cat(`OPENAI_API_KEY="sk-`, "proj-", tk(csB64URL, 74, 50), "T3BlbkFJ", tk(csB64URL, 74, 51), `"`),
		cat("sk_", "live_", tk(csA62, 99, 52)),
		`var e="ghp_"+"QwEr0987654321TyUiOpMnBjHgFdSaKlZxCv",i={github_token:e};`,
		`var n="wJalrXUtnFEMI/K7MDENG/bPxRfiCYTESTKEY000",i={aws_secret_access_key:n};`,
		"Authorization: Basic " + "c3ZjLWRlcGxveTpadDhzUTF4VnAzTG0=",
		`jdbc:postgresql://db:5432/app?user=svc&password=Zt8sQ1xVp3`,
		`{"auths":{"https://index.docker.io/v1/":{"auth":"Ym9iOlp0OHNRMXhWcDNMbQ=="}}}`,
		cat(`appId:"sq0idp-`, rep("AbCdEfGhIjKlMnOpQrSt12", 22), `"`),
		`data:image/png;base64,` + rep("iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB", 3000),
		`dbhost:5432:mydb:bob:s3cretPass99`,
		`https://user:Zt8sQ1xVp3@internal.example.com/x`,
		`username: "deployer", password: "Zt8sQ1xVp3Lm"`,
		cat(`"clientSecret": "`, tk(csA62, 3, 12), "8Q~", tk(csA62+"_~.-", 34, 13), `"`),
	}
}
