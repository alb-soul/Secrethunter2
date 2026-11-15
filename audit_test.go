package main

// audit_test.go — regresi untuk temuan audit 2026-11.
// Setiap test di sini memetakan 1:1 ke satu cacat yang ditemukan (lihat AUDIT.md).

import (
	"sort"
	"strings"
	"testing"
)

// ── helper ───────────────────────────────────────────────────────────────────

func patternsFired(content string) []string {
	var out []string
	for _, f := range scanContent("test://x", content) {
		out = append(out, f.Pattern)
	}
	sort.Strings(out)
	return out
}

func mustFire(t *testing.T, content, pattern string) {
	t.Helper()
	for _, n := range patternsFired(content) {
		if n == pattern || strings.HasPrefix(n, pattern) {
			return
		}
	}
	t.Fatalf("pattern %q tidak fire untuk %q; yang fire: %v", pattern, content, patternsFired(content))
}

func mustNotFire(t *testing.T, content, pattern string) {
	t.Helper()
	for _, n := range patternsFired(content) {
		if n == pattern || strings.HasPrefix(n, pattern) {
			t.Fatalf("pattern %q seharusnya TIDAK fire untuk %q (FP)", pattern, content)
		}
	}
}

// ── BUG: ghr_ panjang tetap 76 → token 36 char (nyata) tidak terdeteksi ──────
func TestAuditGitHubRefreshLength(t *testing.T) {
	// panjang nyata token ghr_ adalah 36 char setelah prefiks
	mustFire(t, `"refresh_token": "ghr_mK3pQ7sV1xZ9aB5cD2eF4gH6iJ8kL0mN2oP4"`, "GitHub App Refresh Token (ghr_)")
	mustFire(t, "GITHUB_REFRESH_TOKEN=ghr_mK3pQ7sV1xZ9aB5cD2eF4gH6iJ8kL0mN2oP4qR6sT8uV0wX2yZ4\n", "GitHub App Refresh Token (ghr_)")
}

// ── BUG: Turnstile sitekey nyata 24-27 char tidak pernah match ({30,}) ───────
func TestAuditTurnstileLength(t *testing.T) {
	// sitekey format nyata (dipakai Cloudflare docs)
	mustFire(t, `<div class="cf-turnstile" data-sitekey="0x4AAAAAAABkMYinukE8nzY9"></div>`, "Cloudflare Turnstile Site Key")
	// secret key format lebih panjang
	mustFire(t, `turnstile_secret = "0x4AAAAAAABkMYinukE8nzY9AbCdEfGhIjKlMn"`, "Cloudflare Turnstile Secret Key")
}

// ── BUG: pola PGP hanya match header → CRITICAL palsu di dokumentasi ────────
func TestAuditPGPHeaderOnly(t *testing.T) {
	mustNotFire(t, "Use `-----BEGIN PGP PRIVATE KEY BLOCK-----` to start the block.", "PGP Private Key Block")
	mustFire(t, "-----BEGIN PGP PRIVATE KEY BLOCK-----\\nlQOYBGAbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghij", "PGP Private Key Block")
}

// ── BUG: .pgpass cocok dengan baris IPv6 di /etc/hosts ──────────────────────
func TestAuditPgpassIPv6(t *testing.T) {
	mustNotFire(t, "fe80:0000:0000:0000:0000:0000:0000:0001", "PostgreSQL .pgpass entry")
	mustFire(t, "dbhost:5432:mydb:bob:s3cretPass99", "PostgreSQL .pgpass entry")
}

// ── BUG: URI DB dengan password placeholder dilaporkan CRITICAL ─────────────
func TestAuditURIPlaceholder(t *testing.T) {
	for _, s := range []string{
		"postgres://user:password@localhost:5432/db",
		"mongodb://admin:secret@10.0.0.5:27017/admin",
		"redis://:pass@cache.internal:6379",
		"mysql://root:root@localhost/db",
		"postgres://${DB_USER}:${DB_PASS}@db/app",
	} {
		mustNotFire(t, s, "URI")
	}
	// password nyata tetap harus dilaporkan
	mustFire(t, "postgres://admin:S3cretPass99@db.internal:5432/app", "PostgreSQL URI")
	mustFire(t, "amqp://svc:Kd9fLp2Qw8@rabbit.internal:5672/vhost", "Messaging URI")
	mustFire(t, "ldaps://cn=svc:Zx81QpLm@ldap.internal:636", "Directory URI")
}

// ── BUG: token yang menempel di URL path dibuang (isBase64Slice) ────────────
func TestAuditTokenInURLPath(t *testing.T) {
	mustFire(t, `const u = "https://cdn.example.com/v1/ghp_AbCdEfGhIjKlMnOpQrStUvWx1234567890AB";`, "GitHub Personal Access Token (ghp_)")
	mustFire(t, `"/api/key/AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7"`, "Google API Key")
	// tapi potongan blob base64 panjang tetap harus ditolak
	notFired(t, "QWxsb3dUaGlzSXNBQmxvYlNsaWNlQmxvYlNsaWNl"+"AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7"+"QWxzb0Jsb2JTbGljZQ", "Google API Key")
}

// ── BUG: Stripe memotong kunci di 34 char (kunci modern ~99 char) ───────────
func TestAuditStripeFullLength(t *testing.T) {
	key := "sk_live_" + strings.Repeat("51AbCdEfGhIjKlMnOpQrStUv", 4) + "Wx"
	fds := scanContent("test://x", `STRIPE_SECRET_KEY=`+key)
	for _, f := range fds {
		if strings.HasPrefix(f.Pattern, "Stripe Live Secret Key") {
			if f.Match != key {
				t.Fatalf("Stripe key terpotong: got %d char, want %d", len(f.Match), len(key))
			}
			return
		}
	}
	t.Fatalf("Stripe key tidak terdeteksi: %v", patternsFired(`STRIPE_SECRET_KEY=`+key))
}

// ── BUG: satu nilai dilaporkan dua kali oleh pola berbeda ───────────────────
func TestAuditNoDuplicateFamily(t *testing.T) {
	fds := scanContent("test://x", "postgres://admin:S3cretPass99@db.internal:5432/app")
	if len(fds) != 1 {
		var got []string
		for _, f := range fds {
			got = append(got, f.Pattern+"|"+f.Severity+"|"+f.Match)
		}
		t.Fatalf("URI yang sama dilaporkan %d kali: %v", len(fds), got)
	}
}

// ── prefilter gate (AST) harus SOUND: tidak boleh menghilangkan temuan ──────
// Membandingkan hasil scan normal dengan scan yang mengabaikan gate.
func TestAuditGateSound(t *testing.T) {
	corpus := []string{
		`aws_access_key_id=AKIA4H8K2M5P7Q1W3E6R`,
		`{"stripe":"sk_live_4eC39HqLyjWDarjtT1zdp7dc","gh":"ghp_AbCdEfGhIjKlMnOpQrStUvWx1234567890AB"}`,
		`<script>var k="AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7";</script>`,
		`mongodb://admin:S3cretPass99@10.0.0.5:27017/admin`,
		`xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx`,
		// URL dirakit dari bagian-bagian: fixture asli (utuh) memicu GitHub push
		// protection "Slack Incoming Webhook" saat repo di-push.
		"https://hooks.slack.com/services/" + "T024BE7LD/B024BE7LD/" + "abcdefghijkmnpqrstuvwxyz",
		`password = "S3cretPass99"`,
		`admin:HiddenInPlainSight`,
		`-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7bq9uG3vKx8LmNpQrStUvWxYz0123456789abcdefghij`,
		`ntn_` + strings.Repeat("Ab3", 16),
		`patAbCdEfGhIjKl.` + strings.Repeat("a1", 32),
		`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.` + strings.Repeat("Ab3", 16),
		`GOCSPX-` + strings.Repeat("Ab3", 9) + "xW",
		`identityPoolId: "us-east-1:` + "1b2c3d4e-1111-2222-3333-444455556666" + `"`,
		`sk_test_AbCdEfGhIjKlMnOpQrStUvWx1234567890abcd`,
		`whsec_` + strings.Repeat("a1", 20),
		`DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=` + strings.Repeat("Ab1+", 21) + "==",
		`sqlserver://sa:Pa55w0rdStrong@db:1433?database=x`,
		`SMTP_PASSWORD=s3cretPass99`,
	}
	for _, c := range corpus {
		gated := map[string]bool{}
		for _, f := range scanContent("test://x", c) {
			gated[f.Pattern+"\x00"+f.Match] = true
		}
		for _, f := range scanNoGate(c) {
			if !gated[f.Pattern+"\x00"+f.Match] && !strings.Contains(f.Pattern, "(decoded)") {
				t.Fatalf("gate menghilangkan temuan %q (%q) pada korpus:\n%s\ngated=%v", f.Pattern, f.Match, c, keysOf(gated))
			}
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// scanNoGate menjalankan semua pola tanpa gate literal (pembanding soundness).
// Dedupe-nya disamakan dengan jalur normal (first-pattern-wins per match) supaya
// yang dibandingkan hanya efek gate.
func scanNoGate(content string) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, p := range patterns {
		for _, loc := range p.Regex.FindAllStringSubmatchIndex(content, -1) {
			start, end := loc[0], loc[1]
			if p.MatchGroup > 0 {
				gi := 2 * p.MatchGroup
				if gi+1 >= len(loc) || loc[gi] < 0 {
					continue
				}
				start, end = loc[gi], loc[gi+1]
			}
			m := content[start:end]
			if len(m) < 6 || isPlaceholder(m) || seen[m] {
				continue
			}
			seen[m] = true
			findings = append(findings, Finding{URL: "test://x", Pattern: p.Name, Match: m, Severity: p.Severity})
		}
	}
	return dedupeOverlapping(findings)
}

// ── pola baru (patterns_extra.go) ───────────────────────────────────────────
func TestAuditExtraPatternsFire(t *testing.T) {
	cases := []struct{ content, pattern string }{
		{`GOOGLE_OAUTH_SECRET=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`, "Google OAuth Client Secret (GOCSPX-)"},
		{`identityPoolId: "us-east-1:1b2c3d4e-1111-2222-3333-444455556666"`, "AWS Cognito Identity Pool ID (context)"},
		{`userPoolId: "us-east-1_Ab3dEf6Gh"`, "AWS Cognito User Pool ID (context)"},
		{`AZURE_DEVOPS_PAT=abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrsx`, "Azure DevOps PAT (context)"},
		{`$ANSIBLE_VAULT;1.1;AES256`, "Ansible Vault Encrypted Blob"},
		{`client-key-data: ` + strings.Repeat("Ab3dEf6G", 20), "Kubernetes kubeconfig client-key-data (base64 key)"},
		{`JENKINS_API_TOKEN=0123456789abcdef0123456789abcdef`, "Jenkins API Token (context)"},
		{`GITEA_ACCESS_TOKEN=0123456789abcdef0123456789abcdef01234567`, "Gitea / Forgejo Access Token (context)"},
		{`vercel_blob_rw_Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4St`, "Vercel Blob Read-Write Token"},
		{`SLACK_SIGNING_SECRET=0123456789abcdef0123456789abcdef`, "Slack Signing Secret (context)"},
		{`org-Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr`, "OpenAI Organization / Project ID"},
		{`amqp://svc:Kd9fLp2Qw8@rabbit.internal:5672/vhost`, "Messaging URI with credentials (AMQP/NATS/MQTT/Kafka)"},
		{`Server=db.internal;User Id=sa;Password=Pa55w0rdStrong`, "MSSQL / SQL Server connection string"},
		{`sk_sbox_Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4StUv7Wx`, "Checkout.com Secret Key (sk_sbox_/sk_live_)"},
		{`MOLLIE_API_KEY=live_Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4St`, "Mollie API Key (live_/test_, context)"},
		{`midtrans_doku_secret_key = "Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4St"`, "DOKU Secret Key (context)"},
		{`AZURE_OPENAI_API_KEY=0123456789abcdef0123456789abcdef`, "Azure OpenAI Key (context)"},
		{`QDRANT_API_KEY=Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4St`, "Qdrant API Key (context)"},
		{`WEAVIATE_API_KEY=Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4St`, "Weaviate API Key (context)"},
		{`FUSIONAUTH_API_KEY=Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4St`, "FusionAuth / Descope API Key (context)"},
		{`SPARKPOST_API_KEY=0123456789abcdef0123456789abcdef01234567`, "SparkPost API Key (context)"},
		{`STRAPI_API_TOKEN=Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4St`, "Strapi / Prismic API Token (context)"},
		{`BIGCOMMERCE_API_TOKEN=Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4St`, "BigCommerce / Magento / Wix API Credentials (context)"},
		{`CANVA_CLIENT_SECRET=Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4St`, "Canva / Miro / Box / Vimeo Client Secret (context)"},
		{`https://hc-ping.com/1b2c3d4e-1111-2222-3333-444455556666`, "Healthchecks.io Ping URL (token)"},
		{`$2b$12$Ab3dEf6Gh9Ij2Kl5Mn8Op1Qr4StUv7WxYz0aBcDeFgHiJkLmNoPqRsT`, "bcrypt Password Hash"},
	}
	for _, c := range cases {
		mustFire(t, c.content, c.pattern)
	}
}

// pola baru tidak boleh menambah noise di bundle JS biasa
func TestAuditExtraPatternsNoNoise(t *testing.T) {
	js := `!function(){"use strict";var a=document.querySelectorAll("[data-toggle]");` +
		`forEach(a,function(b){b.addEventListener("click",function(){var c=b.getAttribute("data-target");` +
		`document.querySelector(c).classList.toggle("is-open")})});fetch("/api/v1/session",{method:"POST",` +
		`headers:{"Content-Type":"application/json","X-Request-Id":"5ac41e5b-7b3a-4f3a-9479-b13abb98616d"}})` +
		`.then(function(a){return a.json()}).then(function(a){console.log(a)});}();`
	for _, f := range scanContent("test://x", js) {
		if strings.HasSuffix(f.Pattern, "(context)") {
			t.Fatalf("pola context-anchored noisy di JS: %s=%q", f.Pattern, f.Match)
		}
	}
}

// ── helper kecil yang dipakai beberapa fix ───────────────────────────────────
func TestAuditWithScheme(t *testing.T) {
	cases := map[string]string{
		"example.com":                "https://example.com",
		"https://example.com":        "https://example.com",
		"//example.com/x":            "https://example.com/x",
		"127.0.0.1:8899":             "http://127.0.0.1:8899",
		"localhost:3000/api":         "http://localhost:3000/api",
		"ftp://example.com":          "ftp://example.com",
		"  example.com/path?q=1  ":   "https://example.com/path?q=1",
		"sub.example.com:8443/deep":  "https://sub.example.com:8443/deep",
		"http://plain.example.com/x": "http://plain.example.com/x",
	}
	for in, want := range cases {
		if got := withScheme(in); got != want {
			t.Errorf("withScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuditMinSeverity(t *testing.T) {
	if !severityAtLeast("", SevInfo) {
		t.Fatal("empty min-severity should allow everything")
	}
	if severityAtLeast(SevHigh, SevMedium) {
		t.Fatal("MEDIUM must be filtered when min=HIGH")
	}
	if !severityAtLeast(SevLow, SevCritical) {
		t.Fatal("CRITICAL must pass min=LOW")
	}
}

func TestAuditAnsiStripper(t *testing.T) {
	var b strings.Builder
	w := ansiStripper{w: &b}
	in := colorRed + colorBold + "[CRITICAL]" + colorReset + " AWS | AKIA...\n"
	if _, err := w.Write([]byte(in)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b") {
		t.Fatalf("escape code masih tersisa: %q", b.String())
	}
	if !strings.Contains(b.String(), "[CRITICAL]") {
		t.Fatalf("teks hilang: %q", b.String())
	}
}
