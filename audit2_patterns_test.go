package main

// audit2_patterns_test.go — regresi audit 2026-11b untuk perbaikan presisi /
// recall pola yang SUDAH ada. Setiap kasus punya sisi positif & negatif.
// Token dirakit dengan cat()/rep() (lihat audit2_io_test.go).

import (
	"encoding/base64"
	"strings"
	"testing"
)

func b64u(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func sevOf(content, pattern string) string {
	for _, f := range scanContent("test://x", content) {
		if f.Pattern == pattern {
			return f.Severity
		}
	}
	return ""
}

func TestAudit2AWSKeyCaseSensitive(t *testing.T) {
	mustFire(t, cat(`{accessKeyId:"AKIA`, "4H8K2M5P7Q1W3E6R", `"}`), "AWS Access Key ID")
	// identifier minified huruf kecil: dulu CRITICAL palsu karena (?i)
	mustNotFire(t, cat(`var akia`, "4h8k2m5p7q1w3e6r", `=function(){return 1};`), "AWS Access Key ID")
	mustNotFire(t, cat(`window.asia`, "pacificregionmenu", `=1`), "AWS Access Key ID")
}

func TestAudit2MongoRequiresCredentials(t *testing.T) {
	mustNotFire(t, `const MONGO="mongodb://localhost:27017/shop";`, "MongoDB URI")
	mustNotFire(t, `mongodb://db1.internal:27017,db2.internal:27017/app?replicaSet=rs0`, "MongoDB URI")
	mustFire(t, cat("mongodb://svc_app:", "Kq7Zt2Lm9Xw4", "@db1.internal:27017,db2.internal:27017/app"), "MongoDB URI")
}

func TestAudit2SQLDriverURI(t *testing.T) {
	mustFire(t, cat("DB=postgresql+psycopg2://app:", "Zt8sQ1xVp3", "@db.internal:5432/app"), "PostgreSQL URI")
	mustFire(t, cat("DB=mysql+pymysql://app:", "Zt8sQ1xVp3", "@db.internal:3306/app"), "MySQL URI")
	mustNotFire(t, "postgresql+psycopg2://app:password@localhost:5432/app", "PostgreSQL URI")
}

func TestAudit2Telegram(t *testing.T) {
	tok := cat("7012345678", ":AAH", rep("dqTcvCH1vGWJxfSeofSAs0K5PALDsaw", 32))
	mustFire(t, `fetch("https://api.telegram.org/bot`+tok+`/sendMessage")`, "Telegram Bot API Token")
	mustFire(t, `TELEGRAM_TOKEN=`+tok+"\n", "Telegram Bot API Token")
	// timestamp:hash (cache key / etag) — bukan token bot
	mustNotFire(t, `t=1712345678:`+rep("9f8e7d6c5b4a3210fedcba", 35), "Telegram Bot API Token")
	// run digit terlalu panjang (bukan bot id)
	mustNotFire(t, "id=123456789012345:"+cat("AAH", rep("dqTcvCH1vGWJxfSeofSAs0K5PALDsaw", 32)), "Telegram Bot API Token")
}

func TestAudit2MailgunMailchimpBoundaries(t *testing.T) {
	mustFire(t, cat(`api:key-`, rep("3ax6xnjp29jd6fds4gc373sgvjxteol0", 32)), "Mailgun Private API Key")
	mustNotFire(t, cat(`monkey-`, rep("3ax6xnjp29jd6fds4gc373sgvjxteol0", 32)), "Mailgun Private API Key")
	mustNotFire(t, cat(`hotkey-`, rep("abcdefghijklmnopqrstuvwxyzabcdef", 32)), "Mailgun Private API Key")
	mustFire(t, cat(`mc_key="`, rep("0a1b2c3d4e5f60718293a4b5c6d7e8f9", 32), `-us12"`), "Mailchimp API Key")
	mustNotFire(t, cat(`x`, rep("0a1b2c3d4e5f60718293a4b5c6d7e8f9", 32), `-us12`), "Mailchimp API Key")
}

func TestAudit2Twitch(t *testing.T) {
	mustFire(t, cat(`PASS oauth:`, rep("k2m9x4q7w1z8c3v6b5n0a2s4d6f8gh", 30)), "Twitch OAuth Token")
	mustNotFire(t, `{oauth:handleOauthCallbackRedirectUri1234,state:s}`, "Twitch OAuth Token")
}

func TestAudit2DiscordBotTokenModern(t *testing.T) {
	tok := cat("O", rep("TAyOTg3NjU0MzIxMDk4NzY1Nz", 25), ".", "GhIjKl", ".", rep("MnOpQrStUvWxYz0123456789ABCD", 38))
	mustFire(t, `DISCORD_TOKEN="`+tok+`"`, "Discord Bot Token")
}

func TestAudit2IdentifierPronePrefixes(t *testing.T) {
	// identifier snake/kebab-case di bundle (dulu HIGH palsu)
	mustNotFire(t, `function re_render_component_header_lifecycle(){}`, "Resend API Key (re_)")
	mustNotFire(t, `<div class="pa-container-wrapper-element-responsive-layout-grid-item-main">`, "Voyage AI API Key (pa-)")
	mustNotFire(t, `x.rnd_seed_value_generator_for_tests_only=1;`, "Render API Key (rnd_)")
	// token asli (acak) tetap terdeteksi
	mustFire(t, cat(`RESEND_API_KEY="re_`, "Ab12Cd34_EfGh56IjKl78MnOp90QrStUv", `"`), "Resend API Key (re_)")
	mustFire(t, cat(`VOYAGE_API_KEY="pa-`, rep("Xk3_Lm9Pq2-Rs7Tv1Wx8Yz4Ab6Cd0Ef5Gh", 50), `"`), "Voyage AI API Key (pa-)")
}

func TestAudit2BasicAuthMustDecode(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("svc-deploy:Zt8sQ1xVp3Lm"))
	mustFire(t, "Authorization: Basic "+good, "Authorization: Basic header")
	mustFire(t, `const h={auth_token:"Basic `+good+`"}`, "Basic Auth Token in code")
	// base64 yang ter-decode menjadi biner (nonce/hash/id acak) — bukan kredensial
	junk := base64.StdEncoding.EncodeToString([]byte{0x9f, 0x12, 0xe3, 0x00, 0x7a, 0xc4, 0x88, 0x01, 0xfe, 0x33, 0x5b, 0xa0, 0x0d, 0x91, 0xee, 0x42})
	mustNotFire(t, "authorization: Basic "+junk, "Authorization: Basic header")
	if basicAuthValid("!!!notbase64!!!") || basicAuthValid(base64.StdEncoding.EncodeToString([]byte{0xff, 0x00, ':', 0x01})) {
		t.Fatal("basicAuthValid menerima nilai biner / bukan base64")
	}
	// Basic base64(UUID) tanpa ':' (kasus nyata binus) tetap diterima
	if !basicAuthValid(base64.StdEncoding.EncodeToString([]byte("EDDA657D-7849-406D-9ED7-33A2D3C57A52"))) {
		t.Fatal("Basic base64(UUID) harus diterima")
	}
	if !basicAuthValid(base64.StdEncoding.EncodeToString([]byte("sk_test_abcdef123456:"))) {
		t.Fatal("basic auth ala API key (password kosong) harus diterima")
	}
}

func TestAudit2SupabaseJWTRole(t *testing.T) {
	hdr := b64u(`{"alg":"HS256","typ":"JWT"}`)
	sig := rep("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", 43)
	svc := hdr + "." + b64u(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"service_role","iat":1700000000,"exp":2000000000}`) + "." + sig
	anon := hdr + "." + b64u(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon","iat":1700000000,"exp":2000000000}`) + "." + sig
	user := hdr + "." + b64u(`{"sub":"1234567890","name":"John"}`) + "." + sig

	if got := sevOf(`createClient(u,"`+svc+`")`, "Supabase Service Role Key (JWT role=service_role)"); got != SevCritical {
		t.Fatalf("service_role JWT (payload diawali iss) harus CRITICAL, got %q; fired=%v", got, patternsFired(svc))
	}
	if got := sevOf(`createClient(u,"`+anon+`")`, "Supabase Anon Key (JWT, public)"); got != SevInfo {
		t.Fatalf("anon JWT harus INFO, got %q", got)
	}
	if got := sevOf(user, "JSON Web Token (JWT)"); got != SevLow {
		t.Fatalf("JWT biasa harus LOW, got %q", got)
	}
	noPublicGlobal = true
	defer func() { noPublicGlobal = false }()
	mustNotFire(t, anon, "Supabase Anon Key")
}

func TestAudit2PlaceholderShortWords(t *testing.T) {
	// kata pendek yang tertanam di token acak BUKAN placeholder (dulu FN)
	for _, s := range []string{
		cat("ghp_x7Nu", "LLk2Qw9Zp3Lm8Rt4Vb6Yc1Xd5Fg0Hj2Ka"),
		cat("AIzaSyA1b2C3d4", "NoNe5f6G7h8I9j0K1l2M3n4O5p"),
		cat("sk_live_51H7s9XTo", "Do2Lm9Pq4Rs7Tv1Wx3Yz5Ab8"),
	} {
		if isPlaceholder(s) {
			t.Fatalf("token acak %q dianggap placeholder", s)
		}
	}
	for _, s := range []string{cat("sk_live_", "none"), "TODO-replace-me-later", cat("api_key=", "null"), "asdf-asdf-asdf"} {
		if !isPlaceholder(s) {
			t.Fatalf("placeholder %q lolos", s)
		}
	}
}

func TestAudit2SquareSplit(t *testing.T) {
	sec := cat("sq0csp-", rep("Xk3_Lm9Pq2-Rs7Tv1Wx8Yz4Ab6Cd0Ef5Gh", 43))
	if got := sevOf(`SQUARE_SECRET="`+sec+`"`, "Square OAuth Client Secret (sq0csp-)"); got != SevHigh {
		t.Fatalf("sq0csp- harus HIGH, got %q", got)
	}
	if got := sevOf(cat(`appId:"sq0idp-`, rep("AbCdEfGhIjKlMnOpQrSt12", 22), `"`), "Square Application ID (sq0idp-)"); got != SevLow {
		t.Fatalf("sq0idp- harus LOW, got %q", got)
	}
}

func TestAudit2SeverityIdentifiers(t *testing.T) {
	cases := []struct{ content, pattern, sev string }{
		{cat("sid=AC", rep("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", 32)), "Twilio Account SID", SevLow},
		{cat("app_sid=AP", rep("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", 32)), "Twilio App SID", SevLow},
		{cat("dsn=https://", rep("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", 32), "@o123456.ingest.us.sentry.io/1234567"), "Sentry DSN", SevLow},
		{`{"type": "service_account", "project_id": "x"}`, "Google Cloud Service Account (type field)", SevMedium},
		{`gsa="deployer-sa@my-project-123.iam.gserviceaccount.com"`, "GCP Service Account Email", SevLow},
	}
	for _, c := range cases {
		if got := sevOf(c.content, c.pattern); got != c.sev {
			t.Fatalf("%s: severity %q, want %q (fired=%v)", c.pattern, got, c.sev, patternsFired(c.content))
		}
	}
}

// isBase64Slice: hanya RUN base64 kontigu panjang di kanan yang menandai
// potongan blob; teks biasa setelah '/' tidak boleh membuang token.
func TestAudit2Base64SliceContiguous(t *testing.T) {
	gh := cat("gh", "p_", rep("Hk2Lm9Pq4Rs7Tv1Wx3Yz5", 36))
	content := `fetch("https://cdn.example.com/` + gh + `/sendMessage");` + "\n" +
		`hook="https://discord.com/api/webhooks/199007541669397831/` + rep("gEzUSdT4C-O9-nkybHERjDFLXgzZ2Fp85PEeb5VEi", 68) + `";`
	mustFire(t, content, "GitHub Personal Access Token (ghp_)")
	// blob base64 panjang yang kebetulan memuat prefix tetap ditolak
	blob := rep("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo", 40) + gh + rep("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo", 90)
	mustNotFire(t, `src="data:font/woff2;base64,`+blob+`"`, "GitHub Personal Access Token (ghp_)")
}

// Guard: daftar map nama pola harus merujuk ke pola yang benar-benar ada
// (salah ketik nama = guard diam-diam tidak aktif).
func TestAudit2GuardMapsReferenceRealPatterns(t *testing.T) {
	names := map[string]bool{}
	for _, p := range patterns {
		names[p.Name] = true
	}
	for label, m := range map[string]map[string]bool{
		"standaloneTokenPatterns": standaloneTokenPatterns,
		"identifierPronePatterns": identifierPronePatterns,
		"publicByDesign":          publicByDesign,
		"humanCredPatterns":       humanCredPatterns,
		"genericPatterns":         genericPatterns,
		"basicAuthPatterns":       basicAuthPatterns,
	} {
		for n := range m {
			if !names[n] && !strings.HasPrefix(n, "JWT") {
				t.Errorf("%s merujuk pola yang tidak ada: %q", label, n)
			}
		}
	}
}
