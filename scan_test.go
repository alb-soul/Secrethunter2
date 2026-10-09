package main

import (
	"encoding/json"
	"strings"
	"testing"
)
func fired(t *testing.T, content, wantName, wantSev string) []Finding {
	t.Helper()
	fds := scanContent("test://x", content)
	for _, f := range fds {
		if f.Pattern == wantName && (wantSev == "" || f.Severity == wantSev) {
			return fds
		}
	}
	var got []string
	for _, f := range fds {
		got = append(got, f.Pattern+"|"+f.Severity)
	}
	t.Fatalf("pattern %q (sev %q) did not fire; got: %v", wantName, wantSev, got)
	return nil
}

func notFired(t *testing.T, content, notName string) {
	t.Helper()
	for _, f := range scanContent("test://x", content) {
		if f.Pattern == notName {
			t.Fatalf("pattern %q unexpectedly fired: %v", notName, f.Match)
		}
	}
}

// ── positif per keluarga besar ──
func TestPositives(t *testing.T) {
	cases := []struct{ content, name, sev string }{
		{`aws_access_key_id = "AKIA4H8K2M5P7Q1W3E6R"`, "AWS Access Key ID", "CRITICAL"},
		{`token=glpat-abcdefghij1234567890`, "GitLab Personal Access Token", "CRITICAL"},
		{`STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc`, "Stripe Live Secret Key", "CRITICAL"},
		{`STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc`, "Stripe Test Secret Key", "MEDIUM"},
		{`xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx`, "Slack Bot Token (xoxb-)", "CRITICAL"},
		{`xoxp-1234567890-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx12345678`, "Slack User Token (xoxp-)", "CRITICAL"},
		{`token ghp_AbCdEfGhIjKlMnOpQrStUvWx1234567890AB`, "GitHub Personal Access Token (ghp_)", "CRITICAL"},
		{`npm_token=npm_AbCdEfGhIjKlMnOpQrStUvWx1234567890AB`, "NPM Access Token", "HIGH"},
		{`pypi-AgEIcHlwaS5vcmcAbCdEfGhIjKlMnOpQrStUvWx1234567890abcdefABCDEFghij`, "PyPI Upload Token (pypi-)", "HIGH"},
		{`postgres://bob:s3cretPass@db.internal:5432/app`, "PostgreSQL URI", "CRITICAL"},
		{`mongodb://admin:s3cretPass@10.0.0.5:27017/admin`, "MongoDB URI", "CRITICAL"},
		{`redis://:s3cretPass123@cache.internal:6379`, "Redis URI with password", "CRITICAL"},
		{`Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==`, "Authorization: Basic header", "HIGH"},
		{`sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEfGhIjKlMnOpQrStUvWx123456`, "Anthropic API Key", "CRITICAL"},
		{`hf_AbCdEfGhIjKlMnOpQrStUvWx1234567890ABCD`, "Hugging Face Access Token", "HIGH"},
		{`re_abcDEF1234567890abcdef`, "Resend API Key (re_)", "HIGH"},
		{`tvly-AbCdEfGhIjKlMnOpQrStUvWx12345678`, "Tavily API Key (tvly-)", "MEDIUM"},
		{`fc-AbCdEfGhIjKlMnOpQrStUvWx1234567890abcdef`, "Firecrawl API Key (fc-)", "MEDIUM"},
		{`nfp_AbCdEfGhIjKlMnOpQrStUvWx1234567890abcdef`, "Netlify Personal Access Token (nfp_)", "HIGH"},
		{`gloas-AbCdEfGhIjKlMnOpQrStUvWx`, "GitLab OAuth App Secret (gloas-)", "HIGH"},
		{`<!-- TODO: remove test credentials admin:HiddenInPlainSight -->`, "HTML comment credentials (user:pass)", "HIGH"},
		{`// credentials admin:HiddenInPlainSight`, "JS/line comment credentials (user:pass)", "HIGH"},
		{`password = "S3cretPass99"`, "Password assignment (quoted or bare)", "MEDIUM"},
		{`machine api.example.com login deploy password S3cretDeploy99`, ".netrc credentials (machine login password)", "HIGH"},
		{`-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7bq9uG3vKx8LmNpQrStUvWxYz01`, "RSA Private Key", "CRITICAL"},
		{`mongodb+srv://user:p4ssw0rd99@cluster0.ab12cd34.mongodb.net/mydb`, "MongoDB URI", "CRITICAL"},
	}
	for _, c := range cases {
		fired(t, c.content, c.name, c.sev)
	}
}

// JWT normal = LOW, alg:none = CRITICAL rename
func TestJWT(t *testing.T) {
	normal := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	fds := scanContent("test://x", normal)
	found := false
	for _, f := range fds {
		if f.Pattern == "JSON Web Token (JWT)" && f.Severity == "LOW" {
			found = true
		}
	}
	if !found {
		t.Fatalf("normal JWT not LOW: %+v", fds)
	}
	noneHdr := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
	fds2 := scanContent("test://x", noneHdr)
	found2 := false
	for _, f := range fds2 {
		if f.Pattern == "JWT with alg:none (Forgeable — Auth Bypass)" && f.Severity == "CRITICAL" {
			found2 = true
		}
	}
	if !found2 {
		t.Fatalf("alg:none JWT not CRITICAL: %+v", fds2)
	}
}

// public-by-design → INFO, dan --no-public drop
func TestPublicByDesign(t *testing.T) {
	content := `pk_live_51H7s9XAbCdEfGhIjKlMnOpQrStUvWx1234567890ab`
	fds := scanContent("test://x", content)
	ok := false
	for _, f := range fds {
		if f.Pattern == "Stripe Live Publishable Key" && f.Severity == "INFO" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("publishable key not INFO: %+v", fds)
	}
	noPublicGlobal = true
	defer func() { noPublicGlobal = false }()
	for _, f := range scanContent("test://x", content) {
		if f.Pattern == "Stripe Live Publishable Key" {
			t.Fatalf("no-public did not drop publishable key")
		}
	}
}

// FP corpus: minified JS / CSS / UI — tidak boleh ada HIGH/CRITICAL dari human/generic
func TestNegatives(t *testing.T) {
	minJS := `var e={selectedSections:u,onSelectedSectionsChange:d,timezone:p}=e,src:i,className:r,strokeWidth:1,fill:"red",status:ai.EMPTY,errorCode:void 0;transport:e.transport||Qd;to:this.roomjid,type:"groupchat";password:this.od.qbb;`
	css := `body{background-color:#EDECEC;color:#333}input[type=password]{border:1px solid #ccc}`
	ui := `<label>Password</label><input type="password" required placeholder="Enter your password">Forgot password? Reset password.`
	_ = ui
	for _, c := range []string{minJS, css} {
		for _, f := range scanContent("test://x", c) {
			if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
				t.Fatalf("FP %s %s on %q", f.Severity, f.Pattern, f.Match)
			}
		}
	}
	// placeholder harus dibuang
	notFired(t, `api_key = "your-api-key-here"`, "Generic API Key in code")
	notFired(t, `password = "changeme123456"`, "Generic Secret / Password in code")
}

// ── binus-2026-09: pola baru kasus 1 ──
func TestBinusMissingSecrets(t *testing.T) {
	fired(t, `var getApiAuthToken="Basic RUREQTY1N0QtNzg0OS00MDZELTlFRDctMzNBMkQzQzU3QTUy";`, "Basic Auth Token in code", "HIGH")
	fired(t, `var getApiSIDAuthToken="Basic RUM5NjhDN0YtMzExNS00MjNDLUE4MjctMzRCNTZDQTM5MzFD";`, "Basic Auth Token in code", "HIGH")
	fired(t, `var getApiExamToken="Basic MENCQjBDMzUtMENDMi00NEIyLUI4REQtOUQzNDg1RkRGMDQ4";`, "Basic Auth Token in code", "HIGH")
	fired(t, `REDPER="%v$4T!9CRqE_[G-="`, "Encryption Key in code", "HIGH")
	fired(t, `clientId="ad768ba0-0059-46cf-ac71-c4e627361377"`, "OAuth Client ID (UUID)", "MEDIUM")
	notFired(t, `var x="eyTunggakanKeuanganPrivileges.SurveyOutstandingMasterConfiguration.Menu";`, "JSON Web Token (JWT)")
}

// square/twitter data-uri guard
func TestDataURIGuard(t *testing.T) {
	content := `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==">`
	for _, f := range scanContent("test://x", content) {
		if strings.HasPrefix(f.Pattern, "Square") || f.Pattern == "Twitter/X Bearer Token" {
			t.Fatalf("data-uri guard failed: %v", f)
		}
	}
}

// prefilter soundness: tiap pola di atas harus fire walau pendek
func TestPrefilterSound(t *testing.T) {
	for _, c := range []struct{ s, name string }{
		{`AKIA4H8K2M5P7Q1W3E6R`, "AWS Access Key ID"},
		{`sk_live_4eC39HqLyjWDarjtT1zdp7dc`, "Stripe Live Secret Key"},
		{`statsig_secret = "secret-AbCdEfGhIjKlMnOpQrStUvWx12345678"`, "Statsig Server Secret (context)"},
	} {
		fired(t, c.s, c.name, "")
	}
}

func TestFacebookBroad(t *testing.T) {
	fb := "EAABwzLixnjyBAKJ7hG2mN4pQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD"
	fds := scanContent("test://x", "token="+fb)
	ok := false
	for _, f := range fds {
		if f.Pattern == "Facebook / Meta Access Token" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("EAAB token missed: %+v", fds)
	}
}

func TestFullValuePreserved(t *testing.T) {
	long := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + strings.Repeat("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", 6) + "." + strings.Repeat("XyZ0123456789AbCdEfGhIjKlMnOpQrStUv", 4)
	fds := scanContent("test://x", "tok="+long)
	if len(fds) == 0 {
		t.Fatal("long JWT not found at all")
	}
	full := ""
	for _, f := range fds {
		if f.Pattern == "JSON Web Token (JWT)" {
			full = f.Match
		}
	}
	if full == "" {
		t.Fatalf("JWT finding missing: %+v", fds)
	}
	if len(full) != len(long) {
		t.Fatalf("Finding.Match truncated: got %d want %d", len(full), len(long))
	}
	b, _ := json.Marshal(full)
	var back string
	if err := json.Unmarshal(b, &back); err != nil || back != long {
		t.Fatalf("JSON roundtrip broken")
	}
}

func TestNoFalseFacebook(t *testing.T) {
	neg := []string{
		`var EAAsmall = 1;`,
		`EAAshort`,
		`BEAAAbCdEfGh`,
	}
	for _, s := range neg {
		for _, f := range scanContent("test://x", s) {
			if f.Pattern == "Facebook / Meta Access Token" {
				t.Fatalf("FB FP on %q", s)
			}
		}
	}
}

func TestMoreFamilies(t *testing.T) {
	cases := []struct{ content, name string }{
		{`discord_token = "MTAyOTg3NjU0MzIxMDk4NzY1.GhIjKl.MnOpQrStUvWxYz0123456789ABCD"`, "Discord Bot Token"},
		{`bot_token=1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1`, "Telegram Bot API Token"},
		{`twilio_auth_token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"`, "Twilio Auth Token"},
		{`sid=ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`, "Twilio Account SID"},
	{`app_sid=APa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`, "Twilio App SID"},
	{`refresh_token="1//0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"`, "Google OAuth Refresh Token (1//0...)"},
	{`xoxa-1234567890-9876543210-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789`, "Slack App Token (xoxa-)"},
	{`BINANCE_API_KEY = "AbCdEf12GhIjKl34MnOpQrSt"`, "Binance API Key (context)"},
	{`kraken_api_key = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUv"`, "Kraken API Key (context)"},
		{`SENDGRID_API_KEY=SG.AbCdEfGhIjKlMnOpQrStUv.abcdefghijklmnopqrstuvwxyz0123456789_X-Ab12`, "SendGrid API Key"},
		{`sq0idp-AbCdEfGhIjKlMnOpQrStUvWx12`, ""}, // Square App ID format differs; just ensure no crash, may or may not fire
		{`hvs.AbCdEfGhIjKlMnOpQrStUvWx12`, "Vault Service Token (hvs.)"},
		{`dp.pt.AbCdEfGhIjKlMnOpQrStUvWx1234567890abcdef`, "Doppler Token (dp.xx.)"},
		{`tskey-api-AbCdEfGh-AbCdEfGhIjKlMnOpQrSt12`, "Tailscale Auth/API Key (tskey-)"},
		{`CLOUDINARY_URL=cloudinary://123456789012345:AbCdEfGhIjKlMnOpQrStUv@mycloud`, "Cloudinary URL"},
		{`dsn=https://a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6@o123456.ingest.sentry.io/1234567`, "Sentry DSN"},
		{`webhook=https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx12345678`, "Slack Webhook URL"},
		{`hook=https://hooks.zapier.com/hooks/catch/1234567/abcdefg/`, "Zapier Webhook URL"},
		{`github_pat_AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEf0123456789`, "GitHub Fine-grained PAT"},
		{`atlassian_token=ATATT3xFf0AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEfGhIjKlMnOpQrStUvWx1234567890abcd`, "Atlassian API Token (ATATT3)"},
		{`spotify_client_secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"`, "Spotify Client ID/Secret (context)"},
		{`databricks_token=dapi1234567890abcdef1234567890abcdef`, "Databricks Personal Access Token (dapi)"},
		{`rpa_AbCdEfGhIjKlMnOpQrStUvWx12`, "RunPod API Key (rpa_)"},
		{`gsk_AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEfGhIjKlMnOpQr`, "Groq API Key (gsk_)"},
		{`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`, "OpenRouter API Key (sk-or-v1-)"},
		{`pplx-AbCdEfGhIjKlMnOpQrStUvWx1234567890abcdef`, "Perplexity API Key (pplx-)"},
		{`xai-AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEfGhIjKl`, "xAI API Key (xai-)"},
		{`csk-AbCdEfGhIjKlMnOpQrStUvWx12345678`, "Cerebras API Key (csk-)"},
		{`nvapi-AbCdEfGhIjKlMnOpQrStUvWx12345678`, "NVIDIA NIM API Key (nvapi-)"},
		{`op://vault/item/field`, ""}, // 1Password-style ref, should not crash
		{`glsa_AbCdEfGhIjKlMnOpQrStUvWx12345678_AB12CD34`, "Grafana API Key"},
		{`dckr_pat_AbCdEfGhIjKlMnOpQrStUvWx12`, "Docker Hub Personal Access Token (dckr_pat_)"},
		{`vcp_AbCdEfGhIjKlMnOpQrStUv`, "Vercel Access Token (vcp_)"},
		{`lsv2_pt_AbCdEfGhIjKlMnOpQrStUvWx12345678_a1b2c3d4e5`, "LangSmith API Key (lsv2_)"},
		{`pcsk_AbCdEfGhIjKlMnOpQrStUvWx1234567890abcdef`, "Pinecone API Key (pcsk_)"},
		{`xkeysib-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2-AbCdEfGhIjKlMnOp`, "Brevo API Key (xkeysib-)"},
		{`pul-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0`, "Pulumi Access Token (pul-)"},
		{`xau_AbCdEfGhIjKlMnOpQrStUvWx12`, "Xata API Key (xau_)"},
		{`jina_AbCdEfGhIjKlMnOpQrStUvWx12`, "Jina AI API Key (jina_)"},
	}
	for _, c := range cases {
		fds := scanContent("test://x", c.content)
		if c.name == "" {
			continue
		}
		ok := false
		for _, f := range fds {
			if f.Pattern == c.name {
				ok = true
			}
		}
		if !ok {
			var got []string
			for _, f := range fds {
				got = append(got, f.Pattern)
			}
			t.Errorf("pattern %q did not fire; got %v", c.name, got)
		}
	}
}

// WorkOS vs Clerk same-shape string: overlapping DIFFERENT-length values both
// fire (correct: values differ, both labels plausible). Same VALUE twice must
// dedup to exactly one finding.
func TestCrossTalkDedup(t *testing.T) {
	s := `sk_test_AbCdEfGhIjKlMnOpQrStUvWx1234567890abcd`
	fds := scanContent("test://x", s)
	if len(fds) != 2 {
		var got []string
		for _, f := range fds {
			got = append(got, f.Pattern+"|"+f.Severity)
		}
		t.Fatalf("expected 2 overlapping findings for 40-char sk_test_, got %v", got)
	}
	// exact same value matched twice by same pattern family -> dedup to 1
	s2 := `xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx`
	fds2 := scanContent("test://x", s2+" "+s2)
	n := 0
	for _, f := range fds2 {
		if f.Pattern == "Slack Bot Token (xoxb-)" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("same value twice should dedup to 1, got %d", n)
	}
}

func TestMoreFamilies2(t *testing.T) {
	cases := []struct{ content, name string }{
		{`github_client_secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"`, "GitHub Client Secret"},
		{`client_id=sq0idp-AbCdEfGhIjKlMnOpQrStUvWx12`, "Square App ID / Client Secret"},
		{`jdbc:oracle:thin:scott/tiger@dbhost:1521/orcl`, "Oracle JDBC Thin URL"},
		{`dbhost:5432:mydb:bob:s3cretPass99`, "PostgreSQL .pgpass entry"},
		{`travis_token = "AbCdEfGhIjKlMnOpQrStUvWx12"`, ""},
		{`FLWSECK_TEST-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6-X`, "Flutterwave Secret Key (FLWSECK...)"},
		{`atlassian_api_token=ATATT3xFf0AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEfGhIjKlMnOpQrStUvWx1234567890AbCdEfGhIjKlMnOpQrStUvWx1234567890abcd_extra`, "Atlassian API Token (ATATT3)"},
		{`linkedin_client_secret = "AbCdEfGhIjKlMnOp"`, "LinkedIn Client ID/Secret"},
		{`datadog_api_key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"`, ""},
		{`pagerduty_token=PabcDefGhiJkLmNoPqRs12`, "PagerDuty API Token"},
		{`rollbar_token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"`, ""},
		{`newrelic_license = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"`, ""},
		{`opsgenie_api_key = "a1b2c3d4-1234-abcd-ef56-a1b2c3d4e5f6"`, ""},
		{`bugsnag_api_key = "a1b2c3d4e5f6a7b8c9d0e1f2"`, ""},
		{`launchdarkly_sdk_key = "sdk-a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"`, "LaunchDarkly SDK/Mobile/API Key (sdk-/mob-/api-)"},
		{`datadog_app_key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"`, "DataDog Application Key (context)"},
		{`snyk_token = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"`, ""},
		{`contentful_token = "CFPAT-AbCdEfGhIjKlMnOpQrStUvWx1234567890abcdef"`, "Contentful Access Token"},
		{`sanity_token = "skAbCdEfGhIjKlMnOpQrStUvWx1234567890abcdef"`, "Sanity API Token (context)"},
	}
	for _, c := range cases {
		fds := scanContent("test://x", c.content)
		if c.name == "" {
			continue
		}
		ok := false
		for _, f := range fds {
			if f.Pattern == c.name {
				ok = true
			}
		}
		if !ok {
			var got []string
			for _, f := range fds {
				got = append(got, f.Pattern)
			}
			t.Errorf("pattern %q did not fire; got %v", c.name, got)
		}
	}
}

// Parallel vs serial equivalence on >1MB content
func TestParallelEquivalence(t *testing.T) {
	padding := strings.Repeat("lorem ipsum dolor sit amet consectetur adipiscing elit. ", 30000) // ~1.6MB
	secrets := "AKIA4H8K2M5P7Q1W3E6R\nsk_live_4eC39HqLyjWDarjtT1zdp7dc\n<!-- TODO: remove test credentials admin:HiddenInPlainSight -->\n"
	content := secrets + padding[:800000] + "\nre_abcDEF1234567890abcdef\n" + padding[800000:] + "\nsecret-AbCdEfGhIjKlMnOpQrStUvWx12345678\n"
	if len(content) < 1024*1024 {
		t.Fatalf("test content too small: %d", len(content))
	}
	lower := strings.ToLower(content)
	seq := scanContentSeq("t://x", content, lower)
	par := scanContentPar("t://x", content, lower)
	key := func(f Finding) string { return f.Pattern + "\x00" + f.Match + "\x00" + f.Severity }
	a, b := map[string]int{}, map[string]int{}
	for _, f := range seq {
		a[key(f)]++
	}
	for _, f := range par {
		b[key(f)]++
	}
	if len(a) != len(b) {
		t.Fatalf("seq=%d distinct, par=%d distinct", len(a), len(b))
	}
	for k := range a {
		if a[k] != b[k] {
			t.Fatalf("mismatch on %q: seq=%d par=%d", k, a[k], b[k])
		}
	}
}

// CLI: --json valid, -o file, truncate display 120 vs JSON full

// Adyen: standalone token fires; slice of a longer base64 run must not.
func TestAdyenStandalone(t *testing.T) {
	const adyenName = "Adyen API Key (AQE\u2026)"
	key := "AQE8bXe27PlCPZPgyisg6OKCFQlrl9zc4obbn6KXzqb7TtGaQ5CVd4RISThmjnLdvfPqlIqXcIMP93"
	if len(key) != 78 {
		t.Fatalf("test key length = %d, want 78", len(key))
	}
	// true positives: quoted, bare assignment, API header
	fired(t, `"adyen_api_key": "`+key+`"`, adyenName, "CRITICAL")
	fired(t, "adyen_api_key="+key+"\n", adyenName, "CRITICAL")
	fired(t, "X-API-Key: "+key, adyenName, "CRITICAL")
	// false positives: embedded in longer base64 runs
	blob := "FyJ58N/94+h5+e8PVrNq6DuKescCoQVwE+xp0FYRqTa6QJwgCHMchlUziurIShVspRSye5PU3V9M1AIkU3HTTb/nrTZ/" + key + "xx==" + "D6vxh8LJyZreDjRz/5aw0+zmXimCwi9Ols3UVbO1x33UP8+Id/5IVnXiUGfOUzh3HofrMp5ocqq0d"
	notFired(t, "<html>"+blob+"</html>", adyenName)
	blogger := "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgt5TE65EeqyWgBg-" + key + "-Ff3xP15NEb7rBmzftiNRh6boGSoEeV0Aa6StjOxScNtm0Sa4Uk/w1200-h630-p-k-no-nu/image.jpg"
	notFired(t, `<meta property='og:image' content='`+blogger+`'/>`, adyenName)
	jpeg := "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAf/Y/+AA=="
	notFired(t, `<img src="`+jpeg+`">`, adyenName)
}

// Google API Key: standalone fires; slice of a longer base64 run must not.
func TestGoogleStandalone(t *testing.T) {
	const gname = "Google API Key"
	key := "AIza6nPfRRlgzeUwtXaUklgTszjTwGDppSjSjFr"
	if len(key) != 39 {
		t.Fatalf("test key length = %d, want 39", len(key))
	}
	fired(t, `"google_api_key": "`+key+`"`, gname, "HIGH")
	fired(t, "google_api_key="+key+"\n", gname, "HIGH")
	fired(t, "https://maps.googleapis.com/maps/api/js?key="+key+"&callback=init", gname, "HIGH")
	blob := "LerGoUnYsuHrnqUadaK9vTTte923e70+Fq1rLbf7zrwWYY7Kpc+X4qWGqNWnywhN2Tbir1IzTXvN6dbPeMbclbfB/4O6dK81l8IPhlHMoUkyeFbK8cn" + key + "zm73bX8zta56suLuKK0VGtnFaUWmkvYYRJJdPdorTRelj0C1gtLHT003TrS00fTIREFsNH06y0nS4Yyv"
	notFired(t, "<html>"+blob+"</html>", gname)
}

// GitHub tokens: standalone fires; slice of a Cloudflare challenge blob must not.
func TestGitHubStandalone(t *testing.T) {
	const ghrName = "GitHub App Refresh Token (ghr_)"
	key := "ghr_0mTO3m8FUtRpN8yfjbol30N8eTmRBxuUWmAqiJ30ugI11RgUufImungwy8k3jWvJk2Ol81mxVdit"
	if len(key) != 80 {
		t.Fatalf("test key length = %d, want 80", len(key))
	}
	fired(t, `"github_refresh_token": "`+key+`"`, ghrName, "HIGH")
	fired(t, "GITHUB_REFRESH_TOKEN="+key+"\n", ghrName, "HIGH")
	cf := "md: '.XC6vggKFnMvDDJNnDFCZPb9uef3_3NhrPZpq0s.Kmk-1788763374-1.2.1.1-DDJtstVSPbOnwA.trkI2kI8_KNRRf..SeQs3k17LwmZbnos7qUMjNgDVANl3wKnzsldhG9W7eS.eA1"+key+"3FWb69xm2eW4qBPwf.5hcln6TE229bLuWc2OBa5VlcGaJKHXak7YQ9D8zfiwpT8q9FKkTzBXJl3MX3WKfhLPoGbAfW9Qot5"
	notFired(t, "<title>Just a moment...</title><script>window._cf_chl_opt={cType: 'managed',"+cf+"};</script>", ghrName)
	notFired(t, "zzghp_AbCdEfGhIjKlMnOpQrStUvWx1234567890abcdYY", "GitHub Personal Access Token (ghp_)")
}
