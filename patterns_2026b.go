package main

import "regexp"

// ============================================================
// patterns_2026b.go — coverage tambahan audit 2026-11b
//
// Kriteria masuk: (1) format/prefix terdokumentasi atau dipakai scanner rujukan
// (gitleaks/trufflehog) dengan struktur khas, (2) umum bocor di target bug
// bounty (bundle JS, config, response API, CI log), (3) punya test positif DAN
// negatif di audit2_coverage_test.go. Token tanpa prefix khas WAJIB konteks.
//
// Di-append ke `patterns` di init() main.go setelah extraPatterns, jadi bila
// nilai yang sama juga ditangkap pola lama yang spesifik, pola lama menang
// (dedupeOverlapping: urutan deklarasi), sedangkan terhadap pola generik pola
// di sini yang menang.
// ============================================================

var coveragePatterns2026b = []Pattern{

	// ─── AI / LLM ────────────────────────────────────────────────────────────
	{
		// Claude Code / Console OAuth access & refresh token.
		Name:     "Anthropic OAuth Token (sk-ant-oat01-/ort01-)",
		Regex:    regexp.MustCompile(`\bsk-ant-(?:oat|ort)01-[A-Za-z0-9_\-]{80,120}`),
		Severity: SevCritical,
	},
	{
		Name:     "OpenAI Admin Key (sk-admin-)",
		Regex:    regexp.MustCompile(`\bsk-admin-[A-Za-z0-9_\-]{80,200}`),
		Severity: SevCritical,
	},
	{
		Name:     "Hugging Face Org Token (api_org_)",
		Regex:    regexp.MustCompile(`\bapi_org_[A-Za-z]{34}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Prefect API Key (pnu_)",
		Regex:    regexp.MustCompile(`\bpnu_[A-Za-z0-9]{36}\b`),
		Severity: SevHigh,
	},

	// ─── Cloud ───────────────────────────────────────────────────────────────
	{
		// SDK v3 / Amplify config tanpa prefix "aws": {secretAccessKey:"…"}.
		Name:       "AWS Secret Access Key (secretAccessKey)",
		Regex:      regexp.MustCompile(`(?i)\bsecret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})(?:["'\s,;}\]]|$)`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		// API key GraphQL AppSync — sering di bundle Amplify (aws-exports.js).
		Name:     "AWS AppSync API Key (da2-)",
		Regex:    regexp.MustCompile(`\bda2-[a-z0-9]{26}\b`),
		Severity: SevMedium,
	},
	{
		// Client secret Entra ID / Azure AD format baru: 3 char + digit + "Q~".
		Name:       "Azure AD Client Secret (Q~)",
		Regex:      regexp.MustCompile(`(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.\-]{31,34})(?:$|[\\'"\x60\s<),])`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:     "Azure Service Bus / Event Hub Connection String",
		Regex:    regexp.MustCompile(`Endpoint=sb://[A-Za-z0-9.\-]+/?;SharedAccessKeyName=[^;"'\s]+;SharedAccessKey=[A-Za-z0-9+/=]{43,44}`),
		Severity: SevCritical,
	},
	{
		Name:     "Azure Cosmos DB Connection String",
		Regex:    regexp.MustCompile(`AccountEndpoint=https://[A-Za-z0-9.\-]+(?::\d+)?/?;AccountKey=[A-Za-z0-9+/=]{86,88}`),
		Severity: SevCritical,
	},
	{
		// API Management subscription key — sering di bundle SPA (header Ocp-Apim-*).
		Name:       "Azure APIM Subscription Key (context)",
		Regex:      regexp.MustCompile(`(?i)ocp-apim-subscription-key["']?\s*[:=,]\s*["']([0-9a-f]{32})["']`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		// Logic App / Power Automate HTTP trigger: URL ber-sig = kredensial pemicu.
		Name:     "Azure Logic App / Power Automate Webhook (sig)",
		Regex:    regexp.MustCompile(`https://[a-z0-9\-]+\.[a-z0-9\-]+\.logic\.azure\.com(?::443)?/workflows/[0-9a-f]{32}/triggers/[^\s"'<>]{1,200}?sig=[A-Za-z0-9_\-%]{40,}`),
		Severity: SevHigh,
	},
	{
		// objek JSON service account lengkap (bisa langsung `gcloud auth`).
		Name:     "Google Cloud Service Account JSON (with private key)",
		Regex:    regexp.MustCompile(`"type"\s*:\s*"service_account"[\s\S]{0,600}?"private_key"\s*:\s*"-----BEGIN`),
		Severity: SevCritical,
	},
	{
		// API token Cloudflare format "scannable" (prefix + checksum).
		Name:     "Cloudflare API Token (cfut_/cfat_/cfk_)",
		Regex:    regexp.MustCompile(`\bcf(?:ut|at|k)_[A-Za-z0-9]{40,60}\b`),
		Severity: SevCritical,
	},
	{
		Name:     "Heroku API Key v2 (HRKU-)",
		Regex:    regexp.MustCompile(`\bHRKU-AA[0-9A-Za-z_\-]{58}\b`),
		Severity: SevCritical,
	},

	// ─── CI/CD / developer platform ──────────────────────────────────────────
	{
		Name:     "GitLab Runner Authentication Token (glrt-)",
		Regex:    regexp.MustCompile(`\bglrt-(?:t\d_)?[0-9A-Za-z_\-]{20,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "GitLab Agent Token (glagent-)",
		Regex:    regexp.MustCompile(`\bglagent-[0-9A-Za-z_\-]{50}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "CircleCI Personal API Token (CCIPAT_)",
		Regex:    regexp.MustCompile(`\bCCIPAT_[A-Za-z0-9]{22}_[a-f0-9]{40}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Buildkite User Access Token (bkua_)",
		Regex:    regexp.MustCompile(`\bbkua_[a-f0-9]{40}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Docker Hub Organization Access Token (dckr_oat_)",
		Regex:    regexp.MustCompile(`\bdckr_oat_[A-Za-z0-9_\-]{30,64}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Contentful Personal Access Token (CFPAT-)",
		Regex:    regexp.MustCompile(`\bCFPAT-[A-Za-z0-9_\-]{43}\b`),
		Severity: SevHigh,
	},
	{
		// .npmrc lama: _auth = base64(user:pass) (divalidasi decode → teks).
		Name:       "npm legacy _auth (base64 user:pass)",
		Regex:      regexp.MustCompile(`(?m)(?:^|[\s;])(?://[^\s=]+:)?_auth\s*=\s*["']?([A-Za-z0-9+/]{12,}={0,2})["']?(?:\s|$)`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		// ~/.docker/config.json: {"auths":{"registry":{"auth":"base64(user:pass)"}}}
		Name:       "Docker config.json auth (base64)",
		Regex:      regexp.MustCompile(`"auths"\s*:\s*\{[\s\S]{0,300}?"auth"\s*:\s*"([A-Za-z0-9+/]{12,}={0,2})"`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Kafka SASL JAAS password",
		Regex:      regexp.MustCompile(`(?i)org\.apache\.kafka\.common\.security\.(?:plain|scram)\.\w+LoginModule\s+required\s+username\s*=\s*\\?"[^"\\]+\\?"\s+password\s*=\s*\\?"([^"\\]{4,})\\?"`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		// password di query/properti JDBC (mysql, postgresql, sqlserver, …).
		Name:       "JDBC URL with password",
		Regex:      regexp.MustCompile(`jdbc:(?:mysql|mariadb|postgresql|sqlserver|db2|redshift|snowflake|clickhouse|oracle:thin)[^\s"'<>]{0,200}?[?;&](?:password|pwd)=([^&;\s"'<>]{4,})`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},

	// ─── Payments ────────────────────────────────────────────────────────────
	{
		// access token OAuth PayPal (client_credentials) — Bearer A21AA…
		Name:     "PayPal OAuth Access Token (A21AA)",
		Regex:    regexp.MustCompile(`\bA21AA[A-Za-z0-9_\-]{80,120}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Plaid Access Token",
		Regex:    regexp.MustCompile(`\baccess-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
		Severity: SevHigh,
	},
	{
		// Storefront API = publik by design (dipakai di browser) → INFO via publicByDesign.
		Name:       "Shopify Storefront Access Token (context, public)",
		Regex:      regexp.MustCompile(`(?i)(?:x-shopify-storefront-access-token|storefront[_\-]?access[_\-]?token)["']?\s*[:=,]\s*["']([0-9a-f]{32})["']`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
	{
		Name:       "Algolia Admin API Key (context)",
		Regex:      regexp.MustCompile(`(?i)algolia[^\n]{0,40}?admin[_\-\s]*(?:api[_\-\s]*)?key["']?\s*[:=]\s*["']?([a-f0-9]{32})["']?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},

	// ─── Messaging / webhooks ────────────────────────────────────────────────
	{
		Name:     "Slack Workflow / Trigger Webhook",
		Regex:    regexp.MustCompile(`https://hooks\.slack\.com/(?:workflows|triggers)/T[0-9A-Z]{8,12}/(?:[0-9A-Za-z]+/){1,2}[0-9A-Za-z]{20,}`),
		Severity: SevHigh,
	},
	{
		Name:     "Google Chat Webhook",
		Regex:    regexp.MustCompile(`https://chat\.googleapis\.com/v1/spaces/[A-Za-z0-9_\-]+/messages\?key=AIza[0-9A-Za-z_\-]{35}&token=[A-Za-z0-9_\-%=]{20,}`),
		Severity: SevHigh,
	},
	{
		Name:       "IFTTT Webhook Key",
		Regex:      regexp.MustCompile(`https://maker\.ifttt\.com/(?:trigger/[^/\s"']+/(?:json/)?with/key|use)/([A-Za-z0-9_\-]{22,43})`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:     "New Relic Insert Key (NRII-)",
		Regex:    regexp.MustCompile(`\bNRII-[A-Za-z0-9_\-]{32}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "MailerSend API Token (mlsn.)",
		Regex:    regexp.MustCompile(`\bmlsn\.[a-f0-9]{64}\b`),
		Severity: SevHigh,
	},

	// ─── Kripto / file kunci ─────────────────────────────────────────────────
	{
		Name:     "age Secret Key (AGE-SECRET-KEY-1)",
		Regex:    regexp.MustCompile(`\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b`),
		Severity: SevCritical,
	},
}
