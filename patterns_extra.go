package main

import "regexp"

// ============================================================
// patterns_extra.go — tambahan pola hasil audit 2026-11
//
// Semua pola di sini di-append ke `patterns` di init() main.go (sebelum
// prefilter dibangun). Aturan yang dipakai:
//   * token yang formatnya generik (UUID/hex/alnum) WAJIB context-anchored
//     (`[^\n]{0,40}?` + nama layanan) supaya tidak menambah FP di bundle JS.
//   * MatchGroup selalu 1 (nilai rahasianya), kecuali pola marker.
//   * severity mengikuti dampak nyata: server-side key = CRITICAL,
//     write-scope/tenant token = HIGH, read-only/publik-terbatas = MEDIUM/LOW.
// ============================================================

var extraPatterns = []Pattern{

	// ─── Google / GCP ────────────────────────────────────────────────────────
	{
		// bocor paling sering di bundle JS (GCP OAuth client secret).
		Name:     "Google OAuth Client Secret (GOCSPX-)",
		Regex:    regexp.MustCompile(`\b(GOCSPX-[A-Za-z0-9_\-]{28})\b`),
		Severity: SevCritical,
	},
	{
		// Identity Pool ID yang terbuka = jalan ke kredensial AWS unauthenticated.
		Name:       "AWS Cognito Identity Pool ID (context)",
		Regex:      regexp.MustCompile(`(?i)identity[_\-]?pool[_\-]?id["']?\s*[=:]\s*["']?([a-z]{2}-[a-z]+-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "AWS Cognito User Pool ID (context)",
		Regex:      regexp.MustCompile(`(?i)user[_\-]?pool[_\-]?id["']?\s*[=:]\s*["']?([a-z]{2}-[a-z]+-\d_[A-Za-z0-9]{9})`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Cloud / CI-CD ───────────────────────────────────────────────────────
	{
		Name:       "Azure DevOps PAT (context)",
		Regex:      regexp.MustCompile(`(?i)(?:azure[_\-]?devops|vsts|dev\.azure\.com)[^\n]{0,40}?\b([a-z2-7][a-z0-9]{51})\b`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:     "Ansible Vault Encrypted Blob",
		Regex:    regexp.MustCompile(`\$ANSIBLE_VAULT;1\.[12];AES256`),
		Severity: SevHigh,
	},
	{
		Name:       "Kubernetes kubeconfig client-key-data (base64 key)",
		Regex:      regexp.MustCompile(`client-key-data:\s*([A-Za-z0-9+/=]{100,})`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:       "Jenkins API Token (context)",
		Regex:      regexp.MustCompile(`(?i)jenkins[^\n]{0,40}?(?:api[_\-]?)?token["']?\s*[=:]\s*["']?([0-9a-f]{32})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Gitea / Forgejo Access Token (context)",
		Regex:      regexp.MustCompile(`(?i)(?:gitea|forgejo)[^\n]{0,40}?(?:access[_\-]?)?token["']?\s*[=:]\s*["']?([0-9a-f]{40})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Vercel Blob Read-Write Token",
		Regex:      regexp.MustCompile(`\b(vercel_blob_rw_[A-Za-z0-9_]{20,})\b`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Dropbox Short-Lived Access Token (sl.)",
		Regex:      regexp.MustCompile(`\b(sl\.[A-Za-z0-9_\-]{120,})\b`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Slack Signing Secret (context)",
		Regex:      regexp.MustCompile(`(?i)slack[^\n]{0,30}?signing[_\-]?secret["']?\s*[=:]\s*["']?([0-9a-f]{32})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "OpenAI Organization / Project ID",
		Regex:      regexp.MustCompile(`\b(org-[A-Za-z0-9]{20,24})\b`),
		Severity:   SevLow,
		MatchGroup: 1,
	},

	// ─── Database / messaging / directory URI ───────────────────────────────
	{
		Name:       "Messaging URI with credentials (AMQP/NATS/MQTT/Kafka)",
		Regex:      regexp.MustCompile(`\b(?:amqps?|nats|mqtts?|rediss?)://[^:\s/@]{1,64}:([^@\s/]{3,128})@[A-Za-z0-9.\-]{2,}`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Directory URI with credentials (LDAP/LDAPS/IMAP)",
		Regex:      regexp.MustCompile(`\b(?:ldaps?|imaps?|pop3s?)://[^:\s/@]{1,64}:([^@\s/]{3,128})@[A-Za-z0-9.\-]{2,}`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:       "ClickHouse / Trino URI with credentials",
		Regex:      regexp.MustCompile(`\b(?:clickhouse|trino|presto)://[^:\s/@]{1,64}:([^@\s/]{3,128})@[A-Za-z0-9.\-]{2,}`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		// MatchGroup 0 (seluruh conn string): kalau hanya password yang di-capture,
		// temuan ini bisa kalah oleh pola generik "Password assignment" yang
		// menangkap teks yang sama lebih dulu.
		Name:     "MSSQL / SQL Server connection string",
		Regex:    regexp.MustCompile(`(?i)(?:Server|Data Source)\s*=\s*[^;\n]{1,120};\s*(?:User\s*Id|UID)\s*=\s*[^;\n]{1,60};\s*(?:Password|PWD)\s*=\s*[^;\n]{3,64}`),
		Severity: SevCritical,
	},

	// ─── Payments (termasuk gateway regional ID) ────────────────────────────
	{
		Name:       "Checkout.com Secret Key (sk_sbox_/sk_live_)",
		Regex:      regexp.MustCompile(`\b(sk_(?:sbox|live)_[A-Za-z0-9]{32,})`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:       "Mollie API Key (live_/test_, context)",
		Regex:      regexp.MustCompile(`(?i)mollie[^\n]{0,40}?["']?((?:live|test)_[A-Za-z0-9]{26,30})["']?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:       "Klarna API Credentials (context)",
		Regex:      regexp.MustCompile(`(?i)klarna[^\n]{0,40}?(?:api[_\-]?)?(?:secret|password|api[_\-]?key)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,64})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "PayU Merchant Key/Salt (context)",
		Regex:      regexp.MustCompile(`(?i)payu[^\n]{0,40}?(?:merchant[_\-]?)?(?:key|salt|secret)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,64})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "DOKU Secret Key (context)",
		Regex:      regexp.MustCompile(`(?i)doku[^\n]{0,40}?(?:secret[_\-]?key|api[_\-]?key|private[_\-]?key)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,128})["']?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:       "Nicepay / Faspay Credentials (context)",
		Regex:      regexp.MustCompile(`(?i)(?:nicepay|faspay)[^\n]{0,40}?(?:merchant[_\-]?key|password|secret|private[_\-]?key)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,128})["']?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:       "Telnyx API Key (context)",
		Regex:      regexp.MustCompile(`(?i)telnyx[^\n]{0,40}?(?:api[_\-]?)?key["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{30,64})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── AI / data platform ─────────────────────────────────────────────────
	{
		Name:       "Azure OpenAI Key (context)",
		Regex:      regexp.MustCompile(`(?i)(?:azure[_\-.\s]*openai|openai[_\-. ]*azure)[^\n]{0,60}?(?:api[_\-]?key|key)["']?\s*[=:]\s*["']?([0-9a-f]{32})["']?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:       "Qdrant API Key (context)",
		Regex:      regexp.MustCompile(`(?i)qdrant[^\n]{0,40}?api[_\-]?key["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,64})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Weaviate API Key (context)",
		Regex:      regexp.MustCompile(`(?i)weaviate[^\n]{0,40}?api[_\-]?key["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,64})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Chroma / vector DB token (context)",
		Regex:      regexp.MustCompile(`(?i)chroma[^\n]{0,30}?(?:api[_\-]?key|auth[_\-]?token|token)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-\.]{20,80})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Turso Database Token (context)",
		Regex:      regexp.MustCompile(`(?i)turso[^\n]{0,40}?(?:auth[_\-]?)?token["']?\s*[=:]\s*["']?([A-Za-z0-9_\-\.]{40,})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "QuickNode / Helius RPC Key (context)",
		Regex:      regexp.MustCompile(`(?i)(?:quicknode|helius)[^\n]{0,40}?(?:api[_\-]?)?(?:key|token)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,64})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Auth / identity SaaS ───────────────────────────────────────────────
	{
		Name:       "FusionAuth / Descope API Key (context)",
		Regex:      regexp.MustCompile(`(?i)(?:fusionauth|descope)[^\n]{0,40}?(?:api[_\-]?key|management[_\-]?key|project[_\-]?key)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-\.]{20,128})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Kinde / Stytch Client Secret (context)",
		Regex:      regexp.MustCompile(`(?i)(?:kinde|stytch)[^\n]{0,40}?(?:client[_\-]?secret|secret[_\-]?key)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,80})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "ServiceNow Credentials (context)",
		Regex:      regexp.MustCompile(`(?i)servicenow[^\n]{0,40}?(?:password|api[_\-]?key|client[_\-]?secret)["']?\s*[=:]\s*["']?([^"'\s]{8,128})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Email / analytics / realtime ───────────────────────────────────────
	{
		Name:       "SparkPost API Key (context)",
		Regex:      regexp.MustCompile(`(?i)sparkpost[^\n]{0,40}?(?:api[_\-]?)?key["']?\s*[=:]\s*["']?([0-9a-f]{40})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Elastic Email / Customer.io Key (context)",
		Regex:      regexp.MustCompile(`(?i)(?:elastic[_\-\s]*email|customer\.io)[^\n]{0,40}?(?:api[_\-]?)?(?:key|token)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-\.]{20,80})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Ably / LiveKit API Secret (context)",
		Regex:      regexp.MustCompile(`(?i)(?:ably|livekit)[^\n]{0,40}?(?:api[_\-]?)?(?:key|secret)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-\.]{20,80})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Agora App Certificate (context)",
		Regex:      regexp.MustCompile(`(?i)agora[^\n]{0,40}?app[_\-]?certificate["']?\s*[=:]\s*["']?([0-9a-f]{32})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Speechmatics / LogRocket Key (context)",
		Regex:      regexp.MustCompile(`(?i)(?:speechmatics|logrocket)[^\n]{0,40}?(?:api[_\-]?)?(?:key|app[_\-]?id|token)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-/]{8,80})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Feature flags / CMS / e-commerce ───────────────────────────────────
	{
		Name:       "Split.io / Flagsmith / Unleash Key (context)",
		Regex:      regexp.MustCompile(`(?i)(?:split\.io|flagsmith|unleash)[^\n]{0,40}?(?:sdk|server|client|api)?[_\-]?(?:key|token)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-:\.]{20,128})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Strapi / Prismic API Token (context)",
		Regex:      regexp.MustCompile(`(?i)(?:strapi|prismic)[^\n]{0,40}?(?:api[_\-]?token|access[_\-]?token|api[_\-]?key)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-\.]{20,128})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "BigCommerce / Magento / Wix API Credentials (context)",
		Regex:      regexp.MustCompile(`(?i)(?:bigcommerce|magento|wix)[^\n]{0,40}?(?:api[_\-]?)?(?:token|secret|key|password)["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,80})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Canva / Miro / Box / Vimeo Client Secret (context)",
		Regex:      regexp.MustCompile(`(?i)(?:canva|miro|box|vimeo)[^\n]{0,40}?client[_\-]?secret["']?\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,64})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Ops / misc ─────────────────────────────────────────────────────────
	{
		Name:       "Healthchecks.io Ping URL (token)",
		Regex:      regexp.MustCompile(`https://hc-ping\.com/([0-9a-f\-]{36})`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
	{
		Name:       "UptimeRobot API Key (context)",
		Regex:      regexp.MustCompile(`(?i)uptimerobot[^\n]{0,40}?api[_\-]?key["']?\s*[=:]\s*["']?(u[0-9]{6,7}-[a-f0-9]{32})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "DefectDojo / Codecov Token (context)",
		Regex:      regexp.MustCompile(`(?i)(?:defectdojo|codecov)[^\n]{0,40}?(?:api[_\-]?)?token["']?\s*[=:]\s*["']?([0-9a-f]{40})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Make / Integromat Webhook (scenario trigger)",
		Regex:      regexp.MustCompile(`https://hook\.(?:eu1|eu2|us1|us2)\.make\.com/([A-Za-z0-9]{16,})`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Hash disclosure (dipakai untuk chain: crack → login) ───────────────
	{
		Name:     "bcrypt Password Hash",
		Regex:    regexp.MustCompile(`\$(2[aby])\$[0-9]{2}\$[./A-Za-z0-9]{53}`),
		Severity: SevLow,
	},
	{
		Name:       "NTLM / NTLMv2 Hash (context)",
		Regex:      regexp.MustCompile(`(?i)(?:ntlm|nthash|netntlm)[^\n]{0,20}?[:=]\s*([0-9a-f]{32})`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
}
