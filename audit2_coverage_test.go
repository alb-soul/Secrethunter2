package main

// audit2_coverage_test.go — test positif & negatif untuk setiap pola baru di
// patterns_2026b.go. Token DIBANGKITKAN deterministik oleh tk() (bukan literal)
// supaya file test aman dari GitHub push protection.

import (
	"encoding/base64"
	"testing"
)

const (
	csUpper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	csLower  = "abcdefghijklmnopqrstuvwxyz"
	csDigit  = "0123456789"
	csA62    = csUpper + csLower + csDigit
	csHex    = "0123456789abcdef"
	csB64URL = csA62 + "-_"
	csB64    = csA62 + "+/"
	csBech32 = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
)

// tk membangkitkan token pseudo-acak deterministik dari charset cs. Hasil yang
// kebetulan terlihat seperti placeholder ditolak (seed berikutnya dipakai).
func tk(cs string, n int, seed uint32) string {
	for {
		x := seed*2654435761 + 12345
		b := make([]byte, n)
		for i := range b {
			x = x*1664525 + 1013904223
			b[i] = cs[int(x>>9)%len(cs)]
		}
		s := string(b)
		if !isPlaceholder(s) && !looksLikeIdentifier(s+"0aA") {
			return s
		}
		seed++
	}
}

func uuidT(seed uint32) string {
	h := tk(csHex, 32, seed)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

type covCase struct {
	pattern string
	sev     string
	pos     []string
	neg     []string
}

func TestAudit2CoveragePatterns(t *testing.T) {
	basicGood := base64.StdEncoding.EncodeToString([]byte("bob:Zt8sQ1xVp3Lm"))
	basicBin := base64.StdEncoding.EncodeToString([]byte{0x9f, 0x12, 0xe3, 0x00, 0x7a, 0xc4, 0x88, 0x01, 0xfe, 0x33, 0x5b, 0xa0})
	hex32 := tk(csHex, 32, 7)

	cases := []covCase{
		{"Anthropic OAuth Token (sk-ant-oat01-/ort01-)", SevCritical,
			[]string{"CLAUDE_CODE_OAUTH_TOKEN=" + cat("sk-ant-", "oat01-", tk(csB64URL, 93, 1), "AA"), cat(`"refresh":"sk-ant-`, "ort01-", tk(csB64URL, 93, 2), `AA"`)},
			[]string{cat("sk-ant-", "oat01-", "short"), cat("sk-ant-", "oat99-", tk(csB64URL, 95, 3))}},
		{"OpenAI Admin Key (sk-admin-)", SevCritical,
			[]string{cat(`OPENAI_ADMIN_KEY="sk-`, "admin-", tk(csB64URL, 120, 4), `"`)},
			[]string{`href="/sk-admin-panel-route"`}},
		{"Hugging Face Org Token (api_org_)", SevHigh,
			[]string{cat("HF_ORG=api_", "org_", tk(csUpper+csLower, 34, 5))},
			[]string{`api_org_settings_page_container`}},
		{"Prefect API Key (pnu_)", SevHigh,
			[]string{cat("PREFECT_API_KEY=pnu_", tk(csA62, 36, 6))},
			[]string{cat("pnu_", tk(csA62, 20, 6))}},
		{"AWS Secret Access Key (secretAccessKey)", SevCritical,
			[]string{cat(`{region:"us-east-1",secretAccessKey:"`, tk(csB64, 40, 8), `"}`), cat("SECRET_ACCESS_KEY=", tk(csB64, 40, 9), "\n")},
			[]string{`secretAccessKey: process.env.AWS_SECRET`, cat(`secretAccessKey:"`, tk(csA62, 30, 10), `"`)}},
		{"AWS AppSync API Key (da2-)", SevMedium,
			[]string{cat(`"aws_appsync_apiKey": "da2-`, tk(csLower+csDigit, 26, 11), `"`)},
			[]string{`x="da2-abcdefghijklmnopqrstuvwxyz"`}},
		{"Azure AD Client Secret (Q~)", SevCritical,
			// konteks "client_secret" sudah ditangkap pola lama "Azure Client Secret"
			// (CRITICAL juga); pola Q~ menangkap nilai TANPA konteks kata kunci.
			[]string{cat(`const s = "`, tk(csA62, 3, 12), "8Q~", tk(csA62+"_~.-", 34, 13), `";`), cat(`{secret:"`, tk(csA62, 3, 41), "7Q~", tk(csA62, 34, 42), `"}`)},
			[]string{`x = "ab8Q~short"`, cat(`k=x`, tk(csA62, 3, 12), "8Q~", tk(csA62, 34, 13), "zz")}},
		{"Azure Service Bus / Event Hub Connection String", SevCritical,
			[]string{cat("Endpoint=sb://myns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=", tk(csB64, 43, 14), "=")},
			[]string{"Endpoint=sb://myns.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=<your-key>"}},
		{"Azure Cosmos DB Connection String", SevCritical,
			[]string{cat("AccountEndpoint=https://acct.documents.azure.com:443/;AccountKey=", tk(csB64, 86, 15), "==;")},
			[]string{"AccountEndpoint=https://acct.documents.azure.com:443/;AccountKey=;"}},
		{"Azure APIM Subscription Key (context)", SevMedium,
			[]string{`headers:{"Ocp-Apim-Subscription-Key":"` + hex32 + `"}`},
			[]string{`headers:{"Ocp-Apim-Subscription-Key": key}`}},
		{"Azure Logic App / Power Automate Webhook (sig)", SevHigh,
			[]string{cat("https://prod-12.westeurope.logic.azure.com:443/workflows/", tk(csHex, 32, 16), "/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=", tk(csB64URL, 43, 17))},
			[]string{cat("https://prod-12.westeurope.logic.azure.com:443/workflows/", tk(csHex, 32, 16), "/triggers/manual/paths/invoke?api-version=2016-06-01")}},
		{"Google Cloud Service Account JSON (with private key)", SevCritical,
			[]string{cat(`{"type": "service_account", "project_id": "p-1", "private_key_id": "`, tk(csHex, 40, 18), `", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQ`, tk(csB64, 60, 19), `"}`)},
			[]string{`{"type": "service_account", "project_id": "p-1", "client_email": "a@b.iam.gserviceaccount.com"}`}},
		{"Cloudflare API Token (cfut_/cfat_/cfk_)", SevCritical,
			[]string{cat("CF_API_TOKEN=cf", "at_", tk(csA62, 40, 20), tk(csHex, 8, 21), "\n")},
			[]string{"cfat_short_value"}},
		{"Heroku API Key v2 (HRKU-)", SevCritical,
			[]string{cat("HEROKU_API_KEY=HRKU-", "AA", tk(csB64URL, 58, 22))},
			[]string{cat("HRKU-", "AB", tk(csB64URL, 58, 22))}},
		{"GitLab Runner Authentication Token (glrt-)", SevHigh,
			[]string{cat("token = glrt-", "t1_", tk(csA62, 20, 23))},
			[]string{"see glrt-docs"}},
		{"GitLab Agent Token (glagent-)", SevHigh,
			[]string{cat("glagent-", tk(csA62, 50, 24))},
			[]string{cat("glagent-", tk(csA62, 30, 24))}},
		{"CircleCI Personal API Token (CCIPAT_)", SevHigh,
			[]string{cat("CIRCLE_TOKEN=CCIPAT_", tk(csA62, 22, 25), "_", tk(csHex, 40, 26))},
			[]string{cat("CCIPAT_", tk(csA62, 22, 25), "_", tk(csUpper, 40, 26))}},
		{"Buildkite User Access Token (bkua_)", SevHigh,
			[]string{cat("BUILDKITE_TOKEN=bkua_", tk(csHex, 40, 27))},
			[]string{cat("bkua_", tk(csHex, 30, 27))}},
		{"Docker Hub Organization Access Token (dckr_oat_)", SevHigh,
			[]string{cat("DOCKER_TOKEN=dckr_", "oat_", tk(csA62, 32, 28))},
			[]string{"dckr_oat_short"}},
		{"Contentful Personal Access Token (CFPAT-)", SevHigh,
			[]string{cat("CONTENTFUL_MANAGEMENT_TOKEN=CFPAT-", tk(csB64URL, 43, 29))},
			[]string{cat("CFPAT-", tk(csA62, 20, 29))}},
		{"npm legacy _auth (base64 user:pass)", SevHigh,
			[]string{"//registry.npmjs.org/:_auth=" + basicGood + "\n", "_auth = " + basicGood + "\n"},
			[]string{"_auth=" + basicBin + "\n"}},
		{"Docker config.json auth (base64)", SevHigh,
			[]string{`{"auths":{"https://index.docker.io/v1/":{"auth":"` + basicGood + `"}}}`},
			[]string{`{"auths":{"https://index.docker.io/v1/":{"auth":"` + basicBin + `"}}}`}},
		{"Kafka SASL JAAS password", SevHigh,
			[]string{`sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="svc" password="Zt8sQ1xVp3";`,
				`"sasl.jaas.config": "org.apache.kafka.common.security.scram.ScramLoginModule required username=\"svc\" password=\"Zt8sQ1xVp3\";"`},
			[]string{`org.apache.kafka.common.security.plain.PlainLoginModule required username="svc" password="${KAFKA_PASS}";`}},
		{"JDBC URL with password", SevCritical,
			[]string{"jdbc:postgresql://db:5432/app?user=svc&password=Zt8sQ1xVp3", "jdbc:sqlserver://h:1433;databaseName=x;user=sa;password=Zt8sQ1xVp3;"},
			[]string{"jdbc:mysql://localhost:3306/app?user=root&password=password", "jdbc:mysql://h/app?user=u&password=${DB_PASS}"}},
		{"PayPal OAuth Access Token (A21AA)", SevHigh,
			[]string{cat(`Authorization: "Bearer A21AA`, tk(csB64URL, 92, 30), `"`)},
			[]string{cat("A21AA", tk(csA62, 20, 30))}},
		{"Plaid Access Token", SevHigh,
			[]string{"PLAID_ACCESS_TOKEN=access-production-" + uuidT(31)},
			[]string{"access-staging-" + uuidT(31)}},
		{"Shopify Storefront Access Token (context, public)", SevInfo,
			[]string{`"X-Shopify-Storefront-Access-Token": "` + hex32 + `"`},
			[]string{`"X-Shopify-Storefront-Access-Token": token`}},
		{"Algolia Admin API Key (context)", SevCritical,
			[]string{`algoliaAdminKey: "` + hex32 + `"`},
			[]string{`algoliaSearchKey: "` + hex32 + `"`}},
		{"Slack Workflow / Trigger Webhook", SevHigh,
			[]string{cat("https://hooks.slack.com/triggers/T0123ABCD45/", tk(csDigit, 13, 32), "/", tk(csHex, 32, 33))},
			[]string{"https://hooks.slack.com/triggers/"}},
		{"Google Chat Webhook", SevHigh,
			[]string{cat("https://chat.googleapis.com/v1/spaces/AAAA", tk(csA62, 7, 34), "/messages?key=AIza", tk(csB64URL, 35, 35), "&token=", tk(csB64URL, 43, 36), "%3D")},
			[]string{cat("https://chat.googleapis.com/v1/spaces/AAAA", tk(csA62, 7, 34), "/messages")}},
		{"IFTTT Webhook Key", SevHigh,
			[]string{cat("https://maker.ifttt.com/trigger/door_open/with/key/", tk(csB64URL, 22, 37))},
			[]string{"https://maker.ifttt.com/trigger/door_open/with/key/"}},
		{"New Relic Insert Key (NRII-)", SevHigh,
			[]string{cat("NEW_RELIC_INSERT_KEY=NRII-", tk(csB64URL, 32, 38))},
			[]string{cat("NRII-", tk(csA62, 10, 38))}},
		{"MailerSend API Token (mlsn.)", SevHigh,
			[]string{cat("MAILERSEND_API_KEY=mlsn.", tk(csHex, 64, 39))},
			[]string{cat("mlsn.", tk(csHex, 40, 39))}},
		{"age Secret Key (AGE-SECRET-KEY-1)", SevCritical,
			[]string{cat("AGE-SECRET-", "KEY-1", tk(csBech32, 58, 40))},
			[]string{cat("AGE-SECRET-", "KEY-1", "BIO", tk(csBech32, 55, 40))}},
	}

	for _, c := range cases {
		for _, p := range c.pos {
			got := sevOf(p, c.pattern)
			if got == "" {
				t.Errorf("[%s] positif tidak terdeteksi: %q\n   fired=%v", c.pattern, p, patternsFired(p))
			} else if got != c.sev {
				t.Errorf("[%s] severity %s, want %s", c.pattern, got, c.sev)
			}
		}
		for _, n := range c.neg {
			if sevOf(n, c.pattern) != "" {
				t.Errorf("[%s] negatif ikut terdeteksi (FP): %q", c.pattern, n)
			}
		}
	}
}

// Pola konteks Cloudflare lama tidak boleh lagi melaporkan token baru
// `cfat_…` dalam keadaan terpotong 40 char.
func TestAudit2CloudflareContextNoTruncation(t *testing.T) {
	tok := cat("cf", "at_", tk(csA62, 40, 20), tk(csHex, 8, 21))
	for _, f := range scanContent("test://x", "CF_API_TOKEN="+tok+"\n") {
		if f.Match != tok && len(f.Match) < len(tok) && f.Pattern == "Cloudflare API Token" {
			t.Fatalf("token cfat_ dilaporkan terpotong: %q", f.Match)
		}
	}
}
